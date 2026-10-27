package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// ddbReads answers the write gate's reads (checkReads, gate.go) from a
// DynamoDB table, so a write on this backend is checked by the same code
// as on SQL. The reads run outside any transaction: the commit
// (ddb.Commit) pins what the checks relied on — every item's head and the
// configuration in force — and a write whose commit finds them moved is
// checked again (D.3).
//
// The gate's rows carry int64 ids it only hands back (nsRow.id,
// configSeq, revRow.seq and res, author ids, entry seqs): here they are
// handles, minted per check, onto the table's keys. What the backend
// doesn't store reads as empty where nothing of the kind can exist
// (branches, draft copies, schema uses, pruning horizons), and as 501
// where a request needs a feature it lacks (blobs, sealed and e2e keys,
// grants, $schema namespaces, archives, reads at an earlier entry).
type ddbReads struct {
	e   *Engine
	b   *ddbBackend
	s   *ddb.Store
	ctx context.Context

	next    int64
	nss     map[int64]*ddbNS
	nsNamed map[string]int64
	cfgs    map[int64]ddbCfgRef
	cfgAt   map[ddbPosKey]int64
	revs    map[int64]*ddbRevRef
	revAt   map[ddbRevKey]int64
	res     map[int64]ddbResRef
	resAt   map[ddbResRef]int64
	authors map[int64]string
	authorN map[string]int64
	logs    map[int64]ddbPosKey
	logAt   map[ddbPosKey]int64
	logKeys map[string]int64 // each namespace's high bits of its log handles
	// resRows are the resources read, by handle: the commit pins them.
	resRows map[int64]*ddb.ResRow
	// uploaderVer is the version pendingUsed read: the upload pins it.
	uploaderVer uint64
	// schemaNSs are the schema namespaces read, with their configuration.
	schemaNSs map[string]int64
	// schemaRefs are the revisions' schema paths read, by handle.
	schemaRefs map[int64]string
	// copies are the resources copyRows answered with: a purge's commit
	// pins them (Commit.Copies).
	copies []ddb.ResourceRef
}

type ddbNS struct {
	name string
	row  *ddb.NSRow
}

type ddbPosKey struct {
	ns  string
	pos uint64
}

type ddbCfgRef struct {
	ns  string
	pos uint64
}

type ddbResRef struct{ ns, name string }

type ddbRevKey struct {
	ns, name string
	pos      uint64
}

type ddbRevRef struct {
	key ddbRevKey
	row *revRow // nil until read
}

func newDDBReads(b *ddbBackend, ctx context.Context) *ddbReads {
	return &ddbReads{
		b: b, e: b.e, s: b.store, ctx: ctx,
		nss: map[int64]*ddbNS{}, nsNamed: map[string]int64{},
		cfgs: map[int64]ddbCfgRef{}, cfgAt: map[ddbPosKey]int64{},
		revs: map[int64]*ddbRevRef{}, revAt: map[ddbRevKey]int64{},
		res: map[int64]ddbResRef{}, resAt: map[ddbResRef]int64{},
		authors: map[int64]string{}, authorN: map[string]int64{},
		logs: map[int64]ddbPosKey{}, logAt: map[ddbPosKey]int64{}, logKeys: map[string]int64{},
		resRows: map[int64]*ddb.ResRow{}, schemaRefs: map[int64]string{},
	}
}

var _ checkReads = (*ddbReads)(nil)

// must panics with err: a gate run recovers it (ddbCheck).
func (r *ddbReads) must(err error) {
	if err != nil {
		panic(err)
	}
}

func (r *ddbReads) handle() int64 { r.next++; return r.next }

// --- handles ---

func (r *ddbReads) cfgHandle(ns string, pos uint64) int64 {
	k := ddbPosKey{ns, pos}
	if h, ok := r.cfgAt[k]; ok {
		return h
	}
	h := r.handle()
	r.cfgAt[k], r.cfgs[h] = h, ddbCfgRef{ns, pos}
	return h
}

// posBits is how many low bits of a log or revision handle hold its
// position: positions are below 10^12 (posDigits), under 2^40.
const posBits = 40

// logHandle is entry pos of ns's log as the gate's seq: ordered as the
// positions are within a namespace, as SQL's seqs are (the reads compare
// them: a range (from, to], since past the head).
func (r *ddbReads) logHandle(ns string, pos uint64) int64 {
	k := ddbPosKey{ns, pos}
	if h, ok := r.logAt[k]; ok {
		return h
	}
	key, ok := r.logKeys[ns]
	if !ok {
		key = r.handle()
		r.logKeys[ns] = key
	}
	h := key<<posBits | int64(pos)
	r.logAt[k], r.logs[h] = h, k
	return h
}

func (r *ddbReads) resHandle(ns, name string) int64 {
	k := ddbResRef{ns, name}
	if h, ok := r.resAt[k]; ok {
		return h
	}
	h := r.handle()
	r.resAt[k], r.res[h] = h, k
	return h
}

// revHandle is revision pos of name in ns as the gate's seq: ordered as
// the positions are within the resource (logHandle).
func (r *ddbReads) revHandle(ns, name string, pos uint64) int64 {
	k := ddbRevKey{ns, name, pos}
	if h, ok := r.revAt[k]; ok {
		return h
	}
	h := r.resHandle(ns, name)<<posBits | int64(pos)
	r.revAt[k], r.revs[h] = h, &ddbRevRef{key: k}
	return h
}

func (r *ddbReads) authorHandle(name string) int64 {
	if h, ok := r.authorN[name]; ok {
		return h
	}
	h := r.handle()
	r.authorN[name], r.authors[h] = h, name
	return h
}

// revRowOf is a stored revision as the gate's row, its handle registered.
func (r *ddbReads) revRowOf(ns string, ri *ddb.RevInfo) *revRow {
	h := r.revHandle(ns, ri.Name, ri.Pos)
	ref := r.revs[h]
	if ref.row != nil {
		return ref.row
	}
	row := &revRow{seq: h, res: r.resHandle(ns, ri.Name), first: ri.Pos == 1, author: r.authorHandle(ri.Author), created: ri.Created}
	id, err := ids.Parse(ri.ID)
	r.must(err)
	row.id = id
	switch {
	case ri.Pos > 1:
		row.parentSeq.Int64, row.parentSeq.Valid = r.revHandle(ns, ri.Name, ri.Pos-1), true
	case ri.ParentNS != "":
		// A foreign parent: the base's revision it continues (§7.6).
		row.parentSeq.Int64, row.parentSeq.Valid = r.revHandle(ri.ParentNS, ri.Name, ri.ParentPos), true
	}
	if ri.Kind == "tombstone" {
		row.kind = kindTombstone
	} else {
		row.kind = kindRev
		row.patches.String, row.patches.Valid = ri.Patches, true
		row.size.Int64, row.size.Valid = int64(ri.Size), true
		row.digest = ri.Digest
	}
	if ri.Gesture != "" {
		row.gesture.String, row.gesture.Valid = ri.Gesture, true
	}
	if ri.Undoes != "" {
		row.undoes.String, row.undoes.Valid = ri.Undoes, true
	}
	if ri.SchemaRef != "" {
		r.schemaRefs[h] = ri.SchemaRef
	}
	if ri.GrantID != "" {
		gid, err := ids.Parse(ri.GrantID)
		r.must(err)
		row.grantID = gid[:]
	}
	ref.row = row
	return row
}

// --- namespaces ---

func (r *ddbReads) nsByName(name string) *nsRow {
	if h, ok := r.nsNamed[name]; ok {
		return r.nsRowOf(h)
	}
	row, err := r.s.Namespace(r.ctx, name)
	r.must(err)
	if row == nil {
		return nil
	}
	h := r.handle()
	r.nsNamed[name], r.nss[h] = h, &ddbNS{name: name, row: row}
	return r.nsRowOf(h)
}

func (r *ddbReads) nsRowOf(h int64) *nsRow {
	n := r.nss[h]
	out := &nsRow{id: h, name: n.name, frozen: n.row.Frozen, purged: n.row.Purged, configSeq: r.cfgHandle(n.name, n.row.ConfigPos)}
	if n.row.TipPos > 0 {
		out.headSeq.Int64, out.headSeq.Valid = r.logHandle(n.name, n.row.TipPos), true
	}
	if b := n.row.Base; b != "" {
		// A branch (§7.6): its base, the entry it branched at, the base's
		// configuration then.
		if base := r.nsByName(b); base != nil {
			out.base.Int64, out.base.Valid = base.id, true
			out.baseAt.Int64, out.baseAt.Valid = r.logHandle(b, n.row.BaseAt), true
			out.baseConfigSeq.Int64, out.baseConfigSeq.Valid = r.cfgHandle(b, n.row.BaseCfgPos), true
		}
	}
	return out
}

func (r *ddbReads) nsName(h int64) string {
	n, ok := r.nss[h]
	if !ok {
		panic(fmt.Errorf("ddb: unknown namespace handle %d", h))
	}
	return n.name
}

// The locks a write takes on SQL (pglock.go) have no counterpart: the
// commit's conditions serialise instead.
func (r *ddbReads) nsForResources(name string) *nsRow { return r.nsByName(name) }
func (r *ddbReads) nsForWrite(name string) *nsRow     { return r.nsByName(name) }
func (r *ddbReads) nsByID(id int64) *nsRow {
	if _, ok := r.nss[id]; !ok {
		return nil
	}
	return r.nsRowOf(id)
}
func (r *ddbReads) nsRowUnlocked(id int64) *nsRow  { return r.nsByID(id) }
func (r *ddbReads) lockNS(ns int64, mode lockMode) {}
func (r *ddbReads) branchesOf(n *nsRow) []*nsRow {
	bs, err := r.s.Branches(r.ctx, r.nsName(n.id))
	r.must(err)
	var out []*nsRow
	for _, b := range bs {
		if bn := r.nsByName(b.Name); bn != nil {
			out = append(out, bn)
		}
	}
	return out
}

// baseIdentity names a branch's base: its name, which a deployment never
// reuses (remote bases aren't built here).
func (r *ddbReads) baseIdentity(n *nsRow) string {
	if !n.isBranch() {
		return ""
	}
	return r.nsName(n.base.Int64)
}

// schemaNS is nsByName for a schema path's namespace; the commit pins its
// configuration (schemaPins), as SQL's recheck compares its row.
func (r *ddbReads) schemaNS(name string) *nsRow {
	n := r.nsByName(name)
	if n != nil {
		if r.schemaNSs == nil {
			r.schemaNSs = map[string]int64{}
		}
		r.schemaNSs[name] = n.configSeq
	}
	return n
}

// schemaPins are the configurations of the schema namespaces read, but
// own's (which the commit pins anyway).
func (r *ddbReads) schemaPins(own string) []ddb.NSPin {
	var out []ddb.NSPin
	for _, name := range sortedKeys(r.schemaNSs) {
		if name == own {
			continue
		}
		seq := r.schemaNSs[name]
		out = append(out, ddb.NSPin{NS: name, CfgPos: r.cfgs[seq].pos, CfgID: r.cfgRow(seq).ID})
	}
	return out
}
func (r *ddbReads) prefetchResources(int64, []string)      {}
func (r *ddbReads) prefetchHeads(*nsRow, []string, *int64) {}
func (r *ddbReads) prefetchSchemas([]schema.Ref)           {}

func (r *ddbReads) nsLevel(n *nsRow) int { return r.config(n.configSeq).level }

// --- configurations ---

func (r *ddbReads) cfgRow(seq int64) *ddb.ConfigRow {
	ref, ok := r.cfgs[seq]
	if !ok {
		panic(fmt.Errorf("ddb: unknown configuration handle %d", seq))
	}
	c, err := r.s.ConfigAt(r.ctx, ref.ns, ref.pos)
	r.must(err)
	if c == nil {
		panic(fmt.Errorf("ddb: configuration %s/%d missing", ref.ns, ref.pos))
	}
	return c
}

// config is the configuration at seq's position, parsed as SQL parses a
// stored document (config of engine.go), cached by namespace and id.
func (r *ddbReads) config(seq int64) *Config {
	ref := r.cfgs[seq]
	c := r.cfgRow(seq)
	key := ref.ns + "\x00" + c.ID
	b := r.b
	b.cfgMu.Lock()
	cfg, ok := b.byID[key]
	b.cfgMu.Unlock()
	if ok {
		return cfg
	}
	cfg, err := r.e.parseConfig(c.Doc)
	if err != nil {
		panic(fmt.Errorf("stored namespace document %s/%d is invalid: %w", ref.ns, ref.pos, err))
	}
	b.cfgMu.Lock()
	b.byID[key] = cfg
	b.cfgMu.Unlock()
	return cfg
}

func (r *ddbReads) configID(seq int64) ids.ID {
	id, err := ids.Parse(r.cfgRow(seq).ID)
	r.must(err)
	return id
}

func (r *ddbReads) configByID(n *nsRow, id ids.ID) (seq, author int64, ok bool) {
	ns := r.nsName(n.id)
	c, err := r.s.ConfigByID(r.ctx, ns, id.String())
	r.must(err)
	if c == nil {
		return 0, 0, false
	}
	return r.cfgHandle(ns, c.Pos), r.authorHandle(c.Author), true
}

func (r *ddbReads) firstEntryOfConfig(n *nsRow, seq int64) (int64, bool) {
	c := r.cfgRow(seq)
	if c.LogPos == 0 {
		return 0, false
	}
	return r.logHandle(r.nsName(n.id), c.LogPos), true
}

// --- the log ---

func (r *ddbReads) entry(seq int64) *ddb.EntryRow {
	k, ok := r.logs[seq]
	if !ok {
		panic(fmt.Errorf("ddb: unknown entry handle %d", seq))
	}
	le, err := r.s.EntryAt(r.ctx, k.ns, k.pos)
	r.must(err)
	return le
}

func (r *ddbReads) nsLogID(seq int64) ids.ID {
	le := r.entry(seq)
	if le == nil {
		panic(fmt.Errorf("ddb: entry %d missing", seq))
	}
	id, err := ids.Parse(le.ID)
	r.must(err)
	return id
}

func (r *ddbReads) nsLogSeq(ns int64, id ids.ID) (int64, bool) {
	name := r.nsName(ns)
	pos, err := r.s.EntryPos(r.ctx, name, id.String())
	r.must(err)
	if pos == 0 {
		return 0, false
	}
	return r.logHandle(name, pos), true
}

func (r *ddbReads) configEntryGestures(seq int64) (string, bool) {
	le := r.entry(seq)
	if le == nil || le.Kind != "config" {
		return "", false
	}
	if g := gestureMeta(le.Gesture, le.Undoes); g != nil {
		return string(jsonv.Canonical(g)), true
	}
	return "", false
}

func (r *ddbReads) batchEntry(n *nsRow, seq, author int64) (ids.ID, string, bool) {
	le := r.entry(seq)
	if le == nil || le.Kind != "batch" || le.Author != r.authors[author] {
		return ids.ID{}, "", false
	}
	id, err := ids.Parse(le.ID)
	r.must(err)
	return id, le.Body, true
}

// --- resources and revisions ---

func (r *ddbReads) resolve(n *nsRow, name string, asOf *int64) *view {
	ns := r.nsName(n.id)
	v := &view{ns: n, name: name}
	rr, err := r.s.Resource(r.ctx, ns, name)
	r.must(err)
	rh := r.resHandle(ns, name)
	if rr == nil {
		// No entries: a handle still, for the resource's pending blobs
		// (an upload precedes the create that references it), as the
		// SQL schema's resource row without a head (ensureResource).
		v.own = &resRow{id: rh, name: name}
		return r.readThrough(n, v)
	}
	r.resRows[rh] = rr
	own := &resRow{id: rh, name: name, state: stateLive}
	v.own, v.src = own, own
	headPos := rr.HeadPos
	switch {
	case rr.Purged:
		// Purged at every entry, with its head (§8.3).
		own.state = statePurged
		v.state = Purged
		hns := ns
		if rr.HeadNS != "" {
			hns = rr.HeadNS // purged as read through from a base
		}
		v.head = r.rev(r.revHandle(hns, name, headPos))
		return v
	case asOf != nil:
		// The head as of a log entry: the history rows (ddb.Store.HeadAt),
		// as SQL's head_history.
		h, err := r.s.HeadAt(r.ctx, ns, name, r.logs[*asOf].pos)
		r.must(err)
		if h == nil {
			v.src = nil
			return r.readThrough(n, v)
		}
		headPos = h.Pos
	}
	hh := r.revHandle(ns, name, rr.HeadPos)
	own.headSeq.Int64, own.headSeq.Valid = hh, true
	v.head = r.rev(r.revHandle(ns, name, headPos))
	if v.head.kind == kindTombstone {
		v.state = Tombstoned
	} else {
		v.state = Live
	}
	return v
}

func (r *ddbReads) rev(seq int64) *revRow {
	ref, ok := r.revs[seq]
	if !ok {
		panic(fmt.Errorf("ddb: unknown revision handle %d", seq))
	}
	if ref.row != nil {
		return ref.row
	}
	ri, err := r.s.RevAt(r.ctx, ref.key.ns, ref.key.name, ref.key.pos)
	r.must(err)
	if ri == nil {
		panic(fmt.Errorf("ddb: revision %s/%s/%d missing", ref.key.ns, ref.key.name, ref.key.pos))
	}
	return r.revRowOf(ref.key.ns, ri)
}

func (r *ddbReads) revID(seq int64) ids.ID { return r.rev(seq).id }

func (r *ddbReads) revByID(n *nsRow, name string, id ids.ID) *revRow {
	ns := r.nsName(n.id)
	ri, err := r.s.ReadRevOf(r.ctx, ns, name, id.String())
	r.must(err)
	if ri == nil {
		return nil
	}
	return r.revRowOf(ns, ri)
}

func (r *ddbReads) entriesTo(row *revRow) []int64 {
	ref := r.revs[row.seq]
	ri, err := r.s.RevAt(r.ctx, ref.key.ns, ref.key.name, ref.key.pos)
	r.must(err)
	if ri == nil || ri.LogPos == 0 {
		return nil
	}
	return []int64{r.logHandle(ref.key.ns, ri.LogPos)}
}

func (r *ddbReads) docBytesAt(row *revRow) ([]byte, error) {
	ref := r.revs[row.seq]
	return r.s.DocAt(r.ctx, ref.key.ns, ref.key.name, ref.key.pos)
}

// ancestry: a resource's chain, then its first revision's foreign
// parent's, and so on (§7.6).
func (r *ddbReads) ancestry(head *revRow) []segment {
	segs := []segment{{res: head.res, max: head.seq}}
	for {
		k := r.res[segs[len(segs)-1].res]
		first, err := r.s.RevAt(r.ctx, k.ns, k.name, 1)
		r.must(err)
		if first == nil || first.ParentNS == "" {
			return segs
		}
		segs = append(segs, segment{res: r.resHandle(first.ParentNS, k.name), max: r.revHandle(first.ParentNS, k.name, first.ParentPos)})
	}
}

func (r *ddbReads) locate(segs []segment, id ids.ID) (int, *revRow) {
	for i, sg := range segs {
		rf := r.res[sg.res]
		ri, err := r.s.ReadRevOf(r.ctx, rf.ns, rf.name, id.String())
		r.must(err)
		if ri != nil && ri.Pos <= r.revs[sg.max].key.pos {
			return i, r.revRowOf(rf.ns, ri)
		}
	}
	return -1, nil
}

func (r *ddbReads) horizonID(res int64) string { return "" }

// namesAfter: n's own names and its bases' (read-through), the k
// smallest of their union (namesAfter of reads.go).
func (r *ddbReads) namesAfter(n *nsRow, after string, k int) []string {
	names := map[string]bool{}
	for m := n; ; m = r.nsByID(m.base.Int64) {
		heads, _, err := r.s.ListHeads(r.ctx, r.nsName(m.id), after, k)
		r.must(err)
		for _, h := range heads {
			names[h.Name] = true
		}
		if !m.isBranch() {
			break
		}
	}
	sorted := sortedKeys(names)
	if len(sorted) > k {
		sorted = sorted[:k]
	}
	return sorted
}

// copyRows: the revisions with id named name in every namespace (GSI1).
func (r *ddbReads) copyRows(id ids.ID, name string) []copyRow {
	cs, err := r.s.RevsByID(r.ctx, id.String(), name)
	r.must(err)
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].NS != cs[j].NS {
			return cs[i].NS < cs[j].NS
		}
		return cs[i].Pos < cs[j].Pos
	})
	var out []copyRow
	for _, c := range cs {
		if c.Kind == "tombstone" {
			continue
		}
		n := r.nsByName(c.NS)
		if n == nil {
			continue
		}
		ri := c.RevInfo
		row := r.revRowOf(c.NS, &ri)
		state := stateLive
		if r.purgedRes(row.res) {
			state = statePurged
		}
		if state != statePurged {
			r.copies = append(r.copies, ddb.ResourceRef{NS: c.NS, Name: name})
		}
		out = append(out, copyRow{seq: row.seq, ns: n.id, res: row.res, state: state})
	}
	return out
}

// --- authors ---

func (r *ddbReads) actorID(a *actor) int64 { return r.authorHandle(a.id()) }

func (r *ddbReads) authorName(id int64) string { return r.authors[id] }

// --- what this backend doesn't store ---

func (r *ddbReads) archiveURL(res, seq int64) string { panic(ddbUnsupported("archives")) }

// referencedUpTo: every blob a document of res references is attached to
// res, at the first revision that referenced it (refPos), and pruning,
// which ends attachments, isn't built here: a document up to max
// references bid exactly when the attachment's first is at or before.
func (r *ddbReads) referencedUpTo(res, max int64, bid ids.ID) bool {
	k := r.res[res]
	b, err := r.s.Attachment(r.ctx, k.ns, k.name, bid.String())
	r.must(err)
	return b != nil && b.RefPos > 0 && b.RefPos <= r.revs[max].key.pos
}
func (r *ddbReads) declaredAt(row *revRow) []ids.ID   { panic(ddbUnsupported("e2e namespaces")) }
func (r *ddbReads) dek(res int64, create bool) []byte { panic(ddbUnsupported("encryption at rest")) }
func (r *ddbReads) e2eEpochOK(n *nsRow, cfg *Config, e int) bool {
	panic(ddbUnsupported("sealed namespaces"))
}
func (r *ddbReads) grantJob(n *nsRow, id ids.ID, plain func() []byte) *sealJob {
	panic(ddbUnsupported("sealed namespaces"))
}

// --- grants ---

func (r *ddbReads) grantRow(id []byte) ([]byte, *grantRoot, bool) {
	g, err := r.s.Grant(r.ctx, ids.FromBytes(id).String())
	r.must(err)
	if g == nil {
		return nil, nil, false
	}
	return g.Blocks, &grantRoot{sub: g.Sub, kid: g.Kid}, true
}

// recordsGrant: an entry of n, or of its bases up to the entry each
// branched at (recordsGrant of grants.go), by their markers.
func (r *ddbReads) recordsGrant(n *nsRow, id ids.ID) bool {
	var upTo uint64 // n's own entries: all of them
	for cur := n; cur != nil; {
		ok, err := r.s.RecordsGrant(r.ctx, r.nsName(cur.id), id.String(), upTo)
		r.must(err)
		if ok {
			return true
		}
		if !cur.isBranch() {
			return false
		}
		upTo = r.logs[cur.baseAt.Int64].pos
		cur = r.nsByID(cur.base.Int64)
	}
	return false
}

func (r *ddbReads) nextEntryCreated(ns, seq int64) (int64, bool) {
	k, ok := r.logs[seq]
	if !ok {
		panic(fmt.Errorf("ddb: unknown entry handle %d", seq))
	}
	le, err := r.s.EntryAt(r.ctx, k.ns, k.pos+1)
	r.must(err)
	if le == nil {
		return 0, false
	}
	return le.Created, true
}

// gateRead runs f on a gate over the table's
// reads, what they panic with returned as errors (ddbCheck).
func (b *ddbBackend) gateRead(ctx context.Context, f func(t *gate) error) error {
	e := b.e
	g := &gate{checkReads: newDDBReads(b, ctx), checkState: &checkState{e: e, now: e.now()}}
	err, perr := ddbCheck(func() error { return f(g) })
	if perr != nil {
		return perr
	}
	return err
}

// ddbCheck runs f, a gate's check, turning what its reads panic with into
// errors: the gate's own answers (*Error, a 501 for a feature this
// backend lacks among them) and the store's (*ddb.Error), and anything
// else as an internal error, as update1 does on SQL.
func ddbCheck[T any](f func() T) (out T, err error) {
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		var ce *Error
		var de *ddb.Error
		switch v := p.(type) {
		case *Error:
			err = v
		case error:
			if errors.As(v, &ce) {
				err = ce
			} else if errors.As(v, &de) {
				err = ddbAsErr(de)
			} else {
				err = panicErr(v)
			}
		default:
			err = panicErr(p)
		}
	}()
	return f(), nil
}

// --- blobs ---

// ddbBlobRow is a store row as the gate's, of resource handle res.
func ddbBlobRow(res int64, b *ddb.BlobRow) *blobRow {
	bid, _ := ids.Parse(b.Bid)
	return &blobRow{res: res, bid: bid, typ: b.Type, nonce: b.Nonce, size: b.Size, hash: b.Hash, pending: !b.Attachment}
}

func (r *ddbReads) attachedBlob(res int64, bid ids.ID) *blobRow {
	k := r.res[res]
	b, err := r.s.Attachment(r.ctx, k.ns, k.name, bid.String())
	r.must(err)
	if b == nil {
		return nil
	}
	return ddbBlobRow(res, b)
}

func (r *ddbReads) pendingBlob(res int64, bid ids.ID, uploader string, cutoff int64) *blobRow {
	k := r.res[res]
	b, err := r.s.Pending(r.ctx, k.ns, k.name, bid.String(), uploader)
	r.must(err)
	if b == nil || b.Created < cutoff {
		return nil
	}
	return ddbBlobRow(res, b)
}

// blobArchive: no archives on this backend.
func (r *ddbReads) blobArchive(res int64, bid ids.ID) string { return "" }

func (r *ddbReads) openBytes(owner int64, hash []byte) blobContent {
	data, file, ok, err := r.s.Bytes(r.ctx, hash)
	r.must(err)
	if !ok {
		panic(fmt.Errorf("blob bytes %x are missing", hash))
	}
	if file == "" {
		return memContent(data)
	}
	f, err := r.e.blobs.open(file)
	r.must(err)
	return fileContent(f)
}

func (r *ddbReads) pendingUsed(n *nsRow, uploader string, cutoff, res int64, bid ids.ID) int64 {
	// The version first: an upload committed after it moves it, and this
	// one's PutPending fails stale.
	ver, err := r.s.UploaderVersion(r.ctx, r.nsName(n.id), uploader)
	r.must(err)
	r.uploaderVer = ver
	ps, err := r.s.PendingOf(r.ctx, r.nsName(n.id))
	r.must(err)
	var skip ddbResRef
	if res != 0 {
		skip = r.res[res]
	}
	var used int64
	for _, p := range ps {
		if p.Uploader != uploader || p.Created < cutoff || (res != 0 && p.Name == skip.name && p.Bid == bid.String()) {
			continue
		}
		used += max(p.Size, pendingMin)
	}
	return used
}

func (r *ddbReads) sealedBlobHead(n *nsRow, name string, bid ids.ID, out *Blob) *sealJob {
	panic(ddbUnsupported("sealed namespaces"))
}

// --- schema references ---

func (r *ddbReads) noLocks() func() { return func() {} }

func (r *ddbReads) nsNames() []string {
	names, err := r.s.Namespaces(r.ctx)
	r.must(err)
	return names
}

func (r *ddbReads) pinnedRefs(l *nsRow) []string {
	pins, err := r.s.SchemaRefs(r.ctx, r.nsName(l.id), "")
	r.must(err)
	seen := map[string]bool{}
	var out []string
	for _, p := range pins {
		if !seen[p.Ref] {
			seen[p.Ref] = true
			out = append(out, p.Ref)
		}
	}
	return out
}

func (r *ddbReads) pinningNames(l *nsRow, ref string) []string {
	pins, err := r.s.SchemaRefs(r.ctx, r.nsName(l.id), ref)
	r.must(err)
	var out []string
	for _, p := range pins {
		out = append(out, p.Name)
	}
	return out
}

func (r *ddbReads) schemaRefOf(seq int64) (string, bool) {
	r.rev(seq)
	ref, ok := r.schemaRefs[seq]
	return ref, ok
}

// --- serving reads ---

func (r *ddbReads) knowRevID(seq int64, id ids.ID) {}

// prunedIn: nothing is pruned on this backend; a purged resource's range
// is (prunedIn of resolve.go).
func (r *ddbReads) prunedIn(segs []segment, lo int64) error {
	for _, s := range segs {
		if r.purgedRes(s.res) {
			return purgedError{}
		}
	}
	return nil
}

func (r *ddbReads) revsBetween(res, from, max int64, limit int, visit func(*revRow) bool) {
	k := r.res[res]
	var fromPos uint64
	if from != 0 {
		fromPos = r.revs[from].key.pos
	}
	r.must(r.s.RevsBetween(r.ctx, k.ns, k.name, fromPos, r.revs[max].key.pos, limit, func(ri *ddb.RevInfo) bool {
		return visit(r.revRowOf(k.ns, ri))
	}))
}

func (r *ddbReads) nsLogRows(n *nsRow, from, to int64, limit int, visit func(nsLogRow) bool) {
	ns := r.nsName(n.id)
	var fromPos uint64
	if from != 0 {
		fromPos = r.logs[from].pos
	}
	r.must(r.s.EntriesBetween(r.ctx, ns, fromPos, r.logs[to].pos, limit, func(le *ddb.EntryRow) bool {
		id, err := ids.Parse(le.ID)
		r.must(err)
		row := nsLogRow{seq: r.logHandle(ns, le.Pos), id: id[:], body: le.Body, author: r.authorHandle(le.Author), created: le.Created}
		if le.PrevPos > 0 {
			p := r.logHandle(ns, le.PrevPos)
			row.prev = &p
		}
		if le.GrantID != "" {
			gid, err := ids.Parse(le.GrantID)
			r.must(err)
			row.grantID = gid[:]
		}
		if le.NoAuth {
			row.noAuth.Int64, row.noAuth.Valid = 1, true
		}
		// The members ns_log.gestures holds (gestureMeta, batchGestures).
		var meta map[string]any
		switch {
		case le.Gestures != "":
			meta = map[string]any{"gestures": jsonv.MustParse([]byte(le.Gestures))}
		case le.Gesture != "" || le.Undoes != "":
			meta = gestureMeta(le.Gesture, le.Undoes)
		}
		if meta != nil {
			row.meta.String, row.meta.Valid = string(jsonv.Canonical(meta)), true
		}
		return visit(row)
	}))
}

func (r *ddbReads) resState(res int64) int {
	if r.purgedRes(res) {
		return statePurged
	}
	return stateLive
}

// purgedRes reports whether resource handle res is purged.
func (r *ddbReads) purgedRes(res int64) bool {
	rr, ok := r.resRows[res]
	if !ok {
		k := r.res[res]
		var err error
		rr, err = r.s.Resource(r.ctx, k.ns, k.name)
		r.must(err)
		r.resRows[res] = rr
	}
	return rr != nil && rr.Purged
}

func (r *ddbReads) entryConfig(seq int64) (int64, string) {
	k := r.logs[seq]
	le := r.entry(seq)
	if le == nil {
		panic(fmt.Errorf("ddb: entry %d missing", seq))
	}
	h := r.cfgHandle(k.ns, le.CfgPos)
	return h, string(jsonv.Canonical(r.cfgRow(h).Doc))
}

func (r *ddbReads) resJob(n *nsRow, name string, row *revRow, kind string, plain func() []byte) *sealJob {
	panic(ddbUnsupported("sealed namespaces"))
}
func (r *ddbReads) stored(n *nsRow, j *sealJob) bool   { panic(ddbUnsupported("sealed namespaces")) }
func (r *ddbReads) entryEpoch(n *nsRow, seq int64) int { panic(ddbUnsupported("sealed namespaces")) }
func (r *ddbReads) epochKey(ns int64, epoch int) []byte {
	panic(ddbUnsupported("sealed namespaces"))
}
func (r *ddbReads) e2eSnapshot(row *revRow) string  { panic(ddbUnsupported("e2e namespaces")) }
func (r *ddbReads) e2eFoldSince(row *revRow) string { panic(ddbUnsupported("e2e namespaces")) }

func (r *ddbReads) allNamespaces() []*nsRow {
	var out []*nsRow
	for _, name := range r.nsNames() {
		if n := r.nsByName(name); n != nil && !n.purged && !strings.HasPrefix(name, "~") {
			out = append(out, n)
		}
	}
	return out
}

// schemaPinsIn: n's schema reference markers, of its unpurged resources.
func (r *ddbReads) schemaPinsIn(n *nsRow) []schemaUse {
	ns := r.nsName(n.id)
	pins, err := r.s.SchemaRefs(r.ctx, ns, "")
	r.must(err)
	var out []schemaUse
	for _, p := range pins {
		if !r.purgedRes(r.resHandle(ns, p.Name)) {
			out = append(out, schemaUse{name: p.Name, ref: p.Ref})
		}
	}
	return out
}

// --- branches ---

func (r *ddbReads) configGenesis(n *nsRow) (int64, int64, ids.ID, bool) {
	ns := r.nsName(n.id)
	h := r.cfgHandle(ns, 1)
	c := r.cfgRow(h)
	id, err := ids.Parse(c.ID)
	r.must(err)
	return h, r.authorHandle(c.Author), id, true
}

// branchEntry: the base lists its branches with the entry that created
// each (BRANCH#).
func (r *ddbReads) branchEntry(base *nsRow, gseq int64) (int64, bool) {
	bname := r.nsName(base.id)
	b, err := r.s.Branch(r.ctx, bname, r.cfgs[gseq].ns)
	r.must(err)
	if b == nil {
		return 0, false
	}
	return r.logHandle(bname, b.EntryPos), true
}

// liveRegistrations: no remote branches here.
func (r *ddbReads) liveRegistrations(n *nsRow) []map[string]any { return nil }

// readThrough completes the view of a resource n has no head of: in a
// branch, the base's as of the entry it branched at (resolve of
// resolve.go); NotFound elsewhere.
func (r *ddbReads) readThrough(n *nsRow, v *view) *view {
	if !n.isBranch() {
		v.state = NotFound
		return v
	}
	at := n.baseAt.Int64
	bv := r.resolve(r.nsByID(n.base.Int64), v.name, &at)
	v.state, v.head, v.src = bv.state, bv.head, bv.src
	return v
}
