package core

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

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
	// resRows are the resources read, by handle: the commit pins them.
	resRows map[int64]*ddb.ResRow
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

func newDDBReads(e *Engine, ctx context.Context) *ddbReads {
	return &ddbReads{
		e: e, s: e.ddb.store, ctx: ctx,
		nss: map[int64]*ddbNS{}, nsNamed: map[string]int64{},
		cfgs: map[int64]ddbCfgRef{}, cfgAt: map[ddbPosKey]int64{},
		revs: map[int64]*ddbRevRef{}, revAt: map[ddbRevKey]int64{},
		res: map[int64]ddbResRef{}, resAt: map[ddbResRef]int64{},
		authors: map[int64]string{}, authorN: map[string]int64{},
		logs: map[int64]ddbPosKey{}, logAt: map[ddbPosKey]int64{},
		resRows: map[int64]*ddb.ResRow{},
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

func (r *ddbReads) logHandle(ns string, pos uint64) int64 {
	k := ddbPosKey{ns, pos}
	if h, ok := r.logAt[k]; ok {
		return h
	}
	h := r.handle()
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

func (r *ddbReads) revHandle(ns, name string, pos uint64) int64 {
	k := ddbRevKey{ns, name, pos}
	if h, ok := r.revAt[k]; ok {
		return h
	}
	h := r.handle()
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
	if ri.Pos > 1 {
		row.parentSeq.Int64, row.parentSeq.Valid = r.revHandle(ns, ri.Name, ri.Pos-1), true
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
func (r *ddbReads) nsRowUnlocked(id int64) *nsRow          { return r.nsByID(id) }
func (r *ddbReads) lockNS(ns int64, mode lockMode)         {}
func (r *ddbReads) branchesOf(n *nsRow) []*nsRow           { return nil }
func (r *ddbReads) baseIdentity(n *nsRow) string           { panic(ddbUnsupported("branches")) }
func (r *ddbReads) schemaNS(name string) *nsRow            { panic(ddbUnsupported("$schema validation")) }
func (r *ddbReads) prefetchResources(int64, []string)      {}
func (r *ddbReads) prefetchHeads(*nsRow, []string, *int64) {}
func (r *ddbReads) prefetchSchemas([]schema.Ref)           {}
func (r *ddbReads) schemaUses(func(ns *nsRow, res string) bool) map[string]map[int64]*nsRow {
	return map[string]map[int64]*nsRow{}
}

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
	b := r.e.ddb
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
	if asOf != nil {
		panic(ddbUnsupported("reads as of an earlier entry"))
	}
	ns := r.nsName(n.id)
	v := &view{ns: n, name: name}
	rr, err := r.s.Resource(r.ctx, ns, name)
	r.must(err)
	if rr == nil {
		v.state = NotFound
		return v
	}
	rh := r.resHandle(ns, name)
	r.resRows[rh] = rr
	hh := r.revHandle(ns, name, rr.HeadPos)
	own := &resRow{id: rh, name: name, state: stateLive}
	own.headSeq.Int64, own.headSeq.Valid = hh, true
	v.own, v.src = own, own
	v.head = r.rev(hh)
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

// A resource's chain is one segment: there are no foreign parents
// without branches (§7.6).
func (r *ddbReads) ancestry(head *revRow) []segment {
	return []segment{{res: head.res, max: head.seq}}
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

func (r *ddbReads) namesAfter(n *nsRow, after string, k int) []string {
	heads, _, err := r.s.ListHeads(r.ctx, r.nsName(n.id), after, k)
	r.must(err)
	out := make([]string, len(heads))
	for i, h := range heads {
		out[i] = h.Name
	}
	return out
}

func (r *ddbReads) copyRows(id ids.ID, name string) []copyRow { return nil }

// --- authors ---

func (r *ddbReads) actorID(a *actor) int64 { return r.authorHandle(a.id()) }

func (r *ddbReads) authorName(id int64) string { return r.authors[id] }

// --- what this backend doesn't store ---

func (r *ddbReads) archiveURL(res, seq int64) string { panic(ddbUnsupported("archives")) }
func (r *ddbReads) attachedBlob(res int64, bid ids.ID) *blobRow {
	panic(ddbUnsupported("blobs"))
}
func (r *ddbReads) pendingBlob(res int64, bid ids.ID, uploader string, cutoff int64) *blobRow {
	panic(ddbUnsupported("blobs"))
}
func (r *ddbReads) referencedUpTo(res, max int64, bid ids.ID) bool { panic(ddbUnsupported("blobs")) }
func (r *ddbReads) declaredAt(row *revRow) []ids.ID                { panic(ddbUnsupported("e2e namespaces")) }
func (r *ddbReads) dek(res int64, create bool) []byte              { panic(ddbUnsupported("encryption at rest")) }
func (r *ddbReads) e2eEpochOK(n *nsRow, cfg *Config, e int) bool {
	panic(ddbUnsupported("sealed namespaces"))
}
func (r *ddbReads) grantRef(id []byte) map[string]any {
	panic(ddbUnsupported("grants (" + hex.EncodeToString(id) + ")"))
}
func (r *ddbReads) checkAt(n *nsRow) func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error {
	panic(ddbUnsupported("grants"))
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
