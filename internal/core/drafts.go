package core

import (
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
)

// Draft schema revisions in branches (§6.1, §7.4, §F.9).
//
// A schema path /r/N/R/rev/X never names a branch. In a write to a branch,
// a path that N can't resolve is looked up among the candidates: the local
// branches of N, branches of branches included, that aren't e2e, and that
// serve the target (the target is the candidate or one of its branches, or
// is listed, with its branches, in the candidate's drafts.for). Only
// revisions a candidate wrote itself count: rows of its own resources, never
// what it reads through. The writer needs read on R in the candidate, with
// the request's grant or any in Source-Authorization.
//
// The same structure, without anyone's grants, decides whether a reference
// is satisfied: by an available copy of the revision in N, or, for a
// reference from a branch, in a candidate serving that branch. A purge or a
// config write that would leave a satisfied reference without a copy is
// refused with 409 in_use (brokenReferences).

// draftPatternRe is an entry of drafts.for: a namespace name, or a prefix of
// one ending in "*".
var draftPatternRe = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9_-]{0,63}|[a-z0-9_-]{0,63}\*)$`)

// parseDrafts parses a branch's drafts member (§7.4).
func parseDrafts(v any) ([]string, error) { return parseForList(v, "drafts") }

// parseSchemaReads parses a namespace's schemaReads member (§6.1, §7.4),
// shaped and matched like drafts.
func parseSchemaReads(v any) ([]string, error) { return parseForList(v, "schemaReads") }

// parseForList parses { "for": [names or prefixes ending in "*"] } at
// /member.
func parseForList(v any, member string) ([]string, error) {
	shape := `/` + member + ` must be { "for": [ namespace name or prefix ending in "*", … ] }`
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s", shape)
	}
	for k := range m {
		if k != "for" {
			return nil, fmt.Errorf("/%s/%s is not a known field", member, k)
		}
	}
	arr, ok := m["for"].([]any)
	if !ok {
		return nil, fmt.Errorf("%s", shape)
	}
	out := []string{}
	for i, x := range arr {
		s, ok := x.(string)
		if !ok || !draftPatternRe.MatchString(s) {
			return nil, fmt.Errorf("/%s/for/%d must be a namespace name or a prefix ending in \"*\"", member, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// DraftsMatch reports whether a drafts.for list names a namespace, by name
// or by a prefix ending in "*" (§7.4).
func DraftsMatch(list []string, ns string) bool {
	for _, p := range list {
		if pre, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(ns, pre) {
				return true
			}
		} else if p == ns {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nsRowUnlocked reads a namespace row without taking its lock: for the
// structural scans of purges, which lock what they rely on themselves.
// (What walks a chain of bases, which never changes, reads its links:
// chain.go.)
func (t *tx) nsRowUnlocked(id int64) *nsRow {
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE ns = ?`, id))
	t.must(err)
	return n
}

// draftRoot is the namespace whose schema paths n's own revisions may serve
// as drafts: the root of n's chain of local bases. "" if n isn't a local
// branch.
func (t *tx) draftRoot(n *nsRow) string {
	if !n.isBranch() {
		return ""
	}
	b := linkOf(n)
	for b.isBranch() {
		b = t.link(b.base.Int64)
	}
	return b.name
}

// cfgOf is n's namespace document, or the one a pending change writes.
func (t *tx) cfgOf(n *nsRow, over map[int64]*Config) *Config {
	if c, ok := over[n.id]; ok {
		return c
	}
	return t.config(n.configSeq)
}

// isDraftCandidate reports whether c may hold drafts for schema paths of
// namespace root: a local branch of it, not purged, not e2e.
func (t *tx) isDraftCandidate(c *nsRow, root string, over map[int64]*Config) bool {
	return c.isBranch() && !c.purged && t.cfgOf(c, over).level != levelE2E && t.draftRoot(c) == root
}

// draftsServe reports whether candidate c, under its namespace document
// ccfg, serves writes to w: w is c or one of its branches, or w or one of
// its bases is listed in ccfg's drafts.for (§6.1).
func (t *tx) draftsServe(c *nsRow, ccfg *Config, w *nsRow) bool {
	for x := linkOf(w); ; {
		if x.id == c.id || DraftsMatch(ccfg.DraftsFor, x.name) {
			return true
		}
		if !x.isBranch() {
			return false
		}
		x = t.link(x.base.Int64)
	}
}

// schemaReadsServe reports whether n's schemaReads opens its schema
// revisions for writes to w (§6.1): w is n, or listed in schemaReads.for,
// or a local branch of such a namespace, branches of branches included.
// schemaReads.for is never matched against a branch: a branch qualifies
// only through the namespace at the root of its chain of local bases.
func (t *tx) schemaReadsServe(n *nsRow, w *nsRow) bool {
	cfg := t.config(n.configSeq)
	if cfg.SchemaReadsFor == nil || cfg.level >= levelSealed || n.isBranch() {
		return false
	}
	for x := linkOf(w); ; {
		if !x.isBranch() {
			return x.id == n.id || DraftsMatch(cfg.SchemaReadsFor, x.name)
		}
		x = t.link(x.base.Int64)
	}
}

// copyRow is a revisions row with a given id in a resource of a given name,
// anywhere in the deployment (revisions_by_id, D.2).
type copyRow struct {
	seq, ns, res int64
	state        int
}

func (t *tx) copyRows(id ids.ID, name string) []copyRow {
	rows, err := t.Query(`SELECT r.seq, s.ns, s.res, s.state FROM revisions r JOIN resources s ON s.res = r.res
		WHERE r.id = ? AND s.name = ? AND r.kind = 0 ORDER BY s.ns, r.seq`, id[:], name)
	t.must(err)
	defer rows.Close()
	var out []copyRow
	for rows.Next() {
		var c copyRow
		t.must(rows.Scan(&c.seq, &c.ns, &c.res, &c.state))
		out = append(out, c)
	}
	t.must(rows.Err())
	return out
}

// credsRead reports whether any of creds may read resource name of n
// (§C.2): a grant that names n and verifies under its keys.
func (t *tx) credsRead(n *nsRow, name string, creds []Credentials) bool {
	if t.e.opt.AuthDisabled || t.config(n.configSeq).Read == "public" {
		return true
	}
	for _, c := range creds {
		if c.Bearer == "" {
			continue
		}
		if _, err := t.reader(n, c, name); err == nil {
			return true
		}
	}
	return false
}

// credsReadRow is credsRead for one revision or tombstone, row, of name:
// a grant that may read name and whose read rules allow reading row
// (§C.2 item 5), as resolving a schema revision takes (§6.1 Read
// permission).
func (t *tx) credsReadRow(n *nsRow, name string, row *revRow, creds []Credentials) bool {
	if t.e.opt.AuthDisabled || t.config(n.configSeq).Read == "public" {
		return true
	}
	for _, c := range creds {
		if c.Bearer == "" {
			continue
		}
		if a, err := t.reader(n, c, name); err == nil && t.mayReadRow(a, n, name, row) {
			return true
		}
	}
	return false
}

// credsReadBlob reports whether any of creds may read blob bid of name in
// n as its stored documents that reference it decide (mayReadBlob, §7.8):
// a copy from it is 404 where only revisions a grant can't read do.
func (t *tx) credsReadBlob(n *nsRow, name string, bid ids.ID, creds []Credentials) bool {
	if t.e.opt.AuthDisabled || t.config(n.configSeq).Read == "public" {
		return true
	}
	for _, c := range creds {
		if c.Bearer == "" {
			continue
		}
		if a, err := t.reader(n, c, name); err == nil && t.mayReadBlob(a, n, name, bid) {
			return true
		}
	}
	return false
}

// credsReadAny reports whether any of creds may read anything in m: some
// resource of it (the rule for other namespaces, §7.5), for the
// referencing namespaces an in_use answer lists (§6.1).
func (t *tx) credsReadAny(m *nsRow, creds []Credentials) bool {
	if t.e.opt.AuthDisabled || t.config(m.configSeq).Read == "public" {
		return true
	}
	cfg := t.config(m.configSeq)
	var names []string
	for _, c := range creds {
		if c.Bearer == "" {
			continue
		}
		g, err := t.decodeGrant(m.name, c)
		if err != nil {
			continue // doesn't name m, or isn't a grant
		}
		ma, err := t.verifyGrant(g, m.name, m, cfg, nil)
		if err != nil {
			continue
		}
		t.e.bearers.put(c.Bearer, g)
		if t.canRead(m, cfg, ma, "") {
			return true // no rule ties it to a resource
		}
		if !ma.verified.Can["read"] {
			continue
		}
		if names == nil {
			names = t.resourceNames(m, 1000)
		}
		for _, name := range names {
			if t.canRead(m, cfg, ma, name) {
				return true
			}
		}
	}
	return false
}

// resourceNames lists up to limit resource names of m and the bases it
// reads through.
func (t *tx) resourceNames(m *nsRow, limit int) []string {
	var out []string
	for _, h := range t.listHeads(m, nil) {
		if h.state != Purged {
			out = append(out, h.name)
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

// schemaCtx is who resolves schema paths, for which namespace (§6.1).
type schemaCtx struct {
	a      *actor
	target *nsRow
	// creds are the request's grant and those of Source-Authorization:
	// any that verifies for a candidate branch reads drafts there.
	creds []Credentials
	// source is a batch's local source the writer reads unrestricted
	// (checkSource), whose revisions a write may copy (copiesIn); nil if
	// none.
	source *batchSource
	// copied are the rules markers docRules fixed, by revision id; copies
	// the namespaces a copy inherits a marker from (copiesIn), once known.
	copied map[ids.ID]schema.Rules
	copies []int64
}

// copiesIn lists the namespaces whose revisions a write may copy by id,
// inheriting their rules marker (docRules): the namespace written and its
// bases, which it reads through, and a batch's local source, read
// unrestricted, and its bases.
func (sc *schemaCtx) copiesIn(t *tx) []int64 {
	if sc.copies != nil {
		return sc.copies
	}
	sc.copies = []int64{}
	add := func(n *nsRow) {
		for x := linkOf(n); ; x = t.link(x.base.Int64) {
			sc.copies = append(sc.copies, x.id)
			if !x.isBranch() {
				return
			}
		}
	}
	if sc.target != nil {
		add(sc.target)
	}
	if sc.source != nil && sc.source.n != nil {
		add(sc.source.n)
	}
	return sc.copies
}

// loadDraft looks a schema revision up among the candidates serving the
// write's target (§6.1), and returns it with the row it was read from.
// Each namespace holding a copy is locked shared and read as of its lock
// (D.8). A revision the writer can't read there counts as not found.
func (t *tx) loadDraft(ref schema.Ref, sc *schemaCtx) (any, int64, bool) {
	if sc == nil || sc.target == nil || !sc.target.isBranch() {
		return nil, 0, false
	}
	id, err := ids.Parse(ref.Rev)
	if err != nil {
		return nil, 0, false
	}
	for _, cr := range t.copyRows(id, ref.Name) {
		if cr.state == statePurged {
			continue
		}
		c := t.nsByID(cr.ns)
		if !t.isDraftCandidate(c, ref.NS, nil) || !t.draftsServe(c, t.config(c.configSeq), sc.target) {
			continue
		}
		row := t.rev(cr.seq)
		if !t.credsReadRow(c, ref.Name, row, sc.creds) {
			continue
		}
		if !t.schemaKeysOpen(c, ref.Name, row, sc) {
			continue // a sealed candidate's draft takes keys (§6.1)
		}
		d, err := t.docAt(row)
		if err != nil {
			continue
		}
		return d, row.seq, true
	}
	return nil, 0, false
}

// pendingNS is the namespace of the schema paths under which the documents
// a write's steps write in namespace n may be referenced by later items of
// the same write (§7.5): n itself, or in a local branch its root, as
// drafts serving the branch itself (§6.1). "" if none.
func (t *tx) pendingNS(n *nsRow) string {
	if !n.isBranch() {
		return n.name
	}
	if ns := t.draftRoot(n); ns != "" && !t.isE2E(n) {
		return ns
	}
	return ""
}

// pendingKey is the schema path of a step's document under pendingNS ns,
// or "" if ns is.
func pendingKey(ns, resource string, id ids.ID) string {
	if ns == "" {
		return ""
	}
	return "/r/" + ns + "/" + resource + "/rev/" + id.String()
}

// --- references and copies (§6.1 Purged or unknown references) -------------

// schemaCopy is an available copy of a schema revision.
type schemaCopy struct {
	ns  *nsRow
	seq int64
}

// satisfyingCopies lists the available copies, among rows, that satisfy a
// reference to ref from namespace m: in ref's namespace itself, or, for a
// branch, in a candidate serving it. over replaces namespace documents a
// pending config write changes. Structural: nobody's grants are consulted.
func (t *tx) satisfyingCopies(ref schema.Ref, m *nsRow, over map[int64]*Config, rows []copyRow) []schemaCopy {
	var out []schemaCopy
	for _, cr := range rows {
		if cr.state == statePurged {
			continue
		}
		c := t.nsRowUnlocked(cr.ns)
		if c.purged {
			continue
		}
		switch {
		case !c.isBranch() && c.name == ref.NS:
			if t.cfgOf(c, over).level == levelE2E {
				continue // the server can't read it (§E.3.2)
			}
		case m.isBranch() && t.isDraftCandidate(c, ref.NS, over) && t.draftsServe(c, t.cfgOf(c, over), m):
		default:
			continue
		}
		if _, err := t.docBytesAt(t.rev(cr.seq)); err != nil {
			continue // purged or pruned
		}
		out = append(out, schemaCopy{c, cr.seq})
	}
	return out
}

// schemaUses lists the referenced schema revisions of §6.1, by path, with
// the namespaces referencing each: $schema of the last live document of
// every unpurged resource (read-through ones as of the branch's at), for a
// branch also of every revision it wrote, and the $ref closure of those,
// resolved as the referencing namespace would. exclude skips referencing
// resources.
func (t *tx) schemaUses(exclude func(ns *nsRow, res string) bool) map[string]map[int64]*nsRow {
	// Nothing read here is locked (on Postgres, pglock.go): a write that
	// makes a schema referenced holds the lock of the namespace it resolved
	// it in shared, and purges hold that lock exclusively, or take it
	// shared before relying on a copy (brokenReferences).
	t.noLock++
	defer func() { t.noLock-- }()
	t.e.schemaScans.Add(1)
	rows, err := t.Query(`SELECT ` + nsCols + ` FROM namespaces WHERE purged = 0`)
	t.must(err)
	var all []*nsRow
	for rows.Next() {
		n, err := scanNS(rows)
		t.must(err)
		all = append(all, n)
	}
	rows.Close()
	uses := map[string]map[int64]*nsRow{}
	copies := map[string][]copyRow{}
	docs := map[string]any{}
	for _, n := range all {
		var queue []string
		add := func(p string) {
			if uses[p] == nil {
				uses[p] = map[int64]*nsRow{}
			}
			if uses[p][n.id] == nil {
				uses[p][n.id] = n
				queue = append(queue, p)
			}
		}
		for _, h := range t.listHeads(n, nil) {
			if h.state == Purged || h.row == nil || exclude(n, h.name) {
				continue
			}
			var ref sql.NullString
			ll := t.lastLive(h.row)
			t.must(t.QueryRow(`SELECT schema_ref FROM revisions WHERE seq = ?`, ll.seq).Scan(&ref))
			if ref.Valid {
				add(ref.String)
			}
		}
		if n.isBranch() {
			// Every revision a branch wrote: a merge replays and validates
			// every step (§7.5).
			rr, err := t.Query(`SELECT DISTINCT s.name, r.schema_ref FROM revisions r JOIN resources s ON s.res = r.res
				WHERE s.ns = ? AND s.state <> ? AND r.schema_ref IS NOT NULL`, n.id, statePurged)
			t.must(err)
			type use struct{ name, ref string }
			var us []use
			for rr.Next() {
				var u use
				t.must(rr.Scan(&u.name, &u.ref))
				us = append(us, u)
			}
			t.must(rr.Err())
			rr.Close()
			for _, u := range us {
				if !exclude(n, u.name) {
					add(u.ref)
				}
			}
		}
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			ref, ok := schema.ParseRef(p)
			if !ok {
				continue
			}
			d, ok := docs[p]
			if !ok {
				cr, ok := copies[p]
				if !ok {
					if id, err := ids.Parse(ref.Rev); err == nil {
						cr = t.copyRows(id, ref.Name)
					}
					copies[p] = cr
				}
				cs := t.satisfyingCopies(ref, n, nil, cr)
				if len(cs) == 0 {
					continue
				}
				var err error
				if d, err = t.docAt(t.rev(cs[0].seq)); err != nil {
					continue
				}
				docs[p] = d // an id determines its document everywhere (§3.3)
			}
			for _, x := range schema.Refs(d) {
				add(x.Path())
			}
		}
	}
	return uses
}

// possiblyReferenced lists every schema revision path a document of the
// deployment may reference: a superset of schemaUses' paths, at the cost
// of one index probe per distinct $schema stored and, the first time, one
// read per schema revision, whatever the number of namespaces and
// documents. It takes every revision's $schema (schemaUses: the last live
// ones of unpurged resources, and those a branch wrote) and follows $ref
// from any readable copy (schemaUses: from a copy that satisfies the
// referencing namespace).
func (t *tx) possiblyReferenced() []string {
	t.noLock++ // as schemaUses
	defer func() { t.noLock-- }()
	seen := map[string]bool{}
	var out []string
	for last := ""; ; {
		// The next distinct value in revisions_schema_ref's order.
		var v sql.NullString
		t.must(t.QueryRow(`SELECT min(schema_ref) FROM revisions WHERE schema_ref IS NOT NULL AND schema_ref > ?`, last).Scan(&v))
		if !v.Valid {
			break
		}
		last = v.String
		seen[last] = true
		out = append(out, last)
	}
	for i := 0; i < len(out); i++ {
		for _, x := range t.schemaRefsOf(out[i]) {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// schemaRefsOf is the paths the schema revision at path p references by
// $ref, read from any copy of it. A revision's id determines its document
// everywhere (§3.3), so what was read once is kept for the engine's life;
// a revision with no readable copy is looked for again each time.
func (t *tx) schemaRefsOf(p string) []string {
	t.e.refsMu.Lock()
	refs, ok := t.e.refsCache.Get(p)
	t.e.refsMu.Unlock()
	if ok {
		return refs
	}
	ref, ok := schema.ParseRef(p)
	if !ok {
		return nil
	}
	id, err := ids.Parse(ref.Rev)
	if err != nil {
		return nil
	}
	for _, cr := range t.copyRows(id, ref.Name) {
		if cr.state == statePurged {
			continue
		}
		d, err := t.docAt(t.rev(cr.seq))
		if err != nil {
			continue
		}
		refs = []string{}
		for _, x := range schema.Refs(d) {
			refs = append(refs, x.Path())
		}
		t.e.refsMu.Lock()
		t.e.refsCache.Put(p, refs, 0)
		t.e.refsMu.Unlock()
		return refs
	}
	return nil
}

// touchedPaths lists the schema revision paths anything may reference of
// which ch touches a copy: brokenReferences' own test of a path, over
// possiblyReferenced's superset. None means brokenReferences is empty.
func (t *tx) touchedPaths(ch refChange) []string {
	t.noLock++
	defer func() { t.noLock-- }()
	var out []string
	for _, p := range t.possiblyReferenced() {
		ref, ok := schema.ParseRef(p)
		if !ok || ch.name != "" && ref.Name != ch.name {
			continue
		}
		id, err := ids.Parse(ref.Rev)
		if err != nil {
			continue
		}
		for _, cr := range t.copyRows(id, ref.Name) {
			if _, ok := ch.cfg[cr.ns]; ok || ch.removed(t.nsRowUnlocked(cr.ns), ref.Name) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// schemaUsesOf is schemaUses for the paths in targets alone, at the cost
// of what references them and not of the deployment. A namespace
// references a target through a chain of $refs that starts at a $schema
// it holds or reads through, every path of which reaches the target in
// possiblyReferenced's graph. So only those paths' revisions are looked
// at: the resources holding one, in the namespaces that hold or read them
// through, resolved as schemaUses resolves every resource.
func (t *tx) schemaUsesOf(targets []string, exclude func(ns *nsRow, res string) bool) map[string]map[int64]*nsRow {
	uses := map[string]map[int64]*nsRow{}
	w := t.usesWalkOf(targets, exclude)
	for _, n := range w.all {
		for _, p := range w.of(n) {
			if uses[p] == nil {
				uses[p] = map[int64]*nsRow{}
			}
			uses[p][n.id] = n
		}
	}
	return uses
}

// usesWalk is schemaUsesOf a namespace at a time: all the deployment's
// namespaces in byte order of name, and of(n) the paths n uses. A caller
// that needs only the first few referencing namespaces by name stops
// there, at the cost of those it looked at (brokenEach).
type usesWalk struct {
	t       *tx
	exclude func(ns *nsRow, res string) bool
	reach   map[string]bool           // the paths that reach a target
	holds   map[int64]map[string]bool // by namespace, the resources with a revision whose $schema is one
	all     []*nsRow                  // by name; none if nothing holds one
	byID    map[int64]*nsRow
	copies  map[string][]copyRow
	docs    map[string]any
}

func (t *tx) usesWalkOf(targets []string, exclude func(ns *nsRow, res string) bool) *usesWalk {
	w := &usesWalk{t: t, exclude: exclude, byID: map[int64]*nsRow{}, copies: map[string][]copyRow{}, docs: map[string]any{}}
	if len(targets) == 0 {
		return w
	}
	t.noLock++ // as schemaUses
	defer func() { t.noLock-- }()
	// The paths that reach a target, the targets among them.
	back := map[string][]string{}
	for _, q := range t.possiblyReferenced() {
		for _, x := range t.schemaRefsOf(q) {
			back[x] = append(back[x], q)
		}
	}
	reach := map[string]bool{}
	queue := append([]string(nil), targets...)
	for _, p := range targets {
		reach[p] = true
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, q := range back[p] {
			if !reach[q] {
				reach[q] = true
				queue = append(queue, q)
			}
		}
	}
	// The resources with a revision whose $schema is one of them, by
	// namespace (revisions_schema_ref).
	holds := map[int64]map[string]bool{}
	for _, q := range sortedKeys(reach) {
		rows, err := t.Query(`SELECT DISTINCT s.ns, s.name FROM revisions r JOIN resources s ON s.res = r.res WHERE r.schema_ref = ?`, q)
		t.must(err)
		for rows.Next() {
			var ns int64
			var name string
			t.must(rows.Scan(&ns, &name))
			if holds[ns] == nil {
				holds[ns] = map[string]bool{}
			}
			holds[ns][name] = true
		}
		t.must(rows.Err())
		rows.Close()
	}
	if len(holds) == 0 {
		return w
	}
	w.reach, w.holds = reach, holds
	rows, err := t.Query(`SELECT ` + nsCols + ` FROM namespaces`)
	t.must(err)
	for rows.Next() {
		n, err := scanNS(rows)
		t.must(err)
		w.all = append(w.all, n)
		w.byID[n.id] = n
	}
	t.must(rows.Err())
	rows.Close()
	sort.Slice(w.all, func(i, j int) bool { return w.all[i].name < w.all[j].name })
	return w
}

// of is the paths that reach a target which n references (schemaUses'
// rule for one namespace), in no order; none for a purged namespace.
func (w *usesWalk) of(n *nsRow) []string {
	t, exclude, reach, holds, byID, copies, docs := w.t, w.exclude, w.reach, w.holds, w.byID, w.copies, w.docs
	t.noLock++ // as schemaUses
	defer func() { t.noLock-- }()
	var out []string
	used := map[string]bool{}
	if n.purged {
		return nil
	}
	// What n holds or reads through of those resources.
	names := map[string]bool{}
	for m := n; m != nil; m = byID[m.base.Int64] {
		for name := range holds[m.id] {
			names[name] = true
		}
		if !m.isBranch() {
			break
		}
	}
	if len(names) == 0 {
		return nil
	}
	var queue []string
	add := func(p string) {
		if !reach[p] {
			return
		}
		if !used[p] {
			used[p] = true
			out = append(out, p)
			queue = append(queue, p)
		}
	}
	for _, name := range sortedKeys(names) {
		if exclude(n, name) {
			continue
		}
		v := t.resolve(n, name, nil)
		if v.state == NotFound || v.state == Purged || v.head == nil {
			continue
		}
		var ref sql.NullString
		ll := t.lastLive(v.head)
		t.must(t.QueryRow(`SELECT schema_ref FROM revisions WHERE seq = ?`, ll.seq).Scan(&ref))
		if ref.Valid {
			add(ref.String)
		}
	}
	if n.isBranch() && holds[n.id] != nil {
		// Every revision a branch wrote (schemaUses).
		rr, err := t.Query(`SELECT DISTINCT s.name, r.schema_ref FROM revisions r JOIN resources s ON s.res = r.res
			WHERE s.ns = ? AND s.state <> ? AND r.schema_ref IS NOT NULL`, n.id, statePurged)
		t.must(err)
		type use struct{ name, ref string }
		var us []use
		for rr.Next() {
			var u use
			t.must(rr.Scan(&u.name, &u.ref))
			us = append(us, u)
		}
		t.must(rr.Err())
		rr.Close()
		for _, u := range us {
			if !exclude(n, u.name) {
				add(u.ref)
			}
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		ref, ok := schema.ParseRef(p)
		if !ok {
			continue
		}
		d, ok := docs[p]
		if !ok {
			cr, ok := copies[p]
			if !ok {
				if id, err := ids.Parse(ref.Rev); err == nil {
					cr = t.copyRows(id, ref.Name)
				}
				copies[p] = cr
			}
			cs := t.satisfyingCopies(ref, n, nil, cr)
			if len(cs) == 0 {
				continue
			}
			var err error
			if d, err = t.docAt(t.rev(cs[0].seq)); err != nil {
				continue
			}
			docs[p] = d
		}
		for _, x := range schema.Refs(d) {
			add(x.Path())
		}
	}
	return out
}

// SchemaScans is the number of passes over every document of the
// deployment made for schema references so far (schemaUses), for tests.
func (e *Engine) SchemaScans() int64 { return e.schemaScans.Load() }

// referencedPaths is the set of referenced schema revision paths (§6.1).
func (t *tx) referencedPaths() map[string]bool {
	out := map[string]bool{}
	for p := range t.schemaUses(func(*nsRow, string) bool { return false }) {
		out[p] = true
	}
	return out
}

// referencedOf is the referenced schema revision paths (§6.1) among the
// revisions of resource name of namespace ns: referencedPaths' of that
// resource, without its pass over every document.
func (t *tx) referencedOf(ns, name string) map[string]bool {
	var targets []string
	for _, p := range t.possiblyReferenced() {
		if ref, ok := schema.ParseRef(p); ok && ref.NS == ns && ref.Name == name {
			targets = append(targets, p)
		}
	}
	out := map[string]bool{}
	for p := range t.schemaUsesOf(targets, func(*nsRow, string) bool { return false }) {
		out[p] = true
	}
	if validateBoth {
		prefix, full := "/r/"+ns+"/"+name+"/rev/", t.referencedPaths()
		for p := range full {
			if strings.HasPrefix(p, prefix) && !out[p] {
				panic("referencedOf: missed " + p)
			}
		}
		for p := range out {
			if !full[p] {
				panic("referencedOf: " + p + " isn't referenced")
			}
		}
	}
	return out
}

// refChange describes what a purge or config write would change, for
// brokenReferences.
type refChange struct {
	// exclude: referencing resources the change removes.
	exclude func(ns *nsRow, res string) bool
	// removed: copies the change removes (by namespace and resource name).
	removed func(ns *nsRow, res string) bool
	// cfg: namespace documents the change writes.
	cfg map[int64]*Config
	// name: the only resource name removed answers true for, if the
	// change removes copies of one name alone.
	name string
}

// brokenReferences returns the namespaces holding a reference that a copy
// satisfies now and none would after the change (§6.1), in byte order of
// name. Every other namespace holding a copy of a revision the change
// touches is locked shared before its copy is relied on (D.8), so two
// purges can't each remove one of the last two copies.
func (t *tx) brokenReferences(ch refChange) []*nsRow {
	out := []*nsRow{}
	t.brokenEach(&ch, func(m *nsRow) bool {
		out = append(out, m)
		return true
	})
	if validateBoth {
		full := t.brokenByEveryDocument(ch)
		same := len(full) == len(out)
		for i := 0; same && i < len(full); i++ {
			same = full[i].id == out[i].id
		}
		if !same {
			panic(fmt.Sprintf("brokenReferences: %d namespaces by what references the touched revisions, %d by every document", len(out), len(full)))
		}
	}
	return out
}

// brokenByEveryDocument is brokenReferences from a pass over every
// document of the deployment, the PATCHLOG_TEST_VALIDATE_BOTH oracle of
// brokenEach. Its statements aren't a purge's: tests that count
// statements don't see them (asOracle).
func (t *tx) brokenByEveryDocument(ch refChange) []*nsRow {
	none := func(*nsRow, string) bool { return false }
	if ch.exclude == nil {
		ch.exclude = none
	}
	if ch.removed == nil {
		ch.removed = none
	}
	t.oracle++
	defer func() { t.oracle-- }()
	return t.brokenAmong(ch, t.schemaUses(ch.exclude))
}

// brokenEach calls visit with each namespace of brokenReferences, in byte
// order of name, until visit answers false. Namespaces are judged one at
// a time in that order, each by what it references (usesWalk), so a
// caller that stops after the first few pays for the namespaces up to
// there and not for every reference in the deployment: a refusal lists a
// page of them (refsInUse). A walk that isn't stopped locks the copies it
// relies on as brokenReferences says.
//
// Most changes touch no schema revision anything references, and one
// that does is judged by what references those revisions: neither reads
// every document of the deployment (touchedPaths, usesWalkOf).
func (t *tx) brokenEach(ch *refChange, visit func(m *nsRow) bool) {
	none := func(*nsRow, string) bool { return false }
	if ch.exclude == nil {
		ch.exclude = none
	}
	if ch.removed == nil {
		ch.removed = none
	}
	touched := t.touchedPaths(*ch)
	if len(touched) == 0 {
		return
	}
	// A path's copies, and whether the change touches one, found once.
	type judged struct {
		ref     schema.Ref
		rows    []copyRow
		touched bool
	}
	paths := map[string]*judged{}
	path := func(p string) *judged {
		if j, ok := paths[p]; ok {
			return j
		}
		j := &judged{}
		paths[p] = j
		ref, ok := schema.ParseRef(p)
		if !ok {
			return j
		}
		id, err := ids.Parse(ref.Rev)
		if err != nil {
			return j
		}
		j.ref, j.rows = ref, t.copyRows(id, ref.Name)
		for _, cr := range j.rows {
			if _, ok := ch.cfg[cr.ns]; ok || ch.removed(t.nsRowUnlocked(cr.ns), ref.Name) {
				j.touched = true
				break
			}
		}
		if j.touched {
			for _, cr := range j.rows {
				if !ch.removed(t.nsRowUnlocked(cr.ns), ref.Name) {
					t.lockNS(cr.ns, lockShared)
				}
			}
		}
		return j
	}
	w := t.usesWalkOf(touched, ch.exclude)
	for _, m := range w.all {
		ps := w.of(m)
		sort.Strings(ps)
		broken := false
		for _, p := range ps {
			// Every touched path is looked up, and its copies locked,
			// whether or not an earlier one already breaks m.
			j := path(p)
			if !j.touched || broken {
				continue
			}
			if len(t.satisfyingCopies(j.ref, m, nil, j.rows)) == 0 {
				continue // not satisfied now: nothing to break
			}
			left := 0
			for _, c := range t.satisfyingCopies(j.ref, m, ch.cfg, j.rows) {
				if !ch.removed(c.ns, j.ref.Name) {
					left++
				}
			}
			broken = left == 0
		}
		if broken && !visit(m) {
			return
		}
	}
}

// brokenAmong is brokenReferences given the uses of the schema revisions
// (schemaUses, or schemaUsesOf the touched ones).
func (t *tx) brokenAmong(ch refChange, uses map[string]map[int64]*nsRow) []*nsRow {
	broken := map[int64]*nsRow{}
	for _, p := range sortedKeys(uses) {
		ref, ok := schema.ParseRef(p)
		if !ok {
			continue
		}
		id, err := ids.Parse(ref.Rev)
		if err != nil {
			continue
		}
		rows := t.copyRows(id, ref.Name)
		touched := false
		for _, cr := range rows {
			if _, ok := ch.cfg[cr.ns]; ok || ch.removed(t.nsRowUnlocked(cr.ns), ref.Name) {
				touched = true
				break
			}
		}
		if !touched {
			continue
		}
		for _, cr := range rows {
			if !ch.removed(t.nsRowUnlocked(cr.ns), ref.Name) {
				t.lockNS(cr.ns, lockShared)
			}
		}
		ms := make([]*nsRow, 0, len(uses[p]))
		for _, m := range uses[p] {
			ms = append(ms, m)
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].id < ms[j].id })
		for _, m := range ms {
			if broken[m.id] != nil {
				continue
			}
			if len(t.satisfyingCopies(ref, m, nil, rows)) == 0 {
				continue // not satisfied now: nothing to break
			}
			left := 0
			for _, c := range t.satisfyingCopies(ref, m, ch.cfg, rows) {
				if !ch.removed(c.ns, ref.Name) {
					left++
				}
			}
			if left == 0 {
				broken[m.id] = m
			}
		}
	}
	out := make([]*nsRow, 0, len(broken))
	for _, m := range broken {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// refsInUse is the 409 in_use of §6.1 for a change that would leave
// references without a copy, nil if it leaves none. It lists, as
// referencing, the referencing namespaces in which the caller may read
// anything, by the rule for other namespaces (§7.5), with the request's
// grant or any in Source-Authorization: the first logPageSize in byte
// order of name, with "more": true where the caller may read others
// (v0.86). So more never tells a caller that namespaces it can't read
// exist, and a caller who may read none gets [] without it.
//
// The search stops at the first readable namespace past the page: a
// refusal over a schema that thousands of namespaces reference costs a
// page of them. (A caller who may read few of them still has the search
// go on to the end.)
func (t *tx) refsInUse(ch refChange, msg string) *Error {
	// The list's judgments share one budget of validationSteps; where it
	// runs out the list ends there, without more (§6.6, v0.88).
	defer t.ownReadScope()()
	limit := t.e.opt.Maximums.LogPageSize
	names := []string{}
	found, more := false, false
	readable := map[int64]bool{}
	reads := func(m *nsRow) bool {
		r, ok := readable[m.id]
		if !ok {
			r = t.credsReadAny(m, t.reqCreds)
			readable[m.id] = r
		}
		return r
	}
	t.brokenEach(&ch, func(m *nsRow) bool {
		found = true
		if t.readSpent() {
			return false
		}
		if !reads(m) {
			return !t.readSpent()
		}
		if len(names) == limit {
			more = true
			return false
		}
		names = append(names, m.name)
		return true
	})
	if validateBoth {
		// The capped answer is a prefix of the whole one: the first page
		// of the namespaces every document gives that the caller may
		// read, and more exactly where there is another.
		full := t.brokenByEveryDocument(ch)
		want := []string{}
		wantMore := false
		for _, m := range full {
			if !reads(m) {
				continue
			}
			if len(want) == limit {
				wantMore = true
				break
			}
			want = append(want, m.name)
		}
		if found != (len(full) > 0) || !sameStrings(names, want) || more != wantMore {
			panic(fmt.Sprintf("refsInUse: referencing %v (more %v, any %v), by every document %v (more %v) of %d", names, more, found, want, wantMore, len(full)))
		}
	}
	if !found {
		return nil
	}
	e := apiErr(409, "in_use", "message", msg, "referencing", anyStrings(names))
	if more {
		e.Body["more"] = true
	}
	return e
}
