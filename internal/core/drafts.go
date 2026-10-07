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
// base chain, which never changes, and for the structural scans of purges,
// which lock what they rely on themselves.
func (t *tx) nsRowUnlocked(id int64) *nsRow {
	n, err := scanNS(t.QueryRow(`SELECT `+nsCols+` FROM namespaces WHERE ns = ?`, id))
	t.must(err)
	return n
}

// draftRoot is the namespace whose schema paths n's own revisions may serve
// as drafts: the root of n's chain of local bases. "" if n isn't a local
// branch (no base, or a remote base's shadow in its chain).
func (t *tx) draftRoot(n *nsRow) string {
	if !n.isBranch() || n.isShadow() {
		return ""
	}
	b := n
	for b.isBranch() {
		b = t.nsRowUnlocked(b.base.Int64)
		if b.isShadow() {
			return ""
		}
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
	return c.isBranch() && !c.purged && !c.isShadow() && t.cfgOf(c, over).level != levelE2E && t.draftRoot(c) == root
}

// draftsServe reports whether candidate c, under its namespace document
// ccfg, serves writes to w: w is c or one of its branches, or w or one of
// its bases is listed in ccfg's drafts.for (§6.1).
func (t *tx) draftsServe(c *nsRow, ccfg *Config, w *nsRow) bool {
	for x := w; ; {
		if x.id == c.id || DraftsMatch(ccfg.DraftsFor, x.name) {
			return true
		}
		if !x.isBranch() {
			return false
		}
		x = t.nsRowUnlocked(x.base.Int64)
		if x.isShadow() {
			return false
		}
	}
}

// schemaReadsServe reports whether n's schemaReads opens its schema
// revisions for writes to w (§6.1): w is n, or listed in schemaReads.for,
// or a local branch of such a namespace.
func (t *tx) schemaReadsServe(n *nsRow, w *nsRow) bool {
	cfg := t.config(n.configSeq)
	if cfg.SchemaReadsFor == nil || cfg.level >= levelSealed || n.isBranch() {
		return false
	}
	for x := w; ; {
		if x.id == n.id || DraftsMatch(cfg.SchemaReadsFor, x.name) {
			return true
		}
		if !x.isBranch() {
			return false
		}
		x = t.nsRowUnlocked(x.base.Int64)
		if x.isShadow() {
			return false
		}
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
}

// loadDraft looks a schema revision up among the candidates serving the
// write's target (§6.1). Each namespace holding a copy is locked shared and
// read as of its lock (D.8). A revision the writer can't read there counts
// as not found.
func (t *tx) loadDraft(ref schema.Ref, sc *schemaCtx) (any, bool) {
	if sc == nil || sc.target == nil || !sc.target.isBranch() {
		return nil, false
	}
	id, err := ids.Parse(ref.Rev)
	if err != nil {
		return nil, false
	}
	for _, cr := range t.copyRows(id, ref.Name) {
		if cr.state == statePurged {
			continue
		}
		c := t.nsByID(cr.ns)
		if !t.isDraftCandidate(c, ref.NS, nil) || !t.draftsServe(c, t.config(c.configSeq), sc.target) {
			continue
		}
		if !t.credsRead(c, ref.Name, sc.creds) {
			continue
		}
		d, err := t.docAt(t.rev(cr.seq))
		if err != nil {
			continue
		}
		return d, true
	}
	return nil, false
}

// pendingKey is the schema path under which a step's document written in
// namespace n may be referenced by later items of the same write (§7.5):
// its own path, or in a local branch the path of its root, as a draft
// serving the branch itself (§6.1). "" if none.
func (t *tx) pendingKey(n *nsRow, resource string, id ids.ID) string {
	ns := n.name
	if n.isBranch() {
		if ns = t.draftRoot(n); ns == "" || t.isE2E(n) {
			return ""
		}
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
		if c.purged || c.isShadow() {
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
	rows, err := t.Query(`SELECT ` + nsCols + ` FROM namespaces WHERE purged = 0 AND name NOT LIKE '~%'`)
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

// referencedPaths is the set of referenced schema revision paths (§6.1).
func (t *tx) referencedPaths() map[string]bool {
	out := map[string]bool{}
	for p := range t.schemaUses(func(*nsRow, string) bool { return false }) {
		out[p] = true
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
}

// brokenReferences returns the namespaces holding a reference that a copy
// satisfies now and none would after the change (§6.1). Every other
// namespace holding a copy of a revision the change touches is locked
// shared before its copy is relied on (D.8), so two purges can't each
// remove one of the last two copies.
func (t *tx) brokenReferences(ch refChange) []*nsRow {
	none := func(*nsRow, string) bool { return false }
	if ch.exclude == nil {
		ch.exclude = none
	}
	if ch.removed == nil {
		ch.removed = none
	}
	uses := t.schemaUses(ch.exclude)
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

// inUse is the 409 of §6.1 for a change that would leave references
// without a copy: it lists, as referencing, the referencing namespaces in
// which the caller may read anything, by the rule for other namespaces
// (§7.5): with the request's grant or any in Source-Authorization.
func (t *tx) inUse(broken []*nsRow, msg string) *Error {
	names := []string{}
	for _, m := range broken {
		if t.credsReadAny(m, t.reqCreds) {
			names = append(names, m.name)
		}
	}
	return apiErr(409, "in_use", "message", msg, "referencing", anyStrings(names))
}
