package core

import (
	"sort"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
)

// Schemas follow their documents (§6.1).
//
// A namespace N that sets schemaReads: { for: [names or prefixes] } opens
// its schema revisions, resources whose own $schema is a dialect URL, in
// two ways, N itself always counting as listed:
//
//   - for a write to a listed namespace, or a local branch of one, whose
//     document pins the revision through $schema or its $ref closure, the
//     revision resolves without the writer's read on N
//     (loadSchemaIn, schemaReadsServe);
//   - a revision path /r/N/{name}/rev/{id}, and nothing else of N, may be
//     read under a grant that may read a resource of a listed namespace
//     that references it (schemaReadsRev), even one that doesn't name N
//     (§7).
//
// A referrer, as the refusals of §6.1 count references, is an unpurged
// resource of the listed namespace whose head, or last live document if
// tombstoned, names the revision by $schema or reaches it through the $ref
// closure of that schema, resolved structurally as schemaUses does. Only
// the listed namespace's own resources count: what a branch reads through
// from its base is the base's to open. The namespaces considered are those
// the grant names; a "*" grant considers every namespace schemaReads lists.

// schemaReadsRev reports whether cred may read revision rid of resource
// name in n by path under n's schemaReads (§6.1).
func (t *tx) schemaReadsRev(n *nsRow, name string, rid ids.ID, cred Credentials) bool {
	if cred.Bearer == "" || n.purged || n.isBranch() || n.isShadow() {
		return false
	}
	cfg := t.config(n.configSeq)
	if cfg.SchemaReadsFor == nil || cfg.level >= levelSealed {
		return false
	}
	// The revision: in n itself, not a tombstone, a schema document.
	v := t.resolve(n, name, nil)
	if v.head == nil || v.state == Purged || v.state == NotFound {
		return false
	}
	row := t.findInAncestry(v.head, rid)
	if row == nil || row.kind == kindTombstone {
		return false
	}
	d, err := t.docAt(row)
	if err != nil || !schema.IsSchemaDoc(d) {
		return false
	}
	g, err := grant.Decode(cred.Bearer, t.e.opt.Maximums.GrantSize)
	if err != nil {
		return false
	}
	path := "/r/" + n.name + "/" + name + "/rev/" + rid.String()
	t.noLock++
	defer func() { t.noLock-- }()
	closures := map[string]bool{}
	for _, l := range t.schemaReadsCandidates(n, cfg, g) {
		if t.refersIn(l, g, path, closures) {
			return true
		}
	}
	return false
}

// schemaReadsCandidates lists the namespaces whose readers schemaReads of
// n may open n's schemas to that grant g names: n, and those matching
// schemaReads.for.
func (t *tx) schemaReadsCandidates(n *nsRow, cfg *Config, g *grant.Grant) []*nsRow {
	names := map[string]bool{}
	star := false
	for _, s := range g.Blocks[0].NS {
		if s == "*" {
			star = true
		} else if s == n.name || DraftsMatch(cfg.SchemaReadsFor, s) {
			names[s] = true
		}
	}
	if star {
		names[n.name] = true
		rows, err := t.Query(`SELECT name FROM namespaces WHERE purged = 0 AND name NOT LIKE '~%'`)
		t.must(err)
		for rows.Next() {
			var s string
			t.must(rows.Scan(&s))
			if DraftsMatch(cfg.SchemaReadsFor, s) {
				names[s] = true
			}
		}
		t.must(rows.Err())
		rows.Close()
	}
	var out []*nsRow
	for _, s := range sortedKeys(names) {
		if !g.NamesNS(s) {
			continue
		}
		if l := t.nsByName(s); l != nil && !l.purged && !l.isShadow() {
			out = append(out, l)
		}
	}
	return out
}

// refersIn reports whether g may read a resource of l that references
// path (§6.1): see the package comment above.
func (t *tx) refersIn(l *nsRow, g *grant.Grant, path string, closures map[string]bool) bool {
	lcfg := t.config(l.configSeq)
	var a *actor
	if lcfg.Read != "public" {
		var err *Error
		if a, err = t.verifyGrant(g, l.name, l, lcfg, nil); err != nil || !a.verified.Can["read"] {
			return false
		}
	}
	// The schemas pinned in l whose closure reaches path.
	rows, err := t.Query(`SELECT DISTINCT r.schema_ref FROM revisions r JOIN resources s ON s.res = r.res
		WHERE s.ns = ? AND s.state <> ? AND r.schema_ref IS NOT NULL`, l.id, statePurged)
	t.must(err)
	var pinned []string
	for rows.Next() {
		var s string
		t.must(rows.Scan(&s))
		pinned = append(pinned, s)
	}
	t.must(rows.Err())
	rows.Close()
	sort.Strings(pinned)
	reaching := map[string]bool{}
	for _, s := range pinned {
		key := l.name + "\x00" + s
		r, ok := closures[key]
		if !ok {
			r = t.closureReaches(s, path, l)
			closures[key] = r
		}
		if r {
			reaching[s] = true
		}
	}
	if len(reaching) == 0 {
		return false
	}
	// Resources of l, unpurged, whose current document pins one of them.
	var names []string
	for _, s := range sortedKeys(reaching) {
		rows, err := t.Query(`SELECT DISTINCT s.name FROM revisions r JOIN resources s ON s.res = r.res
			WHERE s.ns = ? AND s.state <> ? AND r.schema_ref = ?`, l.id, statePurged, s)
		t.must(err)
		for rows.Next() {
			var nm string
			t.must(rows.Scan(&nm))
			names = append(names, nm)
		}
		t.must(rows.Err())
		rows.Close()
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, nm := range names {
		if seen[nm] {
			continue
		}
		seen[nm] = true
		if lcfg.Read != "public" && !t.canRead(l, lcfg, a, nm) {
			continue
		}
		res := t.resource(l.id, nm)
		if res == nil {
			continue
		}
		v := t.resolve(l, nm, nil)
		if v.head == nil || v.state == Purged || v.state == NotFound {
			continue
		}
		ll := t.lastLive(v.head)
		var ref *string
		t.must(t.QueryRow(`SELECT schema_ref FROM revisions WHERE seq = ?`, ll.seq).Scan(&ref))
		if ref != nil && reaching[*ref] {
			return true
		}
	}
	return false
}

// closureReaches reports whether path is start or is reached through the
// $ref closure of start, resolved as a reference from m would be,
// structurally (satisfyingCopies).
func (t *tx) closureReaches(start, path string, m *nsRow) bool {
	seen := map[string]bool{}
	queue := []string{start}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		if p == path {
			return true
		}
		ref, ok := schema.ParseRef(p)
		if !ok {
			continue
		}
		id, err := ids.Parse(ref.Rev)
		if err != nil {
			continue
		}
		cs := t.satisfyingCopies(ref, m, nil, t.copyRows(id, ref.Name))
		if len(cs) == 0 {
			continue
		}
		d, err := t.docAt(t.rev(cs[0].seq))
		if err != nil {
			continue
		}
		for _, x := range schema.Refs(d) {
			queue = append(queue, x.Path())
		}
	}
	return false
}
