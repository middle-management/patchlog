package index

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// SchemaCache loads schema revisions through the core API and keeps them
// forever: a revision id determines its document (§3.3), so an entry never
// goes stale. For documents of a branch it also finds draft schema
// revisions in branches of the path's namespace, as the server resolves
// them (§6.1, client.ResolveSchema).
type SchemaCache struct {
	c      *client.Client
	mu     sync.Mutex
	m      map[string]any
	branch map[string]bool // namespace -> is a branch (never changes, §7.4)
}

// NewSchemaCache returns a cache reading through c.
func NewSchemaCache(c *client.Client) *SchemaCache {
	return &SchemaCache{c: c, m: map[string]any{}, branch: map[string]bool{}}
}

// Loader returns a schema.Loader for one walk, resolving paths in their
// own namespaces only. A revision that answers 403, 404 or 410, or that
// can't be opened for want of keys (unavailable), is schema.ErrUnavailable;
// any other failure (network, 5xx, 429, and a 401 to the service's own
// grant) is recorded in *transient so the caller can retry instead of
// indexing the document without its fields.
func (s *SchemaCache) Loader(ctx context.Context, transient *error) schema.Loader {
	return s.LoaderFor(ctx, "", transient)
}

// refused reports a 403, 404 or 410 answer to a schema revision (§A.1).
func refused(err error) bool {
	ae, ok := client.AsAPIError(err)
	return ok && (ae.Status == 403 || ae.Status == 404 || ae.Status == 410)
}

// unavailable reports a schema revision that leaves a document indexed as
// one without $schema (§A.1): refused, or one the service can't open for
// want of keys (§6.1, §E.2.3), which asking again won't mend. A 401 isn't
// one: the service's own grant failed to verify, which its operator mends.
func unavailable(err error) bool { return refused(err) || errors.Is(err, client.ErrNoKeys) }

// LoaderFor is Loader for a document of namespace ns: if ns is a branch,
// a path its namespace can't resolve is looked up among that namespace's
// branches (§6.1).
func (s *SchemaCache) LoaderFor(ctx context.Context, ns string, transient *error) schema.Loader {
	fail := func(err error) (any, error) {
		if unavailable(err) {
			return nil, schema.ErrUnavailable
		}
		if *transient == nil {
			*transient = err
		}
		return nil, err
	}
	return func(r schema.Ref) (any, error) {
		p := r.Path()
		s.mu.Lock()
		v, ok := s.m[p]
		s.mu.Unlock()
		if ok {
			return jsonv.Clone(v), nil
		}
		d, err := s.c.ResolveSchema(ctx, r, client.ResolveOptions{})
		if err != nil && ns != "" && refused(err) {
			// Only a branch's documents may use drafts. A namespace
			// document this client can't read (sealed, say) means no.
			if b, berr := s.isBranch(ctx, ns); berr == nil && b {
				if dd, derr := s.c.ResolveSchema(ctx, r, client.ResolveOptions{Drafts: true, For: ns}); derr == nil || !refused(derr) {
					d, err = dd, derr
				}
			}
		}
		if err != nil {
			return fail(err)
		}
		s.mu.Lock()
		s.m[p] = d.Doc.Value
		s.mu.Unlock()
		return jsonv.Clone(d.Doc.Value), nil
	}
}

func (s *SchemaCache) isBranch(ctx context.Context, ns string) (bool, error) {
	s.mu.Lock()
	b, ok := s.branch[ns]
	s.mu.Unlock()
	if ok {
		return b, nil
	}
	b, err := s.c.IsBranch(ctx, ns)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	s.branch[ns] = b
	s.mu.Unlock()
	return b, nil
}

type textRow struct{ path, body string }
type facetRow struct{ path, value, raw string }
type sortRow struct {
	path  string
	value any    // the least value (sortColumn)
	raw   string // every value at the path, as written: a canonical JSON array (hits show it)
}

type refRow struct {
	path, ref        string // instance pointer of the string, and the string as written
	targetNS, target string
	rev, entry       string // "" when the reference is live / names no entry
}

type docRows struct {
	text  []textRow
	facet []facetRow
	sort  []sortRow
	refs  []refRow
}

// extract returns the document's $schema and its index rows. Untyped
// documents (no $schema) are typed=false, and so is one whose pinned schema
// revision is unavailable (§A.1): it is indexed exactly as one without
// $schema. A schema document is typed by its dialect URL. x-index values
// are collected by a static walk (§A.2, valueWalk), so a document that
// doesn't validate gets rows too; a schema revision a $ref names that is
// unavailable marks nothing. Transient failures are returned so Apply
// retries.
func (ix *Index) extract(ctx context.Context, ns, resource string, doc any) (string, bool, *docRows, error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return "", false, nil, nil
	}
	sch, _ := obj["$schema"].(string)
	if sch == "" {
		return "", false, nil, nil
	}
	if schema.IsDialect(sch) {
		// §A.4: a schema document is indexed against its dialect's
		// meta-schema, which has no x-index; its references are the
		// revision paths of $ref keywords at schema positions.
		var rows *docRows
		for _, r := range schema.RefLocations(doc) {
			if rows == nil {
				rows = &docRows{}
			}
			rows.refs = append(rows.refs, refRow{path: r.Pointer.String(), ref: r.Raw, targetNS: r.Ref.NS, target: r.Ref.Name, rev: r.Ref.Rev})
		}
		return sch, true, rows, nil
	}
	var transient error
	load := ix.schemas.LoaderFor(ctx, ns, &transient)
	ref, ok := schema.ParseRef(sch)
	if !ok {
		// Neither a revision path nor a dialect: the core stores none.
		ix.opt.Logf("index: %s/%s: $schema %q is not a schema revision path (indexed without rows)", ns, resource, sch)
		return sch, true, nil, nil
	}
	root, err := load(ref)
	if err != nil {
		switch {
		case transient != nil:
			return "", false, nil, transient
		case errors.Is(err, schema.ErrUnavailable):
			// §A.1: no rows, no match for schema=, a docs row only if
			// untyped documents are listed, and its schema counts for no
			// path (checkFields reads the docs rows' schemas).
			ix.opt.Logf("index: %s/%s: schema %s is unavailable; indexed as a document without $schema", ns, resource, sch)
			return "", false, nil, nil
		default:
			return "", false, nil, err
		}
	}
	rows := collectValues(doc, ref.Path(), &markWalk{load: load, docs: map[string]any{ref.Path(): root}})
	if transient != nil {
		return "", false, nil, transient
	}
	// §A.2: references come from §6.5's static walk with the schema
	// revision the document pins, whether or not the document validates.
	found, err := annot.FindRefs(doc, load)
	if err != nil {
		if transient != nil {
			return "", false, nil, transient
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", false, nil, err
		}
		ix.opt.Logf("index: %s/%s: walking x-ref: %v (indexed without them)", ns, resource, err)
	}
	if len(found) > 0 {
		rows.refs = refRows(found)
	}
	return sch, true, rows, nil
}

// refRows turns found references into rows: the target as written (not
// resolved, so a branch's preview index matches what its documents say,
// §A.4), one row per location.
func refRows(found []annot.Ref) []refRow {
	var out []refRow
	seen := map[string]bool{}
	for _, r := range found {
		if seen[r.Pointer] {
			continue // the same location, found with another pinned/key
		}
		seen[r.Pointer] = true
		out = append(out, refRow{path: r.Pointer, ref: r.Raw, targetNS: r.NS, target: r.Name, rev: r.Rev, entry: r.Entry})
	}
	return out
}

// indexKinds reads an x-index value: "text" | "facet" | "sort", or (an
// extension) an array of them.
func indexKinds(v any) []string {
	var out []string
	add := func(x any) {
		if s, ok := x.(string); ok && (s == "text" || s == "facet" || s == "sort") {
			out = append(out, s)
		}
	}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			add(x)
		}
	} else {
		add(v)
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// facetValue is the exact-match form of a value: a string as itself,
// anything else as canonical JSON (so the string "3" and the number 3 share
// a facet value); raw is always canonical JSON, for hits and counts.
func facetValue(v any) (value, raw string) {
	raw = string(jsonv.Canonical(v))
	if s, ok := v.(string); ok {
		return s, raw
	}
	return raw, raw
}

// sortLess is the order of sort values (§A.2): numbers before strings
// before booleans; numbers by value, strings by UTF-8 bytes (no date-time
// normalisation), false before true.
func sortLess(a, b any) bool {
	ra, rb := sortRank(a), sortRank(b)
	if ra != rb {
		return ra < rb
	}
	switch x := a.(type) {
	case float64:
		return x < b.(float64)
	case string:
		return x < b.(string)
	case bool:
		return !x && b.(bool)
	}
	return false
}

func sortRank(v any) int {
	switch v.(type) {
	case float64:
		return 0
	case string:
		return 1
	}
	return 2
}

// sortColumn is a sort value as stored, typed so that SQLite orders the
// column as sortLess does: a number as REAL, a string as TEXT (compared as
// bytes, BINARY), a boolean as a BLOB x'00' (false) or x'01' (true), since
// SQLite orders REAL before TEXT before BLOB.
func sortColumn(v any) any {
	if b, ok := v.(bool); ok {
		if b {
			return []byte{1}
		}
		return []byte{0}
	}
	return v
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
