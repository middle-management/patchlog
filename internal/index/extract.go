package index

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
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

// Loader returns a schema.Loader for one Collect call, resolving paths in
// their own namespaces only. A revision that is unknown, purged or
// unreadable is schema.ErrUnavailable; any other failure (network, 5xx,
// 429) is recorded in *transient so the caller can retry instead of
// indexing the document without its fields.
func (s *SchemaCache) Loader(ctx context.Context, transient *error) schema.Loader {
	return s.LoaderFor(ctx, "", transient)
}

// LoaderFor is Loader for a document of namespace ns: if ns is a branch,
// a path its namespace can't resolve is looked up among that namespace's
// branches (§6.1).
func (s *SchemaCache) LoaderFor(ctx context.Context, ns string, transient *error) schema.Loader {
	fail := func(err error) (any, error) {
		if client.IsNotFound(err) || client.IsGone(err) || client.IsAuth(err) {
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
		if err != nil && ns != "" && (client.IsNotFound(err) || client.IsGone(err) || client.IsAuth(err)) {
			// Only a branch's documents may use drafts. A namespace
			// document this client can't read (sealed, say) means no.
			if b, berr := s.isBranch(ctx, ns); berr == nil && b {
				if dd, derr := s.c.ResolveSchema(ctx, r, client.ResolveOptions{Drafts: true, For: ns}); derr == nil || !client.IsNotFound(derr) && !client.IsGone(derr) && !client.IsAuth(derr) {
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
	value any // float64 or string
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
// documents (no $schema, or a schema document) are typed=false. A typed
// document whose annotations cannot be collected for a permanent reason
// (invalid against its schema, unavailable schema) is indexed without rows
// and logged; transient failures are returned so Apply retries.
func (ix *Index) extract(ctx context.Context, ns, resource string, doc any) (string, bool, *docRows, error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return "", false, nil, nil
	}
	sch, _ := obj["$schema"].(string)
	if sch == "" || schema.IsDialect(sch) {
		return "", false, nil, nil
	}
	var transient error
	load := ix.schemas.LoaderFor(ctx, ns, &transient)
	// failed classifies an error of one of the two walks: transient ones
	// (and cancellation) are returned so Apply retries; the rest are
	// permanent, and the document is indexed without what the walk gave.
	failed := func(what string, err error) error {
		if transient != nil {
			return transient
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		ix.opt.Logf("index: %s/%s: %s: %v (indexed without them)", ns, resource, what, err)
		return nil
	}
	var rows *docRows
	anns, err := annot.Collect(doc, load, "x-index")
	if err != nil {
		if err := failed("collecting x-index", err); err != nil {
			return "", false, nil, err
		}
	} else {
		rows = rowsFor(doc, anns)
	}
	// §A.2: references come from §6.5's static walk with the schema
	// revision the document pins, whether or not the document validates.
	found, err := annot.FindRefs(doc, load)
	if err != nil {
		if err := failed("walking x-ref", err); err != nil {
			return "", false, nil, err
		}
	}
	if len(found) > 0 {
		if rows == nil {
			rows = &docRows{}
		}
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

// rowsFor turns x-index annotations into rows (§A.2).
func rowsFor(doc any, anns []annot.Annotation) *docRows {
	r := &docRows{}
	seen := map[string]bool{}
	sortSeen := map[string]bool{}
	for _, a := range anns {
		path := fieldPath(doc, a.Pointer)
		for _, kind := range indexKinds(a.Value) {
			key := kind + "\x00" + a.Pointer
			if seen[key] {
				continue // the same location annotated by several subschemas
			}
			seen[key] = true
			switch kind {
			case "text":
				// Objects and arrays: every string leaf.
				walkStrings(a.Instance, func(s string) {
					if strings.TrimSpace(s) != "" {
						r.text = append(r.text, textRow{path, s})
					}
				})
			case "facet":
				vals := []any{a.Instance}
				if arr, ok := a.Instance.([]any); ok {
					vals = arr
				}
				for _, v := range vals {
					fv, raw := facetValue(v)
					r.facet = append(r.facet, facetRow{path, fv, raw})
				}
			case "sort":
				// One value per path: the first in document order.
				if sortSeen[path] {
					continue
				}
				if v, ok := sortValue(a.Instance); ok {
					sortSeen[path] = true
					r.sort = append(r.sort, sortRow{path, v})
				}
			}
		}
	}
	return r
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

// fieldPath drops array indices from an instance pointer, walking the
// document to tell array positions from object members named like numbers.
func fieldPath(doc any, ptr string) string {
	p, err := pointer.Parse(ptr)
	if err != nil {
		return ptr
	}
	var out pointer.Pointer
	cur := doc
	for _, tok := range p {
		switch c := cur.(type) {
		case []any:
			i, ok := pointer.ArrayIndex(tok)
			if !ok || i >= len(c) {
				return out.String()
			}
			cur = c[i]
		case map[string]any:
			out = append(out, tok)
			cur = c[tok]
		default:
			out = append(out, tok)
			cur = nil
		}
	}
	return out.String()
}

func walkStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case []any:
		for _, e := range x {
			walkStrings(e, fn)
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			walkStrings(x[k], fn)
		}
	}
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

// sortTime is the fixed-width UTC form RFC 3339 timestamps are normalised
// to, so that they compare lexically in time order.
const sortTime = "2006-01-02T15:04:05.000000000Z"

// normTime returns s normalised if it is an RFC 3339 date-time.
func normTime(s string) (string, bool) {
	if len(s) < 20 || s[4] != '-' || (s[10] != 'T' && s[10] != 't') {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.ToUpper(s))
	if err != nil {
		return "", false
	}
	return t.UTC().Format(sortTime), true
}

// sortValue is the stored sort key: numbers as REAL, strings as TEXT
// (RFC 3339 date-times normalised to UTC with nanoseconds). Other values,
// and arrays (first sortable element), are skipped.
func sortValue(v any) (any, bool) {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		return x, true
	case string:
		if n, ok := normTime(x); ok {
			return n, true
		}
		return x, true
	case []any:
		for _, e := range x {
			if s, ok := sortValue(e); ok {
				return s, true
			}
		}
	}
	return nil, false
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
