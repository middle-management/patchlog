package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// errSchemas is a schema that can't be read for now (network, 5xx, 429):
// the fields can't be checked (502).
var errSchemas = errors.New("cannot read a schema of the namespace's documents")

// checkFields returns a *FieldError for the first of fields that no schema
// of ns's documents, as of tx, marks with x-index (§A.4). The marks are read
// from the schemas, not from the rows, so whether a query fails never
// depends on whether a document has values at the path: the index learns a
// document's marks only where it has values (annot.Collect walks schema and
// document together), so here each schema is walked alone, along the path.
func (ix *Index) checkFields(ctx context.Context, tx *sql.Tx, ns string, fields []string) error {
	if len(fields) == 0 {
		return nil
	}
	var schemas []string
	for last := ""; ; {
		// The distinct schemas, one seek each on docs_q.
		var s string
		err := tx.QueryRowContext(ctx, `SELECT schema FROM docs WHERE ns = ? AND schema > ? ORDER BY schema LIMIT 1`, ns, last).Scan(&s)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		schemas, last = append(schemas, s), s
	}
	var transient error
	w := &markWalk{load: ix.schemas.LoaderFor(ctx, ns, &transient), docs: map[string]any{}}
	for _, f := range fields {
		w.path, _ = pointer.Parse(f) // ParseQuery validated it
		marked := false
		for _, s := range schemas {
			// A schema document is typed by its dialect, which marks nothing.
			if ref, ok := schema.ParseRef(s); ok {
				w.seen = map[string]bool{}
				if marked = w.marked(ref.Path(), nil, 0); marked {
					break
				}
			}
		}
		if transient != nil {
			return fmt.Errorf("%w: %v", errSchemas, transient)
		}
		if !marked {
			return &FieldError{Path: f}
		}
	}
	return nil
}

// markWalk walks schemas statically along one field path, through the
// keywords that mark a path (§A.4), whatever an instance would hold. Array
// items apply at their array's path, since rows store paths with array
// indices removed (valueWalk). A schema or reference it can't resolve marks
// nothing. It also loads and resolves schemas for valueWalk.
type markWalk struct {
	load schema.Loader
	docs map[string]any // revision path → schema document (nil: unavailable)
	path pointer.Pointer
	kind string          // the x-index kind the path needs ("": any)
	seen map[string]bool // subschemas visited, with their position in path
	res  map[string]*regexp.Regexp
}

// marked reports whether the subschema at ptr of the schema at base, applied
// at the first i tokens of path, marks path with an x-index naming w.kind
// (any of text, facet or sort if it is "").
func (w *markWalk) marked(base string, ptr pointer.Pointer, i int) bool {
	key := base + "#" + ptr.String() + "\x00" + strconv.Itoa(i)
	if w.seen[key] {
		return false
	}
	w.seen[key] = true
	v, _ := pointer.Get(w.doc(base), ptr)
	obj, _ := v.(map[string]any)
	if obj == nil {
		return false
	}
	if i == len(w.path) && hasKind(obj["x-index"], w.kind) {
		return true
	}
	sub := func(i int, toks ...string) bool { return w.marked(base, append(ptr[:len(ptr):len(ptr)], toks...), i) }
	for _, kw := range []string{"$ref", "$dynamicRef"} {
		if r, ok := obj[kw].(string); ok {
			if b, p, ok := w.resolve(base, r); ok && w.marked(b, p, i) {
				return true
			}
		}
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		arr, _ := obj[kw].([]any)
		for j := range arr {
			if sub(i, kw, strconv.Itoa(j)) {
				return true
			}
		}
	}
	for _, kw := range []string{"if", "then", "else", "items", "contains"} {
		if _, ok := obj[kw]; ok && sub(i, kw) {
			return true
		}
	}
	deps, _ := obj["dependentSchemas"].(map[string]any)
	for n := range deps {
		if sub(i, "dependentSchemas", n) {
			return true
		}
	}
	if i == len(w.path) {
		return false
	}
	name, matched := w.path[i], false
	props, _ := obj["properties"].(map[string]any)
	if _, ok := props[name]; ok {
		matched = true
		if sub(i+1, "properties", name) {
			return true
		}
	}
	pats, _ := obj["patternProperties"].(map[string]any)
	for pat := range pats {
		if re := w.regexp(pat); re != nil && re.MatchString(name) {
			matched = true
			if sub(i+1, "patternProperties", pat) {
				return true
			}
		}
	}
	_, additional := obj["additionalProperties"]
	return !matched && additional && sub(i+1, "additionalProperties")
}

// hasKind reports whether an x-index value names kind, or any kind if
// kind is "".
func hasKind(v any, kind string) bool {
	for _, k := range indexKinds(v) {
		if kind == "" || k == kind {
			return true
		}
	}
	return false
}

// regexp compiles a patternProperties pattern once per walk (nil if it
// doesn't compile, which matches no name).
func (w *markWalk) regexp(pat string) *regexp.Regexp {
	if re, ok := w.res[pat]; ok {
		return re
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		re = nil
	}
	if w.res == nil {
		w.res = map[string]*regexp.Regexp{}
	}
	w.res[pat] = re
	return re
}

// resolve resolves a $ref or $dynamicRef value against base as annot does:
// a revision path with an optional JSON Pointer fragment, or a fragment of
// the same document, a pointer or an anchor.
func (w *markWalk) resolve(base, ref string) (string, pointer.Pointer, bool) {
	if !strings.HasPrefix(ref, "#") {
		r, p, err := schema.SplitRef(ref)
		return r.Path(), p, err == nil
	}
	frag, err := url.PathUnescape(ref[1:])
	if err != nil {
		return "", nil, false
	}
	if frag == "" || frag[0] == '/' {
		p, err := pointer.Parse(frag)
		return base, p, err == nil
	}
	p, ok := findAnchor(w.doc(base), frag, nil)
	return base, p, ok
}

// doc returns the schema document at revision path p, nil if unavailable.
func (w *markWalk) doc(p string) any {
	d, ok := w.docs[p]
	if !ok {
		if ref, isRef := schema.ParseRef(p); isRef {
			d, _ = w.load(ref)
		}
		w.docs[p] = d
	}
	return d
}

// findAnchor finds the subschema of s, at at, whose $anchor or
// $dynamicAnchor is name. definitions holds subschemas, as $defs does
// (§6.5).
func findAnchor(s any, name string, at pointer.Pointer) (pointer.Pointer, bool) {
	obj, ok := s.(map[string]any)
	if !ok {
		return nil, false
	}
	if obj["$anchor"] == name || obj["$dynamicAnchor"] == name {
		return at, true
	}
	sub := func(v any, toks ...string) (pointer.Pointer, bool) {
		return findAnchor(v, name, append(at[:len(at):len(at)], toks...))
	}
	for k, v := range obj {
		switch k {
		case "items", "contains", "additionalProperties", "not", "if", "then", "else",
			"propertyNames", "unevaluatedItems", "unevaluatedProperties", "contentSchema":
			if p, ok := sub(v, k); ok {
				return p, true
			}
		case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
			m, _ := v.(map[string]any)
			for n, e := range m {
				if p, ok := sub(e, k, n); ok {
					return p, true
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			arr, _ := v.([]any)
			for j, e := range arr {
				if p, ok := sub(e, k, strconv.Itoa(j)); ok {
					return p, true
				}
			}
		}
	}
	return nil, false
}

// sloc is a subschema: a schema revision path and a pointer into it.
type sloc struct {
	base string
	ptr  pointer.Pointer
}

func (l sloc) child(toks ...string) sloc {
	return sloc{l.base, append(l.ptr[:len(l.ptr):len(l.ptr)], toks...)}
}

func (l sloc) id() string { return l.base + "#" + l.ptr.String() }

// valueWalk collects a document's x-index values (§A.2) by the static walk
// of §6.5, through only the keywords that mark a path (§A.4): at every
// instance location it considers every subschema that could apply through
// $ref and $dynamicRef, properties, patternProperties,
// additionalProperties, dependentSchemas (of members present), items,
// prefixItems and contains, and every branch of allOf, anyOf, oneOf, if,
// then and else, whether or not it validates; never not, propertyNames,
// unevaluated* or contentSchema. A document that doesn't validate gets its
// rows all the same. Only strings, numbers and booleans are collected, an
// array's scalars at the array's own path, and text collects strings only:
// an object marked text indexes nothing.
type valueWalk struct {
	m     *markWalk // loads and resolves schemas
	rows  docRows
	got   map[string]bool  // kind and instance location of each value collected
	sorts map[string][]any // field path → its sort values, in document order
	order []string         // the field paths of sorts, as first found
}

// collectValues walks doc (as validated: without the members §6.2 step 5
// leaves out) with the schema at root and returns its x-index rows.
func collectValues(doc any, root string, m *markWalk) *docRows {
	w := &valueWalk{m: m, got: map[string]bool{}, sorts: map[string][]any{}}
	w.walk([]sloc{{base: root}}, schema.Instance(doc), nil, nil)
	for _, path := range w.order {
		vals := w.sorts[path]
		least := vals[0]
		for _, v := range vals[1:] {
			if sortLess(v, least) {
				least = v
			}
		}
		w.rows.sort = append(w.rows.sort, sortRow{path: path, value: sortColumn(least), raw: string(jsonv.Canonical(vals))})
	}
	return &w.rows
}

// here is a subschema that applies at the walk's instance location.
type here struct {
	l   sloc
	obj map[string]any
}

// walk applies the subschemas at locs, and every one they reach through
// the in-place applicators, each once, to inst at instance location at
// (indices included) and field path field (without them), collects their
// values, and walks the members and items they reach.
func (w *valueWalk) walk(locs []sloc, inst any, at, field pointer.Pointer) {
	var hs []here
	seen := map[string]bool{}
	obj, _ := inst.(map[string]any)
	for len(locs) > 0 {
		l := locs[0]
		locs = locs[1:]
		if seen[l.id()] {
			continue
		}
		seen[l.id()] = true
		v, _ := pointer.Get(w.m.doc(l.base), l.ptr)
		s, _ := v.(map[string]any)
		if s == nil {
			continue // a boolean schema, or one that can't be resolved
		}
		hs = append(hs, here{l, s})
		for _, kw := range []string{"$ref", "$dynamicRef"} {
			if r, ok := s[kw].(string); ok {
				if b, p, ok := w.m.resolve(l.base, r); ok {
					locs = append(locs, sloc{b, p})
				}
			}
		}
		for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
			arr, _ := s[kw].([]any)
			for j := range arr {
				locs = append(locs, l.child(kw, strconv.Itoa(j)))
			}
		}
		for _, kw := range []string{"if", "then", "else"} {
			if _, ok := s[kw]; ok {
				locs = append(locs, l.child(kw))
			}
		}
		deps, _ := s["dependentSchemas"].(map[string]any)
		for n := range deps {
			if _, present := obj[n]; present {
				locs = append(locs, l.child("dependentSchemas", n))
			}
		}
	}
	for _, h := range hs {
		for _, kind := range indexKinds(h.obj["x-index"]) {
			w.collect(kind, inst, at, field)
		}
	}
	switch v := inst.(type) {
	case map[string]any:
		for _, name := range sortedKeys(v) {
			var next []sloc
			for _, h := range hs {
				matched := false
				props, _ := h.obj["properties"].(map[string]any)
				if _, ok := props[name]; ok {
					matched = true
					next = append(next, h.l.child("properties", name))
				}
				pats, _ := h.obj["patternProperties"].(map[string]any)
				for pat := range pats {
					if re := w.m.regexp(pat); re != nil && re.MatchString(name) {
						matched = true
						next = append(next, h.l.child("patternProperties", pat))
					}
				}
				if _, ok := h.obj["additionalProperties"]; ok && !matched {
					next = append(next, h.l.child("additionalProperties"))
				}
			}
			if len(next) > 0 {
				w.walk(next, v[name], append(at[:len(at):len(at)], name), append(field[:len(field):len(field)], name))
			}
		}
	case []any:
		for i, e := range v {
			var next []sloc
			for _, h := range hs {
				prefix, _ := h.obj["prefixItems"].([]any)
				if i < len(prefix) {
					next = append(next, h.l.child("prefixItems", strconv.Itoa(i)))
				} else if _, ok := h.obj["items"]; ok {
					next = append(next, h.l.child("items"))
				}
				if _, ok := h.obj["contains"]; ok {
					next = append(next, h.l.child("contains"))
				}
			}
			if len(next) > 0 {
				// Items count at their array's path (§A.2).
				w.walk(next, e, append(at[:len(at):len(at)], strconv.Itoa(i)), field)
			}
		}
	}
}

// collect records the values of kind at instance location at: inst if it
// is a string, number or boolean, or an array's elements that are, each
// once per kind and location, however many subschemas mark it.
func (w *valueWalk) collect(kind string, inst any, at, field pointer.Pointer) {
	path := field.String()
	add := func(v any, at string) {
		switch v.(type) {
		case string, float64, bool:
		default:
			return // objects, null, nested arrays
		}
		key := kind + "\x00" + at
		if w.got[key] {
			return
		}
		w.got[key] = true
		switch kind {
		case "text":
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				w.rows.text = append(w.rows.text, textRow{path, s})
			}
		case "facet":
			fv, raw := facetValue(v)
			w.rows.facet = append(w.rows.facet, facetRow{path, fv, raw})
		case "sort":
			if _, ok := w.sorts[path]; !ok {
				w.order = append(w.order, path)
			}
			w.sorts[path] = append(w.sorts[path], v)
		}
	}
	if arr, ok := inst.([]any); ok {
		for i, e := range arr {
			add(e, at.String()+"/"+strconv.Itoa(i))
		}
		return
	}
	add(inst, at.String())
}
