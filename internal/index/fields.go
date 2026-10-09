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
// applicators annot.Collect follows, whatever an instance would hold. Array
// items apply at their array's path, since rows store paths with array
// indices removed (fieldPath). A schema or reference it can't resolve marks
// nothing.
type markWalk struct {
	load schema.Loader
	docs map[string]any // revision path → schema document (nil: unavailable)
	path pointer.Pointer
	seen map[string]bool // subschemas visited, with their position in path
}

// marked reports whether the subschema at ptr of the schema at base, applied
// at the first i tokens of path, marks path with an x-index naming text,
// facet or sort.
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
	if i == len(w.path) && len(indexKinds(obj["x-index"])) > 0 {
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
		if re, err := regexp.Compile(pat); err == nil && re.MatchString(name) {
			matched = true
			if sub(i+1, "patternProperties", pat) {
				return true
			}
		}
	}
	_, additional := obj["additionalProperties"]
	return !matched && additional && sub(i+1, "additionalProperties")
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
// $dynamicAnchor is name.
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
		case "properties", "patternProperties", "$defs", "dependentSchemas":
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
