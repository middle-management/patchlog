// Package annot collects x-* schema annotations (§6.5) for a document: the
// keywords such as x-index (Addendum A) and x-ref (§6.5, §G.4.2) that apply to
// locations of an instance under its schema.
//
// Annotations follow JSON Schema 2020-12 semantics: a keyword applies to an
// instance location when the subschema holding it was applied to that location
// and validated successfully. Annotations are therefore followed through $ref
// (same-document fragments and revision paths), properties, patternProperties,
// additionalProperties, prefixItems, items, contains, allOf, anyOf, oneOf,
// if/then/else and dependentSchemas, and dropped from any subschema that failed
// (a non-matching anyOf/oneOf branch, the untaken if/then/else branch, a
// non-matching contains item). The santhosh-tekuri library validates but does
// not expose annotations, so this package walks schema and instance together
// and uses the library only to decide validity of individual subschemas.
package annot

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var printer = message.NewPrinter(language.English)

// Annotation is one x-* keyword that applies to a location in the instance.
type Annotation struct {
	Keyword    string // e.g. "x-index", "x-ref"
	Value      any    // the keyword's value (jsonv model)
	Pointer    string // RFC 6901 instance location, e.g. "/players/2/name"
	Instance   any    // the instance value at Pointer
	SchemaPath string // where the keyword was found, "{schema path}#{JSON pointer}"
}

// MaxDepth bounds the chain of subschemas ($ref, allOf, anyOf, …) applied at
// a single instance location. Descending into the instance resets it: the
// instance's own depth is finite (and limited by §6.6).
const MaxDepth = 128

// syntheticBase mirrors internal/schema: revision paths live under it.
const syntheticBase = "https://patchlog.invalid"

// localBase is used for a CollectWith root whose path is not absolute.
const localBase = syntheticBase + "/annot-root"

// ErrDepth reports more than MaxDepth nested subschemas at one instance location.
var ErrDepth = errors.New("annot: schema walk exceeds maximum depth")

// Collect returns every x-* annotation (or only the keywords listed, if
// non-empty) that applies to doc under the schema named by doc's $schema
// (revision path), loading schemas through load. Untyped documents (no
// $schema, or a dialect $schema, i.e. schema documents) return nil. A document
// that does not validate returns a *schema.ValidationError.
//
// Order: by instance location in document order (object members sorted by
// key, array elements by index, parents before children), then by schema
// traversal order.
func Collect(doc any, load schema.Loader, keywords ...string) ([]Annotation, error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, nil
	}
	raw, ok := obj["$schema"]
	if !ok {
		return nil, nil
	}
	s, ok := raw.(string)
	if !ok {
		return nil, &schema.RefError{Msg: "$schema must be a string"}
	}
	if schema.IsDialect(s) {
		return nil, nil
	}
	ref, ok := schema.ParseRef(s)
	if !ok {
		return nil, &schema.RefError{Msg: fmt.Sprintf("$schema %q is neither a schema revision path nor a supported dialect", s)}
	}
	c := newCollector(load, keywords)
	base := syntheticBase + ref.Path()
	if _, err := c.doc(base); err != nil {
		return nil, err
	}
	return c.run(base, schema.Instance(doc))
}

// CollectWith uses an explicit root schema document instead of doc's $schema.
// rootPath names the root for SchemaPath and for resolving references; it may
// be a revision path or any other label (e.g. "" for an unsaved schema).
func CollectWith(root any, rootPath string, doc any, load schema.Loader, keywords ...string) ([]Annotation, error) {
	c := newCollector(load, keywords)
	base := localBase
	if strings.HasPrefix(rootPath, "/") {
		base = syntheticBase + rootPath
	}
	c.rootLabel = rootPath
	root = jsonv.Clone(root)
	if err := c.comp.AddResource(base, root); err != nil {
		return nil, &schema.SchemaError{Msg: err.Error()}
	}
	c.docs[base] = root
	return c.run(base, schema.Instance(doc))
}

type collector struct {
	load      schema.Loader
	filter    map[string]bool
	comp      *jsonschema.Compiler
	docs      map[string]any                // base URL -> schema document
	compiled  map[string]*jsonschema.Schema // base#fragment -> validator
	regexps   map[string]*regexp.Regexp
	loadErr   error
	rootLabel string

	out  []item
	seen map[[3]string]bool
}

type item struct {
	a   Annotation
	key []tok
}

// tok is one step of an instance location, kept typed for ordering.
type tok struct {
	idx   int
	key   string
	isIdx bool
}

func newCollector(load schema.Loader, keywords []string) *collector {
	c := &collector{
		load:     load,
		docs:     map[string]any{},
		compiled: map[string]*jsonschema.Schema{},
		regexps:  map[string]*regexp.Regexp{},
		seen:     map[[3]string]bool{},
	}
	if len(keywords) > 0 {
		c.filter = map[string]bool{}
		for _, k := range keywords {
			c.filter[k] = true
		}
	}
	comp := jsonschema.NewCompiler()
	comp.DefaultDraft(jsonschema.Draft2020)
	comp.AssertFormat()
	comp.UseLoader(urlLoader(func(u string) (any, error) { return c.doc(u) }))
	c.comp = comp
	return c
}

type urlLoader func(string) (any, error)

func (f urlLoader) Load(u string) (any, error) { return f(u) }

// doc returns the schema document at base URL u, loading revision paths.
func (c *collector) doc(u string) (any, error) {
	if d, ok := c.docs[u]; ok {
		return d, nil
	}
	fail := func(err error) (any, error) {
		if c.loadErr == nil {
			c.loadErr = err
		}
		return nil, err
	}
	path, ok := strings.CutPrefix(u, syntheticBase)
	if !ok {
		return fail(&schema.RefError{Msg: fmt.Sprintf("reference %q is not a schema revision path", u)})
	}
	ref, ok := schema.ParseRef(path)
	if !ok {
		return fail(&schema.RefError{Msg: fmt.Sprintf("reference %q is not a schema revision path", path)})
	}
	if c.load == nil {
		return fail(&schema.UnavailableError{Ref: path})
	}
	d, err := c.load(ref)
	switch {
	case err == nil:
	case errors.Is(err, schema.ErrUnavailable):
		return fail(&schema.UnavailableError{Ref: path})
	case errors.Is(err, schema.ErrBranch):
		return fail(&schema.RefError{Msg: fmt.Sprintf("%s names a branch namespace", path)})
	default:
		return fail(fmt.Errorf("loading schema %s: %w", path, err))
	}
	switch dd := d.(type) {
	case bool:
	case map[string]any:
		if s, _ := dd["$schema"].(string); !schema.IsDialect(s) {
			return fail(&schema.SchemaError{Msg: path + " is not a schema document"})
		}
	default:
		return fail(&schema.SchemaError{Msg: path + " is not a schema document"})
	}
	if err := schema.CheckSchemaDocument(d, path); err != nil {
		return fail(err)
	}
	d = jsonv.Clone(d)
	c.docs[u] = d
	return d, nil
}

// label is the SchemaPath prefix for a base URL.
func (c *collector) label(base string) string {
	if base == localBase {
		return c.rootLabel
	}
	return strings.TrimPrefix(base, syntheticBase)
}

// loc is a subschema location: a document and a JSON pointer into it.
type loc struct {
	base string
	ptr  pointer.Pointer
}

func (l loc) child(toks ...string) loc {
	p := make(pointer.Pointer, 0, len(l.ptr)+len(toks))
	return loc{l.base, append(append(p, l.ptr...), toks...)}
}

func (l loc) id() string { return l.base + "#" + l.ptr.String() }

func fragment(p pointer.Pointer) string {
	var b strings.Builder
	for _, t := range p {
		t = strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1")
		b.WriteByte('/')
		b.WriteString(url.PathEscape(t))
	}
	return b.String()
}

// validates reports whether the subschema at l accepts inst.
func (c *collector) validates(l loc, inst any) (bool, error) {
	err := c.validate(l, inst)
	if err == nil {
		return true, nil
	}
	var ve *jsonschema.ValidationError
	if errors.As(err, &ve) {
		return false, nil
	}
	return false, err
}

func (c *collector) validate(l loc, inst any) error {
	key := l.id()
	sch := c.compiled[key]
	if sch == nil {
		var err error
		sch, err = c.comp.Compile(l.base + "#" + fragment(l.ptr))
		if err != nil {
			if c.loadErr != nil {
				return c.loadErr
			}
			return &schema.SchemaError{Msg: err.Error()}
		}
		c.compiled[key] = sch
	}
	return sch.Validate(inst)
}

func (c *collector) run(base string, doc any) ([]Annotation, error) {
	root := loc{base: base}
	if err := c.validate(root, doc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			if msg, ok := refCycle(ve); ok {
				return nil, &schema.SchemaError{Msg: msg}
			}
			return nil, toValidationError(ve)
		}
		return nil, err
	}
	if err := c.walk(root, doc, nil, 0, nil); err != nil {
		return nil, err
	}
	sort.SliceStable(c.out, func(i, j int) bool { return lessKey(c.out[i].key, c.out[j].key) })
	var res []Annotation
	for _, it := range c.out {
		res = append(res, it.a)
	}
	return res, nil
}

func lessKey(a, b []tok) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if x.isIdx && y.isIdx {
			if x.idx != y.idx {
				return x.idx < y.idx
			}
			continue
		}
		if x.key != y.key {
			return x.key < y.key
		}
	}
	return len(a) < len(b)
}

func instPointer(key []tok) string {
	p := make(pointer.Pointer, len(key))
	for i, t := range key {
		if t.isIdx {
			p[i] = strconv.Itoa(t.idx)
		} else {
			p[i] = t.key
		}
	}
	return p.String()
}

func appendKey(key []tok, t tok) []tok {
	out := make([]tok, 0, len(key)+1)
	return append(append(out, key...), t)
}

// lookup resolves the subschema value at l.
func (c *collector) lookup(l loc) (any, error) {
	d, err := c.doc(l.base)
	if err != nil {
		return nil, err
	}
	v, ok := pointer.Get(d, l.ptr)
	if !ok {
		return nil, &schema.SchemaError{Msg: fmt.Sprintf("unresolvable schema location %s", l.id())}
	}
	return v, nil
}

// resolveRef resolves a $ref / $dynamicRef value relative to base. A $ref to
// another revision is a revision path optionally followed by a JSON Pointer
// fragment (§6.1); anchors are resolved only within the same document.
func (c *collector) resolveRef(base, ref string) (loc, error) {
	if !strings.HasPrefix(ref, "#") {
		r, p, err := schema.SplitRef(ref)
		if err != nil {
			return loc{}, err
		}
		return loc{syntheticBase + r.Path(), p}, nil
	}
	target := base
	frag, err := url.PathUnescape(ref[1:])
	if err != nil {
		return loc{}, &schema.RefError{Msg: fmt.Sprintf("$ref %q: %v", ref, err)}
	}
	if frag == "" || strings.HasPrefix(frag, "/") {
		p, err := pointer.Parse(frag)
		if err != nil {
			return loc{}, &schema.RefError{Msg: fmt.Sprintf("$ref %q: %v", ref, err)}
		}
		return loc{target, p}, nil
	}
	d, err := c.doc(target)
	if err != nil {
		return loc{}, err
	}
	if p, ok := findAnchor(d, frag, nil); ok {
		return loc{target, p}, nil
	}
	return loc{}, &schema.SchemaError{Msg: fmt.Sprintf("anchor %q not found in %s", frag, c.label(target))}
}

// findAnchor searches a schema document for $anchor or $dynamicAnchor name.
func findAnchor(s any, name string, at pointer.Pointer) (pointer.Pointer, bool) {
	obj, ok := s.(map[string]any)
	if !ok {
		return nil, false
	}
	if a, _ := obj["$anchor"].(string); a == name {
		return at, true
	}
	if a, _ := obj["$dynamicAnchor"].(string); a == name {
		return at, true
	}
	sub := func(v any, toks ...string) (pointer.Pointer, bool) {
		p := append(append(pointer.Pointer{}, at...), toks...)
		return findAnchor(v, name, p)
	}
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		switch k {
		case "items", "contains", "additionalProperties", "not", "if", "then", "else",
			"propertyNames", "unevaluatedItems", "unevaluatedProperties", "contentSchema":
			if p, ok := sub(v, k); ok {
				return p, true
			}
		case "properties", "patternProperties", "$defs", "dependentSchemas":
			if m, ok := v.(map[string]any); ok {
				for _, n := range sortedKeys(m) {
					if p, ok := sub(m[n], k, n); ok {
						return p, true
					}
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			if arr, ok := v.([]any); ok {
				for i, e := range arr {
					if p, ok := sub(e, k, strconv.Itoa(i)); ok {
						return p, true
					}
				}
			}
		}
	}
	return nil, false
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (c *collector) regexp(re string) (*regexp.Regexp, error) {
	if r, ok := c.regexps[re]; ok {
		return r, nil
	}
	r, err := regexp.Compile(re)
	if err != nil {
		return nil, &schema.SchemaError{Msg: fmt.Sprintf("patternProperties %q: %v", re, err)}
	}
	c.regexps[re] = r
	return r, nil
}

// walk applies the subschema at l, already known to validate inst, to the
// instance location key. Its own x-* keywords are recorded, then applicators
// are followed. Children whose validity is implied by l's (properties, items,
// allOf, $ref, the taken if-branch, …) are walked directly; children that may
// fail independently (anyOf, oneOf, if, contains) are checked first.
//
// refs holds the schema locations entered through $ref at this instance
// location, to cut reference cycles that make no instance progress.
func (c *collector) walk(l loc, inst any, key []tok, depth int, refs map[string]bool) error {
	if depth > MaxDepth {
		return ErrDepth
	}
	s, err := c.lookup(l)
	if err != nil {
		return err
	}
	obj, ok := s.(map[string]any)
	if !ok {
		return nil // boolean schema: no annotations
	}

	// Own annotations.
	ptrStr := ""
	for _, k := range sortedKeys(obj) {
		if !strings.HasPrefix(k, "x-") || (c.filter != nil && !c.filter[k]) {
			continue
		}
		if ptrStr == "" {
			ptrStr = instPointer(key)
		}
		sp := c.label(l.base) + "#" + l.ptr.String()
		dk := [3]string{k, ptrStr, sp}
		if c.seen[dk] {
			continue
		}
		c.seen[dk] = true
		c.out = append(c.out, item{
			a:   Annotation{Keyword: k, Value: obj[k], Pointer: ptrStr, Instance: inst, SchemaPath: sp},
			key: key,
		})
	}

	same := func(cl loc) error { return c.walk(cl, inst, key, depth+1, refs) }
	maybe := func(cl loc) (bool, error) {
		ok, err := c.validates(cl, inst)
		if err != nil || !ok {
			return false, err
		}
		return true, same(cl)
	}
	viaRef := func(kw string) error {
		r, ok := obj[kw].(string)
		if !ok {
			return nil
		}
		target, err := c.resolveRef(l.base, r)
		if err != nil {
			return err
		}
		id := target.id()
		if refs[id] {
			return nil // cycle without instance progress
		}
		next := make(map[string]bool, len(refs)+1)
		for k := range refs {
			next[k] = true
		}
		next[id] = true
		return c.walk(target, inst, key, depth+1, next)
	}

	if err := viaRef("$ref"); err != nil {
		return err
	}
	// $dynamicRef is resolved statically, like $ref to an anchor in the
	// current document; dynamic scope is not tracked.
	if err := viaRef("$dynamicRef"); err != nil {
		return err
	}
	if arr, ok := obj["allOf"].([]any); ok {
		for i := range arr {
			if err := same(l.child("allOf", strconv.Itoa(i))); err != nil {
				return err
			}
		}
	}
	for _, kw := range []string{"anyOf", "oneOf"} {
		if arr, ok := obj[kw].([]any); ok {
			for i := range arr {
				if _, err := maybe(l.child(kw, strconv.Itoa(i))); err != nil {
					return err
				}
			}
		}
	}
	if _, ok := obj["if"]; ok {
		took, err := maybe(l.child("if"))
		if err != nil {
			return err
		}
		branch := "else"
		if took {
			branch = "then"
		}
		if _, ok := obj[branch]; ok {
			if err := same(l.child(branch)); err != nil {
				return err
			}
		}
	}

	switch v := inst.(type) {
	case map[string]any:
		if m, ok := obj["dependentSchemas"].(map[string]any); ok {
			for _, n := range sortedKeys(m) {
				if _, present := v[n]; present {
					if err := same(l.child("dependentSchemas", n)); err != nil {
						return err
					}
				}
			}
		}
		props, _ := obj["properties"].(map[string]any)
		pats, _ := obj["patternProperties"].(map[string]any)
		patKeys := sortedKeys(pats)
		_, hasAdditional := obj["additionalProperties"]
		for _, name := range sortedKeys(v) {
			ck := appendKey(key, tok{key: name})
			matched := false
			if _, ok := props[name]; ok {
				matched = true
				if err := c.walk(l.child("properties", name), v[name], ck, 0, nil); err != nil {
					return err
				}
			}
			for _, pk := range patKeys {
				re, err := c.regexp(pk)
				if err != nil {
					return err
				}
				if re.MatchString(name) {
					matched = true
					if err := c.walk(l.child("patternProperties", pk), v[name], ck, 0, nil); err != nil {
						return err
					}
				}
			}
			if !matched && hasAdditional {
				if err := c.walk(l.child("additionalProperties"), v[name], ck, 0, nil); err != nil {
					return err
				}
			}
		}
	case []any:
		prefix, _ := obj["prefixItems"].([]any)
		_, hasItems := obj["items"]
		_, hasContains := obj["contains"]
		for i, e := range v {
			ck := appendKey(key, tok{idx: i, isIdx: true})
			if i < len(prefix) {
				if err := c.walk(l.child("prefixItems", strconv.Itoa(i)), e, ck, 0, nil); err != nil {
					return err
				}
			} else if hasItems {
				if err := c.walk(l.child("items"), e, ck, 0, nil); err != nil {
					return err
				}
			}
			if hasContains {
				cl := l.child("contains")
				ok, err := c.validates(cl, e)
				if err != nil {
					return err
				}
				if ok {
					if err := c.walk(cl, e, ck, 0, nil); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// refCycle reports a reference cycle, which the library detects at
// validation time; it is a defect of the schema, not of the document.
func refCycle(ve *jsonschema.ValidationError) (string, bool) {
	if rc, ok := ve.ErrorKind.(*kind.RefCycle); ok {
		return ve.ErrorKind.LocalizedString(printer) + " (" + rc.URL + ")", true
	}
	for _, c := range ve.Causes {
		if msg, ok := refCycle(c); ok {
			return msg, true
		}
	}
	return "", false
}

// toValidationError flattens a library validation error into leaf details.
func toValidationError(ve *jsonschema.ValidationError) error {
	seen := map[schema.Detail]bool{}
	var out []schema.Detail
	var rec func(e *jsonschema.ValidationError)
	rec = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			d := schema.Detail{
				Pointer: pointer.Pointer(e.InstanceLocation).String(),
				Message: e.ErrorKind.LocalizedString(printer),
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
			return
		}
		for _, cause := range e.Causes {
			rec(cause)
		}
	}
	rec(ve)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pointer != out[j].Pointer {
			return out[i].Pointer < out[j].Pointer
		}
		return out[i].Message < out[j].Message
	})
	return &schema.ValidationError{Errors: out}
}
