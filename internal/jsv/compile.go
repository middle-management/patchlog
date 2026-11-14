// Package jsv is a JSON Schema draft 2020-12 validator for plain decoded
// JSON values (nil, bool, float64, string, []any, map[string]any).
//
// A schema is compiled once into an immutable tree of nodes with every
// reference resolved, every pattern compiled and every keyword prepared.
// Validation then walks that tree without allocating on the success path,
// stops at the first failure, and can be bounded by a step budget
// (ValidateOptions.Budget). ValidateChange revalidates only what a patch
// to a previously valid document can have affected.
//
// The package is a spike: nothing in the server uses it yet.
package jsv

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Draft2020 is the dialect this package implements.
const Draft2020 = "https://json-schema.org/draft/2020-12/schema"

// defaultBase is the base URI of a root schema compiled without one.
const defaultBase = "https://jsv.invalid/schema.json"

// Matcher is a compiled regular expression.
type Matcher = interface{ MatchString(string) bool }

// Options configure Compile.
type Options struct {
	// Load returns the decoded document at an absolute URI (no fragment),
	// for a $ref or $schema that names another document. The draft 2020-12
	// meta-schemas are built in and never reach Load. A nil Load refuses.
	Load func(uri string) (any, error)
	// Regexp compiles the patterns of pattern, patternProperties and the
	// regex format. The default is Go's regexp package.
	Regexp func(pattern string) (Matcher, error)
	// Formats adds to, or replaces, the built-in format checks. A format
	// with no check always passes.
	Formats map[string]func(string) bool
	// AssertFormat makes format an assertion. It is one anyway in a schema
	// whose meta-schema requires the format-assertion vocabulary.
	AssertFormat bool
	// SkipMetaSchema leaves out the validation of each schema document
	// against the draft 2020-12 meta-schema, for documents checked before.
	// Keywords are still checked for what compiling them needs.
	SkipMetaSchema bool
}

// CompileError reports a schema that cannot be compiled: a keyword of the
// wrong shape, a reference that names nothing, a pattern that does not
// compile, a document that cannot be loaded.
type CompileError struct {
	Location string // absolute location of the schema, URI#pointer
	Msg      string
	Err      error // the cause, if any (a Load error, say)
}

func (e *CompileError) Error() string {
	if e.Location == "" {
		return "jsv: " + e.Msg
	}
	return "jsv: " + e.Location + ": " + e.Msg
}

func (e *CompileError) Unwrap() error { return e.Err }

// UnsupportedError reports a schema that uses something this package does
// not implement, named by Keyword, so it is refused rather than
// mis-validated.
type UnsupportedError struct {
	Location string
	Keyword  string
	Msg      string
}

func (e *UnsupportedError) Error() string {
	return "jsv: " + e.Location + ": unsupported " + e.Keyword + ": " + e.Msg
}

// Schema is a compiled schema. It is immutable and safe for concurrent use.
type Schema struct {
	root    *node
	dynamic bool // some $dynamicRef resolves by dynamic scope
	cyclic  bool // some schema may come back to itself on the same instance
	nodes   int
	regexp  func(string) (Matcher, error)
}

// Nodes returns the number of schema nodes compiled.
func (s *Schema) Nodes() int { return s.nodes }

// The JSON types, as a bit set.
const (
	tNull uint8 = 1 << iota
	tBool
	tNumber
	tInteger
	tString
	tArray
	tObject
)

var typeNames = []string{"null", "boolean", "number", "integer", "string", "array", "object"}

func typeSetString(t uint8) string {
	var out []string
	for i, name := range typeNames {
		if t&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return strings.Join(out, " or ")
}

// Vocabularies, as a bit set.
const (
	vCore uint8 = 1 << iota
	vApplicator
	vUnevaluated
	vValidation
	vFormatAnnotation
	vFormatAssertion
	vContent
	vMetaData

	vDefault = vCore | vApplicator | vUnevaluated | vValidation | vFormatAnnotation | vContent | vMetaData
)

var vocabURIs = map[string]uint8{
	"https://json-schema.org/draft/2020-12/vocab/core":              vCore,
	"https://json-schema.org/draft/2020-12/vocab/applicator":        vApplicator,
	"https://json-schema.org/draft/2020-12/vocab/unevaluated":       vUnevaluated,
	"https://json-schema.org/draft/2020-12/vocab/validation":        vValidation,
	"https://json-schema.org/draft/2020-12/vocab/format-annotation": vFormatAnnotation,
	"https://json-schema.org/draft/2020-12/vocab/format-assertion":  vFormatAssertion,
	"https://json-schema.org/draft/2020-12/vocab/content":           vContent,
	"https://json-schema.org/draft/2020-12/vocab/meta-data":         vMetaData,
}

// otherDrafts are the dialects a $schema may name that this package
// refuses.
var otherDrafts = map[string]bool{
	"http://json-schema.org/schema":                true,
	"http://json-schema.org/draft-03/schema":       true,
	"http://json-schema.org/draft-04/schema":       true,
	"http://json-schema.org/draft-06/schema":       true,
	"http://json-schema.org/draft-07/schema":       true,
	"https://json-schema.org/draft/2019-09/schema": true,
	"https://json-schema.org/draft/next/schema":    true,
}

// node is one compiled schema. Every field is set by the compiler and
// read-only afterwards.
type node struct {
	loc string    // absolute location: document URI # JSON Pointer
	res *resource // the schema resource it belongs to

	boolean int8 // 1: always valid (true, or no assertion at all); -1: false; 0: see below

	// Which groups of keywords are present, so evaluation skips the rest.
	hasValue   bool // const or enum
	hasNum     bool
	hasStr     bool
	hasObj     bool // required, dependentRequired, min/maxProperties
	hasArr     bool // min/maxItems, uniqueItems
	hasProps   bool // properties, patternProperties, additionalProperties
	hasItems   bool // prefixItems, items
	hasInPlace bool // $ref, $dynamicRef, allOf, anyOf, oneOf, not, if, dependentSchemas
	hasRest    bool // the in-place applicators other than $ref and allOf
	uneval     bool // unevaluatedProperties or unevaluatedItems

	// Any instance.
	types    uint8 // 0: no type keyword
	hasConst bool
	constVal any
	enum     *enumSet

	// Numbers.
	hasMin, hasMax, hasXMin, hasXMax bool
	min, max, xmin, xmax             float64
	multipleOf                       *multiple

	// Strings.
	minLen, maxLen int // -1: none
	pattern        Matcher
	patternSrc     string
	format         func(string) bool
	formatName     string
	formatRegex    bool // the regex format, checked with Schema.regexp

	// Objects.
	minProps, maxProps int // -1: none
	required           []string
	requiredOther      []string // those of required that properties does not declare
	depRequired        []depRequired
	props              []prop
	propMap            map[string]*node
	patProps           []patProp
	addProps           *node
	propNames          *node
	depSchemas         []prop

	// Arrays.
	minItems, maxItems       int // -1: none
	unique                   bool
	prefix                   []*node
	items                    *node
	contains                 *node
	minContains, maxContains int // maxContains -1: none

	// In-place applicators.
	ref     *node
	dynRef  *node  // the target $dynamicRef resolves to statically
	dynName string // non-empty: look the anchor up in the dynamic scope
	allOf   []*node
	anyOf   []*node
	oneOf   []*node
	not     *node
	ifN     *node
	thenN   *node
	elseN   *node

	unevalProps *node
	unevalItems *node

	mark uint8 // cycle check
}

type prop struct {
	key      string
	n        *node
	required bool // key is in required: properties checks its presence in passing
}

type patProp struct {
	src string
	re  Matcher
	n   *node
}

type depRequired struct {
	key  string
	need []string
}

// enumSet is an enum prepared by kind, so a scalar is looked up without
// comparing it to every member.
type enumSet struct {
	hasNull, hasTrue, hasFalse bool
	nums                       []float64
	strs                       []string
	strSet                     map[string]struct{} // set when strs is long
	others                     []any               // arrays and objects
	all                        []any               // as written, for messages
}

func newEnumSet(vals []any) *enumSet {
	e := &enumSet{all: vals}
	for _, v := range vals {
		switch x := v.(type) {
		case nil:
			e.hasNull = true
		case bool:
			if x {
				e.hasTrue = true
			} else {
				e.hasFalse = true
			}
		case float64:
			e.nums = append(e.nums, x)
		case string:
			e.strs = append(e.strs, x)
		default:
			e.others = append(e.others, v)
		}
	}
	if len(e.strs) > 8 {
		e.strSet = make(map[string]struct{}, len(e.strs))
		for _, s := range e.strs {
			e.strSet[s] = struct{}{}
		}
	}
	return e
}

func (e *enumSet) has(v any) bool {
	switch x := v.(type) {
	case nil:
		return e.hasNull
	case bool:
		if x {
			return e.hasTrue
		}
		return e.hasFalse
	case float64:
		for _, n := range e.nums {
			if n == x {
				return true
			}
		}
		return false
	case string:
		if e.strSet != nil {
			_, ok := e.strSet[x]
			return ok
		}
		for _, s := range e.strs {
			if s == x {
				return true
			}
		}
		return false
	}
	for _, o := range e.others {
		if equal(o, v) {
			return true
		}
	}
	return false
}

// resource is a schema resource: a document root, or a subschema with $id.
type resource struct {
	id         string // absolute URI, no fragment: the base of its references
	doc        *document
	ptr        string            // where it is in doc
	anchors    map[string]string // $anchor and $dynamicAnchor name -> pointer in doc
	dynAnchors map[string]string // $dynamicAnchor name -> pointer in doc
	dynNodes   map[string]*node  // dynAnchors, compiled
	vocab      uint8
}

// document is one loaded JSON document holding schemas.
type document struct {
	url   string
	root  any
	resAt map[string]*resource // pointer -> the resource rooted there
}

// resourceFor returns the resource a location belongs to: the one rooted
// at its nearest ancestor (or itself).
func (d *document) resourceFor(ptr string) *resource {
	for {
		if r := d.resAt[ptr]; r != nil {
			return r
		}
		i := strings.LastIndexByte(ptr, '/')
		if i < 0 {
			return d.resAt[""]
		}
		ptr = ptr[:i]
	}
}

type compiler struct {
	opts      Options
	regexp    func(string) (Matcher, error)
	formats   map[string]func(string) bool
	docs      map[string]*document
	resources map[string]*resource
	resList   []*resource
	nodes     map[string]*node
	dynamic   bool
	isCyclic  bool // cyclic(), as of cyclicAt nodes
	cyclicAt  int
}

//go:embed metaschemas
var metaFS embed.FS

var metaDocs = sync.OnceValue(func() map[string]any {
	docs := map[string]any{}
	for _, name := range []string{"schema", "meta/core", "meta/applicator", "meta/unevaluated", "meta/validation",
		"meta/format-annotation", "meta/format-assertion", "meta/content", "meta/meta-data"} {
		data, err := metaFS.ReadFile("metaschemas/" + name + ".json")
		if err != nil {
			panic("jsv: embedded meta-schema " + name + ": " + err.Error())
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			panic("jsv: embedded meta-schema " + name + ": " + err.Error())
		}
		docs["https://json-schema.org/draft/2020-12/"+name] = v
	}
	return docs
})

// embedded returns a draft 2020-12 meta-schema document, or nil. The
// documents are shared and never modified.
func embedded(uri string) any { return metaDocs()[uri] }

var (
	metaOnce     sync.Once
	metaCompiled *Schema
)

// metaSchema returns the draft 2020-12 meta-schema, compiled with formats
// asserted.
func metaSchema() *Schema {
	metaOnce.Do(func() {
		meta, err := Compile(embedded(Draft2020), Draft2020, Options{AssertFormat: true, SkipMetaSchema: true})
		if err != nil {
			panic("jsv: compiling the embedded meta-schema: " + err.Error())
		}
		metaCompiled = meta
	})
	return metaCompiled
}

// Compile compiles the schema document root, whose base URI is baseURI (the
// URI it would be retrieved from; a default is used if empty).
func Compile(root any, baseURI string, opts Options) (*Schema, error) {
	if baseURI == "" {
		baseURI = defaultBase
	}
	if i := strings.IndexByte(baseURI, '#'); i >= 0 {
		baseURI = baseURI[:i]
	}
	c := NewCompiler(opts)
	if err := c.AddResource(baseURI, root); err != nil {
		return nil, err
	}
	return c.Compile(baseURI)
}

// Compiler compiles several schemas over the same documents: the
// documents are loaded and checked once, and what the schemas share is
// compiled once. It is not safe for concurrent use; the schemas it
// returns are.
type Compiler struct{ c *compiler }

// NewCompiler returns a Compiler with no documents.
func NewCompiler(opts Options) *Compiler {
	c := &compiler{
		opts:      opts,
		regexp:    opts.Regexp,
		formats:   map[string]func(string) bool{},
		docs:      map[string]*document{},
		resources: map[string]*resource{},
		nodes:     map[string]*node{},
	}
	if c.regexp == nil {
		c.regexp = func(p string) (Matcher, error) { return regexp.Compile(p) }
	}
	for name, f := range builtinFormats {
		c.formats[name] = f
	}
	for name, f := range opts.Formats {
		c.formats[name] = f
	}
	return &Compiler{c}
}

// AddResource makes doc the document at uri (absolute, no fragment), so
// that it is not asked of Options.Load.
func (cc *Compiler) AddResource(uri string, doc any) error {
	if cc.c.docs[uri] != nil {
		return &CompileError{Location: uri, Msg: "the document is already added"}
	}
	_, err := cc.c.addDoc(uri, doc)
	return err
}

// Compile compiles the schema at uri: a document, or with a fragment a
// JSON Pointer or an anchor into one.
func (cc *Compiler) Compile(uri string) (*Schema, error) {
	c := cc.c
	n, _, err := c.resolveRef(&resource{}, uri, uri)
	if err != nil {
		return nil, err
	}
	if c.dynamic {
		// A $dynamicRef may land on any $dynamicAnchor of any resource in
		// scope, so compile them all. Compiling can load more documents.
		for i := 0; i < len(c.resList); i++ {
			r := c.resList[i]
			if len(r.dynNodes) == len(r.dynAnchors) {
				continue
			}
			names := make([]string, 0, len(r.dynAnchors))
			for name := range r.dynAnchors {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				ptr := r.dynAnchors[name]
				raw, _ := lookup(r.doc.root, ptr)
				dn, err := c.compileAt(r.doc, ptr, raw)
				if err != nil {
					return nil, err
				}
				if r.dynNodes == nil {
					r.dynNodes = map[string]*node{}
				}
				r.dynNodes[name] = dn
			}
		}
	}
	// Nodes compiled for an earlier schema may be shared with this one,
	// so both flags are those of everything compiled so far: a schema
	// compiled before a $dynamicRef or a cycle appeared reaches neither.
	if len(c.nodes) != c.cyclicAt {
		c.cyclicAt, c.isCyclic = len(c.nodes), c.cyclic()
	}
	return &Schema{root: n, dynamic: c.dynamic, cyclic: c.dynamic || c.isCyclic, nodes: len(c.nodes), regexp: c.regexp}, nil
}

// getDoc returns the document at uri, loading it if need be.
func (c *compiler) getDoc(uri, from string) (*document, error) {
	if d := c.docs[uri]; d != nil {
		return d, nil
	}
	root := embedded(uri)
	if root == nil {
		if c.opts.Load == nil {
			return nil, &CompileError{Location: from, Msg: fmt.Sprintf("cannot resolve %q: no loader", uri)}
		}
		var err error
		root, err = c.opts.Load(uri)
		if err != nil {
			return nil, &CompileError{Location: from, Msg: fmt.Sprintf("loading %q: %v", uri, err), Err: err}
		}
	}
	return c.addDoc(uri, root)
}

func (c *compiler) addDoc(uri string, root any) (*document, error) {
	d := &document{url: uri, root: root, resAt: map[string]*resource{}}
	c.docs[uri] = d
	r := &resource{id: uri, doc: d, vocab: vDefault}
	d.resAt[""] = r
	c.resList = append(c.resList, r)
	if _, dup := c.resources[uri]; !dup {
		c.resources[uri] = r
	}
	if err := c.index(d, root, "", r); err != nil {
		return nil, err
	}
	if err := c.checkMeta(d); err != nil {
		return nil, err
	}
	return d, nil
}

// checkMeta validates a schema document against the draft 2020-12
// meta-schema, formats asserted (regex with the caller's engine), as the
// library this package replaced does when it compiles. It finds
// what compiling does not look at: a malformed schema nothing refers to, a
// keyword that is only an annotation here. A document of a dialect with
// its own meta-schema is not checked against that one.
func (c *compiler) checkMeta(d *document) error {
	if c.opts.SkipMetaSchema || embedded(d.url) != nil {
		return nil
	}
	if m, ok := d.root.(map[string]any); ok {
		if s, ok := m["$schema"].(string); ok && strings.TrimSuffix(s, "#") != Draft2020 {
			return nil
		}
	}
	s := metaSchema().newState(ValidateOptions{})
	s.regexp = c.regexp
	err := s.finish(s.eval(s.sch.root, d.root, nil), ValidateOptions{})
	var ve *ValidationError
	if errors.As(err, &ve) {
		return &CompileError{Location: d.url + "#" + ve.InstancePath, Msg: "not a valid schema: " + ve.Message}
	}
	return err
}

// Where subschemas are.
var (
	schemaKeywords = []string{"additionalProperties", "items", "contains", "propertyNames", "not", "if", "then", "else",
		"unevaluatedItems", "unevaluatedProperties", "contentSchema"}
	schemaArrayKeywords = []string{"allOf", "anyOf", "oneOf", "prefixItems"}
	schemaMapKeywords   = []string{"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
)

// index finds the resources ($id) and anchors of a document, visiting only
// the places a schema can be: an $id in a const, say, identifies nothing.
func (c *compiler) index(d *document, raw any, ptr string, res *resource) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	loc := d.url + "#" + ptr
	if idv, ok := m["$id"]; ok {
		id, ok := idv.(string)
		if !ok {
			return &CompileError{Location: loc, Msg: "$id must be a string"}
		}
		abs, frag, err := resolveURI(res.id, id)
		if err != nil {
			return &CompileError{Location: loc, Msg: fmt.Sprintf("$id %q: %v", id, err)}
		}
		if frag != "" {
			return &CompileError{Location: loc, Msg: fmt.Sprintf("$id %q has a fragment", id)}
		}
		if ptr == "" {
			res.id = abs
		} else {
			res = &resource{id: abs, doc: d, ptr: ptr, vocab: res.vocab}
			d.resAt[ptr] = res
			c.resList = append(c.resList, res)
		}
		if _, dup := c.resources[abs]; !dup {
			c.resources[abs] = res
		}
	}
	if res.ptr == ptr {
		if sv, ok := m["$schema"]; ok {
			s, ok := sv.(string)
			if !ok {
				return &CompileError{Location: loc, Msg: "$schema must be a string"}
			}
			v, err := c.vocabOf(strings.TrimSuffix(s, "#"), loc)
			if err != nil {
				return err
			}
			res.vocab = v
		}
	}
	for _, kw := range [...]string{"$anchor", "$dynamicAnchor"} {
		av, ok := m[kw]
		if !ok {
			continue
		}
		name, ok := av.(string)
		if !ok {
			return &CompileError{Location: loc, Msg: kw + " must be a string"}
		}
		if res.anchors == nil {
			res.anchors = map[string]string{}
		}
		if prev, dup := res.anchors[name]; dup && prev != ptr {
			return &CompileError{Location: loc, Msg: fmt.Sprintf("anchor %q is defined twice in %s", name, res.id)}
		}
		res.anchors[name] = ptr
		if kw == "$dynamicAnchor" {
			if res.dynAnchors == nil {
				res.dynAnchors = map[string]string{}
			}
			res.dynAnchors[name] = ptr
		}
	}
	for _, kw := range schemaKeywords {
		if sub, ok := m[kw]; ok {
			if err := c.index(d, sub, ptr+"/"+kw, res); err != nil {
				return err
			}
		}
	}
	for _, kw := range schemaArrayKeywords {
		if arr, ok := m[kw].([]any); ok {
			for i, sub := range arr {
				if err := c.index(d, sub, ptr+"/"+kw+"/"+strconv.Itoa(i), res); err != nil {
					return err
				}
			}
		}
	}
	for _, kw := range schemaMapKeywords {
		if obj, ok := m[kw].(map[string]any); ok {
			for k, sub := range obj {
				if err := c.index(d, sub, ptr+"/"+kw+"/"+escapeToken(k), res); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// vocabOf returns the vocabularies of the dialect a $schema names.
func (c *compiler) vocabOf(dialect, loc string) (uint8, error) {
	if dialect == Draft2020 {
		return vDefault, nil
	}
	if otherDrafts[dialect] {
		return 0, &UnsupportedError{Location: loc, Keyword: "$schema", Msg: fmt.Sprintf("dialect %q; only draft 2020-12 is implemented", dialect)}
	}
	md, err := c.getDoc(dialect, loc)
	if err != nil {
		return 0, err
	}
	mm, _ := md.root.(map[string]any)
	if ms, ok := mm["$schema"].(string); ok {
		if ms = strings.TrimSuffix(ms, "#"); otherDrafts[ms] {
			return 0, &UnsupportedError{Location: loc, Keyword: "$schema", Msg: fmt.Sprintf("dialect %q is a %q meta-schema; only draft 2020-12 is implemented", dialect, ms)}
		}
	}
	vv, ok := mm["$vocabulary"]
	if !ok {
		return vDefault, nil
	}
	vm, ok := vv.(map[string]any)
	if !ok {
		return 0, &CompileError{Location: dialect, Msg: "$vocabulary must be an object"}
	}
	v := vCore
	for uri, req := range vm {
		bit, known := vocabURIs[uri]
		if !known {
			if req == true {
				return 0, &UnsupportedError{Location: loc, Keyword: "$vocabulary", Msg: fmt.Sprintf("dialect %q requires vocabulary %q", dialect, uri)}
			}
			continue
		}
		v |= bit
	}
	return v, nil
}

// resolveURI resolves ref against base and returns the absolute URI
// without its fragment, and the fragment, percent-decoded.
func resolveURI(base, ref string) (abs, frag string, err error) {
	rawFrag := ""
	if i := strings.IndexByte(ref, '#'); i >= 0 {
		ref, rawFrag = ref[:i], ref[i+1:]
	}
	if rawFrag != "" {
		frag, err = url.PathUnescape(rawFrag)
		if err != nil {
			return "", "", err
		}
	}
	if ref == "" {
		return base, frag, nil
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", "", err
	}
	if r.IsAbs() {
		return r.String(), frag, nil
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", "", err
	}
	return b.ResolveReference(r).String(), frag, nil
}

func escapeToken(s string) string {
	if !strings.ContainsAny(s, "~/") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func unescapeToken(s string) string {
	if strings.IndexByte(s, '~') < 0 {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}

// arrayIndex reads a JSON Pointer token as an index into an array of n
// elements.
func arrayIndex(tok string, n int) (int, bool) {
	if tok == "" || len(tok) > 1 && tok[0] == '0' || len(tok) > 18 {
		return 0, false
	}
	i := 0
	for j := 0; j < len(tok); j++ {
		if tok[j] < '0' || tok[j] > '9' {
			return 0, false
		}
		i = i*10 + int(tok[j]-'0')
	}
	return i, i < n
}

// lookup returns the value at JSON Pointer ptr in v.
func lookup(v any, ptr string) (any, bool) {
	for ptr != "" {
		if ptr[0] != '/' {
			return nil, false
		}
		ptr = ptr[1:]
		tok := ptr
		if i := strings.IndexByte(ptr, '/'); i >= 0 {
			tok, ptr = ptr[:i], ptr[i:]
		} else {
			ptr = ""
		}
		switch x := v.(type) {
		case map[string]any:
			c, ok := x[unescapeToken(tok)]
			if !ok {
				return nil, false
			}
			v = c
		case []any:
			i, ok := arrayIndex(tok, len(x))
			if !ok {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// resolveRef compiles the schema a $ref or $dynamicRef at loc names. It
// also returns the name of the anchor the reference ends in, if the target
// declares it as a $dynamicAnchor.
func (c *compiler) resolveRef(res *resource, ref, loc string) (*node, string, error) {
	abs, frag, err := resolveURI(res.id, ref)
	if err != nil {
		return nil, "", &CompileError{Location: loc, Msg: fmt.Sprintf("reference %q: %v", ref, err)}
	}
	target := c.resources[abs]
	if target == nil {
		d, err := c.getDoc(abs, loc)
		if err != nil {
			return nil, "", err
		}
		target = d.resAt[""]
	}
	d := target.doc
	ptr, anchor := target.ptr, ""
	switch {
	case frag == "":
	case frag[0] == '/':
		ptr += frag
	default:
		p, ok := target.anchors[frag]
		if !ok {
			return nil, "", &CompileError{Location: loc, Msg: fmt.Sprintf("reference %q: no anchor %q in %s", ref, frag, target.id)}
		}
		ptr, anchor = p, frag
	}
	raw, ok := lookup(d.root, ptr)
	if !ok {
		return nil, "", &CompileError{Location: loc, Msg: fmt.Sprintf("reference %q: nothing at %s#%s", ref, d.url, ptr)}
	}
	n, err := c.compileAt(d, ptr, raw)
	if err != nil {
		return nil, "", err
	}
	dyn := ""
	if anchor != "" {
		if _, ok := target.dynAnchors[anchor]; ok {
			dyn = anchor
		}
	}
	return n, dyn, nil
}

// compileAt compiles the schema raw found at ptr of d, once.
func (c *compiler) compileAt(d *document, ptr string, raw any) (*node, error) {
	key := d.url + "#" + ptr
	if n := c.nodes[key]; n != nil {
		return n, nil
	}
	n := &node{loc: key, res: d.resourceFor(ptr), minLen: -1, maxLen: -1, minProps: -1, maxProps: -1,
		minItems: -1, maxItems: -1, minContains: 1, maxContains: -1}
	switch x := raw.(type) {
	case bool:
		n.boolean = -1
		if x {
			n.boolean = 1
		}
		c.nodes[key] = n
		return n, nil
	case map[string]any:
		c.nodes[key] = n
		b := &builder{c: c, d: d, ptr: ptr, m: x, n: n}
		if err := b.build(); err != nil {
			return nil, err
		}
		return n, nil
	}
	return nil, &CompileError{Location: key, Msg: fmt.Sprintf("a schema must be an object or a boolean, got %s", kindOf(raw))}
}

// builder compiles the keywords of one schema object.
type builder struct {
	c   *compiler
	d   *document
	ptr string
	m   map[string]any
	n   *node
}

func (b *builder) errf(kw, format string, args ...any) error {
	return &CompileError{Location: b.n.loc, Msg: kw + ": " + fmt.Sprintf(format, args...)}
}

func (b *builder) sub(kw string) (*node, error) {
	raw, ok := b.m[kw]
	if !ok {
		return nil, nil
	}
	return b.c.compileAt(b.d, b.ptr+"/"+kw, raw)
}

func (b *builder) subList(kw string) ([]*node, error) {
	raw, ok := b.m[kw]
	if !ok {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, b.errf(kw, "must be an array")
	}
	if len(arr) == 0 && kw != "prefixItems" {
		return nil, b.errf(kw, "must not be empty")
	}
	out := make([]*node, len(arr))
	for i, s := range arr {
		n, err := b.c.compileAt(b.d, b.ptr+"/"+kw+"/"+strconv.Itoa(i), s)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

func (b *builder) subMap(kw string) ([]prop, error) {
	raw, ok := b.m[kw]
	if !ok {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, b.errf(kw, "must be an object")
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]prop, len(keys))
	for i, k := range keys {
		n, err := b.c.compileAt(b.d, b.ptr+"/"+kw+"/"+escapeToken(k), obj[k])
		if err != nil {
			return nil, err
		}
		out[i] = prop{key: k, n: n}
	}
	return out, nil
}

func (b *builder) num(kw string) (float64, bool, error) {
	raw, ok := b.m[kw]
	if !ok {
		return 0, false, nil
	}
	f, ok := raw.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false, b.errf(kw, "must be a number")
	}
	return f, true, nil
}

// count reads a non-negative integer keyword; def is its value if absent.
func (b *builder) count(kw string, def int) (int, error) {
	f, ok, err := b.num(kw)
	if err != nil || !ok {
		return def, err
	}
	if f < 0 || f != math.Trunc(f) {
		return 0, b.errf(kw, "must be a non-negative integer")
	}
	if f > math.MaxInt32 {
		return math.MaxInt32, nil
	}
	return int(f), nil
}

func (b *builder) strings(kw string, raw any) ([]string, error) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, b.errf(kw, "must be an array of strings")
	}
	out := make([]string, len(arr))
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return nil, b.errf(kw, "must be an array of strings")
		}
		out[i] = s
	}
	return out, nil
}

func (b *builder) build() error {
	n, m, c := b.n, b.m, b.c
	vocab := n.res.vocab
	var err error

	// Core.
	if rv, ok := m["$ref"]; ok {
		ref, ok := rv.(string)
		if !ok {
			return b.errf("$ref", "must be a string")
		}
		if n.ref, _, err = c.resolveRef(n.res, ref, n.loc); err != nil {
			return err
		}
	}
	if rv, ok := m["$dynamicRef"]; ok {
		ref, ok := rv.(string)
		if !ok {
			return b.errf("$dynamicRef", "must be a string")
		}
		if n.dynRef, n.dynName, err = c.resolveRef(n.res, ref, n.loc); err != nil {
			return err
		}
		if n.dynName != "" {
			c.dynamic = true
		}
	}
	// Keywords of earlier drafts that draft 2020-12 replaced: ignoring
	// them, as unknown keywords are, would quietly drop a constraint the
	// author meant, so they are refused.
	for kw, use := range map[string]string{
		"$recursiveRef": "$dynamicRef",
		"dependencies":  "dependentRequired and dependentSchemas",
	} {
		if _, ok := m[kw]; ok {
			return &UnsupportedError{Location: n.loc, Keyword: kw, Msg: "not a draft 2020-12 keyword; use " + use}
		}
	}
	if vocab&vValidation != 0 {
		if err = b.validation(); err != nil {
			return err
		}
	}
	if fv, ok := m["format"]; ok && vocab&(vFormatAnnotation|vFormatAssertion) != 0 {
		name, ok := fv.(string)
		if !ok {
			return b.errf("format", "must be a string")
		}
		if c.opts.AssertFormat || vocab&vFormatAssertion != 0 {
			n.formatName = name
			if f := c.formats[name]; f != nil {
				n.format = f
			} else if name == "regex" {
				n.formatRegex = true
			}
		}
	}
	if vocab&vApplicator != 0 {
		if err = b.applicators(); err != nil {
			return err
		}
	}
	if vocab&vUnevaluated != 0 {
		if n.unevalProps, err = b.sub("unevaluatedProperties"); err != nil {
			return err
		}
		if n.unevalItems, err = b.sub("unevaluatedItems"); err != nil {
			return err
		}
	}
	if vocab&vContent != 0 {
		if _, err = b.sub("contentSchema"); err != nil {
			return err
		}
	}

	n.requiredOther = n.required
	if len(n.props) > 0 && len(n.required) > 0 {
		n.requiredOther = nil
		for _, k := range n.required {
			if n.propMap[k] == nil {
				n.requiredOther = append(n.requiredOther, k)
			}
		}
		for i := range n.props {
			for _, k := range n.required {
				n.props[i].required = n.props[i].required || k == n.props[i].key
			}
		}
	}
	n.hasValue = n.hasConst || n.enum != nil
	n.hasNum = n.hasMin || n.hasMax || n.hasXMin || n.hasXMax || n.multipleOf != nil
	n.hasStr = n.minLen >= 0 || n.maxLen >= 0 || n.pattern != nil || n.format != nil || n.formatRegex
	n.hasObj = n.minProps >= 0 || n.maxProps >= 0 || len(n.required) > 0 || len(n.depRequired) > 0
	n.hasArr = n.minItems >= 0 || n.maxItems >= 0 || n.unique
	n.hasProps = len(n.props) > 0 || len(n.patProps) > 0 || n.addProps != nil
	n.hasItems = len(n.prefix) > 0 || n.items != nil
	n.hasRest = n.dynRef != nil || n.anyOf != nil || n.oneOf != nil || n.not != nil || n.ifN != nil || len(n.depSchemas) > 0
	n.hasInPlace = n.hasRest || n.ref != nil || n.allOf != nil
	n.uneval = n.unevalProps != nil || n.unevalItems != nil
	if n.types == 0 && !n.hasValue && !n.hasNum && !n.hasStr && !n.hasObj && !n.hasArr && !n.hasProps && !n.hasItems &&
		n.propNames == nil && n.contains == nil && !n.hasInPlace && !n.uneval {
		n.boolean = 1
	}
	return nil
}

func (b *builder) validation() error {
	n, m := b.n, b.m
	var err error
	if tv, ok := m["type"]; ok {
		var names []string
		if s, ok := tv.(string); ok {
			names = []string{s}
		} else if names, err = b.strings("type", tv); err != nil {
			return b.errf("type", "must be a string or an array of strings")
		}
		for _, name := range names {
			i := sort.SearchStrings(sortedTypeNames, name)
			if i == len(sortedTypeNames) || sortedTypeNames[i] != name {
				return b.errf("type", "unknown type %q", name)
			}
			n.types |= sortedTypeBits[i]
		}
		if n.types == 0 {
			// "type": [] admits nothing.
			n.types = 1 << 7
		}
	}
	if cv, ok := m["const"]; ok {
		n.hasConst, n.constVal = true, cv
	}
	if ev, ok := m["enum"]; ok {
		arr, ok := ev.([]any)
		if !ok {
			return b.errf("enum", "must be an array")
		}
		n.enum = newEnumSet(arr)
	}
	if n.min, n.hasMin, err = b.num("minimum"); err != nil {
		return err
	}
	if n.max, n.hasMax, err = b.num("maximum"); err != nil {
		return err
	}
	if n.xmin, n.hasXMin, err = b.num("exclusiveMinimum"); err != nil {
		return err
	}
	if n.xmax, n.hasXMax, err = b.num("exclusiveMaximum"); err != nil {
		return err
	}
	if f, ok, err := b.num("multipleOf"); err != nil {
		return err
	} else if ok {
		if f <= 0 {
			return b.errf("multipleOf", "must be greater than 0")
		}
		n.multipleOf = newMultiple(f)
	}
	if n.minLen, err = b.count("minLength", -1); err != nil {
		return err
	}
	if n.maxLen, err = b.count("maxLength", -1); err != nil {
		return err
	}
	if pv, ok := m["pattern"]; ok {
		src, ok := pv.(string)
		if !ok {
			return b.errf("pattern", "must be a string")
		}
		if n.pattern, err = b.c.regexp(src); err != nil {
			return b.errf("pattern", "%q does not compile: %v", src, err)
		}
		n.patternSrc = src
	}
	if n.minProps, err = b.count("minProperties", -1); err != nil {
		return err
	}
	if n.maxProps, err = b.count("maxProperties", -1); err != nil {
		return err
	}
	if rv, ok := m["required"]; ok {
		if n.required, err = b.strings("required", rv); err != nil {
			return err
		}
	}
	if dv, ok := m["dependentRequired"]; ok {
		obj, ok := dv.(map[string]any)
		if !ok {
			return b.errf("dependentRequired", "must be an object")
		}
		for k, v := range obj {
			need, err := b.strings("dependentRequired", v)
			if err != nil {
				return err
			}
			n.depRequired = append(n.depRequired, depRequired{key: k, need: need})
		}
		sort.Slice(n.depRequired, func(i, j int) bool { return n.depRequired[i].key < n.depRequired[j].key })
	}
	if n.minItems, err = b.count("minItems", -1); err != nil {
		return err
	}
	if n.maxItems, err = b.count("maxItems", -1); err != nil {
		return err
	}
	if uv, ok := m["uniqueItems"]; ok {
		if n.unique, ok = uv.(bool); !ok {
			return b.errf("uniqueItems", "must be a boolean")
		}
	}
	if n.minContains, err = b.count("minContains", 1); err != nil {
		return err
	}
	if n.maxContains, err = b.count("maxContains", -1); err != nil {
		return err
	}
	return nil
}

var (
	sortedTypeNames = []string{"array", "boolean", "integer", "null", "number", "object", "string"}
	sortedTypeBits  = []uint8{tArray, tBool, tInteger, tNull, tNumber, tObject, tString}
)

func (b *builder) applicators() error {
	n := b.n
	var err error
	if n.props, err = b.subMap("properties"); err != nil {
		return err
	}
	if len(n.props) > 0 {
		n.propMap = make(map[string]*node, len(n.props))
		for _, p := range n.props {
			n.propMap[p.key] = p.n
		}
	}
	pats, err := b.subMap("patternProperties")
	if err != nil {
		return err
	}
	for _, p := range pats {
		re, err := b.c.regexp(p.key)
		if err != nil {
			return b.errf("patternProperties", "%q does not compile: %v", p.key, err)
		}
		n.patProps = append(n.patProps, patProp{src: p.key, re: re, n: p.n})
	}
	if n.addProps, err = b.sub("additionalProperties"); err != nil {
		return err
	}
	if n.propNames, err = b.sub("propertyNames"); err != nil {
		return err
	}
	if n.depSchemas, err = b.subMap("dependentSchemas"); err != nil {
		return err
	}
	if n.prefix, err = b.subList("prefixItems"); err != nil {
		return err
	}
	if n.items, err = b.sub("items"); err != nil {
		return err
	}
	if n.contains, err = b.sub("contains"); err != nil {
		return err
	}
	if n.allOf, err = b.subList("allOf"); err != nil {
		return err
	}
	if n.anyOf, err = b.subList("anyOf"); err != nil {
		return err
	}
	if n.oneOf, err = b.subList("oneOf"); err != nil {
		return err
	}
	if n.not, err = b.sub("not"); err != nil {
		return err
	}
	if n.ifN, err = b.sub("if"); err != nil {
		return err
	}
	if n.thenN, err = b.sub("then"); err != nil {
		return err
	}
	if n.elseN, err = b.sub("else"); err != nil {
		return err
	}
	if n.ifN == nil {
		// then and else do nothing without if.
		n.thenN, n.elseN = nil, nil
	}
	return nil
}

// inPlace calls f for each schema n applies to the same instance by a
// reference known at compile time.
func (n *node) inPlace(f func(*node) error) error {
	one := func(t *node) error {
		if t == nil {
			return nil
		}
		return f(t)
	}
	for _, t := range [...]*node{n.ref, n.dynRef, n.not, n.ifN, n.thenN, n.elseN} {
		if err := one(t); err != nil {
			return err
		}
	}
	for _, l := range [...][]*node{n.allOf, n.anyOf, n.oneOf} {
		for _, t := range l {
			if err := f(t); err != nil {
				return err
			}
		}
	}
	for _, p := range n.depSchemas {
		if err := f(p.n); err != nil {
			return err
		}
	}
	return nil
}

// cyclic reports whether some schema applies itself to the same instance
// through references known at compile time, as {"$ref": "#"} does.
// Validation then watches for it; most schemas need not.
func (c *compiler) cyclic() bool {
	errCycle := errors.New("cycle")
	for _, n := range c.nodes {
		n.mark = 0
	}
	var visit func(n *node) error
	visit = func(n *node) error {
		switch n.mark {
		case 1:
			return errCycle
		case 2:
			return nil
		}
		n.mark = 1
		if err := n.inPlace(visit); err != nil {
			return err
		}
		n.mark = 2
		return nil
	}
	for _, n := range c.nodes {
		if visit(n) != nil {
			return true
		}
	}
	return false
}

func kindOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		if x == math.Trunc(x) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// MetaSchema compiles the draft 2020-12 meta-schema with opts, to validate
// schema documents with: Collect then says all that is wrong with one.
func MetaSchema(opts Options) (*Schema, error) {
	opts.SkipMetaSchema = true
	return Compile(embedded(Draft2020), Draft2020, opts)
}
