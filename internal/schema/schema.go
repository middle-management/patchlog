// Package schema resolves and applies JSON Schema (draft 2020-12) validation
// for documents that opt in with a top-level "$schema" (§6.1, §6.2 step 5).
//
// Schemas are addressed only by revision path (/r/{ns}/{name}/rev/{id}). The
// underlying library never touches the network or the file system: revision
// paths are served through a caller-supplied Loader under a synthetic base URL,
// and dialect meta-schemas come from the library's embedded copies.
package schema

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/lru"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// RefPattern is the only accepted form of a schema revision reference (§6.1).
const RefPattern = `^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$`

var refRE = regexp.MustCompile(RefPattern)

// Dialect2020 is the draft 2020-12 meta-schema URL.
const Dialect2020 = "https://json-schema.org/draft/2020-12/schema"

// syntheticBase is the absolute base under which revision paths are registered
// with the library. The .invalid TLD guarantees it never resolves.
const syntheticBase = "https://patchlog.invalid"

// newSchemaURL is the base URL of a dialect document being checked before it
// has a revision path. It is never loaded.
const newSchemaURL = syntheticBase + "/new-schema"

// Ref is a parsed schema revision path.
type Ref struct{ NS, Name, Rev string }

// ParseRef parses a revision path. No normalisation is applied.
func ParseRef(s string) (Ref, bool) {
	if !refRE.MatchString(s) {
		return Ref{}, false
	}
	parts := strings.Split(s, "/") // "", "r", ns, name, "rev", id
	return Ref{NS: parts[2], Name: parts[3], Rev: parts[5]}, true
}

// Path returns the revision path of r.
func (r Ref) Path() string { return "/r/" + r.NS + "/" + r.Name + "/rev/" + r.Rev }

// anchorName is the grammar of $anchor and $dynamicAnchor, so of the
// plain names a fragment can resolve.
var anchorName = regexp.MustCompile(`^[A-Za-z_][-A-Za-z0-9._]*$`)

// RefTarget is what a foreign $ref names (§6.1): a schema revision and, by
// its fragment, a JSON Pointer or a plain name into it.
type RefTarget struct {
	Ref     Ref
	Pointer pointer.Pointer // the decoded pointer; nil for the whole revision or a name
	Anchor  string          // a plain name, which an $anchor or $dynamicAnchor of the revision must define; "" if none
}

// ParseRefTarget parses a foreign $ref value: a schema revision path
// optionally followed by "#" and a fragment (§6.1), written as an RFC 3986
// URI fragment: only fragment characters and well-formed percent-encodings
// that decode to valid UTF-8. The fragment is percent-decoded before it is
// read, as RFC 6901 section 6 reads a pointer from a fragment, as the
// library resolves one, and as v0.55 read every fragment, so a schema it
// stored with "#%2F$defs%2Fk" still names /$defs/k (§6.1). Decoded, one
// that is empty or starts with "/" is a JSON Pointer (RFC 6901, so "~"
// only as "~0" or "~1"); any other is a plain name, which compiling
// resolves against the anchors of the revision. A malformed path or
// fragment is a *RefError (schema_ref); a plain name outside the grammar
// of anchors names nothing, which makes the schema invalid, a
// *SchemaError.
func ParseRefTarget(s string) (RefTarget, error) {
	docPart, rawFrag, hasFrag := strings.Cut(s, "#")
	ref, ok := ParseRef(docPart)
	if !ok {
		return RefTarget{}, &RefError{Msg: fmt.Sprintf("$ref %q is neither a same-document fragment nor a schema revision path", s)}
	}
	if !hasFrag {
		return RefTarget{Ref: ref}, nil
	}
	if !validURIFragment(rawFrag) {
		return RefTarget{}, &RefError{Msg: fmt.Sprintf("$ref %q: fragment is not a valid URI fragment", s)}
	}
	dec, uerr := url.PathUnescape(rawFrag)
	if uerr != nil || !utf8.ValidString(dec) {
		return RefTarget{}, &RefError{Msg: fmt.Sprintf("$ref %q: fragment is not valid percent-encoded UTF-8", s)}
	}
	if dec != "" && dec[0] != '/' {
		if !anchorName.MatchString(dec) {
			return RefTarget{}, &SchemaError{Msg: fmt.Sprintf("$ref %q: fragment %q is neither a JSON Pointer nor a name an anchor can define", s, rawFrag)}
		}
		return RefTarget{Ref: ref, Anchor: dec}, nil
	}
	frag, perr := pointer.Parse(dec)
	if perr != nil {
		return RefTarget{}, &RefError{Msg: fmt.Sprintf("$ref %q: fragment of a schema revision is not a JSON Pointer", s)}
	}
	return RefTarget{Ref: ref, Pointer: frag}, nil
}

// SplitRef is ParseRefTarget for callers that want the revision a foreign
// $ref names, and a pointer fragment if it has one: frag is nil for the
// whole revision and for a plain-name fragment, whose name only
// ParseRefTarget gives.
func SplitRef(s string) (ref Ref, frag pointer.Pointer, err error) {
	t, err := ParseRefTarget(s)
	return t.Ref, t.Pointer, err
}

// validURIFragment reports whether s uses only RFC 3986 fragment characters
// (pchar / "/" / "?") with well-formed percent-encodings.
func validURIFragment(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/?", c) >= 0:
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// IsDialect reports whether s is an accepted dialect URL: a $schema value that
// marks the document itself as a schema.
func IsDialect(s string) bool { return s == Dialect2020 }

// IsSchemaDoc reports whether doc is a schema: an object whose own $schema
// is a dialect URL (§6.1).
func IsSchemaDoc(doc any) bool {
	m, ok := doc.(map[string]any)
	if !ok {
		return false
	}
	s, _ := m["$schema"].(string)
	return IsDialect(s)
}

// Loader fetches the document at a schema revision. See the package errors.
type Loader func(ref Ref) (any, error)

var (
	// ErrUnavailable: the revision is unknown or purged (422 schema_unavailable).
	ErrUnavailable = errors.New("schema unavailable")
	// ErrBranch: the revision names a branch namespace (422 schema_ref).
	ErrBranch = errors.New("schema reference names a branch namespace")
	// ErrForbidden: the caller lacks read on the schema's namespace.
	ErrForbidden = errors.New("no read access to schema namespace")
)

// RefError reports a malformed or disallowed $schema, $ref or $dynamicRef,
// or a stored schema's $id other than its own path (422 schema_ref).
type RefError struct{ Msg string }

func (e *RefError) Error() string { return "schema_ref: " + e.Msg }

// UnavailableError reports an unknown or purged schema revision (422 schema_unavailable).
type UnavailableError struct{ Ref string }

func (e *UnavailableError) Error() string { return "schema_unavailable: " + e.Ref }

// Detail is one validation failure, located by a pointer into the instance.
type Detail struct {
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

// ValidationError reports that a document does not validate (422 invalid).
type ValidationError struct{ Errors []Detail }

func (e *ValidationError) Error() string {
	var b strings.Builder
	b.WriteString("invalid:")
	for i, d := range e.Errors {
		if i > 0 {
			b.WriteByte(';')
		}
		fmt.Fprintf(&b, " %s: %s", d.Pointer, d.Message)
	}
	return b.String()
}

// SchemaError reports that a schema (the document itself, or a referenced
// revision) is not a valid schema (422 invalid).
type SchemaError struct{ Msg string }

func (e *SchemaError) Error() string { return "invalid schema: " + e.Msg }

// forbiddenError wraps ErrForbidden with the offending path.
type forbiddenError struct{ path string }

func (e *forbiddenError) Error() string { return ErrForbidden.Error() + ": " + e.path }
func (e *forbiddenError) Unwrap() error { return ErrForbidden }

// RefPath returns the revision path a load failure (unknown, purged or not
// readable) is about, or "" if err names none.
func RefPath(err error) string {
	var fe *forbiddenError
	if errors.As(err, &fe) {
		return fe.path
	}
	var ue *UnavailableError
	if errors.As(err, &ue) {
		return ue.Ref
	}
	return ""
}

var printer = message.NewPrinter(language.English)

// Validator compiles and caches schemas by revision path. Safe for concurrent use.
//
// Both caches keep the most recently used: compiled schemas, and the
// checked schema documents they were compiled from (a schema's $ref
// closure). A schema evicted is loaded and compiled again when next used.
// They were unbounded, so a deployment whose schemas get new revisions
// kept every revision it ever validated against until restart.
//
// A schema compiles under the Rules marker of the revision a document's
// $schema names (§6.1), so compiled schemas are kept by path and marker.
type Validator struct {
	mu       sync.Mutex
	compiled lru.Cache[compiledKey, *jsonschema.Schema] // revision path and marker -> compiled root
	docs     lru.Cache[string, any]                     // revision path -> checked schema document
	meta     *jsonschema.Schema                         // draft 2020-12 meta-schema, for schemas written now
}

// compiledKey keys a compiled schema: its revision path and the rules it
// compiled under.
type compiledKey struct {
	path  string
	rules Rules
}

// The schemas kept: compiled, and their documents (a compiled schema's
// closure may span several).
const (
	maxCompiledSchemas = 512
	maxSchemaDocs      = 2048
)

// NewValidator returns an empty Validator.
func NewValidator() *Validator {
	c := newCompiler(nil, V073)
	meta, err := c.Compile(Dialect2020)
	if err != nil {
		panic("schema: compiling bundled meta-schema: " + err.Error())
	}
	return &Validator{
		compiled: lru.Cache[compiledKey, *jsonschema.Schema]{MaxEntries: maxCompiledSchemas},
		docs:     lru.Cache[string, any]{MaxEntries: maxSchemaDocs},
		meta:     meta,
	}
}

type urlLoaderFunc func(url string) (any, error)

func (f urlLoaderFunc) Load(url string) (any, error) { return f(url) }

func newCompiler(load urlLoaderFunc, r Rules) *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	r.Configure(c)
	if load == nil {
		load = func(url string) (any, error) { return nil, fmt.Errorf("refusing to load %q", url) }
	}
	c.UseLoader(load)
	return c
}

// freshNonce is the fresh-nonce form of §6.4.1: 128 bits as 26 base32
// characters.
var freshNonce = regexp.MustCompile(`^[a-z2-7]{26}$`)

// Names valid under §3.6, as core.ValidNSName and core.ValidResourceName,
// which this package can't import.
var (
	nsNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	resNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// Successor reports whether v is a $successor of the form of §8.1: a bare
// resource name, for one in the same namespace, or /r/{ns}/{name}, for one
// in another, with names valid under §3.6.
func Successor(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if resNameRe.MatchString(s) {
		return true
	}
	rest, ok := strings.CutPrefix(s, "/r/")
	if !ok {
		return false
	}
	ns, name, ok := strings.Cut(rest, "/")
	return ok && nsNameRe.MatchString(ns) && resNameRe.MatchString(name)
}

// LeftOut reports whether top-level member k with value v is one §6.2
// step 5 leaves out of the instance: $schema, a $nonce of the fresh-nonce
// form, and a $successor of the form of §8.1. A $nonce or $successor of
// any other form is data. At a raw document's root they aren't part of
// the blob reference either (§7.8).
func LeftOut(k string, v any) bool {
	switch k {
	case "$schema":
		return true
	case "$nonce":
		s, ok := v.(string)
		return ok && freshNonce.MatchString(s)
	case "$successor":
		return Successor(v)
	}
	return false
}

// Instance returns what §6.2 step 5 validates for a document: the document
// without the top-level members LeftOut names. They are mechanics rather
// than data, so closed schemas needn't declare them, and schemas can't
// constrain them. Reference walks (§6.5) and clients validating at E3
// (§E.3.2) use the same instance. doc itself is never modified.
func Instance(doc any) any {
	obj, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	n := 0
	for _, k := range [...]string{"$schema", "$nonce", "$successor"} {
		if v, ok := obj[k]; ok && LeftOut(k, v) {
			n++
		}
	}
	if n == 0 {
		return doc
	}
	out := make(map[string]any, len(obj)-n)
	for k, v := range obj {
		if !LeftOut(k, v) {
			out[k] = v
		}
	}
	return out
}

// Validate implements §6.2 step 5 for a resulting document. A document
// that is a schema (a dialect $schema) is checked as one written now:
// in write mode (CheckSchemaDocument), compiled under V073. A schema
// revision a document names compiles under Legacy, as every stored
// revision does until revisions keep their markers (ValidateRules).
func (v *Validator) Validate(doc any, load Loader) error {
	return v.ValidateRules(doc, load, Legacy)
}

// ValidateRules is Validate, compiling the schema revision doc's $schema
// names under rules, the marker it was written under (§6.1). The marker
// of that revision governs its whole $ref closure.
func (v *Validator) ValidateRules(doc any, load Loader, rules Rules) error {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := obj["$schema"]
	if !ok {
		return nil
	}
	s, ok := raw.(string)
	if !ok {
		return &RefError{Msg: "$schema must be a string"}
	}
	if IsDialect(s) {
		return v.validateSchemaDocument(doc, load)
	}
	ref, ok := ParseRef(s)
	if !ok {
		return &RefError{Msg: fmt.Sprintf("$schema %q is neither a schema revision path nor a supported dialect", s)}
	}
	sch, err := v.compile(ref, load, rules)
	if err != nil {
		return err
	}
	return toValidationError(sch.Validate(Instance(doc)))
}

// validateSchemaDocument checks a document whose $schema is a dialect URL,
// as a schema written now. A top-level $nonce or $successor that step 5
// leaves out isn't a keyword: it is left out before the document is
// checked against its dialect, checked and compiled (§6.5).
func (v *Validator) validateSchemaDocument(doc any, load Loader) error {
	doc = leaveOut(doc)
	if err := toValidationError(v.meta.Validate(doc)); err != nil {
		return err
	}
	if err := CheckSchemaDocument(doc, ""); err != nil {
		return err
	}
	// Compile it too, so unresolvable fragments, plain names no anchor
	// defines and unavailable revisions are caught now rather than when a
	// document first references this schema (§6.1).
	var loadErr error
	c := newCompiler(v.urlLoader(load, &loadErr), V073)
	if err := c.AddResource(newSchemaURL, doc); err != nil {
		return &SchemaError{Msg: err.Error()}
	}
	if _, err := c.Compile(newSchemaURL); err != nil {
		if loadErr != nil {
			return loadErr
		}
		return &SchemaError{Msg: err.Error()}
	}
	return nil
}

func (v *Validator) compile(ref Ref, load Loader, rules Rules) (*jsonschema.Schema, error) {
	path := ref.Path()
	key := compiledKey{path, rules}
	v.mu.Lock()
	sch, _ := v.compiled.Get(key)
	v.mu.Unlock()
	if sch != nil {
		return sch, nil
	}
	var loadErr error
	c := newCompiler(v.urlLoader(load, &loadErr), rules)
	sch, err := c.Compile(syntheticBase + path)
	if err != nil {
		if loadErr != nil {
			return nil, loadErr
		}
		return nil, &SchemaError{Msg: err.Error()}
	}
	v.mu.Lock()
	if prev, _ := v.compiled.Get(key); prev != nil {
		sch = prev
	} else {
		v.compiled.Put(key, sch, 1)
	}
	v.mu.Unlock()
	return sch, nil
}

// urlLoader serves only revision paths under syntheticBase, through the
// document cache and then the caller's loader. The first failure is recorded
// in *loadErr so it can be reported with its proper kind.
func (v *Validator) urlLoader(load Loader, loadErr *error) urlLoaderFunc {
	return func(url string) (any, error) {
		fail := func(err error) (any, error) {
			if *loadErr == nil {
				*loadErr = err
			}
			return nil, err
		}
		path, ok := strings.CutPrefix(url, syntheticBase)
		if !ok {
			return fail(&RefError{Msg: fmt.Sprintf("reference %q is not a schema revision path", url)})
		}
		ref, ok := ParseRef(path)
		if !ok {
			return fail(&RefError{Msg: fmt.Sprintf("reference %q is not a schema revision path", path)})
		}
		v.mu.Lock()
		doc, cached := v.docs.Get(path)
		v.mu.Unlock()
		if cached {
			return doc, nil
		}
		if load == nil {
			return fail(&UnavailableError{Ref: path})
		}
		doc, err := load(ref)
		switch {
		case err == nil:
		case errors.Is(err, ErrUnavailable):
			return fail(&UnavailableError{Ref: path})
		case errors.Is(err, ErrBranch):
			return fail(&RefError{Msg: fmt.Sprintf("%s names a branch namespace", path)})
		case errors.Is(err, ErrForbidden):
			return fail(&forbiddenError{path: path})
		default:
			return fail(fmt.Errorf("loading schema %s: %w", path, err))
		}
		if err := checkStoredSchema(doc, path); err != nil {
			return fail(err)
		}
		doc = jsonv.Clone(leaveOut(doc))
		v.mu.Lock()
		if prev, ok := v.docs.Get(path); ok {
			doc = prev
		} else {
			v.docs.Put(path, doc, 1)
		}
		v.mu.Unlock()
		return doc, nil
	}
}

// checkStoredSchema defensively re-checks a schema loaded by revision
// path, in stored mode (CheckSchemaDocument): a schema stored under an
// earlier version is compiled as that version did (§6.1).
func checkStoredSchema(doc any, path string) error {
	switch d := doc.(type) {
	case bool:
		return nil
	case map[string]any:
		s, _ := d["$schema"].(string)
		if !IsDialect(s) {
			return &SchemaError{Msg: fmt.Sprintf("%s is not a schema document", path)}
		}
	default:
		return &SchemaError{Msg: fmt.Sprintf("%s is not a schema document", path)}
	}
	if err := CheckSchemaDocument(doc, path); err != nil {
		var re *RefError
		if errors.As(err, &re) {
			return &SchemaError{Msg: path + ": " + re.Msg}
		}
		return err
	}
	return nil
}

// toValidationError flattens a library validation error into leaf Details.
func toValidationError(err error) error {
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return &SchemaError{Msg: err.Error()}
	}
	seen := map[Detail]bool{}
	var out []Detail
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			d := Detail{
				Pointer: pointer.Pointer(e.InstanceLocation).String(),
				Message: e.ErrorKind.LocalizedString(printer),
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pointer != out[j].Pointer {
			return out[i].Pointer < out[j].Pointer
		}
		return out[i].Message < out[j].Message
	})
	return &ValidationError{Errors: out}
}
