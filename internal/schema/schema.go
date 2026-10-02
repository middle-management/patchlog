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

// SplitRef parses a foreign $ref value: a schema revision path optionally
// followed by "#" and a fragment (§6.1). The fragment must be empty or a JSON
// Pointer (RFC 6901, so it starts with "/"), written as an RFC 3986 URI
// fragment: only fragment characters, well-formed percent-encodings that decode
// to valid UTF-8, and "~" only as "~0" or "~1". Anchors ("#foo") are not
// resolved across revisions and are rejected. The returned Ref is the bare
// revision; frag is the decoded pointer ("" for the whole revision).
func SplitRef(s string) (ref Ref, frag pointer.Pointer, err error) {
	docPart, rawFrag, _ := strings.Cut(s, "#")
	ref, ok := ParseRef(docPart)
	if !ok {
		return Ref{}, nil, &RefError{Msg: fmt.Sprintf("$ref %q is neither a same-document fragment nor a schema revision path", s)}
	}
	if !strings.Contains(s, "#") {
		return ref, nil, nil
	}
	if !validURIFragment(rawFrag) {
		return Ref{}, nil, &RefError{Msg: fmt.Sprintf("$ref %q: fragment is not a valid URI fragment", s)}
	}
	dec, uerr := url.PathUnescape(rawFrag)
	if uerr != nil || !utf8.ValidString(dec) {
		return Ref{}, nil, &RefError{Msg: fmt.Sprintf("$ref %q: fragment is not valid percent-encoded UTF-8", s)}
	}
	frag, perr := pointer.Parse(dec)
	if perr != nil {
		return Ref{}, nil, &RefError{Msg: fmt.Sprintf("$ref %q: fragment of a schema revision must be a JSON Pointer", s)}
	}
	return ref, frag, nil
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

// RefError reports a malformed or disallowed $schema, $ref or $id (422 schema_ref).
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

var printer = message.NewPrinter(language.English)

// Validator compiles and caches schemas by revision path. Safe for concurrent use.
type Validator struct {
	mu       sync.Mutex
	compiled map[string]*jsonschema.Schema // revision path -> compiled root
	docs     map[string]any                // revision path -> checked schema document
	meta     *jsonschema.Schema            // draft 2020-12 meta-schema
}

// NewValidator returns an empty Validator.
func NewValidator() *Validator {
	c := newCompiler(nil)
	meta, err := c.Compile(Dialect2020)
	if err != nil {
		panic("schema: compiling bundled meta-schema: " + err.Error())
	}
	return &Validator{
		compiled: map[string]*jsonschema.Schema{},
		docs:     map[string]any{},
		meta:     meta,
	}
}

type urlLoaderFunc func(url string) (any, error)

func (f urlLoaderFunc) Load(url string) (any, error) { return f(url) }

func newCompiler(load urlLoaderFunc) *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if load == nil {
		load = func(url string) (any, error) { return nil, fmt.Errorf("refusing to load %q", url) }
	}
	c.UseLoader(load)
	return c
}

// freshNonce is the fresh-nonce form of §6.4.1: 128 bits as 26 base32
// characters.
var freshNonce = regexp.MustCompile(`^[a-z2-7]{26}$`)

// Instance returns what §6.2 step 5 validates for a document: the document
// without its top-level $schema, and without a top-level $nonce of the
// fresh-nonce form. They are mechanics rather than data, so closed schemas
// needn't declare them. Reference walks (§6.5) and clients validating at
// E3 use the same instance. doc itself is never modified.
func Instance(doc any) any {
	obj, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	n, hasNonce := obj["$nonce"].(string)
	strip := hasNonce && freshNonce.MatchString(n)
	if _, ok := obj["$schema"]; !ok && !strip {
		return doc
	}
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		if k == "$schema" || (k == "$nonce" && strip) {
			continue
		}
		out[k] = v
	}
	return out
}

// Validate implements §6.2 step 5 for a resulting document.
func (v *Validator) Validate(doc any, load Loader) error {
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
	sch, err := v.compile(ref, load)
	if err != nil {
		return err
	}
	return toValidationError(sch.Validate(Instance(doc)))
}

// validateSchemaDocument checks a document whose $schema is a dialect URL.
func (v *Validator) validateSchemaDocument(doc any, load Loader) error {
	if err := toValidationError(v.meta.Validate(doc)); err != nil {
		return err
	}
	if err := CheckSchemaDocument(doc, ""); err != nil {
		return err
	}
	// Compile it too, so unresolvable fragments and unavailable revisions are
	// caught now rather than when a document first references this schema.
	var loadErr error
	c := newCompiler(v.urlLoader(load, &loadErr))
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

func (v *Validator) compile(ref Ref, load Loader) (*jsonschema.Schema, error) {
	path := ref.Path()
	v.mu.Lock()
	sch := v.compiled[path]
	v.mu.Unlock()
	if sch != nil {
		return sch, nil
	}
	var loadErr error
	c := newCompiler(v.urlLoader(load, &loadErr))
	sch, err := c.Compile(syntheticBase + path)
	if err != nil {
		if loadErr != nil {
			return nil, loadErr
		}
		return nil, &SchemaError{Msg: err.Error()}
	}
	v.mu.Lock()
	if prev := v.compiled[path]; prev != nil {
		sch = prev
	} else {
		v.compiled[path] = sch
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
		doc, cached := v.docs[path]
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
		doc = jsonv.Clone(doc)
		v.mu.Lock()
		if prev, ok := v.docs[path]; ok {
			doc = prev
		} else {
			v.docs[path] = doc
		}
		v.mu.Unlock()
		return doc, nil
	}
}

// checkStoredSchema defensively re-checks a schema loaded by revision path.
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
