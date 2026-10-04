package annot

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// Ref is one reference found in a document through x-ref (§6.5).
type Ref struct {
	Pointer    string // instance location of the string
	Raw        string // the string as found
	NS, Name   string
	Rev        string // "" for a live reference
	Entry      string // decoded fragment id, "" if none
	Key        string // the x-ref key pointer, "" if none
	Pinned     bool   // x-ref declared pinned
	SchemaPath string // where the x-ref keyword was found
}

// refStringRE is /r/{ns}/{name}[/rev/{id}][#{fragment}] with the §3.6 name
// grammar and the §3.2 id text form.
var refStringRE = regexp.MustCompile(`^/r/([a-z0-9][a-z0-9_-]{0,63})/([a-z0-9][a-z0-9._-]{0,127})(?:/rev/(1[a-z2-7]{32}))?(?:#(.*))?$`)

// ParseRefString parses a reference string /r/{ns}/{name}[/rev/{id}][#{fragment}].
// The fragment must be a non-empty RFC 3986 fragment; it is returned
// percent-decoded in Entry. Only NS, Name, Rev, Entry and Raw are set.
func ParseRefString(s string) (Ref, bool) {
	m := refStringRE.FindStringSubmatch(s)
	if m == nil {
		return Ref{}, false
	}
	r := Ref{Raw: s, NS: m[1], Name: m[2], Rev: m[3]}
	if strings.Contains(s, "#") {
		frag := m[4]
		if frag == "" || !validFragment(frag) {
			return Ref{}, false
		}
		id, err := url.PathUnescape(frag)
		if err != nil {
			return Ref{}, false
		}
		r.Entry = id
	}
	return r, true
}

// validFragment reports whether s uses only RFC 3986 fragment characters
// (pchar / "/" / "?"), with well-formed percent-encodings.
func validFragment(s string) bool {
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

// ResolveEntry finds the entry id names in target under the key pointer:
// either an array of objects with a string "id" member, or an object whose
// member names are the ids. ok is false if the entry doesn't exist.
func ResolveEntry(target any, key, id string) (entry any, ok bool) {
	p, err := pointer.Parse(key)
	if err != nil {
		return nil, false
	}
	c, ok := pointer.Get(target, p)
	if !ok {
		return nil, false
	}
	switch v := c.(type) {
	case []any:
		for _, e := range v {
			if o, ok := e.(map[string]any); ok {
				if s, ok := o["id"].(string); ok && s == id {
					return e, true
				}
			}
		}
	case map[string]any:
		e, ok := v[id]
		return e, ok
	}
	return nil, false
}

// FindRefs statically walks doc with its schema (named by doc's $schema,
// loaded through load) and returns every reference (§6.5). Untyped documents
// and schema documents return nil. The document is not validated.
//
// The walk over-approximates, as §6.5 intends: at every instance location
// every subschema that could apply is considered, including every branch of
// allOf, anyOf, oneOf, if, then and else, whether or not it validates. A
// string is reported when any such subschema carries x-ref and the string has
// the reference form; other strings are ignored. Mismatches between x-ref
// and the string (pinned but live, key but no fragment, …) are reported as
// found. Each distinct (location, pinned, key) is reported once, with the
// first schema location found. Order is document order.
func FindRefs(doc any, load schema.Loader) ([]Ref, error) {
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
	c := newCollector(load, nil)
	base := syntheticBase + ref.Path()
	if _, err := c.doc(base); err != nil {
		return nil, err
	}
	return c.findRefs(base, schema.Instance(doc))
}

// FindRefsWith is FindRefs with an explicit root schema document; rootPath is
// as for CollectWith.
func FindRefsWith(root any, rootPath string, doc any, load schema.Loader) ([]Ref, error) {
	c := newCollector(load, nil)
	base := localBase
	if strings.HasPrefix(rootPath, "/") {
		base = syntheticBase + rootPath
	}
	c.rootLabel = rootPath
	c.docs[base] = jsonv.Clone(root)
	return c.findRefs(base, schema.Instance(doc))
}

type refItem struct {
	r   Ref
	key []tok
}

type refWalker struct {
	c    *collector
	out  []refItem
	seen map[string]bool
}

func (c *collector) findRefs(base string, doc any) ([]Ref, error) {
	w := &refWalker{c: c, seen: map[string]bool{}}
	if err := w.walk(loc{base: base}, doc, nil, 0, nil); err != nil {
		return nil, err
	}
	sort.SliceStable(w.out, func(i, j int) bool { return lessKey(w.out[i].key, w.out[j].key) })
	var res []Ref
	for _, it := range w.out {
		res = append(res, it.r)
	}
	return res, nil
}

func (w *refWalker) walk(l loc, inst any, key []tok, depth int, refs map[string]bool) error {
	if depth > MaxDepth {
		return ErrDepth
	}
	s, err := w.c.lookup(l)
	if err != nil {
		return err
	}
	obj, ok := s.(map[string]any)
	if !ok {
		return nil
	}

	if xr, ok := obj["x-ref"]; ok {
		if str, ok := inst.(string); ok {
			if r, ok := ParseRefString(str); ok {
				if m, ok := xr.(map[string]any); ok {
					r.Pinned, _ = m["pinned"].(bool)
					r.Key, _ = m["key"].(string)
				}
				r.Pointer = instPointer(key)
				r.SchemaPath = w.c.label(l.base) + "#" + l.ptr.String()
				dk := r.Pointer + "\x00" + strconv.FormatBool(r.Pinned) + "\x00" + r.Key
				if !w.seen[dk] {
					w.seen[dk] = true
					w.out = append(w.out, refItem{r: r, key: key})
				}
			}
		}
	}

	same := func(cl loc) error { return w.walk(cl, inst, key, depth+1, refs) }
	viaRef := func(kw string) error {
		r, ok := obj[kw].(string)
		if !ok {
			return nil
		}
		target, err := w.c.resolveRef(l.base, r)
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
		return w.walk(target, inst, key, depth+1, next)
	}
	if err := viaRef("$ref"); err != nil {
		return err
	}
	if err := viaRef("$dynamicRef"); err != nil {
		return err
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf"} {
		if arr, ok := obj[kw].([]any); ok {
			for i := range arr {
				if err := same(l.child(kw, strconv.Itoa(i))); err != nil {
					return err
				}
			}
		}
	}
	for _, kw := range []string{"if", "then", "else", "not"} {
		if _, ok := obj[kw]; ok {
			if err := same(l.child(kw)); err != nil {
				return err
			}
		}
	}
	if _, ok := inst.(string); ok {
		if _, ok := obj["contentSchema"]; ok {
			// contentSchema applies to the string's content; the walk
			// over-approximates and judges the string itself (§6.5).
			if err := same(l.child("contentSchema")); err != nil {
				return err
			}
		}
	}

	down := func(cl loc, v any, ck []tok) error { return w.walk(cl, v, ck, 0, nil) }
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
		_, hasUneval := obj["unevaluatedProperties"]
		for _, name := range sortedKeys(v) {
			ck := appendKey(key, tok{key: name})
			if _, ok := obj["propertyNames"]; ok {
				// propertyNames applies a subschema to the member names,
				// which are strings of the document (§6.5).
				if err := down(l.child("propertyNames"), name, ck); err != nil {
					return err
				}
			}
			matched := false
			if _, ok := props[name]; ok {
				matched = true
				if err := down(l.child("properties", name), v[name], ck); err != nil {
					return err
				}
			}
			for _, pk := range patKeys {
				re, err := w.c.regexp(pk)
				if err != nil {
					return err
				}
				if re.MatchString(name) {
					matched = true
					if err := down(l.child("patternProperties", pk), v[name], ck); err != nil {
						return err
					}
				}
			}
			if !matched && hasAdditional {
				if err := down(l.child("additionalProperties"), v[name], ck); err != nil {
					return err
				}
			}
			if hasUneval { // over-approximation: may apply to any member
				if err := down(l.child("unevaluatedProperties"), v[name], ck); err != nil {
					return err
				}
			}
		}
	case []any:
		prefix, _ := obj["prefixItems"].([]any)
		_, hasItems := obj["items"]
		_, hasContains := obj["contains"]
		_, hasUneval := obj["unevaluatedItems"]
		for i, e := range v {
			ck := appendKey(key, tok{idx: i, isIdx: true})
			if i < len(prefix) {
				if err := down(l.child("prefixItems", strconv.Itoa(i)), e, ck); err != nil {
					return err
				}
			} else if hasItems {
				if err := down(l.child("items"), e, ck); err != nil {
					return err
				}
			}
			if hasContains {
				if err := down(l.child("contains"), e, ck); err != nil {
					return err
				}
			}
			if hasUneval {
				if err := down(l.child("unevaluatedItems"), e, ck); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
