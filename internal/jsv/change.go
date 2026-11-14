package jsv

import (
	"fmt"
	"strings"
)

// ValidateChange reports whether doc is valid against the schema, given
// that doc was produced from a document that WAS valid against this same
// schema by changes confined to the locations in changed. It returns what
// Validate(doc) would, as a verdict (the failure it names may be another
// one of several), while visiting only what the changes can have affected.
//
// changed holds JSON Pointers (RFC 6901) into doc. The contract is:
//
//   - the value at a location that is neither at or under a changed
//     location, nor an ancestor of one, is what it was;
//   - a proper ancestor of a changed location is the same container it
//     was (an object stays an object, an array an array), with the same
//     members or items except those on the way to a changed location, and
//     an array has the same length with every other item at the index it
//     had. So an insertion into or removal from an array is reported as
//     the array, not as an index in it; ChangedPaths does that.
//
// A pointer that names nothing in doc (a removed member) stands for its
// deepest ancestor that does exist. No pointers means nothing changed, and
// the root pointer "" means everything may have.
//
// How it stays sound: a schema's verdict on a value is the conjunction of
// its keywords' verdicts. At an ancestor of a changed location, each
// keyword is either
//
//   - an assertion on the value itself (type, required, minProperties,
//     maxItems, const, enum, uniqueItems, propertyNames, ...): rechecked;
//   - properties, patternProperties, additionalProperties, prefixItems,
//     items: the subschemas a member or item gets depend only on its name
//     or index, so an unchanged child keeps the verdict it had, and only
//     children on the way to a change are visited, by this same rule;
//   - $ref, allOf: the same instance, by this same rule;
//   - anything else (anyOf, oneOf, not, if/then/else, dependentSchemas,
//     contains, $dynamicRef): that keyword is evaluated in full on the
//     value, since its verdict is no conjunction over children.
//
// A schema with unevaluatedProperties or unevaluatedItems is evaluated in
// full where it applies, since those depend on what every other keyword
// evaluated. At a changed location itself everything is evaluated in full.
func (sc *Schema) ValidateChange(doc any, changed []string, o ValidateOptions) error {
	if len(changed) == 0 {
		if o.Stats != nil {
			o.Stats.Steps = 0
		}
		return nil
	}
	root := &change{}
	for _, p := range changed {
		if err := root.add(doc, p); err != nil {
			return err
		}
	}
	s := sc.newState(o)
	return s.finish(s.change(sc.root, doc, root), o)
}

// change is a node of the tree of changed locations: full if the value
// here is to be validated whole, else the children on the way to changes.
type change struct {
	full bool
	keys []string // in the order added, so runs are repeatable
	kids map[string]*change
}

// add marks the location ptr of doc as changed.
func (c *change) add(doc any, ptr string) error {
	if ptr != "" && ptr[0] != '/' {
		return fmt.Errorf("jsv: changed location %q is not a JSON Pointer", ptr)
	}
	v := doc
	for ptr != "" && !c.full {
		tok := ptr[1:]
		if i := strings.IndexByte(tok, '/'); i >= 0 {
			tok, ptr = tok[:i], tok[i:]
		} else {
			ptr = ""
		}
		tok = unescapeToken(tok)
		var next any
		switch x := v.(type) {
		case map[string]any:
			e, ok := x[tok]
			if !ok {
				c.setFull()
				return nil
			}
			next = e
		case []any:
			i, ok := arrayIndex(tok, len(x))
			if !ok {
				c.setFull()
				return nil
			}
			next = x[i]
		default:
			c.setFull()
			return nil
		}
		k := c.kids[tok]
		if k == nil {
			k = &change{}
			if c.kids == nil {
				c.kids = map[string]*change{}
			}
			c.kids[tok] = k
			c.keys = append(c.keys, tok)
		}
		c, v = k, next
	}
	c.setFull()
	return nil
}

func (c *change) setFull() { c.full, c.keys, c.kids = true, nil, nil }

// change evaluates n against v, a value whose changes are those of c.
func (s *state) change(n *node, v any, c *change) bool {
	if c.full || n.uneval || n.boolean != 0 {
		return s.eval(n, v, nil)
	}
	s.steps++
	if s.budget > 0 && s.steps > s.budget {
		s.over = true
		return false
	}
	s.hop++
	if s.hop > s.maxHop {
		s.loop = true
		return false
	}
	var ok bool
	// The dynamic scope is kept as full validation would have it here.
	if s.sch.dynamic && (len(s.scope) == 0 || s.scope[len(s.scope)-1] != n.res) {
		s.scope = append(s.scope, n.res)
		ok = s.changeBody(n, v, c)
		s.scope = s.scope[:len(s.scope)-1]
	} else {
		ok = s.changeBody(n, v, c)
	}
	s.hop--
	return ok
}

func (s *state) changeChild(n *node, v any, c *change) bool {
	h := s.hop
	s.hop = 0
	ok := s.change(n, v, c)
	s.hop = h
	return ok
}

func (s *state) changeBody(n *node, v any, c *change) bool {
	if !s.assert(n, v) {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		if n.propNames != nil && !s.propertyNames(n, x) {
			return false
		}
		if n.hasProps {
			for _, k := range c.keys {
				pv, kc := x[k], c.kids[k]
				hit := false
				if pn := n.propMap[k]; pn != nil {
					hit = true
					if !s.changeChild(pn, pv, kc) {
						return s.upProp(k, "properties", k)
					}
				}
				for i := range n.patProps {
					p := &n.patProps[i]
					if !p.re.MatchString(k) {
						continue
					}
					hit = true
					if !s.changeChild(p.n, pv, kc) {
						return s.upProp(k, "patternProperties", p.src)
					}
				}
				if !hit && n.addProps != nil && !s.changeChild(n.addProps, pv, kc) {
					return s.upProp(k, "additionalProperties", "")
				}
			}
		}
	case []any:
		if n.hasItems {
			for _, k := range c.keys {
				i, _ := arrayIndex(k, len(x))
				if i < len(n.prefix) {
					if !s.changeChild(n.prefix[i], x[i], c.kids[k]) {
						return s.upItem(i, "prefixItems", i)
					}
				} else if n.items != nil && !s.changeChild(n.items, x[i], c.kids[k]) {
					return s.upItem(i, "items", -1)
				}
			}
		}
		if n.contains != nil && !s.containsOK(n, x, v, nil) {
			return false
		}
	}
	if n.hasInPlace {
		if n.ref != nil && !s.change(n.ref, v, c) {
			return s.upKw("$ref")
		}
		for i, sub := range n.allOf {
			if !s.change(sub, v, c) {
				return s.upKwAt("allOf", i)
			}
		}
		if n.hasRest {
			return s.inPlaceRest(n, v, nil)
		}
	}
	return true
}

// ChangedPaths maps an RFC 6902 patch, as decoded JSON, to the locations
// ValidateChange is to be told of for the document the patch results in.
// It errs on the side of naming too much, and without the document it
// cannot tell an array index from a member named by digits:
//
//   - replace: its path;
//   - add: its path, or the parent of it if its last token is "-" or
//     digits (in an array, the items after it move);
//   - remove: the parent of its path;
//   - move: as a remove of from and an add of path; copy: as an add;
//   - test: nothing.
//
// ChangedPathsIn tells the two apart.
func ChangedPaths(ops []any) ([]string, error) {
	return changedPaths(nil, false, ops)
}

// ChangedPathsIn is ChangedPaths given doc, the document AFTER the patch:
// an add whose last token is digits is reported as its own path when its
// parent is an object in doc.
//
// The document after serves although a later operation may have changed
// what an earlier one's path names: the parent of the path can only have
// become another value, or moved, by an operation that is itself reported
// at the parent or above it, which covers the path.
func ChangedPathsIn(doc any, ops []any) ([]string, error) {
	return changedPaths(doc, true, ops)
}

func changedPaths(doc any, hasDoc bool, ops []any) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	emit := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	parent := func(p string) string {
		return p[:max(strings.LastIndexByte(p, '/'), 0)]
	}
	added := func(p string) {
		if p == "" {
			emit("")
			return
		}
		par := parent(p)
		last := p[len(par)+1:]
		indexLike := last == "-"
		if !indexLike {
			_, digits := digits(last)
			indexLike = digits
		}
		if indexLike {
			if hasDoc {
				if pv, ok := lookup(doc, par); ok {
					if _, isObj := pv.(map[string]any); isObj {
						emit(p)
						return
					}
				}
			}
			emit(par)
			return
		}
		emit(p)
	}
	for i, raw := range ops {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("jsv: patch operation %d is not an object", i)
		}
		op, _ := m["op"].(string)
		path, ok := m["path"].(string)
		if !ok || path != "" && path[0] != '/' {
			return nil, fmt.Errorf("jsv: patch operation %d has no JSON Pointer path", i)
		}
		switch op {
		case "test":
		case "replace":
			emit(path)
		case "add", "copy":
			added(path)
		case "remove":
			emit(parent(path))
		case "move":
			from, ok := m["from"].(string)
			if !ok || from != "" && from[0] != '/' {
				return nil, fmt.Errorf("jsv: patch operation %d has no JSON Pointer from", i)
			}
			emit(parent(from))
			added(path)
		default:
			return nil, fmt.Errorf("jsv: patch operation %d has unknown op %q", i, op)
		}
	}
	return out, nil
}
