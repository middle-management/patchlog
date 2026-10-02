package schemaimport

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// A typed document's top-level $schema is validated against the schema it
// names (§6.1), so a schema that is closed at the instance root rejects every
// document that uses it unless it declares $schema. Any imported resource can
// be named by a document, so for each one the subschemas that apply at the
// instance root are found (the root, and what it reaches through $ref, allOf
// and, conservatively, every branch of anyOf/oneOf/if/then/else and
// dependentSchemas) and the closed ones get a $schema property.

const stubPrefix = "@"

// nodeRef is a subschema of a bundle's converted content.
type nodeRef struct {
	res string // resource name
	ptr pointer.Pointer
}

func (n nodeRef) String() string { return n.res + "#" + n.ptr.String() }

type declaration struct {
	docs    map[string]any // converted content by resource name; refs between resources are stubs
	seen    map[string]bool
	order   []nodeRef // reached at the instance root, in discovery order
	rootSet map[string]bool
	below   map[string]bool // reached somewhere other than at the instance root
}

func nodeKey(res string, ptr pointer.Pointer) string { return res + "\x00" + ptr.String() }

// resolveStub resolves a $ref of converted content: a same-document fragment
// or a stub "@name#fragment".
func resolveStub(res, ref string) (string, pointer.Pointer, bool) {
	doc, frag, _ := strings.Cut(ref, "#")
	if strings.HasPrefix(doc, stubPrefix) {
		res = doc[len(stubPrefix):]
	} else if doc != "" {
		return "", nil, false
	}
	dec, err := url.PathUnescape(frag)
	if err != nil {
		return "", nil, false
	}
	p, err := pointer.Parse(dec)
	if err != nil {
		return "", nil, false
	}
	return res, p, true
}

func (d *declaration) visit(res string, ptr pointer.Pointer, atRoot bool) {
	doc, ok := d.docs[res]
	if !ok {
		return
	}
	node, ok := pointer.Get(doc, ptr)
	if !ok {
		return
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	key := nodeKey(res, ptr)
	flag := "b"
	if atRoot {
		flag = "r"
	}
	if d.seen[key+flag] {
		return
	}
	d.seen[key+flag] = true
	if atRoot {
		if !d.rootSet[key] {
			d.rootSet[key] = true
			d.order = append(d.order, nodeRef{res, ptr})
		}
	} else {
		d.below[key] = true
	}
	sub := func(root bool, toks ...string) {
		d.visit(res, append(append(pointer.Pointer{}, ptr...), toks...), root)
	}
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		switch k {
		case "allOf", "anyOf", "oneOf", "prefixItems":
			if a, ok := v.([]any); ok {
				for i := range a {
					sub(atRoot && k != "prefixItems", k, strconv.Itoa(i))
				}
			}
		case "if", "then", "else":
			sub(atRoot, k)
		case "not", "items", "contains", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "contentSchema":
			sub(false, k)
		case "properties", "patternProperties":
			if m, ok := v.(map[string]any); ok {
				for _, n := range sortedKeys(m) {
					sub(false, k, n)
				}
			}
		case "dependentSchemas":
			if m, ok := v.(map[string]any); ok {
				for _, n := range sortedKeys(m) {
					sub(atRoot, k, n)
				}
			}
		case "$ref", "$dynamicRef":
			if s, ok := v.(string); ok {
				if r, p, ok := resolveStub(res, s); ok {
					d.visit(r, p, atRoot)
				}
			}
		}
	}
}

// declares reports whether $schema is covered by a closed schema's properties
// or patternProperties.
func declares(obj map[string]any) bool {
	if m, ok := obj["properties"].(map[string]any); ok {
		if _, ok := m["$schema"]; ok {
			return true
		}
	}
	if m, ok := obj["patternProperties"].(map[string]any); ok {
		for pat := range m {
			if re, err := regexp.Compile(pat); err == nil && re.MatchString("$schema") {
				return true
			}
		}
	}
	return false
}

// closedObject reports whether a schema object rejects properties it doesn't
// list. Only the literal false is recognised.
func closedObject(obj map[string]any) bool {
	return obj["additionalProperties"] == false || obj["unevaluatedProperties"] == false
}

// refusesSchemaKey says why a closed schema can't be given a $schema
// property: the key would still be refused, or counted against a limit.
func refusesSchemaKey(obj map[string]any) string {
	if _, ok := obj["maxProperties"]; ok {
		return "maxProperties counts the $schema key"
	}
	pn, ok := obj["propertyNames"]
	if !ok {
		return ""
	}
	const path = "/r/x/pn/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Probed one level down: validation leaves out the top-level $schema
	// (§6.2 step 5), and an older server is what the declaration is for.
	doc := map[string]any{"$schema": schema.Dialect2020, "properties": map[string]any{"p": map[string]any{"propertyNames": pn}}}
	probe := map[string]any{"$schema": path, "p": map[string]any{"$schema": ""}}
	load := func(ref schema.Ref) (any, error) {
		if ref.Path() == path {
			return doc, nil
		}
		return nil, schema.ErrUnavailable
	}
	if err := schema.NewValidator().Validate(probe, load); err != nil {
		if _, ok := err.(*schema.ValidationError); ok {
			return "propertyNames rejects $schema"
		}
	}
	return ""
}

// declareSchema finds the closed subschemas applying at the instance root of
// any resource, and returns those to patch per resource, those that can't be
// patched (with the reason) and those also used below the instance root.
func declareSchema(docs map[string]any) (patch map[string][]pointer.Pointer, refused map[string]string, shared []nodeRef) {
	d := &declaration{docs: docs, seen: map[string]bool{}, rootSet: map[string]bool{}, below: map[string]bool{}}
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d.visit(n, pointer.Pointer{}, true)
	}
	patch = map[string][]pointer.Pointer{}
	refused = map[string]string{}
	for _, n := range d.order {
		node, _ := pointer.Get(docs[n.res], n.ptr)
		obj := node.(map[string]any)
		if !closedObject(obj) || declares(obj) {
			continue
		}
		if why := refusesSchemaKey(obj); why != "" {
			refused[n.String()] = why
			continue
		}
		if props, ok := obj["properties"]; ok {
			if _, ok := props.(map[string]any); !ok {
				continue
			}
		}
		patch[n.res] = append(patch[n.res], n.ptr)
		if d.below[nodeKey(n.res, n.ptr)] {
			shared = append(shared, n)
		}
	}
	return patch, refused, shared
}

// applyDeclaration adds the $schema property to the subschemas at ptrs.
func applyDeclaration(content any, ptrs []pointer.Pointer) {
	for _, p := range ptrs {
		node, ok := pointer.Get(content, p)
		if !ok {
			continue
		}
		obj := node.(map[string]any)
		props, _ := obj["properties"].(map[string]any)
		if props == nil {
			props = map[string]any{}
			obj["properties"] = props
		}
		props["$schema"] = map[string]any{"type": "string"}
	}
}

// noteDeclaration reports what declareSchema decided.
func (p *planner) noteDeclaration(patch map[string][]pointer.Pointer, refused map[string]string, shared []nodeRef) {
	n := 0
	for _, ps := range patch {
		n += len(ps)
	}
	if n > 0 {
		s := "s"
		if n == 1 {
			s = ""
		}
		p.notes = append(p.notes, fmt.Sprintf("declared $schema in %d closed schema%s for servers before spec v0.36 (-declare-schema)", n, s))
	}
	if len(shared) > 0 {
		var at []string
		for i, r := range shared {
			if i == 3 {
				at = append(at, fmt.Sprintf("%d more", len(shared)-3))
				break
			}
			at = append(at, r.String())
		}
		p.notes = append(p.notes, fmt.Sprintf("%d of them are also used below the document root, where they now permit a $schema property (%s)", len(shared), strings.Join(at, ", ")))
	}
	var rs []string
	for r := range refused {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	for _, r := range rs {
		p.warn("a closed schema can't take a $schema property ("+refused[r]+"), so it can't type documents (§6.1)", r)
	}
}
