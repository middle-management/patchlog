package jsv

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
)

func mustJSON(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}

// structuredSchema is the schema of the "structured 1 MiB" benchmark.
const structuredSchema = `{
  "type": "object",
  "required": ["n", "items"],
  "properties": {
    "n": {"type": "integer"},
    "items": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name", "score", "tags", "at", "ok"],
        "properties": {
          "id": {"type": "integer", "minimum": 0},
          "name": {"type": "string", "pattern": "^item-[0-9]{6}$", "examples": ["item-000001", "item-123456"]},
          "score": {"type": "number", "minimum": 0, "maximum": 100},
          "tags": {"type": "array", "maxItems": 4, "items": {"type": "string", "maxLength": 16}},
          "at": {"type": "string", "format": "date-time"},
          "ok": {"type": "boolean"}
        }
      }
    }
  }
}`

// mixedSchema has a keyword that is not a conjunction over children
// (oneOf, if, contains, uniqueItems, unevaluatedProperties, not,
// propertyNames, dependentSchemas) at each depth.
const mixedSchema = `{
  "type": "object",
  "required": ["kind", "nums"],
  "properties": {
    "kind": {"enum": ["a", "b"]},
    "title": {"type": "string", "maxLength": 8, "examples": ["x", "hello"]},
    "nums": {"type": "array", "maxItems": 6, "uniqueItems": true, "items": {"type": "integer", "minimum": 0, "maximum": 9}},
    "tags": {"type": "array", "maxItems": 4, "contains": {"const": "core"}, "items": {"type": "string", "examples": ["core", "x", "y"]}},
    "shape": {
      "oneOf": [
        {"type": "object", "required": ["circle"], "additionalProperties": false,
         "properties": {"circle": {"type": "number", "minimum": 0, "maximum": 5}}},
        {"type": "object", "required": ["rect"], "additionalProperties": false,
         "properties": {"rect": {"type": "array", "minItems": 2, "maxItems": 3,
           "prefixItems": [{"type": "number", "minimum": 0, "maximum": 5}, {"type": "number", "minimum": 0, "maximum": 5}],
           "items": {"type": "string", "examples": ["cm"]}}}}
      ]
    },
    "meta": {
      "type": "object",
      "properties": {"a": {"type": "integer", "minimum": 0, "maximum": 3}, "b": {"type": "string", "examples": ["s"]}},
      "allOf": [{"properties": {"c": {"type": "boolean"}}}],
      "dependentRequired": {"a": ["b"]},
      "unevaluatedProperties": false
    },
    "nested": {
      "type": "object",
      "maxProperties": 3,
      "propertyNames": {"pattern": "^[a-z]+$"},
      "additionalProperties": {
        "type": "object",
        "properties": {
          "n": {"type": "integer", "minimum": 0, "maximum": 3},
          "deep": {
            "type": "array",
            "maxItems": 3,
            "items": {
              "type": "object",
              "properties": {"v": {"type": "integer", "minimum": 0, "maximum": 3}, "flag": {"type": "boolean"},
                "w": {"type": "array", "maxItems": 2, "items": {"type": "integer", "minimum": 0, "maximum": 3}}},
              "if": {"required": ["flag"]},
              "then": {"required": ["v"]},
              "not": {"required": ["bad"]},
              "dependentSchemas": {"w": {"properties": {"v": {"minimum": 1}}}}
            }
          }
        }
      }
    }
  },
  "patternProperties": {"^x-": {"type": "integer", "minimum": 0, "maximum": 3}},
  "additionalProperties": false,
  "if": {"properties": {"kind": {"const": "a"}}},
  "then": {"required": ["title"]}
}`

// unionSchema is the recursive union of the benchmark: a node is one of
// four kinds, each with children that are nodes.
const unionSchema = `{
  "$ref": "#/$defs/node",
  "$defs": {
    "node": {"oneOf": [{"$ref": "#/$defs/k0"}, {"$ref": "#/$defs/k1"}, {"$ref": "#/$defs/k2"}, {"$ref": "#/$defs/k3"}]},
    "k0": {"type": "object", "required": ["kind"], "properties": {"kind": {"const": "k0"}, "children": {"type": "array", "maxItems": 3, "items": {"$ref": "#/$defs/node"}}}},
    "k1": {"type": "object", "required": ["kind"], "properties": {"kind": {"const": "k1"}, "children": {"type": "array", "maxItems": 3, "items": {"$ref": "#/$defs/node"}}}},
    "k2": {"type": "object", "required": ["kind"], "properties": {"kind": {"const": "k2"}, "children": {"type": "array", "maxItems": 3, "items": {"$ref": "#/$defs/node"}}}},
    "k3": {"type": "object", "required": ["kind"], "properties": {"kind": {"const": "k3"}, "children": {"type": "array", "maxItems": 3, "items": {"$ref": "#/$defs/node"}}}}
  }
}`

// dynamicSchema is a tree extended through $dynamicRef, with a closed
// tuple and anyOf leaves.
const dynamicSchema = `{
  "$id": "https://example.test/strict-tree",
  "$dynamicAnchor": "node",
  "$ref": "tree",
  "unevaluatedProperties": false,
  "$defs": {
    "tree": {
      "$id": "tree",
      "$dynamicAnchor": "node",
      "type": "object",
      "required": ["data"],
      "properties": {
        "data": {"anyOf": [{"type": "integer", "minimum": 0, "maximum": 9}, {"type": "string", "maxLength": 3, "examples": ["a", "bc"]}]},
        "pair": {"type": "array", "prefixItems": [{"type": "integer", "minimum": 0, "maximum": 9}, {"type": "boolean"}], "items": false, "minItems": 1},
        "children": {"type": "array", "maxItems": 3, "items": {"$dynamicRef": "#node"}}
      }
    }
  }
}`

// openTreeSchema is dynamicSchema without unevaluatedProperties.
var openTreeSchema = strings.Replace(dynamicSchema, `"unevaluatedProperties": false,`, "", 1)

// testSchemas are the schemas of the differential and property tests.
// local says a change deep in a document can be validated without
// validating all of it: not so for dynamicSchema, whose root, which is
// every node, has unevaluatedProperties.
var testSchemas = []struct {
	name, schema string
	local        bool
}{
	{"structured", structuredSchema, true},
	{"mixed", mixedSchema, true},
	{"union", unionSchema, true},
	{"dynamic", dynamicSchema, false},
	{"open-tree", openTreeSchema, true},
}

// generator makes a document from a schema, as well as a handful of
// keywords allow: good enough that most come out valid, which the tests
// then check with the validator. With noise, a value is now and then
// replaced by junk.
type generator struct {
	r     *rand.Rand
	root  any
	noise float64
}

const genMaxDepth = 5

var junk = []any{nil, true, false, 0.0, 1.0, 2.0, 5.0, -1.0, 2.5, 100.0, "a", "core", "hello", "k1", "item-000001",
	"2026-10-15T12:00:00Z", "a very long string of many characters", []any{}, map[string]any{}, []any{1.0, 1.0}, map[string]any{"bad": true}}

func (g *generator) junk() any { return cloneJSON(junk[g.r.Intn(len(junk))]) }

func cloneJSON(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneJSON(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneJSON(e)
		}
		return out
	}
	return v
}

func (g *generator) gen(schema any, depth int) any {
	if g.noise > 0 && g.r.Float64() < g.noise {
		return g.junk()
	}
	m, ok := schema.(map[string]any)
	if !ok {
		return g.junk()
	}
	for _, kw := range []string{"$ref", "$dynamicRef"} {
		ref, ok := m[kw].(string)
		if !ok {
			continue
		}
		var target any
		switch {
		case strings.HasPrefix(ref, "#/"):
			target, _ = lookup(g.root, ref[1:])
		case ref == "#node":
			target = g.root
		default: // "tree" in dynamicSchema
			target, _ = lookup(g.root, "/$defs/"+ref)
		}
		return g.gen(target, depth)
	}
	for _, kw := range []string{"oneOf", "anyOf"} {
		if branches, ok := m[kw].([]any); ok {
			return g.gen(branches[g.r.Intn(len(branches))], depth)
		}
	}
	if c, ok := m["const"]; ok {
		return cloneJSON(c)
	}
	if e, ok := m["enum"].([]any); ok {
		return cloneJSON(e[g.r.Intn(len(e))])
	}
	if ex, ok := m["examples"].([]any); ok {
		return cloneJSON(ex[g.r.Intn(len(ex))])
	}
	typ, _ := m["type"].(string)
	if typ == "" {
		switch {
		case m["properties"] != nil:
			typ = "object"
		case m["items"] != nil:
			typ = "array"
		default:
			typ = "integer"
		}
	}
	num := func(kw string, def float64) float64 {
		if f, ok := m[kw].(float64); ok {
			return f
		}
		return def
	}
	switch typ {
	case "null":
		return nil
	case "boolean":
		return g.r.Intn(2) == 0
	case "integer":
		lo, hi := num("minimum", 0), num("maximum", 20)
		return lo + float64(g.r.Intn(int(hi-lo)+1))
	case "number":
		lo, hi := num("minimum", 0), num("maximum", 20)
		return lo + math.Round(g.r.Float64()*(hi-lo)*10)/10
	case "string":
		if m["format"] == "date-time" {
			return fmt.Sprintf("2026-10-%02dT12:00:00Z", 1+g.r.Intn(28))
		}
		return strings.Repeat("s", 1+g.r.Intn(3))
	case "array":
		prefix, _ := m["prefixItems"].([]any)
		lo, hi := int(num("minItems", 0)), int(num("maxItems", 4))
		if depth >= genMaxDepth {
			hi = lo
		}
		n := lo + g.r.Intn(hi-lo+1)
		if m["contains"] != nil && n == 0 {
			n = 1
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			switch {
			case i < len(prefix):
				out = append(out, g.gen(prefix[i], depth+1))
			case m["items"] == false:
			case m["items"] != nil:
				out = append(out, g.gen(m["items"], depth+1))
			default:
				out = append(out, g.junk())
			}
		}
		if c, ok := m["contains"].(map[string]any); ok && len(out) > 0 && g.r.Intn(8) > 0 {
			out[g.r.Intn(len(out))] = g.gen(c, depth+1)
		}
		return out
	case "object":
		out := map[string]any{}
		required := map[string]bool{}
		if req, ok := m["required"].([]any); ok {
			for _, k := range req {
				required[k.(string)] = true
			}
		}
		props, _ := m["properties"].(map[string]any)
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if required[k] || g.r.Intn(3) > 0 {
				out[k] = g.gen(props[k], depth+1)
			}
		}
		if ap, ok := m["additionalProperties"].(map[string]any); ok && depth < genMaxDepth {
			for i := g.r.Intn(3); i > 0; i-- {
				out[string(rune('p'+g.r.Intn(4)))] = g.gen(ap, depth+1)
			}
		}
		if all, ok := m["allOf"].([]any); ok {
			for _, sub := range all {
				if o, ok := g.gen(sub, depth).(map[string]any); ok {
					for k, v := range o {
						out[k] = v
					}
				}
			}
		}
		return out
	}
	return g.junk()
}

// pointers lists every location of doc, as JSON Pointers.
func pointers(doc any) []string {
	var out []string
	var walk func(v any, p string)
	walk = func(v any, p string) {
		out = append(out, p)
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], p+"/"+escapeToken(k))
			}
		case []any:
			for i, e := range x {
				walk(e, p+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(doc, "")
	return out
}
