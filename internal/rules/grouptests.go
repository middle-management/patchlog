package rules

import (
	"sort"

	"github.com/middle-management/patchlog/internal/pointer"
)

// ptrPrincipalGroups is /principal/groups, the member §B.11.5's deciding
// groups are read from.
var ptrPrincipalGroups = pointer.Pointer{"principal", "groups"}

// GroupTests classifies how a rule, as raw JSON (§6.4.2), refers to
// /principal/groups, for §B.11.5's deciding subjects: named are the groups
// it tests the caller holds by value, sorted and without duplicates, and
// onlyPositive reports that it refers to /principal/groups solely by such
// positive tests, outside not and if, so that a group it doesn't name
// can't change its outcome. A rule that never refers to /principal/groups
// gives (nil, true).
//
// The accepted tests are exactly
//
//	{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": S } } }
//	{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "enum": [S, …] } } }
//
// with S strings, the schema optionally also holding "type": "array", or
// a schema that is only an allOf, a non-empty array of such schemas
// (§B.11.5, v0.76), reached through all and any only, never inside not,
// if or then. Anything else that can read /principal/groups makes
// onlyPositive false: a value or exists test, a path below it
// (/principal/groups/0) or above it (/principal, the whole envelope ""),
// any other schema keyword (minItems, pattern, items, not …), contains
// or type beside allOf, an allOf element without contains, nested allOf,
// and a compare whose path or operand path names it. A rule that isn't
// well-formed is false too: when unsure, the answer is false, which keeps
// all the caller's groups (§B.11.5).
func GroupTests(rule any) (named []string, onlyPositive bool) {
	set := map[string]bool{}
	ok := groupWalk(rule, false, set)
	if !ok {
		return nil, false
	}
	return sortedSet(set), true
}

// GroupTestsList is GroupTests over a list of rules: the union of their
// named groups, onlyPositive only if every rule's is.
func GroupTestsList(rs []any) (named []string, onlyPositive bool) {
	set := map[string]bool{}
	for _, r := range rs {
		if !groupWalk(r, false, set) {
			return nil, false
		}
	}
	return sortedSet(set), true
}

func sortedSet(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// groupWalk walks a rule's raw JSON, adding the groups its positive tests
// name to set; negated reports that the rule sits inside not, if or then.
// It reports false for a reference to /principal/groups it doesn't accept,
// or a rule it can't read.
func groupWalk(v any, negated bool, set map[string]bool) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if op, has := m["op"]; has {
		switch op {
		case "test":
			return groupTest(m, negated, set)
		case "compare":
			for _, p := range comparePaths(m) {
				if p == nil || p.Overlaps(ptrPrincipalGroups) {
					return false
				}
			}
			return true
		case "writes":
			return true // reads /writes only
		}
		return false
	}
	switch {
	case has(m, "all") && len(m) == 1, has(m, "any") && len(m) == 1:
		key := "all"
		if has(m, "any") {
			key = "any"
		}
		arr, ok := m[key].([]any)
		if !ok {
			return false
		}
		for _, x := range arr {
			if !groupWalk(x, negated, set) {
				return false
			}
		}
		return true
	case has(m, "not") && len(m) == 1:
		return groupWalk(m["not"], true, set)
	case has(m, "if") && has(m, "then") && len(m) == 2:
		for _, k := range []string{"if", "then"} {
			arr, ok := m[k].([]any)
			if !ok {
				return false
			}
			for _, x := range arr {
				if !groupWalk(x, true, set) {
					return false
				}
			}
		}
		return true
	}
	return false
}

// groupTest classifies a test op (groupWalk).
func groupTest(m map[string]any, negated bool, set map[string]bool) bool {
	s, ok := m["path"].(string)
	if !ok {
		return false
	}
	p, err := pointer.Parse(s)
	if err != nil {
		return false
	}
	if !p.Overlaps(ptrPrincipalGroups) {
		return true
	}
	if negated || len(p) != len(ptrPrincipalGroups) || len(m) != 3 || !has(m, "schema") {
		return false
	}
	names, ok := groupSchema(m["schema"])
	if !ok || len(names) == 0 {
		return false
	}
	for _, n := range names {
		set[n] = true
	}
	return true
}

// groupSchema reads a test's schema of the accepted forms (GroupTests,
// §B.11.5): exactly a containsSchema, or exactly {"allOf": [...]}, a
// non-empty array of containsSchemas. contains beside allOf, type beside
// allOf, an allOf element without contains and nested allOf are refused.
// It returns the groups named.
func groupSchema(v any) ([]string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	if !has(m, "allOf") {
		return containsSchema(m)
	}
	arr, ok := m["allOf"].([]any)
	if len(m) != 1 || !ok || len(arr) == 0 {
		return nil, false
	}
	var out []string
	for _, sub := range arr {
		sm, ok := sub.(map[string]any)
		if !ok {
			return nil, false
		}
		names, ok := containsSchema(sm)
		if !ok {
			return nil, false
		}
		out = append(out, names...)
	}
	return out, true
}

// containsSchema reads a schema whose only keys are contains, which is
// exactly {"const": S} or {"enum": [S, …]} with S strings, and optionally
// "type": "array" (§B.11.5). It returns the groups named.
func containsSchema(m map[string]any) ([]string, bool) {
	if !has(m, "contains") {
		return nil, false
	}
	for k, x := range m {
		if k != "contains" && (k != "type" || x != "array") {
			return nil, false
		}
	}
	c, ok := m["contains"].(map[string]any)
	if !ok || len(c) != 1 {
		return nil, false
	}
	if s, ok := c["const"].(string); ok {
		return []string{s}, true
	}
	arr, ok := c["enum"].([]any)
	if !ok || len(arr) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// comparePaths are the pointers a compare op reads: its path and, if its
// operand is a path, that one; nil stands for one that doesn't parse.
func comparePaths(m map[string]any) []pointer.Pointer {
	var out []pointer.Pointer
	parse := func(v any) pointer.Pointer {
		s, ok := v.(string)
		if !ok {
			return nil
		}
		p, err := pointer.Parse(s)
		if err != nil {
			return nil
		}
		if p == nil {
			p = pointer.Pointer{}
		}
		return p
	}
	out = append(out, parse(m["path"]))
	for _, k := range []string{"eq", "lt", "le", "gt", "ge", "in"} {
		if o, ok := m[k].(map[string]any); ok {
			if q, ok := o["path"]; ok {
				out = append(out, parse(q))
			}
		}
	}
	return out
}
