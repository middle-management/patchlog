package grant

import "regexp"

// resNameRe is a valid resource name (§3.6), as core.ValidResourceName.
var resNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ResourceLiterals returns the literals a rule of a fixing form tests
// /resource against (§2.1): a test with value, or with a schema of only
// enum, or a compare with eq and a literal, or with in and a literal
// array. It reports false for a rule of any other form.
func ResourceLiterals(rv any) ([]any, bool) {
	m, ok := rv.(map[string]any)
	if !ok || len(m) != 3 || m["path"] != "/resource" {
		return nil, false
	}
	var lits []any
	literal := func(k string) (any, bool) {
		o, ok := m[k].(map[string]any)
		if !ok || len(o) != 1 {
			return nil, false
		}
		v, ok := o["value"]
		return v, ok
	}
	switch m["op"] {
	case "test":
		if v, ok := m["value"]; ok {
			lits = []any{v}
		} else if sch, ok := m["schema"].(map[string]any); ok && len(sch) == 1 {
			if lits, ok = sch["enum"].([]any); !ok {
				return nil, false
			}
		} else {
			return nil, false
		}
	case "compare":
		if v, ok := literal("eq"); ok {
			lits = []any{v}
		} else if v, ok := literal("in"); ok {
			if lits, ok = v.([]any); !ok {
				return nil, false
			}
		} else {
			return nil, false
		}
	default:
		return nil, false
	}
	return lits, true
}

// FixesResource reports whether the grant's rules fix /resource (§2.1): a
// rule of its blocks or its key's scope, at top level or inside all,
// tests /resource against one name or a finite set, and the names every
// such rule allows are some, all of them valid (§3.6).
func (v *Verified) FixesResource() bool {
	var names map[string]bool
	ok := true
	var walk func(rules []any)
	walk = func(rules []any) {
		for _, rv := range rules {
			if m, isMap := rv.(map[string]any); isMap && len(m) == 1 {
				if all, isAll := m["all"].([]any); isAll {
					walk(all)
					continue
				}
			}
			lits, shaped := ResourceLiterals(rv)
			if !shaped {
				continue
			}
			set := map[string]bool{}
			for _, l := range lits {
				name, isStr := l.(string)
				if !isStr || !resNameRe.MatchString(name) {
					ok = false
				}
				set[name] = true
			}
			if names == nil {
				names = set
				continue
			}
			for n := range names {
				if !set[n] {
					delete(names, n)
				}
			}
		}
	}
	walk(v.KeyRules)
	walk(v.BlockRules)
	return ok && len(names) > 0
}
