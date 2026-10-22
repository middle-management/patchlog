package core

import (
	"fmt"

	"github.com/middle-management/patchlog/internal/rules"
)

var stepOneRefs = []string{"action", "resource", "principal", "now"}

// grantRules evaluates key-scope, block and role rules. With stepOne, only
// rules that refer solely to action, resource, principal and now are
// evaluated.
func (t *tx) grantRules(a *actor, verb string, roles []string, env map[string]any, stepOne bool) *Error {
	return t.grantRulesMode(a, verb, roles, env, stepOne, false)
}

// grantRulesMode is grantRules; with blind, a rule reading writes or /doc
// fails (sealed writes of e2e namespaces, §6.2): a key-scope or block rule
// refuses the request, and a role with one doesn't allow it.
func (t *tx) grantRulesMode(a *actor, verb string, roles []string, env map[string]any, stepOne, blind bool) *Error {
	if a.verified == nil {
		return nil
	}
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil {
				return forbidden("invalid grant rule")
			}
			if stepOne && !r.OnlyRefs(stepOneRefs...) {
				continue
			}
			if _, b := blindRule(r); blind && b {
				return forbidden("a grant or key rule reads writes or /doc, which the server can't see in an e2e namespace (§6.2, §E.3.2)")
			}
			if !r.Eval(env) {
				return forbidden("a grant or key rule refuses the request")
			}
		}
	}
	if a.verified.HasRoles() {
		if roles == nil {
			_, roles = a.verified.Allows(verb)
		}
		passed := false
		for _, role := range roles {
			ok := true
			for _, rv := range a.verified.RoleRules(role) {
				r, err := compileCached(rv)
				if err != nil {
					ok = false
					break
				}
				if stepOne && !r.OnlyRefs(stepOneRefs...) {
					continue
				}
				if _, b := blindRule(r); (blind && b) || !r.Eval(env) {
					ok = false
					break
				}
			}
			if ok {
				passed = true
				break
			}
		}
		if !passed {
			return forbidden("no role allows the request")
		}
	}
	return nil
}

// checkRules is step 6 of §6.2: namespace rules, then grant, key and role
// rules, against the full envelope.
func (t *tx) checkRules(cfg *Config, a *actor, env map[string]any, isConfig bool) *Error {
	verb := env["action"].(string)
	if a.verified != nil {
		if ok, _ := a.verified.Allows(verb); !ok {
			return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
		}
	}
	if !(isConfig && a.star) {
		if i, path, ok := rules.EvalList(cfg.Rules, env); !ok {
			return apiErr(422, "rule", "rule", i, "path", path)
		}
	}
	return t.grantRules(a, verb, nil, env, false)
}
