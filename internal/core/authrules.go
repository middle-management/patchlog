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
	return t.grantRulesMode(a, verb, roles, env, stepOne, nil)
}

// grantRulesMode is grantRules with the envelope members unknown names
// hidden, as a sealed write's writes and doc are at E3 (stepUnknown): a
// rule whose outcome depends on them fails as a whole, a key-scope or
// block rule refusing the request and a role with one not allowing it;
// one that passes, or fails, whatever they hold is decided as usual
// (§6.2, rules.EvalTri).
func (t *tx) grantRulesMode(a *actor, verb string, roles []string, env map[string]any, stepOne bool, unknown []string) *Error {
	if a.verified == nil {
		return nil
	}
	if err := t.scopeRules(a, env, stepOne, unknown); err != nil {
		return err
	}
	return t.roleRules(a, verb, roles, env, stepOne, unknown)
}

// scopeRules evaluates the key-scope and block rules of a's verified
// grant, as grantRulesMode does.
func (t *tx) scopeRules(a *actor, env map[string]any, stepOne bool, unknown []string) *Error {
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil {
				return forbidden("invalid grant rule")
			}
			if stepOne && !r.OnlyRefs(stepOneRefs...) {
				continue
			}
			switch r.EvalTri(env, unknown...) {
			case rules.Unknown:
				return forbidden("the outcome of a grant or key rule depends on writes or /doc, which the server can't see for this write in an e2e namespace (§6.2, §E.3.2)")
			case rules.False:
				return forbidden("a grant or key rule refuses the request")
			}
		}
	}
	return nil
}

// roleRules evaluates the role rules of a's verified grant, if it carries
// roles, as grantRulesMode does: roles are alternatives (§C.1.1), so the
// rules evaluated must pass for one of roles, or with roles nil for one of
// the effective roles that list verb.
func (t *tx) roleRules(a *actor, verb string, roles []string, env map[string]any, stepOne bool, unknown []string) *Error {
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
				if r.EvalTri(env, unknown...) != rules.True {
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

// checkRules is the rules of step 6 of §6.2 for one write, after the
// *-key guard and a config write's in_use refusals, which its callers run:
// grant, key and role rules (403), then namespace rules (422) (§6.4.3,
// §C.2 item 4). A batch runs each half for every item before the next
// (checkItems).
func (t *tx) checkRules(cfg *Config, a *actor, env map[string]any, isConfig bool) *Error {
	if err := t.checkGrantRules(a, env, nil); err != nil {
		return err
	}
	return checkNSRules(cfg, a, env, isConfig, nil)
}

// checkGrantRules is step 6's grant, key and role rules, all of them,
// against the full envelope with the write's verb (§C.2 item 4): 403. The
// envelope members unknown names are hidden (grantRulesMode).
func (t *tx) checkGrantRules(a *actor, env map[string]any, unknown []string) *Error {
	verb := env["action"].(string)
	if a.verified != nil {
		if ok, _ := a.verified.Allows(verb); !ok {
			return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
		}
	}
	return t.grantRulesMode(a, verb, nil, env, false, unknown)
}

// checkNSRules is step 6's namespace rules in cfg, the configuration in
// force (§6.4.3): the first that fails is 422 rule, with its index and the
// path of the failing rule form. With the envelope members unknown names
// hidden, a rule whose outcome depends on them fails as a whole, at its
// own path /rules/{i} (§6.2). A config write under a * key, so any while
// authentication is disabled, isn't judged by them (§1, §6.4.3); nor is a
// namespace's creation under the operator grant, which doesn't call this.
func checkNSRules(cfg *Config, a *actor, env map[string]any, isConfig bool, unknown []string) *Error {
	if isConfig && a.star {
		return nil
	}
	switch i, path, v := rules.EvalTri(cfg.Rules, env, unknown...); v {
	case rules.False:
		return apiErr(422, "rule", "rule", i, "path", path)
	case rules.Unknown:
		return apiErr(422, "rule", "rule", i, "path", path, "message", blindMsg)
	}
	return nil
}
