package core

// Step 6 for sealed writes in end-to-end namespaces (§6.2, §E.3.2).

import (
	"github.com/middle-management/patchlog/internal/rules"
)

// blindRule reports a rule the server can't evaluate for a sealed write:
// it reads writes, doc or the whole envelope (§6.2).
func blindRule(r *rules.Rule) (string, bool) {
	refs := r.Refs()
	switch {
	case refs["*"]:
		return "", true
	case refs["writes"]:
		return "writes", true
	case refs["doc"]:
		return "/doc", true
	}
	return "", false
}

const blindMsg = "the server can't see writes or /doc of a sealed write in an e2e namespace, so a rule reading them fails the write (§6.2, §E.3.2)"

// checkNSRulesE2E is checkNSRules for a sealed create, append or
// restore: a namespace rule reading writes or /doc fails with 422 rule.
// Its grant, key and role rules are checkGrantRules with blind.
func checkNSRulesE2E(cfg *Config, env map[string]any) *Error {
	for i, r := range cfg.Rules {
		if p, blind := blindRule(r); blind {
			return apiErr(422, "rule", "rule", i, "path", p, "message", blindMsg)
		}
		if _, path, ok := rules.EvalList([]*rules.Rule{r}, env); !ok {
			return apiErr(422, "rule", "rule", i, "path", path)
		}
	}
	return nil
}
