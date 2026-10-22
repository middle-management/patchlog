package rules

// formKeys are the members that make an object without "op" a rule form
// (§6.4.2), and hold the forms nested in it.
var formKeys = []string{"all", "any", "not", "if", "then"}

// CountForms counts the rule forms of v, a rule or an array of rules as
// JSON: every object of §6.4.2, those nested in all, any, not, if and then
// included, so {"all": [a, b, c]} counts 4. rulesPerNamespace and
// rulesPerGrant count rule forms this way (§12.2). An op form counts once,
// whatever its operands hold (a test's schema is no rule form). Values
// that aren't rule forms count nothing, so a malformed list, which
// compiling refuses anyway, is counted as far as it goes.
func CountForms(v any) int {
	switch x := v.(type) {
	case []any:
		n := 0
		for _, e := range x {
			n += CountForms(e)
		}
		return n
	case map[string]any:
		if has(x, "op") {
			return 1
		}
		n, form := 0, false
		for _, k := range formKeys {
			if c, ok := x[k]; ok {
				n += CountForms(c)
				form = true
			}
		}
		if !form {
			return 0
		}
		return 1 + n
	}
	return 0
}
