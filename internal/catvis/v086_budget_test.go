package catvis_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// doubling is a schema, as JSON, that takes more than 2^levels validation
// steps on any value.
func doubling(levels int) string {
	defs := map[string]any{fmt.Sprintf("a%d", levels): true}
	for i := 0; i < levels; i++ {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/a%d", i+1)}
		defs[fmt.Sprintf("a%d", i)] = map[string]any{"allOf": []any{next, next}}
	}
	b, _ := json.Marshal(map[string]any{"$ref": "#/$defs/a0", "$defs": defs})
	return string(b)
}

// §6.6 Validation work (v0.86), LIM-7, conformance scenario 90, SERVICES
// §B.11.5: a tree listing filtered per item by a role's rule whose schema
// test runs out of validationSteps for one item leaves that item out and
// lists the rest; under a not it is left out all the same.
func TestV086ItemBudget(t *testing.T) {
	t.Parallel()
	docs := map[string]any{
		"root":          map[string]any{"parents": []any{}, "$access": acc("group:editors", "reader")},
		"matches.derby": map[string]any{"parents": parents("root")},
		"matches.cup":   map[string]any{"parents": parents("root")},
		"matches.final": map[string]any{"parents": parents("root")},
	}
	for name, then := range map[string]string{
		"a test":      `{"op":"test","path":"/resource","schema":` + doubling(30) + `}`,
		"under a not": `{"not":{"op":"test","path":"/resource","schema":` + doubling(30) + `}}`,
	} {
		roles := `{"reader":{"can":["read"],"rules":[{"if":[{"op":"test","path":"/resource","value":"derby"}],"then":[` + then + `]}]}}`
		c := seedCatalog(t, matchesDoc(t, roles, ""), docs)
		for _, steps := range []int{2000, 0} { // 0: the default
			v := c.View([]string{"group:editors"})
			v.Steps = steps
			var got []string
			for _, n := range c.G.Names() {
				if v.Node(c.G.Node(n)) {
					got = append(got, n)
				}
			}
			if s := strings.Join(got, ","); s != "matches.cup,matches.final" {
				t.Errorf("%s, steps %d: editors see %q", name, steps, s)
			}
		}
	}
	// Within the budget the rule decides: every item is listed.
	roles := `{"reader":{"can":["read"],"rules":[{"if":[{"op":"test","path":"/resource","value":"derby"}],"then":[{"op":"test","path":"/resource","schema":` + doubling(4) + `}]}]}}`
	c := seedCatalog(t, matchesDoc(t, roles, ""), docs)
	if s := strings.Join(visibleNodes(c, "group:editors"), ","); s != "matches.cup,matches.derby,matches.final" {
		t.Errorf("within the budget: editors see %q", s)
	}
}
