package merge

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/rules"
)

// §F.8, §12.2: the admin grant the merge service narrows for a catalog
// batch stays within the deployment's rulesPerGrant whatever the batch's
// size, as the origin decodes it (core.Engine.grantLimits), and its rule
// allows exactly the batch's pairs of /resource and /action.
func TestV073P02AdminGrantPairs(t *testing.T) {
	_, priv := grant.GenerateKey()
	admin, err := grant.Mint(map[string]any{"kid": "idp", "sub": "user:anna", "ns": []any{"cat"},
		"can": []any{"read", "create", "append", "delete", "restore"},
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	patch := client.Step{Patches: []any{}}
	p := &Plan{Resources: []*Resource{
		{Name: "a", Class: FastForward, BaseState: client.NotFound.String(), Steps: []client.Step{patch}},
		{Name: "b", Class: FastForward, BaseState: client.Live.String(), Base: "1b", Steps: []client.Step{patch}},
		{Name: "c", Class: FastForward, BaseState: client.Live.String(), Base: "1c", Steps: []client.Step{patch, client.DeleteStep()}},
		{Name: "d", Class: FastForward, BaseState: client.Tombstoned.String(), Base: "1d", Steps: []client.Step{patch}},
	}}
	for i := 0; i < 11; i++ {
		p.Resources = append(p.Resources, &Resource{Name: fmt.Sprintf("e%d", i), Class: FastForward,
			BaseState: client.NotFound.String(), Steps: []client.Step{patch}})
	}
	tok, err := adminGrant(ReleaseOptions{AdminGrant: admin.Encode(), Who: "user:anna", Via: "svc:merge"}, "cat", p)
	if err != nil {
		t.Fatal(err)
	}
	max := core.DefaultMaximums()
	g, err := grant.DecodeLimited(tok, grant.Limits{Size: max.GrantSize, Rules: max.RulesPerGrant})
	if err != nil {
		t.Fatalf("the narrowed admin grant for a %d-item batch, as the origin decodes it: %v", len(p.Resources), err)
	}
	block := g.Blocks[len(g.Blocks)-1]
	if block.Via != "svc:merge" || len(block.Rules) != 1 {
		t.Fatalf("narrowing block %+v", block)
	}
	rule, err := rules.Compile(block.Rules[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range append(p.Items(), &Resource{Name: "zz"}) {
		want := itemActions(r)
		for _, a := range []string{"create", "append", "delete", "restore", "read"} {
			if got := rule.Eval(map[string]any{"resource": r.Name, "action": a}); got != slices.Contains(want, a) {
				t.Errorf("%s %s: allowed %v, the batch's actions there %v", a, r.Name, got, want)
			}
		}
	}
}
