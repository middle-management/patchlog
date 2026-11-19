package grantcheck_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// §6.6 Validation work (v0.86), LIM-7: running out of a read check's
// budget fails that whole check. A grant with roles [slow, reader], slow's
// rule running the budget out and reader having no rules, neither reads
// the namespace unrestricted nor would get a namespace-wide edge grant,
// nor may read a resource: as the origin decides (readsNS), where no
// other role makes up for one that ran out. In the other order reader
// passes before anything is spent.
func TestV086RolesAfterRunOut(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	defs := map[string]any{"a30": true}
	for i := 0; i < 30; i++ {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/a%d", i+1)}
		defs[fmt.Sprintf("a%d", i)] = map[string]any{"allOf": []any{next, next}}
	}
	slow := map[string]any{"op": "test", "path": "/principal", "schema": map[string]any{"$ref": "#/$defs/a0", "$defs": defs}}
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{map[string]any{"op": "add", "path": "/roles/slow",
		"value": map[string]any{"can": []any{"read"}, "rules": []any{slow}}}}))
	svc := f.s.Client(t, client.WithBearer(f.grant(f.admin, "svc:x", []string{"sec"}, []string{"read"})))
	ch := grantcheck.New(svc, grantcheck.WithClock(f.s.Now), grantcheck.WithTTL(0), grantcheck.WithValidationSteps(2000))
	for _, c := range []struct {
		roles []any
		want  bool
	}{
		{[]any{"slow"}, false},
		{[]any{"slow", "reader"}, false},
		{[]any{"reader", "slow"}, true},
		{[]any{"reader"}, true},
	} {
		v, err := ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, map[string]any{"roles": c.roles}))
		if err != nil {
			t.Fatalf("%v: %v", c.roles, err)
		}
		if got := ch.ReadsUnrestricted(v); got != c.want {
			t.Errorf("%v: ReadsUnrestricted %v", c.roles, got)
		}
		if got := ch.NamespaceWide(v); got != c.want {
			t.Errorf("%v: NamespaceWide %v", c.roles, got)
		}
		if got := ch.AllowsRead(v, "a"); got != c.want {
			t.Errorf("%v: AllowsRead %v", c.roles, got)
		}
	}
}
