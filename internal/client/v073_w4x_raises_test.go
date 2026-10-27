package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// w4x (raises lens), Addendum E Levels, §E.2.3, F-E1: after a raise from
// sealed to e2e, a grant without nbf, the usual grant, which read and wrote
// the namespace at E2, keeps reading and appending to what existed before
// the raise. /keys gives the keys of epochs before the raise as at E2, the
// last epoch before the raise standing for the current one, so it still
// gets that epoch's key; the fold of every revision of such a resource,
// written end to end after the raise too, starts at its last revision from
// before it, served sealed under that epoch.
func TestV073W4xNoNbfReaderAfterRaiseFromSealed(t *testing.T) {
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed"})
	r1 := must(v.c.Create(ctx, "e", "d", ops(op("add", "", map[string]any{"n": 1.0}), op("add", "/$nonce", seal.NewNonce())))).ID
	// At E2 the same grant reads it.
	ks := must(v.c.FetchKeys(ctx, "e", nil, nil))
	if len(ks) != 1 || ks[0].Kid != "e#1" {
		t.Fatalf("at E2 /keys: %+v", ks)
	}
	v.p35Raise(t, map[string]any{"level": "e2e", "epoch": 2.0})
	w, err := v.x.AppendSealed(ctx, "e", "d", r1, ops(op("replace", "/n", 2.0)))
	if err != nil {
		t.Fatalf("the writer that wrote d at E2 appends to it after the raise: %v", err)
	}
	r2 := w.ID
	after := must(v.c.FetchKeys(ctx, "e", nil, nil))
	t.Logf("/keys after the raise: %d entries", len(after))
	for _, k := range after {
		t.Logf("  %s", k.Kid)
	}
	fresh := v.c.E2E(v.priv) // a new view: keys only from /keys
	if _, err := fresh.DocE2E(ctx, "e", "d", r1); err != nil {
		t.Errorf("revision from before the raise, fresh view, grant without nbf: %v", err)
	}
	if _, err := fresh.DocE2E(ctx, "e", "d", r2); err != nil {
		t.Errorf("revision written end to end (fold starts before the raise), fresh view, grant without nbf: %v", err)
	}
}

// w4x (raises lens), the other half: the server's own key check for
// content from before a raise from sealed (§6.1 Read permission, §2.1
// Protection: "keys that §E.2.3 gives there") applies the window /keys
// applies to the epochs before the raise (Addendum E Levels: "as at E2"),
// in both directions. With two epochs before the raise, a grant without
// nbf gets the last of them from /keys and nothing of the first, and a
// schema revision sealed under the first is schema_unavailable for it
// while one under the last resolves; a grant whose nbf reaches back gets
// both and resolves both.
func TestV073W4xPreRaiseKeyCheckAgreesWithKeys(t *testing.T) {
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed"})
	sch := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
		"properties": map[string]any{"n": map[string]any{"type": "number"}}, "required": []any{"n"}}
	s1 := must(v.c.Create(ctx, "e", "m", ops(op("add", "", sch), op("add", "/$nonce", seal.NewNonce())))).ID
	v.s.Clock.Advance(20 * time.Minute)
	h := must(v.c.NSHead(ctx, "e"))
	must(v.c.PatchConfig(ctx, "e", h.Config, ops(op("add", "/encryption/epoch", 2.0))))
	s2 := must(v.c.Create(ctx, "e", "m2", ops(op("add", "", sch), op("add", "/$nonce", seal.NewNonce())))).ID
	v.s.Clock.Advance(20 * time.Minute)
	v.p35Raise(t, map[string]any{"level": "e2e", "epoch": 3.0})
	op := v.s.Client(t, client.WithBearer(v.s.OperatorGrant(t, "p")))
	must(op.CreateNamespace(ctx, "p", map[string]any{"read": "grant", "keys": []any{v.k.Entry("*")}}))
	kids := func(c *client.Client) map[string]bool {
		out := map[string]bool{}
		for _, k := range must(c.FetchKeys(ctx, "e", nil, nil)) {
			out[k.Kid] = true
		}
		return out
	}
	unavailable := func(err error) bool {
		var ae *client.APIError
		return errors.As(err, &ae) && ae.Code == "schema_unavailable"
	}
	g := v.k.Grant(t, v.s.Now(), "user:a", []string{"e", "p"}, p29Verbs, map[string]any{"enc": must(jwkOf(t))})
	c := v.s.Client(t, client.WithBearer(g))
	if ks := kids(c); ks["e#1"] || !ks["e#2"] {
		t.Fatalf("/keys of e for a grant without nbf: %v, want e#2 (the last epoch before the raise, as at E2) and not e#1", ks)
	}
	if _, err := c.CreateDoc(ctx, "p", "x", map[string]any{"$schema": "/r/e/m/rev/" + s1, "n": 1.0}); !unavailable(err) {
		t.Errorf("a schema sealed under e#1, which /keys doesn't give the grant: %v, want schema_unavailable", err)
	}
	if _, err := c.CreateDoc(ctx, "p", "y", map[string]any{"$schema": "/r/e/m2/rev/" + s2, "n": 1.0}); err != nil {
		t.Errorf("a schema sealed under e#2, which /keys gives the grant: %v", err)
	}
	if _, err := c.CreateDoc(ctx, "p", "y2", map[string]any{"$schema": "/r/e/m2/rev/" + s2, "n": "x"}); err == nil || unavailable(err) {
		t.Errorf("an invalid document under the e#2 schema: %v, want it refused by the schema", err)
	}
	early := v.k.Grant(t, v.s.Now(), "user:b", []string{"e", "p"}, p29Verbs, map[string]any{"enc": must(jwkOf(t)), "nbf": v.s.Now().Add(-time.Hour).Format(time.RFC3339)})
	ce := v.s.Client(t, client.WithBearer(early))
	if ks := kids(ce); !ks["e#1"] || !ks["e#2"] {
		t.Fatalf("/keys of e for a grant whose nbf reaches back: %v, want e#1 and e#2", ks)
	}
	if _, err := ce.CreateDoc(ctx, "p", "z", map[string]any{"$schema": "/r/e/m/rev/" + s1, "n": 1.0}); err != nil {
		t.Errorf("a schema sealed under e#1, for a grant /keys gives e#1: %v", err)
	}
}

func jwkOf(t *testing.T) (map[string]any, error) {
	jwk, _, err := seal.GenerateRecipient()
	return jwk, err
}
