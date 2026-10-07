package bundle_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"
)

// §C.4, §C.3.1, §G.4.1: a branch accepts its base's keys, so the key that
// signed the root block of a grant first recorded in a branch may be one of
// its bases' keys at the entry's created time, such as one added to the
// base after the branch was created. The exporter finds it for `key`, and
// SourceKeyChecker accepts it, also after the base removed it again; a key
// the base never had is not in force.
func TestBranchGrantKeyFromBase(t *testing.T) {
	nsKey := clienttest.NewKey("ns-key")
	rotated := clienttest.NewKey("rotated")
	bot := signerKey(t, "bot-1", 3)
	g := mintFor(t, rotated.Priv, rotated.Kid, "bob", "r7", bot)
	byAuthor := map[string]*grant.Grant{"bob": g}
	served := map[string]*grant.Grant{g.ID().String(): g}
	srv := clienttest.New(t, clienttest.Options{Wrap: grantsHandler(served, func(a string) *grant.Grant { return byAuthor[a] }, nil)})
	as := func(author string) *client.Client { return srv.Client(t, client.WithAuthor(author)) }
	adm := as("alice")
	must(adm.CreateNamespace(ctx, "main", map[string]any{"read": "public",
		"keys": []any{nsKey.Entry("*")}}))
	srv.Clock.Advance(time.Minute)
	must(adm.CreateBranch(ctx, "main", client.BranchRequest{Name: "r7"}))

	// The base gets a key after the branch exists (a rotation).
	srv.Clock.Advance(time.Minute)
	cfg := must(adm.NSHead(ctx, "main")).Config
	must(adm.PatchConfig(ctx, "main", cfg, ops(op("add", "/keys/-", rotated.Entry("create", "append", "read")))))

	srv.Clock.Advance(time.Minute)
	genesis := client.GenesisPatches(map[string]any{"n": 1})
	p2 := ops(op("replace", "/n", 2))
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	sign := func(parent string, p any) client.WriteOption {
		var par *ids.ID
		if parent != "" {
			id := must(ids.Parse(parent))
			par = &id
		}
		return client.WithSignature(bot.SignPatches(clienttest.Origin, "r7", "d", par, canon(p)))
	}
	r1 := must(as("bob").Create(ctx, "r7", "d", genesis, sign("", genesis))).ID
	r2 := must(as("bob").Append(ctx, "r7", "d", r1, p2, sign(r1, p2))).ID

	check := func(t *testing.T) {
		t.Helper()
		reader := as("alice")
		var buf bytes.Buffer
		plan, _, err := bundle.Export(ctx, reader, &buf, bundle.ExportOptions{Select: []string{"r7/d"}, Authors: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Notes) != 0 {
			t.Fatalf("notes %v", plan.Notes)
		}
		grants := 0
		for _, m := range lineMaps(t, buf.Bytes())[1:] {
			if m["stored"] == nil {
				continue
			}
			grants++
			key, _ := m["key"].(map[string]any)
			if m["ns"] != "r7" || key == nil || key["kid"] != rotated.Kid || key["pub"] != rotated.Pub {
				t.Fatalf("grant line %v", m)
			}
		}
		if grants != 1 {
			t.Fatalf("%d grant lines:\n%s", grants, buf.Bytes())
		}
		st, _ := sigStatuses(t, buf.Bytes(), bundle.VerifyOptions{Keys: bundle.SourceKeyChecker(reader)})
		if st[r1] != bundle.SigVerified || st[r2] != bundle.SigVerified {
			t.Fatalf("statuses %v", st)
		}
	}
	t.Run("added to the base", check)

	// The base removes the key later: history still verifies against the
	// keys in force when it was written.
	srv.Clock.Advance(time.Minute)
	cfg = must(adm.NSHead(ctx, "main")).Config
	must(adm.PatchConfig(ctx, "main", cfg, ops(op("remove", "/keys/1", nil))))
	t.Run("removed from the base later", check)

	// A key the base never had isn't in force (same kid, another key), and
	// the bundle's own key is attested, not verified, against it.
	var buf bytes.Buffer
	if _, _, err := bundle.Export(ctx, as("alice"), &buf, bundle.ExportOptions{Select: []string{"r7/d"}, Authors: true}); err != nil {
		t.Fatal(err)
	}
	stranger := clienttest.NewKey(rotated.Kid)
	chk := bundle.SourceKeyChecker(as("alice"))
	line := &bundle.Line{NS: "r7", Resource: "d", ID: r1, Created: "2026-10-04T12:03:00Z"}
	if v, _ := chk(ctx, "r7", bundle.KeyEntry{Kid: stranger.Kid, Alg: sig.Alg, Pub: stranger.Pub}, line); v == bundle.KeyInForce {
		t.Errorf("a key the base never had is in force")
	}
	if v, why := chk(ctx, "r7", bundle.KeyEntry{Kid: rotated.Kid, Alg: sig.Alg, Pub: rotated.Pub}, line); v != bundle.KeyInForce {
		t.Errorf("the base's key at the time: %v %s", v, why)
	}
}
