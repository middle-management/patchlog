package catalog_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/seal"
)

// A reader who sees items only through catalog roles gets, with its read
// grants, the per-resource keys of the item (opening its revisions) and of
// its placement node (opening its per-entry listing entry), wrapped to its
// grant's enc, and nothing else (§B.11.5, §E.2.6).
func TestReadGrantKeys(t *testing.T) {
	t.Parallel()
	w := setupWith(t, true)
	w.seed()
	w.patch("cat", "matches.derby", map[string]any{"op": "add", "path": "/title", "value": "Derby placement"})
	w.patch("cat", "matches.shared", map[string]any{"op": "add", "path": "/title", "value": "Shared placement"})
	w.start()
	w.caughtUp()
	ctx := context.Background()

	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	fan := w.idp.Grant(t, w.s.Now(), "user:fred", []string{"cat"}, []string{}, map[string]any{"groups": toAny("fan-club"), "enc": jwk})
	r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby", "/r/cat/season", "/r/matches/rumour1", "/r/cat/rumours")})
	if r.status != 200 {
		t.Fatalf("read-grants: %d %v", r.status, r.body)
	}
	gs := r.body["grants"].([]any)
	unwrap := func(e map[string]any) map[string][]byte {
		t.Helper()
		out := map[string][]byte{}
		ks, _ := e["keys"].([]any)
		for _, x := range ks {
			wk, err := seal.ParseWrappedKey(x)
			if err != nil {
				t.Fatal(err)
			}
			k, err := seal.UnwrapKey(priv, wk)
			if err != nil {
				t.Fatal(err)
			}
			out[wk.Kid+" "+wk.Resource] = k
		}
		return out
	}
	names := func(m map[string][]byte) string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	g0, g1, g2, g3 := gs[0].(map[string]any), gs[1].(map[string]any), gs[2].(map[string]any), gs[3].(map[string]any)
	k0, k1 := unwrap(g0), unwrap(g1)
	if g0["grant"] == nil || names(k0) != "cat#1 matches.derby,matches#1 derby" {
		t.Fatalf("item: %v (keys %s)", g0, names(k0))
	}
	if g1["grant"] != nil || names(k1) != "cat#1 season" {
		t.Fatalf("catalog node: %v (keys %s)", g1, names(k1))
	}
	for _, g := range []map[string]any{g2, g3} {
		if g["error"] == nil || g["keys"] != nil || g["grant"] != nil {
			t.Fatalf("refused item: %v", g)
		}
	}

	// The item's K_r opens its revisions, with the read grant.
	st := client.StaticKeys()
	st.AddResource("matches#1", "derby", k0["matches#1 derby"])
	rc := w.core(g0["grant"].(string)).With(client.WithKeys(st))
	if _, d, err := rc.Load(ctx, "matches", "derby"); err != nil || d.Value.(map[string]any)["title"] != "derby" {
		t.Fatalf("revision: %v", err)
	}
	// Not another item's, even with a grant that reads it.
	other := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:x", []string{"matches"}, []string{"read"})), client.WithKeys(st))
	if _, _, err := other.Load(ctx, "matches", "shared"); !errors.Is(err, client.ErrNoKeys) {
		t.Fatalf("K_derby on shared: %v", err)
	}

	// The placement's K_r opens its per-entry listing entry, and no other.
	p := w.do("GET", "/cat/children?of=season", fan, nil)
	loc := p.header.Get("Location")
	p = w.do("GET", loc, fan, nil)
	if p.status != 200 || p.header.Get("Content-Type") != "application/json" {
		t.Fatalf("listing: %d %v", p.status, p.header)
	}
	v := derived.View{NS: "cat", Target: loc}
	byName := map[string]map[string]any{}
	for _, c := range p.body["children"].([]any) {
		byName[c.(map[string]any)["name"].(string)] = c.(map[string]any)
	}
	kd := func(string) []byte { return k0["cat#1 matches.derby"] }
	pt, err := derived.OpenItem(byName["matches.derby"]["sealed"].(string), kd, v, "cat", "matches.derby")
	if err != nil || !strings.Contains(string(pt), "Derby placement") {
		t.Fatalf("entry: %s %v", pt, err)
	}
	if _, err := derived.OpenItem(byName["matches.shared"]["sealed"].(string), kd, v, "cat", "matches.shared"); err == nil {
		t.Fatal("K_r of matches.derby opened matches.shared's entry")
	}

	// Without an enc key: the grant, and the keys withheld.
	plain := w.caller("user:fiona", "fan-club")
	r = w.do("POST", "/read-grants", plain, map[string]any{"items": toAny("/r/matches/derby")})
	e := r.body["grants"].([]any)[0].(map[string]any)
	if e["grant"] == nil || e["keys"] != nil || e["keysWithheld"] == nil {
		t.Fatalf("no enc: %v", e)
	}
}
