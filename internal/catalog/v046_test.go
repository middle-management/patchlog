package catalog_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
)

// TestMinOnGrants: POST /grants and POST /read-grants take ?min={ns}:{ns_id},
// repeatable, as listings do: they decide at a checkpoint at or past every
// min, or answer 503 with Retry-After (§B.11.4 Read-your-writes, §A.5).
// Not parallel: the service must reach the mins within the default
// MinWait (2 s).
func TestMinOnGrants(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	w.doc("matches", "mn", map[string]any{"title": "mn"})
	w.caughtUp()

	// A placement or $access write is visible to the next request that
	// carries its X-Namespace-Revision, without waiting for the service.
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("late%d", i)
		wr := must(w.ops.CreateDoc(ctx, "cat", name, map[string]any{"title": name, "parents": parents("root"),
			"$access": acc("group:match-desk", "desk")}))
		path := "/grants?min=cat:" + wr.NSID
		r := w.do("POST", path, bob, map[string]any{"item": "/r/matches/mn", "want": toAny("place"), "to": toAny(name)})
		if r.status != 200 || r.body["grant"] == nil {
			t.Fatalf("place after %s with min: %d %v", name, r.status, r.body)
		}
		// Read grants too, and the parameter repeats.
		mw := must(w.ops.CreateDoc(ctx, "matches", "x"+name, map[string]any{"title": name}))
		r = w.do("POST", "/read-grants?min=cat:"+wr.NSID+"&min=matches:"+mw.NSID, bob, map[string]any{"items": toAny("/r/matches/derby")})
		if r.status != 200 || r.body["grants"] == nil {
			t.Fatalf("read-grants with two mins: %d %v", r.status, r.body)
		}
	}
}

// TestMinOnGrantsUnreachable: a min the service can't reach (an id of
// another namespace's entry) is 503 with Retry-After, and nothing is
// issued; a malformed one, or one naming a namespace the service doesn't
// follow, is 400 (§B.11.4, §A.5).
func TestMinOnGrantsUnreachable(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")

	other := must(w.ops.CreateDoc(ctx, "matches", "never", map[string]any{"title": "never"}))
	for _, c := range []struct{ path, body string }{
		{"/grants?min=cat:" + other.NSID, "grants"},
		{"/read-grants?min=cat:" + other.NSID, "read-grants"},
	} {
		var body any = map[string]any{"item": "/r/matches/derby", "want": toAny("read")}
		if c.body == "read-grants" {
			body = map[string]any{"items": toAny("/r/matches/derby")}
		}
		r := w.do("POST", c.path, bob, body)
		if r.status != 503 || r.header.Get("Retry-After") == "" {
			t.Errorf("%s unreachable min: %d %v", c.path, r.status, r.header)
		}
	}
	// Malformed, or naming a namespace the service doesn't follow: 400.
	for _, q := range []string{"?min=garbage", "?min=nope:" + other.NSID, "?min=cat:"} {
		for _, p := range []string{"/grants", "/read-grants"} {
			r := w.do("POST", p+q, bob, map[string]any{"items": toAny("/r/matches/derby"), "item": "/r/matches/derby", "want": toAny("read")})
			if r.status != 400 {
				t.Errorf("%s%s: %d %v", p, q, r.status, r.body)
			}
		}
	}
}

// TestInheritPowers: a folder's $access with inheritPowers: true gives tree
// powers collected on the walk up there too (§B.11.2); moves stay bounded
// by no widening (§B.11.4).
func TestInheritPowers(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "desks", map[string]any{"title": "Desks", "parents": parents("root"), "$access": acc("group:match-desk", "desk")})
	w.doc("cat", "plain", map[string]any{"title": "Plain", "parents": parents("desks")})
	w.doc("cat", "inh", map[string]any{"title": "Inherits", "parents": parents("desks"), "$access": acc("inheritPowers", true)})
	w.doc("cat", "cut", map[string]any{"title": "Cut off", "parents": parents("desks"), "$access": acc("inherit", false, "inheritPowers", true)})
	w.doc("cat", "deep", map[string]any{"title": "Deep", "parents": parents("inh")})
	w.doc("matches", "pw", map[string]any{"title": "pw"})
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	place := func(to string, status int) {
		t.Helper()
		w.issue(bob, map[string]any{"item": "/r/matches/pw", "want": toAny("place"), "to": toAny(to)}, status)
	}
	// Powers are assigned where a role granting them is, and nowhere else.
	place("desks", 200)
	place("plain", 403)
	place("deep", 403)
	// inheritPowers brings them down to that folder, not below it.
	place("inh", 200)
	// inherit: false stops the walk up, so nothing is collected.
	place("cut", 403)
	// Folders can be created under it, by the same power.
	w.issue(bob, map[string]any{"node": "newf", "want": toAny("create"), "to": toAny("inh")}, 200)
	w.issue(bob, map[string]any{"node": "newf", "want": toAny("create"), "to": toAny("plain")}, 403)

	// Moves: still bounded by no widening. Out of inh (move there comes by
	// inheritPowers) into derbies (fan-club: desk) would widen.
	anna := w.caller("user:anna", "translators")
	w.issue(anna, map[string]any{"item": "/r/matches/pw", "want": toAny("place"), "to": toAny("inh")}, 403)
	g := w.grantFor(bob, map[string]any{"item": "/r/matches/pw", "want": toAny("place"), "to": toAny("inh")})
	must(w.core(g).CreateDoc(context.Background(), "cat", "matches.pw", map[string]any{"parents": parents("inh")}))
	w.caughtUp()
	r := w.issue(bob, map[string]any{"node": "matches.pw", "want": toAny("move"), "to": toAny("derbies")}, 403)
	if !strings.Contains(r.body["message"].(string), "group:fan-club") {
		t.Errorf("widening message: %v", r.body)
	}
	w.issue(bob, map[string]any{"node": "matches.pw", "want": toAny("move"), "to": toAny("desks")}, 200)
}

// TestReadGrantsAreFixedToTheResource: a read grant is fixed to exactly
// /r/{ns}/{name} (and so /r/{ns}/{name}/…), read-only, for the one
// namespace, so the origin can exchange it for an edge grant (§B.11.5, §C.5).
func TestReadGrantsAreFixedToTheResource(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	fan := w.caller("user:fiona", "fan-club")
	r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")})
	if r.status != 200 {
		t.Fatalf("read-grants: %d %v", r.status, r.body)
	}
	tok := r.body["grants"].([]any)[0].(map[string]any)["grant"].(string)
	g, err := grant.Decode(tok, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Blocks) != 1 {
		t.Fatalf("blocks: %d", len(g.Blocks))
	}
	b := g.Blocks[0]
	if len(b.NS) != 1 || b.NS[0] != "matches" || len(b.Can) != 1 || b.Can[0] != "read" || b.Exp == nil || b.At == nil {
		t.Errorf("read grant: ns %v can %v exp %v at %v", b.NS, b.Can, b.Exp, b.At)
	}
	fixed := false
	for _, rule := range b.Rules {
		if m, ok := rule.(map[string]any); ok && m["op"] == "test" && m["path"] == "/resource" && m["value"] == "derby" {
			fixed = true
		}
	}
	if !fixed {
		t.Errorf("rules do not fix /resource: %v", b.Rules)
	}
}
