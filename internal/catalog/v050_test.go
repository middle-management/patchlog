package catalog_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
)

// listingAt is the at of the current listing of season for token: the
// combined checkpoint (§B.5).
func (w *world) listingAt(token string) string {
	w.t.Helper()
	_, loc := w.follow("/cat/children?of=season", token)
	_, rest, ok := strings.Cut(loc, "/at/")
	if !ok {
		w.t.Fatalf("listing URL %s", loc)
	}
	at, _, _ := strings.Cut(rest, "/")
	return at
}

// TestDecisionCheckpoint: answers of POST /grants and POST /read-grants
// carry checkpoint, the combined checkpoint they were decided at, the
// same value as listings' at, which isn't the grants' own at (the
// catalog's ns_id); refusals that are decisions carry it too (§B.11.4).
func TestDecisionCheckpoint(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	at := w.listingAt(bob)

	r := w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)
	catID := r.body["at"].(map[string]any)["id"]
	if r.body["checkpoint"] != at || at == catID || catID != w.svc.Tree().Checkpoint("cat") {
		t.Errorf("checkpoint %v, listing at %s, grant at %v", r.body["checkpoint"], at, catID)
	}

	// /read-grants: one checkpoint for the answer, one entry per item in
	// request order; the reader may read them all iff no entry has an
	// error.
	items := toAny("/r/matches/rumour1", "/r/matches/derby", "/r/cat/season", "/r/matches/ghost")
	rg := w.do("POST", "/read-grants", bob, map[string]any{"items": items})
	if rg.status != 200 || rg.body["checkpoint"] != at {
		t.Fatalf("read-grants: %d %v (at %s)", rg.status, rg.body, at)
	}
	gs := rg.body["grants"].([]any)
	if len(gs) != len(items) {
		t.Fatalf("read-grants entries: %v", gs)
	}
	for i, want := range []string{"error", "grant", "", "error"} {
		e := gs[i].(map[string]any)
		if e["item"] != items[i] {
			t.Errorf("entry %d is %v, want %v", i, e["item"], items[i])
		}
		_, hasErr := e["error"]
		_, hasGrant := e["grant"]
		if hasErr != (want == "error") || hasGrant != (want == "grant") {
			t.Errorf("entry %d: %v (want %q)", i, e, want)
		}
	}
	rg = w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/matches/derby", "/r/matches/shared", "/r/cat/season")})
	for _, x := range rg.body["grants"].([]any) {
		if e := x.(map[string]any); e["error"] != nil {
			t.Errorf("bob may read derby, shared and season: %v", e)
		}
	}

	// Refusals that are decisions carry it; malformed requests don't.
	for _, c := range []struct {
		name   string
		req    map[string]any
		status int
		cp     bool
	}{
		{"no role", map[string]any{"item": "/r/matches/rumour1", "want": toAny("read")}, 403, true},
		{"not placed", map[string]any{"item": "/r/matches/ghost", "want": toAny("read")}, 403, true},
		{"taken name", map[string]any{"item": "/r/matches/derby", "want": toAny("create")}, 409, true},
		{"never existed", map[string]any{"item": "/r/matches/ghost", "want": toAny("restore")}, 404, true},
		{"live", map[string]any{"item": "/r/matches/derby", "want": toAny("restore")}, 409, true},
		{"no move power", map[string]any{"node": "matches.rumour1", "want": toAny("move"), "to": toAny("season")}, 403, true},
		{"no such node", map[string]any{"node": "matches.ghost", "want": toAny("delete")}, 404, true},
		{"already placed", map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("season")}, 409, true},
		{"unknown verb", map[string]any{"item": "/r/matches/derby", "want": toAny("fly")}, 400, false},
		{"not a folder", map[string]any{"node": "nf", "want": toAny("create"), "to": toAny("matches.derby")}, 422, false},
	} {
		r := w.issue(bob, c.req, c.status)
		if got, has := r.body["checkpoint"]; has != c.cp || has && got != at {
			t.Errorf("%s: %d %v (at %s)", c.name, r.status, r.body, at)
		}
	}

	// A write to a content namespace moves the checkpoint, not the
	// grants' at.
	w.doc("matches", "later", map[string]any{"title": "later"})
	w.caughtUp()
	at2 := w.listingAt(bob)
	r = w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)
	if at2 == at || r.body["checkpoint"] != at2 || r.body["at"].(map[string]any)["id"] != catID {
		t.Errorf("after a content write: checkpoint %v, listing at %s (was %s), grant at %v (was %v)",
			r.body["checkpoint"], at2, at, r.body["at"], catID)
	}

	// A purged item's restore: 410, at the checkpoint after the purge.
	ctx := context.Background()
	w.doc("matches", "doomed", map[string]any{"title": "doomed"})
	w.doc("cat", "matches.doomed", map[string]any{"parents": parents("season")})
	w.caughtUp()
	must(w.ops.Delete(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID))
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "purge"})))
	must(purger.Purge(ctx, "matches", "doomed", must(w.ops.Head(ctx, "matches", "doomed")).ID, false))
	w.caughtUp()
	r = w.issue(bob, map[string]any{"item": "/r/matches/doomed", "want": toAny("restore")}, 410)
	if at3 := w.listingAt(bob); r.body["checkpoint"] != at3 || at3 != w.svc.Tree().At() {
		t.Errorf("purged: %v (listing at %s, now %s)", r.body, at3, w.svc.Tree().At())
	}
}

// TestReadGrantsOneCheckpoint: POST /read-grants decides every item at
// one checkpoint: if it moved while deciding, the items are decided
// again, and if it keeps moving the answer is 503 behind (§B.11.4,
// §B.11.5).
func TestReadGrantsOneCheckpoint(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	// write lands a catalog write and waits for the service to apply it.
	n := 0
	write := func() {
		n++
		before := w.svc.Tree().Checkpoint("cat")
		if _, err := w.ops.CreateDoc(ctx, "cat", fmt.Sprintf("mid%d", n), map[string]any{"title": "mid", "parents": parents("root")}); err != nil {
			t.Error(err)
			return
		}
		deadline := time.Now().Add(10 * time.Second)
		for w.svc.Tree().Checkpoint("cat") == before && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	body := map[string]any{"items": toAny("/r/matches/derby", "/r/matches/shared", "/r/matches/rumour1")}

	// A write lands while the first try decides: the second answers.
	var tries atomic.Int32
	w.svc.SetAfterDecide(func(try int) {
		tries.Add(1)
		if try == 0 {
			write()
		}
	})
	r := w.do("POST", "/read-grants", bob, body)
	if r.status != 200 || tries.Load() != 2 {
		t.Fatalf("read-grants with a write mid-decision: %d %v after %d tries", r.status, r.body, tries.Load())
	}
	if r.body["checkpoint"] != w.svc.Tree().At() {
		t.Errorf("checkpoint %v, now %s", r.body["checkpoint"], w.svc.Tree().At())
	}
	// Every grant is of the catalog checkpoint after the write.
	for i, x := range r.body["grants"].([]any) {
		e := x.(map[string]any)
		if i == 2 {
			if e["error"] == nil {
				t.Errorf("rumour1: %v", e)
			}
			continue
		}
		g := must(grant.Decode(e["grant"].(string), 0))
		if id := g.Blocks[0].At.(map[string]any)["id"]; id != w.svc.Tree().Checkpoint("cat") {
			t.Errorf("%v: grant at %v, catalog at %s", e["item"], id, w.svc.Tree().Checkpoint("cat"))
		}
	}

	// A checkpoint that keeps moving: 503 behind with Retry-After, after
	// the first try and three more.
	tries.Store(0)
	w.svc.SetAfterDecide(func(int) { tries.Add(1); write() })
	r = w.do("POST", "/read-grants", bob, body)
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") != "1" || tries.Load() != 4 {
		t.Errorf("read-grants while moving: %d %v %v after %d tries", r.status, r.body, r.header, tries.Load())
	}
	w.svc.SetAfterDecide(nil)

	// The item cap: 100, 400 above it.
	many := make([]any, 101)
	for i := range many {
		many[i] = "/r/matches/derby"
	}
	if r := w.do("POST", "/read-grants", bob, map[string]any{"items": many}); r.status != 400 {
		t.Errorf("101 items: %d %v", r.status, r.body)
	}
	if r := w.do("POST", "/read-grants", bob, map[string]any{"items": many[:100]}); r.status != 200 {
		t.Errorf("100 items: %d %v", r.status, r.body)
	}
}

// TestDecisionsPinned: roles, their definitions and the catalog's key
// are read as of the checkpoint a decision reports, as for visibility,
// so a /roles change the service hasn't reached doesn't change a decision
// yet (§B.11.4, §B.11.5).
func TestDecisionsPinned(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	rt := &holdRT{ns: "matches", base: transport}
	w.svcClient = w.s.Client(t, client.WithHTTPClient(&http.Client{Transport: rt}),
		client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
			map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	fan := w.caller("user:fred", "fan-club")
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}
	at := w.issue(fan, read, 200).body["checkpoint"]

	// reader stops granting read, but the service hasn't applied it.
	rt.hold.Store(true)
	opm := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "replace", "path": "/roles/reader/can", "value": toAny("append")}}))
	waitFor(t, "the checker to see the new roles", func() bool {
		c, err := w.svc.Tree().Checker().Config(ctx, "matches")
		return err == nil && fmt.Sprint(c.Roles["reader"].Can) == "[append]"
	})
	// Decided at the same checkpoint, the same way.
	if r := w.issue(fan, read, 200); r.body["checkpoint"] != at || fmt.Sprint(r.body["roles"]) != "[reader]" {
		t.Errorf("grant before the service reaches the change: %v (at %v)", r.body, at)
	}
	rg := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")})
	if e := rg.body["grants"].([]any)[0].(map[string]any); rg.body["checkpoint"] != at || e["grant"] == nil {
		t.Errorf("read-grants before the service reaches the change: %v (at %v)", rg.body, at)
	}

	// matches turns public, which the checker sees but the service
	// hasn't applied: /read-grants still decides rumour1, which fred
	// can't read, as at the checkpoint it reports.
	cfg = must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "add", "path": "/read", "value": "public"}}))
	waitFor(t, "the checker to see matches public", func() bool {
		c, err := w.svc.Tree().Checker().Config(ctx, "matches")
		return err == nil && c.Read == "public"
	})
	rumour := map[string]any{"items": toAny("/r/matches/rumour1")}
	rg = w.do("POST", "/read-grants", fan, rumour)
	if e := rg.body["grants"].([]any)[0].(map[string]any); rg.body["checkpoint"] != at || e["error"] == nil || e["public"] != nil {
		t.Errorf("read-grants for rumour1 before the service reaches public: %v (at %v)", rg.body, at)
	}

	// A create refused from the core's head, which is ahead of the
	// checkpoint (the service hasn't seen the document), carries no
	// checkpoint; one the service has seen carries it.
	desk := w.caller("user:bob", "match-desk")
	must(w.ops.CreateDoc(ctx, "cat", "matches.unseen", map[string]any{"parents": parents("season")}))
	waitFor(t, "the service to apply the placement", func() bool {
		return w.svc.Tree().Checkpoint("cat") == must(w.ops.NSHead(ctx, "cat")).ID
	})
	must(w.ops.CreateDoc(ctx, "matches", "unseen", map[string]any{"title": "unseen"}))
	if r := w.issue(desk, map[string]any{"item": "/r/matches/unseen", "want": toAny("create")}, 409); r.body["checkpoint"] != nil {
		t.Errorf("create refused from the core's head: %v", r.body)
	}
	if r := w.issue(desk, map[string]any{"item": "/r/matches/derby", "want": toAny("create")}, 409); r.body["checkpoint"] != w.svc.Tree().At() {
		t.Errorf("create refused from the checkpoint: %v (now %s)", r.body, w.svc.Tree().At())
	}

	// Once applied, a new checkpoint, and the refusal carries it.
	rt.hold.Store(false)
	w.caughtUp()
	r := w.issue(fan, read, 403)
	if r.body["checkpoint"] == at || r.body["checkpoint"] != w.svc.Tree().At() {
		t.Errorf("refusal after the change: %v (was %v)", r.body, at)
	}
	rg = w.do("POST", "/read-grants", fan, rumour)
	if e := rg.body["grants"].([]any)[0].(map[string]any); rg.body["checkpoint"] != w.svc.Tree().At() || e["public"] != true {
		t.Errorf("read-grants for rumour1 once matches is public: %v", rg.body)
	}
}

// TestHeadKeyRefusal: a refusal because the catalog's key is missing from
// the content namespace at the head is decided at the head, not at a
// checkpoint, so it carries none, for restore as for other verbs
// (§B.11.4).
func TestHeadKeyRefusal(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	rt := &holdRT{ns: "matches", base: transport}
	w.svcClient = w.s.Client(t, client.WithHTTPClient(&http.Client{Transport: rt}),
		client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
			map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	bob := w.caller("user:bob", "match-desk")
	rt.hold.Store(true)
	opm := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "remove", "path": "/keys/2"}}))
	waitFor(t, "the checker to drop the catalog's key", func() bool {
		c, err := w.svc.Tree().Checker().Config(ctx, "matches")
		return err == nil && len(c.Keys) == 2
	})
	for _, want := range []string{"read", "restore"} {
		r := w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny(want)}, 403)
		if msg, _ := r.body["message"].(string); !strings.Contains(msg, "catalog's key") || r.body["checkpoint"] != nil {
			t.Errorf("%s with the key missing at the head: %v", want, r.body)
		}
	}
}

// TestMinForContent: a decision on an item also depends on its content
// namespace (whether the item exists): after creating a document it
// placed, a client passes min for both, and the grant asked for at once
// is decided past both writes, never on a dangling placement (§B.11.4).
// Not parallel: the service must reach the mins within the default
// MinWait (2 s).
func TestMinForContent(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("fresh%d", i)
		pw := must(w.ops.CreateDoc(ctx, "cat", "matches."+name, map[string]any{"parents": parents("season")}))
		cw := must(w.ops.CreateDoc(ctx, "matches", name, map[string]any{"title": name}))
		r := w.do("POST", "/grants?min=cat:"+pw.NSID+"&min=matches:"+cw.NSID, bob, map[string]any{"item": "/r/matches/" + name, "want": toAny("append")})
		if r.status != 200 || r.body["grant"] == nil {
			t.Fatalf("append after creating %s, with min for both: %d %v", name, r.status, r.body)
		}
	}
}
