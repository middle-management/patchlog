package catalog_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// TestVisibilityRulesV038: a role with rules counts for an item's
// visibility if its rules pass as a read of the item evaluates them (no
// writes, doc or patches), unless they refer to /now or to /principal
// other than /principal/groups; roles count only through subjects the
// catalog's key may assert (§B.11.5); grants are issued only through them
// too (§B.11.4 Resolve).
func TestVisibilityRulesV038(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	opm := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	role := func(rule any) map[string]any {
		return map[string]any{"can": toAny("read"), "rules": []any{rule}}
	}
	must(opm.PatchConfig(ctx, "matches", cfg, []any{
		map[string]any{"op": "add", "path": "/roles/byid", "value": role(map[string]any{"op": "compare", "path": "/principal/id", "eq": map[string]any{"value": "user:i"}})},
		map[string]any{"op": "add", "path": "/roles/covers", "value": role(map[string]any{"op": "writes", "covers": "/x"})},
		map[string]any{"op": "add", "path": "/roles/overlaps", "value": role(map[string]any{"op": "writes", "overlaps": "/x"})},
		map[string]any{"op": "add", "path": "/roles/notover", "value": role(map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/title"}})},
		map[string]any{"op": "add", "path": "/roles/action", "value": role(map[string]any{"op": "test", "path": "/action", "value": "read"})},
		map[string]any{"op": "add", "path": "/roles/hasdoc", "value": role(map[string]any{"op": "test", "path": "/doc", "exists": true})},
		map[string]any{"op": "add", "path": "/roles/whole", "value": role(map[string]any{"op": "test", "path": "", "schema": map[string]any{"type": "object"}})},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "byid"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "covers"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "overlaps"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "notover"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "action"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "hasdoc"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "whole"},
	}))
	w.doc("cat", "rx", map[string]any{"title": "Rules", "parents": parents("root"), "$access": acc(
		"group:ids", "byid", "group:covs", "covers", "group:ovs", "overlaps", "group:nots", "notover",
		"group:acts", "action", "group:docs", "hasdoc", "group:wholes", "whole",
		// The content namespace's catalog key denies the ops group (§B.11.3).
		"group:ops", "reader")})
	w.doc("matches", "x3", map[string]any{"title": "x3"})
	w.doc("cat", "matches.x3", map[string]any{"parents": parents("rx")})
	w.start()
	w.caughtUp()

	placed := func(token, item string) bool {
		t.Helper()
		r, _ := w.follow("/cat/where?item="+item, token)
		if r.status != 200 {
			t.Fatalf("where %s: %d %v", item, r.status, r.body)
		}
		return r.body["placement"] != nil
	}
	for _, c := range []struct {
		group string
		want  bool
	}{
		{"ids", false},    // /principal/id: never counts
		{"covs", false},   // covers is false without writes
		{"ovs", false},    // overlaps is false without writes
		{"nots", true},    // not overlaps: true without writes
		{"acts", true},    // a read's action is read
		{"docs", false},   // a read has no doc
		{"wholes", false}, // the whole envelope includes /now and /principal
		{"ops", false},    // a group the key may not assert
	} {
		tok := w.caller("user:i", c.group)
		if got := placed(tok, "/r/matches/x3"); got != c.want {
			t.Errorf("group %s sees x3: %v, want %v", c.group, got, c.want)
		}
		// A folder is visible only through a role without rules.
		if r, _ := w.follow("/cat/children?of=rx", tok); r.status != 404 {
			t.Errorf("group %s lists rx: %d", c.group, r.status)
		}
	}
	// The spec's translator (writes within /i18n) sees what it may read.
	if !placed(w.caller("user:anna", "translators"), "/r/matches/derby") {
		t.Error("the translator doesn't see derby")
	}

	// Grants are issued only through subjects the key may assert: ops gets
	// reader on x3 through group:ops, which the key may not assert.
	opsCaller := w.caller("user:o", "ops")
	w.issue(opsCaller, map[string]any{"item": "/r/matches/x3", "want": toAny("read")}, 403)
	rg := w.do("POST", "/read-grants", opsCaller, map[string]any{"items": toAny("/r/matches/x3")})
	if e := rg.body["grants"].([]any)[0].(map[string]any)["error"]; e == nil {
		t.Errorf("read-grants through an unassertable group: %v", rg.body)
	}
	// The same role through an assertable subject does.
	w.patch("cat", "rx", map[string]any{"op": "add", "path": "/$access/user:o", "value": toAny("reader")})
	w.caughtUp()
	w.issue(opsCaller, map[string]any{"item": "/r/matches/x3", "want": toAny("read")}, 200)
	if !placed(opsCaller, "/r/matches/x3") {
		t.Error("a user subject's reader doesn't make x3 visible")
	}
}

// holdRT drops the namespace log reads of one namespace while held, so a
// follower can't apply what lands meanwhile.
type holdRT struct {
	ns   string
	hold atomic.Bool
	base http.RoundTripper
}

func (h *holdRT) held(r *http.Request) bool {
	p := r.URL.Path
	return h.hold.Load() && strings.HasPrefix(p, "/ns/"+h.ns+"/") && (strings.HasSuffix(p, "/log") || strings.HasSuffix(p, "/events"))
}

func (h *holdRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := h.base.RoundTrip(r)
	if err == nil && h.held(r) {
		resp.Body.Close()
		return &http.Response{StatusCode: 503, Status: "503 Service Unavailable", Request: r,
			Header: http.Header{"Content-Type": {"application/json"}, "Retry-After": {"0"}},
			Body:   io.NopCloser(strings.NewReader(`{"code":"held","message":"held by the test"}`))}, nil
	}
	return resp, err
}

// TestVisibilityPinned: the roles, their definitions and the keys used for
// visibility are those as of the content namespaces' ns_ids in the
// listing's combined checkpoint, so a listing at a given at never changes
// when a /roles change lands later (§B.11.5).
func TestVisibilityPinned(t *testing.T) {
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
	r, loc := w.follow("/cat/children?of=season", fan)
	if childNames(r.body) != "matches.derby,matches.shared" {
		t.Fatalf("fan on season: %v", r.body)
	}

	// reader stops granting read, but the service hasn't applied it.
	rt.hold.Store(true)
	before := w.svc.Tree().Checkpoint("matches")
	opm := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "replace", "path": "/roles/reader/can", "value": toAny("append")}}))
	// The grant checker sees the new document (its TTL is a millisecond).
	waitFor(t, "the checker to see the new roles", func() bool {
		c, err := w.svc.Tree().Checker().Config(ctx, "matches")
		return err == nil && fmt.Sprint(c.Roles["reader"].Can) == "[append]"
	})
	time.Sleep(50 * time.Millisecond)
	if got := w.svc.Tree().Checkpoint("matches"); got != before {
		t.Fatalf("the service applied matches while held: %s -> %s", before, got)
	}
	// The listing at the same at is unchanged.
	r = w.do("GET", loc, fan, nil)
	if r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
		t.Errorf("the listing at the same at changed: %d %v", r.status, r.body)
	}
	if r2, loc2 := w.follow("/cat/children?of=season", fan); loc2 != loc || childNames(r2.body) != "matches.derby,matches.shared" {
		t.Errorf("the current listing changed before its at did: %s %v", loc2, r2.body)
	}

	// Once applied, the new at shows the change: season is hidden from fan.
	rt.hold.Store(false)
	w.caughtUp()
	r, loc2 := w.follow("/cat/children?of=season", fan)
	if loc2 == loc || r.status != 404 {
		t.Errorf("after the roles change: %s %d %v", loc2, r.status, r.body)
	}
	// The document is kept with the checkpoint, across restarts.
	w.stop()
	rt.hold.Store(true)
	w.start()
	if r, _ := w.follow("/cat/children?of=season", fan); r.status != 404 {
		t.Errorf("after a restart: %d %v", r.status, r.body)
	}
	if r, _ := w.follow("/cat/children?of=derbies", fan); r.status != 200 || childNames(r.body) != "matches.other,matches.shared" {
		t.Errorf("fan on derbies after a restart: %d %v", r.status, r.body)
	}
	rt.hold.Store(false)
}

// TestRestoreV038: restore's answers come in order (404, 410, then 403
// for callers without read, without restore, without a placement or whose
// restore would widen, then 409), and the item must still be placed; its
// frozen rows stay those of its deletion even if it was unplaced and
// placed again (§B.11.4, §B.11.7).
func TestRestoreV038(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("cat", "matches.final", map[string]any{"parents": parents("season")})
	w.doc("matches", "again", map[string]any{"title": "again"})
	w.doc("cat", "matches.again", map[string]any{"parents": parents("season")})
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	fan := w.caller("user:fred", "fan-club")
	nobody := w.caller("user:nobody")
	restore := func(token, item string, status int) resp {
		t.Helper()
		return w.issue(token, map[string]any{"item": item, "want": toAny("restore")}, status)
	}

	// Never existed: 404, for anyone, placed or not.
	restore(nobody, "/r/matches/final", 404)
	restore(nobody, "/r/matches/ghost", 404)
	// Live: 403 without read, 403 without restore, then 409.
	restore(nobody, "/r/matches/derby", 403)
	restore(fan, "/r/matches/derby", 403)
	restore(bob, "/r/matches/derby", 409)

	// Deleted, then unplaced: no placement, 403.
	must(w.ops.Delete(ctx, "matches", "again", must(w.ops.Head(ctx, "matches", "again")).ID))
	w.caughtUp()
	restore(bob, "/r/matches/again", 200)
	restore(nobody, "/r/matches/again", 403)
	must(w.ops.Delete(ctx, "cat", "matches.again", must(w.ops.Head(ctx, "cat", "matches.again")).ID))
	w.caughtUp()
	if r := restore(bob, "/r/matches/again", 403); !strings.Contains(r.body["message"].(string), "not placed") {
		t.Errorf("unplaced: %v", r.body)
	}
	// Placed again (the placement restored, under derbies): the frozen rows
	// are those of its deletion, so fan-club's desk there is a widening.
	ph := must(w.ops.Head(ctx, "cat", "matches.again"))
	must(w.ops.Restore(ctx, "cat", "matches.again", ph.ID, []any{
		map[string]any{"op": "replace", "path": "", "value": map[string]any{"parents": parents("derbies")}}}))
	w.caughtUp()
	restore(fan, "/r/matches/again", 403)
	if r := restore(bob, "/r/matches/again", 403); !strings.Contains(r.body["message"].(string), "would give group:fan-club the role desk") {
		t.Errorf("widening restore: %v", r.body)
	}
	// An admin restores it.
	admin := w.caller("user:ada", "catalog-admins", "match-desk")
	if b := restore(admin, "/r/matches/again", 200).body; fmt.Sprint(b["roles"]) != "[desk]" {
		t.Errorf("admin's restore grant: %v", b)
	}
	// Moved back under season (by an admin), bob's restore doesn't widen.
	g := w.grantFor(admin, map[string]any{"node": "matches.again", "want": toAny("move"), "to": toAny("season")})
	h := must(w.ops.Head(ctx, "cat", "matches.again"))
	must(w.core(g).Append(ctx, "cat", "matches.again", h.ID, []any{map[string]any{"op": "replace", "path": "/parents", "value": parents("season")}}))
	w.caughtUp()
	b := restore(bob, "/r/matches/again", 200).body
	if fmt.Sprint(b["roles"]) != "[desk]" {
		t.Errorf("restore grant: %v", b)
	}

	// Purged: 410, before anything about the caller.
	purger := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "purge"})))
	must(purger.Purge(ctx, "matches", "again", must(w.ops.Head(ctx, "matches", "again")).ID, false))
	w.caughtUp()
	restore(nobody, "/r/matches/again", 410)
}

// TestMoveDeletedPlacement: a move of a deleted item's placement is
// checked like any other, against the roles the item would have now
// (§B.11.7): a narrowing move is allowed, a widening one isn't.
func TestMoveDeletedPlacement(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	must(w.ops.Delete(ctx, "matches", "shared", must(w.ops.Head(ctx, "matches", "shared")).ID))
	w.caughtUp()
	// shared is under season and derbies: leaving season narrows.
	w.issue(bob, map[string]any{"node": "matches.shared", "want": toAny("move"), "to": toAny("derbies")}, 200)
	// derby (live) moved under derbies would widen; so would a deleted one.
	must(w.ops.Delete(ctx, "matches", "derby", must(w.ops.Head(ctx, "matches", "derby")).ID))
	w.caughtUp()
	w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}, 403)
}

// TestUnfilteredPartial: problems, orphans and manifests need
// namespace-wide read on the catalog and on the content namespaces they
// cover: for a manifest those of the items it pins, for problems and
// orphans every trusted one; a public namespace counts as read
// namespace-wide (§B.11.5). Such an answer in a subject set's URL space
// is kept by no shared cache, and no longer than the grants.
func TestUnfilteredPartial(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	// A second trusted namespace, teams, that nobody below reads as a whole.
	opt := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(opt.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "cat")).Config
	must(opc.PatchConfig(ctx, "cat", cfg, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.start()
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })

	exp := w.s.Now().Add(100 * time.Second)
	partial := w.opsKey.Grant(t, w.s.Now(), "user:pw", []string{"cat", "matches"}, []string{"read"},
		map[string]any{"groups": toAny("fan-club"), "exp": exp.Format(time.RFC3339)})
	fan := w.caller("user:fred", "fan-club")
	_, locFan := w.follow("/cat/children?of=season", fan)
	// Not wide on teams: the subject set's URL space, not g/all.
	_, loc := w.follow("/cat/children?of=season", partial)
	if loc != locFan {
		t.Errorf("a partially wide reader: %s, fan %s", loc, locFan)
	}
	// A manifest of season pins matches items only: allowed, private.
	r, _ := w.follow("/cat/manifest?of=season", partial)
	if r.status != 200 || len(r.body["entries"].([]any)) == 0 {
		t.Fatalf("manifest for a reader wide on what it pins: %d %v", r.status, r.body)
	}
	cc := r.header.Get("Cache-Control")
	age, err := strconv.Atoi(strings.TrimPrefix(cc, "private, max-age="))
	if err != nil || age > 100 || age < 90 || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("manifest caching: %q, CDN %q", cc, r.header.Get("CDN-Cache-Control"))
	}
	// problems and orphans cover every trusted namespace.
	for _, op := range []string{"problems", "orphans"} {
		if r, _ := w.follow("/cat/"+op, partial); r.status != 403 {
			t.Errorf("%s for a reader not wide on teams: %d", op, r.status)
		}
	}
	// The fan, in the same URL space, still can't have the manifest.
	if r, _ := w.follow("/cat/manifest?of=season", fan); r.status != 403 {
		t.Errorf("manifest for the fan: %d", r.status)
	}
	// teams made public counts as read namespace-wide: g/all.
	opTeams := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"teams"}, []string{"read", "config"})))
	tcfg := must(opTeams.NSHead(ctx, "teams")).Config
	must(opTeams.PatchConfig(ctx, "teams", tcfg, []any{map[string]any{"op": "replace", "path": "/read", "value": "public"}}))
	w.caughtUp()
	waitFor(t, "the service to apply teams' change", func() bool {
		h, err := opTeams.NSHead(ctx, "teams")
		return err == nil && w.svc.Tree().Checkpoint("teams") == h.ID
	})
	waitFor(t, "teams to be public", func() bool {
		c, err := w.svc.Tree().Checker().Config(ctx, "teams")
		return err == nil && c.Read == "public"
	})
	r, loc = w.follow("/cat/problems", partial)
	if r.status != 200 || !strings.Contains(loc, "/g/all/") {
		t.Errorf("problems with teams public: %d %s", r.status, loc)
	}
}
