package catalog_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/tree"
)

// v82Refused fails unless r is the caller's-grant 403 of POST /grants and
// POST /read-grants (§B.11.4 The caller's grant): no-store, decided at no
// checkpoint, with no grant, key or item in the body.
func v82Refused(t *testing.T, what string, r resp) {
	t.Helper()
	if r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Cache-Control") != "no-store" ||
		r.body["checkpoint"] != nil || r.body["items"] != nil || r.body["grant"] != nil || r.body["keys"] != nil {
		t.Errorf("%s: %d %q %v, want the caller's-grant 403", what, r.status, r.header.Get("Cache-Control"), r.body)
	}
}

// v82Roles adds to the catalog namespace the role clocked, which lists
// read and append and has a rule on /now, so that it counts for no read
// (§C.2 item 5), and viewer, which lists read, and returns a function
// minting a grant for sub in groups carrying roles of the catalog's.
func (w *world) v82Roles() func(sub string, can []string, groups []string, roles ...string) string {
	w.t.Helper()
	ctx := context.Background()
	opc := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{
		map[string]any{"op": "add", "path": "/roles/clocked", "value": map[string]any{"can": toAny("read", "append"), "rules": []any{nowRule}}},
		map[string]any{"op": "add", "path": "/roles/viewer", "value": map[string]any{"can": toAny("read")}},
	}))
	w.caughtUp()
	return func(sub string, can []string, groups []string, roles ...string) string {
		return w.opsKey.Grant(w.t, w.s.Now(), sub, []string{"cat"}, can, map[string]any{"groups": toAny(groups...), "roles": toAny(roles...)})
	}
}

// ACC-5, scenario 116 (SERVICES §B.11.4 The caller's grant): a caller
// whose grant has a block rule that refers to /now is 403, no-store, at
// POST /grants whatever it wants and at POST /read-grants, after the 401
// and the request-shape 400s and before every other answer: the ?min
// wait's 503, and the 404 of a name that never existed.
func TestV082CallersGrantNowRule(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	desk := w.caller("user:anna", "match-desk")
	clock := w.idp.Grant(t, w.s.Now(), "user:anna", []string{"cat"}, idCan,
		map[string]any{"groups": toAny("match-desk"), "rules": []any{nowRule}})
	items := map[string]any{"items": toAny("/r/matches/derby")}
	for _, req := range []map[string]any{
		{"item": "/r/matches/derby", "want": toAny("append")},
		{"item": "/r/matches/derby", "want": toAny("read")},
		{"item": "/r/matches/derby", "want": toAny("read", "append")},
		{"node": "matches.derby", "want": toAny("move"), "to": toAny("season")},
		{"node": "matches.derby", "want": toAny("delete")},
	} {
		w.issue(desk, req, 200)
		v82Refused(t, fmt.Sprintf("POST /grants %v", req), w.do("POST", "/grants", clock, req))
	}
	v82Refused(t, "POST /read-grants", w.do("POST", "/read-grants", clock, items))

	// 401 and the request-shape 400s come first: no state decides them.
	if r := w.do("POST", "/grants", "", map[string]any{"item": "/r/matches/derby", "want": toAny("append")}); r.status != 401 {
		t.Errorf("no grant: %d %v", r.status, r.body)
	}
	for what, body := range map[string]any{
		"a body that isn't an object": []any{},
		"no want":                     map[string]any{"item": "/r/matches/derby"},
		"an unknown verb":             map[string]any{"item": "/r/matches/derby", "want": toAny("fly")},
		"a malformed item":            map[string]any{"item": "matches/derby", "want": toAny("append")},
		"a malformed node":            map[string]any{"node": "a/b", "want": toAny("delete")},
		"a move without to":           map[string]any{"node": "matches.derby", "want": toAny("move")},
		"a malformed folder":          map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("a/b")},
		"neither item nor node":       map[string]any{"want": toAny("append")},
	} {
		for who, tok := range map[string]string{"the /now grant": clock, "a plain grant": desk} {
			if r := w.do("POST", "/grants", tok, body); r.status != 400 || r.body["code"] != "bad_input" {
				t.Errorf("POST /grants, %s, %s: %d %v, want 400", what, who, r.status, r.body)
			}
		}
	}
	for what, body := range map[string]any{"no items": map[string]any{"items": []any{}}, "a body that isn't an object": []any{}} {
		if r := w.do("POST", "/read-grants", clock, body); r.status != 400 {
			t.Errorf("POST /read-grants, %s: %d %v, want 400", what, r.status, r.body)
		}
	}
	// A malformed ?min is the request's shape too.
	for _, path := range []string{"/grants?min=garbage", "/read-grants?min=garbage"} {
		body := any(map[string]any{"item": "/r/matches/derby", "want": toAny("append")})
		if strings.HasPrefix(path, "/read") {
			body = items
		}
		if r := w.do("POST", path, clock, body); r.status != 400 {
			t.Errorf("POST %s: %d %v, want 400", path, r.status, r.body)
		}
	}

	// Before any other answer. A name that never existed is 404 to a
	// plain grant; a min the service can't reach is 503.
	never := map[string]any{"item": "/r/matches/never-was", "want": toAny("append")}
	w.issue(desk, never, 404)
	v82Refused(t, "a name that never existed", w.do("POST", "/grants", clock, never))
	missing := map[string]any{"node": "no-such-node", "want": toAny("delete")}
	w.issue(desk, missing, 404)
	v82Refused(t, "a node not in the catalog", w.do("POST", "/grants", clock, missing))
	other := must(w.ops.CreateDoc(ctx, "matches", "elsewhere", map[string]any{"title": "elsewhere"}))
	for _, c := range []struct {
		path string
		body any
	}{
		{"/grants?min=cat:" + other.NSID, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}},
		{"/read-grants?min=cat:" + other.NSID, items},
		// A min naming a namespace the service doesn't follow is a 400
		// that state decides: after the 403.
		{"/grants?min=nope:" + other.NSID, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}},
	} {
		v82Refused(t, "POST "+c.path, w.do("POST", c.path, clock, c.body))
	}
	if r := w.do("POST", "/grants?min=cat:"+other.NSID, desk, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}); r.status != 503 {
		t.Errorf("a plain grant behind an unreachable min: %d %v, want 503", r.status, r.body)
	}

	// Even where reads are public.
	w.patchMatches(map[string]any{"op": "replace", "path": "/read", "value": "public"})
	if r := w.do("POST", "/read-grants", desk, items); r.status != 200 || entry(r, 0)["public"] != true {
		t.Fatalf("a public item for a plain grant: %d %v", r.status, r.body)
	}
	v82Refused(t, "POST /read-grants for a public item", w.do("POST", "/read-grants", clock, items))
	v82Refused(t, "POST /grants for a public item", w.do("POST", "/grants", clock, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}))
}

// ACC-5, scenario 116, second class: a grant that allows read in no
// namespace it verifies in (the catalog namespace), having no read in its
// can, or roles of which none counts for read, is 403 at POST
// /read-grants and for a want that lists read. A want without read is
// judged as usual: its identity still counts.
func TestV082CallersGrantReadsNothing(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	with := w.v82Roles()
	desk := []string{"match-desk"}
	items := map[string]any{"items": toAny("/r/matches/derby")}
	appendOnly := map[string]any{"item": "/r/matches/derby", "want": toAny("append")}
	for what, tok := range map[string]string{
		"a grant without read":             w.idp.Grant(t, w.s.Now(), "user:anna", []string{"cat"}, []string{}, map[string]any{"groups": toAny(desk...)}),
		"a grant with append alone":        w.opsKey.Grant(t, w.s.Now(), "user:anna", []string{"cat"}, []string{"append"}, map[string]any{"groups": toAny(desk...)}),
		"every read role on /now":          with("user:anna", []string{"read", "append"}, desk, "clocked"),
		"roles, none listing read":         with("user:anna", []string{"read"}, desk, "desk"),
		"a /now role and one without read": with("user:anna", []string{"read", "append"}, desk, "clocked", "desk"),
	} {
		v82Refused(t, what+": POST /read-grants", w.do("POST", "/read-grants", tok, items))
		v82Refused(t, what+": want read", w.do("POST", "/grants", tok, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}))
		v82Refused(t, what+": want read and append", w.do("POST", "/grants", tok, map[string]any{"item": "/r/matches/derby", "want": toAny("read", "append")}))
		// Before any other answer here too.
		v82Refused(t, what+": want read of a name that never existed", w.do("POST", "/grants", tok, map[string]any{"item": "/r/matches/never-was", "want": toAny("read")}))
		// Judged as usual: the desk's role at derby appends.
		if r := w.do("POST", "/grants", tok, appendOnly); r.status != 200 || r.body["grant"] == nil || fmt.Sprint(r.body["can"]) != "[append]" {
			t.Errorf("%s: want append: %d %v, want a grant", what, r.status, r.body)
		}
		// And refused as usual, at a checkpoint.
		if r := w.do("POST", "/grants", tok, map[string]any{"item": "/r/matches/rumour1", "want": toAny("append")}); r.status != 403 || r.body["checkpoint"] == nil {
			t.Errorf("%s: want append without a role: %d %v, want the decision's 403", what, r.status, r.body)
		}
		if r := w.do("POST", "/grants", tok, map[string]any{"node": "matches.derby", "want": toAny("delete")}); r.status != 200 {
			t.Errorf("%s: an organising request: %d %v", what, r.status, r.body)
		}
	}
	// One read role that counts is enough.
	ok := with("user:anna", []string{"read"}, desk, "clocked", "viewer")
	if r := w.do("POST", "/read-grants", ok, items); r.status != 200 || entry(r, 0)["grant"] == nil {
		t.Errorf("a /now role beside a reader: %d %v", r.status, r.body)
	}
	w.issue(ok, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)
}

// ACC-6, scenario 117 (SERVICES §B.11.2 Through the key, §B.11.4): in a
// content namespace a role counts for read only where no rule of it
// refers to /now (or the whole envelope). A read want leaves such roles
// out; with none kept the answer is the 403 of no role, as for an item
// without a placement, never a grant carrying the role. A mixed want
// keeps its other verbs through it.
func TestV082ReadWantLeavesOutNowRoles(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.doc("matches", "opener", map[string]any{"title": "opener"})
	w.start()
	w.caughtUp()
	w.patchMatches(
		map[string]any{"op": "add", "path": "/roles/timed", "value": map[string]any{"can": toAny("read", "append"), "rules": []any{nowRule}}},
		map[string]any{"op": "add", "path": "/roles/wholly", "value": map[string]any{"can": toAny("read"), "rules": []any{wholeRule}}},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "timed"},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "wholly"})
	w.patch("cat", "season",
		map[string]any{"op": "add", "path": "/$access/group:timers", "value": toAny("timed")},
		map[string]any{"op": "add", "path": "/$access/group:wholes", "value": toAny("wholly")},
		map[string]any{"op": "add", "path": "/$access/group:duo", "value": toAny("reader", "timed")})
	w.caughtUp()
	derby := func(want ...string) map[string]any {
		return map[string]any{"item": "/r/matches/derby", "want": toAny(want...)}
	}

	// Scenario 117: the only role has a /now rule.
	tim := w.caller("user:tim", "timers")
	refused := w.issue(tim, derby("read"), 403)
	unplaced := w.issue(tim, map[string]any{"item": "/r/matches/opener", "want": toAny("read")}, 403)
	if refused.body["grant"] != nil || !p30Same(refused.body, unplaced.body, "/r/matches/derby", "/r/matches/opener") {
		t.Errorf("a read want through a /now role %v, want the 403 of an item without a placement %v", refused.body, unplaced.body)
	}
	// A mixed want keeps append, through the role.
	mixed := w.issue(tim, derby("read", "append"), 200).body
	if fmt.Sprint(mixed["can"]) != "[append]" || fmt.Sprint(mixed["roles"]) != "[timed]" {
		t.Errorf("a mixed want through a /now role: can %v roles %v, want [append] through [timed]", mixed["can"], mixed["roles"])
	}
	if b := w.issue(tim, derby("append"), 200).body; fmt.Sprint(b["can"]) != "[append]" || fmt.Sprint(b["roles"]) != "[timed]" {
		t.Errorf("an append want through a /now role: %v", b)
	}
	// A rule on the whole envelope counts as one on /now.
	w.issue(w.caller("user:wil", "wholes"), derby("read"), 403)
	// Two roles: read through the clean reader, append through the
	// /now editor; a read want alone carries the reader only.
	duo := w.caller("user:dee", "duo")
	if b := w.issue(duo, derby("read", "append"), 200).body; fmt.Sprint(b["can"]) != "[read append]" || fmt.Sprint(b["roles"]) != "[reader timed]" {
		t.Errorf("two roles, a mixed want: can %v roles %v", b["can"], b["roles"])
	}
	if b := w.issue(duo, derby("read"), 200).body; fmt.Sprint(b["can"]) != "[read]" || fmt.Sprint(b["roles"]) != "[reader]" {
		t.Errorf("two roles, a read want: can %v roles %v, want [read] through [reader] alone", b["can"], b["roles"])
	}
	// POST /read-grants agrees.
	if e := entry(w.do("POST", "/read-grants", tim, map[string]any{"items": toAny("/r/matches/derby")}), 0); e["status"] != 403.0 || e["grant"] != nil {
		t.Errorf("read-grants through a /now role: %v", e)
	}
}

// ACC-15 (SERVICES §B.9, §B.11.4): an implicit placement, drawn from a
// content document's $parents, is no node of the catalog namespace: an
// organising request naming it as node is 404, with the body of a node
// not in the catalog. The same name as an item is still judged as an
// item.
func TestV082ImplicitPlacementIsNoNode(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.selfPlacing = true
	w.seed()
	w.doc("matches", "selfie", map[string]any{"title": "selfie", "$parents": parents("season")})
	w.start()
	w.caughtUp()
	admin := w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"read"}, map[string]any{"groups": toAny("catalog-admins")})
	// The service does hold it as an implicit placement, which a reader
	// of both namespaces whole is shown.
	all := w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches"}, []string{"read"})
	if r, _ := w.follow("/cat/where?item=/r/matches/selfie", all); r.status != 200 || r.body["placement"].(map[string]any)["self"] != true {
		t.Fatalf("where of a self-placed item: %d %v", r.status, r.body)
	}
	for _, tok := range []string{w.caller("user:anna", "match-desk"), admin} {
		for _, req := range []map[string]any{
			{"want": toAny("move"), "to": toAny("derbies")},
			{"want": toAny("delete")},
			{"want": toAny("restore")},
		} {
			req["node"] = "matches.selfie"
			implicit := w.issue(tok, req, 404)
			req["node"] = "matches.nosuch"
			missing := w.issue(tok, req, 404)
			if implicit.body["code"] != missing.body["code"] ||
				strings.ReplaceAll(implicit.body["message"].(string), "matches.selfie", "matches.nosuch") != missing.body["message"] {
				t.Errorf("%v: an implicit placement as node %v, a node not in the catalog %v", req["want"], implicit.body, missing.body)
			}
		}
	}
	// As an item it is judged as one: an implicit placement grants
	// nothing (§B.9), so no role is kept, at the checkpoint.
	if r := w.do("POST", "/grants", w.caller("user:anna", "match-desk"), map[string]any{"item": "/r/matches/selfie", "want": toAny("append")}); r.status != 403 || r.body["checkpoint"] == nil {
		t.Errorf("the same name as an item: %d %v, want the decision's 403", r.status, r.body)
	}
}

// SVC-12, scenario 128 (SERVICES §B.5 Behind, §B.11.5): once the service
// stops following a content namespace (here its grant there is refused),
// that namespace's roles count for no folder: one visible to a subject
// set only through them is hidden, answered as a node not in the catalog,
// and its items get no read grant. The listing that showed it isn't
// served again at its at. Followed again, the folder returns.
func TestV082StoppedNamespaceRolesCountForNoFolder(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	fan := w.caller("user:fred", "fan-club")
	sees := func() (int, string) {
		r := w.do("GET", "/cat/children?of=season", fan, nil)
		if r.status != 302 {
			return r.status, ""
		}
		return w.do("GET", r.header.Get("Location"), fan, nil).status, r.header.Get("Location")
	}
	st, before := sees()
	if st != 200 {
		t.Fatalf("season for the fan club, through matches' reader role: %d", st)
	}
	if r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")}); entry(r, 0)["grant"] == nil {
		t.Fatalf("read-grants before the stop: %v", r.body)
	}
	// The service's key leaves matches: its follower is refused there.
	// (Another key keeps the namespace administrable meanwhile.)
	k2 := clienttest.NewKey("admin2")
	w.patchMatches(map[string]any{"op": "add", "path": "/keys/-", "value": k2.Entry("*")})
	admin2 := w.s.Client(t, client.WithBearer(k2.Grant(t, w.s.Now(), "user:admin2", []string{"matches"}, []string{"read", "config"})))
	cfg := must(admin2.NSHead(ctx, "matches"))
	keys := must(admin2.NSDoc(ctx, "matches", cfg.ID)).Value["keys"].([]any)
	must(admin2.PatchConfig(ctx, "matches", cfg.Config, []any{map[string]any{"op": "remove", "path": "/keys/0"}}))
	waitFor(t, "the service to stop following matches", func() bool {
		stopped := false
		w.svc.Tree().View(func(g *tree.Graph, _ map[string]string) { stopped = g.Stopped("matches") })
		return stopped
	})
	if st, _ := sees(); st != 404 {
		t.Errorf("season for the fan club once matches is stopped: %d, want 404 as a node not in the catalog", st)
	}
	if r := w.do("GET", before, fan, nil); r.status == 200 {
		t.Errorf("the listing from before the stop is served at its at: %v", r.body)
	}
	if r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")}); r.status == 200 && (entry(r, 0)["grant"] != nil || entry(r, 0)["public"] != nil) {
		t.Errorf("read-grants for an item of a stopped namespace: %v", r.body)
	}
	// Followed again.
	must(admin2.PatchConfig(ctx, "matches", must(admin2.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/keys/0", "value": keys[0]}}))
	waitFor(t, "season to return for the fan club", func() bool { st, _ := sees(); return st == 200 })
}

// SVC-14t (tests no package had): a private listing answers a credential
// that isn't a Bearer grant 401, as no grant; a folder visible to a
// subject set only through a namespace's reader role is hidden once that
// namespace is purged (scenario 123).
func TestV082ListingCredentialsAndPurgedRoles(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	if r := w.doWith("GET", "/cat/children?of=season", "", nil, map[string]string{"Authorization": "Basic eDp5"}); r.status != 401 {
		t.Errorf("Authorization: Basic at a private listing: %d %v, want 401", r.status, r.body)
	}
	fan := w.caller("user:fred", "fan-club")
	if r, _ := w.follow("/cat/children?of=season", fan); r.status != 200 {
		t.Fatalf("season for the fan club: %d %v", r.status, r.body)
	}
	w.purge("matches")
	waitFor(t, "season to be hidden once matches is purged", func() bool {
		r := w.do("GET", "/cat/children?of=season", fan, nil)
		return r.status == 404 || r.status == 302 && w.do("GET", r.header.Get("Location"), fan, nil).status == 404
	})
}
