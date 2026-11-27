package server

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// v0.87 adversarial review: read rules on /doc (§C.2 item 5) at the
// places that answered before judging the revision they concern.

// v87Stale is an id no resource has.
const v87Stale = "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestV087PurgeHiddenHeadForbidden: a purge by a grant that may read but
// whose read rules don't allow reading the head is 403 at §6.2 step 2.2,
// before the precondition: its 412 would name the hidden head.
func TestV087PurgeHiddenHeadForbidden(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read", "purge"}, map[string]any{"rules": []any{v87TeamA}})
	hid := w.v87Doc("matches", "x", map[string]any{"team": "b"})
	expect(t, w.get("/r/matches/x", g), 404)
	for _, ifMatch := range []string{v87Stale, ""} {
		r := w.purge("matches", "x", ifMatch, g)
		if r.Code != 403 || strings.Contains(string(r.Body), hid) {
			t.Errorf("purge of a hidden head, If-Match %q: %d %s, want 403 without the head (§6.2 step 2.2)", ifMatch, r.Code, r.Body)
		}
	}
	// A head it can read: the precondition answers as before.
	w.v87Doc("matches", "y", map[string]any{"team": "a"})
	expectCode(t, w.purge("matches", "y", v87Stale, g), 412, "stale")
}

// TestV087PruneHiddenHeadForbidden: a prune is a write to the resource
// (§6.2 step 2.2): one of a head the grant can't read is 403 whatever its
// horizon, rather than 422 for a horizon outside the hidden ancestry and
// another answer for one inside it, and is never applied.
func TestV087PruneHiddenHeadForbidden(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	// The rules let a prune through by its action, and reads by /doc.
	rule := map[string]any{"any": []any{map[string]any{"op": "test", "path": "/action", "value": "prune"}, v87TeamA}}
	g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read", "prune"}, map[string]any{"rules": []any{rule}})
	b1 := w.v87Doc("matches", "x", map[string]any{"team": "b"})
	h2 := w.v87Doc("matches", "x", map[string]any{"team": "b", "v": 2.0})
	expect(t, w.get("/r/matches/x", g), 404)
	w.clock.Advance(10 * time.Minute)
	for _, h := range []string{b1, h2, v87Stale} {
		if r := w.prune("matches", "x", map[string]any{"horizon": h}, g); r.Code != 403 {
			t.Errorf("prune of a hidden head at horizon %s: %d %s, want 403 (§6.2 step 2.2)", h, r.Code, r.Body)
		}
	}
	expect(t, w.get("/r/matches/x/rev/"+b1, w.admin), 200)
	// A head it can read is pruned.
	w.v87Doc("matches", "y", map[string]any{"team": "a"})
	y2 := w.v87Doc("matches", "y", map[string]any{"team": "a", "v": 2.0})
	w.clock.Advance(10 * time.Minute)
	expect(t, w.prune("matches", "y", map[string]any{"horizon": y2}, g), 200)
}

// TestV087EndedCookieAtOldAt (§7.9 view): every cookie of a view is 403
// at every URL once an entry after its exchange changes its rules, at an
// at from before that entry too: validity is judged at the current
// checkpoint, the URL's deciding only what it sees.
func TestV087EndedCookieAtOldAt(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	w.seed(nil, nil, []string{"derby"})
	c, vid := w.cookie(w.li())
	base := "/ns/matches/view/" + vid
	old := cookieHdr(c)
	_, at0 := w.filtered(w.li())
	paths := []string{base + "/at/" + at0 + "/heads", base + "/at/" + at0 + "/log"}
	for _, p := range paths {
		expect(t, w.do(req{method: "GET", path: p, hdr: old}), 200)
	}
	expect(t, w.patchNS("matches", ops(op("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}})), w.admin), 201)
	for _, p := range paths {
		if r := w.do(req{method: "GET", path: p, hdr: old}); r.Code != 403 {
			t.Errorf("ended cookie at the at before the change: GET %s: %d %s, want 403", p, r.Code, r.Body)
		}
	}
}

// TestV087PrunedHiddenLiveLog: a resource a reader can read no revision
// of, pruned or not, answers its live log and events as a name that
// doesn't exist does, never 410 naming its horizon: for a partial reader
// in a covered namespace and for any other reader whose rules refer to
// /doc.
func TestV087PrunedHiddenLiveLog(t *testing.T) {
	for name, env := range map[string][]envOpt{
		"covered":   {withLongPoll(time.Second)},
		"uncovered": {withLongPoll(time.Second), func(o *core.Options) { o.NoFilteredReads = true }},
	} {
		t.Run(name, func(t *testing.T) {
			w := newV75s(t, v75sOpts{env: env})
			g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
			adminP := w.grant(w.k, "user:root", []string{"matches"}, []string{"read", "create", "append", "prune"})
			w.v87Doc("matches", "hid", map[string]any{"team": "b"})
			h2 := w.v87Doc("matches", "hid", map[string]any{"team": "b", "v": 2.0})
			same := func(when string) {
				t.Helper()
				for _, p := range []string{"/log?live=long-poll", "/events"} {
					hid, nope := w.v87Get("/r/matches/hid"+p, g), w.v87Get("/r/matches/nope"+p, g)
					if strings.Contains(string(hid.Body), h2) || hid.Code != nope.Code || string(hid.Body) != string(nope.Body) ||
						hid.H.Get("Cache-Control") != nope.H.Get("Cache-Control") {
						t.Errorf("%s %s: hidden %d %s %v, absent %d %s %v, want the same", when, p, hid.Code, hid.Body, hid.H, nope.Code, nope.Body, nope.H)
					}
				}
			}
			same("unpruned")
			w.clock.Advance(10 * time.Minute)
			expect(t, w.prune("matches", "hid", map[string]any{"horizon": h2}, adminP), 200)
			same("pruned")
			// A reader of every revision still learns of the horizon.
			if r := w.v87Get("/r/matches/hid/log?live=long-poll", adminP); r.Code != 410 || !strings.Contains(string(r.Body), h2) {
				t.Errorf("long-poll of a pruned resource by a reader of it: %d %s, want 410 naming the horizon", r.Code, r.Body)
			}
		})
	}
}

// TestV087PrunedVisibleBelowTombstone: a partial reader that can read a
// revision of a pruned resource only below a delete and a restore still
// learns of the horizon: the kept range is judged down to the horizon,
// across the tombstone.
func TestV087PrunedVisibleBelowTombstone(t *testing.T) {
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(time.Second)}})
	g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
	adminP := w.grant(w.k, "user:root", []string{"matches"}, []string{"read", "create", "append", "prune"})
	w.v87Doc("matches", "x", map[string]any{"team": "b"})
	h := w.v87Doc("matches", "x", map[string]any{"team": "b", "v": 2.0})
	w.v87Doc("matches", "x", map[string]any{"team": "a"})
	// The tombstone deletes a team b document: it is hidden too.
	w.v87Doc("matches", "x", map[string]any{"team": "b", "v": 4.0})
	head := etagOf(w.get("/r/matches/x", w.admin))
	del := w.do(req{method: "DELETE", path: "/r/matches/x", ifMatch: head, bearer: w.admin})
	expect(t, del, 200)
	if del.Str("tombstone") == "" {
		t.Fatalf("delete: %s", del.Body)
	}
	r := w.do(req{method: "PATCH", path: "/r/matches/x", ifMatch: del.Str("tombstone"), body: addRoot(map[string]any{"team": "b", "v": 3.0}), bearer: w.admin})
	if r.Code != 200 && r.Code != 201 {
		t.Fatalf("restore: %d %s", r.Code, r.Body)
	}
	w.clock.Advance(10 * time.Minute)
	expect(t, w.prune("matches", "x", map[string]any{"horizon": h}, adminP), 200)
	if r := w.v87Get("/r/matches/x/log?live=long-poll", g); r.Code != 410 || !strings.Contains(string(r.Body), h) {
		t.Errorf("long-poll of a pruned resource with a readable revision below a tombstone: %d %s, want 410 naming the horizon", r.Code, r.Body)
	}
}

// TestV087HiddenSchemaUnavailable (§6.1 Read permission, §C.2 item 5): a
// schema revision the writer's /doc read rules don't allow reading is
// unreadable by it: 422 schema_unavailable for a valid and an invalid
// document alike, its content never judged nor shown.
func TestV087HiddenSchemaUnavailable(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	// It reads team a's documents, and vsch, a schema, by name.
	rule := map[string]any{"any": []any{v87TeamA, map[string]any{"op": "test", "path": "/resource", "value": "vsch"}}}
	writer := w.grant(w.k, "user:w", []string{"matches"}, []string{"read", "create", "append"}, map[string]any{"rules": []any{rule}})
	sch := w.v87Doc("matches", "sch", map[string]any{"$schema": dialect, "properties": map[string]any{"pin": map[string]any{"enum": []any{"SECRET-PIN-42"}}}})
	ref := "/r/matches/sch/rev/" + sch
	expect(t, w.get(ref, writer), 404)
	bad := w.do(req{method: "PATCH", path: "/r/matches/d1", ifNoneMatch: "*", body: addRoot(map[string]any{"$schema": ref, "team": "a", "pin": "guess"}), bearer: writer})
	good := w.do(req{method: "PATCH", path: "/r/matches/d2", ifNoneMatch: "*", body: addRoot(map[string]any{"$schema": ref, "team": "a", "pin": "SECRET-PIN-42"}), bearer: writer})
	for _, r := range []*resp{bad, good} {
		expectCode(t, r, 422, "schema_unavailable")
		if strings.Contains(string(r.Body), "SECRET-PIN") {
			t.Fatalf("the hidden schema's content: %s", r.Body)
		}
	}
	// A schema revision it can read validates.
	vis := w.v87Doc("matches", "vsch", map[string]any{"$schema": dialect, "properties": map[string]any{"pin": map[string]any{"enum": []any{"OPEN"}}}})
	vref := "/r/matches/vsch/rev/" + vis
	expectCode(t, w.do(req{method: "PATCH", path: "/r/matches/d3", ifNoneMatch: "*", body: addRoot(map[string]any{"$schema": vref, "team": "a", "pin": "guess"}), bearer: writer}), 422, "invalid")
	expect(t, w.do(req{method: "PATCH", path: "/r/matches/d4", ifNoneMatch: "*", body: addRoot(map[string]any{"$schema": vref, "team": "a", "pin": "OPEN"}), bearer: writer}), 201)
}

// TestV087HiddenSchemaOtherNamespace: the same for a schema in another
// namespace, read there by the rule for other namespaces (§6.1, §7.5):
// per revision too.
func TestV087HiddenSchemaOtherNamespace(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	w.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{w.k.entry("*")}})
	sg := w.grant(w.k, "user:root", []string{"schemas"}, []string{"read", "create", "append"})
	sch := w.create("schemas", "sch", map[string]any{"$schema": dialect, "properties": map[string]any{"pin": map[string]any{"enum": []any{"SECRET-PIN-42"}}}}, sg)
	vis := w.create("schemas", "vsch", map[string]any{"$schema": dialect, "properties": map[string]any{"pin": map[string]any{"enum": []any{"OPEN"}}}}, sg)
	rule := map[string]any{"any": []any{v87TeamA, map[string]any{"op": "test", "path": "/resource", "value": "vsch"}}}
	writer := w.grant(w.k, "user:w", []string{"matches", "schemas"}, []string{"read", "create", "append"}, map[string]any{"rules": []any{rule}})
	write := func(name, ref, pin string) *resp {
		return w.do(req{method: "PATCH", path: "/r/matches/" + name, ifNoneMatch: "*", body: addRoot(map[string]any{"$schema": ref, "team": "a", "pin": pin}), bearer: writer})
	}
	ref := "/r/schemas/sch/rev/" + sch
	for i, pin := range []string{"guess", "SECRET-PIN-42"} {
		r := write("d"+string(rune('1'+i)), ref, pin)
		expectCode(t, r, 422, "schema_unavailable")
		if strings.Contains(string(r.Body), "SECRET-PIN") {
			t.Fatalf("the hidden schema's content: %s", r.Body)
		}
	}
	vref := "/r/schemas/vsch/rev/" + vis
	expectCode(t, write("d3", vref, "guess"), 422, "invalid")
	expect(t, write("d4", vref, "OPEN"), 201)
}

// TestV087SchemaReadsHiddenReferrer (§6.1 schemaReads, §C.2 item 5): a
// schema revision opens by path to a reader of a referrer only where its
// read rules allow reading that referrer's document: one pinned only by
// documents it can't read stays closed.
func TestV087SchemaReadsHiddenReferrer(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	w.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{w.k.entry("*")}, "schemaReads": map[string]any{"for": []any{"matches"}}})
	sg := w.grant(w.k, "user:root", []string{"schemas"}, []string{"read", "create", "append"})
	sch := w.create("schemas", "s", map[string]any{"$schema": dialect, "type": "object"}, sg)
	ref := "/r/schemas/s/rev/" + sch
	g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
	w.v87Doc("matches", "hid", map[string]any{"$schema": ref, "team": "b"})
	if r := w.get(ref, g); r.Code == 200 {
		t.Fatalf("a schema pinned only by a document the reader can't read: %d %s", r.Code, r.Body)
	}
	w.v87Doc("matches", "vis", map[string]any{"$schema": ref, "team": "a"})
	expect(t, w.get(ref, g), 200)
}

// TestV087SettleHiddenTombstone: §6.2 step 2.2 comes before settling the
// verb, which would tell a hidden tombstone (restore) from a hidden live
// head (append).
func TestV087SettleHiddenTombstone(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	writer := w.grant(w.k, "user:w", []string{"matches"}, []string{"read", "create", "append"}, map[string]any{"rules": []any{v87TeamA}})
	w.v87Doc("matches", "live", map[string]any{"team": "b"})
	w.v87Doc("matches", "dead", map[string]any{"team": "b"})
	h := etagOf(w.get("/r/matches/dead", w.admin))
	expect(t, w.do(req{method: "DELETE", path: "/r/matches/dead", ifMatch: h, bearer: w.admin}), 200)
	patch := []any{map[string]any{"op": "replace", "path": "/team", "value": "a"}}
	rl := w.do(req{method: "PATCH", path: "/r/matches/live", ifMatch: v87Stale, body: patch, bearer: writer})
	rd := w.do(req{method: "PATCH", path: "/r/matches/dead", ifMatch: v87Stale, body: patch, bearer: writer})
	expect(t, rl, 403)
	if string(rl.Body) != string(rd.Body) || rd.Code != rl.Code {
		t.Fatalf("hidden live and hidden tombstoned heads answer differently: %d %s vs %d %s", rl.Code, rl.Body, rd.Code, rd.Body)
	}
}

// TestV087HiddenRevLikeUnknown: a revision a /doc reader can't read is
// answered as an id or a name that doesn't exist, cache headers and tags
// included, under its view and, where the namespace isn't covered, at
// the resource's own URLs.
func TestV087HiddenRevLikeUnknown(t *testing.T) {
	sig := func(r *resp, name string) string {
		tags := strings.ReplaceAll(r.H.Get("Cache-Tag"), "r:matches/"+name, "r:matches/{name}")
		return string(r.Body) + "|" + r.H.Get("Cache-Control") + "|" + r.H.Get("CDN-Cache-Control") + "|" + tags
	}
	name := func(p string) string {
		if strings.Contains(p, "/nope") {
			return "nope"
		}
		return "hid"
	}
	check := func(t *testing.T, w *v75s, g string, pairs [][2]string) {
		t.Helper()
		for _, p := range pairs {
			a, b := w.get(p[0], g), w.get(p[1], g)
			if a.Code != 404 || a.Code != b.Code || sig(a, name(p[0])) != sig(b, name(p[1])) {
				t.Errorf("hidden and absent differ:\n%s: %d %s\n%s: %d %s", p[0], a.Code, sig(a, name(p[0])), p[1], b.Code, sig(b, name(p[1])))
			}
		}
	}
	t.Run("view", func(t *testing.T) {
		w := newV75s(t, v75sOpts{})
		g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
		hidID := w.v87Doc("matches", "hid", map[string]any{"team": "b"})
		w.v87Doc("matches", "vis", map[string]any{"team": "a"})
		vid, _ := w.filtered(g)
		v := "/ns/matches/view/" + vid
		check(t, w, g, [][2]string{
			{"/r/matches/hid", "/r/matches/nope"},
			{v + "/r/hid/rev/" + hidID, v + "/r/hid/rev/" + v87Stale},
			{v + "/r/hid/rev/" + hidID, v + "/r/nope/rev/" + hidID},
			{"/r/matches/hid/raw", "/r/matches/nope/raw"},
		})
		// Rules that pass a null document (§6.4.1), which a name without
		// a head is judged with: the head's answers alike all the same.
		check(t, w, v87NotTeamB(w), [][2]string{
			{"/r/matches/hid", "/r/matches/nope"},
			{"/r/matches/hid/raw", "/r/matches/nope/raw"},
		})
	})
	t.Run("unfiltered", func(t *testing.T) {
		w := newV75s(t, v75sOpts{env: []envOpt{func(o *core.Options) { o.NoFilteredReads = true }}})
		g := w.grant(w.k, "user:t", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
		hidID := w.v87Doc("matches", "hid", map[string]any{"team": "b"})
		check(t, w, g, [][2]string{
			{"/r/matches/hid/rev/" + hidID, "/r/matches/hid/rev/" + v87Stale},
			{"/r/matches/hid/rev/" + hidID, "/r/matches/nope/rev/" + hidID},
			{"/r/matches/hid", "/r/matches/nope"},
			{"/r/matches/hid/raw", "/r/matches/nope/raw"},
		})
		nb := v87NotTeamB(w)
		check(t, w, nb, [][2]string{
			{"/r/matches/hid/rev/" + hidID, "/r/matches/hid/rev/" + v87Stale},
			{"/r/matches/hid", "/r/matches/nope"},
			{"/r/matches/hid/raw", "/r/matches/nope/raw"},
		})
	})
}

// v87NotTeamB is a reader of matches whose rule passes every document
// but team b's, a null one included.
func v87NotTeamB(w *v75s) string {
	return w.grant(w.k, "user:nb", []string{"matches"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/doc/team", "value": "b"}}}})
}

// TestV087FilteredLongPoll204Private: an unrestricted reader's /ns/{ns}
// cookie at a view's long-poll is no cache's, its 204 as much as its
// entries (§7.9 Partial reader).
func TestV087FilteredLongPoll204Private(t *testing.T) {
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(time.Second)}})
	w.seed(nil, nil, []string{"derby"})
	vid, at := w.filtered(w.li())
	r := w.do(req{method: "POST", path: "/edge-grants", bearer: w.grant(w.k, "user:root", []string{"matches"}, []string{"read"})})
	expect(t, r, 200)
	c, ok := edgeCookies(t, r)["/ns/matches"]
	if !ok {
		t.Fatalf("no /ns/matches cookie: %v", r.H.Values("Set-Cookie"))
	}
	lp := w.do(req{method: "GET", path: "/ns/matches/view/" + vid + "/log?live=long-poll&since=" + at, hdr: cookieHdr(c)})
	expect(t, lp, 204)
	expectPrivateNoStore(t, lp)
}
