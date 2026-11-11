package server

import (
	"strings"
	"testing"
	"time"
)

// V82-02 (v0.82), ACC-7o: a trusted catalog that is a remote branch (§G.3)
// covers the namespaces it trusts and makes nothing visible (SERVICES
// §B.11.9 Where; conformance 119).

// v82accessRemoteCatalog is a v75s whose origin also holds cat-season-r,
// a private remote branch of deployment A's public catalog cat-src, with
// k as a * key and matches in its catalog.trust. A's catalog places
// matches.derby under a root that gives editors reader, so the branch,
// read through, would show derby to li if it decided anything. admin is
// k's grant in every namespace here.
func v82accessRemoteCatalog(t *testing.T, o v75sOpts) (w *v75s, admin string) {
	t.Helper()
	a := newEnv(t, withOrigin(originA))
	a.mkNS("cat-src", map[string]any{})
	a.create("cat-src", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"reader"}, "user:li": []any{"reader"}}})
	a.create("cat-src", "matches.derby", map[string]any{"parents": []any{map[string]any{"href": "/r/cat-season-r/root"}}})
	rt := &route{url: a.srv.URL}
	o.env = append(o.env, withOrigin(originB), withRemote(rt))
	w = newV75s(t, o)
	expect(t, w.mkRemote("cat-season-r", remoteGenesis("cat-src", a.nsHead("cat-src"), map[string]any{"read": "grant",
		"keys": []any{w.k.entry("*"), map[string]any{"kid": "cat-reader", "alg": "ed25519", "pub": w.cat.pub, "can": []any{"read"},
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}},
		"catalog": map[string]any{"trust": []any{"matches"}}})), 201)
	admin = w.grant(w.k, "user:root", []string{"cat-season", "cat-season-r", "matches"},
		[]string{"read", "create", "append", "delete", "restore", "purge", "purge-ns", "config", "branch"})
	// The branch reads its source's placements through.
	expect(t, w.get("/r/cat-season-r/matches.derby", admin), 302)
	return w, admin
}

// v82accessVia is catalog-01's grant for li at cat's head.
func v82accessVia(w *v75s, admin, cat string) string {
	return w.li(map[string]any{"at": map[string]any{"ns": cat, "id": w.nsHead(cat, admin)}})
}

// Conformance 119 at the origin: matches trusts only cat-season-r, a
// remote branch of a catalog. It stays covered: li's unfiltered /heads
// redirects to her filtered URLs, which list no resource rows, her log
// holds only config entries, and her long-poll ends 204 past hidden
// writes. Before v0.82 a remote-branch catalog counted as no catalog:
// matches was uncovered and every one of these was 403.
func TestV082AccessRemoteBranchCatalogDark(t *testing.T) {
	t.Parallel()
	w, admin := v82accessRemoteCatalog(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby", "opener"})
	before := w.nsHead("matches", admin)
	expect(t, w.patchNS("matches", ops(
		op("replace", "/catalogs", map[string]any{"cat-season-r": map[string]any{"place": []any{}}}),
		op("replace", "/keys/1/requireAt", "cat-season-r")), admin), 201)
	w.put("matches", "derby", map[string]any{"title": "derby", "v": 2}, map[string]string{"Gesture": gA})
	li := v82accessVia(w, admin, "cat-season-r")

	head := w.nsHead("matches", admin)
	r := w.get("/ns/matches/rev/"+head+"/heads", li)
	expect(t, r, 302)
	loc := r.H.Get("Location")
	parts := strings.Split(loc, "/")
	if len(parts) != 8 || parts[3] != "g" || parts[5] != "at" {
		t.Fatalf("Location %q", loc)
	}
	gs, at := parts[4], parts[6]
	r = w.get(loc, li)
	expect(t, r, 200)
	if names := headNames(t, r); len(names) != 0 {
		t.Fatalf("li's filtered /heads through a remote-branch catalog: %v, want none", names)
	}
	// The branch is in no checkpoint: no answer is tagged with it.
	if strings.Contains(r.H.Get("Cache-Tag"), "cat-season-r") {
		t.Fatalf("Cache-Tag %q names the dark catalog", r.H.Get("Cache-Tag"))
	}
	r = w.get("/ns/matches/g/"+gs+"/at/"+at+"/log", li)
	expect(t, r, 200)
	entries := r.Arr()
	if len(entries) == 0 {
		t.Fatal("li's filtered log is empty: config entries are always shown")
	}
	for _, x := range entries {
		e := x.(map[string]any)
		switch e["kind"] {
		case "config":
		case "batch":
			for _, it := range e["entries"].([]any) {
				if it.(map[string]any)["kind"] != "config" {
					t.Fatalf("li's filtered log shows %v", e)
				}
			}
		default:
			t.Fatalf("li's filtered log shows %v", e)
		}
	}
	if strings.Contains(r.String(), "derby") || strings.Contains(r.String(), "opener") {
		t.Fatalf("li's filtered log names a resource: %s", r.Body)
	}
	// Long-poll: the writes since before are hidden or config, so only
	// the config entries answer; from the head, hidden writes end 204.
	w.put("matches", "opener", map[string]any{"title": "opener", "v": 2})
	res := w.longPoll("/ns/matches/g/"+gs+"/log?live=long-poll&since="+head, li)
	if newest := w.nsHead("matches", admin); res.code != 204 || res.rev != newest {
		t.Fatalf("long-poll: %d %q %s, want 204 %q", res.code, res.rev, res.body, newest)
	}
	res = w.longPoll("/ns/matches/g/"+gs+"/log?live=long-poll&since="+before, li)
	if res.code != 200 || strings.Contains(string(res.body), "derby") || strings.Contains(string(res.body), "opener") {
		t.Fatalf("long-poll from before the config change: %d %s, want 200 with the config entry alone", res.code, res.body)
	}
	// The gestures listing is filtered by visibility too (§B.11.9
	// Answers): nothing of derby, which her rules alone would let her
	// read, and did before v0.82, while the namespace counted as
	// uncovered.
	r = w.get("/ns/matches/gestures/"+gA, li)
	expect(t, r, 200)
	if strings.Contains(r.String(), "derby") {
		t.Fatalf("li's gestures listing names a hidden resource: %s", r.Body)
	}
	if r := w.get("/ns/matches/gestures/"+gA, admin); !strings.Contains(r.String(), "derby") {
		t.Fatalf("the gestures listing for an unrestricted reader: %d %s", r.Code, r.Body)
	}
	expect(t, w.get("/r/matches/derby", li), 302)
	// Her exchange gives the /g/ prefix, as for any covered namespace.
	if _, cgs := w.cookie(li); cgs != gs {
		t.Fatalf("exchange: gs %s, want %s", cgs, gs)
	}

	// The remote-branch catalog itself is a branch, never covered: its
	// partial reader's /heads is 403 with no redirect, and its filtered
	// URLs 403 (§B.11.9 Where, Purged namespaces).
	cr := w.grant(w.cat, "user:li", []string{"cat-season-r"}, []string{"read"}, map[string]any{"kid": "cat-reader", "groups": []any{"editors"},
		"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	expect(t, w.get("/r/cat-season-r/root", cr), 302)
	r = w.get("/ns/cat-season-r/rev/"+w.nsHead("cat-season-r", admin)+"/heads", cr)
	if r.Code != 403 || r.H.Get("Location") != "" {
		t.Fatalf("the remote-branch catalog's /heads for its partial reader: %d %q, want 403", r.Code, r.H.Get("Location"))
	}
	expect(t, w.get("/ns/cat-season-r/g/"+gs+"/heads", cr), 403)
}

// §B.11.9 Where: with a live catalog and a remote-branch one both
// trusted, only the live one decides. li, through either key, sees what
// cat-season places for her and nothing the branch alone would add, and
// the branch is in no checkpoint.
func TestV082AccessRemoteBranchCatalogBesideLive(t *testing.T) {
	t.Parallel()
	w, admin := v82accessRemoteCatalog(t, v75sOpts{})
	w.seed([]string{"shared"}, nil, []string{"derby", "shared"})
	expect(t, w.patchNS("matches", ops(
		op("add", "/catalogs/cat-season-r", map[string]any{"place": []any{}}),
		op("add", "/keys/-", map[string]any{"kid": "catalog-02", "alg": "ed25519", "pub": w.cat.pub, "can": []any{"read"},
			"requireAt": "cat-season-r", "maxTtl": "PT15M",
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}})), admin), 201)
	for name, li := range map[string]string{
		"through the live catalog's key": v82accessVia(w, admin, "cat-season"),
		"through the remote branch's key": w.grant(w.cat, "user:li", []string{"matches"}, []string{"read"}, map[string]any{"kid": "catalog-02",
			"groups": []any{"editors", "interns"}, "roles": []any{"reader"}, "at": map[string]any{"ns": "cat-season-r", "id": w.nsHead("cat-season-r", admin)},
			"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)}),
	} {
		r := w.get("/ns/matches/rev/"+w.nsHead("matches", admin)+"/heads", li)
		expect(t, r, 302)
		r = w.get(r.H.Get("Location"), li)
		expect(t, r, 200)
		if names := headNames(t, r); len(names) != 1 || names[0] != "shared" {
			t.Errorf("%s: %v, want shared alone (derby is placed only in the remote branch)", name, names)
		}
		if tags := r.H.Get("Cache-Tag"); !strings.Contains(tags, "ns:cat-season") || strings.Contains(tags, "cat-season-r") {
			t.Errorf("%s: Cache-Tag %q, want the live catalog's alone", name, tags)
		}
	}
}
