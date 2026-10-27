package catalog_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/tree"
)

// A trusted content namespace that is purged leaves the catalog's grants
// working, sealed or not (§8.5): once a sealed one is purged its namespace
// documents are 410 purged, so the service reads no includes or keys from
// it any more. Its roles are gone with it, so it shows a non-admin no
// node (§B.11.5), whose organising requests are 404; an admin's move is
// decided as before. A restore of its item is 410 as for any purged item,
// and other grants on its items are 410 too.
func TestSealedContentPurged(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.seed()
			w.doc("cat", "deskonly", map[string]any{"title": "Desk only", "parents": parents("root"), "$access": acc("group:match-desk", "desk")})
			w.start()
			w.caughtUp()
			ctx := context.Background()

			var copts []client.Option
			if sealed {
				copts = append(copts, client.WithKeys(client.NewKeys(nil)))
			}
			pc := w.s.Client(t, append(copts, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"read", "config", "purge-ns"})))...)
			must(pc.PatchConfig(ctx, "matches", must(pc.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
			head := must(pc.PurgeNamespace(ctx, "matches", must(pc.NSHead(ctx, "matches")).ID))
			if _, err := pc.NSDoc(ctx, "matches", head); client.IsPurged(err) != sealed {
				t.Fatalf("the purged namespace's document: %v", err)
			}
			waitFor(t, "the purge", func() bool { return w.svc.Tree().Checkpoint("matches") == head })

			bob, admin := w.caller("user:bob", "match-desk"), w.caller("user:ada", "catalog-admins")
			w.issue(bob, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("deskonly")}, 404)
			w.issue(admin, map[string]any{"node": "rumours", "want": toAny("move"), "to": toAny("deskonly")}, 200)
			w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("restore")}, 410)
			if sealed {
				w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}, 410)
				w.issue(bob, map[string]any{"item": "/r/matches/fresh", "want": toAny("place"), "to": toAny("season")}, 404)
				w.issue(admin, map[string]any{"item": "/r/matches/fresh", "want": toAny("place"), "to": toAny("season")}, 410)
			}
		})
	}
}

// purge freezes and purges ns as the ops key, and waits until the service
// has taken the purge.
func (w *world) purge(ns string) string {
	w.t.Helper()
	ctx := context.Background()
	var copts []client.Option
	if w.sealed {
		copts = append(copts, client.WithKeys(client.NewKeys(nil)))
	}
	pc := w.s.Client(w.t, append(copts, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{ns}, []string{"read", "config", "purge-ns"})))...)
	must(pc.PatchConfig(ctx, ns, must(pc.NSHead(ctx, ns)).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	head := must(pc.PurgeNamespace(ctx, ns, must(pc.NSHead(ctx, ns)).ID))
	waitFor(w.t, "the purge of "+ns, func() bool { return w.svc.Tree().Checkpoint(ns) == head })
	return head
}

// TestPurgedCatalogEdgeGrants (§8.5, §B.11.5): once the catalog is purged,
// sealed or not, POST /edge-grants answers 410 purged with head after the
// read check, as its listings do; for a sealed one the core makes that
// check (its documents are 410). A read under a cookie minted before the
// purge is 410 purged too, never sent to the core as an anonymous read:
// with head under a g/all cookie, whose exchange read the catalog, and
// without under a subject set's, which a grant without read on the
// catalog may have got (RoleView), as the core shows a purged catalog's
// head only to its readers.
func TestPurgedCatalogEdgeGrants(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
			w.seed()
			w.start()
			w.caughtUp()
			full := w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches"}, []string{"read"})
			bob := w.caller("user:bob", "match-desk")
			byName := map[string]*http.Cookie{}
			for name, tok := range map[string]string{"all": full, "bob": bob} {
				r, cks := w.exchange(tok, nil, "")
				if r.status != 200 || len(cks) != 1 {
					t.Fatalf("%s before the purge: %d %v", name, r.status, r.body)
				}
				byName[name] = cks[0]
				byName[name+" prefix"] = &http.Cookie{Name: prefixes(r)}
			}
			head := w.purge("cat")

			if r, cks := w.exchange(full, nil, ""); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != head || len(cks) != 0 ||
				r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("exchange after the purge: %d %v %v", r.status, r.body, r.header)
			}
			// The read check comes first.
			if r, _ := w.exchange("", nil, ""); r.status != 401 {
				t.Errorf("no grant: %d %v", r.status, r.body)
			}
			other := w.opsKey.Grant(t, w.s.Now(), "user:o", []string{"matches"}, []string{"read"})
			if r, _ := w.exchange(other, nil, ""); r.status != 403 {
				t.Errorf("a grant for matches only: %d %v", r.status, r.body)
			}
			if byName["all prefix"].Name != "/cat/g/all" || byName["bob prefix"].Name == "/cat/g/all" {
				t.Fatalf("prefixes: all %s, bob %s", byName["all prefix"].Name, byName["bob prefix"].Name)
			}
			for name, want := range map[string]any{"all": head, "bob": nil} {
				path := byName[name+" prefix"].Name + "/at/" + head + "/roots"
				if r := w.withCookie(path, byName[name], nil); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != want ||
					r.header.Get("WWW-Authenticate") != "" || r.header.Get("Cache-Control") != "no-store" {
					t.Errorf("%s: a cookie from before the purge: %d %v %v", name, r.status, r.body, r.header)
				}
			}
			// bob's subject set has no read on the catalog: a grant of its
			// own, as a bearer, gets no head from the core either.
			if r := w.do("GET", "/cat/roots", bob, nil); sealed && r.status != 403 {
				t.Errorf("bob as a bearer: %d %v", r.status, r.body)
			}
		})
	}
}

// TestPurgedContentKeepsAll (§8.5, §B.11.5): a purged trusted content
// namespace has no live items, so every reader reads it whole, sealed or
// not (its documents are 410 once a sealed one is purged): a reader of the
// catalog and every other trusted namespace keeps the unfiltered g/all
// listings and edge grants, and so does a reader that never read it. With
// edge grants, only once an edge's g/all listings from before the purge,
// which show its last items to every g/all cookie, have surely expired:
// until a g/all listing's edge lifetime has passed since the service
// applied the purge, which a restart keeps, each reader's grant is
// checked as before, and a sealed one is read whole by nobody. A purge
// recorded by an earlier release, without a time, counts as applied when
// the service starts.
func TestPurgedContentKeepsAll(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
			w.seed()
			w.start()
			w.caughtUp()
			grants := func() map[string]string {
				return map[string]string{
					"full":         w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches"}, []string{"read"}),
					"catalog only": w.opsKey.Grant(t, w.s.Now(), "user:c", []string{"cat"}, []string{"read"}),
				}
			}
			isAll := func(tok string) bool {
				r := w.do("GET", "/cat/roots", tok, nil)
				if r.status != 302 {
					t.Fatalf("roots: %d %v", r.status, r.body)
				}
				return strings.HasPrefix(r.header.Get("Location"), "/cat/g/all/")
			}
			// within checks who gets g/all while the edge may still hold
			// listings from before the purge.
			within := func(when string) {
				t.Helper()
				for name, tok := range grants() {
					want := name == "full" && !sealed
					if got := isAll(tok); got != want {
						t.Errorf("%s: %s: g/all %v, want %v", when, name, got, want)
					}
					if r, cks := w.exchange(tok, nil, ""); r.status != 200 || (prefixes(r) == "/cat/g/all") != want || len(cks) != 1 {
						t.Errorf("%s: %s: exchange: %d %v", when, name, r.status, r.body)
					}
				}
			}
			for name, tok := range grants() {
				if got := isAll(tok); got != (name == "full") {
					t.Fatalf("%s before the purge: g/all %v", name, got)
				}
			}
			w.purge("matches")
			// The engine's clock stands still: a cookie issued at the very
			// instant the service came to trust a namespace counts as
			// issued before it.
			w.s.Clock.Advance(time.Second)
			within("right after the purge")
			// The time of the purge survives a restart.
			w.s.Clock.Advance(10 * time.Minute)
			w.stop()
			w.start()
			within("10 minutes on, restarted")
			// A g/all listing lives 16 minutes at an edge.
			w.s.Clock.Advance(6 * time.Minute)
			for name, tok := range grants() {
				if !isAll(tok) {
					t.Errorf("%s 16 minutes after the purge: no g/all", name)
					continue
				}
				if r, _ := w.follow("/cat/problems", tok); r.status != 200 {
					t.Errorf("%s: problems after the purge: %d %v", name, r.status, r.body)
				}
				r, cks := w.exchange(tok, nil, "")
				if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
					t.Errorf("%s: exchange after the purge: %d %v", name, r.status, r.body)
					continue
				}
				_, loc := w.follow("/cat/roots", tok)
				if r := w.withCookie(loc, cks[0], nil); r.status != 200 {
					t.Errorf("%s: g/all under the cookie: %d %v", name, r.status, r.body)
				}
			}

			// A purge recorded without a time, by an earlier release.
			w.stop()
			db, err := sql.Open("sqlite", sqlitedsn.DSN(w.db, ""))
			if err != nil {
				t.Fatal(err)
			}
			if res, err := db.Exec(`UPDATE meta SET v = '1' WHERE k = 'purged:matches'`); err != nil || must(res.RowsAffected()) != 1 {
				t.Fatalf("recording the purge as an earlier release: %v", err)
			}
			db.Close()
			w.start()
			within("restarted on a purge without a time")
			w.s.Clock.Advance(16*time.Minute + time.Second)
			for name, tok := range grants() {
				if !isAll(tok) {
					t.Errorf("%s 16 minutes after the restart: no g/all", name)
				}
			}
		})
	}
}

// TestPurgedContentLateStart (§8.5, §B.11.4): a service that starts after
// a trusted content namespace was purged, sealed or not, holds rows for
// some of its items at most: a sealed one's log is 410 purged, and an
// at-rest one's replay drops what comes before the purge-ns entry in its
// batch. It answers as one that followed the purge, and so after a
// restart: a restore of an item of the namespace is 410, deleted or live
// when it was purged, and so is one of a name the service never saw,
// placed or not, since every name of a purged namespace is 410 at the
// core. Other grants and read grants on them are refused as before, and
// their placements dangle as purged, not missing. A name that never
// existed in a trusted namespace that isn't purged is still 404, on every
// one of them.
func TestPurgedContentLateStart(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprint("sealed=", sealed), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, sealed)
			w.seed()
			w.doc("cat", "matches.final", map[string]any{"parents": parents("season")})
			ctx := context.Background()
			var copts []client.Option
			if sealed {
				copts = append(copts, client.WithKeys(client.NewKeys(nil)))
			}
			// teams, a second trusted namespace, is never purged.
			op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
			must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
			opc := w.s.Client(t, append(copts, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"read", "config"})))...)
			must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
			w.svcClient = w.s.Client(t, append(copts, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
				map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))...)
			caughtUp := func() {
				t.Helper()
				w.caughtUp()
				waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
			}
			w.start()
			caughtUp()
			must(w.ops.Delete(ctx, "matches", "derby", must(w.ops.Head(ctx, "matches", "derby")).ID))
			w.caughtUp()
			bob := w.caller("user:bob", "match-desk")
			restore := func(item string) map[string]any {
				return map[string]any{"item": "/r/matches/" + item, "want": toAny("restore")}
			}
			w.issue(bob, restore("ghost"), 404)
			w.issue(bob, restore("derby"), 200)
			w.purge("matches")

			full := w.opsKey.Grant(t, w.s.Now(), "user:r", []string{"cat", "matches", "teams"}, []string{"read"})
			// answers are the service's decisions on the purged
			// namespace's items: restores of a deleted item, a live one,
			// a placed name that never existed and an unplaced one; and
			// on a name that never existed in teams, which isn't purged.
			answers := func(name string) map[string]string {
				t.Helper()
				out := map[string]string{}
				r := w.issue(bob, map[string]any{"item": "/r/teams/ghost", "want": toAny("restore")}, 404)
				out["restore teams ghost"] = fmt.Sprint(r.body["code"], r.body["message"], r.body["checkpoint"])
				for _, it := range []string{"derby", "shared", "final", "ghost"} {
					r := w.issue(bob, restore(it), 410)
					out["restore "+it] = fmt.Sprint(r.body["code"], r.body["message"], r.body["checkpoint"])
				}
				for _, req := range []map[string]any{
					{"item": "/r/matches/shared", "want": toAny("append")},
					{"item": "/r/matches/final", "want": toAny("create")},
				} {
					r := w.do("POST", "/grants", bob, req)
					out[fmt.Sprint(req["want"], req["item"])] = fmt.Sprint(r.status, r.body)
				}
				r = w.do("POST", "/read-grants", bob, map[string]any{"items": toAny("/r/matches/derby", "/r/matches/shared", "/r/matches/ghost")})
				out["read-grants"] = fmt.Sprint(r.status, r.body)
				if !sealed {
					// A sealed catalog's listings are sealed.
					r, _ := w.follow("/cat/problems", full)
					out["problems"] = fmt.Sprint(r.status, r.body)
				}
				w.svc.Tree().View(func(g *tree.Graph, _ map[string]string) {
					for _, it := range []string{"derby", "shared", "rumour1", "other", "final"} {
						if n := g.Node("matches." + it); n == nil || n.Dangling != "purged" {
							t.Errorf("%s: the placement of %s: %+v", name, it, n)
						}
					}
				})
				return out
			}
			want := answers("following")
			w.stop()
			w.db = filepath.Join(t.TempDir(), "late.db")
			w.start()
			caughtUp()
			if got := answers("started after"); !reflect.DeepEqual(got, want) {
				t.Errorf("started after the purge:\n%v\nwant\n%v", got, want)
			}
			w.stop()
			w.start()
			caughtUp()
			if got := answers("started after, restarted"); !reflect.DeepEqual(got, want) {
				t.Errorf("started after the purge, restarted:\n%v\nwant\n%v", got, want)
			}
		})
	}
}
