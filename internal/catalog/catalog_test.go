package catalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/tree"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// world: an authenticated core with a catalog "cat" trusting "matches"
// (§B.11.3), and a running catalog service.
type world struct {
	t        *testing.T
	s        *clienttest.Server
	ops      *client.Client // "*" key on both namespaces
	idp, cat clienttest.Key
	svc      *catalog.Service
	http     *httptest.Server
	cancel   context.CancelFunc
	done     chan struct{}
	db       string

	svcClient *client.Client
}

func toAny(xs ...string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func parents(ps ...string) []any {
	out := []any{}
	for _, p := range ps {
		out = append(out, map[string]any{"href": "/r/cat/" + p})
	}
	return out
}

// noAccessWrites holds when a write doesn't set or change $access: an
// append, delete or restore doesn't write it, and a create's document has
// none.
func noAccessWrites() []any {
	isCreate := map[string]any{"op": "test", "path": "/action", "value": "create"}
	return []any{
		map[string]any{"if": []any{map[string]any{"not": isCreate}},
			"then": []any{map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/$access"}}}},
		map[string]any{"if": []any{isCreate},
			"then": []any{map[string]any{"op": "test", "path": "/doc/$access", "exists": false}}},
	}
}

// live reports whether c can read the resource's head.
func live(c *client.Client, ns, name string) bool {
	h, err := c.Head(context.Background(), ns, name)
	return err == nil && h.State == client.Live
}

func setup(t *testing.T) *world {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	opsKey, idp, catKey := clienttest.NewKey("ops"), clienttest.NewKey("idp"), clienttest.NewKey("catalog-01")
	w := &world{t: t, s: s, idp: idp, cat: catKey}

	catEntry := catKey.Entry("read", "create", "append", "delete")
	catEntry["maxTtl"] = "PT15M"
	catEntry["requireAt"] = true
	catEntry["groups"] = map[string]any{"deny": toAny("catalog-admins", "ops")}
	// §B.11.3's key rule { not: { writes overlaps /$access } } refuses every
	// create (a genesis writes "", which overlaps everything, §6.4.4), so
	// creates are judged by the resulting document instead.
	catEntry["rules"] = noAccessWrites()
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat")))
	must(opc.CreateNamespace(ctx, "cat", map[string]any{
		"read":    "grant",
		"keys":    []any{opsKey.Entry("*"), idp.Entry(), catEntry},
		"maxLag":  "PT60S",
		"catalog": map[string]any{"trust": toAny("matches"), "mode": "dag"},
		"roles": map[string]any{
			"desk": map[string]any{"move": true, "place": true}, "translator": map[string]any{}, "reader": map[string]any{}},
		"rules": []any{map[string]any{
			"if":   []any{map[string]any{"not": map[string]any{"all": noAccessWrites()}}},
			"then": []any{map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "catalog-admins"}}}}}},
	}))
	contentEntry := catKey.Entry("read", "create", "append")
	contentEntry["maxTtl"] = "PT15M"
	contentEntry["readScope"] = "resource"
	contentEntry["requireAt"] = "cat"
	contentEntry["groups"] = map[string]any{"deny": toAny("ops")}
	contentEntry["roles"] = map[string]any{"allow": toAny("desk", "translator", "reader")}
	opm := s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches")))
	must(opm.CreateNamespace(ctx, "matches", map[string]any{
		"read": "grant",
		"keys": []any{opsKey.Entry("*"), idp.Entry(), contentEntry},
		"roles": map[string]any{
			"desk":       map[string]any{"can": toAny("read", "create", "append")},
			"translator": map[string]any{"can": toAny("read", "append"), "rules": []any{map[string]any{"op": "writes", "within": toAny("/i18n")}}},
			"reader":     map[string]any{"can": toAny("read")},
			"deleter":    map[string]any{"can": toAny("delete")}},
		"catalogs": map[string]any{"cat": map[string]any{"place": toAny("group:match-desk", "group:editors-in-chief")}},
	}))
	w.ops = s.Client(t, client.WithBearer(opsKey.Grant(t, s.Now(), "user:ops", []string{"cat", "matches"},
		[]string{"read", "create", "append", "delete", "restore"}, map[string]any{"groups": toAny("catalog-admins")})))
	w.db = filepath.Join(t.TempDir(), "catalog.db")
	w.svcClient = s.Client(t, client.WithBearer(opsKey.Grant(t, s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
		map[string]any{"exp": s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	return w
}

func (w *world) start() {
	w.t.Helper()
	w.done = make(chan struct{})
	svc, err := catalog.Open(context.Background(), catalog.Options{
		Tree: tree.Options{Client: w.svcClient, Catalog: "cat", DB: w.db, Now: w.s.Now, CheckerTTL: time.Millisecond,
			Logf:          func(f string, a ...any) { w.t.Logf(f, a...) },
			FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}},
		Key: w.cat.Priv, Kid: "catalog-01",
	})
	if err != nil {
		w.t.Fatal(err)
	}
	w.svc = svc
	w.http = httptest.NewServer(svc.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go func() { svc.Run(ctx); close(w.done) }()
	w.t.Cleanup(w.stop)
}

func (w *world) stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
	w.http.Close()
	w.svc.Close()
	w.cancel = nil
}

func (w *world) caughtUp() {
	w.t.Helper()
	for _, ns := range []string{"cat", "matches"} {
		waitFor(w.t, "catalog to catch up with "+ns, func() bool {
			h, err := w.ops.NSHead(context.Background(), ns)
			return err == nil && w.svc.Tree().Checkpoint(ns) == h.ID
		})
	}
}

// caller is an identity grant from the identity provider for the catalog
// namespace, with no verbs of its own (§B.11.6: groups come from it).
func (w *world) caller(sub string, groups ...string) string {
	return w.idp.Grant(w.t, w.s.Now(), sub, []string{"cat"}, []string{}, map[string]any{"groups": toAny(groups...)})
}

func (w *world) doc(ns, name string, doc map[string]any) {
	w.t.Helper()
	must(w.ops.CreateDoc(context.Background(), ns, name, doc))
}

func (w *world) patch(ns, name string, ops ...any) {
	w.t.Helper()
	ctx := context.Background()
	h := must(w.ops.Head(ctx, ns, name))
	must(w.ops.Append(ctx, ns, name, h.ID, ops))
}

func acc(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 2 {
		if b, ok := kv[i+1].(bool); ok {
			m[kv[i].(string)] = b
			continue
		}
		m[kv[i].(string)] = toAny(strings.Split(kv[i+1].(string), ",")...)
	}
	return m
}

// seed builds:
//
//	root
//	├── season   $access: match-desk desk, translators translator, fan-club reader, user:li reader
//	│   ├── matches.derby
//	│   ├── matches.shared      (also under derbies)
//	│   └── rumours  $access: inherit false, editors-in-chief desk
//	│       └── matches.rumour1
//	└── derbies  $access: match-desk desk, fan-club desk
//	    ├── matches.shared
//	    └── matches.other       $access (placement): user:guest reader
func (w *world) seed() {
	w.doc("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	w.doc("cat", "season", map[string]any{"title": "Season", "parents": parents("root"),
		"$access": acc("group:match-desk", "desk", "group:translators", "translator", "group:fan-club", "reader", "user:li", "reader")})
	w.doc("cat", "rumours", map[string]any{"title": "Rumours", "parents": parents("season"),
		"$access": acc("inherit", false, "group:editors-in-chief", "desk")})
	w.doc("cat", "derbies", map[string]any{"title": "Derbies", "parents": parents("root"),
		"$access": acc("group:match-desk", "desk", "group:fan-club", "desk")})
	for _, n := range []string{"derby", "shared", "rumour1", "other"} {
		w.doc("matches", n, map[string]any{"title": n})
	}
	w.doc("cat", "matches.derby", map[string]any{"parents": parents("season")})
	w.doc("cat", "matches.shared", map[string]any{"parents": parents("season", "derbies")})
	w.doc("cat", "matches.rumour1", map[string]any{"parents": parents("rumours")})
	w.doc("cat", "matches.other", map[string]any{"parents": parents("derbies"), "$access": acc("user:guest", "reader")})
}

type resp struct {
	status int
	header http.Header
	body   map[string]any
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (w *world) do(method, path, token string, body any) resp {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(must(json.Marshal(body)))
	}
	req := must(http.NewRequest(method, w.http.URL+path, rd))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r := must(noRedirect.Do(req))
	defer r.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(must(io.ReadAll(r.Body)), &m)
	return resp{r.StatusCode, r.Header, m}
}

// issue requests a grant and returns it (or fails unless status matches).
func (w *world) issue(token string, req map[string]any, status int) resp {
	w.t.Helper()
	r := w.do("POST", "/grants", token, req)
	if r.status != status {
		w.t.Fatalf("POST /grants %v: %d %v (want %d)", req, r.status, r.body, status)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		w.t.Errorf("grants Cache-Control %q", r.header.Get("Cache-Control"))
	}
	return r
}

func (w *world) grantFor(token string, req map[string]any) string {
	w.t.Helper()
	return w.issue(token, req, 200).body["grant"].(string)
}

func (w *world) core(token string) *client.Client { return w.s.Client(w.t, client.WithBearer(token)) }

func isStatus(err error, status int) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == status
}

func TestEffectiveAccessAndContentGrants(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()

	anna := w.caller("user:anna", "translators")
	r := w.issue(anna, map[string]any{"item": "/r/matches/derby", "want": toAny("read", "append")}, 200)
	b := r.body
	cp := w.svc.Tree().Checkpoint("cat")
	if fmt.Sprint(b["roles"]) != "[translator]" || fmt.Sprint(b["can"]) != "[read append]" || b["ns"] != "matches" ||
		b["resource"] != "derby" || fmt.Sprint(b["at"]) != fmt.Sprintf("map[id:%s ns:cat]", cp) {
		t.Fatalf("issued %v", b)
	}
	exp := must(time.Parse(time.RFC3339, b["exp"].(string)))
	if d := exp.Sub(w.s.Now()); d > 15*time.Minute || d < 14*time.Minute {
		t.Errorf("lifetime %s", d)
	}
	// The grant works against the core: read, append within /i18n (the
	// translator role's rule, applied by the gate), nothing else.
	ac := w.core(b["grant"].(string))
	h, d, err := ac.Load(ctx, "matches", "derby")
	if err != nil || d.Value.(map[string]any)["title"] != "derby" {
		t.Fatalf("read with issued grant: %v", err)
	}
	if _, err := ac.Append(ctx, "matches", "derby", h.ID, []any{map[string]any{"op": "add", "path": "/i18n", "value": map[string]any{"sv": "derbyt"}}}); err != nil {
		t.Errorf("translator append: %v", err)
	}
	h = must(ac.Head(ctx, "matches", "derby"))
	if _, err := ac.Append(ctx, "matches", "derby", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "x"}}); !isStatus(err, 403) {
		t.Errorf("translator writing /title: %v", err)
	}
	if live(ac, "matches", "shared") {
		t.Error("the grant reads another resource")
	}

	// inherit: false stops the walk.
	w.issue(anna, map[string]any{"item": "/r/matches/rumour1", "want": toAny("read")}, 403)
	eic := w.caller("user:eve", "editors-in-chief")
	if b := w.issue(eic, map[string]any{"item": "/r/matches/rumour1", "want": toAny("append")}, 200).body; fmt.Sprint(b["roles"]) != "[desk]" {
		t.Errorf("eic roles %v", b["roles"])
	}
	// A user entry: li reads, but may not append.
	li := w.caller("user:li")
	if b := w.issue(li, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200).body; fmt.Sprint(b["roles"]) != "[reader]" {
		t.Errorf("li roles %v", b["roles"])
	}
	w.issue(li, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}, 403)
	// Union over the DAG: fan-club is reader under season and desk under derbies.
	fan := w.caller("user:fred", "fan-club")
	if b := w.issue(fan, map[string]any{"item": "/r/matches/shared", "want": toAny("read", "append")}, 200).body; fmt.Sprint(b["roles"]) != "[desk reader]" || fmt.Sprint(b["can"]) != "[read append]" {
		t.Errorf("fan on shared: %v", b)
	}
	w.issue(fan, map[string]any{"item": "/r/matches/derby", "want": toAny("append")}, 403)
	// A placement's own $access shares one item.
	guest := w.caller("user:guest")
	w.issue(guest, map[string]any{"item": "/r/matches/other", "want": toAny("read")}, 200)
	w.issue(guest, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 403)
	// Roles the content namespace defines only with other verbs are dropped;
	// verbs no role lists are refused.
	w.issue(anna, map[string]any{"item": "/r/matches/derby", "want": toAny("delete")}, 403)
	// Unauthenticated and foreign grants.
	w.issue("", map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 401)
	w.issue(clienttest.NewKey("idp").Grant(t, w.s.Now(), "user:anna", []string{"cat"}, []string{}), map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 401)

	// The effective table (§B.11.7) reflects it.
	var n int
	must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective WHERE node = '/r/cat/matches.shared' AND subject = 'group:fan-club'`).Scan(&n))
	if n != 2 {
		t.Errorf("effective rows for fan-club on shared: %d", n)
	}

	// Changing $access (an admin, since the catalog key can't) recomputes the subtree.
	w.patch("cat", "season", map[string]any{"op": "remove", "path": "/$access/group:translators"})
	w.caughtUp()
	w.issue(anna, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 403)
	// Deleting a folder only narrows: rumours' items lose nothing they had from above, derby loses season's.
	w.patch("cat", "rumours", map[string]any{"op": "replace", "path": "/$access/inherit", "value": true})
	w.caughtUp()
	w.issue(fan, map[string]any{"item": "/r/matches/rumour1", "want": toAny("read")}, 200)
	hs := must(w.ops.Head(ctx, "cat", "season"))
	must(w.ops.Delete(ctx, "cat", "season", hs.ID))
	w.caughtUp()
	w.issue(fan, map[string]any{"item": "/r/matches/rumour1", "want": toAny("read")}, 403)
	w.issue(li, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 403)
	// Deleted content: the placement dangles and grants nothing.
	ho := must(w.ops.Head(ctx, "matches", "other"))
	must(w.ops.Delete(ctx, "matches", "other", ho.ID))
	w.caughtUp()
	w.issue(guest, map[string]any{"item": "/r/matches/other", "want": toAny("read")}, 403)
}

func TestGrantStalenessAndExpiry(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	anna := w.caller("user:anna", "translators")
	g := w.grantFor(anna, map[string]any{"item": "/r/matches/derby", "want": toAny("read")})
	ac := w.core(g)
	if _, _, err := ac.Load(ctx, "matches", "derby"); err != nil {
		t.Fatal(err)
	}
	// While at is the catalog head, the grant stays valid (until exp).
	w.s.Clock.Advance(5 * time.Minute)
	if _, _, err := ac.Load(ctx, "matches", "derby"); err != nil {
		t.Fatalf("after 5 minutes: %v", err)
	}
	// A catalog write makes at older; after maxLag (60s) the core refuses it.
	w.doc("cat", "later", map[string]any{"parents": parents("root")})
	w.s.Clock.Advance(30 * time.Second)
	if _, _, err := ac.Load(ctx, "matches", "derby"); err != nil {
		t.Fatalf("within maxLag: %v", err)
	}
	w.s.Clock.Advance(31 * time.Second)
	if live(ac, "matches", "derby") {
		t.Fatal("the grant still reads beyond maxLag")
	}
	// A fresh grant from the new checkpoint works, and expires after 15 minutes.
	w.caughtUp()
	g = w.grantFor(w.caller("user:anna", "translators"), map[string]any{"item": "/r/matches/derby", "want": toAny("read")})
	ac = w.core(g)
	if _, _, err := ac.Load(ctx, "matches", "derby"); err != nil {
		t.Fatalf("fresh grant: %v", err)
	}
	w.s.Clock.Advance(15*time.Minute + time.Second)
	if live(ac, "matches", "derby") {
		t.Fatal("the grant still reads after exp")
	}
}

func TestIssueRefusesWhenBehind(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	w.stop()
	// Restart without running followers: the service's checkpoint stays behind.
	svc := must(catalog.Open(context.Background(), catalog.Options{
		Tree: tree.Options{Client: w.svcClient, Catalog: "cat", DB: w.db, Now: w.s.Now, CheckerTTL: time.Millisecond,
			Logf: func(f string, a ...any) { t.Logf(f, a...) }},
		Key: w.cat.Priv, Kid: "catalog-01",
	}))
	defer svc.Close()
	w.doc("cat", "later", map[string]any{"parents": parents("root")})
	w.s.Clock.Advance(61 * time.Second)
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	body := must(json.Marshal(map[string]any{"item": "/r/matches/derby", "want": toAny("read")}))
	req := must(http.NewRequest("POST", srv.URL+"/grants", bytes.NewReader(body)))
	req.Header.Set("Authorization", "Bearer "+w.caller("user:anna", "translators"))
	r := must(http.DefaultClient.Do(req))
	r.Body.Close()
	if r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Errorf("issuing while behind: %d", r.StatusCode)
	}
}

func TestPlaceMoveUnplace(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	anna := w.caller("user:anna", "translators")

	// Place: in the content namespace's place list, and place on the folder.
	w.doc("matches", "newone", map[string]any{"title": "new"})
	w.issue(anna, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("season")}, 403)
	w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("rumours")}, 403)
	w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("matches.derby")}, 422)
	w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("place"), "to": toAny("season")}, 409)
	g := w.grantFor(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("place"), "to": toAny("/r/cat/season")})
	bc := w.core(g)
	// The grant fixes /resource and /doc/parents.
	if _, err := bc.CreateDoc(ctx, "cat", "matches.newone", map[string]any{"parents": parents("derbies")}); !isStatus(err, 403) {
		t.Errorf("place with other parents: %v", err)
	}
	if _, err := bc.CreateDoc(ctx, "cat", "matches.x", map[string]any{"parents": parents("season")}); !isStatus(err, 403) {
		t.Errorf("place another node: %v", err)
	}
	if _, err := bc.CreateDoc(ctx, "cat", "matches.newone", map[string]any{"parents": parents("season"), "$access": acc("user:bob", "desk")}); !isStatus(err, 403) && !isStatus(err, 422) {
		t.Errorf("place with $access: %v", err)
	}
	if _, err := bc.CreateDoc(ctx, "cat", "matches.newone", map[string]any{"parents": []any{map[string]any{"href": "/r/cat/season", "order": "a5"}}}); err != nil {
		t.Fatalf("place: %v", err)
	}
	w.caughtUp()
	w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("append")}, 200)

	// Move: move on every parent left and every target; no widening.
	w.doc("cat", "deskonly", map[string]any{"title": "Desk only", "parents": parents("root"), "$access": acc("group:match-desk", "desk")})
	w.caughtUp()
	w.issue(bob, map[string]any{"node": "matches.newone", "want": toAny("move"), "to": toAny("rumours")}, 403) // no move on rumours
	w.issue(anna, map[string]any{"node": "matches.newone", "want": toAny("move"), "to": toAny("deskonly")}, 403)
	// season -> deskonly narrows everyone (only match-desk keeps desk).
	g = w.grantFor(bob, map[string]any{"node": "matches.newone", "want": toAny("move"), "to": toAny("deskonly")})
	h := must(w.ops.Head(ctx, "cat", "matches.newone"))
	must(w.core(g).Append(ctx, "cat", "matches.newone", h.ID, []any{map[string]any{"op": "replace", "path": "/parents", "value": parents("deskonly")}}))
	w.caughtUp()
	w.issue(anna, map[string]any{"item": "/r/matches/newone", "want": toAny("read")}, 403)
	// derbies gives fan-club desk: widening, refused.
	r := w.issue(bob, map[string]any{"node": "matches.newone", "want": toAny("move"), "to": toAny("derbies")}, 403)
	if !strings.Contains(r.body["message"].(string), "group:fan-club") {
		t.Errorf("widening message: %v", r.body)
	}
	// Moving back into season widens too (role names are compared as sets).
	w.issue(bob, map[string]any{"node": "matches.newone", "want": toAny("move"), "to": toAny("season")}, 403)
	// A catalog admin may widen.
	admin := w.caller("user:ada", "catalog-admins", "match-desk")
	g = w.grantFor(admin, map[string]any{"node": "matches.newone", "want": toAny("move"), "to": toAny("derbies")})
	ac := w.core(g)
	h = must(w.ops.Head(ctx, "cat", "matches.newone"))
	if _, err := ac.Append(ctx, "cat", "matches.newone", h.ID, []any{map[string]any{"op": "replace", "path": "/parents", "value": parents("season")}}); !isStatus(err, 403) {
		t.Errorf("move to another target: %v", err)
	}
	if _, err := ac.Append(ctx, "cat", "matches.newone", h.ID, []any{
		map[string]any{"op": "replace", "path": "/parents", "value": parents("derbies")},
		map[string]any{"op": "add", "path": "/title", "value": "x"}}); !isStatus(err, 403) {
		t.Errorf("move writing outside /parents: %v", err)
	}
	if _, err := ac.Append(ctx, "cat", "matches.newone", h.ID, []any{map[string]any{"op": "replace", "path": "/parents", "value": parents("derbies")}}); err != nil {
		t.Fatalf("move: %v", err)
	}
	w.caughtUp()
	w.issue(w.caller("user:fred", "fan-club"), map[string]any{"item": "/r/matches/newone", "want": toAny("append")}, 200)
	// A folder can't move under its own descendant.
	w.issue(admin, map[string]any{"node": "season", "want": toAny("move"), "to": toAny("rumours")}, 409)

	// Unplace: move on every current parent.
	w.issue(anna, map[string]any{"node": "matches.newone", "want": toAny("delete")}, 403)
	w.issue(bob, map[string]any{"node": "season", "want": toAny("delete")}, 422)
	g = w.grantFor(bob, map[string]any{"node": "/r/cat/matches.newone", "want": toAny("delete")})
	h = must(w.ops.Head(ctx, "cat", "matches.newone"))
	if _, err := w.core(g).Delete(ctx, "cat", "matches.derby", must(w.ops.Head(ctx, "cat", "matches.derby")).ID); !isStatus(err, 403) {
		t.Errorf("unplace grant deleting another node: %v", err)
	}
	must(w.core(g).Delete(ctx, "cat", "matches.newone", h.ID))
	w.caughtUp()
	w.issue(bob, map[string]any{"item": "/r/matches/newone", "want": toAny("read")}, 403)
	if _, _, err := w.ops.Load(ctx, "matches", "newone"); err != nil {
		t.Errorf("content after unplace: %v", err)
	}
}

func TestCreateFlow(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	bob := w.caller("user:bob", "match-desk")
	anna := w.caller("user:anna", "translators")

	// A name that exists or existed is refused.
	w.issue(bob, map[string]any{"item": "/r/matches/derby", "want": toAny("create")}, 409)
	// Unplaced names get nothing.
	w.issue(bob, map[string]any{"item": "/r/matches/final", "want": toAny("create")}, 403)

	// 1. Place the new item: the placement dangles.
	g := w.grantFor(bob, map[string]any{"item": "/r/matches/final", "want": toAny("place"), "to": toAny("season")})
	must(w.core(g).CreateDoc(ctx, "cat", "matches.final", map[string]any{"parents": parents("season")}))
	w.caughtUp()
	// A dangling placement grants nothing but create.
	w.issue(bob, map[string]any{"item": "/r/matches/final", "want": toAny("read")}, 403)
	w.issue(bob, map[string]any{"item": "/r/matches/final", "want": toAny("create", "append")}, 400)
	// Roles without create (translator) get nothing.
	w.issue(anna, map[string]any{"item": "/r/matches/final", "want": toAny("create")}, 403)

	// 2. A create grant fixed to the name, usable for the genesis only.
	b := w.issue(bob, map[string]any{"item": "/r/matches/final", "want": toAny("create")}, 200).body
	if fmt.Sprint(b["can"]) != "[create]" || fmt.Sprint(b["roles"]) != "[desk]" {
		t.Errorf("create grant %v", b)
	}
	cc := w.core(b["grant"].(string))
	if _, err := cc.CreateDoc(ctx, "matches", "other-name", map[string]any{"title": "x"}); !isStatus(err, 403) {
		t.Errorf("create grant on another name: %v", err)
	}
	res, err := cc.CreateDoc(ctx, "matches", "final", map[string]any{"title": "Final"})
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	if _, err := cc.Append(ctx, "matches", "final", res.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "y"}}); !isStatus(err, 403) {
		t.Errorf("create grant appending: %v", err)
	}
	// A second genesis can't overwrite (If-None-Match: * fails).
	if _, err := cc.CreateDoc(ctx, "matches", "final", map[string]any{"title": "Other"}); !isStatus(err, 412) {
		t.Errorf("second genesis: %v", err)
	}
	w.caughtUp()
	w.issue(bob, map[string]any{"item": "/r/matches/final", "want": toAny("create")}, 409)
	// Later edits use ordinary append grants.
	g = w.grantFor(bob, map[string]any{"item": "/r/matches/final", "want": toAny("append")})
	must(w.core(g).Append(ctx, "matches", "final", res.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Final!"}}))

	// A placed item that was deleted can't be re-created through a create grant.
	w.doc("cat", "matches.gone", map[string]any{"parents": parents("season")})
	w.doc("matches", "gone", map[string]any{})
	hg := must(w.ops.Head(ctx, "matches", "gone"))
	must(w.ops.Delete(ctx, "matches", "gone", hg.ID))
	w.caughtUp()
	w.issue(bob, map[string]any{"item": "/r/matches/gone", "want": toAny("create")}, 409)
}

func TestPrivateListingsAndReadGrants(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()

	// get follows the pointer into the reader's subject-set URL space.
	get := func(path, token string) (map[string]any, string) {
		t.Helper()
		r := w.do("GET", path, token, nil)
		if r.status != 302 {
			t.Fatalf("GET %s: %d %v", path, r.status, r.body)
		}
		loc := r.header.Get("Location")
		r = w.do("GET", loc, token, nil)
		if r.status != 200 {
			t.Fatalf("GET %s: %d %v", loc, r.status, r.body)
		}
		if r.header.Get("Cache-Control") != "private, max-age=5" || r.header.Get("CDN-Cache-Control") == "" {
			t.Errorf("listing cache headers %v", r.header)
		}
		return r.body, loc
	}
	names := func(v any) string {
		var out []string
		for _, x := range v.([]any) {
			out = append(out, x.(map[string]any)["name"].(string))
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if r := w.do("GET", "/cat/children?of=season", "", nil); r.status != 401 {
		t.Errorf("anonymous: %d", r.status)
	}

	fan := w.caller("user:fred", "fan-club")
	b, loc := get("/cat/children?of=season", fan)
	cp := w.svc.Tree().Checkpoint("cat")
	if !strings.HasPrefix(loc, "/cat/at/"+cp+"/g/") {
		t.Errorf("listing url %s", loc)
	}
	// fan-club (reader) sees season's items but not the embargoed folder.
	if got := names(b["children"]); got != "matches.derby,matches.shared" {
		t.Errorf("fan sees %s", got)
	}
	for _, c := range b["children"].([]any) {
		if c.(map[string]any)["head"] == nil {
			t.Errorf("reader sees no head: %v", c)
		}
	}
	// Another member of the same groups shares the listing URL.
	_, loc2 := get("/cat/children?of=season", w.caller("user:fiona", "fan-club"))
	if loc2 != loc {
		t.Errorf("same groups, different listing: %s vs %s", loc2, loc)
	}
	// A user with direct entries gets their own subject set.
	li := w.caller("user:li", "fan-club")
	_, locLi := get("/cat/children?of=season", li)
	if locLi == loc {
		t.Error("a user with direct entries shares the group listing")
	}
	// Presenting someone else's gs redirects to one's own.
	if r := w.do("GET", locLi, fan, nil); r.status != 302 || r.header.Get("Location") != loc {
		t.Errorf("foreign gs: %d %s", r.status, r.header.Get("Location"))
	}
	// The embargoed folder: invisible to fan-club, visible to editors-in-chief.
	if r := w.do("GET", strings.Replace(loc, "children?of=season", "children?of=rumours", 1), fan, nil); r.status != 404 {
		t.Errorf("fan on rumours: %d", r.status)
	}
	eic := w.caller("user:eve", "editors-in-chief")
	b, _ = get("/cat/children?of=rumours", eic)
	if names(b["children"]) != "matches.rumour1" {
		t.Errorf("eic on rumours: %v", b)
	}
	// Roots: a folder is listed only for readers with some role there.
	b, _ = get("/cat/roots", fan)
	if names(b["roots"]) != "" {
		t.Errorf("fan roots: %v", b)
	}
	b, _ = get("/cat/where?item=/r/matches/other", w.caller("user:guest"))
	if b["placement"] == nil {
		t.Errorf("guest where: %v", b)
	}
	// Paths through folders the guest may not see are left out.
	if len(b["paths"].([]any)) != 0 || b["hidden"] != 1.0 {
		t.Errorf("guest paths: %v", b)
	}

	// Read grants: one per item, fixed to it, no-store.
	r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby", "/r/matches/rumour1", "/r/matches/nope")})
	if r.status != 200 || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("read-grants: %d %v", r.status, r.header)
	}
	gs := r.body["grants"].([]any)
	g0, g1, g2 := gs[0].(map[string]any), gs[1].(map[string]any), gs[2].(map[string]any)
	if g0["grant"] == nil || g1["error"].(map[string]any)["status"] != 403.0 || g2["error"] == nil {
		t.Fatalf("read-grants: %v", gs)
	}
	rc := w.core(g0["grant"].(string))
	if _, _, err := rc.Load(ctx, "matches", "derby"); err != nil {
		t.Errorf("read grant: %v", err)
	}
	if live(rc, "matches", "shared") {
		t.Error("read grant reads another item")
	}
	h := must(rc.Head(ctx, "matches", "derby"))
	if _, err := rc.Append(ctx, "matches", "derby", h.ID, []any{map[string]any{"op": "add", "path": "/x", "value": 1}}); !isStatus(err, 403) {
		t.Errorf("read grant appends: %v", err)
	}
}

func TestRestartKeepsEffective(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	var before int
	must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective`).Scan(&before))
	w.stop()
	w.start()
	w.caughtUp()
	var after int
	must(0, w.svc.Tree().DB().QueryRow(`SELECT count(*) FROM effective`).Scan(&after))
	if before == 0 || before != after {
		t.Errorf("effective rows %d then %d", before, after)
	}
	w.issue(w.caller("user:anna", "translators"), map[string]any{"item": "/r/matches/derby", "want": toAny("read")}, 200)
}
