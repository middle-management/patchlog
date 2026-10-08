package index_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
)

func TestPrivateNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create", "append"})))
	sch := must(writer.CreateDoc(ctx, "sec", "schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	ref := "/r/sec/schema/rev/" + sch.ID
	for _, n := range []string{"a", "b", "c"} {
		must(writer.CreateDoc(ctx, "sec", n, map[string]any{"$schema": ref, "title": "secret " + n}))
	}

	// The indexer reads with its own least-privilege grant (§C.6).
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})))
	x := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now})
	x.caughtUp("sec")
	cp := x.ix.Checkpoint("sec")

	// Unauthenticated and invalid grants.
	for _, tok := range []string{"", "garbage", clienttest.NewKey("ghost").Grant(t, s.Now(), "user:x", []string{"sec"}, []string{"read"})} {
		r := x.raw("/sec?q=secret", tok)
		if r.status != 401 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("token %.10q: %d %v", tok, r.status, r.header)
		}
	}
	if r := x.raw("/sec/at/"+cp, ""); r.status != 401 {
		t.Errorf("at without grant: %d", r.status)
	}
	other := issuer.Grant(t, s.Now(), "user:bob", []string{"other"}, []string{"read"})
	if r := x.raw("/sec", other); r.status != 403 {
		t.Errorf("grant for another namespace: %d", r.status)
	}

	// A whole-namespace reader: routed through its subject set.
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"groups": []any{"editors"}})
	r := x.raw("/sec?q=secret", bob)
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.HasPrefix(loc, "/g/") || !strings.Contains(loc, "/sec?q=secret") || r.header.Get("Cache-Control") != "private, no-cache" || r.header.Get("Vary") != "Authorization" {
		t.Fatalf("pointer: %d %s %v", r.status, loc, r.header)
	}
	gs := strings.Split(loc, "/")[2]
	r = x.raw(loc, bob)
	if r.status != 302 || r.header.Get("Location") != "/g/"+gs+"/sec/at/"+cp+"?q=secret" {
		t.Fatalf("gs pointer: %d %s", r.status, r.header.Get("Location"))
	}
	at := r.header.Get("Location")
	r = x.raw(at, bob)
	// No verifying edge (§9): no shared cache keeps a private result.
	if r.status != 200 || r.header.Get("Cache-Control") != "private, max-age=300" || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("at: %d %v", r.status, r.header)
	}
	if got := strings.Join(resources(r.body), ","); got != "a,b,c" {
		t.Errorf("bob sees %s", got)
	}
	for _, h := range r.body["hits"].([]any) {
		u := h.(map[string]any)["url"].(string)
		if strings.Contains(u, "?") || !strings.HasPrefix(u, clienttest.Origin+"/r/sec/") {
			t.Errorf("hit url %s", u)
		}
	}
	// Another user in the same groups shares the subject set (and caches).
	amy := issuer.Grant(t, s.Now(), "user:amy", []string{"sec"}, []string{"read"}, map[string]any{"groups": []any{"editors"}})
	if r := x.raw("/sec", amy); !strings.HasPrefix(r.header.Get("Location"), "/g/"+gs+"/") {
		t.Errorf("amy's subject set differs: %s", r.header.Get("Location"))
	}
	// Without a gs, an at URL redirects into the reader's subject set.
	if r := x.raw("/sec/at/"+cp+"?q=secret", bob); r.status != 302 || r.header.Get("Location") != at {
		t.Errorf("at without gs: %d %s", r.status, r.header.Get("Location"))
	}

	// A resource-scoped grant sees only its resource, under its own gs.
	onlyA := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"groups": []any{"editors"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	b := x.search("/sec?q=secret", onlyA)
	if got := strings.Join(resources(b), ","); got != "a" {
		t.Errorf("scoped grant sees %s", got)
	}
	r = x.raw("/sec", onlyA)
	if strings.HasPrefix(r.header.Get("Location"), "/g/"+gs+"/") {
		t.Error("a scoped grant shares the whole-namespace subject set")
	}
	// Presenting someone else's gs redirects to one's own.
	r = x.raw(at, onlyA)
	if r.status != 302 || strings.Contains(r.header.Get("Location"), gs) {
		t.Errorf("foreign gs: %d %s", r.status, r.header.Get("Location"))
	}
	// A reader's gs on a public-style URL of a private namespace is not served.
	if r := x.raw("/sec/at/"+cp, onlyA); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/g/") {
		t.Errorf("public url for a private ns: %d %s", r.status, r.header.Get("Location"))
	}

	// Behind a verifying edge (§9), private reads need its secret, and
	// verified results get edge lifetimes.
	ev, err := edge.New([]byte("s3cret"), "")
	if err != nil {
		t.Fatal(err)
	}
	y := startSvcWith(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "e.db"), ns: []string{"sec"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Edge = ev })
	y.caughtUp("sec")
	get := func(path, secret string) *http.Response {
		req := must(http.NewRequest("GET", y.http.URL+path, nil))
		req.Header.Set("Authorization", "Bearer "+bob)
		if secret != "" {
			req.Header.Set(edge.DefaultHeader, secret)
		}
		res := must(noFollow.Do(req))
		res.Body.Close()
		return res
	}
	for _, secret := range []string{"", "wrong"} {
		if res := get("/sec?q=secret", secret); res.StatusCode != 403 || res.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("secret %q: %d %v", secret, res.StatusCode, res.Header)
		}
	}
	res := get("/sec?q=secret", "s3cret")
	for res.StatusCode == 302 {
		res = get(res.Header.Get("Location"), "s3cret")
	}
	if res.StatusCode != 200 || res.Header.Get("CDN-Cache-Control") != "max-age=31536000" {
		t.Errorf("verified: %d %v", res.StatusCode, res.Header)
	}
}

func TestBranchPreviewIndex(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	must(w.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-draft"}))
	h := must(w.c.Head(ctx, "matches-draft", "cup"))
	must(w.c.Append(ctx, "matches-draft", "cup", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Cup draft title"}}))

	// Without -branches, only the base.
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	s.caughtUp("matches")
	if r := s.raw("/matches-draft", ""); r.status != 404 {
		t.Errorf("branch served without -branches: %d", r.status)
	}
	s.stop()

	p := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "p.db"), ns: []string{"matches"}, branches: true})
	p.caughtUp("matches")
	p.caughtUp("matches-draft")
	p.expect("/matches-draft?q=draft", "cup")
	p.expect("/matches-draft?q=derby", "derby") // read-through from the base
	p.expect("/matches?q=draft")
	if b := p.search("/matches-draft?q=draft", ""); !strings.HasPrefix(b["hits"].([]any)[0].(map[string]any)["url"].(string), clienttest.Origin+"/r/matches-draft/cup/rev/") {
		t.Errorf("branch hit %v", b["hits"])
	}
}
