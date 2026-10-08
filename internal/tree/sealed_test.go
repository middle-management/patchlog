package tree_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// fetched is a 200 answer after following redirects: the target it was
// served at (the view a sealed listing is bound to) and its raw body.
type fetched struct {
	path   string
	header http.Header
	body   []byte
}

func (s *svc) fetch(path, token string) fetched {
	s.t.Helper()
	for range 5 {
		req := must(http.NewRequest("GET", s.http.URL+path, nil))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		r := must(noRedirect.Do(req))
		b := must(io.ReadAll(r.Body))
		r.Body.Close()
		switch r.StatusCode {
		case 200:
			return fetched{path, r.Header, b}
		case 302:
			path = r.Header.Get("Location")
		default:
			s.t.Fatalf("GET %s: %d %s", path, r.StatusCode, b)
		}
	}
	s.t.Fatalf("GET %s: too many redirects", path)
	return fetched{}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return m
}

func createNonced(t *testing.T, c *client.Client, ns, name string, doc map[string]any) {
	t.Helper()
	ps := append(client.GenesisPatches(doc), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	must(c.Create(context.Background(), ns, name, ps))
}

// Listings of a sealed catalog are one JWE under its epoch key for readers
// of the whole catalog, and carry per-node sealed titles for readers
// restricted to some catalog resources; names, hrefs and structure stay in
// the clear.
func TestSealedCatalog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat", "matches"}, []string{"read", "create", "purge"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"title": "Root zqx", "parents": []any{}})
	createNonced(t, w, "cat", "season", map[string]any{"title": "Season zqx", "parents": parents("root@a0")})
	must(w.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "derby"}))
	createNonced(t, w, "cat", "matches.derby", map[string]any{"parents": parents("season")})

	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat", "matches"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	opts := svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")}
	x := startSvc(t, sc, opts)
	x.caughtUp("cat", "matches")

	epoch := map[string][]byte{}
	for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
		epoch[e.Kid] = e.Key
	}
	keyOf := func(kid string) []byte { return epoch[kid] }

	// A reader of the whole catalog: one JWE bound to { ns, view }.
	full := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
	f := x.fetch("/cat/children?of=root", full)
	if ct := f.header.Get("Content-Type"); ct != seal.ContentType || strings.Contains(string(f.body), "zqx") {
		t.Fatalf("sealed listing %q %s", ct, f.body)
	}
	if !strings.HasPrefix(f.path, "/cat/at/"+x.s.At()+"/g/") {
		t.Fatalf("served at %s", f.path)
	}
	h := must(seal.ParseHeader(string(f.body)))
	if h.Kid != "cat#1" || fmt.Sprint(h.PL) != fmt.Sprint(map[string]any{"ns": "cat", "view": f.path}) {
		t.Fatalf("header %+v", h)
	}
	b := decode(t, must(derived.OpenView(string(f.body), keyOf, derived.View{NS: "cat", Target: f.path})))
	kid := b["children"].([]any)[0].(map[string]any)
	if kid["name"] != "season" || kid["title"] != "Season zqx" || kid["order"] != "a0" {
		t.Fatalf("children %v", b)
	}
	if _, err := derived.OpenView(string(f.body), func(string) []byte { return seal.NewKey() }, derived.View{NS: "cat", Target: f.path}); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := derived.OpenView(string(f.body), keyOf, derived.View{NS: "cat", Target: strings.Replace(f.path, "children", "roots", 1)}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("other view: %v", err)
	}
	if again := x.fetch(f.path, full); string(again.body) != string(f.body) {
		t.Fatal("resealed on a second read")
	}
	// Item heads come from a public content namespace: no key needed for
	// them, but they are inside the catalog's JWE here.
	sf := x.fetch("/cat/subtree?of=root", full)
	sub := decode(t, must(derived.OpenView(string(sf.body), keyOf, derived.View{NS: "cat", Target: sf.path})))
	if !strings.Contains(fmt.Sprint(sub["tree"]), "matches.derby") {
		t.Fatalf("subtree %v", sub)
	}

	// A reader restricted to the catalog resource "root": JSON, the title
	// sealed under K_r of cat/root.
	li := k.Grant(t, s.Now(), "user:li", []string{"cat"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "root"}}})
	r := x.fetch("/cat/roots", li)
	if ct := r.header.Get("Content-Type"); ct != "application/json" || strings.Contains(string(r.body), "zqx") {
		t.Fatalf("per-entry listing %q %s", ct, r.body)
	}
	roots := decode(t, r.body)["roots"].([]any)
	if len(roots) != 1 {
		t.Fatalf("roots %v", roots)
	}
	e := roots[0].(map[string]any)
	if e["name"] != "root" || e["href"] != "/r/cat/root" || e["title"] != nil {
		t.Fatalf("entry %v", e)
	}
	pr := s.Client(t, client.WithBearer(li))
	fk := must(pr.FetchKeys(ctx, "cat", nil, []string{"root"}))
	if len(fk) != 1 || fk[0].Resource != "root" {
		t.Fatalf("keys %+v", fk)
	}
	kr := func(kid string) []byte {
		if kid == fk[0].Kid {
			return fk[0].Key
		}
		return nil
	}
	v := derived.View{NS: "cat", Target: r.path}
	if t0 := decode(t, must(derived.OpenItem(e["sealed"].(string), kr, v, "cat", "root"))); t0["title"] != "Root zqx" {
		t.Fatalf("title %v", t0)
	}
	if _, err := derived.OpenItem(e["sealed"].(string), derived.ItemKey(keyOf, "cat", "season"), v, "cat", "season"); err == nil {
		t.Fatal("opened as another node")
	}

	// Stored in the database with its cache tags: a restart serves the
	// same bytes.
	if tags := x.s.SealedViews()[f.path]; !strings.Contains(tags, "r:cat/season") {
		t.Fatalf("stored view tags %q", tags)
	}
	x.stop()
	x = startSvc(t, sc, opts)
	x.caughtUp("cat", "matches")
	if again := x.fetch(f.path, full); string(again.body) != string(f.body) {
		t.Fatal("resealed after a restart")
	}
	// A purge removes every stored listing showing the resource.
	must(w.Purge(ctx, "cat", "season", must(w.Head(ctx, "cat", "season")).ID, false))
	x.caughtUp("cat")
	for v, tags := range x.s.SealedViews() {
		if strings.Contains(tags, "r:cat/season") || v == f.path {
			t.Fatalf("stored view %s (%s) survived the purge", v, tags)
		}
	}

	// Status.
	st := x.raw("/_status", "").body
	if fmt.Sprint(st["namespaces"]) != "[map[epoch:1 level:sealed ns:cat sealed:true skipped:false] map[ns:matches sealed:false skipped:false]]" {
		t.Fatalf("status %v", st)
	}
}

// An e2e catalog is not consumed without a keyring recipient key: listings
// answer 503 and /_status says why.
func TestE2ECatalogSkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks, LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "encryption": map[string]any{"level": "e2e"}, "catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	x := startSvc(t, c, svcOpts{})
	waitFor(t, "skip", func() bool {
		ns, _ := x.raw("/_status", "").body["namespaces"].([]any)
		return len(ns) == 1 && ns[0].(map[string]any)["skipped"] == true
	})
	st := x.raw("/_status", "").body["namespaces"].([]any)[0].(map[string]any)
	if st["level"] != "e2e" || !strings.Contains(fmt.Sprint(st["reason"]), "keyring recipient") {
		t.Fatalf("status %v", st)
	}
	if r := x.raw("/cat/roots", ""); r.status != 503 || r.body["code"] != "skipped" {
		t.Fatalf("roots: %d %v", r.status, r.body)
	}
	if x.s.Checkpoint("cat") != "" {
		t.Fatal("the skipped catalog was followed")
	}
}
