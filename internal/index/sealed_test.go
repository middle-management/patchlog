package index_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

func keyStore(t *testing.T) *keystore.Local {
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// fetched is a 200 answer after following redirects: the path it was served
// at (the view a sealed result is bound to) and its raw body.
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
		r := must(noFollow.Do(req))
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

func epochKeys(t *testing.T, c *client.Client, ns string) func(string) []byte {
	m := map[string][]byte{}
	for _, e := range must(c.FetchKeys(context.Background(), ns, nil, nil)) {
		if e.Resource == "" {
			m[e.Kid] = e.Key
		}
	}
	if len(m) == 0 {
		t.Fatalf("no epoch keys of %s", ns)
	}
	return func(kid string) []byte { return m[kid] }
}

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return m
}

// createNonced creates a document in a sealed namespace, whose patch sets
// need a fresh $nonce (§C.7, §E.2.5).
func createNonced(c *client.Client, ns, name string, doc map[string]any) (*client.WriteResult, error) {
	ps := append(client.GenesisPatches(doc), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	return c.Create(context.Background(), ns, name, ps)
}

// Results over a sealed namespace are one JWE under its current epoch key,
// bound to the result's URL; a public namespace's stay plain JSON. Keys
// come from POST /keys with the indexer's grant, wrapped to its enc.
func TestSealedNamespace(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"sec", "pub", "schemas"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "sec" {
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"read", "create", "append", "purge", "config"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "pub", "schemas"}, all)), client.WithKeys(client.NewKeys(nil)))
	// The schema lives in a public namespace (§E.2.5).
	sch := must(w.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}, "tag": map[string]any{"type": "string", "x-index": "facet"}}}))
	ref := "/r/schemas/item/rev/" + sch.ID
	for _, ns := range []string{"sec", "pub"} {
		for _, n := range []string{"a", "b"} {
			must(createNonced(w, ns, n, map[string]any{"$schema": ref, "title": "secret " + n, "tag": "t" + n}))
		}
	}

	// The indexer's grant carries its enc: keys come wrapped to it.
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec", "pub"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	opts := svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec", "pub"}, now: s.Now}
	withKey := func(o *indexOpts) { o.Recipient = priv }
	x := startSvcWith(t, ic, opts, withKey)
	x.caughtUp("sec")
	x.caughtUp("pub")

	// Public namespace: unchanged.
	p := x.fetch("/pub?q=secret", "")
	if ct := p.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("public content type %q", ct)
	}
	if got := strings.Join(resources(decodeJSON(t, p.body)), ","); got != "a,b" {
		t.Fatalf("public hits %s", got)
	}

	// Sealed namespace: a JWE under sec#1, bound to { ns, view }.
	f := x.fetch("/sec?q=secret&counts=/tag", "")
	if ct := f.header.Get("Content-Type"); ct != seal.ContentType {
		t.Fatalf("sealed content type %q: %s", ct, f.body)
	}
	if strings.Contains(string(f.body), "secret") {
		t.Fatalf("plaintext in sealed result: %s", f.body)
	}
	h := must(seal.ParseHeader(string(f.body)))
	at := x.ix.Checkpoint("sec")
	if h.Kid != "sec#1" || h.Zip != "" || fmt.Sprint(h.PL) != fmt.Sprint(map[string]any{"ns": "sec", "view": "/sec/at/" + at + "?counts=%2Ftag&q=secret"}) {
		t.Fatalf("header %+v", h)
	}
	keys := epochKeys(t, w, "sec")
	pt := must(derived.OpenView(string(f.body), keys, derived.View{NS: "sec", Target: f.path}))
	b := decodeJSON(t, pt)
	if got := strings.Join(resources(b), ","); got != "a,b" || b["at"] != at || b["counts"] == nil {
		t.Fatalf("decrypted %s", pt)
	}
	hit := b["hits"].([]any)[0].(map[string]any)
	if fmt.Sprint(hit["/tag"]) != "[ta]" || hit["score"] == nil {
		t.Fatalf("hit %v", hit)
	}
	// Requested fields are sealed with the rest (§A.4).
	ff := x.fetch("/sec?q=secret&fields=%2Ftitle", "")
	fpt := must(derived.OpenView(string(ff.body), keys, derived.View{NS: "sec", Target: ff.path}))
	if fh := decodeJSON(t, fpt)["hits"].([]any)[0].(map[string]any); fmt.Sprint(fh["/title"]) != "[secret a]" || strings.Contains(string(ff.body), "secret") {
		t.Fatalf("fields in a sealed result: %s", fpt)
	}
	// Not with another key, nor as another query's result.
	other := seal.NewKey()
	if _, err := derived.OpenView(string(f.body), func(string) []byte { return other }, derived.View{NS: "sec", Target: f.path}); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := derived.OpenView(string(f.body), keys, derived.View{NS: "sec", Target: "/sec/at/" + at + "?q=other"}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("other view: %v", err)
	}
	// Sealed once, served unchanged; only the canonical URL is served.
	if again := x.fetch(f.path, ""); string(again.body) != string(f.body) {
		t.Fatal("resealed on a second read")
	}
	// Stored in the database, with its cache tags: a restart serves the
	// same bytes.
	if tags := x.ix.SealedViews()[f.path]; !strings.Contains(tags, "r:sec/a") || !strings.Contains(tags, "idx:sec") {
		t.Fatalf("stored view tags %q", tags)
	}
	x.stop()
	x = startSvcWith(t, ic, opts, withKey)
	x.caughtUp("sec")
	if again := x.fetch(f.path, ""); string(again.body) != string(f.body) || !strings.Contains(again.header.Get("Cache-Tag"), "r:sec/a") {
		t.Fatalf("resealed after a restart (tags %q)", again.header.Get("Cache-Tag"))
	}
	if r := x.raw("/sec/at/"+at+"?q=secret&counts=/tag", ""); r.status != 302 || r.header.Get("Location") != f.path {
		t.Fatalf("non-canonical: %d %s", r.status, r.header.Get("Location"))
	}

	// Status.
	st := x.raw("/_status", "")
	if fmt.Sprint(st.body["namespaces"]) != "[map[ns:pub sealed:false skipped:false] map[epoch:1 level:sealed ns:sec sealed:true skipped:false]]" {
		t.Fatalf("status %v", st.body)
	}

	// A rotation moves the checkpoint: results are sealed under the new epoch.
	must(s.Engine.RotateEpoch(ctx, "sec", "system:rotate"))
	x.caughtUp("sec")
	f2 := x.fetch("/sec?q=secret", "")
	if h := must(seal.ParseHeader(string(f2.body))); h.Kid != "sec#2" {
		t.Fatalf("after rotation kid %s", h.Kid)
	}
	if got := strings.Join(resources(decodeJSON(t, must(derived.OpenView(string(f2.body), epochKeys(t, w, "sec"), derived.View{NS: "sec", Target: f2.path})))), ","); got != "a,b" {
		t.Fatalf("after rotation %s", got)
	}

	// A purge removes the resource's rows and every sealed result showing it.
	before := x.ix.CountRows("sec")
	must(w.Purge(ctx, "sec", "a", must(w.Head(ctx, "sec", "a")).ID, false))
	x.caughtUp("sec")
	if n := x.ix.CountRows("sec"); n >= before {
		t.Fatalf("rows %d after purge, %d before", n, before)
	}
	for v, tags := range x.ix.SealedViews() {
		if strings.Contains(tags, "r:sec/a") || v == f2.path {
			t.Fatalf("stored view %s (%s) survived the purge", v, tags)
		}
	}
	f3 := x.fetch("/sec?q=secret", "")
	if got := strings.Join(resources(decodeJSON(t, must(derived.OpenView(string(f3.body), epochKeys(t, w, "sec"), derived.View{NS: "sec", Target: f3.path})))), ","); got != "b" {
		t.Fatalf("after purge %s", got)
	}
}

// A reader whose grant restricts resources gets JSON with each hit's
// derived values sealed under its resource's key, and no counts.
func TestSealedPerResource(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	sch := must(w.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	for _, n := range []string{"a", "b"} {
		must(createNonced(w, "sec", n, map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "secret " + n}))
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now})
	x.caughtUp("sec")

	fixed := k.Grant(t, s.Now(), "user:li", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	f := x.fetch("/sec?q=secret", fixed)
	if ct := f.header.Get("Content-Type"); ct != "application/json" || strings.Contains(string(f.body), "secret") {
		t.Fatalf("per-resource: %q %s", ct, f.body)
	}
	b := decodeJSON(t, f.body)
	hits := b["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("hits %v", hits)
	}
	hit := hits[0].(map[string]any)
	if hit["resource"] != "a" || hit["id"] == nil || hit["url"] == nil || hit["score"] != nil {
		t.Fatalf("hit %v", hit)
	}
	jwe := hit["sealed"].(string)
	if h := must(seal.ParseHeader(jwe)); fmt.Sprint(h.PL) != fmt.Sprint(map[string]any{"name": "a", "ns": "sec", "view": f.path}) {
		t.Fatalf("hit pl %v", h.PL)
	}
	// The reader's own K_a opens it; K_b doesn't.
	pr := s.Client(t, client.WithBearer(fixed))
	fk := must(pr.FetchKeys(ctx, "sec", nil, []string{"a"}))
	if len(fk) != 1 || fk[0].Resource != "a" {
		t.Fatalf("keys %+v", fk)
	}
	ka := func(kid string) []byte {
		if kid == fk[0].Kid {
			return fk[0].Key
		}
		return nil
	}
	v := decodeJSON(t, must(derived.OpenItem(jwe, ka, derived.View{NS: "sec", Target: f.path}, "sec", "a")))
	if v["score"] == nil || v["schema"] == nil {
		t.Fatalf("values %v", v)
	}
	kb := derived.ItemKey(epochKeys(t, w, "sec"), "sec", "b")
	if _, err := derived.OpenItem(jwe, kb, derived.View{NS: "sec", Target: f.path}, "sec", "b"); err == nil {
		t.Fatal("opened with K_b")
	}
	var st int
	for p := "/sec?q=secret&counts=/title"; ; {
		r := x.raw(p, fixed)
		if r.status != 302 {
			st = r.status
			break
		}
		p = r.header.Get("Location")
	}
	if st != 400 {
		t.Fatalf("counts for a per-resource reader: %d", st)
	}
}

// An e2e namespace is indexed only by a service whose key is a keyring
// recipient; any other skips it, says why, and holds none of its rows.
func TestE2ENamespace(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "public", "keys": []any{admin.Entry("*")},
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	all := []string{"read", "create", "append", "config"}
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	idxJWK, idxPriv, _ := seal.GenerateRecipient()
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"e", "schemas"}, all, map[string]any{"enc": adminJWK})))
	ad := ac.E2E(adminPriv)
	sch := must(ac.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	must(ad.InitKeyring(ctx, "e", idxPriv.PublicKey()))
	marker := "zqxmarker"
	for _, n := range []string{"a", "b"} {
		must(ad.CreateDocSealed(ctx, "e", n, map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": marker + " " + n}))
	}

	// Without a recipient key: skipped.
	plain := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e"}, []string{"read"})))
	nx := startSvc(t, plain, svcOpts{db: filepath.Join(t.TempDir(), "n.db"), ns: []string{"e"}, untyped: true, now: s.Now})
	waitFor(t, "skip", func() bool {
		st := nx.raw("/_status", "").body["namespaces"].([]any)[0].(map[string]any)
		return st["skipped"] == true
	})
	st := nx.raw("/_status", "").body["namespaces"].([]any)[0].(map[string]any)
	if st["level"] != "e2e" || !strings.Contains(st["reason"].(string), "keyring recipient") {
		t.Fatalf("status %v", st)
	}
	if r := nx.raw("/e?q="+marker, ""); r.status != 503 || r.body["code"] != "skipped" {
		t.Fatalf("skipped namespace: %d %v", r.status, r.body)
	}
	if n := nx.ix.CountRows("e"); n != 0 || nx.ix.Checkpoint("e") != "" {
		t.Fatalf("skipped namespace has %d rows", n)
	}

	// With the keyring recipient key: indexed, and results sealed.
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e"}, []string{"read"}, map[string]any{"enc": idxJWK})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	f := x.fetch("/e?q="+marker, "")
	if ct := f.header.Get("Content-Type"); ct != seal.ContentType || strings.Contains(string(f.body), marker) {
		t.Fatalf("e2e result: %q %s", ct, f.body)
	}
	ke := must(ad.Key(ctx, "e#1"))
	b := decodeJSON(t, must(derived.OpenView(string(f.body), func(kid string) []byte {
		if kid == "e#1" {
			return ke
		}
		return nil
	}, derived.View{NS: "e", Target: f.path})))
	got := resources(b)
	sort.Strings(got)
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("e2e hits %v", got)
	}
	// The keyring is not content: not even in plain listings.
	lst := x.fetch("/e", "")
	b = decodeJSON(t, must(derived.OpenView(string(lst.body), func(string) []byte { return ke }, derived.View{NS: "e", Target: lst.path})))
	if got := strings.Join(resources(b), ","); got != "a,b" {
		t.Fatalf("listing %s", got)
	}
}

// A namespace with encryption.pad gets padded results (§E.2.2, §E.2.6):
// the plaintext is padded to its bucket and never compressed.
func TestSealedPadded(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("w"), client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "p", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "pad": true}}))
	sch := must(c.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}, "tag": map[string]any{"type": "string", "x-index": "facet"}}}))
	for _, n := range []string{"a", "b", "c"} {
		must(createNonced(c, "p", n, map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "padded " + n, "tag": strings.Repeat(n, 700)}))
	}
	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"p"}, now: s.Now})
	x.caughtUp("p")
	f := x.fetch("/p?q=padded", "")
	h := must(seal.ParseHeader(string(f.body)))
	pt := must(derived.OpenView(string(f.body), epochKeys(t, c, "p"), derived.View{NS: "p", Target: f.path}))
	if !seal.IsPadded(h, pt) || len(pt) <= 2100 {
		t.Fatalf("not padded: zip %q, %d bytes", h.Zip, len(pt))
	}
	if got := strings.Join(resources(decodeJSON(t, pt)), ","); got != "a,b,c" {
		t.Fatalf("hits %s", got)
	}
}
