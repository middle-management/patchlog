package index_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// v073World is a public namespace "items" whose documents use one schema
// revision of "schemas", marked as props says.
type v073World struct {
	c   *client.Client
	s   *clienttest.Server
	sch string // the schema's revision path
}

func v073Setup(t *testing.T, props map[string]any) *v073World {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "items", map[string]any{"read": "public"}))
	props["$schema"] = map[string]any{"type": "string"}
	sch := must(c.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object", "properties": props}))
	return &v073World{c: c, s: s, sch: "/r/schemas/item/rev/" + sch.ID}
}

func (w *v073World) doc(t *testing.T, name string, fields map[string]any) {
	t.Helper()
	fields["$schema"] = w.sch
	must(w.c.CreateDoc(context.Background(), "items", name, fields))
}

// answerOf follows redirects and returns the last answer.
func (s *svc) answerOf(path, token string) resp {
	s.t.Helper()
	for range 5 {
		r := s.raw(path, token)
		if r.status != 302 {
			return r
		}
		path = r.header.Get("Location")
	}
	s.t.Fatalf("GET %s: too many redirects", path)
	return resp{}
}

// TestV073BehindBeforeCheckpoint (IX-1, §A.4): until the service has a
// checkpoint for a namespace it follows, a query of it is answered, once
// the reader's grant verifies, 503 behind, no-store, with Retry-After;
// /_refs leaves the namespace out.
func TestV073BehindBeforeCheckpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create"})))
	must(writer.CreateDoc(ctx, "sec", "a", map[string]any{"title": "secret"}))
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})))
	x := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now, noRun: true})

	if r := x.raw("/sec?q=secret", ""); r.status != 401 || r.body["code"] != "unauthenticated" {
		t.Errorf("without a grant: %d %v", r.status, r.body)
	}
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"})
	r := x.raw("/sec?q=secret", bob)
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Retry-After") == "" {
		t.Errorf("with a grant: %d %v %v", r.status, r.body, r.header)
	}
	b := x.answerOf("/_refs?to=/r/sec/a", bob)
	if b.status != 200 || fmt.Sprint(b.body["namespaces"]) != "map[]" {
		t.Errorf("/_refs: %d %v", b.status, b.body)
	}
}

// v073FailKeys answers POST /ns/{ns}/keys 503 from the after-th call on,
// while armed.
type v073FailKeys struct {
	path  string
	after int32
	n     atomic.Int32
	armed atomic.Bool
	rt    http.RoundTripper
}

func (f *v073FailKeys) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && r.URL.Path == f.path && f.n.Add(1) > f.after && f.armed.Load() {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"code":"internal","message":"injected"}`)), Request: r}, nil
	}
	return f.rt.RoundTrip(r)
}

// TestV073KeysLacking (IX-2, §A.4, §E.2.6, §12.1): a namespace whose keys
// the service lacks is 404 not_found as one it doesn't follow, with or
// without a grant; one whose keys it can't fetch for now is 503 behind,
// after the grant check. There is no skipped code.
func TestV073KeysLacking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	keys := []any{admin.Entry("*"), issuer.Entry("read")}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": keys,
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": keys,
		"encryption": map[string]any{"level": "sealed"}}))
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"sec"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	must(createNonced(w, "sec", "a", map[string]any{"title": "secret"}))
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"e", "sec"}, []string{"read"})

	// e2e, and no keyring names the service's recipient key: it lacks
	// keys (client.ErrNoKeys).
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	fk := &v073FailKeys{path: "/ns/sec/keys", after: 1, rt: transport}
	fk.armed.Store(true)
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e", "sec"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e", "sec"}, untyped: true, now: s.Now, hc: &http.Client{Transport: fk}},
		func(o *indexOpts) { o.Recipient = priv })
	waitFor(t, "both skipped", func() bool {
		n := 0
		for _, st := range x.raw("/_status", "").body["namespaces"].([]any) {
			if st.(map[string]any)["skipped"] == true {
				n++
			}
		}
		return n == 2
	})
	for _, tok := range []string{"", bob} {
		r := x.raw("/e?q=secret", tok)
		if r.status != 404 || r.body["code"] != "not_found" || r.body["message"] != "namespace not indexed" || r.header.Get("Cache-Control") != "public, max-age=5" {
			t.Errorf("e2e without keys, token %v: %d %v %v", tok != "", r.status, r.body, r.header)
		}
		if u := x.raw("/unfollowed?q=secret", tok); fmt.Sprint(u.body) != fmt.Sprint(r.body) || u.header.Get("Cache-Control") != r.header.Get("Cache-Control") {
			t.Errorf("unlike an unfollowed namespace: %v %v", u.body, u.header)
		}
	}

	// sealed, and its epoch key can't be fetched for now (503): behind,
	// after the grant check.
	if r := x.raw("/sec?q=secret", ""); r.status != 401 {
		t.Errorf("sealed, keys for now, no grant: %d %v", r.status, r.body)
	}
	r := x.raw("/sec?q=secret", bob)
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Retry-After") == "" {
		t.Errorf("sealed, keys for now: %d %v %v", r.status, r.body, r.header)
	}
	// /_refs leaves both out.
	if b := x.answerOf("/_refs?to=/r/sec/a", bob); b.status != 200 || fmt.Sprint(b.body["namespaces"]) != "map[]" {
		t.Errorf("/_refs: %d %v", b.status, b.body)
	}
	// Once the keys come, it is indexed.
	fk.armed.Store(false)
	x.caughtUp("sec")
	if f := x.fetch("/sec?q=secret", bob); f.header.Get("Content-Type") != seal.ContentType {
		t.Errorf("sealed, keys fetched: %v", f.header)
	}
}

// TestV073SortOrder (IX-6, §A.2): a document sorts by its least value at
// the path in either direction, numbers before strings before booleans,
// numbers by value, strings by UTF-8 bytes with no date-time normalisation,
// false before true, and documents without one last in either direction.
// Hits carry every value as "<path>": [values].
func TestV073SortOrder(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{"rank": map[string]any{"x-index": "sort"}})
	for name, v := range map[string]any{
		"a": 5, "b": []any{9, 1}, "c": "s", "d": true, "e": false, "g": "2026-10-04T18:00:00+02:00", "h": "2026-10-04T17:00:00Z",
		"i": []any{"x", 3}, "j": []any{true, "t"},
	} {
		w.doc(t, name, map[string]any{"rank": v})
	}
	w.doc(t, "f", map[string]any{})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	x.expect("/items?sort=/rank", "b", "i", "a", "h", "g", "c", "j", "e", "d", "f")
	b := x.expect("/items?sort=-/rank", "d", "e", "j", "c", "g", "h", "a", "i", "b", "f")
	got := map[string]string{}
	for _, h := range b["hits"].([]any) {
		m := h.(map[string]any)
		got[m["resource"].(string)] = fmt.Sprint(m["/rank"])
	}
	if got["b"] != "[9 1]" || got["d"] != "[true]" || got["j"] != "[true t]" || got["f"] != "<nil>" {
		t.Errorf("hit values %v", got)
	}
}

// TestV073UnavailableSchema (IX-22, §A.1): a document whose pinned schema
// revision answers 403, or can't be opened for want of keys, is indexed
// exactly as one without $schema: a docs row only if untyped documents
// are listed, no match for schema=, and its schema counts for no path; the
// follower doesn't stall.
func TestV073UnavailableSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin := clienttest.NewKey("admin")
	keys := []any{admin.Entry("*")}
	for ns, doc := range map[string]map[string]any{
		"priv":    {"read": "grant", "keys": keys},
		"sealed":  {"read": "public", "keys": keys, "encryption": map[string]any{"level": "sealed"}},
		"schemas": {"read": "public", "keys": keys},
		"items":   {"read": "public", "keys": keys},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"read", "create"}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"priv", "sealed", "schemas", "items"}, all)), client.WithKeys(client.NewKeys(nil)))
	mk := func(ns string) string {
		sch := map[string]any{"$schema": d2020, "type": "object", "properties": map[string]any{"v": map[string]any{"type": "string", "x-index": "facet"}}}
		if ns == "sealed" {
			return "/r/sealed/s/rev/" + must(createNonced(w, ns, "s", sch)).ID
		}
		return "/r/" + ns + "/s/rev/" + must(w.CreateDoc(ctx, ns, "s", sch)).ID
	}
	open, forbidden, keyless := mk("schemas"), mk("priv"), mk("sealed")
	for name, sch := range map[string]string{"open": open, "forbidden": forbidden, "keyless": keyless} {
		must(w.CreateDoc(ctx, "items", name, map[string]any{"$schema": sch, "v": "x"}))
	}
	// The indexer reads items and schemas, not priv, and holds no keys.
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"items", "schemas", "sealed"}, []string{"read"})))
	x := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}, now: s.Now})
	x.caughtUp("items")
	x.expect("/items", "open")
	x.expect("/items?facet[/v]=x", "open")
	x.expect("/items?schema=" + url.QueryEscape(forbidden))
	x.expect("/items?schema=/r/priv/s")
	x.expect("/items?schema=" + url.QueryEscape(keyless))
	y := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "u.db"), ns: []string{"items"}, untyped: true, now: s.Now})
	y.caughtUp("items")
	b := y.expect("/items", "forbidden", "keyless", "open")
	for _, h := range b["hits"].([]any) {
		if m := h.(map[string]any); m["resource"] != "open" && m["schema"] != nil {
			t.Errorf("an untyped hit with a schema: %v", m)
		}
	}
	y.expect("/items?schema=/r/sealed/s")
}

// TestV073StaticWalk (IX-7, §A.2, §A.4): x-index values are collected by a
// static walk, through every branch whatever the document's validity, and
// only strings, numbers and booleans: an object at a facet path, or one
// marked text, indexes nothing; text collects strings only.
func TestV073StaticWalk(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{
		"a":     map[string]any{"anyOf": []any{map[string]any{"type": "string", "x-index": "facet"}, map[string]any{"type": "number"}}},
		"obj":   map[string]any{"x-index": "facet"},
		"notes": map[string]any{"type": "object", "x-index": "text"},
		"t":     map[string]any{"x-index": "text"},
		"neg":   map[string]any{"not": map[string]any{"type": "null", "x-index": "facet"}},
		"tags":  map[string]any{"type": "array", "x-index": "facet"},
	})
	w.doc(t, "d1", map[string]any{"a": 5, "obj": map[string]any{"k": "v"}, "notes": map[string]any{"summary": "tense"}, "t": 42, "neg": "x",
		"tags": []any{"p", map[string]any{"k": "v"}, 1}})
	w.doc(t, "d2", map[string]any{"obj": nil, "t": "fortytwo"})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	x.expect("/items?facet[/a]=5", "d1") // the failing anyOf branch still marks
	x.expect("/items?facet[/obj]=" + url.QueryEscape(`{"k":"v"}`))
	x.expect("/items?facet[/obj]=null")
	x.expect("/items?q=tense")
	x.expect("/items?q=42")
	x.expect("/items?q=fortytwo", "d2")
	x.expect("/items?facet[/tags]=1", "d1")
	x.expect("/items?facet[/tags]=" + url.QueryEscape(`{"k":"v"}`))
	if r := x.answerOf("/items?facet[/neg]=x", ""); r.status != 400 {
		t.Errorf("a path marked only through not: %d %v", r.status, r.body)
	}
}

// TestV073PathKinds (IX-3, §A.4): a facet[…] or counts path must be marked
// facet, a sort path sort, by a schema indexed for a document the reader
// may see; a fields path with any kind. Otherwise 400 naming the parameter.
func TestV073PathKinds(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{
		"t": map[string]any{"type": "string", "x-index": "text"}, "f": map[string]any{"type": "string", "x-index": "facet"},
		"s": map[string]any{"type": "number", "x-index": "sort"}, "fs": map[string]any{"type": "string", "x-index": []any{"facet", "sort"}},
		"plain": map[string]any{"type": "string"},
	})
	w.doc(t, "a", map[string]any{"t": "x", "f": "x", "s": 1, "fs": "x", "plain": "x"})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	for q, param := range map[string]string{
		"facet[/plain]=x": "facet[/plain]", "facet[/s]=x": "facet[/s]", "facet[/t]=x": "facet[/t]",
		"counts=/s": "counts", "counts=/t": "counts", "sort=/f": "sort", "sort=/t": "sort", "sort=/s,-/f": "sort",
		"fields=/plain": "fields", "gt[/f]=1": "gt[/f]",
	} {
		r := x.answerOf("/items?"+q, "")
		if msg, _ := r.body["message"].(string); r.status != 400 || r.body["code"] != "bad_input" || !strings.HasPrefix(msg, param+": ") {
			t.Errorf("%s: %d %v", q, r.status, r.body)
		}
	}
	for _, q := range []string{"facet[/f]=x", "facet[/fs]=x", "counts=/fs", "sort=/s,-/fs", "fields=/t,/f,/s", "ge[/s]=1"} {
		if r := x.answerOf("/items?"+q, ""); r.status != 200 || len(r.body["hits"].([]any)) != 1 {
			t.Errorf("%s: %d %v", q, r.status, r.body)
		}
	}
}

// TestV073PathsByVisibleDocs (IX-4, §A.4): paths are judged only by the
// schemas of documents the reader may see.
func TestV073PathsByVisibleDocs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create"})))
	pub := must(writer.CreateDoc(ctx, "sec", "pub-schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "facet"}}}))
	secret := must(writer.CreateDoc(ctx, "sec", "salary-schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"salary": map[string]any{"type": "number", "x-index": []any{"text", "facet", "sort"}}}}))
	must(writer.CreateDoc(ctx, "sec", "pub-1", map[string]any{"$schema": "/r/sec/pub-schema/rev/" + pub.ID, "title": "x"}))
	must(writer.CreateDoc(ctx, "sec", "secret-1", map[string]any{"$schema": "/r/sec/salary-schema/rev/" + secret.ID, "salary": 1}))
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})))
	x := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now})
	x.caughtUp("sec")
	whole := issuer.Grant(t, s.Now(), "user:boss", []string{"sec"}, []string{"read"})
	limited := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "pub-1"}}})
	for _, q := range []string{"fields=/salary", "facet[/salary]=1", "counts=/salary", "sort=/salary"} {
		if r := x.answerOf("/sec?"+q, limited); r.status != 400 {
			t.Errorf("%s, limited reader: %d %v", q, r.status, r.body)
		}
		if r := x.answerOf("/sec?"+q, whole); r.status != 200 {
			t.Errorf("%s, whole reader: %d %v", q, r.status, r.body)
		}
	}
	if r := x.answerOf("/sec?facet[/title]=x", limited); r.status != 200 || fmt.Sprint(resources(r.body)) != "[pub-1]" {
		t.Errorf("a path its documents' schema marks: %d %v", r.status, r.body)
	}
}

// TestV073HitOrder (IX-5, §A.4): with q and sort, hits go by the sort keys,
// then resource name, never by score; with q alone by score descending,
// then name; with neither by name.
func TestV073HitOrder(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{"t": map[string]any{"x-index": "text"}, "r": map[string]any{"x-index": "sort"}})
	w.doc(t, "a", map[string]any{"t": "goal", "r": 1})
	w.doc(t, "b", map[string]any{"t": "goal goal goal goal goal", "r": 1})
	w.doc(t, "c", map[string]any{"t": "goal", "r": 0})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	x.expect("/items?q=goal&sort=/r", "c", "a", "b")
	x.expect("/items?q=goal&sort=-/r", "a", "b", "c")
	x.expect("/items?q=goal", "b", "a", "c")
	x.expect("/items", "a", "b", "c")
}

// TestV073Paging (IX-9, §A.4): every query pages as /_refs does. Without q
// or sort, after is a bare resource name, a plain bound, and next the last
// hit's name; with q or sort, next is an opaque position, not a URL, given
// back as after. next is absent on the last page.
func TestV073Paging(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{"t": map[string]any{"x-index": "text"}, "r": map[string]any{"x-index": "sort"}})
	w.doc(t, "a", map[string]any{"t": "x", "r": 3})
	w.doc(t, "b", map[string]any{"t": "x", "r": 2})
	w.doc(t, "c", map[string]any{"t": "x", "r": 1})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	b := x.expect("/items?limit=2", "a", "b")
	if b["next"] != "b" {
		t.Errorf("next by name: %v", b["next"])
	}
	b = x.expect("/items?after=b&limit=2", "c")
	if _, ok := b["next"]; ok {
		t.Errorf("next on the last page: %v", b["next"])
	}
	x.expect("/items?after=a0&limit=5", "b", "c")
	for _, q := range []string{"sort=/r", "q=x"} {
		first, rest := "c,b", "a"
		if q == "q=x" {
			first, rest = "a,b", "c"
		}
		b = x.expect("/items?limit=2&"+q, strings.Split(first, ",")...)
		next, _ := b["next"].(string)
		if next == "" || strings.ContainsAny(next, "/?") {
			t.Fatalf("%s: next is not a position: %v", q, b["next"])
		}
		b = x.expect("/items?after="+url.QueryEscape(next)+"&limit=2&"+q, rest)
		if _, ok := b["next"]; ok {
			t.Errorf("%s: next on the last page: %v", q, b["next"])
		}
	}
}

// TestV073Counts (IX-8, §A.4, §A.2): counts=/a,/b is one comma-separated
// value, and a repeated counts is 400. The answer counts every hit, not
// just the page, by the value's string form: "1" and 1 count together.
func TestV073Counts(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{"v": map[string]any{"x-index": "facet"}, "u": map[string]any{"x-index": "facet"}})
	w.doc(t, "a", map[string]any{"v": "1", "u": "x"})
	w.doc(t, "b", map[string]any{"v": 1, "u": "x"})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	b := x.expect("/items?counts="+url.QueryEscape("/v,/u"), "a", "b")
	if fmt.Sprint(b["counts"]) != "map[/u:map[x:2] /v:map[1:2]]" {
		t.Errorf("counts %v", b["counts"])
	}
	b = x.expect("/items?counts=/v&limit=1", "a")
	if fmt.Sprint(b["counts"]) != "map[/v:map[1:2]]" {
		t.Errorf("counts over every hit: %v", b["counts"])
	}
	if r := x.answerOf("/items?counts=/v&counts=/u", ""); r.status != 400 || r.body["code"] != "bad_input" {
		t.Errorf("repeated counts: %d %v", r.status, r.body)
	}
}

// TestV073SchemaFilter (IX-23, §A.4): schema= is an exact $schema match,
// or a schema's resource path /r/{ns}/{name}, which matches only its /rev/
// revisions; no other prefix matches.
func TestV073SchemaFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := v073Setup(t, map[string]any{})
	w.doc(t, "a", map[string]any{})
	sch2 := must(w.c.CreateDoc(ctx, "schemas", "item2", map[string]any{"$schema": d2020, "type": "object"}))
	must(w.c.CreateDoc(ctx, "items", "b", map[string]any{"$schema": "/r/schemas/item2/rev/" + sch2.ID}))
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}})
	x.caughtUp("items")
	x.expect("/items?schema="+url.QueryEscape(w.sch), "a")
	x.expect("/items?schema=/r/schemas/item", "a")
	x.expect("/items?schema=/r/schemas/item2", "b")
	for _, s := range []string{"/r/schemas/item/", "/r/schemas/item/rev", "/r/schemas/item/rev/", "/r/schemas", "/r/schemas/", "/r/schemas/ite",
		w.sch[:len(w.sch)-2]} {
		x.expect("/items?schema=" + url.QueryEscape(s))
	}
}

// TestV073MinLackingKeys (IX-2, §A.4, §A.5): a namespace whose keys the
// service lacks is answered as one it doesn't follow. A min naming one on
// a query of another namespace is then 400, as a min naming an unfollowed
// namespace is, not a wait ending in 503 behind.
func TestV073MinLackingKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	keys := []any{admin.Entry("*"), issuer.Entry("read")}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": keys,
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pub"))).CreateNamespace(ctx, "pub", map[string]any{"read": "public", "keys": keys}))
	wr := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"pub"}, []string{"read", "create"})))
	must(wr.CreateDoc(ctx, "pub", "a", map[string]any{"title": "x"}))
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"e", "pub"}, []string{"read"})
	// No keyring of e names the service's recipient key: it lacks keys.
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e", "pub"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e", "pub"}, untyped: true, now: s.Now, minWait: 300 * time.Millisecond},
		func(o *indexOpts) { o.Recipient = priv })
	id := x.caughtUp("pub") // any well-formed ns_id
	waitFor(t, "e skipped", func() bool { return x.raw("/e", bob).status == 404 })
	unf := x.raw("/pub?min=unfollowed:"+id, bob)
	if unf.status != 400 || unf.body["code"] != "bad_input" {
		t.Fatalf("unfollowed min: %d %v", unf.status, unf.body)
	}
	lack := x.raw("/pub?min=e:"+id, bob)
	if lack.status != unf.status || fmt.Sprint(lack.body) != fmt.Sprint(unf.body) || lack.header.Get("Cache-Control") != unf.header.Get("Cache-Control") {
		t.Errorf("a min naming a namespace whose keys the service lacks: %d %v %v, unlike an unfollowed one: %d %v %v",
			lack.status, lack.body, lack.header, unf.status, unf.body, unf.header)
	}
}
