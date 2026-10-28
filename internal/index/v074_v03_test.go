package index_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/seal"
)

// answering answers GETs under prefix with status, as the core would
// refuse them, and passes everything else on.
type answering struct {
	prefix string
	status int
	rt     http.RoundTripper
}

func (a *answering) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.Path, a.prefix) {
		return a.rt.RoundTrip(r)
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if a.status == 429 {
		h.Set("Retry-After", "1")
	}
	return &http.Response{StatusCode: a.status, Header: h, Request: r,
		Body: io.NopCloser(strings.NewReader(`{"code":"refused","message":"injected"}`))}, nil
}

// CORE-6/SERVICES-2 (§A.1, Open 86): a schema revision answering a 4xx
// other than 429 (a 401 to the service's own grant included) leaves the
// document indexed as untyped and the checkpoint moves on; a 429 or a 5xx
// is transient, and the batch is retried.
func TestV074V03SchemaFinalStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.doc(t, "derby", w.match, map[string]any{"title": "The Derby", "status": "done"})
	origin := must(w.c.Origin(ctx))
	head := must(w.c.NSHead(ctx, "matches")).ID
	var units []follow.Unit
	for _, e := range must(w.c.NSLog(ctx, "matches", head, "")) {
		units = append(units, follow.Unit{Entry: e})
	}
	batch := &follow.Batch{Origin: origin, NS: "matches", Units: units, NewCheckpoint: head}
	for _, c := range []struct {
		status int
		final  bool
	}{
		{401, true}, {400, true}, {403, true}, {405, true},
		{429, false}, {500, false}, {503, false},
	} {
		db := filepath.Join(t.TempDir(), "i.db")
		rt := &answering{prefix: "/r/schemas/match/", status: c.status, rt: transport}
		s := startSvcWith(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true, noRun: true, hc: &http.Client{Transport: rt}})
		err := s.ix.Apply(ctx, batch)
		if !c.final {
			if err == nil || s.ix.Checkpoint("matches") != "" {
				t.Errorf("schema %d: Apply %v, checkpoint %q; want a transient failure", c.status, err, s.ix.Checkpoint("matches"))
			}
			s.stop()
			continue
		}
		if err != nil {
			t.Errorf("schema %d: Apply %v, want the document indexed untyped", c.status, err)
		} else if s.ix.Checkpoint("matches") != head {
			t.Errorf("schema %d: checkpoint %q, want %s", c.status, s.ix.Checkpoint("matches"), head)
		}
		s.stop()
		d := dumpIndex(t, db)
		parts := strings.Split(d, "--\n")
		if !strings.Contains(parts[0], "derby") || strings.Contains(parts[0], w.match) || parts[1] != "" || parts[2] != "" {
			t.Errorf("schema %d: index\n%s\nwant derby untyped, without rows", c.status, d)
		}
	}
}

// CORE-7/SERVICES-3 (§A.2, §A.4, Open 88): a schema marks, and the walk
// collects, through dependentSchemas whatever the data, so a document
// without the dependency's member still has its rows there.
func TestV074V03DependentSchemasWhateverTheData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	dep := must(w.c.CreateDoc(ctx, "schemas", "dep", map[string]any{"$schema": d2020, "type": "object",
		"dependentSchemas": map[string]any{"a": map[string]any{"properties": map[string]any{"b": map[string]any{"x-index": "facet"}}}}}))
	must(w.c.CreateDoc(ctx, "matches", "nodep", map[string]any{"$schema": "/r/schemas/dep/rev/" + dep.ID, "b": "x"}))
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	s.caughtUp("matches")
	body := s.expect("/matches?facet[/b]=x&counts=/b", "nodep")
	counts, _ := body["counts"].(map[string]any)
	if got, _ := counts["/b"].(map[string]any); len(got) != 1 || got["x"] != 1.0 {
		t.Errorf("counts %v, want {/b: {x: 1}}", body["counts"])
	}
}

// SERVICES-1 (§A.5, §A.4, Open 84): on a query of one namespace, a min
// naming another namespace is 400, the body's min listing it, even one the
// service follows and the reader may see, which v0.51 waited for and
// redirected; no wait comes first.
func TestV074V03ForeignMinStrict(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "schemas"}, minWait: time.Minute})
	w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"})
	at := s.caughtUp("matches")
	sch := s.caughtUp("schemas")
	start := time.Now()
	for _, u := range []string{"/matches?q=derby&min=schemas:" + sch, "/matches/at/" + at + "?q=derby&min=schemas:" + sch,
		"/matches?q=derby&min=matches:" + at + "&min=schemas:" + sch} {
		r := s.raw(u, "")
		if r.status != 400 || r.body["code"] != "bad_input" || fmt.Sprint(r.body["min"]) != fmt.Sprint([]string{"schemas:" + sch}) {
			t.Errorf("%s: %d %v, want 400 listing schemas:%s", u, r.status, r.body, sch)
		}
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("waited %s before refusing", d)
	}
	if r := s.raw("/matches?q=derby&min=matches:"+at, ""); r.status != 302 {
		t.Errorf("a min of matches: %d %v", r.status, r.body)
	}
}

// SERVICES-4 (§A.4): a redirect to another at keeps an after naming a
// resource, applied to the new result, and drops an opaque one (a q or
// sort query's position), starting again. A redirect to the same at, or
// the head pointer's, passes the query on whole.
func TestV074V03RedirectDropsOpaqueAfter(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	w.doc(t, "a1", w.match, map[string]any{"title": "word one"})
	w.doc(t, "a2", w.match, map[string]any{"title": "word two"})
	old := s.caughtUp("matches")
	w.doc(t, "a3", w.match, map[string]any{"title": "word three"})
	cur := s.caughtUp("matches")
	if old == cur {
		t.Fatal("the checkpoint didn't move")
	}
	for _, c := range []struct{ url, want string }{
		// Opaque: q, or sort, pages by position.
		{"/matches/at/" + old + "?after=1&limit=1&q=word", "/matches/at/" + cur + "?limit=1&q=word"},
		{"/matches/at/" + old + "?after=1&limit=1&sort=%2Ftitle", "/matches/at/" + cur + "?limit=1&sort=%2Ftitle"},
		// By name: kept.
		{"/matches/at/" + old + "?after=a1&limit=1", "/matches/at/" + cur + "?after=a1&limit=1"},
		// The head pointer names no at: the query passes whole.
		{"/matches?after=1&limit=1&q=word", "/matches/at/" + cur + "?after=1&limit=1&q=word"},
	} {
		r := s.raw(c.url, "")
		if r.status != 302 || r.header.Get("Location") != c.want {
			t.Errorf("%s: %d %s, want %s", c.url, r.status, r.header.Get("Location"), c.want)
		}
	}
	// The redirect's target answers the first page of the new result.
	b := s.search("/matches/at/"+old+"?after=1&limit=1&q=word", "")
	if b["at"] != cur || len(resources(b)) != 1 {
		t.Errorf("restarted: %v", b)
	}
}

// epochRefusing answers POST {path} asking for epoch 1's key with status
// while armed, as /keys answers a grant that gets no key for it.
type epochRefusing struct {
	path   string
	status atomic.Int32
	rt     http.RoundTripper
}

func (f *epochRefusing) RoundTrip(r *http.Request) (*http.Response, error) {
	if st := f.status.Load(); st != 0 && r.Method == "POST" && r.URL.Path == f.path && r.Body != nil {
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		if bytes.Contains(b, []byte(`"epochs":[1]`)) {
			return &http.Response{StatusCode: int(st), Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"code":"forbidden","message":"injected"}`)), Request: r}, nil
		}
	}
	return f.rt.RoundTrip(r)
}

// SERVICES-5 (§E.2.6, Open 15): a hit served under an epoch whose key the
// service's grant gets none of, for good (a 4xx from /keys), is served by
// name only, resource, id and url and no sealed, in a result sealed per
// entry, on a query of the namespace and on /_refs; a key it can't get for
// now (a 5xx) is still 503 behind.
func TestV074V03NameOnlyWithoutEpochKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"sec", "schemas"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "sec" {
			doc["read"] = "grant"
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	sch := must(w.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{
		"title": map[string]any{"type": "string", "x-index": "text"}, "tag": map[string]any{"type": "string", "x-index": "facet"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	for _, n := range []string{"a", "b"} {
		must(createNonced(w, "sec", n, map[string]any{"$schema": ref, "title": "old " + n, "tag": "t", "related": []any{"/r/target/x"}}))
	}
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	db := filepath.Join(t.TempDir(), "i.db")
	first := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"sec"}, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	first.caughtUp("sec")
	first.stop()
	must(s.Engine.RotateEpoch(ctx, "sec", "system:rotate"))
	must(createNonced(w, "sec", "c", map[string]any{"$schema": ref, "title": "new c", "tag": "t", "related": []any{"/r/target/x"}}))
	// Restarted, the service holds no key of epoch 1, which a and b are
	// served under, and asks /keys for it when it seals their hits.
	fk := &epochRefusing{path: "/ns/sec/keys", rt: transport}
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"sec"}, now: s.Now, hc: &http.Client{Transport: fk}},
		func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("sec")
	whole := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})
	follow := func(path string) resp {
		t.Helper()
		r := x.raw(path, whole)
		if r.status == 302 {
			r = x.raw(r.header.Get("Location"), whole)
		}
		return r
	}

	// For now: behind.
	fk.status.Store(503)
	for _, p := range []string{"/sec?q=old", "/sec?facet%5B%2Ftag%5D=t", "/_refs?to=" + url.QueryEscape("/r/target/x")} {
		if r := follow(p); r.status != 503 || r.body["code"] != "behind" {
			t.Errorf("%s, epoch 1's key for now: %d %v", p, r.status, r.body)
		}
	}
	// For good: by name only.
	fk.status.Store(403)
	for _, c := range []struct {
		path string
		want string // each hit's kid, "" by name only
	}{
		{"/sec?q=old", "map[a: b:]"},
		{"/sec?facet%5B%2Ftag%5D=t", "map[a: b: c:sec#2]"},
		{"/_refs?to=" + url.QueryEscape("/r/target/x"), "map[sec/a: sec/b: sec/c:sec#2]"},
	} {
		f := x.fetch(c.path, whole)
		if f.header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %s, want JSON sealed per entry", c.path, f.header.Get("Content-Type"))
			continue
		}
		if got := p37Kids(t, f.body); fmt.Sprint(got) != c.want {
			t.Errorf("%s: kids %v, want %s", c.path, got, c.want)
		}
		for _, h := range decodeJSON(t, f.body)["hits"].([]any) {
			h := h.(map[string]any)
			if _, sealed := h["sealed"]; sealed {
				continue
			}
			keys := slices.Sorted(maps.Keys(h))
			want := []string{"id", "resource", "url"}
			if _, ok := h["ns"]; ok {
				want = []string{"id", "ns", "resource", "url"}
			}
			if !slices.Equal(keys, want) {
				t.Errorf("%s: a hit by name only has %v", c.path, keys)
			}
		}
	}
	// Counts are served only sealed whole: 400.
	if r := follow("/sec?q=old&counts=/tag"); r.status != 400 || r.body["code"] != "bad_input" {
		t.Errorf("counts over a lacking epoch: %d %v", r.status, r.body)
	}
}
