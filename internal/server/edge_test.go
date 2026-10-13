package server

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
)

const edgeSecret = "edge-s3cret"

func newEdgeEnv(t *testing.T, opts ...envOpt) *tenv {
	t.Helper()
	v, err := edge.New([]byte(edgeSecret), "", "")
	if err != nil {
		t.Fatal(err)
	}
	return newEnvWith(t, []Option{WithEdge(v)}, opts...)
}

// getEdge reads path with secret and prefix in the edge's headers ("" for
// none) and the extra headers hdr, as name, value pairs.
func (e *tenv) getEdge(path, secret, prefix string, hdr ...string) *resp {
	e.t.Helper()
	q := req{method: "GET", path: path, hdr: map[string]string{}}
	if secret != "" {
		q.hdr[edge.DefaultHeader] = secret
	}
	if prefix != "" {
		q.hdr[edge.DefaultPrefixHeader] = prefix
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		q.hdr[hdr[i]] = hdr[i+1]
	}
	return e.do(q)
}

// expectNoStore checks that a private response is served, private
// downstream and no-store for every shared cache (§9).
func expectNoStore(t *testing.T, what string, r *resp) {
	t.Helper()
	if r.Code == 403 || r.Code >= 500 {
		t.Errorf("%s: %d %s", what, r.Code, r.Body)
	}
	if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
		t.Errorf("%s: Cache-Control %q", what, cc)
	}
	if cdn, sc := r.H.Get("CDN-Cache-Control"), r.H.Get("Surrogate-Control"); cdn != "no-store" || sc != "no-store" {
		t.Errorf("%s: CDN-Cache-Control %q, Surrogate-Control %q", what, cdn, sc)
	}
}

// §9: with a verifying edge, private reads are served with or without its
// headers; only a read it verified itself, with the secret and a prefix
// covering the URL and no other credential, gets edge lifetimes, and every
// other one is no-store. Public reads don't care.
func TestEdgeVerifiedPrivateReads(t *testing.T) {
	t.Parallel()
	e := newEdgeEnv(t, withLongPoll(time.Minute))
	e.mkNS("priv", map[string]any{"read": "grant"})
	e.mkNS("pub", map[string]any{"read": "public"})
	priv := e.create("priv", "a", map[string]any{"x": 1.0})
	pub := e.create("pub", "a", map[string]any{"x": 1.0})
	nsHead := e.nsHead("priv")

	// Each private path, with the narrowest prefix an edge grant covering
	// it has, and the namespace-wide one.
	paths := []struct{ path, prefix, wide string }{
		{"/r/priv/a", "/r/priv/a", "/r/priv"},
		{"/r/priv/a/rev/" + priv, "/r/priv/a", "/r/priv"},
		{"/r/priv/a/rev/" + priv + "/log", "/r/priv/a", "/r/priv"},
		{"/r/priv/a/log", "/r/priv/a", "/r/priv"},
		{"/r/priv/a/log?live=long-poll", "/r/priv/a", "/r/priv"},
		{"/r/priv/missing", "/r/priv/missing", "/r/priv"},
		{"/ns/priv", "/ns/priv", "/ns/priv"},
		{"/ns/priv/log", "/ns/priv", "/ns/priv"},
		{"/ns/priv/log?live=long-poll", "/ns/priv", "/ns/priv"},
		{"/ns/priv/branches", "/ns/priv", "/ns/priv"},
		{"/ns/priv/rev/" + nsHead, "/ns/priv", "/ns/priv"},
		{"/ns/priv/rev/" + nsHead + "/log", "/ns/priv", "/ns/priv"},
		{"/ns/priv/rev/" + nsHead + "/heads", "/ns/priv", "/ns/priv"},
	}
	for _, p := range paths {
		other := "/r/priv"
		if strings.HasPrefix(p.path, "/r/") {
			other = "/ns/priv"
		}
		// Not verified by the edge: served all the same, no-store.
		for _, tc := range []struct {
			name, secret, prefix string
			hdr                  []string
		}{
			{"no headers", "", "", nil},
			{"wrong secret", "wrong", p.prefix, nil},
			{"longer secret", edgeSecret + "x", p.prefix, nil},
			{"prefix only", "", p.prefix, nil},
			{"secret only", edgeSecret, "", nil},
			{"another resource", edgeSecret, "/r/priv/b", nil},
			{"not by segment", edgeSecret, p.wide + "-x", nil},
			{"cut short", edgeSecret, p.wide[:len(p.wide)-1], nil},
			{"another kind", edgeSecret, other, nil},
			{"malformed", edgeSecret, "/", nil},
			{"Authorization", edgeSecret, p.prefix, []string{"Authorization", "Bearer x"}},
			{"Source-Authorization", edgeSecret, p.prefix, []string{"Source-Authorization", "Bearer x"}},
		} {
			expectNoStore(t, p.path+" "+tc.name, e.getEdge(p.path, tc.secret, tc.prefix, tc.hdr...))
		}
		// Verified by the edge: edge lifetimes, and no Surrogate-Control.
		for _, prefix := range []string{p.prefix, p.wide} {
			r := e.getEdge(p.path, edgeSecret, prefix)
			if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
				t.Errorf("%s verified: %d Cache-Control %q", p.path, r.Code, cc)
			}
			if cdn := r.H.Get("CDN-Cache-Control"); cdn == "" || cdn == "no-store" || r.H.Get("Surrogate-Control") != "" {
				t.Errorf("%s verified under %s: CDN-Cache-Control %q, Surrogate-Control %q", p.path, prefix, cdn, r.H.Get("Surrogate-Control"))
			}
		}
	}
	verified := func(path, prefix string) *resp { return e.getEdge(path, edgeSecret, prefix) }
	r := verified("/r/priv/a/rev/"+priv, "/r/priv/a")
	expect(t, r, 200)
	if cdn := r.H.Get("CDN-Cache-Control"); cdn != "max-age=86400, s-maxage=31536000, immutable" {
		t.Errorf("immutable edge lifetime %q", cdn)
	}
	if cdn := verified("/r/priv/a", "/r/priv").H.Get("CDN-Cache-Control"); cdn != "max-age=0, s-maxage=1, stale-while-revalidate=5" {
		t.Errorf("head edge lifetime %q", cdn)
	}
	since := verified("/ns/priv/rev/"+nsHead+"/log", "/ns/priv").Arr()[0].(map[string]any)["id"].(string)
	lp := verified("/ns/priv/log?live=long-poll&since="+since, "/ns/priv")
	if lp.Code != 200 || lp.H.Get("CDN-Cache-Control") != "max-age=0, s-maxage=60" {
		t.Errorf("long-poll: %d %v", lp.Code, lp.H)
	}
	// The same reads around the edge are served.
	expect(t, e.getEdge("/r/priv/a/rev/"+priv, "", ""), 200)
	expect(t, e.getEdge("/ns/priv/log?live=long-poll&since="+since, "", ""), 200)

	// Public reads are unaffected, with or without the headers.
	for _, secret := range []string{"", "wrong", edgeSecret} {
		r := e.getEdge("/r/pub/a/rev/"+pub, secret, "/r/pub")
		expect(t, r, 200)
		if cc := r.H.Get("Cache-Control"); cc != ccImmutable || r.H.Get("CDN-Cache-Control") != "" {
			t.Errorf("public %q: %v", secret, r.H)
		}
		if r := e.getEdge("/ns/pub", secret, "/ns/pub"); r.Code != 302 || r.H.Get("Cache-Control") != ccHead {
			t.Errorf("public ns head %q: %d %v", secret, r.Code, r.H)
		}
	}

	// Writes aren't reads: they don't need the edge (and are no-store).
	w := e.write("PATCH", "priv", "a", priv, ops(op("add", "/y", 2.0)))
	expect(t, w, 201)
	if w.H.Get("Cache-Control") != "no-store" {
		t.Errorf("write Cache-Control %q", w.H.Get("Cache-Control"))
	}
}

// §9: a private long-poll is no longer refused around the edge before it
// waits: it waits, and its answer is no-store unless the edge verified it.
func TestEdgePrivateLongPollWaits(t *testing.T) {
	t.Parallel()
	e := newEdgeEnv(t, withLongPoll(200*time.Millisecond))
	e.mkNS("priv", map[string]any{"read": "grant"})
	a := e.create("priv", "a", map[string]any{"x": 1.0})
	path := "/r/priv/a/log?live=long-poll&since=" + a
	r := e.getEdge(path, "", "")
	expect(t, r, 204)
	expectNoStore(t, "around the edge", r)
	r = e.getEdge(path, edgeSecret, "/r/priv/a")
	expect(t, r, 204)
	if r.H.Get("CDN-Cache-Control") != "max-age=0, s-maxage=2" || r.H.Get("Surrogate-Control") != "" {
		t.Errorf("verified: %v", r.H)
	}
}

// v0.50 §C.5: a path with an empty segment, a trailing "/" included, is
// 400 as one with a dot segment or a percent-escape is; "/" itself isn't.
func TestTrailingSlashBadInput(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("demo", map[string]any{"read": "public"})
	e.create("demo", "x", map[string]any{})
	for _, p := range []string{"/r/demo/x/", "/ns/demo/", "/r/demo/", "/r/demo//x", "/r/demo/x/log/", "/edge-grants/",
		"/r/demo/./x", "/r/demo/x/.", "/r/demo/../demo/x", "/r/demo/%78"} {
		expectCode(t, e.get(p), 400, "bad_input")
	}
	expect(t, e.get("/"), 200)
	expect(t, e.get("/r/demo/x"), 302)
}

// §9: without a verifying edge, private responses are no-store for shared
// caches; public ones keep their lifetimes.
func TestNoEdgePrivateNoStore(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLongPoll(time.Minute))
	e.mkNS("priv", map[string]any{"read": "grant"})
	e.mkNS("pub", map[string]any{"read": "public"})
	priv := e.create("priv", "a", map[string]any{})
	pub := e.create("pub", "a", map[string]any{})
	nsHead := e.nsHead("priv")
	since := e.get("/ns/priv/rev/" + nsHead + "/log").Arr()[0].(map[string]any)["id"].(string)
	for _, p := range []string{"/r/priv/a", "/r/priv/a/rev/" + priv, "/r/priv/a/rev/" + priv + "/log", "/r/priv/missing",
		"/ns/priv", "/ns/priv/rev/" + nsHead, "/ns/priv/rev/" + nsHead + "/log", "/ns/priv/rev/" + nsHead + "/heads",
		"/ns/priv/branches", "/ns/priv/log?live=long-poll&since=" + since} {
		r := e.get(p)
		if cdn, sc := r.H.Get("CDN-Cache-Control"), r.H.Get("Surrogate-Control"); cdn != "no-store" || sc != "no-store" {
			t.Errorf("%s: %d CDN-Cache-Control %q, Surrogate-Control %q", p, r.Code, cdn, sc)
		}
	}
	r := e.get("/r/pub/a/rev/" + pub)
	if r.H.Get("Cache-Control") != ccImmutable || r.H.Get("CDN-Cache-Control") != "" || r.H.Get("Surrogate-Control") != "" {
		t.Errorf("public: %v", r.H)
	}
}

type recPurger struct {
	mu   sync.Mutex
	tags [][]string
}

func (p *recPurger) PurgeTags(tags []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tags = append(p.tags, slices.Clone(tags))
}

// take returns the purges so far and forgets them.
func (p *recPurger) take() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.tags
	p.tags = nil
	return out
}

func purged(calls [][]string, tag string) bool {
	for _, c := range calls {
		if slices.Contains(c, tag) {
			return true
		}
	}
	return false
}

// §9: making a public namespace private purges ns:{ns}; other config
// writes don't.
func TestPurgeOnPublicToPrivate(t *testing.T) {
	t.Parallel()
	rec := &recPurger{}
	e := newEnv(t, func(o *core.Options) { o.Purger = rec })
	e.mkNS("docs", map[string]any{"read": "public"})
	e.create("docs", "a", map[string]any{})
	rec.take()

	// Unrelated config write of a public namespace.
	expect(t, e.patchNS("docs", ops(op("add", "/maxLag", "PT1H")), ""), 201)
	if calls := rec.take(); purged(calls, "ns:docs") {
		t.Errorf("unrelated config write purged: %v", calls)
	}
	// public → private.
	expect(t, e.patchNS("docs", ops(op("replace", "/read", "grant")), ""), 201)
	if calls := rec.take(); !purged(calls, "ns:docs") {
		t.Errorf("public→private: purges %v", calls)
	}
	// Unrelated write of a private namespace.
	expect(t, e.patchNS("docs", ops(op("replace", "/maxLag", "PT2H")), ""), 201)
	if calls := rec.take(); purged(calls, "ns:docs") {
		t.Errorf("private config write purged: %v", calls)
	}
	// private → public.
	expect(t, e.patchNS("docs", ops(op("replace", "/read", "public")), ""), 201)
	if calls := rec.take(); purged(calls, "ns:docs") {
		t.Errorf("private→public purged: %v", calls)
	}
	// The change also purges when it comes with a batch's config.
	expect(t, e.do(req{method: "POST", path: "/ns/docs/batch", author: "admin", body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("docs"), "patches": ops(op("replace", "/read", "grant"))},
		"items":  []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}},
	}}), 201)
	if calls := rec.take(); !purged(calls, "ns:docs") {
		t.Errorf("public→private in a batch: purges %v", calls)
	}
}
