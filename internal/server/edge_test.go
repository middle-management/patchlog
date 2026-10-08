package server

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
)

const edgeSecret = "edge-s3cret"

func newEdgeEnv(t *testing.T, opts ...envOpt) *tenv {
	t.Helper()
	v, err := edge.New([]byte(edgeSecret), "")
	if err != nil {
		t.Fatal(err)
	}
	return newEnvWith(t, []Option{WithEdge(v)}, opts...)
}

// getEdge reads path with secret in the edge's header ("" for none).
func (e *tenv) getEdge(path, secret string) *resp {
	e.t.Helper()
	q := req{method: "GET", path: path}
	if secret != "" {
		q.hdr = map[string]string{edge.DefaultHeader: secret}
	}
	return e.do(q)
}

// §9: with a verifying edge, private reads need its secret and get edge
// lifetimes; public reads don't care.
func TestEdgeVerifiedPrivateReads(t *testing.T) {
	t.Parallel()
	e := newEdgeEnv(t, withLongPoll(time.Minute))
	e.mkNS("priv", map[string]any{"read": "grant"})
	e.mkNS("pub", map[string]any{"read": "public"})
	priv := e.create("priv", "a", map[string]any{"x": 1.0})
	pub := e.create("pub", "a", map[string]any{"x": 1.0})

	paths := []string{
		"/r/priv/a", "/r/priv/a/rev/" + priv, "/r/priv/a/rev/" + priv + "/log", "/r/priv/a/log",
		"/r/priv/missing", "/ns/priv", "/ns/priv/log", "/ns/priv/branches",
		// A long-poll is refused before it waits.
		"/ns/priv/log?live=long-poll", "/r/priv/a/log?live=long-poll",
	}
	for _, p := range paths {
		for _, secret := range []string{"", "wrong", edgeSecret + "x"} {
			r := e.getEdge(p, secret)
			expectCode(t, r, 403, "edge_required")
			if cc, cdn := r.H.Get("Cache-Control"), r.H.Get("CDN-Cache-Control"); cc != "no-store" || cdn != "" {
				t.Errorf("%s %q: Cache-Control %q, CDN-Cache-Control %q", p, secret, cc, cdn)
			}
		}
	}
	nsHead := etagOf(e.getEdge("/ns/priv", edgeSecret))
	for _, p := range append(paths[:len(paths)-2], "/ns/priv/rev/"+nsHead, "/ns/priv/rev/"+nsHead+"/log", "/ns/priv/rev/"+nsHead+"/heads") {
		r := e.getEdge(p, edgeSecret)
		if r.Code == 403 {
			t.Errorf("%s verified: %d %s", p, r.Code, r.Body)
			continue
		}
		if cc := r.H.Get("Cache-Control"); len(cc) < 7 || cc[:7] != "private" {
			t.Errorf("%s: Cache-Control %q", p, cc)
		}
		if cdn := r.H.Get("CDN-Cache-Control"); cdn == "" || cdn == "no-store" || r.H.Get("Surrogate-Control") != "" {
			t.Errorf("%s: CDN-Cache-Control %q, Surrogate-Control %q", p, cdn, r.H.Get("Surrogate-Control"))
		}
	}
	r := e.getEdge("/r/priv/a/rev/"+priv, edgeSecret)
	expect(t, r, 200)
	if cdn := r.H.Get("CDN-Cache-Control"); cdn != "max-age=86400, s-maxage=31536000, immutable" {
		t.Errorf("immutable edge lifetime %q", cdn)
	}
	if cdn := e.getEdge("/r/priv/a", edgeSecret).H.Get("CDN-Cache-Control"); cdn != "max-age=0, s-maxage=1, stale-while-revalidate=5" {
		t.Errorf("head edge lifetime %q", cdn)
	}
	lp := e.getEdge("/ns/priv/log?live=long-poll&since="+e.getEdge("/ns/priv/rev/"+nsHead+"/log", edgeSecret).Arr()[0].(map[string]any)["id"].(string), edgeSecret)
	if lp.Code != 200 || lp.H.Get("CDN-Cache-Control") != "max-age=0, s-maxage=60" {
		t.Errorf("long-poll: %d %v", lp.Code, lp.H)
	}

	// Public reads are unaffected, with or without the header.
	for _, secret := range []string{"", "wrong", edgeSecret} {
		r := e.getEdge("/r/pub/a/rev/"+pub, secret)
		expect(t, r, 200)
		if cc := r.H.Get("Cache-Control"); cc != ccImmutable || r.H.Get("CDN-Cache-Control") != "" {
			t.Errorf("public %q: %v", secret, r.H)
		}
		if r := e.getEdge("/ns/pub", secret); r.Code != 302 || r.H.Get("Cache-Control") != ccHead {
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
