package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82encTombSource is a v081Source whose x A pruned at T, the tombstone on
// x2 and x's head at at, with the snapshot of x2: x1, x2 (P), T.
func v82encTombSource(t *testing.T) (s *v081Source, x2, tomb, snap string) {
	t.Helper()
	s = newV081Source(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	x2 = s.write("x", s.x1, ops(op("replace", "/v", 2.0)))
	tomb = s.a.del("m", "x", x2, s.root())
	s.a.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(s.k1, "m#1", "m", "x", x2, map[string]any{"v": 2.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, s.a.prune("m", "x", map[string]any{"horizon": tomb, "snapshot": snap}, s.root()), 200)
	s.at = s.a.nsHead("m", s.root())
	return s, x2, tomb, snap
}

// v82encFront fronts A, answering GET path as serve does and everything
// else as A does.
func v82encFront(t *testing.T, a *tenv, serve map[string]func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	tg, _ := url.Parse(a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(tg)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := serve[r.URL.Path]; f != nil && r.Method == "GET" {
			f(w)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	return front
}

func v82encJSON(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

// E2E-6 (§G.5.2 E3 sources, §G.3, §7.1, §3.4; scenario 75, FED-24): where
// A pruned x at the tombstone T that is its head at at, B learns T's
// parent P as the last of A's 410 for /rev/{T}, checks it against T's id
// and mirrors A's snapshot at P byte for byte. B then answers itself:
// /rev/{P} is A's JWE, /rev/{T} is 410 with tombstone and last, and an id
// below A's horizon, which B never verified, is 404. Before v0.82 this
// creation was 410 pruned. The mirrored snapshot, which sits at its
// resource's horizon, survives the cleanup a later start makes (E2E-5).
func TestV082RemoteTombstoneHorizonAtHead(t *testing.T) {
	t.Parallel()
	s, x2, tomb, snap := v82encTombSource(t)
	p := newV077Proxy(t, s.a, nil)
	var path string
	ks := newKeyStore(t)
	b := newV081B(t, s, p.srv.URL, withFileDB(t), func(o *core.Options) { path = o.Path }, withKeyStore(ks))
	_, g := v081Remote(t, b, s, "r")
	if n := p.count("GET /r/m/x/rev/" + tomb); n == 0 {
		t.Fatal("B never asked A for /rev/{T}")
	}
	asked := p.count("GET /r/m/x/rev/"+x2) + p.count("GET /r/m/x/rev/"+tomb)
	check := func(b *tenv, what string) {
		t.Helper()
		r := b.get("/r/r/x/rev/"+x2, g)
		if r.Code != 200 || string(r.Body) != snap || r.H.Get("Content-Type") != seal.ContentType {
			t.Fatalf("%s: B at P: %d %.200s", what, r.Code, r.Body)
		}
		if h, err := seal.ParseHeader(string(r.Body)); err != nil || h.PL["ns"] != "m" || h.PL["id"] != x2 || h.Kid != "m#1" {
			t.Fatalf("%s: header %v %v", what, h, err)
		}
		r = b.get("/r/r/x/rev/"+tomb, g)
		expectCode(t, r, 410, "gone")
		if r.Str("tombstone") != tomb || r.Str("last") != x2 {
			t.Fatalf("%s: B at T: %s", what, r.Body)
		}
		if h := b.get("/r/r/x", g); h.Code != 410 || h.Str("tombstone") != tomb || h.Str("last") != x2 {
			t.Fatalf("%s: B's head: %d %s", what, h.Code, h.Body)
		}
		// Below A's horizon: an id B never verified.
		if r := b.get("/r/r/x/rev/"+s.x1, g); r.Code != 404 || r.Str("code") == "not_offered" {
			t.Fatalf("%s: B below A's horizon: %d %s", what, r.Code, r.Body)
		}
	}
	check(b, "after creation")
	if after := p.count("GET /r/m/x/rev/"+x2) + p.count("GET /r/m/x/rev/"+tomb); after != asked {
		t.Fatalf("B asked A %d times at read time", after-asked)
	}
	// A later start on B's database: cleanStaleSnapshots keeps the row.
	b2 := newV081B(t, s, p.srv.URL, withPath(path), withKeyStore(ks))
	check(b2, "after another start")
}

// E2E-6: where a restore follows A's tombstone horizon, B has long learnt
// P from A's not_offered; a not_offered that names no last leaves the
// tombstone's own 410, which names it.
func TestV082RemoteTombstoneHorizonNotOfferedWithoutLast(t *testing.T) {
	t.Parallel()
	s := newV081Source(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	x2 := s.write("x", s.x1, ops(op("replace", "/v", 2.0)))
	tomb := s.a.del("m", "x", x2, s.root())
	l := etagOf(s.a.writeRaw("m", "x", tomb, "[]", s.root()))
	s.a.clock.Advance(10 * time.Minute)
	snap, _ := seal.SealSnapshot(s.k1, "m#1", "m", "x", x2, map[string]any{"v": 2.0})
	expect(t, s.a.prune("m", "x", map[string]any{"horizon": tomb, "snapshot": snap}, s.root()), 200)
	s.at = s.a.nsHead("m", s.root())
	front := v82encFront(t, s.a, map[string]func(http.ResponseWriter){
		"/r/m/x/rev/" + l: v82encJSON(404, `{"code":"not_offered","horizon":"`+tomb+`"}`),
	})
	b := newV081B(t, s, front.URL)
	_, g := v081Remote(t, b, s, "r")
	if r := b.get("/r/r/x/rev/"+x2, g); r.Code != 200 || string(r.Body) != snap {
		t.Fatalf("B at P: %d %.200s", r.Code, r.Body)
	}
	r := b.get("/r/r/x/rev/"+l, g)
	expectCode(t, r, 404, "not_offered")
	if r.Str("horizon") != tomb || r.Str("last") != x2 {
		t.Fatalf("B at a later id: %s", r.Body)
	}
}

// E2E-6 against a hostile or older A: the 410 of /rev/{T} is read as the
// snapshot is, capped and without following a redirect; a last that isn't
// T's parent, another tombstone, or a snapshot whose pl.id or kid doesn't
// match is a creation 502 upstream with nothing kept; a 410 without last,
// as A answered before v0.82, keeps the creation 410 pruned.
func TestV082RemoteTombstoneHorizonHostile(t *testing.T) {
	t.Parallel()
	s, x2, tomb, snap := v82encTombSource(t)
	atT, _ := seal.SealSnapshot(s.k1, "m#1", "m", "x", tomb, map[string]any{"v": 2.0})
	atX1, _ := seal.SealSnapshot(s.k1, "m#1", "m", "x", s.x1, map[string]any{"v": 1.0})
	foreign, _ := seal.SealSnapshot(s.k1, "q#1", "q", "x", x2, map[string]any{"v": 2.0})
	kidOnly, _ := seal.Seal(s.k1, "q#1", seal.SnapshotPL("m", "x", x2), []byte(`{"v":2}`))
	var hit int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	t.Cleanup(target.Close)
	jose := func(jwe string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) { w.Header().Set("Content-Type", seal.ContentType); w.Write([]byte(jwe)) }
	}
	gone := func(last string) func(http.ResponseWriter) {
		return v82encJSON(410, `{"code":"gone","tombstone":"`+tomb+`","last":"`+last+`"}`)
	}
	revT, revP := "/r/m/x/rev/"+tomb, "/r/m/x/rev/"+x2
	for name, c := range map[string]struct {
		serve  map[string]func(http.ResponseWriter)
		status int
		code   string
	}{
		"control":                {nil, 201, ""},
		"last isn't T's parent":  {map[string]func(http.ResponseWriter){revT: gone(s.x1), "/r/m/x/rev/" + s.x1: jose(atX1)}, 502, "upstream"},
		"last isn't an id":       {map[string]func(http.ResponseWriter){revT: gone("nope")}, 502, "upstream"},
		"another tombstone":      {map[string]func(http.ResponseWriter){revT: v82encJSON(410, `{"code":"gone","tombstone":"`+x2+`","last":"`+x2+`"}`)}, 502, "upstream"},
		"last without tombstone": {map[string]func(http.ResponseWriter){revT: v82encJSON(410, `{"code":"gone","last":"`+x2+`"}`)}, 502, "upstream"},
		"no last (before v0.82)": {map[string]func(http.ResponseWriter){revT: v82encJSON(410, `{"code":"gone"}`)}, 410, "pruned"},
		"tombstone without last": {map[string]func(http.ResponseWriter){revT: v82encJSON(410, `{"code":"gone","tombstone":"`+tomb+`"}`)}, 410, "pruned"},
		"a 410 that isn't JSON":  {map[string]func(http.ResponseWriter){revT: v82encJSON(410, `gone`)}, 410, "pruned"},
		"the 410 over the cap":   {map[string]func(http.ResponseWriter){revT: v82encJSON(410, `{"code":"gone","tombstone":"`+tomb+`","last":"`+x2+`","pad":"`+strings.Repeat("A", 3<<20)+`"}`)}, 502, "upstream"},
		"the 410 behind a redirect": {map[string]func(http.ResponseWriter){revT: func(w http.ResponseWriter) {
			w.Header().Set("Location", target.URL+"/x")
			w.WriteHeader(http.StatusFound)
		}}, 502, "upstream"},
		"the snapshot behind a redirect": {map[string]func(http.ResponseWriter){revP: func(w http.ResponseWriter) {
			w.Header().Set("Location", target.URL+"/x")
			w.WriteHeader(http.StatusFound)
		}}, 502, "upstream"},
		"a snapshot bound to T":           {map[string]func(http.ResponseWriter){revP: jose(atT)}, 502, "upstream"},
		"a snapshot bound to another id":  {map[string]func(http.ResponseWriter){revP: jose(atX1)}, 502, "upstream"},
		"a snapshot of another namespace": {map[string]func(http.ResponseWriter){revP: jose(foreign)}, 502, "upstream"},
		"a snapshot under another kid":    {map[string]func(http.ResponseWriter){revP: jose(kidOnly)}, 502, "upstream"},
		"a snapshot not served as jose":   {map[string]func(http.ResponseWriter){revP: v82encJSON(200, snap)}, 502, "upstream"},
		"no snapshot at P":                {map[string]func(http.ResponseWriter){revP: v82encJSON(410, `{"code":"pruned","horizon":"`+tomb+`"}`)}, 502, "upstream"},
	} {
		t.Run(name, func(t *testing.T) {
			front := v82encFront(t, s.a, c.serve)
			var path string
			b := newV081B(t, s, front.URL, withFileDB(t), func(o *core.Options) { path = o.Path })
			kB := newKey("badmin")
			mk := func() *resp {
				return b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
			}
			r := mk()
			if c.status == 201 {
				expect(t, r, 201)
				return
			}
			expectCode(t, r, c.status, c.code)
			// Nothing was kept: no snapshot, and the name is free (not 412).
			db, pg := v0261DB(t, path)
			if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM e2e_snapshots`); n != 0 {
				t.Fatalf("%d snapshots stored by a refused creation", n)
			}
			expectCode(t, mk(), c.status, c.code)
		})
	}
	if hit != 0 {
		t.Fatalf("B followed A's redirect %d times", hit)
	}
}
