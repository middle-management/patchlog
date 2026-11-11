package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/index"
)

// v82xIndex is an index of matches served by w, an origin: its grant
// reads matches and both catalogs, its clock is the origin's.
type v82xIndex struct {
	t   *testing.T
	w   *v75s
	ix  *index.Index
	url string
}

func newV82XIndex(t *testing.T, w *v75s) *v82xIndex {
	t.Helper()
	g := w.grant(w.k, "svc:indexer", []string{"matches", "cat-season", "cat-season-r"}, []string{"read"},
		map[string]any{"exp": w.clock.Now().Add(24 * time.Hour).Format(time.RFC3339)})
	c, err := plclient.New(w.srv.URL, plclient.WithBearer(g))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := index.Open(context.Background(), index.Options{Client: c, DB: filepath.Join(t.TempDir(), "i.db"), Namespaces: []string{"matches"},
		UntypedListing: true, Now: w.clock.Now, CheckerTTL: time.Millisecond, RepurgeInterval: -1,
		Logf:          func(f string, a ...any) { t.Logf(f, a...) },
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(ix.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ix.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); ix.Close() })
	return &v82xIndex{t: t, w: w, ix: ix, url: hs.URL}
}

// caughtUp waits until the index applied matches's head and re-reads the
// documents its grant checks use.
func (x *v82xIndex) caughtUp(admin string) {
	x.t.Helper()
	head := x.w.nsHead("matches", admin)
	deadline := time.Now().Add(30 * time.Second)
	for x.ix.Checkpoint("matches") != head {
		if time.Now().After(deadline) {
			x.t.Fatalf("the index didn't reach matches's head %s (at %s)", head, x.ix.Checkpoint("matches"))
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond) // past CheckerTTL
}

// get is one answer of the index to bearer, redirects not followed.
func (x *v82xIndex) get(path, bearer string) (int, http.Header, map[string]any) {
	x.t.Helper()
	rq, err := http.NewRequest("GET", x.url+path, nil)
	if err != nil {
		x.t.Fatal(err)
	}
	rq.Header.Set("Authorization", "Bearer "+bearer)
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := hc.Do(rq)
	if err != nil {
		x.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			x.t.Fatalf("GET %s: %d %s", path, res.StatusCode, raw)
		}
	}
	return res.StatusCode, res.Header, body
}

// hits is what a query of matches answers bearer, a partial reader: the gs
// its redirect names and the resources of its hits, sorted.
func (x *v82xIndex) hits(what, bearer string) (gs string, names []string) {
	x.t.Helper()
	code, h, body := x.get("/matches", bearer)
	loc := h.Get("Location")
	p := strings.Split(loc, "/")
	if code != 302 || len(p) != 6 || p[1] != "matches" || p[2] != "g" || p[4] != "at" {
		x.t.Fatalf("%s: the index answers /matches %d %q %v, want a redirect to /matches/g/{gs}/at/{at}", what, code, loc, body)
	}
	code, h, body = x.get(loc, bearer)
	if code != 200 {
		x.t.Fatalf("%s: the index answers %s %d %v", what, loc, code, body)
	}
	if tags := h.Get("Cache-Tag"); strings.Contains(tags, "cat-season-r") {
		x.t.Errorf("%s: the index's Cache-Tag %q names the dark catalog", what, tags)
	}
	if nss, _ := body["namespaces"].(map[string]any); nss["cat-season-r"] != nil {
		x.t.Errorf("%s: the index's at covers the dark catalog: %v", what, nss)
	}
	names = []string{}
	for _, hv := range body["hits"].([]any) {
		names = append(names, hv.(map[string]any)["resource"].(string))
	}
	slices.Sort(names)
	return p[3], names
}

// heads is what the origin's filtered /heads lists for bearer, a partial
// reader: the gs its redirect names and the resources, sorted.
func v82xHeads(t *testing.T, w *v75s, what, admin, bearer string) (gs string, names []string) {
	t.Helper()
	r := w.get("/ns/matches/rev/"+w.nsHead("matches", admin)+"/heads", bearer)
	loc := r.H.Get("Location")
	p := strings.Split(loc, "/")
	if r.Code != 302 || len(p) != 8 || p[3] != "g" || p[5] != "at" {
		t.Fatalf("%s: the origin answers /heads %d %q %s", what, r.Code, loc, r.Body)
	}
	r = w.get(loc, bearer)
	expect(t, r, 200)
	names = headNames(t, r)
	slices.Sort(names)
	return p[4], names
}

// XT-1 (6), ACC-7o and SVC-09 together (SERVICES §B.11.9 Where, v0.82:
// "a trusted catalog makes nothing visible where it is a branch, local or
// remote"; §A.4; scenario 119, both halves against one deployment):
// matches trusts only cat-season-r, a real remote branch of another
// origin's catalog, which read through places derby for li. The origin
// and an index of it agree: matches is covered at both (each redirects li
// to URLs of a subject set), and each shows her nothing:
// no row in her filtered /heads, no hit, never the documents her rules
// alone would pass. With the live catalog cat-season trusted beside it,
// both show her exactly what that one places, shared, through either key,
// and nothing only the branch places. An unrestricted reader sees
// everything at both throughout.
func TestV082XScenario119OriginAndIndexAgree(t *testing.T) {
	t.Parallel()
	w, admin := v82accessRemoteCatalog(t, v75sOpts{})
	w.seed([]string{"shared"}, nil, []string{"derby", "opener", "shared"})
	x := newV82XIndex(t, w)
	all := w.grant(w.k, "user:root", []string{"matches"}, []string{"read"})
	unrestricted := func(what string) {
		t.Helper()
		// The index redirects every reader to a checkpoint.
		code, h, body := x.get("/matches", all)
		if loc := h.Get("Location"); code != 302 || !strings.HasPrefix(loc, "/matches/") {
			t.Fatalf("%s: the index answers an unrestricted reader %d %q %v", what, code, loc, body)
		} else {
			code, _, body = x.get(loc, all)
		}
		var names []string
		for _, hv := range body["hits"].([]any) {
			names = append(names, hv.(map[string]any)["resource"].(string))
		}
		slices.Sort(names)
		r := w.get("/ns/matches/rev/"+w.nsHead("matches", admin)+"/heads", all)
		expect(t, r, 200)
		on := headNames(t, r)
		slices.Sort(on)
		if code != 200 || !slices.Equal(names, on) || !slices.Equal(on, []string{"derby", "opener", "shared"}) {
			t.Errorf("%s: an unrestricted reader gets %d %v from the index, %v from the origin", what, code, names, on)
		}
	}

	// Only the remote branch is trusted: covered, and dark, at both.
	expect(t, w.patchNS("matches", ops(
		op("replace", "/catalogs", map[string]any{"cat-season-r": map[string]any{"place": []any{}}}),
		op("replace", "/keys/1/requireAt", "cat-season-r")), admin), 201)
	x.caughtUp(admin)
	li := v82accessVia(w, admin, "cat-season-r")
	ogs, heads := v82xHeads(t, w, "the branch alone", admin, li)
	igs, hits := x.hits("the branch alone", li)
	if len(heads) != 0 || len(hits) != 0 {
		t.Errorf("the branch alone: li gets heads %v from the origin and hits %v from the index, want none at either", heads, hits)
	}
	// The index's gs is that of her marker, reads:matches:g:{gs}, over
	// the origin's (SERVICES §A.4), not the origin's own.
	if want := grantcheck.SubjectSetID([]string{"reads:matches:g:" + ogs}); ogs == "" || igs != want {
		t.Errorf("the branch alone: gs %q at the index, want %q, that of reads:matches:g:%s, the origin's", igs, want, ogs)
	}
	unrestricted("the branch alone")

	// The live catalog beside it, each through a key of its own: only the
	// live one decides, at both.
	expect(t, w.patchNS("matches", ops(
		op("replace", "/keys/1/requireAt", "cat-season"),
		op("add", "/catalogs/cat-season", map[string]any{"place": []any{}}),
		op("add", "/keys/-", map[string]any{"kid": "catalog-02", "alg": "ed25519", "pub": w.cat.pub, "can": []any{"read"},
			"requireAt": "cat-season-r", "maxTtl": "PT15M",
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}})), admin), 201)
	x.caughtUp(admin)
	for what, li := range map[string]string{
		"beside the live catalog, through its key": v82accessVia(w, admin, "cat-season"),
		"beside the live catalog, through the branch's key": w.grant(w.cat, "user:li", []string{"matches"}, []string{"read"}, map[string]any{"kid": "catalog-02",
			"groups": []any{"editors", "interns"}, "roles": []any{"reader"}, "at": map[string]any{"ns": "cat-season-r", "id": w.nsHead("cat-season-r", admin)},
			"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)}),
	} {
		_, heads := v82xHeads(t, w, what, admin, li)
		_, hits := x.hits(what, li)
		if !slices.Equal(heads, []string{"shared"}) || !slices.Equal(hits, heads) {
			t.Errorf("%s: li gets heads %v from the origin and hits %v from the index, want shared alone at both", what, heads, hits)
		}
	}
	unrestricted("beside the live catalog")
}
