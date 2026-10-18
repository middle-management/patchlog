package tree_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// A listing is 503 behind until the service holds a checkpoint of every
// namespace it follows: the catalog, and each namespace the catalog
// trusts, which a service started with a fresh database (or trusting it
// lately) catches up with after the catalog. Meanwhile every placement of
// an item there would be missing (§B.3), and a folder shown empty that
// isn't, which a sync tool mirrors as deleted files (§H.3). A trusted
// namespace the service can't follow (one that doesn't exist) isn't
// waited for.
func TestListingsWaitForTrusted(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	var hold atomic.Bool
	hold.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		for hold.Load() && strings.HasPrefix(req.URL.Path, "/ns/matches/") && (strings.Contains(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events") || strings.Contains(req.URL.Path, "/heads")) {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		return base.RoundTrip(req)
	})
	core := w.s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	x := startSvc(t, core, svcOpts{})
	t.Cleanup(func() { hold.Store(false) })
	x.caughtUp("cat")
	r := x.raw("/cat/children?of=season", "")
	for r.status == http.StatusFound {
		r = x.raw(r.header.Get("Location"), "")
	}
	if r.status != http.StatusServiceUnavailable || r.body["code"] != "behind" || !strings.Contains(r.body["message"].(string), "matches") || r.header.Get("Retry-After") == "" {
		t.Fatalf("a listing before matches has a checkpoint: %d %v %v", r.status, r.header, r.body)
	}
	hold.Store(false)
	x.caughtUp("matches")
	if got := names(x.get("/cat/children?of=season", "")["children"]); got != "matches.opener,matches.derby" {
		t.Fatalf("once caught up: %s", got)
	}

	// Trusting a namespace that doesn't exist: listings don't wait for it.
	ctx := context.Background()
	h := must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "nosuch"}}))
	x.caughtUp("cat")
	waitFor(t, "a listing while nosuch can't be followed", func() bool {
		r := x.raw("/cat/children?of=season", "")
		return r.status == http.StatusFound || r.status == http.StatusOK
	})
}

// listing follows the pointer's redirect and returns the answer.
func (s *svc) listing(path string) resp {
	s.t.Helper()
	r := s.raw(path, "")
	for r.status == http.StatusFound {
		r = s.raw(r.header.Get("Location"), "")
	}
	return r
}

// A checkpoint isn't caught up: a log longer than a page is replayed a
// page at a time (§10 Catch up), and the first sets the checkpoint. A
// listing stays 503 behind until the follower has reached the head it
// read when it started, not just its first page, whose items alone would
// show season with 1 of its 5 files (§H.3: a sync tool deletes the rest).
// Once caught up, a restart on the same database doesn't wait again
// (meta "caught:{ns}"): it lists what it holds while it catches up.
func TestListingsWaitForCatchUp(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("tester"))
	ctx := context.Background()
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	w := &world{s: s, c: c}
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season", "root")
	items := []string{"m1", "m2", "m3", "m4", "m5"}
	for _, it := range items {
		w.content(t, "matches", it)
		w.place(t, "matches."+it, "season")
	}
	// Every page of matches' log after the first is held.
	var hold, held atomic.Bool
	hold.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if strings.HasPrefix(req.URL.Path, "/ns/matches/") && strings.HasSuffix(req.URL.Path, "/log") && req.URL.Query().Get("since") != "" {
			held.Store(true)
			for hold.Load() {
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		return base.RoundTrip(req)
	})
	core := s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, core, svcOpts{db: db})
	t.Cleanup(func() { hold.Store(false) })
	x.caughtUp("cat")
	waitFor(t, "matches' second page asked for", held.Load)
	waitFor(t, "matches' first page applied", func() bool { return x.s.Checkpoint("matches") != "" })
	if r := x.listing("/cat/children?of=season"); r.status != http.StatusServiceUnavailable || r.body["code"] != "behind" ||
		!strings.Contains(r.body["message"].(string), "matches") {
		t.Fatalf("a listing while matches is caught up to its first page only: %d %v", r.status, r.body)
	}
	hold.Store(false)
	x.caughtUp("matches")
	if got := names(x.listing("/cat/children?of=season").body["children"]); got != "matches.m1,matches.m2,matches.m3,matches.m4,matches.m5" {
		t.Fatalf("once caught up: %s", got)
	}
	x.stop()

	// Caught up once: a restart holding matches' log again lists at once.
	w.content(t, "matches", "m6")
	w.content(t, "matches", "m7")
	w.content(t, "matches", "m8")
	w.place(t, "matches.m6", "season")
	hold.Store(true)
	held.Store(false)
	y := startSvc(t, core, svcOpts{db: db})
	y.caughtUp("cat")
	waitFor(t, "matches' log asked for after the restart", held.Load)
	if r := y.listing("/cat/children?of=season"); r.status != http.StatusOK || names(r.body["children"]) != "matches.m1,matches.m2,matches.m3,matches.m4,matches.m5" {
		t.Fatalf("a listing after a restart, caught up with matches before: %d %v", r.status, r.body)
	}
	hold.Store(false)
	y.caughtUp("matches")
}

// A trusted namespace the service couldn't follow (here trusted before it
// exists: 404) isn't waited for, and a ?min= naming it is the 400 for a
// namespace the service doesn't follow, not a wait for a checkpoint that
// doesn't come (§A.5). Once the core serves its head, the service follows
// it again, and listings wait for it until caught up, rather than list its
// placements dangling.
func TestListingsWaitForFollowable(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	ctx := context.Background()
	h := must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "late"}}))
	var hold, seen atomic.Bool
	hold.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if strings.HasPrefix(req.URL.Path, "/ns/late/") && strings.HasSuffix(req.URL.Path, "/log") {
			seen.Store(true)
			for hold.Load() {
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		return base.RoundTrip(req)
	})
	core := w.s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	x := startSvc(t, core, svcOpts{})
	t.Cleanup(func() { hold.Store(false) })
	x.caughtUp("cat", "matches")
	waitFor(t, "a listing while late doesn't exist", func() bool { return x.listing("/cat/children?of=season").status == http.StatusOK })
	min := "late:" + x.s.Checkpoint("matches")
	if r := x.raw("/cat/children?of=season&min="+min, ""); r.status != http.StatusBadRequest {
		t.Fatalf("a min naming late, which the service can't follow: %d %v", r.status, r.body)
	}

	must(w.c.CreateNamespace(ctx, "late", map[string]any{"read": "public"}))
	w.content(t, "late", "x")
	w.place(t, "late.x", "season@a2")
	x.caughtUp("cat")
	waitFor(t, "the follower to catch up with late", seen.Load)
	if r := x.listing("/cat/children?of=season"); r.status != http.StatusServiceUnavailable || !strings.Contains(r.body["message"].(string), "late") {
		t.Fatalf("a listing while late is caught up with: %d %v", r.status, r.body)
	}
	hold.Store(false)
	x.caughtUp("late")
	if got := names(x.listing("/cat/children?of=season").body["children"]); got != "matches.opener,matches.derby,late.x" {
		t.Fatalf("once caught up with late: %s", got)
	}
}

// A trusted sealed namespace whose keys the service can't get (its grant
// has an enc and no recipient key is configured, Addendum E) is skipped,
// and isn't waited for: listings answer with its placements dangling, not
// 503 behind for good, and a min naming it is the 400.
func TestListingsSkipKeyless(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"vault": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"pub":   {"read": "grant", "keys": []any{k.Entry("*")}},
		"cat":   {"read": "public", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"pub", "vault"}, "mode": "dag"}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "pub", "vault"}
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"})))
	must(wr.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(wr.CreateDoc(ctx, "pub", "plan", map[string]any{"title": "plan"}))
	must(wr.CreateDoc(ctx, "cat", "pub.plan", map[string]any{"parents": parents("root@a0")}))
	must(wr.CreateDoc(ctx, "cat", "vault.v", map[string]any{"parents": parents("root@a1")}))
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, map[string]any{"enc": jwk})))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "pub")
	var r resp
	waitFor(t, "a listing with vault skipped", func() bool {
		r = x.listing("/cat/children?of=root")
		return r.status == http.StatusOK
	})
	if got := names(r.body["children"]); got != "pub.plan" {
		t.Fatalf("root with vault skipped: %s", got)
	}
	if r := x.raw("/cat/children?of=root&min=vault:"+x.s.Checkpoint("pub"), ""); r.status != http.StatusBadRequest {
		t.Fatalf("a min naming vault, skipped for its keys: %d %v", r.status, r.body)
	}
}

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
