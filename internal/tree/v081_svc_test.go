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
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/tree"
)

// §C.2 item 5, §B.11.5 (v0.78): a grant with a key-scope or block rule on
// /now is refused every read, so it doesn't read the catalog unrestricted
// (problems 403) and reads no listing, nor is it exchanged for an edge
// grant.
func TestV081SvcReadNowTree(t *testing.T) {
	t.Parallel()
	clock := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "exists": true}}}
	q := newP24World(t, "grant", "grant").start(withEdgeGrants)
	cl := q.grant("user:cl", []string{"cat", "matches"}, clock)
	amy := q.grant("user:amy", []string{"cat", "matches"})
	if r := q.do("GET", q.x.atURL("/cat/problems", amy), amy, ""); r.status != 200 {
		t.Fatalf("problems, a namespace-wide reader: %d %v", r.status, r.body)
	}
	for _, path := range []string{"/cat/problems", "/cat/g/all/problems", "/cat/children?of=root"} {
		if r := q.do("GET", path, cl, ""); r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s with a block rule on /now: %d %q %v", path, r.status, r.header.Get("Cache-Control"), r.body)
		}
	}
	req := must(http.NewRequest("POST", q.x.http.URL+"/edge-grants", nil))
	req.Header.Set("Authorization", "Bearer "+cl)
	r := must(noRedirect.Do(req))
	r.Body.Close()
	if r.StatusCode != 403 || len(r.Cookies()) != 0 {
		t.Errorf("exchange with a block rule on /now: %d %v", r.StatusCode, r.Cookies())
	}
}

// §B.11.5, §B.11.9 gs (v0.78): no gs leaves a group out, so an edge
// grant whose subject set was stored holding "partial", under an earlier
// draft, is 403, no-store, until the reader exchanges again, without a
// Profiler too: served as it is it would show what a group it left out
// hides.
func TestV081SvcStoredPartialRefused(t *testing.T) {
	t.Parallel()
	q := newP24World(t, "grant", "grant").start(withEdgeGrants)
	bob := q.scoped("user:bob", "root", "season", "matches.derby")
	prefix, ck := q.exchange(bob)
	r := q.do("GET", prefix+"/children?of=root", "", "", ck)
	if r.status != 302 {
		t.Fatalf("cookie's head pointer: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	if r = q.do("GET", loc, "", "", ck); r.status != 200 {
		t.Fatalf("cookie at its at: %d %v", r.status, r.body)
	}
	gs := strings.TrimPrefix(prefix, "/cat/g/")
	subs := []string{"partial", "scope:matches.derby", "scope:root", "scope:season"}
	if err := q.x.s.RecordSubjects(context.Background(), gs, subs, q.s.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{prefix + "/children?of=root", loc} {
		if r = q.do("GET", path, "", "", ck); r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("a stored partial set at %s: %d %q %v", path, r.status, r.header.Get("Cache-Control"), r.body)
		}
	}
	// Exchanged again, the set is the grant's own and reads.
	prefix2, ck2 := q.exchange(bob)
	if prefix2 != prefix {
		t.Fatalf("exchanged again for %s", prefix2)
	}
	if r = q.do("GET", loc, "", "", ck2); r.status != 200 {
		t.Errorf("exchanged again: %d %v", r.status, r.body)
	}
}

// §E.2.6, v0.78: a namespace is e2e only from its creation, so the born
// epoch of an e2e namespace's revision comes from its own sealed op, never
// from a kid the origin serves with the entry, which only revisions
// sealed before a raise carried.
func TestV081SvcSnapshotBornEpochIgnoresKid(t *testing.T) {
	t.Parallel()
	if e := tree.SnapshotBornEpoch("e3", client.LogEntry{ID: "a", Kid: "e3#2"}); e != 0 {
		t.Errorf("a served kid without a patch set: %d", e)
	}
	plain := client.LogEntry{ID: "a", Kid: "e3#2", HasPatches: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}
	if e := tree.SnapshotBornEpoch("e3", plain); e != tree.BornPending {
		t.Errorf("a served kid with a patch set that isn't the namespace's sealed op: %d", e)
	}
}

// v081StopWorld is a catalog cat (read catRead) trusting pub and sec (read
// contentRead), each holding a placed document (pub.p, sec.s, titled),
// with a tree service following them, whose reads of sec's log the core
// refuses (403) while refuse is set: the service stops following sec
// (purgeStopped), and follows it again once the refusal passes.
type v081StopWorld struct {
	s      *clienttest.Server
	k      clienttest.Key
	x      *svc
	db     string
	refuse *atomic.Bool
}

func newV081StopWorld(t *testing.T, catRead, contentRead string, mods ...func(*tree.Options)) *v081StopWorld {
	t.Helper()
	ctx := context.Background()
	refuse := &atomic.Bool{}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
		Wrap: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if refuse.Load() && strings.HasPrefix(r.URL.Path, "/ns/sec/") && strings.HasSuffix(r.URL.Path, "/log") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					w.Write([]byte(`{"code":"forbidden","message":"injected"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}})
	k := clienttest.NewKey("k")
	all := []string{"cat", "pub", "sec"}
	for _, ns := range all {
		doc := map[string]any{"read": contentRead, "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["read"], doc["catalog"] = catRead, map[string]any{"trust": []any{"pub", "sec"}, "mode": "dag", "title": "/title"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "pub", "p", map[string]any{"title": "Open p8qz"}))
	must(w.CreateDoc(ctx, "sec", "s", map[string]any{"title": "Secret vw3k"}))
	must(w.CreateDoc(ctx, "cat", "pub.p", map[string]any{"parents": parents("root@a0")}))
	must(w.CreateDoc(ctx, "cat", "sec.s", map[string]any{"parents": parents("root@b0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db}, mods...)
	x.caughtUp("cat", "pub", "sec")
	return &v081StopWorld{s: s, k: k, x: x, db: db, refuse: refuse}
}

// stop refuses the service sec's log until it stops following sec.
func (w *v081StopWorld) stop(t *testing.T) {
	t.Helper()
	w.refuse.Store(true)
	waitFor(t, "sec stopped", func() bool { return v0261Stopped(t, w.db, "sec") })
}

// §B.5 Behind, §B.7, §B.11.5 (ACCESS-11, Q24): a namespace the service
// stopped following, for keys it lacks or a refusal, isn't followed: it
// is out of the combined checkpoint, so a public catalog's listings over
// the namespaces that stay in are served unfiltered to anyone, without
// its items, whose placements dangle ("unfollowed") and are listed by
// problems; once followed again, its placements are live again at a new
// at. Before, every anonymous reader got 401.
func TestV081SvcStoppedNotFollowed(t *testing.T) {
	t.Parallel()
	w := newV081StopWorld(t, "public", "public")
	at0 := w.x.s.At()
	if st, _, b, _ := v0261Get(w.x, "/cat/children?of=root", ""); st != 200 || !strings.Contains(b, "sec.s") || !strings.Contains(b, "p8qz") {
		t.Fatalf("setup: %d %s", st, b)
	}
	w.stop(t)
	at1 := w.x.s.At()
	if at1 == at0 {
		t.Errorf("the at didn't move on stop")
	}
	st, hdr, b, loc := v0261Get(w.x, "/cat/children?of=root", "")
	if st != 200 || !strings.Contains(b, "p8qz") || strings.Contains(b, "sec.s") || strings.Contains(b, "vw3k") || !strings.Contains(hdr.Get("Cache-Control"), "public") {
		t.Errorf("anonymous listing with sec stopped: %d %q %s %s", st, hdr.Get("Cache-Control"), loc, b)
	}
	if !strings.HasPrefix(loc, "/cat/at/"+at1+"/") {
		t.Errorf("listed at %s, want the at without sec %s", loc, at1)
	}
	st, _, b, _ = v0261Get(w.x, "/cat/problems", "")
	if st != 200 || !strings.Contains(b, "sec.s") || !strings.Contains(b, "unfollowed") {
		t.Errorf("problems with sec stopped: %d %s", st, b)
	}
	w.refuse.Store(false)
	waitFor(t, "sec followed again", func() bool {
		st, _, b, _ := v0261Get(w.x, "/cat/children?of=root", "")
		return st == 200 && strings.Contains(b, "sec.s")
	})
	if w.x.s.At() == at1 {
		t.Errorf("the at didn't move once followed again")
	}
	if st, _, b, _ := v0261Get(w.x, "/cat/problems", ""); st != 200 || strings.Contains(b, "unfollowed") {
		t.Errorf("problems once followed again: %d %s", st, b)
	}
	// After a restart on the same store, a stop recorded holds while the
	// service still can't follow sec (a new entry it can't read): its
	// placements are derived from it at load.
	w.stop(t)
	wr := w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "user:w", []string{"sec"}, []string{"read", "create"})))
	must(wr.CreateDoc(context.Background(), "sec", "later", map[string]any{"title": "Later"}))
	w.x.stop()
	sc := w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:tree", []string{"cat", "pub", "sec"}, []string{"read"})))
	x := startSvc(t, sc, svcOpts{now: w.s.Now, db: w.db})
	x.caughtUp("cat", "pub")
	if st, _, b, _ := v0261Get(x, "/cat/children?of=root", ""); st != 200 || strings.Contains(b, "sec.s") {
		t.Errorf("after a restart, sec stopped: %d %s", st, b)
	}
}

// §B.11.5 g/all (ACCESS-11): a g/all edge grant issued while sec is
// stopped, and so out of the combined checkpoint, was checked without it:
// once sec is followed again it enters the checkpoint, and the cookie is
// 403 at an at that includes it, until the reader exchanges again.
func TestV081SvcStoppedEntersAgain(t *testing.T) {
	t.Parallel()
	w := newV081StopWorld(t, "grant", "grant", func(o *tree.Options) {
		o.RoleView, o.EdgeGrants, o.EdgeGrantsOwnKey = scopeView{}, edge.NewCookies("tree-cat", nil), true
	})
	w.stop(t)
	w.s.Clock.Advance(2 * time.Second)
	amy := w.k.Grant(t, w.s.Now(), "user:amy", []string{"cat", "pub", "sec"}, []string{"read"})
	p := &p24World{t: t, s: w.s, x: w.x}
	prefix, ck := p.exchange(amy)
	if prefix != "/cat/g/all" {
		t.Fatalf("exchanged for %s", prefix)
	}
	if r := p.do("GET", "/cat/g/all/children?of=root", "", "", ck); r.status != 302 {
		t.Fatalf("g/all with sec stopped: %d %v", r.status, r.body)
	}
	at := w.x.s.At()
	w.s.Clock.Advance(2 * time.Second)
	w.refuse.Store(false)
	waitFor(t, "sec followed again", func() bool { return !v0261Stopped(t, w.db, "sec") && w.x.s.At() != at })
	r := p.do("GET", "/cat/g/all/children?of=root", "", "", ck)
	if r.status == 302 {
		r = p.do("GET", r.header.Get("Location"), "", "", ck)
	}
	if r.status != 403 {
		t.Errorf("the g/all cookie once sec entered the checkpoint again: %d %v", r.status, r.body)
	}
}
