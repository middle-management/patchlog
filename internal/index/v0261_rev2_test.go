package index_test

// Regression tests from the second review of the v0.26.1 index fixes: a
// grant checker document the index never applied is not necessarily newer
// than what it applied. One from before what it applied first (a snapshot
// bootstrap's document, or one applied by an index restarted since) must
// not be trusted as a widening (stillPublic decides by the chain's order).

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v0261StaleHead wraps a core so that GET /ns/pr can be captured once and
// replayed later (a cache or a lagging replica in front of the core), as
// TestV0261StaleCheckerAfterNarrowing does.
type v0261StaleHead struct {
	capture, replay atomic.Bool
	replayed        atomic.Int32
	mu              sync.Mutex
	stale           *httptest.ResponseRecorder
}

func (st *v0261StaleHead) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/ns/pr" {
			h.ServeHTTP(rw, r)
			return
		}
		st.mu.Lock()
		old := st.stale
		st.mu.Unlock()
		if st.replay.Load() && old != nil {
			st.replayed.Add(1)
			for k, v := range old.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(old.Code)
			rw.Write(old.Body.Bytes())
			return
		}
		if st.capture.Load() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			st.mu.Lock()
			st.stale = rec
			st.mu.Unlock()
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			rw.Write(rec.Body.Bytes())
			return
		}
		h.ServeHTTP(rw, r)
	})
}

// v0261CheckAnon asks /pr anonymously while the checker reads the stale
// (public) head and fails if pr, private at its head and in ns_conf, is
// answered or a result is kept under the public URL.
func v0261CheckAnon(t *testing.T, x *svc, st *v0261StaleHead) {
	t.Helper()
	st.replay.Store(true)
	x.ix.ExpireGrantChecks() // the checker reloads pr now, from the stale head
	r := x.raw("/pr?limit=9", "")
	loc := r.header.Get("Location")
	var at resp
	if r.status == 302 && strings.HasPrefix(loc, "/pr/at/") {
		at = x.raw(loc, "")
	}
	st.replay.Store(false)
	t.Logf("anonymous /pr, the checker's head stale (%d replayed): %d Location=%q; %d %v cc=%q", st.replayed.Load(), r.status, loc, at.status, at.body, at.header.Get("Cache-Control"))
	if r.status == 200 || at.status == 200 {
		t.Errorf("pr, private, answered to an anonymous reader from a stale head: %d / %d %v (Cache-Control %q)", r.status, at.status, at.body, at.header.Get("Cache-Control"))
	}
	if strings.HasPrefix(loc, "/pr/at/") && x.ix.KeptHas(loc) {
		t.Errorf("a result of pr, private, kept under the public URL %s", loc)
	}
}

// TestV0261StaleCheckerBeforeSnapshotBootstrap: pr is public, then made
// private, and written to while private. An index bootstraps it from a
// snapshot (follow.WithSnapshot) at its head: ns_conf private. The grant
// checker reloads pr from a stale head from before the narrowing
// (public). That document was never applied by this index because it
// predates the snapshot, not because it is newer: it is no widening, and
// pr's private hits are not served publicly.
func TestV0261StaleCheckerBeforeSnapshotBootstrap(t *testing.T) {
	ctx := context.Background()
	st := &v0261StaleHead{}
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: st.wrap})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public then"}))
	st.capture.Store(true)
	must(w.NSHead(ctx, "pr"))
	st.capture.Store(false)
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	must(w.CreateDoc(ctx, "pr", "b", map[string]any{"title": "written while private"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.CheckerTTL = 30 * time.Second
			o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot())
		})
	x.appliedUpTo(x.caughtUp("pr"))
	v0261CheckAnon(t, x, st)
}

// TestV0261StaleCheckerAfterRestart: an index applied pr's public genesis
// and is restarted on its database. pr is then made private: ns_conf
// private, idx:pr purged. The grant checker reloads pr from a stale head
// from before the narrowing (public, the genesis): it precedes the
// index's checkpoint in pr's chain, so it is not trusted as a widening.
// (Against 2941055, which recorded the config revisions an index applied
// and trusted any other, this is a database from before that record.)
func TestV0261StaleCheckerAfterRestart(t *testing.T) {
	ctx := context.Background()
	st := &v0261StaleHead{}
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: st.wrap})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public then"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	db := filepath.Join(t.TempDir(), "i.db")
	x1 := startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
	x1.caughtUp("pr")
	x1.stop()
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second })
	x.caughtUp("pr")
	st.capture.Store(true)
	must(w.NSHead(ctx, "pr"))
	st.capture.Store(false)
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	must(w.CreateDoc(ctx, "pr", "b", map[string]any{"title": "written while private"}))
	x.appliedUpTo(x.caughtUp("pr"))
	v0261CheckAnon(t, x, st)
}

// TestV0261CheckerReloadRacesObserve: as TestV0261StaleCheckerAfterRestart,
// with no cache in front of the core: the
// checker's own reload races Apply. An anonymous query's read check
// reloads pr's head (public) just before pr is made private; Apply
// commits the narrowing, tells the checker (Observe: nothing cached yet
// to drop) and purges idx:pr; the reload then stores the public document,
// fresh for CheckerTTL (default 30s). Grantcheck's stateWithin stores what
// it loaded whatever Observe did meanwhile, so the stale public document
// is what accessChanged's stillPublic sees. It must not be trusted, or
// pr's hits, b written while private included, are computed after the
// purge and served and kept in the public URL space. The test skips where
// the race isn't hit.
func TestV0261CheckerReloadRacesObserve(t *testing.T) {
	ctx := context.Background()
	var armed atomic.Bool
	var target atomic.Value
	target.Store("")
	blocked, release := make(chan struct{}), make(chan struct{})
	var relOnce sync.Once
	rel := func() { relOnce.Do(func() { close(release) }) }
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			// The checker's load reads the document at the head it read
			// (public); held until the narrowing is applied.
			if r.Method != "GET" || r.URL.Path != target.Load().(string) || !armed.CompareAndSwap(true, false) {
				h.ServeHTTP(rw, r)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r) // the document at the head before the narrowing: public
			close(blocked)
			<-release // answered after the narrowing is applied
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			rw.Write(rec.Body.Bytes())
		})
	}})
	t.Cleanup(rel)
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public then"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	db := filepath.Join(t.TempDir(), "i.db")
	x1 := startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
	x1.caughtUp("pr")
	x1.stop()
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second }) // the default
	// A write the restarted follower applies: it is past its start (which
	// reads the encryption at the head) before the hold is armed.
	must(w.CreateDoc(ctx, "pr", "c", map[string]any{"title": "after the upgrade"}))
	x.appliedUpTo(x.caughtUp("pr"))
	hd := must(w.NSHead(ctx, "pr"))
	cfg := hd.Config
	target.Store("/ns/pr/rev/" + hd.ID)
	x.ix.ExpireGrantChecks()
	armed.Store(true)
	got := make(chan resp, 1)
	go func() { got <- x.raw("/pr?limit=9", "") }()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Skip("the checker never reloaded pr's head (its state was loaded before the hold): the race wasn't exercised")
	}
	select {
	case r := <-got:
		t.Skipf("the query was answered (%d) while the read held was another's: the race wasn't exercised", r.status)
	default:
	}
	must(w.PatchConfig(ctx, "pr", cfg, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	must(w.CreateDoc(ctx, "pr", "b", map[string]any{"title": "written while private"}))
	cur := x.caughtUp("pr")
	x.appliedUpTo(cur)
	rel()
	ptr := <-got
	loc := ptr.header.Get("Location")
	t.Logf("pr's head before the narrowing %s; the index's checkpoint once applied %s", hd.ID, cur)
	t.Logf("anonymous /pr, its read check's reload racing the narrowing, answered after it was applied: %d Location=%q %v", ptr.status, loc, ptr.body)
	// Everything below is asked once pr's narrowing is applied and idx:pr
	// purged: none of it may be answered to an anonymous reader.
	if ptr.status == 302 && strings.HasPrefix(loc, "/pr/at/") {
		at := x.raw(loc, "")
		t.Logf("GET %s: %d %v cc=%q", loc, at.status, at.body, at.header.Get("Cache-Control"))
		if at.status == 200 {
			t.Errorf("pr, private and applied so (idx:pr purged), answered to an anonymous reader at %s: %v (Cache-Control %q)", loc, at.body, at.header.Get("Cache-Control"))
		}
		if x.ix.KeptHas(loc) {
			t.Errorf("a result of pr, private, kept under the public URL %s", loc)
		}
	}
	if r := x.raw("/pr?limit=8", ""); r.status == 302 {
		if a := x.raw(r.header.Get("Location"), ""); a.status == 200 {
			t.Errorf("a later anonymous /pr, the checker's stale state cached for CheckerTTL: %s 200 %v", r.header.Get("Location"), a.body)
		}
	}
}

// v0261ForgetConf deletes ns's ns_conf row from the stopped index's
// database db: a database whose namespace had no config entry applied
// since ns_conf was added.
func v0261ForgetConf(t *testing.T, db, ns string) {
	t.Helper()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	defer sq.Close()
	if _, err := sq.Exec(`DELETE FROM ns_conf WHERE ns = ?`, ns); err != nil {
		t.Fatal(err)
	}
}

// TestV0261MissingConfSeededPublic: an index database holds a checkpoint
// of pr, public, but no read mode applied for it (ns_conf). Restarted, it
// serves pr anonymously: the read mode is seeded from pr's document at
// the checkpoint, neither left to the checker nor taken as private.
func TestV0261MissingConfSeededPublic(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	db := filepath.Join(t.TempDir(), "i.db")
	x1 := startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
	x1.caughtUp("pr")
	x1.stop()
	v0261ForgetConf(t, db, "pr")
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second })
	x.caughtUp("pr")
	if r := x.follow("/pr?limit=5", ""); r.status != 200 {
		t.Errorf("anonymous /pr, public, its read mode not recorded: %d %v, want 200", r.status, r.body)
	}
}

// TestV0261MissingConfStaleChecker: as TestV0261MissingConfSeededPublic,
// with pr made private before the index's checkpoint, and the grant
// checker reloading pr from a stale head from before (public). The read
// mode seeded from pr's document at the checkpoint is private: the
// anonymous query is 401, nothing computed in the public URL space.
func TestV0261MissingConfStaleChecker(t *testing.T) {
	ctx := context.Background()
	st := &v0261StaleHead{}
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: st.wrap})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public then"}))
	st.capture.Store(true)
	must(w.NSHead(ctx, "pr"))
	st.capture.Store(false)
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	must(w.CreateDoc(ctx, "pr", "b", map[string]any{"title": "written while private"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	db := filepath.Join(t.TempDir(), "i.db")
	x1 := startSvc(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now})
	x1.caughtUp("pr")
	x1.stop()
	v0261ForgetConf(t, db, "pr")
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second })
	x.caughtUp("pr")
	v0261CheckAnon(t, x, st)
	st.replay.Store(true)
	x.ix.ExpireGrantChecks()
	r := x.raw("/pr?limit=4", "")
	st.replay.Store(false)
	if r.status != 401 {
		t.Errorf("anonymous /pr, private at the checkpoint, its read mode not recorded, the checker's head stale: %d %v, want 401", r.status, r.body)
	}
}
