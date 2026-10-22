package tree_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/tree"
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

// Caught up as the checkpoint reaching the catch-up's head is published,
// not a moment later: a listing made as soon as the service holds that
// checkpoint (here from its OnApply, which runs before the follower
// returns from the catch-up) isn't 503 behind.
func TestListingsCaughtUpWithCheckpoint(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	head := must(w.c.NSHead(context.Background(), "matches")).ID
	var hold atomic.Bool
	hold.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		for hold.Load() && strings.HasPrefix(req.URL.Path, "/ns/matches/") && strings.HasSuffix(req.URL.Path, "/log") {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		return base.RoundTrip(req)
	})
	core := w.s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	var url atomic.Pointer[string]
	var status atomic.Int64
	x := startSvc(t, core, svcOpts{}, func(o *tree.Options) {
		prev := o.OnApply
		o.OnApply = func(b *follow.Batch) {
			prev(b)
			if u := url.Load(); u != nil && b.NS == "matches" && b.NewCheckpoint == head {
				res, err := noRedirect.Get(*u + "/cat/children?of=season")
				if err == nil {
					res.Body.Close()
					status.Store(int64(res.StatusCode))
				}
			}
		}
	})
	t.Cleanup(func() { hold.Store(false) })
	x.caughtUp("cat")
	url.Store(&x.http.URL)
	hold.Store(false)
	x.caughtUp("matches")
	waitFor(t, "the listing from OnApply", func() bool { return status.Load() != 0 })
	if st := status.Load(); st != http.StatusFound && st != http.StatusOK {
		t.Fatalf("a listing as the checkpoint reaching the catch-up's head is out: %d", st)
	}
}

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A sealed trusted namespace whose epoch key can't be fetched for the
// moment (the core's /keys cut off: a transport error, a 5xx, a 429) is
// skipped, nothing of it consumed, but still waited for (Addendum E,
// §B.5, §H.3): listings are 503 behind, never 200 without its items, as
// they are for one skipped for the service's keys as configured
// (TestListingsSkipKeyless); once the key comes, it is caught up with.
func TestListingsTransientKeyError(t *testing.T) {
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
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(wr.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(wr.CreateDoc(ctx, "pub", "plan", map[string]any{"title": "plan"}))
	createNonced(t, wr, "vault", "v", map[string]any{"title": "v"})
	must(wr.CreateDoc(ctx, "cat", "pub.plan", map[string]any{"parents": parents("root@a0")}))
	must(wr.CreateDoc(ctx, "cat", "vault.v", map[string]any{"parents": parents("root@a1")}))
	// The core's /ns/vault/keys asked for epoch keys is cut off after its
	// first answer (the client's own, reading vault's document), until
	// failing is cleared.
	var failing, failed atomic.Bool
	var asked atomic.Int64
	failing.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && req.URL.Path == "/ns/vault/keys" && req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(b))
			if strings.Contains(string(b), "epochs") && asked.Add(1) > 1 && failing.Load() {
				failed.Store(true)
				return nil, errors.New("connection reset by peer")
			}
		}
		return base.RoundTrip(req)
	})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})), client.WithKeys(client.NewKeys(nil)),
		client.WithHTTPClient(&http.Client{Transport: rt}))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	t.Cleanup(func() { failing.Store(false) })
	x.caughtUp("cat", "pub")
	waitFor(t, "vault's epoch key asked for", failed.Load)
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r := x.listing("/cat/children?of=root"); r.status != http.StatusServiceUnavailable {
			t.Fatalf("a listing while vault's epoch key can't be fetched for the moment: %d %s, want 503 behind", r.status, names(r.body["children"]))
		}
	}
	failing.Store(false)
	x.caughtUp("vault")
	if got := names(x.listing("/cat/children?of=root").body["children"]); got != "pub.plan,vault.v" {
		t.Fatalf("once vault's key came: %s", got)
	}
}

// TestListingsTransientKeyError for an end-to-end namespace the service
// holds a keyring recipient key for: its epoch key comes through the
// relay's POST /keys or the keyring (client.E2E), and those cut off for
// the moment are a failure asking again may mend, not "no keys" (the
// service's configuration): the namespace is still waited for, listings
// 503 behind, never 200 without its items; once its key comes, it is
// caught up with.
func TestListingsTransientKeyErrorE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"secret": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}},
		"pub":    {"read": "grant", "keys": []any{k.Entry("*")}},
		"cat":    {"read": "public", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"pub", "secret"}, "mode": "dag"}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	svcJWK, svcPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	wJWK, wPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	all := []string{"cat", "pub", "secret"}
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"}, map[string]any{"enc": wJWK})),
		client.WithKeys(client.NewKeys(wPriv)))
	x2 := wr.E2E(wPriv)
	must(x2.InitKeyring(ctx, "secret", svcPriv.PublicKey()))
	must(wr.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(wr.CreateDoc(ctx, "pub", "plan", map[string]any{"title": "plan"}))
	must(x2.CreateDocSealed(ctx, "secret", "s1", map[string]any{"title": "e2e"}))
	must(wr.CreateDoc(ctx, "cat", "pub.plan", map[string]any{"parents": parents("root@a0")}))
	must(wr.CreateDoc(ctx, "cat", "secret.s1", map[string]any{"parents": parents("root@a1")}))
	// secret's keys (the relay's POST /keys, the keyring) are cut off
	// until failing is cleared.
	var failing, failed atomic.Bool
	failing.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if failing.Load() && (req.URL.Path == "/ns/secret/keys" || strings.Contains(req.URL.Path, "secret") && strings.Contains(req.URL.Path, client.KeyringName)) {
			failed.Store(true)
			return nil, errors.New("connection reset by peer")
		}
		return base.RoundTrip(req)
	})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, map[string]any{"enc": svcJWK})),
		client.WithKeys(client.NewKeys(svcPriv)), client.WithHTTPClient(&http.Client{Transport: rt}), client.WithKeyringSenders(wPriv.PublicKey()))
	x := startSvc(t, sc, svcOpts{now: s.Now}, func(o *tree.Options) { o.Recipient = svcPriv })
	t.Cleanup(func() { failing.Store(false) })
	x.caughtUp("cat", "pub")
	waitFor(t, "secret's epoch key asked for", failed.Load)
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r := x.listing("/cat/children?of=root"); r.status != http.StatusServiceUnavailable {
			t.Fatalf("a listing while secret's epoch key can't be fetched for the moment: %d %s, want 503 behind", r.status, names(r.body["children"]))
		}
	}
	failing.Store(false)
	x.caughtUp("secret")
	if got := names(x.listing("/cat/children?of=root").body["children"]); got != "pub.plan,secret.s1" {
		t.Fatalf("once secret's key came: %s", got)
	}
}

// A namespace the catalog stops trusting loses its caught mark, so that
// trusted again it is waited for while its follower replays what was
// placed in between (§B.5, §H.3), even when its follower, stopped only
// after the apply that untrusted it, reports its catch-up done after
// that apply: the report is dropped. Here late's follower, restarted on
// the same database, has read late's head when late is untrusted.
func TestCaughtNotAfterUntrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "late", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches", "late"}, "mode": "dag"}}))
	w := &world{s: s, c: c}
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season", "root")
	w.content(t, "matches", "m1")
	w.place(t, "matches.m1", "season@a0")
	w.content(t, "late", "l1")
	w.place(t, "late.l1", "season@a1")
	var armed, held, release, returned, holdLog atomic.Bool
	var heads atomic.Int64
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if armed.Load() && req.Method == http.MethodGet && req.URL.Path == "/ns/late" && heads.Add(1) == 2 {
			// The first is keys.Check's, the second the catch-up's head:
			// held, then answered though the follower is stopped meanwhile.
			held.Store(true)
			for !release.Load() {
				time.Sleep(5 * time.Millisecond)
			}
			res, err := base.RoundTrip(req.WithContext(context.WithoutCancel(req.Context())))
			returned.Store(true)
			return res, err
		}
		if holdLog.Load() && strings.HasPrefix(req.URL.Path, "/ns/late/") && (strings.HasSuffix(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events") || strings.Contains(req.URL.Path, "/poll")) {
			for holdLog.Load() {
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		return base.RoundTrip(req)
	})
	t.Cleanup(func() { release.Store(true); holdLog.Store(false) })
	core := s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, core, svcOpts{db: db})
	x.caughtUp("cat", "matches", "late")
	waitFor(t, "a whole listing", func() bool {
		r := x.listing("/cat/children?of=season")
		return r.status == http.StatusOK && names(r.body["children"]) == "matches.m1,late.l1"
	})
	x.stop()
	armed.Store(true)
	y := startSvc(t, core, svcOpts{db: db})
	waitFor(t, "late's catch-up head asked for", held.Load)
	h := must(c.NSHead(ctx, "cat"))
	must(c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{"matches"}}}))
	y.caughtUp("cat")
	release.Store(true)
	waitFor(t, "the held head answered", returned.Load)
	time.Sleep(200 * time.Millisecond)
	w.content(t, "late", "l2")
	w.place(t, "late.l2", "season@a2")
	holdLog.Store(true)
	h = must(c.NSHead(ctx, "cat"))
	must(c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "late"}}))
	y.caughtUp("cat")
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r := y.listing("/cat/children?of=season"); r.status != http.StatusServiceUnavailable {
			t.Fatalf("a listing while late, trusted again, is caught up with: %d %s (late.l2 missing), want 503 behind", r.status, names(r.body["children"]))
		}
	}
	holdLog.Store(false)
	y.caughtUp("late")
	if got := names(y.listing("/cat/children?of=season").body["children"]); got != "matches.m1,late.l1,late.l2" {
		t.Fatalf("once caught up with late: %s", got)
	}
}

// A catch-up report of a follower stopped since (ensureFollowers, at the
// end of the apply that untrusted its namespace) is dropped, also once
// the namespace is trusted again (§B.5, §H.3): its head was read before
// what was placed in between, and taken, it would mark the namespace
// caught while its new follower is still replaying that, and listings
// would answer 200 short of those items. TestCaughtNotAfterUntrust with
// the held head answered only after late is trusted again.
func TestCaughtNotFromStoppedFollower(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "late", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches", "late"}, "mode": "dag"}}))
	w := &world{s: s, c: c}
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season", "root")
	w.content(t, "matches", "m1")
	w.place(t, "matches.m1", "season@a0")
	w.content(t, "late", "l1")
	w.place(t, "late.l1", "season@a1")
	var armed, held, release, returned, holdLog atomic.Bool
	var heads atomic.Int64
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if armed.Load() && req.Method == http.MethodGet && req.URL.Path == "/ns/late" && heads.Add(1) == 2 {
			// The catch-up's head, read now (H1, before l2), and handed
			// to the follower only once released, by then stopped.
			res, err := base.RoundTrip(req.WithContext(context.WithoutCancel(req.Context())))
			held.Store(true)
			for !release.Load() {
				time.Sleep(5 * time.Millisecond)
			}
			returned.Store(true)
			return res, err
		}
		if holdLog.Load() && strings.HasPrefix(req.URL.Path, "/ns/late/") && (strings.HasSuffix(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events") || strings.Contains(req.URL.Path, "/poll")) {
			for holdLog.Load() {
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		return base.RoundTrip(req)
	})
	t.Cleanup(func() { release.Store(true); holdLog.Store(false) })
	core := s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, core, svcOpts{db: db})
	x.caughtUp("cat", "matches", "late")
	waitFor(t, "a whole listing", func() bool {
		r := x.listing("/cat/children?of=season")
		return r.status == http.StatusOK && names(r.body["children"]) == "matches.m1,late.l1"
	})
	x.stop()
	armed.Store(true)
	y := startSvc(t, core, svcOpts{db: db})
	waitFor(t, "late's catch-up head read", held.Load)
	// Untrusted: its follower is stopped (still holding H1).
	h := must(c.NSHead(ctx, "cat"))
	must(c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{"matches"}}}))
	y.caughtUp("cat")
	// Meanwhile l2 is written and placed; then late is trusted again, and
	// its new follower can't replay the log yet.
	w.content(t, "late", "l2")
	w.place(t, "late.l2", "season@a2")
	holdLog.Store(true)
	h = must(c.NSHead(ctx, "cat"))
	must(c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "late"}}))
	y.caughtUp("cat")
	if r := y.listing("/cat/children?of=season"); r.status != http.StatusServiceUnavailable {
		t.Fatalf("before the stopped follower's report: %d %s, want 503", r.status, names(r.body["children"]))
	}
	// The stopped follower's report arrives now.
	release.Store(true)
	waitFor(t, "the held head answered", returned.Load)
	time.Sleep(200 * time.Millisecond)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r := y.listing("/cat/children?of=season"); r.status != http.StatusServiceUnavailable {
			t.Fatalf("a listing while late, trusted again, is caught up with: %d %s (late.l2 missing), want 503 behind", r.status, names(r.body["children"]))
		}
	}
	holdLog.Store(false)
	y.caughtUp("late")
	if got := names(y.listing("/cat/children?of=season").body["children"]); got != "matches.m1,late.l1,late.l2" {
		t.Fatalf("once caught up with late: %s", got)
	}
}

// A catch-up recorded of a namespace the catalog doesn't trust (left by a
// stop between the apply that untrusted it and the record's DELETE) is
// dropped at start: trusted again, the namespace is waited for while its
// follower replays it (§B.5, §H.3).
func TestCaughtRecordOfUntrustedDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "late", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	w := &world{s: s, c: c}
	w.folder(t, "root", "Root")
	w.folder(t, "season", "Season", "root")
	w.content(t, "matches", "m1")
	w.place(t, "matches.m1", "season@a0")
	w.content(t, "late", "l1")
	w.place(t, "late.l1", "season@a1")
	var holdLog atomic.Bool
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if holdLog.Load() && strings.HasPrefix(req.URL.Path, "/ns/late/") && (strings.HasSuffix(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events") || strings.Contains(req.URL.Path, "/poll")) {
			for holdLog.Load() {
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		return base.RoundTrip(req)
	})
	t.Cleanup(func() { holdLog.Store(false) })
	core := s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, core, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	x.stop()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	if _, err := sq.Exec(`INSERT INTO meta (k, v) VALUES ('caught:late', 'x')`); err != nil {
		t.Fatal(err)
	}
	if err := sq.Close(); err != nil {
		t.Fatal(err)
	}
	holdLog.Store(true)
	y := startSvc(t, core, svcOpts{db: db})
	y.caughtUp("cat", "matches")
	h := must(c.NSHead(ctx, "cat"))
	must(c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "late"}}))
	y.caughtUp("cat")
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r := y.listing("/cat/children?of=season"); r.status != http.StatusServiceUnavailable {
			t.Fatalf("a listing while late, trusted with a stale caught record, is caught up with: %d %s, want 503 behind", r.status, names(r.body["children"]))
		}
	}
	holdLog.Store(false)
	y.caughtUp("late")
	if got := names(y.listing("/cat/children?of=season").body["children"]); got != "matches.m1,late.l1" {
		t.Fatalf("once caught up with late: %s", got)
	}
}
