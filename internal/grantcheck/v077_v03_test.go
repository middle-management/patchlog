package grantcheck_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
)

// chainFixture is a deployment with a sealed catalog namespace cat-season
// and a namespace sec whose key "at" has requireAt "cat-season" (§C.4).
// fail, when set, is the status the origin answers for requests to paths
// with the prefix failPath.
type chainFixture struct {
	t        *testing.T
	s        *clienttest.Server
	admin    clienttest.Key
	at       clienttest.Key
	adminC   *client.Client
	fail     atomic.Int32
	failPath atomic.Value
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	f := &chainFixture{t: t, admin: clienttest.NewKey("admin"), at: clienttest.NewKey("at")}
	f.failPath.Store("/ns/cat-season/keys")
	f.s = clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if st := int(f.fail.Load()); st != 0 && strings.HasPrefix(r.URL.Path, f.failPath.Load().(string)) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(st)
				w.Write([]byte(`{"code":"x","message":"injected"}`))
				return
			}
			h.ServeHTTP(w, r)
		})
	}})
	atEntry := f.at.Entry("read")
	atEntry["requireAt"] = "cat-season"
	for ns, cfg := range map[string]map[string]any{
		"cat-season": {"read": "grant", "keys": []any{f.admin.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"sec":        {"read": "grant", "keys": []any{f.admin.Entry("*"), atEntry}},
	} {
		op := f.s.Client(t, client.WithBearer(f.s.OperatorGrant(t, ns)))
		must(op.CreateNamespace(ctx, ns, cfg))
	}
	f.adminC = f.s.Client(t, client.WithBearer(f.admin.Grant(t, f.s.Now(), "user:root", []string{"sec", "cat-season"}, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	return f
}

// checker is a fresh checker (its client caches no keys) with ttl.
func (f *chainFixture) checker(ttl time.Duration) *grantcheck.Checker {
	g := f.admin.Grant(f.t, f.s.Now(), "svc:index", []string{"sec", "cat-season"}, []string{"read"})
	return grantcheck.New(f.s.Client(f.t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil))), grantcheck.WithClock(f.s.Now), grantcheck.WithTTL(ttl))
}

// grantAt is a read grant on sec from the requireAt key, at at.
func (f *chainFixture) grantAt(at string) string {
	return f.at.Grant(f.t, f.s.Now(), "user:li", []string{"sec"}, []string{"read"}, map[string]any{"at": map[string]any{"ns": "cat-season", "id": at}, "nbf": f.s.Now().Format(time.RFC3339)})
}

// FCORE-3 / FSVC-10, §C.4 requireAt: a verifier that can't read the chain
// answers 503 behind while the cause is transient and 502 upstream
// otherwise, naming no namespace, never 403. The checker gives such a
// failure as a *grantcheck.ChainError, not a *grant.AuthError, from Verify
// and CheckRead alike.
func TestV077ChainUnreadable(t *testing.T) {
	ctx := context.Background()
	f := newChainFixture(t)
	head := must(f.adminC.NSHead(ctx, "cat-season")).ID
	tok := f.grantAt(head)
	if _, err := f.checker(0).Verify(ctx, "sec", tok); err != nil {
		t.Fatalf("readable chain: %v", err)
	}
	cases := []struct {
		path      string
		status    int
		transient bool
	}{
		{"/ns/cat-season/keys", 500, true},
		{"/ns/cat-season/keys", 503, true},
		{"/ns/cat-season/keys", 408, true},
		{"/ns/cat-season/keys", 429, true},
		{"/ns/cat-season/keys", 403, false},
		{"/ns/cat-season/keys", 404, false},
		{"/ns/cat-season", 500, true},
		{"/ns/cat-season", 403, false},
		// The target namespace itself answering 404: lasting (502).
		{"/ns/cat-season", 404, false},
	}
	for _, tc := range cases {
		f.failPath.Store(tc.path)
		f.fail.Store(int32(tc.status))
		ch := f.checker(0)
		for _, check := range []func() error{
			func() error { _, err := ch.Verify(ctx, "sec", tok); return err },
			func() error { _, err := ch.CheckRead(ctx, "sec", tok, ""); return err },
		} {
			err := check()
			var ae *grant.AuthError
			if errors.As(err, &ae) {
				t.Errorf("%s %d: a refusal %v, want the chain unreadable", tc.path, tc.status, err)
				continue
			}
			var cu interface{ ChainUnreadable() bool }
			if !errors.As(err, &cu) {
				t.Errorf("%s %d: %v, want the chain unreadable", tc.path, tc.status, err)
				continue
			}
			if cu.ChainUnreadable() != tc.transient {
				t.Errorf("%s %d: transient %v, want %v", tc.path, tc.status, cu.ChainUnreadable(), tc.transient)
			}
			if strings.Contains(err.Error(), "cat-season") {
				t.Errorf("%s %d: %q names the namespace", tc.path, tc.status, err)
			}
			var ce *grantcheck.ChainError
			if !errors.As(err, &ce) || ce.Err == nil {
				t.Errorf("%s %d: %T, want *grantcheck.ChainError with its cause", tc.path, tc.status, err)
			}
		}
	}
	f.fail.Store(0)
	// A chain that reads, with at in it, verifies again; an at not in it
	// is still refused (403).
	if _, err := f.checker(0).Verify(ctx, "sec", tok); err != nil {
		t.Fatalf("readable chain again: %v", err)
	}
	if _, err := f.checker(0).Verify(ctx, "sec", f.grantAt("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); authStatus(err) != 403 {
		t.Fatalf("at not in the chain: %v, want 403", err)
	}
}

// FCORE-3: the checker's cached head (TTL) may be older than a grant's at.
// The heads are read again before at is refused as not in the chain, so a
// grant at the namespace's new head verifies within the TTL.
func TestV077ChainAtPastCachedHead(t *testing.T) {
	ctx := context.Background()
	f := newChainFixture(t)
	ch := f.checker(time.Hour)
	old := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if _, err := ch.Verify(ctx, "sec", f.grantAt(old)); err != nil {
		t.Fatalf("at the head: %v", err)
	}
	h := must(f.adminC.NSHead(ctx, "cat-season"))
	must(f.adminC.PatchConfig(ctx, "cat-season", h.Config, []any{map[string]any{"op": "add", "path": "/maxLag", "value": "PT90S"}}))
	head := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if head == old {
		t.Fatal("the head didn't move")
	}
	if _, err := ch.Verify(ctx, "sec", f.grantAt(head)); err != nil {
		t.Fatalf("at the new head, within the TTL: %v", err)
	}
	// The old at is still within maxLag of the grant's issuance.
	if _, err := ch.Verify(ctx, "sec", f.grantAt(old)); err != nil {
		t.Fatalf("at the old head: %v", err)
	}
	if _, err := ch.Verify(ctx, "sec", f.grantAt("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); authStatus(err) != 403 {
		t.Fatalf("at not in the chain: %v, want 403", err)
	}
}
