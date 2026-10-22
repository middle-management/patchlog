package index_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// answerOf follows redirects and returns the last answer.
func (s *svc) answerOf(path, token string) resp {
	s.t.Helper()
	for range 5 {
		r := s.raw(path, token)
		if r.status != 302 {
			return r
		}
		path = r.header.Get("Location")
	}
	s.t.Fatalf("GET %s: too many redirects", path)
	return resp{}
}

// TestV073BehindBeforeCheckpoint (IX-1, §A.4): until the service has a
// checkpoint for a namespace it follows, a query of it is answered, once
// the reader's grant verifies, 503 behind, no-store, with Retry-After;
// /_refs leaves the namespace out.
func TestV073BehindBeforeCheckpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create"})))
	must(writer.CreateDoc(ctx, "sec", "a", map[string]any{"title": "secret"}))
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})))
	x := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now, noRun: true})

	if r := x.raw("/sec?q=secret", ""); r.status != 401 || r.body["code"] != "unauthenticated" {
		t.Errorf("without a grant: %d %v", r.status, r.body)
	}
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"})
	r := x.raw("/sec?q=secret", bob)
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Retry-After") == "" {
		t.Errorf("with a grant: %d %v %v", r.status, r.body, r.header)
	}
	b := x.answerOf("/_refs?to=/r/sec/a", bob)
	if b.status != 200 || fmt.Sprint(b.body["namespaces"]) != "map[]" {
		t.Errorf("/_refs: %d %v", b.status, b.body)
	}
}

// v073FailKeys answers POST /ns/{ns}/keys 503 from the after-th call on,
// while armed.
type v073FailKeys struct {
	path  string
	after int32
	n     atomic.Int32
	armed atomic.Bool
	rt    http.RoundTripper
}

func (f *v073FailKeys) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && r.URL.Path == f.path && f.n.Add(1) > f.after && f.armed.Load() {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"code":"internal","message":"injected"}`)), Request: r}, nil
	}
	return f.rt.RoundTrip(r)
}

// TestV073KeysLacking (IX-2, §A.4, §E.2.6, §12.1): a namespace whose keys
// the service lacks is 404 not_found as one it doesn't follow, with or
// without a grant; one whose keys it can't fetch for now is 503 behind,
// after the grant check. There is no skipped code.
func TestV073KeysLacking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	keys := []any{admin.Entry("*"), issuer.Entry("read")}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": keys,
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": keys,
		"encryption": map[string]any{"level": "sealed"}}))
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"sec"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	must(createNonced(w, "sec", "a", map[string]any{"title": "secret"}))
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"e", "sec"}, []string{"read"})

	// e2e, and no keyring names the service's recipient key: it lacks
	// keys (client.ErrNoKeys).
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	fk := &v073FailKeys{path: "/ns/sec/keys", after: 1, rt: transport}
	fk.armed.Store(true)
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e", "sec"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e", "sec"}, untyped: true, now: s.Now, hc: &http.Client{Transport: fk}},
		func(o *indexOpts) { o.Recipient = priv })
	waitFor(t, "both skipped", func() bool {
		n := 0
		for _, st := range x.raw("/_status", "").body["namespaces"].([]any) {
			if st.(map[string]any)["skipped"] == true {
				n++
			}
		}
		return n == 2
	})
	for _, tok := range []string{"", bob} {
		r := x.raw("/e?q=secret", tok)
		if r.status != 404 || r.body["code"] != "not_found" || r.body["message"] != "namespace not indexed" || r.header.Get("Cache-Control") != "public, max-age=5" {
			t.Errorf("e2e without keys, token %v: %d %v %v", tok != "", r.status, r.body, r.header)
		}
		if u := x.raw("/unfollowed?q=secret", tok); fmt.Sprint(u.body) != fmt.Sprint(r.body) || u.header.Get("Cache-Control") != r.header.Get("Cache-Control") {
			t.Errorf("unlike an unfollowed namespace: %v %v", u.body, u.header)
		}
	}

	// sealed, and its epoch key can't be fetched for now (503): behind,
	// after the grant check.
	if r := x.raw("/sec?q=secret", ""); r.status != 401 {
		t.Errorf("sealed, keys for now, no grant: %d %v", r.status, r.body)
	}
	r := x.raw("/sec?q=secret", bob)
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Retry-After") == "" {
		t.Errorf("sealed, keys for now: %d %v %v", r.status, r.body, r.header)
	}
	// /_refs leaves both out.
	if b := x.answerOf("/_refs?to=/r/sec/a", bob); b.status != 200 || fmt.Sprint(b.body["namespaces"]) != "map[]" {
		t.Errorf("/_refs: %d %v", b.status, b.body)
	}
	// Once the keys come, it is indexed.
	fk.armed.Store(false)
	x.caughtUp("sec")
	if f := x.fetch("/sec?q=secret", bob); f.header.Get("Content-Type") != seal.ContentType {
		t.Errorf("sealed, keys fetched: %v", f.header)
	}
}
