package index_test

import (
	"bytes"
	"context"
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

// cancelBody stalls the body of /keys answers asking for epoch 1 while
// armed, until the request's context ends, as net/http's body read does
// when the caller goes away: io.ReadAll then returns a bare
// context.Canceled.
type cancelBody struct {
	armed   atomic.Bool
	reached chan struct{}
	rt      http.RoundTripper
}

type ctxBody struct {
	ctx context.Context
	io.ReadCloser
}

func (b ctxBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }

func (f *cancelBody) RoundTrip(r *http.Request) (*http.Response, error) {
	if !f.armed.Load() || r.Method != "POST" || r.URL.Path != "/ns/sec/keys" || r.Body == nil {
		return f.rt.RoundTrip(r)
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	res, err := f.rt.RoundTrip(r)
	if err != nil || !bytes.Contains(b, []byte(`"epochs":[1]`)) {
		return res, err
	}
	res.Body = ctxBody{r.Context(), res.Body}
	select {
	case f.reached <- struct{}{}:
	default:
	}
	return res, nil
}

// SERVICES-5 (§E.2.6, §A.4): a reader that goes away while the index fetches an
// epoch key makes KeyAt fail with a bare context.Canceled, which
// derived.Retryable calls lasting: the hits are "lacking" for good, and
// the name-only result is kept at that at and served to every later
// reader, though the service gets the key fine.
func TestV074V03CanceledKeyFetchNotLasting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	t0 := s.Now()
	k := clienttest.NewKey("k")
	for _, ns := range []string{"sec", "schemas"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "sec" {
			doc["read"] = "grant"
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	sch := must(w.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{
		"title": map[string]any{"type": "string", "x-index": "text"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	for _, n := range []string{"a", "b"} {
		must(createNonced(w, "sec", n, map[string]any{"$schema": ref, "title": "old " + n}))
	}
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	// The service's grant reaches back to epoch 1 (nbf, §E.2.3): it gets
	// that epoch's key.
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk, "nbf": t0.Format(time.RFC3339)})),
		client.WithKeys(client.NewKeys(priv)))
	db := filepath.Join(t.TempDir(), "i.db")
	first := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"sec"}, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	first.caughtUp("sec")
	first.stop()
	s.Clock.Advance(time.Minute)
	must(s.Engine.RotateEpoch(ctx, "sec", "system:rotate"))
	must(createNonced(w, "sec", "c", map[string]any{"$schema": ref, "title": "new c"}))
	fk := &cancelBody{reached: make(chan struct{}, 1), rt: transport}
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"sec"}, now: s.Now, hc: &http.Client{Transport: fk}},
		func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("sec")
	whole := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})

	// A reader asks, and goes away while epoch 1's key is being read.
	fk.armed.Store(true)
	rctx, cancel := context.WithCancel(ctx)
	req := must(http.NewRequestWithContext(rctx, "GET", x.http.URL+"/sec?q=old", nil))
	req.Header.Set("Authorization", "Bearer "+whole)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if r, err := noFollow.Do(req); err == nil {
			r.Body.Close()
		}
	}()
	select {
	case <-fk.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("epoch 1's key was never asked for")
	}
	cancel()
	<-done
	fk.armed.Store(false)
	time.Sleep(1500 * time.Millisecond) // past the key failure hold

	// Another reader, with the key to be had: a and b are sealed under
	// epoch 1, whole or per entry, never by name only.
	// (A 503 behind while the failure is held is fine; it passes.)
	deadline := time.Now().Add(15 * time.Second)
	for {
		path := "/sec?q=old"
		var r *http.Response
		var b []byte
		for range 5 {
			req := must(http.NewRequest("GET", x.http.URL+path, nil))
			req.Header.Set("Authorization", "Bearer "+whole)
			r = must(noFollow.Do(req))
			b = must(io.ReadAll(r.Body))
			r.Body.Close()
			if r.StatusCode != 302 {
				break
			}
			path = r.Header.Get("Location")
		}
		if r.StatusCode == 503 && time.Now().Before(deadline) {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if r.StatusCode != 200 {
			t.Fatalf("GET %s: %d %s", path, r.StatusCode, b)
		}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			for name, kid := range p37Kids(t, b) {
				if kid == "" {
					t.Errorf("%s: hit %s by name only after another reader went away: %s", path, name, b)
				}
			}
		}
		break
	}
}
