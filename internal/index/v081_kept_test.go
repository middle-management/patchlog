package index_test

import (
	"bytes"
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

// holdEpochKeys holds, once armed, the first POST /ns/sec/keys asking for
// epoch 1 until release is closed, signalling reached: the follower's
// Check, at a start, asking for the key of the epoch it read from the
// namespace's head (Keys.Info) moments before.
type holdEpochKeys struct {
	armed   atomic.Bool
	reached chan struct{}
	release chan struct{}
	rt      http.RoundTripper
}

func (f *holdEpochKeys) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && r.URL.Path == "/ns/sec/keys" && r.Body != nil {
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		if bytes.Contains(b, []byte(`"epochs":[1]`)) && f.armed.CompareAndSwap(true, false) {
			close(f.reached)
			<-f.release
		}
	}
	return f.rt.RoundTrip(r)
}

// TestV081KeptResultAcrossRotationAtStart (§E.2.4, §E.2.3, §A.4 Bounded
// redirects and Unavailable namespaces, §E.2.6 Stored once, served
// forever): a rotation that lands between the follower's Check reading a
// sealed namespace's epoch, at a start, and its POST /keys for that
// epoch's key is no want of keys. A grant without nbf gets the current
// epoch's key only, so /keys gives none of the epoch the rotation
// replaced; judged as lacking, the namespace was stopped (purgeStopped:
// idx:{ns} purged, the kept and stored results with it) and the follower
// restarted a second later, so the result kept at the previous checkpoint
// was gone and its URL redirected to the current at (TestSealedNamespace's
// rare "kept result: …, changed true", the log just before it "cannot
// obtain the epoch key to seal derived views: …; restarting in 1s").
// Where no query had fetched the replaced epoch's key meanwhile, Check
// asked for it again on every restart, for good: the namespace stayed
// skipped (404) and unfollowed until the process restarted.
func TestV081KeptResultAcrossRotationAtStart(t *testing.T) {
	for _, queried := range []bool{true, false} {
		name := "queried"
		if !queried {
			name = "unqueried"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			for _, ns := range []string{"sec", "schemas"} {
				doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
				if ns == "sec" {
					doc["read"] = "grant"
					doc["encryption"] = map[string]any{"level": "sealed"}
				}
				must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
			}
			rd := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
			sch := must(w.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
				"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}, "tag": map[string]any{"type": "string", "x-index": "facet"}}}))
			for _, n := range []string{"a", "b"} {
				must(createNonced(w, "sec", n, map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "secret " + n, "tag": "t" + n}))
			}
			jwk, priv, err := seal.GenerateRecipient()
			if err != nil {
				t.Fatal(err)
			}
			ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})),
				client.WithKeys(client.NewKeys(priv)))
			hk := &holdEpochKeys{rt: transport, reached: make(chan struct{}), release: make(chan struct{})}
			opts := svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now, hc: &http.Client{Transport: hk}}
			withKey := func(o *indexOpts) { o.Recipient = priv }
			x := startSvcWith(t, ic, opts, withKey)
			x.caughtUp("sec")
			f := x.fetch("/sec?q=secret&counts=/tag", rd)

			// Restarted, its follower's Check reads epoch 1 and asks
			// /keys for sec#1; the rotation commits before /keys
			// answers.
			x.stop()
			hk.armed.Store(true)
			x = startSvcWith(t, ic, opts, withKey)
			select {
			case <-hk.reached:
			case <-time.After(30 * time.Second):
				t.Fatal("the follower's Check never asked /keys for sec#1")
			}
			if queried {
				// Served from the database, and kept (§E.2.6).
				if again := x.fetch(f.path, rd); string(again.body) != string(f.body) {
					t.Fatal("resealed after a restart")
				}
			}
			must(s.Engine.RotateEpoch(ctx, "sec", "system:rotate"))
			if got := must(ic.FetchKeys(ctx, "sec", []int{1}, nil)); len(got) != 0 {
				t.Fatalf("the indexer's grant still gets sec#1 after the rotation: %v", got)
			}
			close(hk.release)

			// Followed past the rotation, never skipped nor stopped.
			x.caughtUp("sec")
			if st := fmt.Sprint(x.raw("/_status", "").body); st != "map[namespaces:[map[epoch:2 level:sealed ns:sec sealed:true skipped:false]]]" {
				t.Fatalf("status %s", st)
			}
			f2 := x.fetch("/sec?q=secret", rd)
			if !queried {
				// sec#1, which no query fetched before the rotation, is
				// one the indexer's grant gets no key of now: its hits
				// are served by name only (§E.2.6).
				if ct := f2.header.Get("Content-Type"); ct != "application/json" || strings.Contains(string(f2.body), "secret") || strings.Contains(string(f2.body), "sealed") {
					t.Fatalf("after rotation %q: %s", ct, f2.body)
				}
				if got := strings.Join(resources(decodeJSON(t, f2.body)), ","); got != "a,b" {
					t.Fatalf("after rotation %s", got)
				}
				return
			}
			if h := must(seal.ParseHeader(string(f2.body))); h.Kid != "sec#1" || f2.path == f.path {
				t.Fatalf("after rotation kid %s at %s", h.Kid, f2.path)
			}
			// Kept, the result at the previous checkpoint is still
			// served there, unchanged, at its canonical URL (§A.4
			// Bounded redirects, §E.2.6): a rotation purges nothing
			// (§9, §A.1).
			if again := x.fetch(f.path, rd); again.path != f.path || string(again.body) != string(f.body) {
				t.Fatalf("kept result: %s, changed %v", again.path, string(again.body) != string(f.body))
			}
		})
	}
}
