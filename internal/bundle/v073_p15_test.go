package bundle_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// §7.5 (GB-26): a dry run reports a config change that fails after its
// step 1 in its config member, at 200, and judges the items against the
// configuration in force. The importer's epoch raise (§E.2.1) is such a
// change: when it fails, here because the target's configuration moved
// between reading its head and the dry run (412 stale), the dry run fails
// with that failure, naming the raise, and nothing is submitted.
func TestV073P15ImportDryRunRaiseFails(t *testing.T) {
	t.Parallel()
	s := newE2ESource(t)
	dst := newEncDeployment(t, cmsOrigin)
	importB(t, dst, s.before, bundle.ImportOptions{})

	var mu sync.Mutex
	moved, submits := false, 0
	rp := httputil.NewSingleHostReverseProxy(must(url.Parse(dst.url)))
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/ns/e/batch" {
			body := must(io.ReadAll(r.Body))
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			req, _ := jsonv.MustParse(body).(map[string]any)
			mu.Lock()
			switch {
			case r.URL.Query().Get("dry-run") != "1":
				submits++
			case req["config"] != nil && !moved:
				// The target's configuration moves after the importer
				// read it for the raise.
				moved = true
				h := must(dst.c.NSHead(ctx, "e"))
				must(dst.c.PatchConfig(ctx, "e", h.Config, ops(op("add", "/x-moved", true))))
			}
			mu.Unlock()
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(hs.Close)
	c := must(client.New(hs.URL, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil))))

	rep, err := bundle.Import(ctx, c, bundle.BytesOpener(s.after), bundle.ImportOptions{Mode: bundle.Atomic})
	if !moved {
		t.Fatal("no dry run carried the epoch raise")
	}
	if err == nil || !strings.Contains(err.Error(), "moving it to epoch 2") || !strings.Contains(err.Error(), "412 stale") {
		t.Fatalf("import: %v, want the dry run's failed raise (412 stale)", err)
	}
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 412 || ae.Code != "stale" {
		t.Fatalf("import: %v, want the raise's *client.APIError", err)
	}
	if submits != 0 {
		t.Fatalf("%d submits after the dry run's raise failed", submits)
	}
	failed := false
	for _, b := range rep.Batches {
		failed = failed || b.DryRun == "failed" && strings.Contains(b.Error, "412 stale")
	}
	if !failed {
		t.Fatalf("no batch reports the failed dry run: %+v", rep.Batches)
	}
	if e, d := targetEpoch(t, dst, "e"), dst.head("e", "d").ID; e != 1 || d != s.d0 {
		t.Fatalf("the failed import left e at epoch %v, d at %s", e, d)
	}
}
