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

// V76-02 (v0.76): keys the index fetches to read what visibility reads
// (§A.4 Private namespaces, scenario 100), and keys it lacks for good
// (§A.4, §E.2.6).

// keys76Refusing answers POST {path} asking for epochs with status while
// it is set, as /keys answers when it fails (5xx) or refuses (4xx).
type keys76Refusing struct {
	path, epochs string
	status       atomic.Int32
	rt           http.RoundTripper
}

func (f *keys76Refusing) RoundTrip(r *http.Request) (*http.Response, error) {
	if st := f.status.Load(); st != 0 && r.Method == "POST" && r.URL.Path == f.path && r.Body != nil {
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		if bytes.Contains(b, []byte(f.epochs)) {
			return &http.Response{StatusCode: int(st), Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"code":"injected","message":"injected"}`)), Request: r}, nil
		}
	}
	return f.rt.RoundTrip(r)
}

// TestV076KeysNoRecipientSkipped (ENC-5, FSVC-13; §A.4: a sealed
// namespace whose keys the service lacks is 404; §E.2.6; changelog v0.76
// "a wrapped key no recipient key opens is lacking, not 503 behind"): an
// index whose grant has an enc, with no recipient key configured, gets
// keys it can't unwrap: it lacks them, so a query of the sealed namespace
// is 404, as of one it doesn't follow. Before v0.76 it stayed 503 behind,
// retrying.
func TestV076KeysNoRecipientSkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	must(createNonced(w, "sec", "a", map[string]any{"title": "a"}))
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now})
	reader := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})
	var r resp
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if r = x.raw("/sec?limit=5", reader); r.status == 404 {
			break
		}
	}
	if r.status != 404 || r.body["code"] != "not_found" {
		t.Errorf("a sealed namespace whose keys no recipient key opens: %d %v, want 404", r.status, r.body)
	}
}
