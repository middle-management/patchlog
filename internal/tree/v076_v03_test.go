package tree_test

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
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// v076V03Rewrap sends a POST /ns/{ns}/keys asking for epoch 1 alone
// under other once on is set, so that the keys come back wrapped to
// another recipient than the service's.
type v076V03Rewrap struct {
	ns    string
	other string
	on    atomic.Bool
}

func (rw *v076V03Rewrap) RoundTrip(r *http.Request) (*http.Response, error) {
	if rw.on.Load() && r.URL.Path == "/ns/"+rw.ns+"/keys" && r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(bytes.NewReader(b))
		if strings.Contains(string(b), `"epochs":[1]`) {
			r.Header.Set("Authorization", "Bearer "+rw.other)
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// §A.4, §E.2.6 (v0.76): an older epoch's key that comes back wrapped to
// a recipient the service can't open is lacking for good, not 503
// behind: a listing that shows a node served under that epoch gives it
// by name only.
func TestV076V03ListingUnwrappableKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "c"))).CreateNamespace(ctx, "c", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"c"}, "mode": "tree"}}))
	all := []string{"cat", "c"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})

	jwk, priv := must2(seal.GenerateRecipient())
	otherJWK, _ := must2(seal.GenerateRecipient())
	extra := func(enc map[string]any) map[string]any {
		return map[string]any{"enc": enc, "nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)}
	}
	rw := &v076V03Rewrap{ns: "cat", other: k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, extra(otherJWK))}
	svcClient := func() *client.Client {
		return s.Client(t, client.WithHTTPClient(&http.Client{Transport: rw}),
			client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, extra(jwk))), client.WithKeys(client.NewKeys(priv)))
	}
	withRecipient := func(o *tree.Options) { o.Recipient = priv }
	opts := svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")}
	x := startSvc(t, svcClient(), opts, withRecipient)
	x.caughtUp("cat", "c")
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	createNonced(t, w, "cat", "new", map[string]any{"title": "New", "parents": parents("root")})
	x.caughtUp("cat", "c")

	// After a restart, epoch 1's key comes back wrapped to another
	// recipient.
	x.stop()
	rw.on.Store(true)
	x = startSvc(t, svcClient(), opts, withRecipient)
	x.caughtUp("cat", "c")
	full := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	r := x.listingAs("/cat/children?of=root", full)
	if r.status != http.StatusOK {
		t.Fatalf("children of root without an openable cat#1: %d %v", r.status, r.body)
	}
	f := x.fetch("/cat/children?of=root", full)
	es := entriesOf(t, decode(t, f.body))
	if e := es["old"]; e == nil || e["sealed"] != nil || e["title"] != nil {
		t.Errorf("old without an openable key: %v, want it by name only", e)
	}
	if jwe, _ := es["new"]["sealed"].(string); jwe == "" || must(seal.ParseHeader(jwe)).Kid != "cat#2" {
		t.Errorf("new: %v", es["new"])
	}
}
