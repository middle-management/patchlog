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

// TestV076KeysCatalogBehind (FSVC-8; §A.4 Private namespaces: the index
// "answers a partial reader 502 while it can't read one, or lacks the
// keys (above) to open a sealed one's documents"; scenario 100: "While
// those keys only can't yet be fetched → 503 behind"): m trusts cat, a
// sealed catalog, which the index reads with its own keys (WithKeys)
// without following it. While cat's /keys answers 503, a partial reader's
// query of m is 503 behind with Retry-After, on /_refs too; while it
// answers 403, the key is lacking: 502; once it answers, the reader sees
// what cat places for it. Before v0.76 a key that couldn't be fetched for
// now was 502 too.
func TestV076KeysCatalogBehind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k, cat, rd := clienttest.NewKey("k"), clienttest.NewKey("catalog-01"), clienttest.NewKey("rd")
	scope := []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}
	key, rdKey := cat.Entry("read"), rd.Entry("read")
	key["requireAt"], key["maxTtl"], key["rules"], rdKey["rules"] = "cat", "PT15M", scope, scope
	for ns, doc := range map[string]map[string]any{
		"cat": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"m"}}},
		"m": {"read": "grant", "keys": []any{k.Entry("*"), key, rdKey}, "roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}},
			"catalogs": map[string]any{"cat": map[string]any{"place": []any{}}}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:root", []string{"cat", "m"}, []string{"read", "create", "append"})),
		client.WithKeys(client.NewKeys(nil)))
	must(createNonced(admin, "cat", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:fans": []any{"reader"}}}))
	must(createNonced(admin, "cat", "m.a", map[string]any{"parents": []any{map[string]any{"href": "/r/cat/root"}}}))
	for _, n := range []string{"a", "b"} {
		must(admin.CreateDoc(ctx, "m", n, map[string]any{"title": n}))
	}
	fk := &keys76Refusing{path: "/ns/cat/keys", epochs: `"epochs":[1]`, rt: transport}
	fk.status.Store(503)
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"cat", "m"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"m"}, untyped: true, now: s.Now, hc: &http.Client{Transport: fk}})
	x.caughtUp("m")
	// A partial reader through rd, whose scope rule tests /resource: its
	// grant needs no at, which the grant checker would read cat for.
	fan := rd.Grant(t, s.Now(), "user:fan", []string{"m"}, []string{"read"}, map[string]any{"groups": []any{"fans"}, "roles": []any{"reader"}})
	refs := "/_refs?to=" + "%2Fr%2Ftarget%2Fx"
	for _, p := range []string{"/m?limit=5", refs} {
		if r := x.raw(p, fan); r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s while cat's keys can't be fetched yet: %d %v %v", p, r.status, r.body, r.header)
		}
	}
	fk.status.Store(403)
	x.ix.ExpireGrantChecks()
	for _, p := range []string{"/m?limit=5", refs} {
		if r := x.raw(p, fan); r.status != 502 || r.body["code"] != "upstream" {
			t.Errorf("%s while the index lacks cat's keys: %d %v", p, r.status, r.body)
		}
	}
	fk.status.Store(0)
	x.ix.ExpireGrantChecks()
	if got := resources(x.search("/m?limit=5", fan)); len(got) != 1 || got[0] != "a" {
		t.Errorf("once cat's keys are had, fan sees %v, want a", got)
	}
}

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
