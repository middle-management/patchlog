package index_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V82-05 (v0.82), SVC-15i: at the index's exchange a lasting failure to
// read a requireAt chain wins over a transient one, a refusal over both
// (SPEC §C.4, §C.5.2 All or nothing; CONFORMANCE scenario 129), and the
// index answers a requireAt it can't judge 502 or 503, naming nothing.

// v82Refusing answers the index's GETs under a prefix with the status set
// for it, as the core refuses or fails them, and passes the rest on.
type v82Refusing struct {
	mu     sync.Mutex
	status map[string]int
	rt     http.RoundTripper
}

func (f *v82Refusing) set(prefix string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status == nil {
		f.status = map[string]int{}
	}
	f.status[prefix] = status
}

func (f *v82Refusing) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	st := 0
	for p, s := range f.status {
		if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/") {
			st = s
		}
	}
	f.mu.Unlock()
	if st == 0 {
		return f.rt.RoundTrip(r)
	}
	return &http.Response{StatusCode: st, Header: http.Header{"Content-Type": {"application/json"}}, Request: r,
		Body: io.NopCloser(strings.NewReader(`{"code":"injected","message":"injected"}`))}, nil
}

// v82Chains is two private namespaces, m1 and m2, each with a key whose
// requireAt names a namespace of its own, cat-a and cat-b, which the
// index reads only to check at (§C.4), through fail.
type v82Chains struct {
	t      *testing.T
	s      *clienttest.Server
	k      clienttest.Key
	ka, kb clienttest.Key
	admin  *client.Client
	fail   *v82Refusing
	x      *svc
}

func newV82Chains(t *testing.T) *v82Chains {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	w := &v82Chains{t: t, s: s, k: clienttest.NewKey("k"), ka: clienttest.NewKey("ka"), kb: clienttest.NewKey("kb"), fail: &v82Refusing{rt: transport}}
	mk := func(ns string, doc map[string]any) {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat-a", "cat-b", "m1", "m2"}
	for _, c := range []struct {
		ns, cat string
		key     clienttest.Key
	}{{"m1", "cat-a", w.ka}, {"m2", "cat-b", w.kb}} {
		mk(c.cat, map[string]any{"read": "grant", "keys": []any{w.k.Entry("*")}})
		e := c.key.Entry("read")
		e["requireAt"], e["maxTtl"] = c.cat, "PT15M"
		mk(c.ns, map[string]any{"read": "grant", "keys": []any{w.k.Entry("*"), e}})
	}
	w.admin = s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "user:root", all, []string{"read", "create"})))
	for _, ns := range []string{"m1", "m2"} {
		must(w.admin.CreateDoc(ctx, ns, "a", map[string]any{"title": "a"}))
	}
	w.x = startSvcWith(t, s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"m1", "m2"}, untyped: true, now: s.Now, hc: &http.Client{Transport: w.fail}},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
		})
	w.x.caughtUp("m1")
	w.x.caughtUp("m2")
	return w
}

// grant is k's grant for ns with verbs can, at cat's head.
func (w *v82Chains) grant(k clienttest.Key, ns, cat string, can ...string) string {
	w.t.Helper()
	return k.Grant(w.t, w.s.Now(), "user:li", []string{ns}, can, map[string]any{
		"at":  map[string]any{"ns": cat, "id": must(w.admin.NSHead(context.Background(), cat)).ID},
		"exp": w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
}

// exchange posts grants to /edge-grants.
func (w *v82Chains) exchange(grants ...string) p37Resp {
	w.t.Helper()
	gs := make([]any, len(grants))
	for i, g := range grants {
		gs[i] = g
	}
	return p37Do(w.t, w.x, "POST", "/edge-grants", "", string(must(json.Marshal(map[string]any{"grants": gs}))), nil, "")
}

// TestV082ExchangeLastingChainWins (SVC-15i; §C.4 requireAt: "503
// (behind) while the cause is transient, and 502 (upstream) otherwise,
// naming no namespace"; §C.5.2 All or nothing; scenario 129): the index
// can't read cat-a for good (403 to its own grant) nor cat-b for now
// (503). An exchange of a grant whose chain is cat-a is 502, of one whose
// chain is cat-b 503 behind, and of both 502 in either order: 503 only
// where every unreadable chain's cause is transient. A grant refused 403
// beside them answers 403, and one that is 401 answers 401, in either
// order, never 502 or 503. No answer names a namespace. Before v0.82 the
// last grant's failure answered, so the order decided.
func TestV082ExchangeLastingChainWins(t *testing.T) {
	t.Parallel()
	w := newV82Chains(t)
	ga, gb := w.grant(w.ka, "m1", "cat-a", "read"), w.grant(w.kb, "m2", "cat-b", "read")
	// ka may not grant create: a key-scope refusal, before requireAt.
	refused := w.grant(w.ka, "m1", "cat-a", "create")
	if r := w.exchange(ga, gb); r.status != 200 {
		t.Fatalf("the exchange while both chains are read: %d %v", r.status, r.body)
	}
	w.fail.set("/ns/cat-a", 403)
	w.fail.set("/ns/cat-b", 503)
	w.x.ix.ExpireGrantChecks()
	for _, c := range []struct {
		name   string
		grants []string
		status int
		code   string
	}{
		{"lasting", []string{ga}, 502, "upstream"},
		{"transient", []string{gb}, 503, "behind"},
		{"lasting, transient", []string{ga, gb}, 502, "upstream"},
		{"transient, lasting", []string{gb, ga}, 502, "upstream"},
		{"refused, transient (scenario 129)", []string{refused, gb}, 403, "forbidden"},
		{"transient, refused", []string{gb, refused}, 403, "forbidden"},
		{"lasting, refused", []string{ga, refused}, 403, "forbidden"},
		{"transient, lasting, unverifiable", []string{gb, ga, "x"}, 401, "unauthenticated"},
	} {
		r := w.exchange(c.grants...)
		if r.status != c.status || r.body["code"] != c.code || len(r.cookies) != 0 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v, want %d %s, no-store, no cookie", c.name, r.status, r.body, c.status, c.code)
		}
		if c.status == 503 && r.header.Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", c.name)
		}
		if m, _ := r.body["message"].(string); c.status >= 500 && (strings.Contains(m, "cat-") || strings.Contains(m, "m1") || strings.Contains(m, "m2")) {
			t.Errorf("%s: names a namespace: %q", c.name, m)
		}
	}
}

// TestV082RequireAtUnjudgedNamesNothing (SVC-15i; §C.4, v0.82: "an
// origin answers 403, naming nothing, for a requireAt whose namespace
// doesn't exist; a service, which can't tell, 502 or 503"): a grant from
// a key whose requireAt names a namespace the index can't read, for good
// or because none of that name exists as far as its own grant can tell
// (404), is 502 upstream at a query, at /_refs and at the exchange, and
// 503 behind while the failure is for now; none names the namespace, and
// none is a 403.
func TestV082RequireAtUnjudgedNamesNothing(t *testing.T) {
	t.Parallel()
	w := newV82Chains(t)
	ga := w.grant(w.ka, "m1", "cat-a", "read")
	for _, c := range []struct {
		upstream, status int
		code             string
	}{{404, 502, "upstream"}, {403, 502, "upstream"}, {503, 503, "behind"}} {
		w.fail.set("/ns/cat-a", c.upstream)
		w.x.ix.ExpireGrantChecks()
		for what, r := range map[string]resp{
			"a query": w.x.raw("/m1", ga), "/_refs": w.x.raw("/_refs?to=%2Fr%2Fm1%2Fa", ga), "the exchange": w.exchange(ga).resp,
		} {
			m, _ := r.body["message"].(string)
			if r.status != c.status || r.body["code"] != c.code || strings.Contains(m, "cat-a") {
				t.Errorf("%s while cat-a answers the index %d: %d %v, want %d %s naming nothing", what, c.upstream, r.status, r.body, c.status, c.code)
			}
		}
	}
}
