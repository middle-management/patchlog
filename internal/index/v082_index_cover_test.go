package index_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V82-05 (v0.82), SVC-09: a trusted catalog that is a remote branch (§G.3)
// covers the namespaces it trusts and makes nothing visible (SERVICES
// §B.11.9 Where, §A.4; CONFORMANCE scenario 119, its index half).

var v82NSDoc = regexp.MustCompile(`^/ns/cat-season-r/rev/[^/]+$`)

// v82RemoteDocs makes cat-season-r's namespace documents those of a
// remote branch, as the origin of a deployment that holds one serves
// them: every document of it the core answers gains a base with an
// origin (§G.3). The index tells a remote branch by its documents alone
// (§B.11.9 Where: "as their documents alone decide"), which is all it
// reads of one; the test server (clienttest) reaches no other deployment
// to branch from.
func v82RemoteDocs(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !v82NSDoc.MatchString(r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		var doc map[string]any
		if rec.Code == 200 && json.Unmarshal(body, &doc) == nil {
			doc["base"] = map[string]any{"origin": "https://a.example", "ns": "cat-src", "at": "1" + strings.Repeat("a", 32), "chain": []any{"cat-src"}}
			body, _ = json.Marshal(doc)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.Code)
		w.Write(body)
	})
}

// v82Remote is v75x with cat-season-r beside cat-season: a catalog whose
// documents are a remote branch's (v82RemoteDocs), which trusts matches
// and places matches.opener under a root that gives fans reader, so it
// would show opener, which cat-season places nowhere, if it decided
// anything. catalog-02 is matches's key whose requireAt names it. The
// index follows nss, with a grant that reads cat-season-r too.
type v82Remote struct {
	*v75x
	admin *client.Client
}

func newV82Remote(t *testing.T, nss ...string) *v82Remote {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond, Wrap: v82RemoteDocs})
	w := &v82Remote{v75x: newV75XOn(t, s)}
	all := []string{"schemas", "cat-season", "cat-season-r", "matches"}
	w.admin = s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "user:root", all, []string{"read", "create", "append", "config"})))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat-season-r"))).CreateNamespace(ctx, "cat-season-r",
		map[string]any{"read": "grant", "keys": []any{w.k.Entry("*")}, "catalog": map[string]any{"trust": []any{"matches"}}}))
	must(w.admin.CreateDoc(ctx, "cat-season-r", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:fans": []any{"reader"}}}))
	must(w.admin.CreateDoc(ctx, "cat-season-r", "matches.opener", map[string]any{"parents": []any{map[string]any{"href": "/r/cat-season-r/root"}}}))
	ev := must(edge.New([]byte("s3cret"), "", ""))
	w.x = startSvcWith(t, s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		})
	for _, ns := range nss {
		w.x.caughtUp(ns)
	}
	return w
}

// patch applies ops to matches's document and waits for the index.
func (w *v82Remote) patch(ops ...any) {
	w.t.Helper()
	ctx := context.Background()
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, ops))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
}

// via is li's grant, a fan with the role reader, through matches's key
// kid at cat's head.
func (w *v82Remote) via(kid, cat string) string {
	w.t.Helper()
	return clienttest.Mint(w.t, w.cat.Priv, map[string]any{"kid": kid, "sub": "user:li", "groups": []any{"fans"}, "roles": []any{"reader"},
		"ns": []any{"matches"}, "can": []any{"read"}, "at": map[string]any{"ns": cat, "id": must(w.admin.NSHead(context.Background(), cat)).ID},
		"exp": w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
}

// TestV082RemoteBranchCatalogDark (SVC-09; §B.11.9 Where, v0.82: "a
// trusted catalog makes nothing visible where it is a branch, local or
// remote (§G.3)"; scenario 119: "the index → no hits, never hits judged
// by rules alone"): matches trusts only cat-season-r, a remote branch.
// It stays covered: li, a partial reader, is redirected to
// /matches/g/{gs}/at/{at} under a reads:matches:g:{gs} marker and
// answered 200 with no hits, at a checkpoint and with tags that leave
// the branch out, on /_refs and under her cookie too; an unrestricted
// reader is unaffected. Whether or not the index follows the branch
// itself. Before v0.82 an unfollowed one counted as no catalog (li got
// 403, no marker), and a followed one decided as a live catalog would
// (li saw opener).
func TestV082RemoteBranchCatalogDark(t *testing.T) {
	t.Parallel()
	for name, nss := range map[string][]string{"not followed": {"matches"}, "followed": {"matches", "cat-season-r"}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV82Remote(t, nss...)
			w.patch(map[string]any{"op": "replace", "path": "/catalogs", "value": map[string]any{"cat-season-r": map[string]any{"place": []any{}}}},
				map[string]any{"op": "replace", "path": "/keys/1/requireAt", "value": "cat-season-r"})
			li := w.via("catalog-01", "cat-season-r")
			loc, gs, _ := w.pointer("/matches", li)
			r := w.x.raw(loc, li)
			if r.status != 200 || len(resources(r.body)) != 0 {
				t.Fatalf("li through a remote-branch catalog: %d %v, want 200 with no hits", r.status, r.body)
			}
			if nsm := v75Namespaces(t, r.body); len(nsm) != 1 || nsm["matches"] == "" {
				t.Errorf("at covers %v, want matches alone", nsm)
			}
			if tags := r.header.Get("Cache-Tag"); strings.Contains(tags, "cat-season-r") {
				t.Errorf("Cache-Tag %q names the dark catalog", tags)
			}
			if _, following := w.x.ix.Members()["cat-season-r"]; following {
				t.Error("the index follows the dark catalog for visibility")
			}
			// Her marker is reads:matches:g:{gs}: the exchange gives that
			// prefix, and its cookie reads the same nothing.
			prefix, cookies := v081Exchange(t, w.x, li, "matches")
			if prefix != "/matches/g/"+gs {
				t.Errorf("the exchange gives %s, the query redirected to gs %s", prefix, gs)
			}
			if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 200 || len(p37Hits(got.body)) != 0 {
				t.Errorf("under the cookie: %d %v", got.status, got.body)
			}
			refs := w.x.search("/_refs?to="+"%2Fr%2Ftarget%2Fx", li)
			if got := refsAllHits(refs); strings.Contains(got, "matches/") {
				t.Errorf("/_refs shows li %s", got)
			}
			root := w.k.Grant(t, w.s.Now(), "user:root", []string{"matches"}, []string{"read"})
			if got := strings.Join(resources(w.x.search("/matches", root)), ","); got != "derby,opener,secret,shared" {
				t.Errorf("an unrestricted reader sees %s", got)
			}
		})
	}
}

// TestV082RemoteBranchCatalogBesideLive (SVC-09; §B.11.9 Where): matches
// trusts cat-season, live, and cat-season-r, a remote branch, each
// through a key of its own. Only the live one decides: li sees derby and
// shared, which cat-season places for fans, through either key, and
// never opener, which only the branch places; at covers the live catalog
// and not the branch.
func TestV082RemoteBranchCatalogBesideLive(t *testing.T) {
	t.Parallel()
	for name, nss := range map[string][]string{"not followed": {"matches"}, "followed": {"matches", "cat-season-r"}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV82Remote(t, nss...)
			key := w.cat.Entry("read")
			key["kid"], key["requireAt"], key["maxTtl"] = "catalog-02", "cat-season-r", "PT15M"
			key["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}
			w.patch(map[string]any{"op": "add", "path": "/catalogs/cat-season-r", "value": map[string]any{"place": []any{}}},
				map[string]any{"op": "add", "path": "/keys/-", "value": key})
			for kid, cat := range map[string]string{"catalog-01": "cat-season", "catalog-02": "cat-season-r"} {
				li := w.via(kid, cat)
				loc, _, _ := w.pointer("/matches", li)
				r := w.x.raw(loc, li)
				if got := strings.Join(resources(r.body), ","); r.status != 200 || got != "derby,shared" {
					t.Errorf("li through %s: %d %s, want derby,shared", kid, r.status, got)
				}
				nsm := v75Namespaces(t, r.body)
				if _, ok := nsm["cat-season-r"]; ok || nsm["cat-season"] == "" {
					t.Errorf("through %s, at covers %v: want cat-season and not the branch", kid, nsm)
				}
			}
		})
	}
}

// TestV082RemoteBranchCatalogUnreadable (SVC-09; §A.4 Private
// namespaces: "502, naming no namespace, while it can't read one"): where
// the index's own grant can't read the remote-branch catalog, a partial
// reader of matches is 502 upstream, naming nothing, never answered by
// her rules alone as if matches trusted no catalog.
func TestV082RemoteBranchCatalogUnreadable(t *testing.T) {
	t.Parallel()
	w := newV82Remote(t, "matches")
	w.patch(map[string]any{"op": "replace", "path": "/catalogs", "value": map[string]any{"cat-season-r": map[string]any{"place": []any{}}}},
		map[string]any{"op": "replace", "path": "/keys/1/requireAt", "value": "cat-season-r"})
	li := w.via("catalog-01", "cat-season-r")
	// An index whose grant doesn't name cat-season-r.
	x := w.start(false, "matches")
	r := x.raw("/matches", li)
	b := must(json.Marshal(r.body))
	if r.status != 502 || r.body["code"] != "upstream" || bytes.Contains(b, []byte("cat-season")) {
		t.Errorf("li where the index can't read the remote-branch catalog: %d %s, want 502 upstream naming nothing", r.status, b)
	}
}
