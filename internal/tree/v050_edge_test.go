package tree_test

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/tree"
)

// TestPrivateListingsBehindEdge (v0.50 §9): behind a verifying edge, a
// listing for a reader with a grant is served with or without the edge's
// headers, never 403. Its grant is in Authorization, which the service
// verifies itself and which belongs to one credential, so the listing is
// no-store for every shared cache, whatever the headers say.
func TestPrivateListingsBehindEdge(t *testing.T) {
	t.Parallel()
	s, admin, reader, _ := privateWorld(t, map[string]any{})
	ev := must(edge.New([]byte("s3cret"), "", ""))
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"}))), svcOpts{now: s.Now, edge: ev})
	x.caughtUp("cat", "sec")
	bob := reader.Grant(t, s.Now(), "user:bob", []string{"cat", "sec"}, []string{"read"}, map[string]any{"groups": []any{"eds"}})
	get := func(path string, hdr map[string]string) *http.Response {
		req := must(http.NewRequest("GET", x.http.URL+path, nil))
		req.Header.Set("Authorization", "Bearer "+bob)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res := must(noRedirect.Do(req))
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res
	}
	for _, hdr := range []map[string]string{
		nil,
		{edge.DefaultHeader: "wrong", edge.DefaultPrefixHeader: "/cat"},
		{edge.DefaultHeader: "s3cret"},
		{edge.DefaultHeader: "s3cret", edge.DefaultPrefixHeader: "/cat"},
	} {
		for _, op := range []string{"children?of=top", "ancestors?of=sec.a", "manifest?of=top"} {
			res := get("/cat/"+op, hdr)
			for res.StatusCode == 302 {
				res = get(res.Header.Get("Location"), hdr)
			}
			if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Cache-Control"), "private") ||
				res.Header.Get("CDN-Cache-Control") != "no-store" || res.Header.Get("Surrogate-Control") != "no-store" {
				t.Errorf("%s %v: %d %v", op, hdr, res.StatusCode, res.Header)
			}
		}
	}
}

// TestPlainTreeMintsNoEdgeGrants (§B.11.5): edge grants are bound to a
// subject set, which only a catalog service's listings depend on alone,
// so a plain tree service can't be given any, and its /edge-grants is
// 404 not_offered.
func TestPlainTreeMintsNoEdgeGrants(t *testing.T) {
	t.Parallel()
	s, admin, reader, _ := privateWorld(t, map[string]any{})
	c := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"})))
	if _, err := tree.Open(context.Background(), tree.Options{Client: c, Catalog: "cat", DB: filepath.Join(t.TempDir(), "tree.db"),
		EdgeGrants: edge.NewCookies("tree-cat", nil)}); err == nil {
		t.Fatal("a plain tree service with edge grants")
	}
	x := startSvc(t, c, svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")
	bob := reader.Grant(t, s.Now(), "user:bob", []string{"cat", "sec"}, []string{"read"})
	for _, method := range []string{"POST", "DELETE"} {
		req := must(http.NewRequest(method, x.http.URL+"/edge-grants?prefix=/cat/g/all", nil))
		req.Header.Set("Authorization", "Bearer "+bob)
		res := must(noRedirect.Do(req))
		res.Body.Close()
		if res.StatusCode != 404 || len(res.Cookies()) != 0 {
			t.Errorf("%s /edge-grants: %d", method, res.StatusCode)
		}
	}
}
