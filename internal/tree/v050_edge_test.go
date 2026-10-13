package tree_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
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
