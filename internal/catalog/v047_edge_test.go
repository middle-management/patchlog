package catalog_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// TestReadGrantsForEdgeGrants: the catalog's read grant for a reader who
// holds a rule-free reader role and a role testing /resource by pattern is
// fixed to the item, and POST /edge-grants exchanges it for a cookie of
// the item's prefix: the reader role qualifies, roles being alternatives
// (§C.5 v0.47; implementer report B8, which was 403).
func TestReadGrantsForEdgeGrants(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	opm := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"matches"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "matches")).Config
	must(opm.PatchConfig(ctx, "matches", cfg, []any{
		map[string]any{"op": "add", "path": "/roles/drafter", "value": map[string]any{"can": toAny("read", "append"),
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^d"}}}}},
		map[string]any{"op": "add", "path": "/keys/2/roles/allow/-", "value": "drafter"},
	}))
	w.patch("cat", "season", map[string]any{"op": "replace", "path": "/$access/group:fan-club", "value": toAny("reader", "drafter")})
	w.start()
	w.caughtUp()

	fan := w.caller("user:fred", "fan-club")
	r := w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")})
	g, _ := r.body["grants"].([]any)[0].(map[string]any)["grant"].(string)
	if r.status != 200 || g == "" {
		t.Fatalf("read-grants: %d %v", r.status, r.body)
	}
	core := func(method, path string, hdr http.Header) *http.Response {
		t.Helper()
		req := must(http.NewRequest(method, w.s.URL+path, nil))
		req.Header = hdr
		res := must(noRedirect.Do(req))
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res
	}
	req := must(http.NewRequest("POST", w.s.URL+"/edge-grants", nil))
	req.Header.Set("Authorization", "Bearer "+g)
	res := must(httpClient.Do(req))
	var body struct{ Prefixes []string }
	err := json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || len(body.Prefixes) != 1 || body.Prefixes[0] != "/r/matches/derby" || len(res.Cookies()) != 1 {
		t.Fatalf("edge-grants: %d %v %v", res.StatusCode, body, err)
	}
	ck := res.Cookies()[0]
	hdr := http.Header{"Cookie": {ck.Name + "=" + ck.Value}}
	if s := core("GET", "/r/matches/derby", hdr).StatusCode; s != 302 {
		t.Errorf("the item with the cookie: %d", s)
	}
	if s := core("GET", "/r/matches/shared", hdr).StatusCode; s != 401 {
		t.Errorf("another item with the cookie: %d", s)
	}
}
