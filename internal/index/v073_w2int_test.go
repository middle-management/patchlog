package index_test

import (
	"net/url"
	"strings"
	"testing"
)

// GR-20 (§C.8, §C.6, F-C3 default): the index answers a grant over
// grantSize or rulesPerGrant as the origin, the tree service and the
// catalog service do, 413 limit naming the limit, no-store, on a query of
// a private namespace and on /_refs; a public namespace's reads ignore
// the grant.
func TestV073W2GrantOverLimits(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	many := make([]any, 40)
	for i := range many {
		many[i] = map[string]any{"op": "test", "path": "/action", "value": "read"}
	}
	q := "?to=" + url.QueryEscape("/r/target/x")
	for limit, tok := range map[string]string{
		"grantSize":     w.issuer.Grant(t, w.s.Now(), "user:h", []string{"pa"}, []string{"read"}, map[string]any{"attrs": map[string]any{"x": strings.Repeat("a", 9000)}}),
		"rulesPerGrant": w.issuer.Grant(t, w.s.Now(), "user:m", []string{"pa"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"all": many}}}),
	} {
		for _, p := range []string{"/pa?limit=5", "/_refs" + q} {
			r := w.x.raw(p, tok)
			if r.status != 413 || r.body["code"] != "limit" || r.body["limit"] != limit || r.body["max"] == nil || r.body["measured"] == nil ||
				r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s, %s: %d %v %v", limit, p, r.status, r.body, r.header)
			}
		}
		if r := w.x.raw("/pub?limit=5", tok); r.status != 302 {
			t.Errorf("%s, a public namespace: %d %v", limit, r.status, r.body)
		}
	}
}
