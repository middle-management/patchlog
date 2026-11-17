package tree_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/tree"
)

// SPEC §C.6 Upstream failures (v0.85): "A service's 502 (upstream)
// carries nothing of the answer that caused it." An access check that
// fails on the origin's answer to the service, here a 403 whose body
// names namespaces, is 502 upstream with the service's own fixed
// message: the origin's status, code, message and names are in the log
// alone.
func TestV085UpstreamCarriesNothingOfTheOrigin(t *testing.T) {
	t.Parallel()
	origin := &client.APIError{Method: "GET", Path: "/ns/cat-season", Status: 403,
		Body: map[string]any{"code": "forbidden", "message": "the grant does not apply to namespace \"cat-season\"", "ns": "cat-season"}}
	var logged []string
	rec := httptest.NewRecorder()
	tree.WriteAuthError(rec, fmt.Errorf("reading matches: %w", origin), func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	body := rec.Body.String()
	if rec.Code != 502 || !strings.Contains(body, `"upstream"`) {
		t.Fatalf("%d %s, want 502 upstream", rec.Code, body)
	}
	for _, word := range []string{"cat-season", "matches", "forbidden", "does not apply", "403"} {
		if strings.Contains(body, word) {
			t.Errorf("the 502 carries %q of the origin's answer: %s", word, body)
		}
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "cat-season") {
		t.Errorf("the log doesn't hold the origin's answer: %v", logged)
	}
}
