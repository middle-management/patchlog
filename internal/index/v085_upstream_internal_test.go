package index

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// SPEC §C.6 Upstream failures (v0.85; scenario 108): "A service's 502
// (upstream) carries nothing of the answer that caused it." Whatever the
// origin answered the index, here a 403 whose body names namespaces,
// its 502 carries the index's own message alone, for a read the index's
// grant lacks as for any other; the log holds the origin's answer.
func TestV085UpstreamCarriesNothingOfTheOrigin(t *testing.T) {
	origin := &client.APIError{Method: "GET", Path: "/ns/cat-season", Status: 403,
		Body: map[string]any{"code": "forbidden", "message": "the grant does not apply to namespace \"cat-season\"", "ns": "cat-season"}}
	for what, err := range map[string]error{
		"a read":                 fmt.Errorf("the document of matches: %w", origin),
		"a read its grant lacks": lacksRead("cat-season", origin),
	} {
		var logged []string
		ix := &Index{}
		ix.opt.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
		rec := httptest.NewRecorder()
		ix.writeUpstreamErr(rec, "access check", err, "cannot read a namespace configuration")
		body := rec.Body.String()
		if rec.Code != 502 || !strings.Contains(body, `"upstream"`) {
			t.Fatalf("%s: %d %s, want 502 upstream", what, rec.Code, body)
		}
		for _, word := range []string{"cat-season", "matches", "forbidden", "does not apply", "403"} {
			if strings.Contains(body, word) {
				t.Errorf("%s: the 502 carries %q of the origin's answer: %s", what, word, body)
			}
		}
		if len(logged) != 1 || !strings.Contains(logged[0], "cat-season") {
			t.Errorf("%s: the log doesn't hold the origin's answer: %v", what, logged)
		}
	}
}
