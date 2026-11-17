package catalog

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// SPEC §C.6 Upstream failures (v0.85): "A service's 502 (upstream)
// carries nothing of the answer that caused it." An origin's answer that
// reaches writeErr unwrapped is 502 upstream with the service's own
// message, never a 500 quoting it.
func TestV085UnexpectedOriginAnswer(t *testing.T) {
	origin := &client.APIError{Method: "GET", Path: "/ns/matches", Status: 403,
		Body: map[string]any{"code": "forbidden", "message": "the grant does not apply to namespace \"matches\""}}
	rec := httptest.NewRecorder()
	writeErr(rec, fmt.Errorf("keys: %w", origin))
	if body := rec.Body.String(); rec.Code != 502 || !strings.Contains(body, `"upstream"`) || strings.Contains(body, "matches") || strings.Contains(body, "does not apply") {
		t.Errorf("%d %s, want 502 upstream with nothing of the origin's answer", rec.Code, body)
	}
	rec = httptest.NewRecorder()
	writeErr(rec, fmt.Errorf("a bug of its own"))
	if rec.Code != 500 {
		t.Errorf("an error of the service's own: %d", rec.Code)
	}
}
