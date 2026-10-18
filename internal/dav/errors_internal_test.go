package dav

import (
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// A limit refusal of the core (413, or 422 code limit, §6.6, §12) is a 413
// naming the limit and the sizes it gave (§H.4 "Answers"); a limit without
// sizes is named alone, and a 413 of a core that names no limit keeps its
// text. Any other error is no limit refusal.
func TestLimitRefusal(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		status int
		body   map[string]any
		want   string // "" for none
	}{
		{413, map[string]any{"code": "limit", "message": "document too large", "limit": "documentSize", "measured": 1048577.0, "max": 1048576.0},
			"too large: documentSize 1048577 > 1048576 (§6.6): document too large"},
		{422, map[string]any{"code": "limit", "message": "too many operations", "limit": "opsPerSet", "measured": 1001.0, "max": 1000.0},
			"too large: opsPerSet 1001 > 1000 (§6.6): too many operations"},
		{422, map[string]any{"code": "limit", "message": "blobGrace below retryWindow", "limit": "blobGrace"},
			"over a limit: blobGrace (§6.6): blobGrace below retryWindow"},
		{413, map[string]any{"code": "batch", "items": []any{
			map[string]any{"index": 0.0, "status": 413.0, "code": "limit", "limit": "patchSetSize", "measured": 300.0, "max": 200.0}}},
			"too large: patchSetSize 300 > 200 (§6.6)"},
		{413, map[string]any{"message": "body too large"}, "body too large"},
		{422, map[string]any{"code": "invalid", "message": "no"}, ""},
		{409, map[string]any{"code": "limit", "limit": "x", "measured": 2.0, "max": 1.0}, ""},
	} {
		ae := &client.APIError{Status: c.status, Body: c.body}
		ae.Code, _ = c.body["code"].(string)
		e := limitRefusal(ae, "")
		switch {
		case c.want == "" && e != nil:
			t.Errorf("%d %v: %q", c.status, c.body, e.msg)
		case c.want != "" && (e == nil || e.msg != c.want || e.status != http.StatusRequestEntityTooLarge):
			t.Errorf("%d %v: %+v, want 413 %q", c.status, c.body, e, c.want)
		}
	}
	if e := limitRefusal(&client.APIError{Status: 413, Code: "limit", Body: map[string]any{"code": "limit", "limit": "blobSize", "measured": 9.0, "max": 8.0}}, "; more"); e.msg != "too large: blobSize 9 > 8 (§6.6); more" {
		t.Fatalf("with more: %q", e.msg)
	}
}
