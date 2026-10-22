package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// A limit refusal is 413 where the server stopped reading, and 422 limit
// at step 4 (§6.6, §7.5); IsLimit reports both, and a batch one of whose
// items a limit refused, whatever the status (GB-16).
func TestV073IsLimitEitherStatus(t *testing.T) {
	t.Parallel()
	item := map[string]any{"index": 0.0, "status": 422.0, "code": "limit", "limit": "documentSize", "measured": 20.0, "max": 10.0}
	for _, tc := range []struct {
		name string
		err  *client.APIError
		want bool
		key  string
	}{
		{"413 cut-off", &client.APIError{Status: 413, Code: "limit", Body: map[string]any{"code": "limit", "limit": "batchSize", "measured": 9.0, "max": 8.0}}, true, "batchSize"},
		{"422 step 4", &client.APIError{Status: 422, Code: "limit", Body: map[string]any{"code": "limit", "limit": "itemsPerBatch", "measured": 4.0, "max": 3.0}}, true, "itemsPerBatch"},
		{"422 batch item", &client.APIError{Status: 422, Code: "batch", Body: map[string]any{"code": "batch", "items": []any{item}}}, true, "documentSize"},
		{"413 batch item (before v0.65)", &client.APIError{Status: 413, Code: "batch", Body: map[string]any{"code": "batch", "items": []any{item}}}, true, "documentSize"},
		{"422 invalid", &client.APIError{Status: 422, Code: "invalid", Body: map[string]any{"code": "invalid"}}, false, ""},
		{"422 batch without a limit", &client.APIError{Status: 422, Code: "batch", Body: map[string]any{"code": "batch", "items": []any{map[string]any{"index": 0.0, "status": 422.0, "code": "rule"}}}}, false, ""},
	} {
		if got := client.IsLimit(tc.err); got != tc.want {
			t.Errorf("%s: IsLimit %v, want %v", tc.name, got, tc.want)
		}
		if key, _, _, _, _ := tc.err.Limit(); key != tc.key {
			t.Errorf("%s: limit %q, want %q", tc.name, key, tc.key)
		}
	}
}

// GET /ns/{ns}/grants/{gid} serves stored as the authority SignedBlock,
// one string (§C.3.1); servers before v0.73 serve every block, authority
// first. Grant reads both (GR-31).
func TestV073GrantStoredForms(t *testing.T) {
	t.Parallel()
	gid := ids.Hash(nil, []byte("grant")).String()
	for name, stored := range map[string]any{"string": "QUJD", "array": []any{"QUJD", "REVG"}} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": gid, "root": map[string]any{"sub": "alice"}, "stored": stored})
		}))
		c, err := client.New(hs.URL)
		if err != nil {
			t.Fatal(err)
		}
		g, err := c.Grant(context.Background(), "matches", gid)
		hs.Close()
		if err != nil || len(g.Stored) == 0 || g.Stored[0] != "QUJD" {
			t.Fatalf("%s: %+v, %v", name, g, err)
		}
	}
}
