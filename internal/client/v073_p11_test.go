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
