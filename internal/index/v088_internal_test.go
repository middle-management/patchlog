package index

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/rules"
)

// v0.88 SERVICES §A.4 ("Each judgement gets the origin's validationSteps
// (§6.6), which GET /ns/{ns}/principal gives the service's own grant in
// writer.limits"), Grant scope scenario 80: an index told no
// validationSteps takes the origin's from the first namespace whose
// /principal answers with it; where none does, §12.2's default.
func TestV088ValidationStepsFromPrincipal(t *testing.T) {
	t.Parallel()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ns/docs/principal":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"writer": map[string]any{"limits": map[string]any{"validationSteps": 3000}}})
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"code": "forbidden"})
		}
	}))
	defer hs.Close()
	c, err := client.New(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	logf := func(string, ...any) {}
	if n := originValidationSteps(ctx, c, []string{"closed", "docs"}, logf); n != 3000 {
		t.Fatalf("the origin's validationSteps through docs: %d, want 3000", n)
	}
	if n := originValidationSteps(ctx, c, []string{"closed"}, logf); n != rules.DefaultValidationSteps {
		t.Fatalf("no namespace gives it: %d, want the default", n)
	}
}
