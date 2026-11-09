package catalog_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/catalog"
)

// v077ChainErr is a verifier's error for a requireAt chain it can't read,
// as grantcheck's is joined (ChainUnreadable): its text names the chain's
// namespace, which no answer may.
type v077ChainErr struct{ transient bool }

func (e v077ChainErr) Error() string         { return "namespace cat-season: cannot read its chain" }
func (e v077ChainErr) ChainUnreadable() bool { return e.transient }

// §C.4 requireAt, §12.1 (v0.77, scenario 123): a verifier that can't read
// the chain a key's requireAt names answers 503 behind, with Retry-After,
// while the cause is transient, and 502 upstream otherwise, naming no
// namespace, never 403: on POST /grants, /read-grants and /merge-grants,
// the approver's grant included.
func TestV077V04CatalogChainUnreadable(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	fan := w.caller("user:fred", "fan-club")
	desk := w.caller("user:ann", "match-desk")

	for _, transient := range []bool{true, false} {
		w.svc.FailVerify(func() error { return fmt.Errorf("verifying: %w", v077ChainErr{transient}) })
		check := func(what string, r resp) {
			t.Helper()
			want, code := 502, "upstream"
			if transient {
				want, code = 503, "behind"
			}
			if r.status != want || r.body["code"] != code {
				t.Errorf("%s (transient %v): %d %v, want %d %s", what, transient, r.status, r.body, want, code)
			}
			if got := r.header.Get("Retry-After"); (got != "") != transient {
				t.Errorf("%s (transient %v): Retry-After %q", what, transient, got)
			}
			if msg, _ := r.body["message"].(string); strings.Contains(msg, "cat-season") || strings.Contains(msg, "matches") {
				t.Errorf("%s: the body names a namespace: %q", what, msg)
			}
			if cc := r.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("%s: Cache-Control %q", what, cc)
			}
		}
		check("grants", w.do("POST", "/grants", fan, map[string]any{"want": toAny("/r/matches/derby")}))
		check("read-grants", w.do("POST", "/read-grants", fan, map[string]any{"items": toAny("/r/matches/derby")}))
		check("merge-grants", w.do("POST", "/merge-grants", desk, map[string]any{"batch": map[string]any{}}))
	}

	// The approver's grant alone: the caller's verifies.
	w.svc.FailVerify(nil)
	approver := w.caller("user:li", "editors-in-chief")
	calls := 0
	w.svc.FailVerify(func() error {
		if calls++; calls > 1 {
			return v077ChainErr{true}
		}
		return nil
	})
	r := w.doWith("POST", "/merge-grants", desk, map[string]any{"batch": map[string]any{}}, map[string]string{catalog.ApproverHeader: "Bearer " + approver})
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" {
		t.Errorf("merge-grants, approver's chain unreadable: %d %v", r.status, r.body)
	}
	w.svc.FailVerify(nil)
}
