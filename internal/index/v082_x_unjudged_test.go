package index_test

import (
	"context"
	"errors"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
)

// XT-1 (5), SVC-05 and SVC-06 together (SERVICES §E.2.6 Per-entry
// sealing, v0.82: "Until it can judge it, the service seals nothing
// derived from that revision"): derived.Keys.KeyAt refuses an epoch that
// isn't known with ErrUnjudged, never answering the key current now; and
// in v82Pending's index, over the same deployment, where r's epoch in e-b
// is pending, an answer whose judgement finds another head (a write
// between its read and its judgement, or as it judges) is computed again:
// it is a 200 serving r's head under e-b#1, the epoch that head is served
// under, on a query and on /_refs, never KeyAt's refusal. This pins the
// two behaviours side by side. The index's own guards against passing an
// unjudged epoch to KeyAt (keyAt in http.go and refsall.go) are defence
// in depth no request reaches: answer and refsCompute return errUnjudged
// or errMoved for such a hit before either seals a value.
func TestV082XUnjudgedEpochRefusedAndRecomputed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		what string
		hook func(x *svc, f func())
		path string
		ns   string // of the hit, where the answer names it
	}{
		{"a query, written before judging", func(x *svc, f func()) { x.ix.OnBeforeJudge(f) }, "/e-b?q=zq", ""},
		{"a query, written while judging", func(x *svc, f func()) { x.ix.OnJudge(f) }, "/e-b?q=zq", ""},
		{"/_refs, written after its read", func(x *svc, f func()) { x.ix.OnRefsRead(f) }, "/_refs?to=" + url.QueryEscape("/r/target/x"), "e-b"},
	} {
		t.Run(c.what, func(t *testing.T) {
			t.Parallel()
			x, write := v82Pending(t)
			// The contract the index relies on, for the same deployment.
			keys := derived.NewKeys(x.core, nil)
			for _, e := range []int{0, -1} {
				if k, err := keys.KeyAt(ctx, "e-b", e); !errors.Is(err, derived.ErrUnjudged) || k.K != nil {
					t.Fatalf("KeyAt(e-b, %d): %v, want ErrUnjudged and no key", e, err)
				}
			}
			if _, err := keys.KeyAt(ctx, "e-b", 1); errors.Is(err, derived.ErrUnjudged) {
				t.Fatalf("KeyAt(e-b, 1), a judged epoch: %v", err)
			}
			var once atomic.Bool
			var head string
			c.hook(x, func() {
				if once.CompareAndSwap(false, true) {
					head = write()
				}
			})
			got := x.fetch(c.path, "") // fails the test on anything but a 200
			if !once.Load() {
				t.Fatal("the answer never reached the hook")
			}
			var seen bool
			for _, hv := range decodeJSON(t, got.body)["hits"].([]any) {
				h := hv.(map[string]any)
				if h["resource"] != "r" || c.ns != "" && h["ns"] != c.ns {
					continue
				}
				seen = true
				if h["id"] != head {
					t.Errorf("r is served at %v, want its head %s, whose epoch is judged", h["id"], head)
				}
			}
			if !seen {
				t.Fatalf("no hit for e-b/r: %s", got.body)
			}
			name := "r"
			if c.ns != "" {
				name = c.ns + "/r"
			}
			if kid := p37Kids(t, got.body)[name]; kid != "e-b#1" {
				t.Errorf("r sealed under %q, want e-b#1", kid)
			}
		})
	}
}
