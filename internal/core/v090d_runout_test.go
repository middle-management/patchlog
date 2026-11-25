package core

import (
	"errors"
	"fmt"
	"testing"
)

// v0.90 §6.6 Validation work, §7.7: only the refusal of a read during
// which the request's one budget ran out is the run-out's own, the one a
// long-poll answers 204 (ReadBudgetRanOut). A revoked or expired grant's
// 401, a purge's 410, a 429, an error that isn't an *Error, and any
// refusal of a read that began with the budget spent are not.
func TestV090DReadRanOutRefusal(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		ranOut bool
		want   bool
	}{
		{"403 ran out", errReadRanOut(), true, true},
		{"404 ran out", notFound(), true, true},
		{"403 not ran out", forbidden("no"), false, false},
		{"401 ran out", apiErr(401, "unauthenticated", "message", "grant revoked"), true, false},
		{"410 ran out", gone(), true, false},
		{"429 ran out", rateRefused(0, "x"), true, false},
		{"wrapped", fmt.Errorf("w: %w", notFound()), true, false},
		{"other", errors.New("boom"), true, false},
		{"nil", nil, true, false},
	} {
		got := ranOutRefusal(c.err, c.ranOut)
		if ReadBudgetRanOut(got) != c.want {
			t.Errorf("%s: ReadBudgetRanOut %v, want %v", c.name, !c.want, c.want)
		}
		if c.err != nil && got.Error() != c.err.Error() {
			t.Errorf("%s: %v, want %v unchanged", c.name, got, c.err)
		}
	}
	// The original is never changed: it may be shared.
	e := notFound()
	_ = ranOutRefusal(e, true)
	if ReadBudgetRanOut(e) {
		t.Fatal("ranOutRefusal changed its argument")
	}
}
