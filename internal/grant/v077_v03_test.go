package grant

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// unreadableChain is a CheckAt error that couldn't read the chain.
type unreadableChain struct{ transient bool }

func (e *unreadableChain) Error() string         { return "cannot read the chain" }
func (e *unreadableChain) ChainUnreadable() bool { return e.transient }

// FCORE-3 (§C.4 requireAt): a chain the verifier can't read is no refusal.
// Verify returns CheckAt's error as is, wrapped or not, never a 403; any
// other CheckAt error still refuses the grant.
func TestV077VerifyChainUnreadable(t *testing.T) {
	at := "1" + strings.Repeat("a", 32)
	f := newFixture(t, map[string]any{"requireAt": "cat"})
	g := roundtrip(t, mustMint(t, f, map[string]any{"at": map[string]any{"ns": "cat", "id": at}, "nbf": ts(-time.Minute)}))
	for _, transient := range []bool{true, false} {
		cause := &unreadableChain{transient: transient}
		for _, ret := range []error{cause, fmt.Errorf("checking: %w", cause)} {
			env := f.env()
			env.CheckAt = func(_, _ any, _ time.Time, _ *time.Duration) error { return ret }
			_, err := Verify(g, env)
			var ae *AuthError
			if errors.As(err, &ae) {
				t.Fatalf("transient %v: refused %v", transient, err)
			}
			var cu ChainUnreadableError
			if err != ret || !errors.As(err, &cu) || cu.ChainUnreadable() != transient {
				t.Fatalf("transient %v: %v, want CheckAt's error", transient, err)
			}
		}
	}
	env := f.env()
	env.CheckAt = func(_, _ any, _ time.Time, _ *time.Duration) error { return errors.New("at is not in the chain") }
	_, err := Verify(g, env)
	wantStatus(t, err, 403)
}
