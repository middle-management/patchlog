package grant

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestV082KeyScopeOrder (SVC-15i; SPEC §C.2 item 3, CONFORMANCE AUTH-6,
// v0.82): a key's scope is checked in the order can, sub, maxTtl, groups,
// roles and attrs, the first that fails giving the
// answer. A grant that fails each part in turn is refused for the earliest
// one it fails: before v0.82 maxTtl answered before sub.
func TestV082KeyScopeOrder(t *testing.T) {
	scope := map[string]any{
		"can": []any{"read"}, "sub": "^user:al$", "maxTtl": "PT5M",
		"groups": map[string]any{"allow": []any{"fans"}}, "roles": map[string]any{"allow": []any{"reader"}},
	}
	f := newFixture(t, scope)
	// Fails every part: can (append), sub (bob), maxTtl (an hour), groups
	// (desk) and roles (editor).
	failing := map[string]any{"roles": []string{"editor"}}
	// What makes each part pass, added in the order the parts are checked.
	fixes := []struct {
		part string
		fix  map[string]any
		want string // of the refusal once part passes: the next part's
	}{
		{"", nil, "may not grant"},
		{"can", map[string]any{"can": []string{"read"}}, "sub "},
		{"sub", map[string]any{"sub": "user:al"}, "maxTtl"},
		{"maxTtl", map[string]any{"exp": ts(time.Minute)}, "group "},
		{"groups", map[string]any{"groups": []string{"fans"}}, "role "},
	}
	block := map[string]any{}
	for k, v := range failing {
		block[k] = v
	}
	for _, c := range fixes {
		for k, v := range c.fix {
			block[k] = v
		}
		_, err := Verify(roundtrip(t, mustMint(t, f, block)), f.env())
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Status != 403 || !strings.Contains(ae.Msg, c.want) {
			t.Errorf("once %q passes: %v, want a 403 holding %q", c.part, err, c.want)
		}
	}
}

// TestV082SubBeforeMaxTtl (SVC-15i; SPEC §C.2 item 3): a grant failing
// both its key's sub scope and its maxTtl reports sub.
func TestV082SubBeforeMaxTtl(t *testing.T) {
	f := newFixture(t, map[string]any{"sub": "^user:al$", "maxTtl": "PT5M"})
	_, err := Verify(roundtrip(t, mustMint(t, f, nil)), f.env())
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != 403 || !strings.HasPrefix(ae.Msg, "sub ") {
		t.Fatalf("a grant failing sub and maxTtl: %v, want the sub refusal", err)
	}
}
