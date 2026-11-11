package grant

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestV082KeyScopeOrder (SVC-15i; SPEC §C.2 item 3, CONFORMANCE AUTH-6,
// v0.82): a key's scope is checked in the order can, sub, maxTtl, groups,
// roles, attrs, requireAt and maxLag, the first that fails giving the
// answer. A grant that fails each part in turn is refused for the earliest
// one it fails: before v0.82 maxTtl answered before sub.
func TestV082KeyScopeOrder(t *testing.T) {
	scope := map[string]any{
		"can": []any{"read"}, "sub": "^user:al$", "maxTtl": "PT5M",
		"groups": map[string]any{"allow": []any{"fans"}}, "roles": map[string]any{"allow": []any{"reader"}}, "requireAt": "cat",
	}
	f := newFixture(t, scope)
	// Fails every part: can (append), sub (bob), maxTtl (an hour), groups
	// (desk), roles (editor) and requireAt (no at).
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
		{"roles", map[string]any{"roles": []string{"reader"}}, "requires at"},
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

// TestV082RequireAtRefusalNamesNothing (SVC-15i; SPEC §C.4, §C.5.2,
// v0.82): the 403 for an at a readable chain rejects is exactly "at
// rejected by requireAt", whatever CheckAt's error says: none of its
// detail, which may name the requireAt namespace, is appended. Before
// v0.82 it was "at rejected: " and the checker's text.
func TestV082RequireAtRefusalNamesNothing(t *testing.T) {
	at := "1" + strings.Repeat("a", 32)
	f := newFixture(t, map[string]any{"requireAt": "cat-season"})
	g := roundtrip(t, mustMint(t, f, map[string]any{"at": map[string]any{"ns": "cat-season", "id": at}, "nbf": ts(-time.Minute)}))
	for _, detail := range []string{
		"unknown namespace cat-season",
		"at is not in the chain of cat-season",
		"at was not the head of cat-season within maxLag (PT5M) before the grant was issued",
	} {
		env := f.env()
		env.CheckAt = func(_, _ any, _ time.Time, _ *time.Duration) error { return errors.New(detail) }
		_, err := Verify(g, env)
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Status != 403 || ae.Msg != "at rejected by requireAt" {
			t.Errorf("CheckAt %q: %v, want exactly %q", detail, err, RequireAtRefusal)
		}
	}
}
