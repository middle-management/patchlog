package catvis_test

import (
	"strings"
	"testing"
)

// TestV082PrincipalRuleBelowGroupsOrRoles (SVC-17i; SERVICES §B.11.5
// Listings are filtered by their subject set, v0.82: "a rule that refers
// to a pointer below /principal not at or below /principal/groups or
// /principal/roles makes the role not count"): reader counts for a
// listing while its rule refers to /principal/groups, to
// /principal/roles or to a pointer below either, and doesn't once it
// refers to any other pointer below /principal, to one that only starts
// with the same letters, or to /principal itself or the whole envelope,
// which read all of it.
func TestV082PrincipalRuleBelowGroupsOrRoles(t *testing.T) {
	t.Parallel()
	docs := map[string]any{
		"root":          map[string]any{"parents": []any{}, "$access": acc("group:editors", "reader")},
		"matches.derby": map[string]any{"parents": parents("root")},
	}
	for path, counts := range map[string]bool{
		"/principal/groups":     true,
		"/principal/groups/0":   true,
		"/principal/roles":      true,
		"/principal/roles/0":    true,
		"/principal/attrs":      false,
		"/principal/attrs/desk": false,
		"/principal/id":         false,
		"/principal/groupsx":    false,
		"/principal/rolesx/0":   false,
		"/principal":            false,
		"":                      false,
	} {
		// A rule that passes whatever is at path, so only what it refers
		// to decides.
		roles := `{"reader":{"can":["read"],"rules":[{"any":[{"op":"test","path":"` + path + `","schema":{}},{"not":{"op":"test","path":"` + path + `","schema":{}}}]}]}}`
		c := seedCatalog(t, matchesDoc(t, roles, ""), docs)
		got := strings.Join(visibleNodes(c, "group:editors"), ",")
		if counts && got != "matches.derby,root" || !counts && got != "" {
			t.Errorf("reader with a rule on %q: editors see %q, counts %v", path, got, counts)
		}
	}
}
