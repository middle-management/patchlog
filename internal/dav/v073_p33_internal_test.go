package dav

import (
	"testing"

	"github.com/middle-management/patchlog/internal/files"
)

// Dedup: the gateway compares sibling names as the tree service's lookup
// compares titles (§H.2 "Siblings", §B.5): one folding, files.TitleKey,
// case-sensitive or not as the server is set.
func TestNameKeyIsTitleKeyV073(t *testing.T) {
	t.Parallel()
	for _, cs := range []bool{false, true} {
		s := &Server{opt: Options{CaseSensitive: cs}}
		for _, pair := range [][2]string{
			{"Report.json", "report.JSON"}, {"k", "K"}, {"Maße", "MASSE"}, {"ﬁle", "file"},
			{"Résumé", "Résumé"}, {"ΣΑΣ", "σας"}, {"a", "b"},
		} {
			for _, n := range pair {
				if got, want := s.nameKey(n), files.TitleKey(n, cs); got != want {
					t.Errorf("case-sensitive %v: nameKey(%q) = %q, files.TitleKey %q", cs, n, got, want)
				}
			}
			if same, want := s.nameKey(pair[0]) == s.nameKey(pair[1]), files.TitleKey(pair[0], cs) == files.TitleKey(pair[1], cs); same != want {
				t.Errorf("case-sensitive %v: %q and %q compare %v here, %v in the tree service", cs, pair[0], pair[1], same, want)
			}
		}
	}
}
