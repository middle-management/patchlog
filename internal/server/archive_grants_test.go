package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
)

// §8.6: archives are written with authors and grant lines, so archived
// signatures stay verifiable. The key of each grant line is a key of the
// namespace document in force at the first entry that recorded the grant
// (§G.4.1); a restore skips the grant lines.
func TestArchiveCarriesGrantLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := newAuthFixture(t, nil, withArchive(t, dir), withoutRetentionLoop)
	e := f.tenv
	// Two writers, whose grants are signed by two keys of the namespace
	// document.
	nsWriter := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"read", "create", "append", "prune"})
	opWriter := e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	revs := []string{e.create("sec", "a", map[string]any{"n": 0.0}, nsWriter)}
	for i := 1; i < 6; i++ {
		who := nsWriter
		if i%2 == 0 {
			who = opWriter
		}
		revs = append(revs, e.appendRev("sec", "a", revs[i-1], ops(op("replace", "/n", float64(i))), who))
	}
	e.clock.Advance(time.Hour)
	adminG := e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	expect(t, e.prune("sec", "a", map[string]any{"horizon": revs[4]}, adminG), 200)

	path := filepath.Join(dir, "sec", "a", revs[4]+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := verifyArchive(t, path)
	if !s.Header.Authors || s.Signatures == nil || s.Signatures.Grants != 2 || len(s.Signatures.BadGrants) != 0 {
		t.Fatalf("archive: authors %v, signatures %+v", s.Header.Authors, s.Signatures)
	}
	seen := map[string]bool{}
	named := 0
	for i, l := range bytes.Split(bytes.TrimSpace(raw), []byte("\n"))[1:] {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatal(err)
		}
		if m["stored"] != nil {
			if m["ns"] != "sec" || m["key"] == nil {
				t.Fatalf("grant line %v", m)
			}
			seen[m["grant"].(string)] = true
			continue
		}
		g, _ := m["grant"].(string)
		if g == "" || !seen[g] {
			t.Fatalf("line %d names grant %q before its grant line", i+2, g)
		}
		named++
	}
	if len(seen) != 2 || named != 4 {
		t.Fatalf("%d grant lines, %d history lines naming one", len(seen), named)
	}

	// Restore skips the grant lines and brings the patch sets back.
	moved := t.TempDir()
	if err := os.Rename(filepath.Join(dir, "sec"), filepath.Join(moved, "sec")); err != nil {
		t.Fatal(err)
	}
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{From: archive.URL(moved)})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 || !reps[0].Cleared || reps[0].Restored != 4 || len(reps[0].Failed) != 0 {
		t.Fatalf("restore %+v", reps)
	}
	_ = bundle.Version
}
