package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The engine opens its SQLite database at exactly Options.Path, '#' and
// '?' in it and all, with the DSN's pragmas: "file:" + path cut the path
// at the '#' (t.TempDir of an unnamed subtest holds "#00"), so another
// file held the data.
func TestSQLitePathOpensThatFile(t *testing.T) {
	skipOnPostgres(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a#00?b.db")
	open := func() *Engine {
		t.Helper()
		e, err := Open(Options{Path: path, BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	ctx := context.Background()
	r := Request{NS: "n", Cred: Credentials{Author: "a"}}
	e := open()
	if _, err := e.WriteConfig(ctx, r, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteResource(ctx, r, Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"t": 1}}}}}}); err != nil {
		t.Fatal(err)
	}
	h, err := e.ResourceHead(ctx, "n", "d", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]string{"journal_mode": "wal", "busy_timeout": "10000", "foreign_keys": "1"} {
		var got string
		if err := e.db.QueryRow(`PRAGMA ` + q).Scan(&got); err != nil || got != want {
			t.Errorf("PRAGMA %s = %q, %v; want %q", q, got, err, want)
		}
	}
	e.Close()

	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		if !strings.HasPrefix(ent.Name(), "a#00?b.db") {
			t.Errorf("stray file %q", ent.Name())
		}
	}
	e = open()
	defer e.Close()
	if got, err := e.ResourceHead(ctx, "n", "d", Credentials{}); err != nil || got.Head != h.Head {
		t.Errorf("reopened: head %+v, %v; want %s", got, err, h.Head)
	}
}
