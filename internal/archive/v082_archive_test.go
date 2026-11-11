package archive_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// BT-4 (§G.5.1 access, §8.6): Encode writes the archive's access in the
// header, { ns: access }. An archive that names none of the four levels
// is labelled the strictest: a header without access would read as
// private (bundle.Header.AccessOf), below an e2e or sealed namespace.
func TestV082EncodeWritesAccess(t *testing.T) {
	t.Parallel()
	patches, err := client.ToValue(client.GenesisPatches(map[string]any{"n": 1.0}))
	if err != nil {
		t.Fatal(err)
	}
	id := ids.Revision(nil, jsonv.Canonical(patches)).String()
	for given, want := range map[string]string{
		"public":  bundle.AccessPublic,
		"private": bundle.AccessPrivate,
		"sealed":  bundle.AccessSealed,
		"e2e":     bundle.AccessE2E,
		"":        bundle.AccessE2E,
		"at-rest": bundle.AccessE2E,
	} {
		b := &core.ArchiveBundle{Origin: "https://cms.example", Created: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
			NS: "main", Name: "a", At: ids.Hash(nil, []byte("at")).String(), Head: id, Access: given,
			Entries: func(yield func(core.ArchiveEntry) error) error {
				return yield(core.ArchiveEntry{ID: id, Kind: "rev", Patches: patches, Author: "alice", Created: "2026-10-04T12:00:00Z"})
			}}
		var buf bytes.Buffer
		if err := archive.Encode(context.Background(), &buf, b); err != nil {
			t.Fatalf("access %q: %v", given, err)
		}
		sum, err := bundle.Verify(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("access %q: the archive: %v", given, err)
		}
		if got := sum.Header.Access; len(got) != 1 || got["main"] != want {
			t.Fatalf("access %q: header access %v, want %s", given, got, want)
		}
	}
}
