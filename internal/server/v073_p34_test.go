package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// P34, CIS-34 (§8.6, §G.5.1.1, §E.1): in an encrypted namespace each
// pruning archive is a sealed bundle, one per resource, whose only
// recipient is the resource's archive key, kid its thumbprint. Bundle
// tools open it with that key, another resource's key doesn't, it is
// padded where the namespace pads, a restore reads it, and a purge
// destroys the key: a copy of the archive kept elsewhere can't be read.
// Archives of namespaces without encryption stay plain bundles.
func TestV073EncryptedArchiveIsSealedBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, level := range []string{"none", "at-rest", "sealed", "sealed+pad"} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			e := newEnv(t, withArchive(t, dir), withoutRetentionLoop, withEncTuning, withKeyStore(newKeyStore(t)))
			doc := map[string]any{"read": "public"}
			switch level {
			case "at-rest", "sealed":
				doc["encryption"] = map[string]any{"level": level}
			case "sealed+pad":
				doc["encryption"] = map[string]any{"level": "sealed", "pad": true}
			}
			e.mkNS("m", doc)
			// A fresh $nonce in every patch set, which sealed namespaces
			// need (§E.2.5).
			revs := []string{e.wr("m", "a", "", withNonce(addRoot(map[string]any{"t": encMarker})))}
			for i := 1; i < 5; i++ {
				revs = append(revs, e.wr("m", "a", revs[i-1], withNonce(ops(op("add", fmt.Sprintf("/p%d", i), encMarker)))))
			}
			e.wr("m", "b", "", withNonce(addRoot(map[string]any{"t": encMarker})))
			e.clock.Advance(time.Hour)
			expect(t, e.prune("m", "a", map[string]any{"horizon": revs[3]}, "admin"), 200)
			p := filepath.Join(dir, "m", "a", revs[3]+".jsonl")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			first, _, _ := bytes.Cut(raw, []byte("\n"))
			env, sealed, err := seal.ParseBundleEnvelope(first)
			if err != nil {
				t.Fatal(err)
			}
			if level == "none" {
				// A plain bundle, as before.
				if sealed || !bytes.Contains(raw, []byte(encMarker)) {
					t.Fatalf("archive of a namespace without encryption: sealed %v", sealed)
				}
				if s := verifyArchive(t, p); s.Lines != 3 {
					t.Fatalf("plain archive: %d lines", s.Lines)
				}
				if _, err := e.e.ArchiveIdentity(ctx, "m", "a"); !errors.Is(err, core.ErrNotEncrypted) {
					t.Fatalf("archive identity without encryption: %v", err)
				}
				return
			}
			if !sealed || bytes.Contains(raw, []byte(encMarker)) {
				t.Fatalf("archive of an encrypted namespace isn't a sealed bundle (sealed %v)", sealed)
			}
			id, err := e.e.ArchiveIdentity(ctx, "m", "a")
			if err != nil {
				t.Fatal(err)
			}
			if len(env.Recipients) != 1 || env.Recipients[seal.Thumbprint(id.PublicKey())] == nil {
				t.Fatalf("recipients %v, want only %s", env.Recipients, seal.Thumbprint(id.PublicKey()))
			}
			// Bundle tools open it with the archive key: a full-history
			// bundle with authors (§8.6).
			pr, isSealed, err := bundle.Unseal(bytes.NewReader(raw), id)
			if err != nil || !isSealed {
				t.Fatalf("unseal: %v %v", isSealed, err)
			}
			s, err := bundle.Verify(pr)
			if err != nil || s.Lines != 3 || !s.Header.Authors {
				t.Fatalf("sealed archive: %v %+v", err, s)
			}
			rd, err := e.e.ReadArchive(ctx, "m", "a", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if s2, err := bundle.Verify(rd); err != nil || s2.Digest != s.Digest {
				t.Fatalf("ReadArchive: %v", err)
			}
			// Another resource's archive key isn't a recipient.
			other, err := e.e.ArchiveIdentity(ctx, "m", "b")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := bundle.Unseal(bytes.NewReader(raw), other); !errors.Is(err, bundle.ErrNotRecipient) {
				t.Fatalf("another resource's key: %v", err)
			}
			// Padding (§E.2.2): with pad, each line's ciphertext, as long
			// as its plaintext, is a bucket.
			sc := bufio.NewScanner(bytes.NewReader(raw))
			sc.Buffer(nil, 1<<20)
			sc.Scan() // the envelope
			unpadded := 0
			for sc.Scan() {
				l := base64.RawURLEncoding.DecodedLen(len(strings.Split(sc.Text(), ".")[3]))
				if l < seal.MinPadded || seal.PadLen(l) != l {
					unpadded++
				}
			}
			if pad := level == "sealed+pad"; pad != (unpadded == 0) {
				t.Fatalf("pad %v, but %d lines aren't padded", pad, unpadded)
			}
			// A restore reads it (§D.4).
			reps, err := archive.Restore(ctx, e.e, archive.RestoreOptions{NS: "m", Name: "a"})
			if err != nil || len(reps) != 1 || !reps[0].Cleared || reps[0].Restored != 3 || len(reps[0].Failed) != 0 {
				t.Fatalf("restore %+v %v", reps, err)
			}
			// Pruned again, a copy kept, then purged: the key is destroyed
			// with the data key (§8.3, §E.1).
			expect(t, e.prune("m", "a", map[string]any{"horizon": revs[4]}, "admin"), 200)
			kept, err := os.ReadFile(filepath.Join(dir, "m", "a", revs[4]+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			expect(t, e.purge("m", "a", revs[4], "admin"), 204)
			if _, err := e.e.ReadArchive(ctx, "m", "a", bytes.NewReader(kept)); !errors.Is(err, core.ErrArchiveKeyDestroyed) {
				t.Fatalf("purged resource's archive opened: %v", err)
			}
			if _, err := e.e.ArchiveIdentity(ctx, "m", "a"); !errors.Is(err, core.ErrArchiveKeyDestroyed) {
				t.Fatalf("purged resource's archive key: %v", err)
			}
		})
	}
}
