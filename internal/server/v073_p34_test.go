package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/middle-management/patchlog/internal/grant"
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

// P34, MF-44 (§8.6, §G.4.1, §7.1): archives are written with authors, so
// their history lines carry the entry's authorship members, via included:
// a revision written under a narrowed grant names its delegatees, and one
// written under the root grant carries none. via isn't hashed: the
// archive verifies, ids recomputed.
func TestV073ArchiveCarriesVia(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := newAuthFixture(t, nil, withArchive(t, dir), withoutRetentionLoop)
	e := f.tenv
	root, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:w", "ns": []any{"sec"}, "can": []any{"read", "create", "append"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	nar, err := root.Narrow(map[string]any{"via": "svc:bot"})
	if err != nil {
		t.Fatal(err)
	}
	revs := []string{e.create("sec", "a", map[string]any{"n": 0.0}, nar.Encode())}
	revs = append(revs, e.appendRev("sec", "a", revs[0], ops(op("replace", "/n", 1.0)), root.Encode()))
	revs = append(revs, e.appendRev("sec", "a", revs[1], ops(op("replace", "/n", 2.0)), root.Encode()))
	e.clock.Advance(time.Hour)
	adminG := e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	expect(t, e.prune("sec", "a", map[string]any{"horizon": revs[2]}, adminG), 200)
	path := filepath.Join(dir, "sec", "a", revs[2]+".jsonl")
	if s := verifyArchive(t, path); !s.Header.Authors || s.Lines != 3 {
		t.Fatalf("archive: %+v", s)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	vias := map[string]any{}
	for _, l := range bytes.Split(bytes.TrimSpace(raw), []byte("\n"))[1:] {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatal(err)
		}
		if id, ok := m["id"].(string); ok {
			vias[id] = m["via"]
		}
	}
	if v, _ := vias[revs[0]].([]any); len(v) != 1 || v[0] != "svc:bot" {
		t.Fatalf("the delegated revision's line: via %v", vias[revs[0]])
	}
	if v, has := vias[revs[1]]; has && v != nil {
		t.Fatalf("the root grant's revision's line: via %v", v)
	}
}

// P34 review (§8.6, §7.8, §G.5.1.1): a pruned attachment is archived as
// one blob line, and one of 150 MiB, which -max-blob-size allows, is a
// line longer than seal.MaxBundleLine sealed. The archive the server
// writes is the only copy of the pruned bytes, so in an encrypted
// namespace it is written and read back without that bound, as a plain
// bundle archive is: a restore brings the attachment back in both.
// Not parallel: it holds a few copies of the blob in memory.
func TestV073LargeBlobArchiveRestores(t *testing.T) {
	ctx := context.Background()
	for _, level := range []string{"none", "at-rest"} {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			big := func(o *core.Options) {
				withBlobTuning(o)
				o.Limits.BlobSize, o.Maximums.BlobSize = 256<<20, 256<<20
				o.Limits.BlobPending, o.Maximums.BlobPending = 512<<20, 512<<20
			}
			e := newEnv(t, big, withArchive(t, dir), withoutRetentionLoop, withKeyStore(newKeyStore(t)))
			doc := map[string]any{"read": "public"}
			if level != "none" {
				doc["encryption"] = map[string]any{"level": level}
			}
			e.mkNS("m", doc)
			data := bytes.Repeat([]byte("x"), 150<<20)
			b := e.upload("m", "r", "application/octet-stream", data)
			revs := []string{e.create("m", "r", map[string]any{"a": ref(b, "application/octet-stream", len(data), "")})}
			revs = append(revs, e.appendRev("m", "r", revs[0], ops(op("remove", "/a"))))
			revs = append(revs, e.appendRev("m", "r", revs[1], ops(op("add", "/n", 1.0))))
			e.clock.Advance(time.Hour)
			expect(t, e.prune("m", "r", map[string]any{"horizon": revs[2]}, "admin"), 200)
			expectCode(t, e.get(blobPath("m", "r", b)), 410, "pruned")
			// The archive's longest line, streamed: in the encrypted
			// namespace, the sealed blob line is past seal's bound.
			fh, err := os.Open(filepath.Join(dir, "m", "r", revs[2]+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			br := bufio.NewReaderSize(fh, 1<<16)
			longest, cur := 0, 0
			for {
				chunk, isPrefix, err := br.ReadLine()
				if err != nil {
					break
				}
				cur += len(chunk)
				if !isPrefix {
					longest, cur = max(longest, cur), 0
				}
			}
			fh.Close()
			if level != "none" && longest <= seal.MaxBundleLine {
				t.Fatalf("the sealed blob line is %d bytes, within seal's bound %d", longest, seal.MaxBundleLine)
			}
			// The blob line's bytes are checked against the blob's id as
			// they are restored (§3.7).
			reps, err := archive.Restore(ctx, e.e, archive.RestoreOptions{NS: "m", Name: "r", Log: t.Logf})
			if err != nil || len(reps) != 1 || len(reps[0].Failed) != 0 || !reps[0].Cleared || reps[0].Blobs != 1 {
				t.Fatalf("restore %+v %v", reps, err)
			}
		})
	}
}
