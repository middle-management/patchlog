package server

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/core"
)

// Encryption levels scenario 89, DEL-16 (§8.6 Branches don't prune and
// Archive; v0.86: "writes nothing, an archive included: only namespaces
// that aren't branches have archives"): branch Z has an archive
// configured, by the deployment's default destination and by its own
// document's retention rule. A prune there that passes its checks is 200
// with the current horizon, and nothing is written: no archive, no prune
// entry, no horizon moved. The same prune in the base archives.
func TestV086BranchPruneWithArchiveWritesNothing(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	def, own := filepath.Join(root, "default"), filepath.Join(root, "own")
	e := newEnv(t, withArchive(t, def, own), withoutRetentionLoop)
	rule := []any{map[string]any{"keep": map[string]any{"age": "P30D"}, "archive": archive.URL(own)}}
	e.mkNS("n", map[string]any{"read": "public"})
	c := e.chain("n", "derby", 4)
	expect(t, e.branch("n", map[string]any{"name": "z", "patches": ops(op("add", "/retention", rule))}, "alice"), 201)
	if got := e.configOf("z")["retention"]; got == nil {
		t.Fatalf("branch z's document has no retention rule: %v", e.configOf("z"))
	}
	z1 := e.appendRev("z", "derby", c[3], ops(op("replace", "/n", 9.0)))
	e.clock.Advance(time.Hour)
	files := func() []string {
		var out []string
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				out = append(out, p)
			}
			return nil
		})
		return out
	}
	zHead, nHead := e.nsHead("z"), e.nsHead("n")
	for _, body := range []map[string]any{
		{"horizon": c[2]},
		{"horizon": z1},
		{"horizon": c[3], "archive": false},
	} {
		r := e.prune("z", "derby", body, "admin")
		expect(t, r, 200)
		// The current horizon: none yet, so the genesis.
		if len(r.Obj()) != 1 || r.Str("horizon") != c[0] {
			t.Fatalf("prune %v in the branch: %s, want horizon %s", body, r.Body, c[0])
		}
		noEntry(t, e, r, "z", zHead)
		noEntry(t, e, r, "n", nHead)
		if fs := files(); len(fs) != 0 {
			t.Fatalf("prune %v in the branch wrote an archive: %v", body, fs)
		}
	}
	// No horizon moved: every revision is served, in the branch and the base.
	for _, id := range c {
		expect(t, e.get("/r/z/derby/rev/"+id), 200)
		expect(t, e.get("/r/n/derby/rev/"+id), 200)
	}
	expect(t, e.get("/r/z/derby/rev/"+z1+"/log"), 200)
	// The base, which isn't a branch, archives what it prunes: up to the
	// branch point's revision, which the branch protects.
	r := e.prune("n", "derby", map[string]any{"horizon": c[3]}, "admin")
	expect(t, r, 200)
	if r.Str("horizon") != c[3] || len(files()) != 1 {
		t.Fatalf("prune in the base: %s, archives %v", r.Body, files())
	}
	// The branch then sees the base's horizon, and still writes nothing.
	zHead = e.nsHead("z")
	r = e.prune("z", "derby", map[string]any{"horizon": z1}, "admin")
	expect(t, r, 200)
	if r.Str("horizon") != c[3] || len(files()) != 1 {
		t.Fatalf("prune in the branch after the base's: %s, archives %v", r.Body, files())
	}
	noEntry(t, e, r, "z", zHead)
}

// v086FrozenRotation builds a frozen sealed namespace s whose K_n is at
// the bound that makes a rotation due, with a namespace bucket of burst
// tokens that doesn't refill within the test, rotates it if rotate, and
// returns how many resource writes the namespace bucket then admits to
// their 409 frozen before it is empty (429).
func v086FrozenRotation(t *testing.T, rotate bool) int {
	t.Helper()
	e := newSealedEnv(t, withSealBound(1<<20, 6, 1))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public",
		"limits": map[string]any{"ratePerNamespace": map[string]any{"rate": 0.001, "burst": 12.0}}}))
	heads := map[string]string{}
	for _, name := range []string{"a", "b", "c"} {
		heads[name] = e.wr("s", name, "", withNonce(addRoot(map[string]any{"v": 1.0})))
	}
	first := e.plainNSLog("s", e.nsHead("s")).Entries[0]["id"].(string)
	expect(t, e.patchNS("s", ops(op("add", "/frozen", true)), ""), 201)
	head := e.nsHead("s")
	expect(t, e.get("/ns/s/rev/"+head+"/log?since="+first), 200)
	if rotate {
		done, err := e.e.RetryRotations(context.Background())
		if err != nil || len(done) != 1 || done[0] != "s" {
			t.Fatalf("rotated %v %v, want the frozen namespace s rotated", done, err)
		}
		// The origin's own config entry: system:rotate, no grant, no via
		// (§7.4), and the namespace is still frozen.
		last := v82encLastEntry(t, e, "s")
		if last["kind"] != "config" || last["author"] != core.RotateAuthor {
			t.Fatalf("the rotation's entry: %v", last)
		}
		v82encOwnRotation(t, "a frozen namespace's rotation", last)
		cfg := e.configOf("s")
		if cfg["frozen"] != true || cfg["encryption"].(map[string]any)["epoch"] != 2.0 {
			t.Fatalf("after the rotation: %v", cfg)
		}
	} else if e.nsHead("s") != head {
		t.Fatal("the namespace moved without a rotation")
	}
	// Resource writes stay 409 frozen, each drawing the namespace's
	// token (§6.6 Cost), until its bucket is empty.
	admitted := 0
	for ; admitted < 40; admitted++ {
		r := e.write("PATCH", "s", "a", heads["a"], withNonce(ops(op("replace", "/v", 2.0))), "bob")
		if r.Code == 429 {
			if r.Str("limit") != "ratePerNamespace" {
				t.Fatalf("429 %s, want the namespace's bucket", r.Body)
			}
			break
		}
		expectCode(t, r, 409, "frozen")
	}
	if e.head("s", "a") != heads["a"] {
		t.Fatal("a resource write was written in a frozen namespace")
	}
	return admitted
}

// Encryption levels scenario 90, ENC-26 (§E.2.1 "frozen or not", §8.4,
// §6.6 Exempt: "entries the server writes itself (§7.4)"; v0.86): in a
// frozen sealed namespace whose K_n nears the bound the origin rotates
// by itself: the config entry has no grant or via, is not 409 frozen,
// and draws no token, so the namespace's bucket admits as many requests
// after it as where no rotation ran. Resource writes stay 409 frozen.
func TestV086FrozenRotationDrawsNoToken(t *testing.T) {
	t.Parallel()
	with, without := v086FrozenRotation(t, true), v086FrozenRotation(t, false)
	t.Logf("the namespace bucket admitted %d writes after the rotation, %d without one", with, without)
	if with != without || with == 0 || with >= 40 {
		t.Fatalf("the namespace bucket admitted %d writes after the origin's rotation and %d without one: want the same, the bucket's remaining tokens", with, without)
	}
}
