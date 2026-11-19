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
// the bound that makes a rotation due, with a namespace bucket of 12
// tokens that doesn't refill within the test. Then, by then: "rotate",
// the origin rotates by itself; "config", a request under a grant that
// isn't a * key's writes a config entry; "nothing". It returns how many
// resource writes the namespace bucket admits after that to their 409
// frozen before it is empty (429): the tokens it was left with.
func v086FrozenRotation(t *testing.T, then string) int {
	t.Helper()
	e := newSealedAuthEnv(t, withSealBound(1<<20, 6, 1))
	k, issuer := newKey("k"), newKey("issuer")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant",
		"keys":   []any{k.entry("*"), issuer.entry("read", "create", "append", "config")},
		"limits": map[string]any{"ratePerNamespace": map[string]any{"rate": 0.001, "burst": 12.0}}}))
	g := e.grant(issuer, "user:bob", []string{"s"}, []string{"read", "create", "append", "config"})
	heads := map[string]string{}
	for _, name := range []string{"a", "b", "c"} {
		heads[name] = e.wr("s", name, "", withNonce(addRoot(map[string]any{"v": 1.0})), g)
	}
	expect(t, e.patchNS("s", ops(op("add", "/frozen", true)), g), 201)
	head := e.nsHead("s", g)
	// Sealings under K_n until its rotation is due: distinct ranges.
	for _, since := range v82encLog(t, e, "s", g) {
		expect(t, e.get("/ns/s/rev/"+head+"/log?since="+since["id"].(string), g), 200)
	}
	switch then {
	case "rotate":
		done, err := e.e.RetryRotations(context.Background())
		if err != nil || len(done) != 1 || done[0] != "s" {
			t.Fatalf("rotated %v %v, want the frozen namespace s rotated", done, err)
		}
		// The origin's own config entry: system:rotate, no grant, no via
		// (§7.4), and the namespace is still frozen.
		es := v82encLog(t, e, "s", g)
		last := es[len(es)-1]
		if last["kind"] != "config" || last["author"] != core.RotateAuthor {
			t.Fatalf("the rotation's entry: %v", last)
		}
		v82encOwnRotation(t, "a frozen namespace's rotation", last)
		if e.nsHead("s", g) == head {
			t.Fatal("the rotation wrote no entry")
		}
	case "config":
		// A frozen namespace takes config writes (§8.4), and a request's
		// draws the namespace's token.
		expect(t, e.patchNS("s", ops(op("add", "/x-note", "a request's config write")), g), 201)
	default:
		if e.nsHead("s", g) != head {
			t.Fatal("the namespace moved by itself")
		}
	}
	return v086Admitted(t, e, g, heads["a"])
}

// v086Admitted counts the resource writes s's namespace bucket admits to
// their 409 frozen until it is empty. Resource writes stay 409 frozen,
// each drawing the namespace's token (§6.6 Cost).
func v086Admitted(t *testing.T, e *tenv, g, head string) int {
	t.Helper()
	admitted := 0
	for ; admitted < 40; admitted++ {
		r := e.write("PATCH", "s", "a", head, withNonce(ops(op("replace", "/v", 2.0))), g)
		if r.Code == 429 {
			if r.Str("limit") != "ratePerNamespace" {
				t.Fatalf("429 %s, want the namespace's bucket", r.Body)
			}
			break
		}
		expectCode(t, r, 409, "frozen")
	}
	if e.head("s", "a", g) != head {
		t.Fatal("a resource write was written in a frozen namespace")
	}
	return admitted
}

// Encryption levels scenario 90, ENC-26 (§E.2.1 "frozen or not", §8.4,
// §6.6 Exempt: "entries the server writes itself (§7.4)"; v0.86): in a
// frozen sealed namespace whose K_n nears the bound the origin rotates
// by itself: the config entry has no grant or via, is not 409 frozen,
// and draws no token, where a request's config write there draws one
// from the namespace's bucket. Resource writes stay 409 frozen.
func TestV086FrozenRotationDrawsNoToken(t *testing.T) {
	t.Parallel()
	rotated, config, nothing := v086FrozenRotation(t, "rotate"), v086FrozenRotation(t, "config"), v086FrozenRotation(t, "nothing")
	t.Logf("the namespace bucket admitted %d writes after the origin's rotation, %d after a request's config write, %d after neither", rotated, config, nothing)
	if rotated != nothing || config != nothing-1 || rotated == 0 || rotated >= 40 {
		t.Fatalf("the namespace bucket admitted %d writes after the origin's rotation, %d after a request's config write and %d after neither: want the rotation to draw nothing and the request one token", rotated, config, nothing)
	}
}
