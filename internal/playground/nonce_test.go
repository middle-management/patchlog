package playground

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// §C.7: the editor adds a fresh $nonce only to a patch set that results in
// an object, since no other root has a member to add; where the result
// isn't known it adds one, and the server tells.
func TestNonceFitsWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	src := `require(process.argv[1]);
const Z = globalThis.PLSeal;
const S = { resState: null };
` + jsFunction(t, js, "nonceFits") + `
const add = (path, value) => ({ op: 'add', path, value });
const out = [];
out.push(nonceFits('create', [add('', { a: 1 })]), nonceFits('create', [add('', [1])]), nonceFits('append', [add('/-', 3)]));
S.resState = { kind: 'live', doc: [1, 2] };
out.push(nonceFits('append', [add('/-', 3)]), nonceFits('append', [add('', {})]), nonceFits('append', [add('/x/y', 1)]));
S.resState = { kind: 'tomb', lastDoc: { a: 1 } };
out.push(nonceFits('restore', []), nonceFits('restore', [add('', 'x')]));
S.resState = { kind: 'live', doc: null };
out.push(nonceFits('append', []));
console.log(out.join(' '));`
	out, err := exec.Command(node, "-e", src, sealJS).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if want := "true false true false true true true false false"; strings.TrimSpace(string(out)) != want {
		t.Fatalf("nonceFits %s, want %s", out, want)
	}
}
