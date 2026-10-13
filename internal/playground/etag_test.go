package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// A proxy that compresses responses makes the server's strong ETags weak
// (W/"…"): the page takes the same id from either, for the URLs and
// preconditions it builds from it.
func TestETagIDWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := jsFunction(t, js, "etagID") + `
console.log([etagID('"1abc"'), etagID('W/"1abc"'), etagID(' W/"1abc" '), etagID(null), etagID('')].map((v) => '[' + v + ']').join(' '));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if want := "[1abc] [1abc] [1abc] [] []"; strings.TrimSpace(string(out)) != want {
		t.Fatalf("etagID %s, want %s", out, want)
	}
}
