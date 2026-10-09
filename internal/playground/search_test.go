package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// §A.4 (v0.49): a ref query without q or sort pages by name, its next a
// bare resource name to send as after at the result's at URL; any other
// query's next is the URL of the following page.
func TestSearchNextPathWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := "const INDEX = '/playground/index';\n" + jsFunction(t, js, "srNextPath") + `
console.log(srNextPath('/g/1abc/pa/at/1def?limit=2&ref=%2Fr%2Ft%2Fx', 'a'));
console.log(srNextPath('/pa/at/1def?after=a&limit=2&ref=%2Fr%2Ft%2Fx', 'b'));
console.log(srNextPath('/pa/at/1def?q=x', '/pa/at/1def?after=20&q=x'));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := []string{
		"/playground/index/g/1abc/pa/at/1def?limit=2&ref=%2Fr%2Ft%2Fx&after=a",
		"/playground/index/pa/at/1def?after=b&limit=2&ref=%2Fr%2Ft%2Fx",
		"/playground/index/pa/at/1def?after=20&q=x",
	}
	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("next paths %q, want %q", got, want)
	}
}
