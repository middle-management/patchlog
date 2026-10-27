package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// §A.4 (v0.49): a ref query without q or sort pages by name, its next a
// bare resource name to send as after at the result's at URL, which is
// built in the canonical form (§A.5) to save a redirect. Since v0.73 every
// query pages so, a query with q or sort by the opaque position its next
// gives, no longer a URL.
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
	src := "const INDEX = '/playground/index';\n" + jsFunction(t, js, "canonQuery") + "\n" + jsFunction(t, js, "srNextPath") + `
console.log(srNextPath('/pa/g/1abc/at/1def?limit=2&ref=%2Fr%2Ft%2Fx', 'a'));
console.log(srNextPath('/pa/at/1def?after=a&limit=2&ref=%2Fr%2Ft%2Fx', 'b'));
console.log(srNextPath('/pa/at/1def?q=x', '20'));
console.log(srNextPath('/pa/at/1def?ref=%2Fr%2Ft%2Fx', "it's a (b)*! ~å"));
console.log(canonQuery(new URLSearchParams('z=1&a=b&a=a&q=two+words&%C3%A5=1&%C3%A4=%F0%9F%98%80&%C3%A4=%EF%BF%BD')));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := []string{
		"/playground/index/pa/g/1abc/at/1def?after=a&limit=2&ref=%2Fr%2Ft%2Fx",
		"/playground/index/pa/at/1def?after=b&limit=2&ref=%2Fr%2Ft%2Fx",
		"/playground/index/pa/at/1def?after=20&q=x",
		"/playground/index/pa/at/1def?after=it%27s%20a%20%28b%29%2A%21%20~%C3%A5&ref=%2Fr%2Ft%2Fx",
		// UTF-8 byte order puts U+FFFD (EF BF BD) before U+1F600 (F0 …),
		// which UTF-16 code units would not.
		"?a=a&a=b&q=two%20words&z=1&%C3%A4=%EF%BF%BD&%C3%A4=%F0%9F%98%80&%C3%A5=1",
	}
	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("next paths %q, want %q", got, want)
	}
}
