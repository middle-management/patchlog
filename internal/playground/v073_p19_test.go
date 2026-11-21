package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// With authentication disabled a write without X-Author is 400 (§7.2): the
// page sends a default author until its author box is filled, but not
// beside a bearer, nor to a deployment with authentication on (carry-over
// from P01).
func TestV073DevAuthorWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := "const DEV_AUTHOR = 'anonymous';\nlet authDisabled = false;\nconst box = { author: '', bearer: '' };\nconst $ = (id) => ({ value: box[id] });\n" +
		jsFunction(t, js, "devAuthor") + "\n" + jsFunction(t, js, "authHeaders") + `
const out = [];
for (const [dis, author, bearer] of [[true, '', ''], [true, 'bob', ''], [true, '', 'tok'], [false, '', ''], [false, 'bob', '']]) {
  authDisabled = dis; box.author = author; box.bearer = bearer;
  out.push(authHeaders()['X-Author'] || '-');
}
console.log(out.join(' '));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if want := "anonymous bob - - bob"; strings.TrimSpace(string(out)) != want {
		t.Fatalf("X-Author %s, want %s", out, want)
	}
}

// A sealed document's ETag is "{id}.{e}" (§E.2.2, RH-12): the page takes
// the id from it, as from any tag, for the URLs and preconditions it
// builds.
func TestV073SealedETagIDWithNode(t *testing.T) {
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
console.log([etagID('"1abc.2"'), etagID('W/"1abc.13"'), etagID('"1abc"')].join(' '));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if want := "1abc 1abc 1abc"; strings.TrimSpace(string(out)) != want {
		t.Fatalf("etagID %s, want %s", out, want)
	}
}
