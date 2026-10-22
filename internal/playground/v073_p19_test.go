package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// GET /ns/{ns}/rev/{ns_id}/heads answers { heads, next? } (§7.4, RH-10);
// the page reads that, and { items, next? } from servers before v0.65.
func TestV073HeadsPagesWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := jsFunction(t, js, "headsOf") + "\n" + jsFunction(t, js, "allHeads") + `
const pages = {
  new: { '': { heads: [{ resource: 'a' }], next: 'a' }, a: { heads: [{ resource: 'b' }] } },
  old: { '': { items: [{ resource: 'c' }], next: 'c' }, c: { items: [{ resource: 'd' }] } },
};
let shape;
async function api(method, path) {
  const after = decodeURIComponent((/[?]after=(.*)$/.exec(path) || [])[1] || '');
  return { status: 200, json: pages[shape][after] };
}
(async () => {
  const out = [];
  for (shape of ['new', 'old']) out.push((await allHeads('n', '1x')).map((x) => x.resource).join(','));
  out.push(headsOf({}).length);
  console.log(out.join(' '));
})();`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if want := "a,b c,d 0"; strings.TrimSpace(string(out)) != want {
		t.Fatalf("heads %s, want %s", out, want)
	}
}

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
