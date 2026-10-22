package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// TestV073SearchCountsAndNext (IX-8, IX-9, §A.4): the search tab sends
// counts=/a,/b as one value, a repeated counts being 400, and builds the
// page after a result from its view with next as after, for a query with
// q or sort as for any other.
func TestV073SearchCountsAndNext(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := `const INDEX = '/playground/index';
const fields = { srQ: 'goal', srSchema: '', srFilters: '/league=cup', srSort: '-/kickoff', srCounts: '/league, /round', srLimit: '' };
const $ = (id) => ({ value: fields[id] || '', checked: false });
const WRITES = new Map();
` + jsFunction(t, js, "srFilters") + "\n" + jsFunction(t, js, "srParams") + "\n" + jsFunction(t, js, "canonQuery") + "\n" + jsFunction(t, js, "srNextPath") + `
console.log(srParams('demo').getAll('counts').join('|'));
console.log(srNextPath('/demo/at/1def?q=goal&sort=-%2Fkickoff', '2'));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := []string{"/league,/round", "/playground/index/demo/at/1def?after=2&q=goal&sort=-%2Fkickoff"}
	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestV073SearchLackingKeys (IX-2, §A.4): a namespace the index follows
// but lacks the keys of answers 404, as one it doesn't follow; the search
// tab tells the two apart by /_status, which lists it as skipped, and
// says why.
func TestV073SearchLackingKeys(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := `const SR = { status: [{ ns: 'e', skipped: true, reason: 'no keyring names the service key' }, { ns: 'pub' }] };
SR.indexed = SR.status.map((n) => n.ns);
` + jsFunction(t, js, "srStatusOf") + "\n" + jsFunction(t, js, "srFailure") + `
const res = (status, json) => ({ r: { status, json } });
console.log(srFailure('e', res(404, { code: 'not_found', message: 'namespace not indexed' })));
console.log(srFailure('x', res(404, { code: 'not_found', message: 'namespace not indexed' })));
console.log(srFailure('pub', res(503, { code: 'behind', message: 'the index cannot obtain the keys of the namespace yet' })));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := []string{
		"The index follows e but lacks its keys (404): no keyring names the service key",
		"The index does not serve a namespace named x (404): it follows e, pub.",
		"The index has not reached pub yet (503 behind): the index cannot obtain the keys of the namespace yet",
	}
	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
}
