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
