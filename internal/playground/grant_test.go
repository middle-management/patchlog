package playground

import (
	"os/exec"
	"strings"
	"testing"
)

// §1, §7.4 (v0.38): the namespace log's grant column tells an entry written
// with authentication disabled ("grant": null) from one the server wrote
// itself (no "grant").
func TestGrantTitleWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := jsFunction(t, js, "grantTitle") + `
for (const e of [{ author: 'ann', grant: null }, { author: 'ann' }, { author: 'ann', grant: { id: '1x', sub: 'user:ann', kid: 'k' } }]) console.log(grantTitle(e));`
	out, err := exec.Command(node, "-e", src).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "authentication disabled") || !strings.Contains(lines[1], "server itself") || !strings.Contains(lines[2], "root sub user:ann, key k") {
		t.Fatalf("grant titles %q", lines)
	}
}
