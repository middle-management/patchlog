package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// §7.2 (GB-57): the development stack's core runs -dev, with
// authentication disabled, where a write without X-Author is 400. So every
// tool the compose files start that writes (the janitor's purges, the
// WebDAV gateway's saves) names its author, or a grant.
func TestV073ComposeWritersNameAuthor(t *testing.T) {
	files, err := filepath.Glob("../../compose*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no compose files: %v", err)
	}
	writers := map[string]bool{"janitor": true, "dav": true, "merge": true, "rebase": true, "import": true}
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, cmd := range composeCommands(string(b)) {
			if len(cmd) == 0 || !writers[cmd[0]] {
				continue
			}
			seen[cmd[0]] = true
			named := false
			for _, a := range cmd[1:] {
				named = named || strings.HasPrefix(a, "-author=") || strings.HasPrefix(a, "-bearer=")
			}
			if !named {
				t.Errorf("%s: %v writes without -author or -bearer (§7.2)", filepath.Base(f), cmd)
			}
		}
	}
	if !seen["janitor"] || !seen["dav"] {
		t.Fatalf("writing tools found: %v, want the janitor and dav", seen)
	}
}

// composeCommands returns each command in a compose file, given as a flow
// list on the command: line or as a block list below it.
func composeCommands(s string) [][]string {
	indent := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	unquote := func(a string) string { return strings.Trim(strings.TrimSpace(a), `"'`) }
	var out [][]string
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(l, "command:") {
			continue
		}
		var cmd []string
		switch rest := strings.TrimSpace(strings.TrimPrefix(l, "command:")); {
		case strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]"):
			for _, a := range strings.Split(rest[1:len(rest)-1], ",") {
				cmd = append(cmd, unquote(a))
			}
		case rest == "":
			for in := indent(lines[i]); i+1 < len(lines); i++ {
				n := lines[i+1]
				if t := strings.TrimSpace(n); t != "" && indent(n) <= in {
					break
				} else if strings.HasPrefix(t, "- ") {
					cmd = append(cmd, unquote(t[2:]))
				}
			}
		}
		out = append(out, cmd)
	}
	return out
}
