package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// TestComplete: completion follows the cli struct: commands, nested
// subcommands, a command's flags (embedded groups included), and nothing
// for a flag's value or a positional argument, where the shell completes
// files.
func TestComplete(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		words []string
		want  []string // all of these, and nothing outside the prefix
		none  bool
	}{
		{words: []string{""}, want: []string{"serve", "get", "merge", "completion"}},
		{words: []string{"pa"}, want: []string{"patch"}},
		{words: []string{"merge", ""}, want: []string{"status", "plan", "apply", "release"}},
		{words: []string{"merge", "release", ""}, want: []string{"plan", "approve", "abandon"}},
		{words: []string{"patch", "--"}, want: []string{"--api", "--bearer-file", "--gesture", "--if", "--help"}},
		{words: []string{"blob", "put", "d/r", "--a"}, want: []string{"--api", "--author", "--at"}},
		{words: []string{"get", "--api", ""}, none: true},
		{words: []string{"get", "--json", ""}, none: true}, // a bool: then NS/NAME, a positional
		{words: []string{"ns", ""}, want: []string{"ls", "create", "get", "config", "log", "purge"}},
		{words: []string{"ns", "ls", "--"}, want: []string{"--prefix", "--json", "--bearer-file"}},
	} {
		got := complete(c.words)
		if c.none {
			if len(got) != 0 {
				t.Errorf("%q: %q, want none", c.words, got)
			}
			continue
		}
		cur := c.words[len(c.words)-1]
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%q: %q lacks %s", c.words, got, w)
			}
		}
		for _, g := range got {
			if !strings.HasPrefix(g, cur) {
				t.Errorf("%q: %s doesn't start with %q", c.words, g, cur)
			}
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var b bytes.Buffer
		if err := writeCompletion(&b, sh); err != nil || !strings.Contains(b.String(), "patchlog __complete") {
			t.Errorf("%s: %v %q", sh, err, b.String())
		}
	}
	var out bytes.Buffer
	if code := run([]string{"__complete", "merge", "rel"}, &out, &out); code != 0 || out.String() != "release\n" {
		t.Errorf("__complete: %d %q", code, out.String())
	}
}
