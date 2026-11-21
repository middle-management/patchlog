package merge

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// BYTES-4 (§F.9 The plan, v0.81 "a root operation an add or replace at
// \"\""): a step's patch set loses a fresh top-level $nonce only from the
// value of an add or replace whose path is "". A test at "" keeps it, as
// any other operation's value does.
func TestV081DigestRootOpIsAddOrReplace(t *testing.T) {
	fresh := "abcdefghijklmnopqrstuvwxyz"
	test := map[string]any{"op": "test", "path": "", "value": map[string]any{"$nonce": fresh, "t": 1.0}}
	steps := []client.Step{
		client.PatchStep([]any{test}),
		client.PatchStep([]any{map[string]any{"op": "add", "path": "", "value": map[string]any{"$nonce": fresh, "t": 1.0}}}),
		client.PatchStep([]any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"$nonce": fresh, "t": 1.0}}}),
	}
	got := string(jsonv.Canonical(jsonv.FromGo(digestSteps(steps))))
	want := `[[{"op":"test","path":"","value":{"$nonce":"` + fresh + `","t":1}}],` +
		`[{"op":"add","path":"","value":{"t":1}}],` +
		`[{"op":"replace","path":"","value":{"t":1}}]]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
