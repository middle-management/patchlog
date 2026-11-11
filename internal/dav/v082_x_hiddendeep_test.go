package dav_test

import (
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/dav"
)

// XT-1 (3), the invariant any report of a cut keeps (SERVICES §B.11.5:
// nothing about a hidden node appears, not even as a count; §B.5 Shared
// nodes in DAGs): Kid is in Season 2026 and in Vault, a folder past the
// depth limit that ed doesn't see for a reason of its own (inherit: false,
// and roles for another group only). The tree service's ancestors of Kid,
// as the gateway asks it for ed's copy, is Kid's one visible path and no
// "tooDeep": the path through Vault isn't one cut short but one ed has
// none of, and saying it was cut would show Vault. TR isn't above Kid as
// ed sees it (TOOLS §H.5 Copy), so the copy is made.
func TestV082XHiddenDeepParentLeavesNoTrace(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	embargoTR(t, w)
	desk := map[string]any{"group:match-desk": []any{"desk"}}
	prev := "tr"
	for i := range 66 {
		name := fmt.Sprintf("d%d", i)
		must(w.ops.CreateDoc(w.ctx, "cat", name, map[string]any{"title": name, "parents": parents("cat", prev), "$access": desk}))
		prev = name
	}
	must(w.ops.CreateDoc(w.ctx, "cat", "vault", map[string]any{"title": "Vault", "parents": parents("cat", prev),
		"$access": map[string]any{"inherit": false, "group:legal": []any{"desk"}}}))
	must(w.ops.CreateDoc(w.ctx, "cat", "kid", map[string]any{"title": "Kid", "parents": parents("cat", "season", "vault"), "$access": desk}))
	w.caughtUp(t)
	var rec v82xRecorded
	g := w.derivedGateway(t, func(o *dav.Options) { o.TreeService = rec.front(t, w.catURL) })
	ed := w.user(t, "user:ed", "editors-in-chief", "match-desk")

	g.expect(g.doAs(ed, "COPY", "/cat/Season%202026/TR", "", "Depth", "0", "Destination", "/cat/Season%202026/Kid/TR%20copy"), 201, "ed's COPY of TR into Kid")
	kid := rec.of(t, "kid")
	paths, _ := kid["paths"].([]any)
	if len(paths) != 1 || fmt.Sprint(paths[0]) != "[season kid]" {
		t.Errorf("ancestors of kid for ed: paths %v, want season/kid alone", kid["paths"])
	}
	for _, k := range []string{"tooDeep", "truncated"} {
		if v, has := kid[k]; has {
			t.Errorf("ancestors of kid for ed: %s %v shows Vault, hidden from him", k, v)
		}
	}
}
