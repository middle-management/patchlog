package dav_test

import (
	"strings"
	"testing"
)

// TDA 31 (§H.5 Copy, §B.11.4 Copies, §2.1 Protection, v0.81 "Leaving an
// embargo"): in a tree with tree-derived access, a reader of the embargoed
// folder TR (inherit: false) who has move and place in Season 2026, is in
// matches's place list and has a role there that counts for create
// copies TR into Season 2026: a new folder without $access, and new items,
// which li, a reader of Season 2026 who can't see TR, then reads. No
// request refuses it: the copier can read the source. A Move of TR's file
// itself into Season 2026 stays 403: it widens (No widening). The caller
// reads TR through tree-derived access, with a grant that only proves who
// it is (the scenario's), or one that also reads cat's node documents.
func TestV081FolderCopyLeavesEmbargo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		world func(t *testing.T) *derivedWorld
		ed    func(t *testing.T, w *derivedWorld) string
	}{
		{"identity only", func(t *testing.T) *derivedWorld { return newDerivedWorld(t) },
			func(t *testing.T, w *derivedWorld) string {
				return w.user(t, "user:ed", "editors-in-chief", "match-desk")
			}},
		{"reads cat", func(t *testing.T) *derivedWorld { return newDerivedWorld(t, "read") },
			func(t *testing.T, w *derivedWorld) string {
				return w.idp.Grant(t, w.s.Now(), "user:ed", []string{"cat"}, []string{"read"}, map[string]any{"groups": []any{"editors-in-chief", "match-desk"}})
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := tc.world(t)
			folderCopyLeavesEmbargo(t, w, tc.ed(t, w))
		})
	}
}

// embargoTR makes TR, the embargoed folder in Season 2026 (inherit:
// false, editors-in-chief: desk), holding rumour.json.
func embargoTR(t *testing.T, w *derivedWorld) {
	t.Helper()
	must(w.ops.CreateDoc(w.ctx, "matches", "rumour", map[string]any{"title": "Rumour", "v": "signs monday"}))
	must(w.ops.CreateDoc(w.ctx, "cat", "tr", map[string]any{"title": "TR", "parents": parents("cat", "season"),
		"$access": map[string]any{"inherit": false, "group:editors-in-chief": []any{"desk"}}}))
	must(w.ops.CreateDoc(w.ctx, "cat", "matches.rumour", map[string]any{"title": "rumour.json", "parents": parents("cat", "tr")}))
}

func folderCopyLeavesEmbargo(t *testing.T, w *derivedWorld, ed string) {
	g := w.g
	embargoTR(t, w)
	w.caughtUp(t)
	li := w.user(t, "user:li")
	sameStrings(t, "ed's TR", names(g.propfindAs(ed, "/cat/Season%202026/TR/"), "/cat/Season 2026/TR/"), []string{"rumour.json"})
	sameStrings(t, "li's Season 2026", names(g.propfindAs(li, "/cat/Season%202026/"), "/cat/Season 2026/"), []string{"Sub/", "derby.json"})

	g.expect(g.doAs(ed, "COPY", "/cat/Season%202026/TR", "", "Destination", "/cat/Season%202026/TR%20copy"), 201, "ed's COPY of TR into Season 2026")
	folder, doc := w.titled(t, "TR copy")
	if folder == "" || folder == "tr" || doc["$access"] != nil || !strings.HasSuffix(hrefsOf(doc)[0], "/season") {
		t.Fatalf("the copy %s: %v", folder, doc)
	}
	node, ndoc := w.titled(t, "rumour.json")
	if node == "matches.rumour" {
		// Both placements are titled so: take the copy's.
		for _, it := range must(w.ops.Heads(w.ctx, "cat", must(w.ops.NSHead(w.ctx, "cat")).ID)) {
			if _, d := g.load("cat", it.Resource); it.Resource != "matches.rumour" && strings.HasPrefix(it.Resource, "matches.") {
				if m, _ := d.(map[string]any); m != nil && m["title"] == "rumour.json" {
					node, ndoc = it.Resource, m
				}
			}
		}
	}
	if node == "matches.rumour" || len(hrefsOf(ndoc)) != 1 || hrefsOf(ndoc)[0] != "/r/cat/"+folder {
		t.Fatalf("rumour.json's copy %s: %v", node, ndoc)
	}
	if _, d := g.load("matches", strings.TrimPrefix(node, "matches.")); d.(map[string]any)["v"] != "signs monday" {
		t.Fatalf("the copied item: %v", d)
	}

	// The copy is readable where its new folder is: li reads it.
	w.caughtUp(t)
	sameStrings(t, "li's TR copy", names(g.propfindAs(li, "/cat/Season%202026/TR%20copy/"), "/cat/Season 2026/TR copy/"), []string{"rumour.json"})
	g.expect(g.doAs(li, "GET", "/cat/Season%202026/TR%20copy/rumour.json", ""), 200, "li's GET of the copy")

	// Moving TR's file itself into Season 2026 widens: refused.
	r := g.expect(g.doAs(ed, "MOVE", "/cat/Season%202026/TR/rumour.json", "", "Destination", "/cat/Season%202026/rumour.json"), 403, "ed's MOVE of rumour.json out of TR")
	if !strings.Contains(r.body, "would give") {
		t.Fatalf("the refused move: %s", r.body)
	}
	if _, d := g.load("cat", "matches.rumour"); hrefsOf(d)[0] != "/r/cat/tr" {
		t.Fatalf("rumour.json after the refused move: %v", d)
	}
}

// §H.5 Copy, for a reader of TR who lists the tree through the tree
// service and doesn't read cat's node documents: TR isn't copied into
// itself or a folder in it, whether the destination's path is below TR's
// or the folder is below TR only through a second parent (Both, in Season
// 2026 and in TR's Inner), which the tree service's ancestors show (§B.5);
// nothing is written. A folder that only a folder hidden from the reader
// leads to from TR (Deep, below Hidden in TR) is no loop for a copy that
// lists what the reader sees, and is copied into, so the refusal shows
// nothing hidden. (Both and Deep give match-desk desk themselves, so only
// the check refuses a copy into them.)
func TestV081FolderCopyNotIntoItselfViaService(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	g := w.g
	embargoTR(t, w)
	must(w.ops.CreateDoc(w.ctx, "cat", "inner", map[string]any{"title": "Inner", "parents": parents("cat", "tr")}))
	must(w.ops.CreateDoc(w.ctx, "cat", "both", map[string]any{"title": "Both", "parents": parents("cat", "season", "inner"),
		"$access": map[string]any{"group:match-desk": []any{"desk"}}}))
	must(w.ops.CreateDoc(w.ctx, "cat", "hid", map[string]any{"title": "Hidden", "parents": parents("cat", "tr"),
		"$access": map[string]any{"inherit": false, "group:board": []any{"desk"}}}))
	must(w.ops.CreateDoc(w.ctx, "cat", "deep", map[string]any{"title": "Deep", "parents": parents("cat", "season", "hid"),
		"$access": map[string]any{"group:match-desk": []any{"desk"}}}))
	w.caughtUp(t)
	ed := w.user(t, "user:ed", "editors-in-chief", "match-desk")
	sameStrings(t, "ed's TR", names(g.propfindAs(ed, "/cat/Season%202026/TR/"), "/cat/Season 2026/TR/"), []string{"Inner/", "rumour.json"})
	sameStrings(t, "ed's Season 2026", names(g.propfindAs(ed, "/cat/Season%202026/"), "/cat/Season 2026/"), []string{"Both/", "Deep/", "Sub/", "TR/", "derby.json"})

	for _, dst := range []string{"/cat/Season%202026/TR/TR%20copy", "/cat/Season%202026/TR/Inner/TR%20copy", "/cat/Season%202026/Both/TR%20copy"} {
		r := g.expect(g.doAs(ed, "COPY", "/cat/Season%202026/TR", "", "Destination", dst), 403, "ed's COPY of TR to "+dst)
		if !strings.Contains(r.body, "into itself") {
			t.Fatalf("the refused copy to %s: %s", dst, r.body)
		}
		if n, _ := w.titled(t, "TR copy"); n != "" {
			t.Fatalf("the refused copy to %s made %s", dst, n)
		}
	}

	g.expect(g.doAs(ed, "COPY", "/cat/Season%202026/TR", "", "Destination", "/cat/Season%202026/Deep/TR%20copy"), 201, "ed's COPY of TR into Deep")
	folder, doc := w.titled(t, "TR copy")
	if folder == "" || doc["$access"] != nil || len(hrefsOf(doc)) != 1 || hrefsOf(doc)[0] != "/r/cat/deep" {
		t.Fatalf("the copy into Deep %s: %v", folder, doc)
	}
}
