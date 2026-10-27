package dav_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// The base a PUT names (§H.4): If-Match's first value, W/ dropped; else
// the If header's first entity tag, not negated, of the first list that
// applies to the file (a list tagged with another resource doesn't);
// If-Match: * only asks that the file exist, and the head is the base, so
// the file as written wins on the paths it changes.
func TestSaveBaseForms(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	mine := rendered(map[string]any{"a": "mine", "b": "1"})
	for i, hdr := range [][]string{
		{"If-Match", `W/"%s", "other"`},
		{"If", `<%[2]s/docs/other.json> (["other"]) <%[2]s/docs/x%[3]d.json> (Not ["other"] ["%[1]s"])`},
	} {
		name := fmt.Sprintf("x%d", i)
		r0 := e.create("docs", name, map[string]any{"a": "1", "b": "1"})
		e.theirs("docs", name, replace("/b", "theirs"))
		v := fmt.Sprintf(hdr[1], r0, e.dav.URL, i)
		e.expect(e.do("PUT", "/docs/"+name+".json", mine, hdr[0], v), 201, "PUT "+hdr[0]+": "+v)
		_, doc := e.load("docs", name)
		sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
	}

	e.create("docs", "star", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/star.json", ""), 200, "GET").body
	e.theirs("docs", "star", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/star.json", edit(t, buf, `"a": "1"`, `"a": "mine"`), "If-Match", "*"), 201, "PUT If-Match: *")
	_, doc := e.load("docs", "star")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "1"})
}

// A base the core no longer has (pruned, §8.6) can't be compared: the
// save is a 409 asking for a reload, whether the PUT's If-Match names it
// or it is the user's record, and the head is never taken instead; after
// the reload the edit saves.
func TestSavePrunedBase(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	r0 := e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "2"))
	e.theirs("docs", "x", replace("/b", "theirs"))
	h, _ := e.load("docs", "x")
	e.s.Clock.Advance(10 * time.Minute) // past the retry window, which pruning keeps (§8.6)
	if p := must(e.c.Prune(e.ctx, "docs", "x", client.PruneRequest{Horizon: h.ID})); p.Horizon != h.ID {
		t.Fatalf("pruned to %s, not the head", p.Horizon)
	}

	r := e.expect(e.do("PUT", "/docs/x.json", rendered(map[string]any{"a": "mine", "b": "1"}), "If-Match", `"`+r0+`"`), 409, "PUT If-Match a pruned revision")
	if !strings.Contains(r.body, "pruned") || !strings.Contains(r.body, "reload") {
		t.Fatalf("409 %q", r.body)
	}
	r = e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT from a record whose history is pruned")
	if !strings.Contains(r.body, "pruned") {
		t.Fatalf("409 %q", r.body)
	}
	e.expectLive("docs", "x", h, "after refused saves")
	buf = e.expect(e.do("GET", "/docs/x.json", ""), 200, "reload").body
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT after the reload")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
}

// Others' writes since the base are those of the log entries between it
// and the head (§11.3, §H.4), not only what differs: a value someone
// changed and changed back, or an array they grew and shrank again, was
// written, and a save that changes it is a 409 (it merged before
// Addendum H). The principal's own writes in between are its own to
// change again.
func TestSaveLogWrites(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "items": []any{"p", "q"}, "n": "0"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/a", "2"))
	e.theirs("docs", "x", replace("/a", "1"))
	e.theirs("docs", "x", map[string]any{"op": "add", "path": "/items/-", "value": "r"})
	e.theirs("docs", "x", map[string]any{"op": "remove", "path": "/items/2"})
	h, _ := e.load("docs", "x")
	r := e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT of a value changed and changed back")
	if !strings.Contains(r.body, "/a") {
		t.Fatalf("409 %q", r.body)
	}
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"q"`, `"mine"`)), 409, "PUT into an array grown and shrunk")
	e.expectLive("docs", "x", h, "after refused saves")
	// A path nobody else wrote saves, merged.
	buf = e.expect(e.do("GET", "/docs/x.json", ""), 200, "reload").body
	e.theirs("docs", "x", replace("/a", "3"))
	e.theirs("docs", "x", replace("/a", "1"))
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"n": "0"`, `"n": "1"`)), 201, "PUT of another path")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "1", "items": []any{"p", "q"}, "n": "1"})
}

// A delete or a restore by someone else between the base and the head
// (§11.3, §H.4): the save is a 409, never written over the delete; the
// user's reload (a GET finding the file gone) lets the next save make it
// anew, the root replaced. A save without a base makes it anew at once.
// A file the user deleted longer ago than the restore window (30 s), or
// moved away, is made anew too, not rebased on its last document (§H.6).
func TestSaveOverOthersDelete(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })
	whole := func(name string) {
		t.Helper()
		if p := patchPaths(t, e.lastEntry("docs", name).Patches); len(p) != 1 || p[0] != "" {
			t.Fatalf("%s: not made anew (a root replace): %q", name, p)
		}
	}

	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	h, _ := e.load("docs", "x")
	must(e.c.Delete(e.ctx, "docs", "x", h.ID))
	r := e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT over someone else's delete")
	if !strings.Contains(r.body, "deleted by someone else") {
		t.Fatalf("409 %q", r.body)
	}
	e.expectTombstoned("docs", "x", "after the refused save")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT again without a reload")
	e.expect(e.do("GET", "/docs/x.json", ""), 404, "reload: gone")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT after the reload")
	whole("x")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "1"})

	// Without a base (never read), a new file at once.
	e.create("docs", "y", map[string]any{"a": "1"})
	h, _ = e.load("docs", "y")
	must(e.c.Delete(e.ctx, "docs", "y", h.ID))
	e.expect(e.do("PUT", "/docs/y.json", `{"a": "new"}`), 201, "PUT without a base")
	whole("y")

	// Deleted and restored by someone else in between, the same content
	// back: the edit isn't merged over that.
	e.create("docs", "w", map[string]any{"a": "1", "b": "1"})
	buf = e.expect(e.do("GET", "/docs/w.json", ""), 200, "GET").body
	h, _ = e.load("docs", "w")
	tomb := must(e.c.Delete(e.ctx, "docs", "w", h.ID))
	must(e.c.Restore(e.ctx, "docs", "w", tomb.ID, []any{}))
	h, _ = e.load("docs", "w")
	r = e.expect(e.do("PUT", "/docs/w.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT over a delete and restore")
	if !strings.Contains(r.body, "deleted or restored by someone else") {
		t.Fatalf("409 %q", r.body)
	}
	e.expectLive("docs", "w", h, "after the refused save")
	buf = e.expect(e.do("GET", "/docs/w.json", ""), 200, "reload").body
	e.expect(e.do("PUT", "/docs/w.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT after the reload")

	// The user's own delete, 31 s before: made anew, not restored with a
	// diff (a write 30 s after is a restore: TestDeleteRestore).
	e.create("docs", "z", map[string]any{"a": "1", "b": "1"})
	e.expect(e.do("GET", "/docs/z.json", ""), 200, "GET")
	e.expect(e.do("DELETE", "/docs/z.json", ""), 204, "DELETE")
	c.add(31 * time.Second)
	e.expect(e.do("PUT", "/docs/z.json", `{"a": "1", "b": "2"}`), 201, "PUT 31 s after the user's DELETE")
	whole("z")

	// Moved away (its last document has $successor): no write to the old
	// name makes it anew, moments after or later (§H.2, §H.4): a 409
	// naming the new path.
	e.create("docs", "m", map[string]any{"a": "1"})
	e.expect(e.do("MOVE", "/docs/m.json", "", "Destination", "/docs/n.json"), 201, "MOVE")
	if h, _ := e.load("docs", "m"); h.Successor != "n" {
		t.Fatalf("m's successor %q", h.Successor)
	}
	r = e.expect(e.do("PUT", "/docs/m.json", `{"a": "again"}`), 409, "PUT the old name")
	if !strings.Contains(r.body, "/docs/n.json") {
		t.Fatalf("409 %q", r.body)
	}
	e.expectTombstoned("docs", "m", "after the refused save")
}

// Saves of a JSON file are patch sets from the base's rendering (§H.4):
// the base's $successor, which the rendering leaves out, is kept. One over
// opsPerSet or patchSetSize (§6.6), the namespace's or the deployment's
// (the core's refusal says), is sent as a root replace carrying the
// $successor and a fresh $nonce where nonces apply, if the base is the
// head; one merged with others' edits is a 413 instead.
func TestOversizeSave(t *testing.T) {
	t.Parallel()
	// 3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize (§6.6 Values).
	e := newEnv(t, []string{"lim", "dflt", "sealedish"}, nil, map[string]map[string]any{
		"lim":       {"limits": map[string]any{"patchSetSize": 2048, "valueSize": 300, "pathSize": 40, "opsPerSet": 3}},
		"sealedish": {"nonce": "required", "limits": map[string]any{"patchSetSize": 2048, "valueSize": 300, "pathSize": 40}},
	})
	isWhole := func(ns, name string) {
		t.Helper()
		p := patchPaths(t, e.lastEntry(ns, name).Patches)
		if len(p) == 0 || p[0] != "" {
			t.Fatalf("%s/%s: not a root replace: %q", ns, name, p)
		}
	}
	// Over patchSetSize, in strings within valueSize.
	bigV := make([]any, 8)
	for i := range bigV {
		bigV[i] = strings.Repeat("x", 290)
	}
	big := rendered(bigV)

	e.create("lim", "x", map[string]any{"v": "1", "$successor": "elsewhere"})
	buf := e.expect(e.do("GET", "/lim/x.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/lim/x.json", edit(t, buf, `"v": "1"`, `"v": `+big)), 201, "PUT over patchSetSize")
	isWhole("lim", "x")
	_, doc := e.load("lim", "x")
	sameJSON(t, doc, map[string]any{"v": bigV, "$successor": "elsewhere"})

	e.create("lim", "ops", map[string]any{"a": "0", "b": "0", "c": "0", "d": "0"})
	e.expect(e.do("GET", "/lim/ops.json", ""), 200, "GET")
	e.expect(e.do("PUT", "/lim/ops.json", `{"a": "1", "b": "1", "c": "1", "d": "1"}`), 201, "PUT over opsPerSet")
	isWhole("lim", "ops")

	e.create("lim", "merged", map[string]any{"v": "1", "w": "1"})
	buf = e.expect(e.do("GET", "/lim/merged.json", ""), 200, "GET").body
	e.theirs("lim", "merged", replace("/w", "theirs"))
	h, _ := e.load("lim", "merged")
	r := e.expect(e.do("PUT", "/lim/merged.json", edit(t, buf, `"v": "1"`, `"v": `+big)), 413, "PUT over patchSetSize, merged")
	if !strings.HasPrefix(r.body, "too large: patchSetSize ") || !strings.Contains(r.body, " > 2048 (§6.6)") || !strings.Contains(r.body, "merged") {
		t.Fatalf("413 %q", r.body)
	}
	e.expectLive("lim", "merged", h, "after a 413")

	// The deployment's limits (patchSetSize 256 KiB, opsPerSet 1000),
	// which only the core's refusal tells.
	e.create("dflt", "x", map[string]any{"v": "1"})
	e.expect(e.do("GET", "/dflt/x.json", ""), 200, "GET")
	huge := map[string]any{"v": "1"}
	for i := 0; i < 6; i++ {
		huge[fmt.Sprint("s", i)] = strings.Repeat("y", 50<<10) // valueSize is 64 KiB
	}
	e.expect(e.do("PUT", "/dflt/x.json", rendered(huge)), 201, "PUT over the deployment's patchSetSize")
	isWhole("dflt", "x")
	many := map[string]any{}
	for i := 0; i < 1001; i++ {
		many[fmt.Sprintf("k%04d", i)] = "0"
	}
	e.create("dflt", "ops", many)
	e.expect(e.do("GET", "/dflt/ops.json", ""), 200, "GET")
	for k := range many {
		many[k] = "1"
	}
	e.expect(e.do("PUT", "/dflt/ops.json", rendered(many)), 201, "PUT over the deployment's opsPerSet")
	isWhole("dflt", "ops")
	e.theirs("dflt", "ops", map[string]any{"op": "add", "path": "/theirs", "value": true})
	for k := range many {
		many[k] = "2"
	}
	r = e.expect(e.do("PUT", "/dflt/ops.json", rendered(many)), 413, "PUT over opsPerSet, merged")
	if !strings.HasPrefix(r.body, "too large: opsPerSet 1001 > 1000 (§6.6): too many operations") || !strings.Contains(r.body, "merged") {
		t.Fatalf("413 %q", r.body)
	}

	// Where nonces are required, the root replace carries a fresh one.
	e.create("sealedish", "x", map[string]any{"v": "1", "$nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaa"})
	e.expect(e.do("GET", "/sealedish/x.json", ""), 200, "GET")
	e.expect(e.do("PUT", "/sealedish/x.json", `{"v": `+big+`}`), 201, "PUT over patchSetSize, nonces required")
	isWhole("sealedish", "x")
	_, doc = e.load("sealedish", "x")
	if n, _ := doc.(map[string]any)["$nonce"].(string); n == "" || n == "aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("$nonce %q", n)
	}
}

// Answers (§H.4): a purged file is 410 (403 before Addendum H), and so is
// a file of a purged namespace.
func TestSavePurged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs", "gone"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1"})
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	h, _ := e.load("docs", "x")
	must(e.c.Purge(e.ctx, "docs", "x", h.ID, false))
	r := e.expect(e.do("PUT", "/docs/x.json", `{"a": "2"}`), 410, "PUT of a purged file")
	if !strings.Contains(r.body, "purged") {
		t.Fatalf("410 %q", r.body)
	}
	e.expect(e.do("PUT", "/docs/x.md", "# x"), 201, "PUT of another name")

	e.create("gone", "y", map[string]any{"a": "1"})
	nh := must(e.c.NSHead(e.ctx, "gone"))
	must(e.c.PatchConfig(e.ctx, "gone", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	nh = must(e.c.NSHead(e.ctx, "gone"))
	must(e.c.PurgeNamespace(e.ctx, "gone", nh.ID))
	e.expect(e.do("PUT", "/gone/y.json", `{"a": "2"}`), 410, "PUT in a purged namespace")
}

// Only a revision served whole is recorded as a base (§H.4): a range read
// (a mount's, a type sniffer's) after a refused save isn't the reload it
// asked for, so the same save is refused again rather than taken from the
// newer version it read part of; a GET of the whole file is.
func TestSaveRangeReadNoBase(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"title": "A", "n": "1"})
	editor := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/title", "Theirs"))
	e.expect(e.do("PUT", "/docs/x.json", edit(t, editor, `"A"`, `"Mine"`)), 409, "PUT over their edit")
	e.expect(e.do("GET", "/docs/x.json", "", "Range", "bytes=0-3"), 206, "a range read")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, editor, `"A"`, `"Mine"`)), 409, "PUT again after a range read")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"title": "Theirs", "n": "1"})
	e.expect(e.do("GET", "/docs/x.json", "", "Range", "bytes=0-"), 206, "a range read of the whole file")
	e.expect(e.do("PUT", "/docs/x.json", edit(t, editor, `"A"`, `"Mine"`)), 201, "PUT after it: the reload")
}

// Records last a day (§H.4): after it they count as evicted, so a save
// without a tag is a 409, never written over others' edits as one with
// no base would be, and after the reload it asks for the save merges.
func TestSaveRecordsForADay(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.Now = c.now })
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	c.add(23 * time.Hour)
	e.expect(e.do("PUT", "/docs/x.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT after 23 h")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})

	e.create("docs", "y", map[string]any{"a": "1", "b": "1"})
	buf = e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET").body
	e.theirs("docs", "y", replace("/b", "theirs"))
	c.add(25 * time.Hour)
	e.expect(e.do("PUT", "/docs/y.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 409, "PUT after 25 h")
	buf = e.expect(e.do("GET", "/docs/y.json", ""), 200, "the reload").body
	e.expect(e.do("PUT", "/docs/y.json", edit(t, buf, `"a": "1"`, `"a": "mine"`)), 201, "PUT after the reload")
	_, doc = e.load("docs", "y")
	sameJSON(t, doc, map[string]any{"a": "mine", "b": "theirs"})
}

// A write moments after the user's own DELETE restores the file rebased
// on its last live document (§H.6), and a restore patch set over
// opsPerSet or patchSetSize is written whole from there, as an edit from
// the head is (§H.4), in the flat view and in a tree, rather than refused
// and the DELETE undone.
func TestOversizeRestore(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"lim"}, []string{"cat"}, map[string]map[string]any{
		"lim": {"limits": map[string]any{"opsPerSet": 3}},
		"cat": {"catalog": treeCatalog("lim")},
	})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	e.create("lim", "ops", map[string]any{"a": "0", "b": "0", "c": "0", "d": "0"})
	e.create("lim", "t", map[string]any{"a": "0", "b": "0", "c": "0", "d": "0"})
	e.create("cat", "lim.t", map[string]any{"title": "t.json", "parents": parents("cat", "root")})
	for _, c := range []struct{ path, ns, name string }{{"/lim/ops.json", "lim", "ops"}, {"/cat/t.json", "lim", "t"}} {
		e.expect(e.do("GET", c.path, ""), 200, "GET "+c.path)
		e.expect(e.do("DELETE", c.path, ""), 204, "DELETE "+c.path)
		e.expect(e.do("PUT", c.path, `{"a": "2", "b": "2", "c": "2", "d": "2"}`), 201, "PUT over opsPerSet after the DELETE of "+c.path)
		h, doc := e.load(c.ns, c.name)
		if h.State != client.Live {
			t.Fatalf("%s: %v", c.path, h.State)
		}
		sameJSON(t, doc, map[string]any{"a": "2", "b": "2", "c": "2", "d": "2"})
		if p := patchPaths(t, e.lastEntry(c.ns, c.name).Patches); len(p) == 0 || p[0] != "" {
			t.Fatalf("%s: not a root replace: %q", c.path, p)
		}
	}
	sameStrings(t, "tree", names(e.propfind("/cat/"), "/cat/"), []string{"t.json"})
}
