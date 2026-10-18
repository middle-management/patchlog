package dav_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// clock is a settable dav.Options.Now.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now()} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// guardEnv is a server over flat namespace docs and catalog cat (trusting
// docs), with files of at most 1 KiB and clock c.
func guardEnv(t *testing.T, c *clock) *env {
	return newEnv(t, []string{"docs"}, []string{"cat"}, map[string]map[string]any{
		"cat": {"catalog": map[string]any{"trust": []any{"docs"}}},
	}, func(_ *clienttest.Options, o *dav.Options) {
		o.MaxFileSize = 1024
		o.Now = c.now
	})
}

// refusals are saves of /docs/{name}.json the server refuses, each after
// the document {"a": "1", "b": "1"} was read (GET).
var refusals = []struct {
	what   string
	status int
	save   func(e *env, name, served string) resp
}{
	{"a conflict", 409, func(e *env, name, served string) resp {
		e.theirs("docs", name, replace("/a", "theirs"))
		return e.do("PUT", "/docs/"+name+".json", edit(e.t, served, `"a": "1"`, `"a": "mine"`))
	}},
	{"a body that isn't JSON", 400, func(e *env, name, served string) resp {
		return e.do("PUT", "/docs/"+name+".json", served[:len(served)/2])
	}},
	{"a body over -max-file-size", 413, func(e *env, name, served string) resp {
		return e.do("PUT", "/docs/"+name+".json", edit(e.t, served, `"a": "1"`, `"a": "`+strings.Repeat("x", 2000)+`"`))
	}},
}

// refusedSave creates docs/name, reads it, and has the server refuse a
// save of it as refusals[i] does, returning the head before the save.
func (e *env) refusedSave(i int, name string) *client.Head {
	e.t.Helper()
	e.create("docs", name, map[string]any{"a": "1", "b": "1"})
	served := e.expect(e.do("GET", "/docs/"+name+".json", ""), 200, "GET").body
	r := refusals[i]
	e.expect(r.save(e, name, served), r.status, "PUT of "+r.what)
	h, _ := e.load("docs", name)
	return h
}

// expectLive fails unless ns/name's head is still h: nothing written.
func (e *env) expectLive(ns, name string, h *client.Head, what string) {
	e.t.Helper()
	if now, _ := e.load(ns, name); now.State != client.Live || now.ID != h.ID {
		e.t.Fatalf("%s: %s/%s is %v at %s, was live at %s", what, ns, name, now.State, now.ID, h.ID)
	}
}

func (e *env) expectTombstoned(ns, name, what string) {
	e.t.Helper()
	if h, _ := e.load(ns, name); h.State != client.Tombstoned {
		e.t.Fatalf("%s: %s/%s is %v, want tombstoned", what, ns, name, h.State)
	}
}

// expectGuarded fails unless a DELETE of p is refused as following a
// refused save.
func (e *env) expectGuarded(p, what string) {
	e.t.Helper()
	r := e.expect(e.do("DELETE", p, ""), 409, what)
	if !strings.Contains(r.body, "refused save") || !strings.Contains(r.body, "delete it again") {
		e.t.Fatalf("%s: %q", what, r.body)
	}
}

// rclone deletes a file whose upload failed, a second after the failure
// (removeFailedCopy), whatever refused it: a conflict, a body that isn't
// JSON, one too large. That DELETE is refused, once, so a refused save
// doesn't delete the document for every reader; a second DELETE
// tombstones it.
func TestDeleteAfterRefusedSave(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	for i, r := range refusals {
		name := "x" + string(rune('a'+i))
		h := e.refusedSave(i, name)
		e.expectGuarded("/docs/"+name+".json", "DELETE after "+r.what)
		e.expectLive("docs", name, h, "after "+r.what)
		e.expect(e.do("DELETE", "/docs/"+name+".json", ""), 204, "DELETE again after "+r.what)
		e.expectTombstoned("docs", name, "after a second DELETE")
	}
}

// rclone's --retries (and a mount's write-back) send the refused save
// again, each time followed by a DELETE: every one is refused, and the
// document stays as it was. So does one whose save deleted the original
// first (a DELETE, then the PUT), which the refusal restores: the DELETE
// after that refusal is refused, not a tombstone again.
func TestDeleteAfterRefusedSaveRetried(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	h := e.refusedSave(1, "x")
	for i := 0; i < 3; i++ {
		e.expectGuarded("/docs/x.json", "rclone's cleanup DELETE")
		e.expect(e.do("PUT", "/docs/x.json", `{"a": "1"`), 400, "the retried PUT")
	}
	e.expectGuarded("/docs/x.json", "the last cleanup DELETE")
	e.expectLive("docs", "x", h, "after retries")

	e.create("docs", "y", map[string]any{"v": 1})
	e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET")
	e.expect(e.do("DELETE", "/docs/y.json", ""), 204, "DELETE, the original first")
	e.expect(e.do("PUT", "/docs/y.json", `{"v": 2`), 400, "PUT that isn't JSON: restored")
	h, _ = e.load("docs", "y")
	e.expectGuarded("/docs/y.json", "rclone's cleanup DELETE after the restore")
	e.expect(e.do("PUT", "/docs/y.json", `{"v": 2`), 400, "the retried PUT")
	e.expectGuarded("/docs/y.json", "the retry's cleanup DELETE")
	e.expectLive("docs", "y", h, "after the retries")
}

// A GET of the file after the refused save (200: the user reloaded it)
// lifts the guard; a HEAD, a listing or a range read (a mount's) doesn't.
func TestDeleteAfterRefusedSaveRead(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.refusedSave(0, "x")
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET, a reload")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE after the reload")
	e.expectTombstoned("docs", "x", "DELETE after a reload")

	h := e.refusedSave(1, "y")
	e.expect(e.do("HEAD", "/docs/y.json", ""), 200, "HEAD")
	e.propfind("/docs/")
	e.expect(e.do("GET", "/docs/y.json", "", "Range", "bytes=0-3"), 206, "a range read")
	e.expect(e.do("GET", "/docs/z.json", ""), 404, "GET of another name")
	e.expectGuarded("/docs/y.json", "DELETE after a HEAD, a listing and a range read")
	e.expectLive("docs", "y", h, "after a HEAD, a listing and a range read")
}

// The guard lasts a few seconds: rclone's DELETE comes a second after the
// failure.
func TestDeleteAfterRefusedSaveWindow(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := guardEnv(t, c)
	e.refusedSave(1, "x")
	c.add(9 * time.Second)
	e.expectGuarded("/docs/x.json", "DELETE 9 s after")
	e.refusedSave(1, "y")
	c.add(11 * time.Second)
	e.expect(e.do("DELETE", "/docs/y.json", ""), 204, "DELETE 11 s after")
	e.expectTombstoned("docs", "y", "DELETE after the window")
}

// A DELETE that names the revision it deletes (If-Match, or an If
// header's entity tag) is deliberate: it isn't refused (nor does it use
// the guard up: one that names an old revision is a 412).
func TestDeleteAfterRefusedSaveIfMatch(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	h := e.refusedSave(1, "x")
	e.expect(e.do("DELETE", "/docs/x.json", "", "If-Match", `"`+h.ID+`"`), 204, "DELETE If-Match the head")
	e.expectTombstoned("docs", "x", "DELETE If-Match")

	h = e.refusedSave(1, "y")
	e.expect(e.do("DELETE", "/docs/y.json", "", "If", `(["`+h.ID+`"])`), 204, "DELETE If [the head]")
	e.expectTombstoned("docs", "y", "DELETE If")

	h = e.refusedSave(0, "z")
	e.expect(e.do("DELETE", "/docs/z.json", "", "If-Match", `"`+h.Last+`x"`), 412, "DELETE If-Match another revision")
	e.expectGuarded("/docs/z.json", "DELETE without If-Match")
	e.expectLive("docs", "z", h, "after a 412 and a refused DELETE")
}

// The guard is the principal's own: in a gateway, another user's DELETE
// after someone's refused save is done.
func TestDeleteAfterRefusedSaveGateway(t *testing.T) {
	t.Parallel()
	e, k := authEnv(t, true)
	writer := []string{"read", "create", "append", "restore", "delete"}
	alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)
	bob := k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)
	for _, n := range []string{"x", "y"} {
		e.create("docs", n, map[string]any{"a": "1"})
		e.expect(e.doAs(alice, "GET", "/docs/"+n+".json", ""), 200, "alice GETs")
		e.expect(e.doAs(alice, "PUT", "/docs/"+n+".json", `{"a": `), 400, "alice's refused save")
	}
	e.expect(e.doAs(bob, "DELETE", "/docs/x.json", ""), 204, "bob's DELETE")
	e.expectTombstoned("docs", "x", "bob's DELETE")
	e.expect(e.doAs(alice, "DELETE", "/docs/y.json", ""), 409, "alice's DELETE")
	if h, _ := e.load("docs", "y"); h.State != client.Live {
		t.Fatalf("alice's DELETE after her refused save: %v", h.State)
	}
}

// A save that succeeded, merged with others' edits or not, sets no guard,
// and lifts one a refused save set: rclone deletes a merged upload whose
// size differs only without --ignore-size, a documented case.
func TestDeleteAfterSuccessfulSave(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.create("docs", "x", map[string]any{"a": "1"})
	served := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.expect(e.do("PUT", "/docs/x.json", edit(t, served, `"1"`, `"2"`)), 201, "PUT")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE after a save")
	e.expectTombstoned("docs", "x", "DELETE after a save")

	e.create("docs", "y", map[string]any{"a": "1", "b": "1"})
	served = e.expect(e.do("GET", "/docs/y.json", ""), 200, "GET").body
	e.theirs("docs", "y", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/y.json", edit(t, served, `"a": "1"`, `"a": "mine"`)), 201, "PUT merged")
	e.expect(e.do("DELETE", "/docs/y.json", ""), 204, "DELETE after a merged save")
	e.expectTombstoned("docs", "y", "DELETE after a merged save")

	h := e.refusedSave(1, "z")
	e.expectGuarded("/docs/z.json", "DELETE after a refused save")
	e.expectLive("docs", "z", h, "after a refused DELETE")
	e.expect(e.do("PUT", "/docs/z.json", `{"a": "1"`), 400, "refused again")
	e.expect(e.do("PUT", "/docs/z.json", `{"a": "2", "b": "1"}`), 201, "then saved")
	e.expect(e.do("DELETE", "/docs/z.json", ""), 204, "DELETE after the save")
	e.expectTombstoned("docs", "z", "DELETE after a refused save, then a save")
}

// A refused MOVE or COPY of a scratch file onto a document (an atomic
// save whose temporary file isn't JSON) sets the guard as a refused PUT
// does.
func TestDeleteAfterRefusedMove(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	for _, m := range []string{"MOVE", "COPY"} {
		name := strings.ToLower(m)
		e.create("docs", name, map[string]any{"a": "1"})
		h, _ := e.load("docs", name)
		e.expect(e.do("PUT", "/docs/.tmp-"+name, `{"a": "2"`), 201, "PUT scratch")
		e.expect(e.do(m, "/docs/.tmp-"+name, "", "Destination", "/docs/"+name+".json", "Overwrite", "T"), 400, m+" that isn't JSON onto the document")
		e.expectGuarded("/docs/"+name+".json", "DELETE after a refused "+m)
		e.expectLive("docs", name, h, "after a refused "+m)
	}
}

// In a catalog folder, rclone's DELETE of a placement whose save was
// refused would unplace it: refused once, as a document's.
func TestDeleteAfterRefusedPlacementSave(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.create("docs", "p", map[string]any{"v": 1})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "docs.p", map[string]any{"parents": parents("cat", "root")})
	e.expect(e.do("GET", "/cat/root/docs.p.json", ""), 200, "GET")
	e.expect(e.do("PUT", "/cat/root/docs.p.json", `{"v": 2`), 400, "PUT that isn't JSON")
	e.expectGuarded("/cat/root/docs.p.json", "DELETE of the placement")
	sameJSON(t, e.parentsOf("docs.p"), parents("cat", "root"))
	e.expect(e.do("DELETE", "/cat/root/docs.p.json", ""), 204, "DELETE again")
	if h, _ := e.load("cat", "docs.p"); h.State != client.Tombstoned {
		t.Fatalf("the placement is %v after a second DELETE", h.State)
	}
	if h, _ := e.load("docs", "p"); h.State != client.Live {
		t.Fatalf("the item is %v", h.State)
	}
}

// Editors' save sequences after a refused save still save, and none
// leaves a tombstone: vim's (backup, write, backup gone), gedit's and VS
// Code's (a temporary file moved over the document), and those that
// delete the original first (rclone's mount without a cache: DELETE, then
// MOVE onto the name), whose DELETE is refused and whose MOVE then is an
// edit (Overwrite: T), a 412 (Overwrite: F: the document is there), or
// refused as the save was.
func TestSavesAfterRefusedSave(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	saved := map[string]any{"a": "2", "b": "1"}
	text := rendered(saved)

	e.refusedSave(1, "vim")
	e.expect(e.do("MOVE", "/docs/vim.json", "", "Destination", "/docs/vim.json~"), 201, "vim: original to backup")
	e.expect(e.do("PUT", "/docs/vim.json", text), 201, "vim: write")
	e.expect(e.do("DELETE", "/docs/vim.json~", ""), 204, "vim: backup gone")
	_, doc := e.load("docs", "vim")
	sameJSON(t, doc, saved)

	e.refusedSave(1, "code")
	e.expect(e.do("PUT", "/docs/.code.json.tmp", text), 201, "VS Code: temporary file")
	e.expect(e.do("MOVE", "/docs/.code.json.tmp", "", "Destination", "/docs/code.json"), 204, "VS Code: over the original")
	_, doc = e.load("docs", "code")
	sameJSON(t, doc, saved)

	e.refusedSave(1, "rc")
	e.expect(e.do("PUT", "/docs/rc.json.tmp", text), 201, "rclone: temporary file")
	e.expectGuarded("/docs/rc.json", "rclone: DELETE of the original")
	e.expect(e.do("MOVE", "/docs/rc.json.tmp", "", "Destination", "/docs/rc.json", "Overwrite", "T"), 204, "MOVE onto it")
	_, doc = e.load("docs", "rc")
	sameJSON(t, doc, saved)

	h := e.refusedSave(1, "rcf")
	e.expect(e.do("PUT", "/docs/rcf.json.tmp", text), 201, "temporary file")
	e.expectGuarded("/docs/rcf.json", "DELETE of the original")
	e.expect(e.do("MOVE", "/docs/rcf.json.tmp", "", "Destination", "/docs/rcf.json", "Overwrite", "F"), 412, "MOVE onto it, Overwrite: F")
	e.expectLive("docs", "rcf", h, "after a MOVE with Overwrite: F")

	h = e.refusedSave(0, "conflict")
	e.expect(e.do("PUT", "/docs/conflict.json.tmp", rendered(map[string]any{"a": "mine", "b": "1"})), 201, "temporary file")
	e.expectGuarded("/docs/conflict.json", "DELETE of the original")
	e.expect(e.do("MOVE", "/docs/conflict.json.tmp", "", "Destination", "/docs/conflict.json"), 409, "MOVE of the conflicting version")
	e.expectLive("docs", "conflict", h, "after the conflicting MOVE")
}
