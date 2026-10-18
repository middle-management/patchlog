package dav_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
// document stays as it was. One the principal deleted before the refused
// save (rm in a mount, then a new file of the name; the DELETE of a
// save that deletes the original first) is restored by the refusal
// (undoOwnDelete), and the DELETE after it isn't refused: it leaves the
// document deleted, as the principal chose, each retry alike.
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
	for i := 0; i < 3; i++ {
		e.expect(e.do("PUT", "/docs/y.json", `{"v": 2`), 400, "PUT that isn't JSON: restored")
		if h, _ := e.load("docs", "y"); h.State != client.Live {
			t.Fatalf("not restored: %v", h.State)
		}
		e.expect(e.do("DELETE", "/docs/y.json", ""), 204, "rclone's cleanup DELETE after the restore")
		e.expectTombstoned("docs", "y", "after the cleanup")
	}
}

// A GET of the file a few seconds after the refused save (200: the user
// reloaded it) lifts the guard; one in the second before rclone's DELETE
// (another program of the same user), a HEAD, a listing or a range read
// (a mount's) doesn't.
func TestDeleteAfterRefusedSaveRead(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := guardEnv(t, c)
	e.refusedSave(0, "x")
	c.add(time.Second)
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET a second after")
	e.expectGuarded("/docs/x.json", "DELETE after a GET a second after the refusal")
	e.refusedSave(0, "w")
	c.add(3 * time.Second)
	e.expect(e.do("GET", "/docs/w.json", ""), 200, "GET, a reload")
	e.expect(e.do("DELETE", "/docs/w.json", ""), 204, "DELETE after the reload")
	e.expectTombstoned("docs", "w", "DELETE after a reload")

	h := e.refusedSave(1, "y")
	c.add(3 * time.Second)
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

	// A DELETE done forgets the guard it passed: a refused save after it
	// restores the document (undoOwnDelete), and rclone's DELETE then
	// deletes it again, as the user chose; the first refusal's guard
	// mustn't keep it.
	h = e.refusedSave(1, "v")
	e.expect(e.do("DELETE", "/docs/v.json", "", "If-Match", `"`+h.ID+`"`), 204, "DELETE If-Match the head")
	e.expect(e.do("PUT", "/docs/v.json", `{"a": "2"`), 400, "a refused save after it: restored")
	e.expect(e.do("DELETE", "/docs/v.json", ""), 204, "rclone's cleanup DELETE")
	e.expectTombstoned("docs", "v", "after the cleanup")
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

// A save that succeeded, merged with others' edits or not, sets no guard
// (rclone deletes a merged upload whose size differs only without
// --ignore-size, a documented case), nor lifts one a refused save set:
// rclone's DELETE after its refused upload would delete the other
// program's save.
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
	e.expect(e.do("PUT", "/docs/z.json", `{"a": "2", "b": "1"}`), 201, "another program's save")
	h, _ = e.load("docs", "z")
	e.expectGuarded("/docs/z.json", "rclone's cleanup DELETE after the other save")
	e.expectLive("docs", "z", h, "after the cleanup")
	e.expect(e.do("DELETE", "/docs/z.json", ""), 204, "DELETE again")
	e.expectTombstoned("docs", "z", "DELETE again")
}

// A refused MOVE or COPY of a scratch file onto a document (an atomic
// save whose temporary file isn't JSON) sets no guard: rclone deletes
// nothing after one, and without a cache its next save over the file is
// a DELETE, then a MOVE (Overwrite: F), which gives up when the DELETE is
// refused (sed -i: "cannot rename").
func TestDeleteAfterRefusedMove(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.create("docs", "s", map[string]any{"n": 1})
	e.expect(e.do("GET", "/docs/s.json", "", "Range", "bytes=0-100"), 206, "a mount's read")
	e.expect(e.do("PUT", "/docs/sedA", `{"n": 1,}`), 201, "sed's temporary file")
	e.expect(e.do("DELETE", "/docs/s.json", ""), 204, "rclone's rename: DELETE")
	e.expect(e.do("MOVE", "/docs/sedA", "", "Destination", "/docs/s.json", "Overwrite", "F"), 400, "MOVE that isn't JSON: restored")
	e.expect(e.do("DELETE", "/docs/sedA", ""), 204, "sed removes its temporary file")
	e.expect(e.do("PUT", "/docs/sedB", `{"n": 2}`), 201, "the next sed -i: temporary file")
	e.expect(e.do("DELETE", "/docs/s.json", ""), 204, "rclone's rename: DELETE")
	e.expect(e.do("MOVE", "/docs/sedB", "", "Destination", "/docs/s.json", "Overwrite", "F"), 201, "MOVE onto the name")
	_, doc := e.load("docs", "s")
	sameJSON(t, doc, map[string]any{"n": 2.0})

	e.create("docs", "copy", map[string]any{"a": "1"})
	e.expect(e.do("PUT", "/docs/.tmp-copy", `{"a": "2"`), 201, "PUT scratch")
	e.expect(e.do("COPY", "/docs/.tmp-copy", "", "Destination", "/docs/copy.json", "Overwrite", "T"), 400, "COPY that isn't JSON onto the document")
	e.expect(e.do("DELETE", "/docs/copy.json", ""), 204, "DELETE after a refused COPY")
	e.expectTombstoned("docs", "copy", "DELETE after a refused COPY")
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
// Code's (a temporary file moved over the document); rclone's mount
// without a cache (its cleanup DELETE refused, then a save as DELETE and
// MOVE onto the name, Overwrite: F); and a client that deletes the
// original first and goes on when that DELETE is refused, whose MOVE then
// is an edit (Overwrite: T), a 412 (Overwrite: F: the document is there),
// or refused as the save was.
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
	e.expectGuarded("/docs/rc.json", "rclone: the refused upload's cleanup DELETE")
	e.expect(e.do("PUT", "/docs/rc.json.tmp", text), 201, "rclone: temporary file")
	e.expect(e.do("DELETE", "/docs/rc.json", ""), 204, "rclone: DELETE of the original")
	e.expect(e.do("MOVE", "/docs/rc.json.tmp", "", "Destination", "/docs/rc.json", "Overwrite", "F"), 201, "rclone: MOVE onto the name")
	_, doc = e.load("docs", "rc")
	sameJSON(t, doc, saved)

	e.refusedSave(1, "del")
	e.expect(e.do("PUT", "/docs/del.json.tmp", text), 201, "temporary file")
	e.expectGuarded("/docs/del.json", "DELETE of the original")
	e.expect(e.do("MOVE", "/docs/del.json.tmp", "", "Destination", "/docs/del.json", "Overwrite", "T"), 204, "MOVE onto it")
	_, doc = e.load("docs", "del")
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

// A document the user deleted a while ago isn't brought back by a refused
// save of its name: the delete-then-write restore (undoOwnDelete) is for
// a DELETE moments before the write, and the DELETE after a refusal that
// restored one is done, so rclone's cleanup puts back the deletion. Nor
// is a placement the user unplaced.
func TestRefusedSaveAfterOldDelete(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := guardEnv(t, c)
	e.create("docs", "gone", map[string]any{"secret": "unpublish me"})
	e.expect(e.do("DELETE", "/docs/gone.json", ""), 204, "a deliberate DELETE")
	c.add(6 * time.Hour)
	r := e.expect(e.do("PUT", "/docs/gone.json", `{"title": "new"`), 400, "a new file of the name, not JSON")
	if strings.Contains(r.body, "restored") {
		t.Fatalf("restored 6 h after: %q", r.body)
	}
	e.expectTombstoned("docs", "gone", "after a refused save 6 h after the DELETE")
	e.expect(e.do("DELETE", "/docs/gone.json", ""), 404, "rclone's cleanup DELETE")
	e.expectTombstoned("docs", "gone", "after the cleanup")

	// Within the restore's window (31 s isn't), still restored, and the
	// cleanup deletes it again.
	e.create("docs", "late", map[string]any{"v": 1})
	e.expect(e.do("DELETE", "/docs/late.json", ""), 204, "DELETE")
	c.add(31 * time.Second)
	e.expect(e.do("PUT", "/docs/late.json", `{"v": 2`), 400, "refused 31 s after")
	e.expectTombstoned("docs", "late", "refused 31 s after the DELETE")
	e.create("docs", "soon", map[string]any{"v": 1})
	e.expect(e.do("DELETE", "/docs/soon.json", ""), 204, "DELETE")
	c.add(15 * time.Second)
	r = e.expect(e.do("PUT", "/docs/soon.json", `{"v": 2`), 400, "refused 15 s after")
	if !strings.Contains(r.body, "restored") {
		t.Fatalf("not restored 15 s after: %q", r.body)
	}
	e.expect(e.do("DELETE", "/docs/soon.json", ""), 204, "rclone's cleanup DELETE")
	e.expectTombstoned("docs", "soon", "after the cleanup")

	e.create("docs", "p", map[string]any{"v": 1})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "docs.p", map[string]any{"parents": parents("cat", "root")})
	e.expect(e.do("DELETE", "/cat/root/docs.p.json", ""), 204, "unplace")
	c.add(time.Hour)
	e.expect(e.do("PUT", "/cat/root/docs.p.json", `{"v": 2`), 400, "a refused save of the path an hour after")
	e.do("DELETE", "/cat/root/docs.p.json", "")
	if h, _ := e.load("cat", "docs.p"); h.State != client.Tombstoned {
		t.Fatalf("unplaced an hour ago, the placement is %v after a refused save", h.State)
	}
}

// More refused uploads at once than 64 (rclone --transfers, or several
// clients of local mode's one user) keep their guards; a cleanup DELETE
// that finds nothing (a refused create's) uses its guard up.
func TestDeleteAfterManyRefusedSaves(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	const n = 80
	for i := 0; i < n; i++ {
		e.create("docs", fmt.Sprintf("m%02d", i), map[string]any{"v": 1})
	}
	for i := 0; i < n; i++ {
		e.expect(e.do("PUT", fmt.Sprintf("/docs/m%02d.json", i), `{"v": 2`), 400, "refused")
	}
	for i := 0; i < n; i++ {
		e.expectGuarded(fmt.Sprintf("/docs/m%02d.json", i), "cleanup DELETE")
		if h, _ := e.load("docs", fmt.Sprintf("m%02d", i)); h.State != client.Live {
			t.Fatalf("m%02d is %v", i, h.State)
		}
	}

	e.expect(e.do("PUT", "/docs/new.json", `{"v": 1`), 400, "a refused create")
	e.expect(e.do("DELETE", "/docs/new.json", ""), 404, "its cleanup DELETE")
	e.create("docs", "new", map[string]any{"v": 1})
	e.expect(e.do("DELETE", "/docs/new.json", ""), 204, "a DELETE after someone created it")
}

// Two refused saves of one file before their cleanups (two clients of the
// same user) refuse two DELETEs, saying so; a client's repeated refused
// saves refuse at most two.
func TestDeleteAfterTwoRefusedSaves(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.create("docs", "two", map[string]any{"v": 1})
	h, _ := e.load("docs", "two")
	e.expect(e.do("PUT", "/docs/two.json", `{"v": 2`), 400, "refused 1")
	e.expect(e.do("PUT", "/docs/two.json", `{"v": 3`), 400, "refused 2")
	r := e.expect(e.do("DELETE", "/docs/two.json", ""), 409, "cleanup 1")
	if !strings.Contains(r.body, "2 refused saves") || !strings.Contains(r.body, "2 more times") {
		t.Fatalf("cleanup 1: %q", r.body)
	}
	e.expectGuarded("/docs/two.json", "cleanup 2")
	e.expectLive("docs", "two", h, "after two cleanups")

	for i := 0; i < 4; i++ {
		e.expect(e.do("PUT", "/docs/two.json", `{"v": 4`), 400, "refused again")
	}
	e.expect(e.do("DELETE", "/docs/two.json", ""), 409, "DELETE 1")
	e.expectGuarded("/docs/two.json", "DELETE 2")
	e.expect(e.do("DELETE", "/docs/two.json", ""), 204, "DELETE 3")
	e.expectTombstoned("docs", "two", "DELETE 3")
}

// flakyRT answers the next GET of catalog cat's resources with a 429
// while armed.
type flakyRT struct{ armed atomic.Bool }

func (f *flakyRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "GET" && r.URL.Path == "/ns/cat" && f.armed.CompareAndSwap(true, false) {
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"5"}, "Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"code":"rate_limited","message":"slow down"}`)), Request: r}, nil
	}
	return http.DefaultTransport.RoundTrip(r)
}

// A PUT of a placement's file refused because the catalog couldn't be
// read (the core's 429: 503) still guards the placement against rclone's
// cleanup DELETE, which may find it read.
func TestDeleteAfterRefusedPlacementSaveUnread(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.create("docs", "p", map[string]any{"v": 1})
	e.create("cat", "root", map[string]any{"parents": []any{}})
	e.create("cat", "docs.p", map[string]any{"parents": parents("cat", "root")})
	rt := &flakyRT{}
	srv, err := dav.New(dav.Options{Client: e.s.Client(t, client.WithAuthor("dav"), client.WithHTTPClient(&http.Client{Transport: rt})),
		Namespaces: []string{"docs"}, Catalogs: []string{"cat"}, Password: e.pw, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	e.dav = httptest.NewServer(srv)
	t.Cleanup(e.dav.Close)
	rt.armed.Store(true)
	e.expect(e.do("PUT", "/cat/root/docs.p.json", `{"v": 2}`), 503, "PUT, the catalog's read rate-limited")
	e.expectGuarded("/cat/root/docs.p.json", "rclone's cleanup DELETE")
	sameJSON(t, e.parentsOf("docs.p"), parents("cat", "root"))
}

// A frozen namespace takes no DELETE (§8.4): the DELETE after a save
// refused there, by the core or by the server (a body that isn't JSON),
// gets the core's 403, not the guard's 409, which would say a second
// DELETE deletes it.
func TestDeleteAfterRefusedSaveFrozen(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := guardEnv(t, c)
	e.create("docs", "x", map[string]any{"a": "1"})
	e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	nh := must(e.c.NSHead(e.ctx, "docs"))
	must(e.c.PatchConfig(e.ctx, "docs", nh.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	c.add(time.Minute) // past the server's cache of the namespace's document
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "2"`), 400, "a body that isn't JSON")
	r := e.expect(e.do("DELETE", "/docs/x.json", ""), 403, "DELETE after it")
	if !strings.Contains(r.body, "frozen") {
		t.Fatalf("DELETE: %q", r.body)
	}
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "2"}`), 403, "a save the core refuses")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 403, "DELETE after it")
	if h, _ := e.load("docs", "x"); h.State != client.Live {
		t.Fatalf("x is %v", h.State)
	}
}
