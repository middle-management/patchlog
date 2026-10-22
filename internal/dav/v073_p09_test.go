package dav_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// Spec v0.73, Addendum H (gateways): saves, deletes and moves.

// A gateway re-checks a grant at least every five minutes (§H.7
// "Re-checking"): VerifyEvery above that is refused (GW-32).
func TestV073VerifyEveryFiveMinutes(t *testing.T) {
	t.Parallel()
	c := must(client.New("http://127.0.0.1:1"))
	if _, err := dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true, VerifyEvery: 5*time.Minute + time.Second}); err == nil {
		t.Fatal("VerifyEvery of 5m1s taken")
	}
	must(dav.New(dav.Options{Client: c, Namespaces: []string{"docs"}, Gateway: true, VerifyEvery: 5 * time.Minute}))
}

// A DELETE without a tag deletes the head the gateway read, with If-Match
// on it (§H.5 "Delete a file"): an edit someone makes between that read
// and the delete is a 409, never tombstoned unseen; in a tree the
// placement is put back as it was (GW-34).
func TestV073DeleteWithoutTagHeadMoved(t *testing.T) {
	t.Parallel()
	h := &hook{}
	e := treeEnv(t, withHook(h))
	h.set(at("DELETE", "/r/matches/derby"), func() {
		e.theirs("matches", "derby", map[string]any{"op": "add", "path": "/theirs", "value": "important"})
	})
	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 409, "tree DELETE, the item edited after the gateway read it")
	if hn, _ := e.load("cat", "matches.derby"); hn.State != client.Live {
		t.Fatalf("placement %v", hn.State)
	}
	if hi, doc := e.load("matches", "derby"); hi.State != client.Live || doc.(map[string]any)["theirs"] != "important" {
		t.Fatalf("item %v %v", hi.State, doc)
	}
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"derby.json"})

	e.create("matches", "x", map[string]any{"a": "1"})
	h.set(at("DELETE", "/r/matches/x"), func() {
		e.theirs("matches", "x", replace("/a", "theirs"))
	})
	e.expect(e.do("DELETE", "/matches/x.json", ""), 409, "flat DELETE, edited after the gateway read it")
	if hx, doc := e.load("matches", "x"); hx.State != client.Live || doc.(map[string]any)["a"] != "theirs" {
		t.Fatalf("x %v %v", hx.State, doc)
	}
	e.expect(e.do("DELETE", "/matches/x.json", ""), 204, "DELETE again")
	e.expectTombstoned("matches", "x", "x")
	e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "tree DELETE again")
	e.expectTombstoned("matches", "derby", "the item")
}

// Dangling placements aren't a folder's contents: those the grant can't
// delete (401, 403) are orphaned with it, and don't fail the folder's
// DELETE (§H.5 "Delete a folder", GW-35).
func TestV073DeleteFolderDanglingForbidden(t *testing.T) {
	t.Parallel()
	e := treeEnv(t, func(o *clienttest.Options, _ *dav.Options) {
		o.Wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" && r.URL.Path == "/r/cat/matches.ghost" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"code":"forbidden","message":"this grant doesn't delete placements"}`))
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	})
	e.create("matches", "ghost", map[string]any{"t": 1})
	e.create("cat", "matches.ghost", map[string]any{"title": "ghost.json", "parents": parents("cat", "empty")})
	h, _ := e.load("matches", "ghost")
	must(e.c.Delete(e.ctx, "matches", "ghost", h.ID))
	e.expect(e.do("DELETE", "/cat/Empty", ""), 204, "DELETE of a folder holding a dangling placement the grant can't delete")
	e.expectTombstoned("cat", "empty", "the folder")
	if hn, _ := e.load("cat", "matches.ghost"); hn.State != client.Live {
		t.Fatalf("the dangling placement is %v, want live (orphaned)", hn.State)
	}
}

// A weak tag works as a DELETE's precondition (§H.1 "Writer's bytes",
// done GW-3): W/"{head}" deletes, an older one is 412, in the flat view
// and in a tree.
func TestV073DeleteWeakTag(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	r0 := e.create("matches", "x", map[string]any{"a": "1"})
	e.theirs("matches", "x", replace("/a", "2"))
	e.expect(e.do("DELETE", "/matches/x.json", "", "If-Match", `W/"`+r0+`"`), 412, "flat DELETE W/ an old revision")
	h, _ := e.load("matches", "x")
	e.expect(e.do("DELETE", "/matches/x.json", "", "If-Match", `W/"`+h.ID+`"`), 204, "flat DELETE W/ the head")
	e.expectTombstoned("matches", "x", "x")

	old := must(e.c.Head(e.ctx, "matches", "derby")).ID
	e.theirs("matches", "derby", replace("/title", "Derby 2"))
	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If", `([W/"`+old+`"])`), 412, "tree DELETE If W/ an old revision")
	e.nodeDoc("cat", "matches.derby")
	head := must(e.c.Head(e.ctx, "matches", "derby")).ID
	e.expect(e.do("DELETE", "/cat/Season/derby.json", "", "If-Match", `W/"`+head+`"`), 204, "tree DELETE W/ the head")
	e.expectTombstoned("matches", "derby", "the item")
}
