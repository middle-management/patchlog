package tree_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// §A.4 paging, §B.5 (v0.77, v0.76 Open 44): a redirect from the head
// pointer or to another at drops an after that is a children listing's
// position (opaque), whether given as such or as the next it came in,
// and the folder starts again; one at the same at keeps it. The cursor of
// earlier releases, naming an order, is kept.
func TestV077V04ChildrenCursorRedirect(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.folder(t, "root", "Root")
	for _, n := range []string{"a", "b", "c"} {
		w.folder(t, n, strings.ToUpper(n), "root@"+n)
	}
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")

	first := x.get("/cat/children?of=root&limit=1", "")
	at, _ := first["at"].(string)
	next, _ := first["next"].(string)
	if names(first["children"]) != "a" || next == "" {
		t.Fatalf("first page: %v", first)
	}
	q := must(url.ParseQuery(strings.TrimPrefix(next, "?")))
	cursor := q.Get("after")

	location := func(path string) string {
		t.Helper()
		r := x.raw(path, "")
		if r.status != http.StatusFound {
			t.Fatalf("GET %s: %d %v", path, r.status, r.body)
		}
		return r.header.Get("Location")
	}
	afterOf := func(loc string) string {
		_, rq, _ := strings.Cut(loc, "?")
		return must(url.ParseQuery(rq)).Get("after")
	}
	for name, after := range map[string]string{"cursor": cursor, "next": next} {
		loc := location("/cat/children?of=root&limit=1&after=" + url.QueryEscape(after))
		if afterOf(loc) != "" || !strings.Contains(loc, "/cat/at/"+at+"/") {
			t.Errorf("head pointer with a %s: Location %s, want at %s without after", name, loc, at)
		}
		if got := x.get(loc, ""); names(got["children"]) != "a" {
			t.Errorf("head pointer with a %s: %v, want the folder from its start", name, got)
		}
	}
	// At the same at the position stands: the page continues.
	if got := x.get("/cat/at/"+at+"/children?of=root&limit=1&after="+url.QueryEscape(cursor), ""); names(got["children"]) != "b" {
		t.Errorf("at %s with its own cursor: %v, want b", at, got)
	}
	// A legacy cursor (an order) is kept, applied to the new result.
	if loc := location("/cat/children?of=root&limit=1&after=a&name=a"); afterOf(loc) != "a" {
		t.Errorf("head pointer with a legacy cursor: Location %s", loc)
	}

	// To another at: the checkpoint moved, and the old at's later pages
	// aren't kept for this query (a limit it wasn't computed with).
	w.folder(t, "d", "D", "root@d")
	x.caughtUp("cat")
	path := "/cat/at/" + at + "/children?of=root&limit=2&after=" + url.QueryEscape(cursor)
	loc := location(path)
	if strings.Contains(loc, "/at/"+at+"/") {
		t.Fatalf("GET %s: redirected to its own at: %s", path, loc)
	}
	if afterOf(loc) != "" {
		t.Errorf("to another at: Location %s keeps the position", loc)
	}
	if got := x.get(loc, ""); names(got["children"]) != "a,b" {
		t.Errorf("to another at: %v, want the folder from its start", got)
	}
}
