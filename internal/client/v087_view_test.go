package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// §7.9 (v0.91): a resource's URLs answer a partial reader in place, so the
// client follows no redirect of a document read: a 302 under a view is the
// caller's, as any other.
func TestV087FollowsNoViewContent(t *testing.T) {
	view := "1" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	id := "1" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/m/d/rev/" + id:
			http.Redirect(w, r, "/ns/m/view/"+view+"/r/d/rev/"+id, 302)
		case "/ns/m/view/" + view + "/r/d/rev/" + id:
			t.Error("the redirect under the view was followed")
		default:
			http.NotFound(w, r)
		}
	}))
	defer hs.Close()
	c, err := New(hs.URL, WithBearer("tok"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Doc(context.Background(), "m", "d", id); err == nil {
		t.Fatal("a 302 read as the document")
	}
}

// §7.9 Log entries: a partial reader folds only onto what it holds; after
// a hidden entry, or an entry without patches, it fetches the revision's
// document instead.
func TestV087FoldFiltered(t *testing.T) {
	a, h, c3 := "1"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1"+"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "1"+"cccccccccccccccccccccccccccccccc"
	fetched := 0
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r/m/d/rev/"+c3 {
			fetched++
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"team":"a","v":3}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer hs.Close()
	c, err := New(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	es := []LogEntry{
		{ID: a, Kind: "rev", HasPatches: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"team": "a"}}}},
		{ID: h, Parent: a, Kind: "hidden"},
		{ID: c3, Parent: h, Kind: "rev"},
	}
	at, doc, err := c.FoldFiltered(context.Background(), "m", "d", "", nil, es[:1])
	if err != nil || at != a || doc.(map[string]any)["team"] != "a" {
		t.Fatalf("genesis folded: %s %v %v", at, doc, err)
	}
	at, doc, err = c.FoldFiltered(context.Background(), "m", "d", at, doc, es[1:])
	if err != nil || at != c3 || doc.(map[string]any)["v"] != 3.0 || fetched != 1 {
		t.Fatalf("after hidden: %s %v %v (fetched %d)", at, doc, err, fetched)
	}
}
