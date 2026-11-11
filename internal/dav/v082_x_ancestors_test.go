package dav_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/dav"
)

// v82xRecorded fronts the catalog's tree service unchanged and keeps each
// 200 it answers for ancestors, by the node asked of.
type v82xRecorded struct {
	mu   sync.Mutex
	seen map[string]map[string]any
}

func (a *v82xRecorded) front(t *testing.T, svcURL string) string {
	t.Helper()
	target, err := url.Parse(svcURL)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = func(res *http.Response) error {
		if res.StatusCode != http.StatusOK || !strings.HasSuffix(res.Request.URL.Path, "/ancestors") {
			return nil
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		res.Body = io.NopCloser(bytes.NewReader(raw))
		var body map[string]any
		if json.Unmarshal(raw, &body) == nil {
			a.mu.Lock()
			if a.seen == nil {
				a.seen = map[string]map[string]any{}
			}
			a.seen[res.Request.URL.Query().Get("of")] = body
			a.mu.Unlock()
		}
		return nil
	}
	return newTestServer(t, rp).URL
}

func (a *v82xRecorded) of(t *testing.T, node string) map[string]any {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.seen[node]
	if b == nil {
		t.Fatalf("the gateway never got an ancestors answer for %s (asked of %v)", node, len(a.seen))
	}
	return b
}

// XT-1 (3), SVC-11t and BT-7g together (SERVICES §B.5 Shared nodes in
// DAGs, TOOLS §H.5 Copy; scenario 130): the gateway judges "not into
// itself" from what the real tree service answers for ancestors since
// v0.82: paths, each an array of node names from the reader's visible
// root down to the node itself, and "tooDeep": true, a JSON boolean, where
// a path was cut at depth 64. For ed, who reads no node document: a copy
// of TR into Both, below TR through a second parent, is 403 with TR on a
// path the service listed; into Sub, beside it, the copy is made; into Far,
// also at the end of a chain 66 folders long, where the service says
// tooDeep, the check is left undone and the copy refused, 403, nothing
// written (a v0.27.0 gateway answered that conforming body with 502);
// into Near, also eight folders down that chain, it is made.
func TestV082XFolderCopyOverRealAncestors(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	embargoTR(t, w)
	must(w.ops.CreateDoc(w.ctx, "cat", "inner", map[string]any{"title": "Inner", "parents": parents("cat", "tr")}))
	must(w.ops.CreateDoc(w.ctx, "cat", "both", map[string]any{"title": "Both", "parents": parents("cat", "season", "inner"),
		"$access": map[string]any{"group:match-desk": []any{"desk"}}}))
	const depth = 66
	// Every folder of the chain gives match-desk desk itself: ed sees it
	// however deep it is, and only the check refuses a copy into one.
	desk := map[string]any{"group:match-desk": []any{"desk"}}
	prev := "season"
	for i := range depth {
		name := fmt.Sprintf("d%d", i)
		must(w.ops.CreateDoc(w.ctx, "cat", name, map[string]any{"title": name, "parents": parents("cat", prev), "$access": desk}))
		prev = name
	}
	// Far and Near are in Season 2026 too, where the gateway finds them,
	// and at the end of the chain or eight levels down it.
	must(w.ops.CreateDoc(w.ctx, "cat", "far", map[string]any{"title": "Far", "parents": parents("cat", "season", prev), "$access": desk}))
	must(w.ops.CreateDoc(w.ctx, "cat", "near", map[string]any{"title": "Near", "parents": parents("cat", "season", "d7"), "$access": desk}))
	w.caughtUp(t)
	var rec v82xRecorded
	g := w.derivedGateway(t, func(o *dav.Options) { o.TreeService = rec.front(t, w.catURL) })
	ed := w.user(t, "user:ed", "editors-in-chief", "match-desk")

	names := func(body map[string]any, node string) [][]string {
		t.Helper()
		raw, ok := body["paths"].([]any)
		if !ok || len(raw) == 0 {
			t.Fatalf("ancestors of %s: paths %v", node, body["paths"])
		}
		var out [][]string
		for _, p := range raw {
			arr, ok := p.([]any)
			if !ok || len(arr) == 0 {
				t.Fatalf("ancestors of %s: a path %v, want an array of node names", node, p)
			}
			var path []string
			for _, n := range arr {
				s, ok := n.(string)
				if !ok {
					t.Fatalf("ancestors of %s: a path element %v (%T), want a node name", node, n, n)
				}
				path = append(path, s)
			}
			if path[len(path)-1] != node {
				t.Fatalf("ancestors of %s: a path ends at %s, want the node itself", node, path[len(path)-1])
			}
			out = append(out, path)
		}
		return out
	}
	copyTR := func(dir, title string, want int, say string) {
		t.Helper()
		what := "ed's COPY of TR to " + dir
		r := g.expect(g.doAs(ed, "COPY", "/cat/Season%202026/TR", "", "Destination", dir+"/"+strings.ReplaceAll(title, " ", "%20")), want, what)
		folder, _ := w.titled(t, title)
		if want == 201 {
			if folder == "" {
				t.Fatalf("%s: no folder made", what)
			}
			return
		}
		if !strings.Contains(r.body, say) {
			t.Fatalf("%s: %s, want %q", what, r.body, say)
		}
		if folder != "" {
			t.Fatalf("%s: the refused copy made %s", what, folder)
		}
	}

	// Below TR through a second parent: TR is on a path the service lists.
	copyTR("/cat/Season%202026/Both", "TR copy 1", 403, "into itself")
	both := rec.of(t, "both")
	var viaTR bool
	for _, p := range names(both, "both") {
		// ed sees the tree from Season 2026, his visible root.
		if p[0] != "season" {
			t.Errorf("ancestors of both: a path starts at %s, want season", p[0])
		}
		viaTR = viaTR || strings.Join(p, "/") == "season/tr/inner/both"
	}
	if !viaTR || len(names(both, "both")) != 2 {
		t.Errorf("ancestors of both: paths %v, want season/both and season/tr/inner/both", both["paths"])
	}
	for _, k := range []string{"tooDeep", "truncated"} {
		if v, has := both[k]; has {
			t.Errorf("ancestors of both: %s %v without a cut", k, v)
		}
	}
	// Beside TR: checked and made.
	copyTR("/cat/Season%202026/Sub", "TR copy 2", 201, "")
	if ps := names(rec.of(t, "sub"), "sub"); len(ps) != 1 || strings.Join(ps[0], "/") != "season/sub" {
		t.Errorf("ancestors of sub: %v", ps)
	}
	// Past the depth limit: the service says so, and the gateway leaves
	// the copy unmade.
	copyTR("/cat/Season%202026/Far", "TR copy 3", 403, "didn't list every path")
	if far := rec.of(t, "far"); far["tooDeep"] != true || far["truncated"] != nil {
		t.Errorf("ancestors of far: tooDeep %v (%T), truncated %v; want the boolean true alone", far["tooDeep"], far["tooDeep"], far["truncated"])
	}
	// Within it: checked and made.
	copyTR("/cat/Season%202026/Near", "TR copy 4", 201, "")
	if near := rec.of(t, "near"); near["tooDeep"] != nil || len(names(near, "near")) != 2 {
		t.Errorf("ancestors of near: tooDeep %v, paths %v", near["tooDeep"], near["paths"])
	}
}
