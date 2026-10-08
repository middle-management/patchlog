package tree_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/tree"
)

// TestPreviewFollowsRelease: a long-running preview follows the release
// document's log (§B.5, §10), so a revision listing other branches (a
// rebase's successors) takes effect without a restart.
func TestPreviewFollowsRelease(t *testing.T) {
	t.Parallel()
	w := setup(t)
	ctx := context.Background()
	w.seed(t)
	must(w.c.CreateNamespace(ctx, "releases", map[string]any{"read": "public"}))
	must(w.c.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-r1"}))
	must(w.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r1"}))
	must(w.c.CreateDoc(ctx, "cat-r1", "r1only", map[string]any{"title": "R1", "parents": parents("root")}))
	ref := release.Ref{NS: "releases", Name: "release-7"}
	doc := &release.Doc{Name: "release-7", Branches: map[string]release.Branch{
		"cat": {NS: "cat-r1"}, "matches": {NS: "matches-r1"}}}
	rev1 := must(release.Write(ctx, w.c, ref, "", doc))

	p := must(tree.OpenPreview(ctx, tree.Options{Client: w.c, Catalog: "cat", DB: filepath.Join(t.TempDir(), "p.db"),
		CheckerTTL: time.Millisecond, Logf: func(f string, a ...any) { t.Logf(f, a...) },
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}}, "/r/releases/release-7"))
	hs := httptest.NewServer(p.Handler())
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { p.Run(cctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); p.Close() })
	x := &svc{t: t, http: hs, core: w.c}

	// at waits until the preview has reached every branch's head.
	reached := func(cat, matches string) {
		t.Helper()
		waitFor(t, "the preview to reach "+cat+" and "+matches, func() bool {
			s := p.Service()
			hc, err1 := w.c.NSHead(ctx, cat)
			hm, err2 := w.c.NSHead(ctx, matches)
			return err1 == nil && err2 == nil && s.Branches()["cat"] == cat && s.Checkpoint("cat") == hc.ID && s.Checkpoint("matches") == hm.ID
		})
	}
	reached("cat-r1", "matches-r1")
	if p.Revision() != rev1 {
		t.Errorf("revision %s, want %s", p.Revision(), rev1)
	}
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "season,derbies,r1only" {
		t.Errorf("preview of r1: %s", got)
	}

	// A revision listing the same branches changes nothing but the revision.
	first := p.Service()
	doc.Owners = []string{"user:anna"}
	rev2 := must(release.Write(ctx, w.c, ref, rev1, doc))
	waitFor(t, "the preview to see the new revision", func() bool { return p.Revision() == rev2 })
	if p.Service() != first {
		t.Error("the same branches reopened the service")
	}

	// A rebase's successor: the preview switches to it.
	must(w.c.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-r2"}))
	must(w.c.CreateDoc(ctx, "cat-r2", "r2only", map[string]any{"title": "R2", "parents": parents("root")}))
	doc.Branches["cat"] = release.Branch{NS: "cat-r2"}
	rev3 := must(release.Write(ctx, w.c, ref, rev2, doc))
	waitFor(t, "the preview to switch", func() bool { return p.Revision() == rev3 })
	reached("cat-r2", "matches-r1")
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "season,derbies,r2only" {
		t.Errorf("preview of r2: %s", got)
	}
	// Listings name the new branches.
	if r := x.raw("/cat/children?of=root", ""); !strings.HasPrefix(r.header.Get("Location"), "/cat/at/") {
		t.Errorf("pointer %d %v", r.status, r.header)
	}

	// An invalid revision, or deleting the document, leaves the preview as it is.
	must(w.c.Append(ctx, "releases", "release-7", rev3, []any{map[string]any{"op": "replace", "path": "/branches", "value": map[string]any{}}}))
	h := must(w.c.Head(ctx, "releases", "release-7"))
	must(w.c.Delete(ctx, "releases", "release-7", h.ID))
	time.Sleep(400 * time.Millisecond) // a few long-poll rounds (150 ms)
	if p.Revision() != rev3 || p.Service().Branches()["cat"] != "cat-r2" {
		t.Errorf("after an invalid revision and a delete: %s %v", p.Revision(), p.Service().Branches())
	}
	if got := names(x.get("/cat/children?of=root", "")["children"]); got != "season,derbies,r2only" {
		t.Errorf("preview after the delete: %s", got)
	}
}
