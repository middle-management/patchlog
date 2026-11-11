package tree_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// The seam between a release preview's entries and a reader's check of a
// value of another resource (SERVICES §B.5 Previews, §E.2.6 Values of
// another resource: "a reader compares ns and name with the resource the
// entry draws the value from, where the entry names it"). In a preview of
// a file tree over sealed content, a placement's file metadata is drawn
// from the release's branch of its item's namespace and sealed under that
// branch's keys: kid and pl.ns name the branch. The entry's "item" keeps
// the link documents use, in the base, so the entry names the resource
// the value is drawn from in "branch", beside "item"; a reader that takes
// the namespace from "branch" and the name from "item" opens the value,
// and one comparing with the base is refused.
func TestV082XrevPreviewFileNamesItsBranch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	q := newV82Sealed(t)
	nss := []string{"cat", "files", "cat-r7", "files-r7"}
	w := q.s.Client(t, client.WithBearer(q.k.Grant(t, q.s.Now(), "user:w", nss, []string{"read", "create", "config", "branch"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-r7"}))
	must(w.CreateBranch(ctx, "files", client.BranchRequest{Name: "files-r7"}))
	for _, ns := range []string{"cat-r7", "files-r7"} {
		for _, e := range must(w.FetchKeys(ctx, ns, nil, nil)) {
			q.keys[e.Kid] = e.Key
		}
	}
	sc := q.s.Client(t, client.WithBearer(q.k.Grant(t, q.s.Now(), "svc:tree", nss, []string{"read"},
		map[string]any{"nbf": q.s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: q.s.Now, db: q.db}, func(o *tree.Options) {
		o.Branches = map[string]string{"cat": "cat-r7", "files": "files-r7"}
	})
	full := q.k.Grant(t, q.s.Now(), "user:r", nss, []string{"read"})
	var e map[string]any
	var path string
	waitFor(t, "the preview to list files.notes with its file metadata", func() bool {
		if x.listingAs("/cat/children?of=root", full).status != http.StatusOK {
			return false
		}
		f := x.fetch("/cat/children?of=root", full)
		body := f.body
		if f.header.Get("Content-Type") == seal.ContentType {
			// Sealed whole, under the branch catalog's keys; the file
			// metadata nests inside.
			pt, err := derived.OpenView(string(f.body), q.keyOf, derived.View{NS: "cat-r7", Target: f.path})
			if err != nil {
				t.Fatalf("the preview's listing, opened as cat-r7's: %v", err)
			}
			body = pt
		}
		e, path = entriesOf(t, decode(t, body))["files.notes"], f.path
		jwe, _ := fileOf(e)["sealed"].(string)
		return jwe != ""
	})
	if !strings.HasPrefix(path, "/cat/") {
		t.Fatalf("the view as served: %s", path)
	}
	// What the entry names: the item where documents link it, and the
	// branch the preview read it in.
	if e["item"] != "/r/files/notes" || e["branch"] != "files-r7" {
		t.Fatalf("the preview's entry of files.notes: item %v, branch %v; want /r/files/notes and files-r7", e["item"], e["branch"])
	}
	if u, _ := e["url"].(string); !strings.Contains(u, "/r/files-r7/notes/rev/") {
		t.Errorf("the preview's entry of files.notes: url %v, want the head in files-r7", e["url"])
	}
	if len(fileOf(e)) != 1 {
		t.Fatalf("file of files.notes: %v, want { sealed } alone", fileOf(e))
	}
	jwe := fileOf(e)["sealed"].(string)
	h := must(seal.ParseHeader(jwe))
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil || kns != "files-r7" || len(h.PL) != 3 || h.PL["ns"] != "files-r7" || h.PL["name"] != "notes" || h.PL["view"] != path {
		t.Fatalf("the preview's file of files.notes: kid %s pl %v, want files-r7's kid and { ns: files-r7, name: notes, view }", h.Kid, h.PL)
	}
	// The reader's check: the namespace the entry's branch names, the
	// name its item names.
	ns, name := e["branch"].(string), strings.TrimPrefix(e["item"].(string), "/r/files/")
	v := derived.View{NS: "cat-r7", Target: path}
	pt, err := derived.OpenItem(jwe, derived.ItemKey(q.keyOf, ns, name), v, ns, name)
	if err != nil {
		t.Fatalf("the preview's file opened as %s/%s, which the entry names: %v", ns, name, err)
	}
	if m := decode(t, pt); len(m) != 1 || m["file"] == nil {
		t.Errorf("the preview's file: plaintext %s, want an object of that one member", pt)
	}
	// Compared with the base's resource, which "item" alone names, it is
	// refused on pl; the base's key opens nothing.
	if _, err := derived.OpenItem(jwe, derived.ItemKey(q.keyOf, "files", "notes"), v, "files", "notes"); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("the preview's file opened as the base's: %v, want ErrMismatch", err)
	}
	baseKey := func(string) []byte { return q.keys["files#1"] }
	if _, err := derived.OpenItem(jwe, derived.ItemKey(baseKey, "files-r7", "notes"), v, "files-r7", "notes"); !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("the preview's file opened with the base's key: %v, want ErrDecrypt", err)
	}
}

// Scenario 128, SVC-21 (SERVICES §B.5 Behind: a namespace the service
// stopped following "leaves the combined checkpoint, so at moves when the
// service stops and when it resumes following it"), with nothing written
// anywhere between: the core refuses the service's reads of sec's log for
// a while, which stops sec, and then answers them again, which ends the
// stop at the checkpoint it was stopped at. The at a listing redirects to
// is another one while sec is stopped, though no namespace's checkpoint
// moved, and moves again once sec is followed again, to the at of the
// same checkpoints as before the stop.
func TestV082XrevAtMovesAcrossStopNothingWritten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var refuse atomic.Bool
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
		Wrap: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if refuse.Load() && strings.HasPrefix(r.URL.Path, "/ns/sec/") && strings.HasSuffix(r.URL.Path, "/log") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					w.Write([]byte(`{"code":"forbidden","message":"injected"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"cat", "sec"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag", "title": "/title"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	both := []string{"cat", "sec"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "A"}))
	must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "sec")
	heads := func() [2]string {
		return [2]string{must(w.NSHead(ctx, "cat")).ID, must(w.NSHead(ctx, "sec")).ID}
	}
	atRE := regexp.MustCompile(`^/cat/at/([^/?]+)/`)
	// at is the at an anonymous listing is redirected to, and whether
	// the listing it names shows sec.a.
	at := func() (string, bool) {
		st, _, b, loc := v0261Get(x, "/cat/children?of=root", "")
		m := atRE.FindStringSubmatch(loc)
		if st != 200 || m == nil {
			return "", false
		}
		return m[1], strings.Contains(b, "sec.a")
	}
	start := heads()
	before, shown := at()
	if before == "" || !shown {
		t.Fatalf("setup: at %q, sec.a shown %v", before, shown)
	}
	refuse.Store(true)
	waitFor(t, "sec stopped", func() bool { return v0261Stopped(t, db, "sec") })
	var during string
	waitFor(t, "a listing without sec.a", func() bool {
		a, shown := at()
		during = a
		return a != "" && !shown
	})
	if during == before {
		t.Errorf("at while sec is stopped: %s, as before the stop: it didn't move", during)
	}
	refuse.Store(false)
	waitFor(t, "sec followed again", func() bool { return !v0261Stopped(t, db, "sec") })
	var after string
	waitFor(t, "a listing with sec.a again", func() bool {
		a, shown := at()
		after = a
		return a != "" && shown
	})
	if after == during {
		t.Errorf("at once sec is followed again: %s, as while stopped: it didn't move", after)
	}
	if heads() != start {
		t.Fatalf("something was written meanwhile: heads %v, were %v", heads(), start)
	}
	// Nothing was written, so the checkpoints are those of before.
	if after != before {
		t.Errorf("at once sec is followed again, nothing written: %s, want %s as before the stop", after, before)
	}
}
