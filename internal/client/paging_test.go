package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// §7.1 Paging: NSLog and Log read every page of a range; NSLogPage and
// LogPage read one, naming the next page's since.
func TestLogPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "docs", map[string]any{"read": "public"}))
	w := must(c.CreateDoc(ctx, "docs", "a", map[string]any{"n": 0}))
	ids := []string{w.ID}
	for i := 1; i < 5; i++ {
		w = must(c.Append(ctx, "docs", "a", w.ID, ops(op("replace", "/n", i))))
		ids = append(ids, w.ID)
	}
	h := must(c.NSHead(ctx, "docs"))
	all := must(c.NSLog(ctx, "docs", h.ID, ""))
	if len(all) != 6 || all[0].Kind != "config" || all[5].ID != h.ID {
		t.Fatalf("namespace log %d entries", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Prev != all[i-1].ID {
			t.Fatalf("entry %d doesn't chain", i)
		}
	}
	// Page by page.
	var paged []client.NSEntry
	since, pages := "", 0
	for {
		es, next, err := c.NSLogPage(ctx, "docs", h.ID, since)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(es) > 2 || next != "" && next != es[len(es)-1].ID {
			t.Fatalf("page %d: %d entries, next %s", pages, len(es), next)
		}
		paged = append(paged, es...)
		if next == "" {
			break
		}
		since = next
	}
	if pages != 3 || len(paged) != 6 || paged[5].ID != h.ID {
		t.Fatalf("%d pages, %d entries", pages, len(paged))
	}
	// A range from a since, and one up to an older id.
	if es := must(c.NSLog(ctx, "docs", all[4].ID, all[0].ID)); len(es) != 4 || es[3].ID != all[4].ID {
		t.Fatalf("range %d", len(es))
	}
	if es := must(c.NSLog(ctx, "docs", h.ID, h.ID)); len(es) != 0 {
		t.Fatalf("empty range %d", len(es))
	}

	lg := must(c.Log(ctx, "docs", "a", "", ""))
	if len(lg) != 5 || lg[4].ID != ids[4] {
		t.Fatalf("resource log %d", len(lg))
	}
	for i, e := range lg {
		if e.ID != ids[i] || i > 0 && e.Parent != ids[i-1] {
			t.Fatalf("entry %d: %+v", i, e)
		}
	}
	if es := must(c.Log(ctx, "docs", "a", ids[3], ids[0])); len(es) != 3 || es[0].ID != ids[1] {
		t.Fatalf("resource range %d", len(es))
	}
	if es := must(c.Log(ctx, "docs", "a", ids[2], ids[2])); len(es) != 0 {
		t.Fatalf("empty resource range %d", len(es))
	}
	// LogPage reads one page: enough to learn whether since is an
	// ancestor.
	es, next, err := c.LogPage(ctx, "docs", "a", ids[4], "")
	if err != nil || len(es) != 2 || es[1].ID != ids[1] || next != ids[1] {
		t.Fatalf("first resource page: %v, next %q, %v", es, next, err)
	}
	if es, next, err = c.LogPage(ctx, "docs", "a", ids[4], ids[2]); err != nil || len(es) != 2 || es[1].ID != ids[4] || next != "" {
		t.Fatalf("last resource page: %v, next %q, %v", es, next, err)
	}
	if _, _, err := c.LogPage(ctx, "docs", "a", ids[2], ids[3]); !client.IsNotFound(err) {
		t.Fatalf("page after a since that isn't an ancestor: %v", err)
	}
}

func fakeID(c byte) string { return "1" + strings.Repeat(string(c), 32) }

// A page short of its range without X-Log-Next can't pass for the whole
// range, nor can an X-Log-Next that isn't the page's last entry, or an
// empty page that names one (§7.1 Paging). A range from an e2e pruning
// horizon holds only the entries after it (its snapshot is /rev/{H}).
func TestLogPagesChecked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s0, e1, e2, e3 := fakeID('s'), fakeID('b'), fakeID('c'), fakeID('d')
	nsEntry := func(id, prev string) map[string]any {
		m := map[string]any{"id": id, "kind": "head", "resource": "a", "target": id, "author": "x", "created": "2026-10-04T12:00:00.000Z"}
		if prev != "" {
			m["prev"] = prev
		}
		return m
	}
	resEntry := func(id, parent string) map[string]any {
		m := map[string]any{"id": id, "kind": "rev", "patches": []any{}, "author": "x", "created": "2026-10-04T12:00:00.000Z"}
		if parent != "" {
			m["parent"] = parent
		}
		return m
	}
	type answer struct {
		next    string
		entries []any
	}
	var pages map[string]answer // by since
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := pages[r.URL.Query().Get("since")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if a.next != "" {
			w.Header().Set("X-Log-Next", a.next)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(a.entries)
	}))
	defer srv.Close()
	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	pages = map[string]answer{
		"":   {e2, []any{nsEntry(e1, ""), nsEntry(e2, e1)}},
		e2:   {"", []any{nsEntry(e3, e2)}},
		"zz": {},
	}
	if es, err := c.NSLog(ctx, "n", e3, ""); err != nil || len(es) != 3 || es[2].ID != e3 {
		t.Fatalf("well-formed pages: %v %v", es, err)
	}
	for name, first := range map[string]answer{
		"no X-Log-Next":         {"", []any{nsEntry(e1, ""), nsEntry(e2, e1)}},
		"X-Log-Next not last":   {e1, []any{nsEntry(e1, ""), nsEntry(e2, e1)}},
		"empty with X-Log-Next": {e1, []any{}},
		"X-Log-Next malformed":  {"1x", []any{nsEntry(e1, "")}},
	} {
		pages[""] = first
		if _, err := c.NSLog(ctx, "n", e3, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := c.Log(ctx, "n", "a", e3, ""); err == nil {
			t.Errorf("%s: resource log accepted", name)
		}
	}

	pages = map[string]answer{
		s0: {e2, []any{resEntry(e1, s0), resEntry(e2, e1)}},
		e2: {"", []any{resEntry(e3, e2)}},
	}
	es, err := c.Log(ctx, "n", "a", e3, s0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range es {
		got = append(got, e.Kind+":"+e.ID[1:2])
	}
	if strings.Join(got, ",") != "rev:b,rev:c,rev:d" {
		t.Fatalf("e2e range %v", got)
	}
}

// The client's own flows with a log page size of 2: every log range they
// read spans pages (sealed namespace ranges are opened page by page, and
// e2e folds read the range after a prune's horizon across pages).
//
// Paged sets the environment, so these flows run serially and call the
// tests' bodies, not the parallel TestX.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"namespace": testNamespaceAPI, "sealed": testSealedTransparent, "e2e": testE2EClient,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}

// A real server prunes an e2e resource at the last entry of the first page
// of a range a client is reading, before the client asks for the next: the
// next page's since is then the horizon. That page holds only the entries
// after it (the snapshot is /rev/{H}, never a log entry), so the range
// reads as one chain from where it began (§7.1 Paging).
func TestLogPageFromSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu     sync.Mutex
		heads  = map[string]string{} // armed: name → the range's id
		pruned = map[string]string{} // name → horizon
		w      *client.E2E
	)
	// After serving the first page of a range up to an armed head, and
	// before the client sees it, prune at the page's last entry.
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			seg := strings.Split(r.URL.Path, "/") // "", r, e, name, rev, id, log
			if len(seg) != 7 || seg[1] != "r" || seg[6] != "log" || r.URL.Query().Get("since") != "" {
				h.ServeHTTP(rw, r)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			mu.Lock()
			name, next := seg[3], rec.Header().Get("X-Log-Next")
			arm := heads[name] == seg[5] && next != ""
			if arm {
				delete(heads, name)
			}
			mu.Unlock()
			if arm {
				if _, err := w.PruneE2E(context.Background(), "e", name, next); err != nil {
					t.Errorf("prune %s at %s: %v", name, next, err)
				}
				mu.Lock()
				pruned[name] = next
				mu.Unlock()
			}
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			rw.Write(rec.Body.Bytes())
		})
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Archiver: arch, LogPageSize: 2, Wrap: wrap})
	writer := clienttest.NewKey("writer")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e")))
	must(opc.CreateNamespace(ctx, "e", map[string]any{"keys": []any{writer.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	jwk, priv, _ := seal.GenerateRecipient()
	wc := s.Client(t, client.WithBearer(writer.Grant(t, s.Now(), "user:writer", []string{"e"}, []string{"read", "create", "append", "prune", "config"}, map[string]any{"enc": jwk})))
	w = wc.E2E(priv)
	must(w.InitKeyring(ctx, "e"))
	revs := map[string][]string{}
	for _, name := range []string{"a", "b"} {
		r := must(w.CreateDocSealed(ctx, "e", name, map[string]any{"n": 0}))
		revs[name] = []string{r.ID}
		for i := 1; i < 6; i++ {
			r = must(w.AppendSealed(ctx, "e", name, r.ID, ops(op("replace", "/n", i))))
			revs[name] = append(revs[name], r.ID)
		}
	}
	s.Clock.Advance(10 * time.Minute)
	mu.Lock()
	heads["a"], heads["b"] = revs["a"][5], revs["b"][5]
	mu.Unlock()

	es := must(wc.Log(ctx, "e", "a", revs["a"][5], ""))
	var got []string
	for _, e := range es {
		got = append(got, e.ID)
	}
	if strings.Join(got, ",") != strings.Join(revs["a"], ",") {
		t.Fatalf("log across a prune: %v, want %v", got, revs["a"])
	}
	d := must(w.DocE2E(ctx, "e", "b", revs["b"][5]))
	sameJSON(t, d.Value, map[string]any{"n": 5})
	mu.Lock()
	pa, pb := pruned["a"], pruned["b"]
	mu.Unlock()
	if pa != revs["a"][1] || pb != revs["b"][1] {
		t.Fatalf("pruned at %s and %s", pa, pb)
	}
	// The prune really happened: the range from genesis is gone now.
	if _, err := wc.Log(ctx, "e", "a", revs["a"][5], ""); !client.IsPruned(err) {
		t.Fatalf("range across the horizon after the prune: %v", err)
	}
}

// A pruned e2e resource folds from its horizon's snapshot, which /rev/{H}
// serves, plus the range after it, which never holds the snapshot (§7.1
// Paging, §8.6): across pages and on a single page, at the horizon itself,
// and from a tombstone horizon, whose /rev/{H} is a 410 carrying the last
// live document.
func TestE2EFoldFromHorizon(t *testing.T) {
	t.Parallel()
	for _, size := range []int{2, 100} {
		t.Run(fmt.Sprintf("page%d", size), func(t *testing.T) { testE2EFoldFromHorizon(t, size) })
	}
}

func testE2EFoldFromHorizon(t *testing.T, size int) {
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		paths []string
		pages = map[string]int{} // log range URL path → pages read
	)
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			mu.Lock()
			paths = append(paths, r.URL.RequestURI())
			if strings.HasSuffix(r.URL.Path, "/log") && rec.Code == 200 {
				pages[r.URL.Path]++
				var arr []map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &arr); err == nil {
					for _, m := range arr {
						if m["kind"] == "snapshot" || m["snapshot"] != nil {
							t.Errorf("%s: a snapshot in a log range: %v", r.URL, m)
						}
					}
				}
			}
			mu.Unlock()
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			rw.Write(rec.Body.Bytes())
		})
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Archiver: arch, LogPageSize: size, Wrap: wrap})
	writer := clienttest.NewKey("writer")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e")))
	must(opc.CreateNamespace(ctx, "e", map[string]any{"keys": []any{writer.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	jwk, priv, _ := seal.GenerateRecipient()
	wc := s.Client(t, client.WithBearer(writer.Grant(t, s.Now(), "user:writer", []string{"e"}, []string{"read", "create", "append", "delete", "restore", "prune", "config"}, map[string]any{"enc": jwk})))
	w := wc.E2E(priv)
	must(w.InitKeyring(ctx, "e"))
	r := must(w.CreateDocSealed(ctx, "e", "p", map[string]any{"n": 0}))
	revs := []string{r.ID}
	for i := 1; i < 7; i++ {
		r = must(w.AppendSealed(ctx, "e", "p", r.ID, ops(op("replace", "/n", i))))
		revs = append(revs, r.ID)
	}
	s.Clock.Advance(10 * time.Minute)
	h := revs[2]
	if pr := must(w.PruneE2E(ctx, "e", "p", h)); pr.Horizon != h {
		t.Fatalf("horizon %s, want %s", pr.Horizon, h)
	}
	// A fresh view (no cached keys or documents) reads it.
	x := wc.E2E(priv)
	read := func(id string) (any, []string) {
		t.Helper()
		mu.Lock()
		paths, pages = nil, map[string]int{}
		mu.Unlock()
		d := must(x.DocE2E(ctx, "e", "p", id))
		if len(d.Flagged) != 0 || d.ValidID != id {
			t.Fatalf("fold at %s: flagged %v, valid %s", id, d.Flagged, d.ValidID)
		}
		mu.Lock()
		defer mu.Unlock()
		return d.Value, append([]string(nil), paths...)
	}
	has := func(ps []string, p string) bool {
		for _, x := range ps {
			if x == p {
				return true
			}
		}
		return false
	}
	revPath := func(id string) string { return "/r/e/p/rev/" + id }

	// After the horizon: /rev/{H} for the snapshot, then the range after H.
	v, ps := read(revs[6])
	sameJSON(t, v, map[string]any{"n": 6})
	if !has(ps, revPath(h)) || !has(ps, revPath(revs[6])+"/log?since="+h) {
		t.Fatalf("fold at the head read %v", ps)
	}
	mu.Lock()
	n := pages[revPath(revs[6])+"/log"]
	mu.Unlock()
	if want := (4 + size - 1) / size; n != want {
		t.Fatalf("4 entries after the horizon in pages of %d took %d pages, want %d", size, n, want)
	}
	// Right after it: a one-entry range.
	v, _ = read(revs[3])
	sameJSON(t, v, map[string]any{"n": 3})
	// At the horizon: the snapshot alone, no log.
	v, ps = read(h)
	sameJSON(t, v, map[string]any{"n": 2})
	for _, p := range ps {
		if strings.Contains(p, "/log") {
			t.Fatalf("fold at the horizon read a log range: %v", ps)
		}
	}
	// Log and LogPage after the horizon hold only revisions.
	es := must(wc.Log(ctx, "e", "p", revs[6], h))
	if len(es) != 4 || es[0].Parent != h || es[0].Kind != "rev" {
		t.Fatalf("log after the horizon: %v", es)
	}
	page, _, err := wc.LogPage(ctx, "e", "p", revs[6], h)
	if err != nil || len(page) != min(4, size) || page[0].ID != revs[3] {
		t.Fatalf("first page after the horizon: %v %v", page, err)
	}

	// A tombstone horizon: a restore with [] brings back the snapshot's
	// document, the last live one.
	del := must(wc.Delete(ctx, "e", "p", revs[6]))
	s.Clock.Advance(10 * time.Minute)
	must(w.PruneE2E(ctx, "e", "p", del.ID))
	res := must(w.RestoreSealed(ctx, "e", "p", del.ID, nil))
	v, ps = read(res.ID)
	sameJSON(t, v, map[string]any{"n": 6})
	if !has(ps, revPath(del.ID)) || !has(ps, revPath(res.ID)+"/log?since="+del.ID) {
		t.Fatalf("fold after a tombstone horizon read %v", ps)
	}
	if _, err := x.DocE2E(ctx, "e", "p", del.ID); !client.IsGone(err) {
		t.Fatalf("the tombstone horizon itself: %v", err)
	}
}
