package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §7.1 Paging: NSLog and Log read every page of a range; NSLogPage reads
// one, naming the next page's since.
func TestLogPages(t *testing.T) {
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
}

func fakeID(c byte) string { return "1" + strings.Repeat(string(c), 32) }

// A page short of its range without X-Log-Next can't pass for the whole
// range, nor can an X-Log-Next that isn't the page's last entry, or an
// empty page that names one (§7.1 Paging). A later page of an e2e range
// repeats the snapshot of its since; Log leaves it out.
func TestLogPagesChecked(t *testing.T) {
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
	snapshot := func(id string) map[string]any {
		return map[string]any{"id": id, "kind": "snapshot", "snapshot": "x.y.z"}
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
		s0: {e2, []any{snapshot(s0), resEntry(e1, s0), resEntry(e2, e1)}},
		e2: {"", []any{snapshot(e2), resEntry(e3, e2)}},
	}
	es, err := c.Log(ctx, "n", "a", e3, s0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range es {
		got = append(got, e.Kind+":"+e.ID[1:2])
	}
	if strings.Join(got, ",") != "snapshot:s,rev:b,rev:c,rev:d" {
		t.Fatalf("e2e range %v", got)
	}
}

// The client's own flows with a log page size of 2: every log range they
// read spans pages (sealed namespace ranges are opened page by page, and
// e2e folds read the range from a prune snapshot across pages).
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"namespace": TestNamespaceAPI, "sealed": TestSealedTransparent, "e2e": TestE2EClient,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
