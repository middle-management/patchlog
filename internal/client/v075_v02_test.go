package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
)

// v075ID is a well-formed id for s.
func v075ID(s string) string { return ids.Hash(nil, []byte(s)).String() }

// v075Fake serves h and returns a client of it.
func v075Fake(t *testing.T, h http.HandlerFunc) *client.Client {
	t.Helper()
	hs := httptest.NewServer(h)
	t.Cleanup(hs.Close)
	c, err := client.New(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func v075JSON(w http.ResponseWriter, hdr map[string]string, v any) {
	w.Header().Set("Content-Type", "application/json")
	for k, x := range hdr {
		w.Header().Set(k, x)
	}
	json.NewEncoder(w).Encode(v)
}

// /principal's roles are objects { name, can, rules } from v0.75 servers
// (§7.4): Roles keeps the names and RoleDefs the definitions; from older
// servers, names only (MUST-2, SVC-8).
func TestV075NSPrincipalRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var roles atomic.Value
	c := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		v075JSON(w, map[string]string{"X-Config-Revision": v075ID("cfg")}, map[string]any{"principal": map[string]any{"id": "user:r"},
			"kid": "k", "operator": false, "can": []any{"read"}, "roles": roles.Load(), "writer": map[string]any{}})
	})
	rule := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}
	roles.Store([]any{map[string]any{"name": "reader", "can": []any{"read"}, "rules": []any{}},
		map[string]any{"name": "translator", "can": []any{"read", "append"}, "rules": []any{rule}}})
	p := must(c.NSPrincipal(ctx, "n"))
	if !reflect.DeepEqual(p.Roles, []string{"reader", "translator"}) || len(p.RoleDefs) != 2 {
		t.Fatalf("roles %v defs %+v", p.Roles, p.RoleDefs)
	}
	if d := p.RoleDefs[0]; d.Name != "reader" || !reflect.DeepEqual(d.Can, []string{"read"}) || d.Rules == nil || len(d.Rules) != 0 {
		t.Fatalf("reader %+v", d)
	}
	if d := p.RoleDefs[1]; d.Name != "translator" || !reflect.DeepEqual(d.Can, []string{"read", "append"}) || len(d.Rules) != 1 {
		t.Fatalf("translator %+v", d)
	}
	// A server before v0.75 sends names.
	roles.Store([]any{"reader"})
	p = must(c.NSPrincipal(ctx, "n"))
	if !reflect.DeepEqual(p.Roles, []string{"reader"}) || len(p.RoleDefs) != 1 || p.RoleDefs[0].Name != "reader" || p.RoleDefs[0].Can != nil {
		t.Fatalf("old roles %v defs %+v", p.Roles, p.RoleDefs)
	}

	// Against this server, end to end (§7.4).
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("k")
	admin := s.Client(t, client.WithBearer(s.OperatorGrant(t, "p")))
	must(admin.CreateNamespace(ctx, "p", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"roles": map[string]any{"translator": map[string]any{"can": []any{"read", "append"}, "rules": []any{rule}}}}))
	tr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:t", []string{"p"}, nil, map[string]any{"roles": []any{"translator", "ghost"}})))
	p = must(tr.NSPrincipal(ctx, "p"))
	if !reflect.DeepEqual(p.Roles, []string{"translator"}) || len(p.RoleDefs) != 1 ||
		!reflect.DeepEqual(p.RoleDefs[0].Can, []string{"read", "append"}) || len(p.RoleDefs[0].Rules) != 1 {
		t.Fatalf("server roles %v defs %+v", p.Roles, p.RoleDefs)
	}
}

// /heads takes ?prefix=, a resource name (§7.4, §12.4): HeadsPrefix sends
// it and reads every page; an invalid prefix is refused before any
// request, and a row outside it is an error (MUST-8, SVC-9).
func TestV075HeadsPrefix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	nsID := v075ID("h")
	var asked atomic.Int32
	var stray atomic.Bool
	c := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		q := r.URL.Query()
		if r.URL.Path != "/ns/n/rev/"+nsID+"/heads" || q.Get("prefix") != "pub-" {
			http.Error(w, "want prefix=pub-: "+r.URL.String(), 400)
			return
		}
		row := func(n string) any { return map[string]any{"resource": n, "kind": "head", "target": v075ID(n)} }
		switch q.Get("after") {
		case "":
			v075JSON(w, nil, map[string]any{"heads": []any{row("pub-a")}, "next": "pub-a"})
		case "pub-a":
			rows := []any{row("pub-b")}
			if stray.Load() {
				rows = append(rows, row("x"))
			}
			v075JSON(w, nil, map[string]any{"heads": rows})
		}
	})
	got := must(c.HeadsPrefix(ctx, "n", nsID, "pub-"))
	if len(got) != 2 || got[0].Resource != "pub-a" || got[1].Resource != "pub-b" {
		t.Fatalf("heads %+v", got)
	}
	n := asked.Load()
	for _, bad := range []string{".x", "a/b", "-a", "A", strings.Repeat("a", 129)} {
		if _, _, err := c.HeadsPrefixPage(ctx, "n", nsID, bad, ""); err == nil {
			t.Fatalf("prefix %q accepted", bad)
		}
	}
	if asked.Load() != n {
		t.Fatal("an invalid prefix was sent")
	}
	stray.Store(true)
	if _, err := c.HeadsPrefix(ctx, "n", nsID, "pub-"); err == nil || !strings.Contains(err.Error(), "outside prefix") {
		t.Fatalf("stray row: %v", err)
	}
}

// v075Filtered is a fake origin filtering namespace m for a partial
// reader (§B.11.9), in the shape of conformance scenarios 83 and 89: ranges
// at /ns/m/g/{gs}/at/{at}/…, reached by 302 from the unfiltered URLs.
type v075Filtered struct {
	gs, at, end string
	// log pages by since: entries, and X-Log-Next ("" on the last).
	pages map[string]v075Page
	heads map[string]v075Page
}

type v075Page struct {
	body []any
	next string
}

func (f *v075Filtered) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		base := "/ns/m/g/" + f.gs
		switch p := r.URL.Path; {
		case p == "/ns/m/log" && q.Get("live") == "":
			// Through the unfiltered range, as a cached head pointer may.
			http.Redirect(w, r, "/ns/m/rev/"+f.end+"/log?"+r.URL.RawQuery, 302)
		case p == "/ns/m/rev/"+f.end+"/log":
			http.Redirect(w, r, base+"/at/"+f.at+"/log?"+r.URL.RawQuery, 302)
		case p == base+"/log" && q.Get("live") == "":
			http.Redirect(w, r, base+"/at/"+f.at+"/log?"+r.URL.RawQuery, 302)
		case p == base+"/at/"+f.at+"/log":
			pg, ok := f.pages[q.Get("since")]
			if !ok {
				http.Error(w, `{"code":"not_found"}`, 404)
				return
			}
			h := map[string]string{"X-Namespace-Revision": f.end}
			if pg.next != "" {
				h["X-Log-Next"] = pg.next
			}
			v075JSON(w, h, pg.body)
		case strings.HasPrefix(p, "/ns/m/rev/") && strings.HasSuffix(p, "/heads"), p == base+"/heads":
			http.Redirect(w, r, base+"/at/"+f.at+"/heads?"+r.URL.RawQuery, 302)
		case p == base+"/at/"+f.at+"/heads":
			pg := f.heads[q.Get("after")]
			m := map[string]any{"heads": pg.body}
			if pg.next != "" {
				m["next"] = pg.next
			}
			v075JSON(w, map[string]string{"X-Namespace-Revision": f.end}, m)
		default:
			http.Error(w, "unexpected "+r.URL.String(), 418)
		}
	}
}

func v075Entry(id, prev, kind, res string) map[string]any {
	m := map[string]any{"id": id, "prev": prev, "kind": kind, "target": v075ID("t" + id), "author": "a", "created": "2026-01-01T00:00:00.000Z"}
	if res != "" {
		m["resource"] = res
	}
	return m
}

// A filtered range (§B.11.9 Log ranges, §7.1): pages count hidden entries,
// X-Log-Next names hidden ones, a page may be empty, and the range ends at
// X-Namespace-Revision with the page that lacks X-Log-Next. FilteredLog
// follows the redirects there and returns exactly the visible entries,
// batches with their visible items; NSLog, unchanged, can't (SVC-10).
func TestV075FilteredLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c0, b1, h1, h2, e3, h4, e5 := v075ID("c0"), v075ID("b1"), v075ID("h1"), v075ID("h2"), v075ID("e3"), v075ID("h4"), v075ID("e5")
	end := v075ID("end")
	batch := v075Entry(b1, c0, "batch", "")
	batch["entries"] = []any{map[string]any{"kind": "head", "resource": "pub-a", "target": v075ID("pa")}}
	f := &v075Filtered{gs: v075ID("gs"), at: v075ID("at"), end: end, pages: map[string]v075Page{
		"": {[]any{v075Entry(c0, "", "config", ""), batch}, h1},
		h1: {[]any{}, h2},
		h2: {[]any{v075Entry(e3, h2, "head", "pub-b")}, h4},
		h4: {[]any{v075Entry(e5, h4, "tombstone", "pub-a")}, ""},
		// A page whose X-Log-Next doesn't move on.
		e5: {[]any{}, e5},
	}}
	c := v075Fake(t, f.serve(t))
	es, fa, err := c.FilteredLog(ctx, "m", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := (client.FilteredAt{NS: "m", GS: f.gs, At: f.at, End: end}); fa != want || !fa.Filtered() {
		t.Fatalf("at %+v, want %+v", fa, want)
	}
	var got []string
	for _, e := range es {
		got = append(got, e.ID)
	}
	if !reflect.DeepEqual(got, []string{c0, b1, e3, e5}) || len(es[1].Entries) != 1 || es[1].Entries[0].Resource != "pub-a" {
		t.Fatalf("entries %v %+v", got, es)
	}
	// From a since naming a hidden entry, and under a cookie's /g/{gs}.
	es, _, err = c.FilteredLogAt(ctx, client.FilteredAt{NS: "m", GS: f.gs}, h2)
	if err != nil || len(es) != 2 || es[0].ID != e3 || es[1].ID != e5 {
		t.Fatalf("from %s: %v %+v", h2, err, es)
	}
	// One page at a time: the empty page names a hidden entry.
	page, next, got1, err := c.FilteredLogPage(ctx, fa, h1)
	if err != nil || len(page) != 0 || next != h2 || got1.End != end {
		t.Fatalf("empty page %v %v %s %+v", err, page, next, got1)
	}
	if _, _, _, err := c.FilteredLogPage(ctx, fa, e5); err == nil {
		t.Fatal("an X-Log-Next equal to since was accepted")
	}
	// The unfiltered reads are unchanged: the 302 is an API error.
	if _, err := c.NSLog(ctx, "m", end, ""); err == nil {
		t.Fatal("NSLog followed the redirect")
	} else if ae, ok := client.AsAPIError(err); !ok || ae.Status != 302 {
		t.Fatalf("NSLog: %v", err)
	}

	// An unrestricted reader is answered the unfiltered range.
	cfg := v075Entry(c0, "", "config", "")
	u := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ns/m/log":
			http.Redirect(w, r, "/ns/m/rev/"+c0+"/log", 302)
		case "/ns/m/rev/" + c0 + "/log":
			v075JSON(w, nil, []any{cfg})
		}
	})
	es, fa, err = u.FilteredLog(ctx, "m", "")
	if err != nil || len(es) != 1 || es[0].ID != c0 || fa.Filtered() || fa.End != c0 {
		t.Fatalf("unrestricted %v %+v %+v", err, es, fa)
	}
}

// Filtered /heads (§B.11.9 /heads): a partial reader is redirected to the
// listing at the current at, whose pages are filled and carry next on
// every full page, so the last may be empty (SVC-10).
func TestV075FilteredHeads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	row := func(n string) any { return map[string]any{"resource": n, "kind": "head", "target": v075ID(n)} }
	f := &v075Filtered{gs: v075ID("gs"), at: v075ID("at"), end: v075ID("end"), heads: map[string]v075Page{
		"":      {[]any{row("pub-a"), row("pub-b")}, "pub-b"},
		"pub-b": {[]any{row("pub-d"), row("pub-e")}, "pub-e"},
		"pub-e": {[]any{}, ""},
	}}
	c := v075Fake(t, f.serve(t))
	nsID := v075ID("old")
	items, next, fa, err := c.FilteredHeadsPage(ctx, "m", nsID, "pub-", "")
	if err != nil || len(items) != 2 || next != "pub-b" || fa != (client.FilteredAt{NS: "m", GS: f.gs, At: f.at, End: f.end}) {
		t.Fatalf("first page %v %+v %s %+v", err, items, next, fa)
	}
	all, fa2, err := c.FilteredHeads(ctx, "m", nsID, "pub-")
	if err != nil || len(all) != 4 || all[3].Resource != "pub-e" || fa2 != fa {
		t.Fatalf("all %v %+v %+v", err, all, fa2)
	}
	// Under a cookie, without an at: redirected to the current one.
	items, _, fa3, err := c.FilteredHeadsAt(ctx, client.FilteredAt{NS: "m", GS: f.gs}, "pub-", "pub-b")
	if err != nil || len(items) != 2 || fa3.At != f.at {
		t.Fatalf("at the current at %v %+v %+v", err, items, fa3)
	}
	// HeadsPage, unchanged, doesn't follow.
	if _, _, err := c.HeadsPage(ctx, "m", nsID, ""); err == nil {
		t.Fatal("HeadsPage followed the redirect")
	}
}

// Filtered long-poll (§B.11.9 Long-poll, §7.7): LongPoll follows the 302
// into /ns/{ns}/g/{gs}/log; an interval with only hidden entries ends 204,
// whose X-Namespace-Revision, the newest hidden id, becomes the next since,
// and FilteredLongPoll sends it (conformance scenario 72; SVC-11).
func TestV075FilteredLongPoll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gs, s0, hidden, vis, newer := v075ID("gs"), v075ID("s0"), v075ID("hidden"), v075ID("vis"), v075ID("newer")
	c := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/ns/m/log" && q.Get("live") == "long-poll":
			http.Redirect(w, r, "/ns/m/g/"+gs+"/log?"+r.URL.RawQuery, 302)
		case r.URL.Path == "/ns/m/g/"+gs+"/log" && q.Get("live") == "long-poll" && q.Get("since") == s0:
			w.Header().Set("X-Namespace-Revision", hidden)
			w.Header().Set("X-Cursor", "8")
			w.WriteHeader(204)
		case r.URL.Path == "/ns/m/g/"+gs+"/log" && q.Get("live") == "long-poll" && q.Get("since") == hidden && q.Get("cursor") == "8":
			v075JSON(w, map[string]string{"X-Namespace-Revision": newer, "X-Cursor": "9"}, []any{v075Entry(vis, hidden, "head", "pub-a")})
		default:
			http.Error(w, `{"code":"not_found"}`, 404)
		}
	})
	res, err := c.LongPoll(ctx, "m", s0, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Timeout || res.Since != hidden || res.Cursor != "8" || res.GS != gs {
		t.Fatalf("timeout %+v", res)
	}
	res, err = c.FilteredLongPoll(ctx, "m", res.GS, res.Since, res.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if res.Timeout || len(res.Entries) != 1 || res.Entries[0].ID != vis || res.Since != newer || res.Cursor != "9" {
		t.Fatalf("entries %+v", res)
	}
	if _, err := c.FilteredLongPoll(ctx, "m", "all", "", ""); err == nil {
		t.Fatal("gs all accepted")
	}

	// A redirect anywhere else stays the error it was.
	o := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ns/other/g/"+gs+"/log?"+r.URL.RawQuery, 302)
	})
	if _, err := o.LongPoll(ctx, "m", "", ""); err == nil {
		t.Fatal("followed a redirect into another namespace")
	} else if ae, ok := client.AsAPIError(err); !ok || ae.Status != 302 {
		t.Fatalf("other redirect: %v", err)
	}
}

// Filtered events (§B.11.9 Events, §7.3): NSEvents follows the 302 into
// /ns/{ns}/g/{gs}/events with the same since, which may name a hidden
// entry; FilteredNSEvents reads it directly (SVC-11).
func TestV075FilteredEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gs, hidden, a, b := v075ID("gs"), v075ID("hidden"), v075ID("a"), v075ID("b")
	var mu sync.Mutex
	var sinces []string
	c := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ns/m/events":
			http.Redirect(w, r, "/ns/m/g/"+gs+"/events?"+r.URL.RawQuery, 302)
		case "/ns/m/g/" + gs + "/events":
			mu.Lock()
			sinces = append(sinces, r.URL.Query().Get("since"))
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			for _, e := range []map[string]any{v075Entry(a, hidden, "head", "pub-a"), v075Entry(b, v075ID("h2"), "tombstone", "pub-a")} {
				d, _ := json.Marshal(e)
				fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", e["id"], e["kind"], d)
			}
		default:
			http.Error(w, `{"code":"not_found"}`, 404)
		}
	})
	for name, run := range map[string]func(fn func(client.NSEntry) error) error{
		"NSEvents":         func(fn func(client.NSEntry) error) error { return c.NSEvents(ctx, "m", hidden, fn) },
		"FilteredNSEvents": func(fn func(client.NSEntry) error) error { return c.FilteredNSEvents(ctx, "m", gs, hidden, fn) },
	} {
		var got []string
		if err := run(func(e client.NSEntry) error { got = append(got, e.ID); return nil }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, []string{a, b}) {
			t.Fatalf("%s: %v", name, got)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(sinces, []string{hidden, hidden}) {
		t.Fatalf("sinces %v", sinces)
	}
	// Resource streams follow no redirect.
	if err := c.ResourceEvents(ctx, "m", "x", "", func(client.Event) error { return nil }); err == nil {
		t.Fatal("resource events: no error")
	}
}
