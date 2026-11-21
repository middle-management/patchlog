package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/middle-management/patchlog/internal/core"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// v0.87: reads judged per revision (§C.2 item 5, §6.4.1 doc), §6.2 step
// 2.2, content under a view's prefix (§7.9 Content), and every read route
// as a partial reader meets it.

// v87TeamA is a rule testing the read envelope's doc.
var v87TeamA = map[string]any{"op": "test", "path": "/doc/team", "value": "a"}

// v87Doc writes ns/name as admin, returning the new head.
func (w *v75s) v87Doc(ns, name string, doc map[string]any) string {
	w.t.Helper()
	return w.put(ns, name, doc)
}

// v87Follow follows a 302 with the same grant.
func (w *v75s) v87Follow(r *resp, bearer string) *resp {
	w.t.Helper()
	expect(w.t, r, 302)
	return w.get(r.H.Get("Location"), bearer)
}

// RUL-8 / AUTH-31: doc in read envelopes. A grant whose block rule tests
// /doc/team reads, at a resource's URLs, only the revisions whose
// documents pass: the head for /r/{ns}/{name}, that revision for
// /rev/{id} (under its view, a partial reader's), a tombstone's deleted
// document, a blob's referencing documents; pruned and never judged,
// null.
func TestV087DocEnvelopes(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	g := w.grant(w.k, "user:t", []string{"matches", "matches-r7"}, []string{"read", "prune"}, map[string]any{"rules": []any{v87TeamA}})
	adminP := w.grant(w.k, "user:root", []string{"matches", "matches-r7"}, []string{"read", "create", "append", "delete", "restore", "prune", "branch"})

	a1 := w.v87Doc("matches", "x", map[string]any{"team": "a"})
	b2 := w.v87Doc("matches", "x", map[string]any{"team": "b"})
	// The head says b: a read-rule failure, 404.
	expect(t, w.get("/r/matches/x", g), 404)
	// /rev/{id}: under the view, that revision's document decides.
	if r := w.v87Follow(w.get("/r/matches/x/rev/"+a1, g), g); r.Code != 200 || !strings.Contains(string(r.Body), `"a"`) {
		t.Fatalf("x at a1 under the view: %d %s", r.Code, r.Body)
	}
	expect(t, w.v87Follow(w.get("/r/matches/x/rev/"+b2, g), g), 404)

	// A tombstone's read envelope carries the document it deleted.
	w.v87Doc("matches", "y", map[string]any{"team": "a"})
	w.v87Doc("matches", "z", map[string]any{"team": "b"})
	for _, n := range []string{"y", "z"} {
		h := etagOf(w.get("/r/matches/"+n, w.admin))
		expect(t, w.do(req{method: "DELETE", path: "/r/matches/" + n, ifMatch: h, bearer: w.admin}), 200)
	}
	expect(t, w.get("/r/matches/y", g), 410)
	expect(t, w.get("/r/matches/z", g), 404)

	// Pruned: an answer kept from before stands; one never judged is null.
	p1 := w.v87Doc("matches", "p", map[string]any{"team": "a"})
	p2 := w.v87Doc("matches", "p", map[string]any{"team": "a", "v": 2.0})
	q1 := w.v87Doc("matches", "q", map[string]any{"team": "a"})
	q2 := w.v87Doc("matches", "q", map[string]any{"team": "a", "v": 2.0})
	expect(t, w.v87Follow(w.get("/r/matches/p/rev/"+p1, g), g), 200)
	w.clock.Advance(10 * time.Minute)
	expect(t, w.prune("matches", "p", map[string]any{"horizon": p2}, adminP), 200)
	expect(t, w.prune("matches", "q", map[string]any{"horizon": q2}, adminP), 200)
	if r := w.v87Follow(w.get("/r/matches/p/rev/"+p1, g), g); r.Code != 410 || !strings.Contains(string(r.Body), "pruned") {
		t.Fatalf("a judged revision once pruned: %d %s, want 410 pruned", r.Code, r.Body)
	}
	expect(t, w.v87Follow(w.get("/r/matches/q/rev/"+q1, g), g), 404)

	// A blob: readable where a stored document referencing it passes,
	// else as the head.
	data := []byte("hello")
	bid := w.upload("matches", "f", "text/plain", data, w.admin)
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	w.v87Doc("matches", "f", map[string]any{"team": "a", "file": ref})
	w.v87Doc("matches", "f", map[string]any{"team": "b", "file": ref})
	if r := w.v87Follow(w.get("/r/matches/f/blob/"+bid, g), g); r.Code != 200 || string(r.Body) != "hello" {
		t.Fatalf("a blob a visible revision references: %d %s", r.Code, r.Body)
	}
	bid2 := w.upload("matches", "h", "text/plain", []byte("other"), w.admin)
	ref2 := map[string]any{"$blob": bid2, "type": "text/plain", "size": 5.0}
	w.v87Doc("matches", "h", map[string]any{"team": "b", "file": ref2})
	w.v87Doc("matches", "h", map[string]any{"team": "a"})
	expect(t, w.v87Follow(w.get("/r/matches/h/blob/"+bid2, g), g), 404)
	// Blob-From: a copy from h takes nothing only hidden revisions
	// reference.
	if r := w.copyBlob("matches", "x", bid2, "/r/matches/h/blob/"+bid2, "", g); r.Code != 404 && r.Code != 403 {
		t.Fatalf("a copy of a blob only hidden revisions reference: %d %s", r.Code, r.Body)
	}

	// In a branch, which §7.9 doesn't cover: no 302, per revision at the
	// unfiltered URL, and a log only where every entry, and each one's
	// parent, passes.
	expect(t, w.branch("matches", map[string]any{"name": "matches-r7"}, adminP), 201)
	expect(t, w.get("/r/matches-r7/x/rev/"+a1, g), 200)
	expect(t, w.get("/r/matches-r7/x/rev/"+b2, g), 404)
	expect(t, w.get("/r/matches-r7/x/rev/"+a1+"/log", g), 200)
	expect(t, w.get("/r/matches-r7/x/rev/"+b2+"/log", g), 404)

	// A head whose document passes is read at its own URL, in a base and
	// for a branch's own draft; one that doesn't is 404.
	w.v87Doc("matches", "ok", map[string]any{"team": "a"})
	expect(t, w.get("/r/matches/ok", g), 302)
	w.v87Doc("matches-r7", "draft-a", map[string]any{"team": "a"})
	w.v87Doc("matches-r7", "draft-b", map[string]any{"team": "b"})
	expect(t, w.get("/r/matches-r7/draft-a", g), 302)
	expect(t, w.get("/r/matches-r7/draft-b", g), 404)
	h := etagOf(w.get("/r/matches-r7/draft-a", g))
	expect(t, w.get("/r/matches-r7/draft-a/rev/"+h, g), 200)
}

// §6.2 step 2.2 (GATE-3, AUTH-31): a write to a resource with a head,
// a DELETE or create included, by a grant that may read but whose read
// rules don't allow reading that head is 403 before the precondition; a
// grant without read isn't judged so. It counts as an authorisation
// failure in a batch's report and dry run.
func TestV087StepTwoTwo(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	writer := w.grant(w.k, "user:w", []string{"matches"}, []string{"read", "create", "append", "delete", "restore"}, map[string]any{"rules": []any{v87TeamA}})
	blind := w.grant(w.k, "user:b", []string{"matches"}, []string{"create", "append", "delete", "restore"}, map[string]any{"rules": []any{v87TeamA}})
	w.v87Doc("matches", "ra", map[string]any{"team": "a"})
	w.v87Doc("matches", "rb", map[string]any{"team": "b"})
	stale := "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	patch := []any{map[string]any{"op": "replace", "path": "/team", "value": "a"}}
	// The head it can read: the precondition answers.
	expect(t, w.do(req{method: "PATCH", path: "/r/matches/ra", ifMatch: stale, body: patch, bearer: writer}), 412)
	// The head it can't: 403 first, whatever the precondition.
	for _, q := range []req{
		{method: "PATCH", path: "/r/matches/rb", ifMatch: stale, body: patch, bearer: writer},
		{method: "PATCH", path: "/r/matches/rb", ifNoneMatch: "*", body: addRoot(map[string]any{"team": "a"}), bearer: writer},
		{method: "DELETE", path: "/r/matches/rb", ifMatch: stale, bearer: writer},
	} {
		expectCode(t, w.do(q), 403, "forbidden")
	}
	// A grant without read learns from the precondition (§6.4.1).
	expect(t, w.do(req{method: "PATCH", path: "/r/matches/rb", ifMatch: stale, body: patch, bearer: blind}), 412)
	// A batch: the item fails authorisation, in a dry run too.
	body := map[string]any{"items": []any{map[string]any{"resource": "rb", "ifMatch": stale, "steps": []any{patch}}}}
	for _, path := range []string{"/ns/matches/batch", "/ns/matches/batch?dry-run=1"} {
		r := w.do(req{method: "POST", path: path, body: body, bearer: writer})
		if r.Code != 403 && !strings.Contains(string(r.Body), `"status":403`) {
			t.Fatalf("%s: %d %s, want the item's 403", path, r.Code, r.Body)
		}
	}
}

// v87Routes are the GET routes the server registers (server.go), read
// from its source so that a route added without a row here fails.
func v87Routes(t *testing.T) []string {
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range regexp.MustCompile(`HandleFunc\("GET ([^"]+)"`).FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	if len(out) < 20 {
		t.Fatalf("only %d GET routes found", len(out))
	}
	return append(out, core.DefaultJWKSPath)
}

// §7.9 (HTTP-70, HTTP-73, HTTP-76): every read route, to a partial reader
// with its grant in Authorization, is filtered, a 302 to its filtered
// form, or refused (403, or 404 at a resource's URLs); and no answer
// carries a hidden document or the name of a resource it can't read. In
// a branch, which §7.9 doesn't cover, its filtered URLs are 403, and
// nothing is redirected.
func TestV087RouteTable(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	adminP := w.grant(w.k, "user:root", []string{"matches", "matches-r7"}, []string{"read", "create", "append", "delete", "restore", "branch"})
	// The reader: names a–m, documents of team a.
	reader := w.grant(w.k, "user:r", []string{"matches", "matches-r7"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"all": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^[a-m]"}}, v87TeamA}}}})
	data := []byte("blob")
	bid := w.upload("matches", "doc", "text/plain", data, w.admin)
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	visible := w.v87Doc("matches", "doc", map[string]any{"team": "a", "file": ref})
	w.v87Doc("matches", "hid", map[string]any{"team": "b", "mark": "HIDDEN-DOC"})
	w.v87Doc("matches", "zzz-name", map[string]any{"team": "a", "mark": "HIDDEN-NAME"})
	nsHead := etagOf(w.get("/ns/matches", w.admin))
	expect(t, w.branch("matches", map[string]any{"name": "matches-r7"}, adminP), 201)
	gid := ""
	for _, e := range w.nsLog("matches", w.admin) {
		if g, ok := e["grant"].(map[string]any); ok {
			gid, _ = g["id"].(string)
		}
	}
	// The reader's view.
	r := w.get("/ns/matches/rev/"+nsHead+"/heads", reader)
	expect(t, r, 302)
	view := strings.Split(r.H.Get("Location"), "/")[4]

	type want struct {
		codes []int  // any of them
		loc   string // a 302's Location prefix
	}
	filtered := want{codes: []int{200}}
	redirect := want{codes: []int{302}, loc: "/ns/matches/view/" + view + "/"}
	refused := want{codes: []int{403, 404}}
	sub := func(p string) string {
		return strings.NewReplacer("{ns}", "matches", "{name}", "doc", "{id}", visible, "{bid}", bid, "{e}", "1", "{view}", view,
			"{at}", nsHead, "{gesture}", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "{gid}", gid, "{$}", "").Replace(p)
	}
	table := map[string]want{
		"/{$}":                                       filtered, // the root
		"/r/{ns}/{name}":                             {codes: []int{302}, loc: "/r/matches/doc/rev/"},
		"/r/{ns}/{name}/rev/{id}":                    redirect,
		"/r/{ns}/{name}/rev/{id}/log":                filtered,
		"/r/{ns}/{name}/raw":                         {codes: []int{404}},
		"/r/{ns}/{name}/rev/{id}/raw":                redirect,
		"/r/{ns}/{name}/log":                         filtered,
		"/r/{ns}/{name}/events":                      filtered,
		"/r/{ns}/{name}/blob/{bid}":                  redirect,
		"/r/{ns}/{name}/blob/{bid}/e/{e}":            {codes: []int{404}},
		"/ns":                                        refused,
		"/ns/{ns}":                                   {codes: []int{302}, loc: "/ns/matches/rev/"},
		"/ns/{ns}/rev/{id}":                          refused,
		"/ns/{ns}/rev/{id}/log":                      redirect,
		"/ns/{ns}/rev/{id}/heads":                    redirect,
		"/ns/{ns}/log":                               redirect,
		"/ns/{ns}/events":                            redirect,
		"/ns/{ns}/view/{view}/at/{at}/heads":         filtered,
		"/ns/{ns}/view/{view}/at/{at}/log":           filtered,
		"/ns/{ns}/view/{view}/heads":                 redirect,
		"/ns/{ns}/view/{view}/log":                   redirect,
		"/ns/{ns}/view/{view}/events":                filtered,
		"/ns/{ns}/view/{view}/r/{name}/rev/{id}":     filtered,
		"/ns/{ns}/view/{view}/r/{name}/rev/{id}/raw": {codes: []int{404}},
		"/ns/{ns}/view/{view}/r/{name}/blob/{bid}":   filtered,
		"/ns/{ns}/gestures/{gesture}":                filtered,
		"/ns/{ns}/principal":                         filtered,
		"/ns/{ns}/grants/{gid}":                      refused,
		"/ns/{ns}/branches":                          refused,
		core.DefaultJWKSPath:                         filtered,
	}
	for _, route := range v87Routes(t) {
		wt, ok := table[route]
		if !ok {
			t.Errorf("route %s has no row: classify it", route)
			continue
		}
		path := sub(route)
		if strings.HasSuffix(route, "/{ns}/{name}/log") || strings.HasSuffix(route, "{view}/log") {
			if !strings.Contains(route, "{view}") {
				path += "?live=long-poll"
			}
		}
		if strings.HasSuffix(route, "/events") {
			path += "?since=" + nsHead
			if strings.HasPrefix(route, "/r/") {
				path = sub(route) + "?since=" + visible
			}
		}
		if strings.HasPrefix(route, "/ns/{ns}/log") {
			path = sub(route) + "?live=long-poll"
		}
		r := w.v87Get(path, reader)
		if !slices.Contains(wt.codes, r.Code) {
			t.Errorf("%s (%s): %d %s, want %v", route, path, r.Code, r.Body, wt.codes)
			continue
		}
		if wt.loc != "" && !strings.HasPrefix(r.H.Get("Location"), wt.loc) {
			t.Errorf("%s: Location %q, want under %q", route, r.H.Get("Location"), wt.loc)
		}
		for _, leak := range []string{"HIDDEN-DOC", "HIDDEN-NAME", "zzz-name", `"hid"`} {
			if strings.Contains(string(r.Body), leak) || strings.Contains(r.H.Get("Location"), leak) {
				t.Errorf("%s: leaks %s: %s", route, leak, r.Body)
			}
		}
	}
	// A hidden revision under the view: a read-rule failure.
	hid := etagOf(w.get("/r/matches/hid", w.admin))
	expect(t, w.get("/ns/matches/view/"+view+"/r/hid/rev/"+hid, reader), 404)
	// In a branch §7.9 doesn't cover: the filtered URLs are 403, the
	// unfiltered ones judged per revision, never redirected.
	for _, p := range []string{"/ns/matches-r7/view/" + view + "/heads", "/ns/matches-r7/view/" + view + "/r/doc/rev/" + visible} {
		expect(t, w.get(p, reader), 403)
	}
	expect(t, w.get("/r/matches-r7/doc/rev/"+visible, reader), 200)
	expect(t, w.get("/r/matches-r7/hid/rev/"+hid, reader), 404)
	// A grant reads only at its own view.
	other := "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	expect(t, w.get("/ns/matches/view/"+other+"/r/doc/rev/"+visible, reader), 403)
}

// v87Get is a GET that doesn't wait on a stream: an event stream's first
// bytes are enough.
func (w *v75s) v87Get(path, bearer string) *resp {
	w.t.Helper()
	if strings.Contains(path, "/events") {
		return w.sseFirst(path, bearer)
	}
	return w.get(path, bearer)
}

var _ = json.Marshal

// sseFirst opens an event stream and returns what it sends within a
// moment, as a resp: its status, headers and the events' data.
func (w *v75s) sseFirst(path, bearer string) *resp {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	hr, _ := http.NewRequestWithContext(ctx, "GET", w.srv.URL+path, nil)
	hr.Header.Set("Authorization", "Bearer "+bearer)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Do(hr)
	if err != nil {
		w.t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body) // until the deadline ends the stream
	return &resp{Code: r.StatusCode, H: r.Header, Body: body}
}

// §7.9 Content: under a view whose rules refer only to /resource, a
// revision or blob of a name the rules refuse is a read-rule failure, by
// grant and by cookie alike.
func TestV087ViewContentByName(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed(nil, nil, []string{"derby"})
	data := []byte("s")
	bid := w.upload("matches", "secret", "text/plain", data, w.admin)
	sec := w.v87Doc("matches", "secret", map[string]any{"file": map[string]any{"$blob": bid, "type": "text/plain", "size": 1.0}, "mark": "HIDDEN"})
	der := etagOf(w.get("/r/matches/derby", w.admin))
	li := w.li()
	c, view := w.cookie(li)
	ck := cookieHdr(c)
	base := "/ns/matches/view/" + view
	for _, p := range []string{base + "/r/secret/rev/" + sec, base + "/r/secret/rev/" + sec + "/raw", base + "/r/secret/blob/" + bid} {
		for who, q := range map[string]req{"grant": {method: "GET", path: p, bearer: li}, "cookie": {method: "GET", path: p, hdr: ck}} {
			if r := w.do(q); r.Code != 404 || strings.Contains(string(r.Body), "HIDDEN") {
				t.Errorf("%s by %s: %d %s, want 404", p, who, r.Code, r.Body)
			}
		}
	}
	for who, q := range map[string]req{"grant": {method: "GET", path: base + "/r/derby/rev/" + der, bearer: li}, "cookie": {method: "GET", path: base + "/r/derby/rev/" + der, hdr: ck}} {
		expect(t, w.do(q), 200)
		_ = who
	}
}
