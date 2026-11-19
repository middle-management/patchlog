package server

import (
	"net/url"
	"reflect"
	"testing"
	"time"
)

// v086BranchKeys pages GET /ns/{ns}/branches from after to the end and
// returns the keys of its rows page by page: a local branch's name, a
// remote one's {origin}/{ns} (§7.4).
func v086BranchKeys(t *testing.T, e *tenv, ns, after string, limit int) [][]string {
	t.Helper()
	var pages [][]string
	for n := 0; ; n++ {
		if n > 100 {
			t.Fatal("the listing doesn't end")
		}
		path := "/ns/" + ns + "/branches"
		if after != "" {
			path += "?after=" + url.QueryEscape(after)
		}
		r := e.get(path)
		expect(t, r, 200)
		if _, ok := r.JSON().(map[string]any); !ok {
			t.Fatalf("%s: %s, want an object (§7.4)", path, r.Body)
		}
		rows, ok := r.Obj()["branches"].([]any)
		if !ok {
			t.Fatalf("%s: no branches array: %s", path, r.Body)
		}
		page := []string{}
		for _, x := range rows {
			m := x.(map[string]any)
			key, _ := m["name"].(string)
			if rm, ok := m["remote"].(map[string]any); ok {
				key = rm["origin"].(string) + "/" + rm["ns"].(string)
				if len(m) != 4 || m["at"] == nil || m["ns_id"] == nil || m["expires"] == nil {
					t.Fatalf("remote row %v", m)
				}
			} else if m["at"] == nil || m["frozen"] == nil || m["purged"] == nil {
				t.Fatalf("local row %v", m)
			}
			page = append(page, key)
		}
		if len(page) > limit {
			t.Fatalf("%s: %d rows, over logPageSize %d", path, len(page), limit)
		}
		pages = append(pages, page)
		next, has := r.Obj()["next"]
		if !has {
			return pages
		}
		// next is for the following page: the last row's key here.
		if len(page) == 0 || next != page[len(page)-1] {
			t.Fatalf("%s: next %v after rows %v", path, next, page)
		}
		after = next.(string)
	}
}

// HTTP-31, HTTP-19 (§7.4 GET /ns/{ns}/branches?after={key}; v0.86):
// { "branches": [ … ], "next"? }, local and remote rows together in
// ascending byte order of key (a local branch's name, a remote one's
// {origin}/{ns}), strictly after after, a plain bound, paged by
// logPageSize, next absent on the last page.
func TestV086BranchesPaged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withOrigin(originA), withLogPageSize(3))
	e.mkNS("main", map[string]any{"read": "public"})
	at := e.nsHead("main")
	// Byte order: "-" < digits < "_" < letters, which no linguistic
	// collation gives ("a-b" < "a0" < "a_b" < "ab").
	for _, name := range []string{"ab", "a_b", "a0", "a-b", "zz", "b"} {
		expect(t, e.branch("main", map[string]any{"name": name}, "alice"), 201)
	}
	// Remote rows by {origin}/{ns}, not by (origin, ns): "." < "/", so
	// "https://r.example.org/x" is before "https://r.example/x".
	for _, rm := range [][2]string{{"https://r.example", "x"}, {"https://r.example.org", "x"}, {"https://r.example", "a"}} {
		expect(t, e.do(req{method: "POST", path: "/ns/main/branches", ifNoneMatch: "*", author: "b",
			body: map[string]any{"remote": map[string]any{"origin": rm[0], "ns": rm[1]}, "at": at}}), 201)
	}
	// Nine rows, three a page: the last page is full and carries no next.
	want := [][]string{
		{"a-b", "a0", "a_b"},
		{"ab", "b", "https://r.example.org/x"},
		{"https://r.example/a", "https://r.example/x", "zz"},
	}
	if got := v086BranchKeys(t, e, "main", "", 3); !reflect.DeepEqual(got, want) {
		t.Fatalf("pages %v, want %v", got, want)
	}
	// after is a plain bound: a key that is no row's, a remote key, one
	// past every row, and strings no key can be (bytes above "~", a NUL).
	for after, want := range map[string][][]string{
		"a1":                     {{"a_b", "ab", "b"}, {"https://r.example.org/x", "https://r.example/a", "https://r.example/x"}, {"zz"}},
		"https://r.example.org/": {{"https://r.example.org/x", "https://r.example/a", "https://r.example/x"}, {"zz"}},
		"https://r.example/a":    {{"https://r.example/x", "zz"}},
		"https://r.example/x":    {{"zz"}},
		"zz":                     {{}},
		"zzz":                    {{}},
		"bé":                     {{"https://r.example.org/x", "https://r.example/a", "https://r.example/x"}, {"zz"}},
		"a_\x00z":                {{"a_b", "ab", "b"}, {"https://r.example.org/x", "https://r.example/a", "https://r.example/x"}, {"zz"}},
	} {
		if got := v086BranchKeys(t, e, "main", after, 3); !reflect.DeepEqual(got, want) {
			t.Errorf("after %q: pages %v, want %v", after, got, want)
		}
	}
	// A purged branch stays listed, and an expired registration doesn't.
	expect(t, e.patchNS("b", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/b/purge", ifMatch: e.nsHead("b"), author: "admin"}), 204)
	e.clock.Advance(31 * 24 * time.Hour)
	want = [][]string{{"a-b", "a0", "a_b"}, {"ab", "b", "zz"}}
	if got := v086BranchKeys(t, e, "main", "", 3); !reflect.DeepEqual(got, want) {
		t.Fatalf("after the registrations expired: pages %v, want %v", got, want)
	}
	// A parameter the route doesn't define is 400 as on every route.
	expect(t, e.get("/ns/main/branches?prefix=a"), 400)
}
