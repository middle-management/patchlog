package server

import (
	"net/url"
	"reflect"
	"testing"
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
			if m["remote"] != nil || m["at"] == nil || m["frozen"] == nil || m["purged"] == nil {
				t.Fatalf("row %v", m)
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

// HTTP-31, HTTP-19 (§7.4 GET /ns/{ns}/branches?after={key}; v0.86, v0.87):
// { "branches": [ … ], "next"? }, the local branches in ascending byte
// order of name, strictly after after, a plain bound, paged by
// logPageSize, next absent on the last page. v0.87 removed remote
// branches: a registration body is 400 as any unknown member.
func TestV086BranchesPaged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLogPageSize(3))
	e.mkNS("main", map[string]any{"read": "public"})
	at := e.nsHead("main")
	// Byte order: "-" < digits < "_" < letters, which no linguistic
	// collation gives ("a-b" < "a0" < "a_b" < "ab").
	for _, name := range []string{"ab", "a_b", "a0", "a-b", "zz", "b"} {
		expect(t, e.branch("main", map[string]any{"name": name}, "alice"), 201)
	}
	expect(t, e.do(req{method: "POST", path: "/ns/main/branches", ifNoneMatch: "*", author: "b",
		body: map[string]any{"remote": map[string]any{"origin": "https://r.example", "ns": "x"}, "at": at}}), 400)
	// Six rows, three a page: the last page is full and carries no next.
	want := [][]string{{"a-b", "a0", "a_b"}, {"ab", "b", "zz"}}
	if got := v086BranchKeys(t, e, "main", "", 3); !reflect.DeepEqual(got, want) {
		t.Fatalf("pages %v, want %v", got, want)
	}
	// after is a plain bound: a key that is no row's, a row's, one past
	// every row, and strings no name can be (bytes above "~", a NUL).
	for after, want := range map[string][][]string{
		"a1":      {{"a_b", "ab", "b"}, {"zz"}},
		"a-b":     {{"a0", "a_b", "ab"}, {"b", "zz"}},
		"zz":      {{}},
		"zzz":     {{}},
		"bé":      {{"zz"}},
		"a_\x00z": {{"a_b", "ab", "b"}, {"zz"}},
	} {
		if got := v086BranchKeys(t, e, "main", after, 3); !reflect.DeepEqual(got, want) {
			t.Errorf("after %q: pages %v, want %v", after, got, want)
		}
	}
	// A purged branch stays listed.
	expect(t, e.patchNS("b", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/b/purge", ifMatch: e.nsHead("b"), author: "admin"}), 204)
	if got := v086BranchKeys(t, e, "main", "", 3); !reflect.DeepEqual(got, want) {
		t.Fatalf("after the purge: pages %v, want %v", got, want)
	}
	// A parameter the route doesn't define is 400 as on every route.
	expect(t, e.get("/ns/main/branches?prefix=a"), 400)
}
