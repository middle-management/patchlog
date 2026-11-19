package server

import (
	"fmt"
	"reflect"
	"testing"
)

// v086More reports whether a refusal's body carries "more": true, and
// fails on any other value of the member (§12.1).
func v086More(t *testing.T, r *resp) bool {
	t.Helper()
	v, has := r.Obj()["more"]
	if has && v != true {
		t.Fatalf("more is %v: present only as true (§12.1): %s", v, r.Body)
	}
	return has
}

// SCH-6, Limits scenario 94 (§6.1 Refusals; v0.86): an in_use refusal's
// referencing holds the first logPageSize namespaces, in byte order of
// name, among those the caller may read anything in, with "more": true
// where the caller may read others. A caller who may read none of them
// gets [] without more: more never tells of namespaces it can't read.
func TestV086ReferencingCapped(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, withLogPageSize(3))
	k := newKey("k")
	e.mkNS("schemas", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	all := []string{"schemas"}
	// Seven referencing namespaces: byte order puts "d-1" before "d0"
	// before "d_2" before "da".
	refs := []string{"d-1", "d0", "d1", "d2", "d_2", "da", "db"}
	for _, ns := range refs {
		e.mkNS(ns, map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
		all = append(all, ns)
	}
	root := e.grant(k, "user:root", all, allVerbs)
	r := e.write("PATCH", "schemas", "team", "", addRoot(teamSchema()), root)
	expect(t, r, 201)
	t1 := etagOf(r)
	for _, ns := range refs {
		expect(t, e.typed(ns, "m", "/r/schemas/team/rev/"+t1, root), 201)
	}
	for _, c := range []struct {
		reads []string
		want  []string
		more  bool
	}{
		// May read them all: the first page by name, and more.
		{refs, []string{"d-1", "d0", "d1"}, true},
		// Five of the seven: the first three of those it reads.
		{[]string{"d0", "d2", "d_2", "da", "db"}, []string{"d0", "d2", "d_2"}, true},
		// One past the page, which only more tells of.
		{[]string{"d-1", "d1", "d_2", "db"}, []string{"d-1", "d1", "d_2"}, true},
		// Exactly a page: no more.
		{[]string{"d1", "d_2", "db"}, []string{"d1", "d_2", "db"}, false},
		{[]string{"da"}, []string{"da"}, false},
		// None: [] without more.
		{nil, nil, false},
	} {
		g := e.grant(k, "user:p", append([]string{"schemas"}, c.reads...), allVerbs)
		r := e.purge("schemas", "team", t1, g)
		expectCode(t, r, 409, "in_use")
		if _, ok := r.Obj()["referencing"].([]any); !ok {
			t.Fatalf("reads %v: no referencing array: %s", c.reads, r.Body)
		}
		if got := referencing(r); !reflect.DeepEqual(got, c.want) || v086More(t, r) != c.more {
			t.Errorf("reads %v: %s, want referencing %v, more %v", c.reads, r.Body, c.want, c.more)
		}
	}
	// A namespace purge that would remove the copy is capped alike.
	expect(t, e.patchNS("schemas", ops(op("add", "/frozen", true)), root), 201)
	r = e.do(req{method: "POST", path: "/ns/schemas/purge", ifMatch: e.nsHead("schemas", root), bearer: root})
	expectCode(t, r, 409, "in_use")
	if got := referencing(r); !reflect.DeepEqual(got, []string{"d-1", "d0", "d1"}) || !v086More(t, r) {
		t.Errorf("namespace purge: %s", r.Body)
	}
}

// Limits scenario 94, the purge-ns list item 5 (§8.5 item 4; v0.86): a
// namespace purge held up by dependents lists the first logPageSize by
// name, in byte order, with "more": true if there are others. Purged
// branches aren't dependents.
func TestV086DependentsCapped(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLogPageSize(3))
	e.mkNS("main", map[string]any{})
	for _, name := range []string{"ab", "a_b", "a0", "a-b", "zz"} {
		expect(t, e.branch("main", map[string]any{"name": name}, "admin"), 201)
	}
	expect(t, e.patchNS("main", ops(op("add", "/frozen", true)), ""), 201)
	purgeNS := func(ns string) *resp {
		return e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns), author: "admin"})
	}
	deps := func(r *resp) string { return fmt.Sprint(r.Obj()["dependents"]) }
	r := purgeNS("main")
	expectCode(t, r, 409, "in_use")
	if deps(r) != "[a-b a0 a_b]" || !v086More(t, r) {
		t.Fatalf("five dependents: %s", r.Body)
	}
	// One purged, and it is the first by name: the page starts after it.
	expect(t, e.patchNS("a-b", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, purgeNS("a-b"), 204)
	r = purgeNS("main")
	expectCode(t, r, 409, "in_use")
	if deps(r) != "[a0 a_b ab]" || !v086More(t, r) {
		t.Fatalf("four dependents: %s", r.Body)
	}
	// Exactly a page: no more.
	expect(t, e.patchNS("zz", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, purgeNS("zz"), 204)
	r = purgeNS("main")
	expectCode(t, r, 409, "in_use")
	if deps(r) != "[a0 a_b ab]" || v086More(t, r) {
		t.Fatalf("three dependents: %s", r.Body)
	}
}
