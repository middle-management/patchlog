package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// prefetchHeads lets a page of a heads listing answer from memory in
// either dialect, and changes no answer: at every position of a
// namespace's log, of its branch's and of that branch's branch, and now,
// the pages list what resolve answers alone, name by name from nothing
// remembered, in byte order, across live, tombstoned and purged
// resources, a branch's own and its bases'. The page reads each base once
// (memo.ns).
func TestPrefetchHeads(t *testing.T) {
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	heads := map[string]string{} // ns/name -> head id
	set := func(ns, name, base string, i int) {
		t.Helper()
		ifMatch := heads[ns+"/"+name]
		if ifMatch == "" {
			ifMatch = heads[base+"/"+name] // a branch's first write of a base's resource
		}
		id, err := put(e, ns, name, ifMatch, i)
		if err != nil {
			t.Fatalf("%s/%s: %v", ns, name, err)
		}
		heads[ns+"/"+name] = id
	}
	del := func(ns, name, base string) {
		t.Helper()
		ifMatch := heads[ns+"/"+name]
		if ifMatch == "" {
			ifMatch = heads[base+"/"+name]
		}
		r := who
		r.NS = ns
		res, err := e.WriteResource(ctx, r, Item{Resource: name, IfMatch: ifMatch, Steps: []Step{{Delete: true}}})
		if err != nil {
			t.Fatalf("delete %s/%s: %v", ns, name, err)
		}
		heads[ns+"/"+name] = res.Items[0].IDs[0]
	}
	var names []string
	for i := 0; i < 24; i++ {
		names = append(names, fmt.Sprintf("r%02d", i))
	}
	names = append(names, "a-b", "a.b", "a0", "a_b", "z")
	for i, name := range names {
		set("n", name, "", i)
	}
	for _, name := range names[:8] {
		set("n", name, "", 100)
	}
	for _, name := range names[8:11] {
		del("n", name, "")
	}
	purge(t, e, "n", "r11")
	if _, err := e.CreateBranch(ctx, Request{NS: "n", Cred: who.Cred}, BranchRequest{Name: "b", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	set("n", "r12", "", 200)
	set("n", "r30", "", 200)
	del("n", "r13", "")
	for _, name := range names[:4] {
		set("b", name, "n", 300)
	}
	del("b", "r04", "n")
	for _, name := range []string{"s0", "s1", "s2", "a+", "r05x"} {
		set("b", name, "n", 400)
	}
	del("b", "s1", "n")
	purge(t, e, "b", "s2")
	if _, err := e.CreateBranch(ctx, Request{NS: "b", Cred: who.Cred}, BranchRequest{Name: "c", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	set("b", "r01", "n", 500)
	for _, name := range []string{"r00", "s0", "t0", "t1"} {
		set("c", name, "b", 600)
	}
	del("c", "a+", "b")
	del("c", "r20", "n") // read through both

	render := func(items []headItem) string {
		var b strings.Builder
		for _, h := range items {
			id := ""
			if h.row != nil {
				id = h.row.id.String()
			}
			fmt.Fprintf(&b, "%s %d %s\n", h.name, h.state, id)
		}
		return b.String()
	}
	for _, ns := range []string{"n", "b", "c"} {
		var at []*int64
		if err := e.read(ctx, func(t *tx) error {
			rows, err := t.Query(`SELECT seq FROM ns_log WHERE ns = ? ORDER BY seq`, t.nsByName(ns).id)
			t.must(err)
			for rows.Next() {
				var seq int64
				t.must(rows.Scan(&seq))
				at = append(at, &seq)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		for _, asOf := range append(at, nil) {
			label := fmt.Sprintf("%s as of %v", ns, asOf)
			if asOf != nil {
				label = fmt.Sprintf("%s as of %d", ns, *asOf)
			}
			var want []headItem
			if err := e.read(ctx, func(t *tx) error {
				n := t.nsByName(ns)
				for _, name := range t.namesAfter(n, "", 1<<20) {
					t.forget()
					if v := t.resolve(n, name, asOf); v.state != NotFound {
						want = append(want, headItem{name: name, state: v.state, row: v.head})
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if asOf == nil {
				states := map[State]bool{}
				for _, h := range want {
					states[h.state] = true
				}
				if !states[Live] || !states[Tombstoned] || !states[Purged] {
					t.Fatalf("%s: states %v, want live, tombstoned and purged ones", label, states)
				}
			}
			for _, limit := range []int{3, 1000} {
				var got []headItem
				if err := e.read(ctx, func(t *tx) error {
					n := t.nsByName(ns)
					for after := ""; ; {
						page, next := t.pageHeads(n, asOf, after, limit)
						got = append(got, page...)
						if next == "" {
							return nil
						}
						after = next
					}
				}); err != nil {
					t.Fatal(err)
				}
				if g, w := render(got), render(want); g != w {
					t.Fatalf("%s, pages of %d:\n%s\nwant (resolve alone):\n%s", label, limit, g, w)
				}
				for i := 1; i < len(got); i++ {
					if got[i-1].name >= got[i].name {
						t.Fatalf("%s: %q before %q, not in byte order", label, got[i-1].name, got[i].name)
					}
				}
			}
			// The page's resource rows, heads and head revisions are in
			// memory before resolve looks.
			if err := e.read(ctx, func(t *tx) error {
				n := t.nsByName(ns)
				t.prefetchHeads(n, t.namesAfter(n, "", 1<<20), asOf)
				for _, name := range t.namesAfter(n, "", 1<<20) {
					r, ok := t.memo.res[resKey{n.id, name}]
					if !ok {
						return fmt.Errorf("%s: %s/%s not prefetched", label, ns, name)
					}
					if r != nil && asOf != nil && r.state != statePurged {
						if _, ok := t.memo.headAt[headAtKey{r.id, *asOf}]; !ok {
							return fmt.Errorf("%s: head of %s/%s not prefetched", label, ns, name)
						}
					}
				}
				for _, h := range want {
					if h.row == nil {
						continue
					}
					if _, ok := t.memo.rev[h.row.seq]; !ok {
						return fmt.Errorf("%s: head revision of %s not prefetched", label, h.name)
					}
				}
				for m := n; m.isBranch(); m = t.nsByID(m.base.Int64) {
					if _, ok := t.memo.ns[m.base.Int64]; !ok {
						return fmt.Errorf("%s: base %d of %s not remembered", label, m.base.Int64, m.name)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A read transaction reads a namespace row once and hands out copies
// (memo.ns); a write transaction reads it each time, as its own writes,
// and on Postgres other writers', change it under it.
func TestNamespaceMemo(t *testing.T) {
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	var id int64
	if err := e.read(ctx, func(t *tx) error {
		id = t.nsByName("n").id
		t.nsByID(id).frozen = true
		if _, ok := t.memo.ns[id]; !ok {
			return fmt.Errorf("namespace %d not remembered", id)
		}
		if t.nsByID(id).frozen {
			return fmt.Errorf("a caller's change to its copy reached the memo")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback")
	if err := e.update(ctx, func(t *tx) error {
		if t.nsByID(id).frozen || len(t.memo.ns) > 0 {
			return fmt.Errorf("frozen, or remembered in a write transaction")
		}
		_, err := t.Exec(`UPDATE namespaces SET frozen = ? WHERE ns = ?`, true, id)
		t.must(err)
		if !t.nsByID(id).frozen {
			return fmt.Errorf("the transaction's own freeze unseen")
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
}
