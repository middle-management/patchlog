package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// A namespace log entry's prev is resolved from the page's own rows, with
// a lookup for the first entry's only (core.namespaceLog): every page of
// every size, from every since and up to every id, as a range, a long-poll
// answer, an event catch-up and over HTTP, is a slice of the whole chain,
// in which each entry's prev is the entry before it. In plain and sealed
// namespaces and their branches, across a batch, a config change, a
// tombstone, a purge and a prune.
func TestNSLogPagePrev(t *testing.T) {
	e := newSealedEnv(t, withLogPageSize(3))
	ctx := context.Background()
	fill := func(ns string, sealed bool) {
		doc := map[string]any{"read": "public"}
		w := func(p []any) []any { return p }
		if sealed {
			doc, w = sealedDoc(doc), withNonce
		}
		e.mkNS(ns, doc)
		a := e.wr(ns, "a", "", w(addRoot(map[string]any{"v": 0.0})))
		for i := 1; i < 3; i++ {
			a = e.wr(ns, "a", a, w(ops(op("replace", "/v", float64(i)))))
		}
		b := e.wr(ns, "b", "", w(addRoot(map[string]any{})))
		expect(t, e.batchReq(ns, map[string]any{"items": []any{
			map[string]any{"resource": "a", "ifMatch": a, "steps": []any{w(ops(op("replace", "/v", 3.0)))}},
			map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{w(addRoot(map[string]any{}))}},
		}}, "admin"), 201)
		expect(t, e.patchNS(ns, ops(op("add", "/x-title", "T")), ""), 201)
		e.del(ns, "d", e.wr(ns, "d", "", w(addRoot(map[string]any{}))))
		expect(t, e.purge(ns, "b", b, "admin"), 204)
		a = e.head(ns, "a")
		e.clock.Advance(10 * time.Minute)
		expect(t, e.prune(ns, "a", map[string]any{"horizon": a}, "admin"), 200)
		a = e.wr(ns, "a", a, w(ops(op("replace", "/v", 4.0))))
		expect(t, e.branch(ns, map[string]any{"name": ns + "-br"}, "admin"), 201)
		e.wr(ns+"-br", "a", a, w(ops(op("replace", "/v", 5.0))))
		x := e.wr(ns+"-br", "e", "", w(addRoot(map[string]any{"v": 0.0})))
		for i := 1; i < 5; i++ {
			x = e.wr(ns+"-br", "e", x, w(ops(op("replace", "/v", float64(i)))))
		}
		e.wr(ns, "c", e.head(ns, "c"), w(ops(op("add", "/x", true))))
	}
	same := func(what string, got, want []map[string]any) {
		t.Helper()
		if g, w := canonical(anyOf(got)), canonical(anyOf(want)); string(g) != string(w) {
			t.Fatalf("%s:\n got %s\nwant %s", what, g, w)
		}
	}
	check := func(ns string, sealed bool) {
		head := e.nsHead(ns)
		all := e.plainNSLog(ns, head).Entries
		if len(all) < 7 {
			t.Fatalf("%s: %d entries", ns, len(all))
		}
		for i, m := range all {
			if prev, _ := m["prev"].(string); i == 0 && prev != "" || i > 0 && prev != all[i-1]["id"] {
				t.Fatalf("%s: entry %d's prev %q", ns, i, prev)
			}
		}
		var key []byte
		var kid string
		if sealed {
			keys, r := e.keysOf(ns, nil, "")
			expect(t, r, 200)
			kid = ns + "#1"
			key = keys[kid]
		}
		since := func(k int) string {
			if k == 0 {
				return ""
			}
			return all[k-1]["id"].(string)
		}
		for k := 0; k < len(all); k++ {
			for end := k + 1; end <= len(all); end++ {
				for _, lim := range []int{1, 2, 3, 0} {
					n := end - k
					if lim > 0 && lim < n {
						n = lim
					}
					lg, err := e.e.NamespaceLog(ctx, ns, all[end-1]["id"].(string), since(k), lim, core.Credentials{})
					if err != nil {
						t.Fatal(err)
					}
					same(fmt.Sprintf("%s (%d, %d] limit %d", ns, k, end, lim), lg.Entries, all[k:k+n])
					if lg.More != (k+n < end) || sealed != (lg.Range != "") {
						t.Fatalf("%s (%d, %d] limit %d: more %v, range %q", ns, k, end, lim, lg.More, lg.Range)
					}
				}
			}
			n := min(2, len(all)-k)
			lp, err := e.e.NamespaceLog(ctx, ns, "", since(k), 2, core.Credentials{})
			if err != nil {
				t.Fatal(err)
			}
			same(fmt.Sprintf("%s long-poll from %d", ns, k), lp.Entries, all[k:k+n])
			ev, err := e.e.NamespaceEvents(ctx, ns, since(k), 2, core.Credentials{})
			if err != nil {
				t.Fatal(err)
			}
			same(fmt.Sprintf("%s events from %d", ns, k), ev.Entries, all[k:k+n])
			if sealed != (len(ev.EntryJWEs) == n) {
				t.Fatalf("%s events from %d: %d JWEs", ns, k, len(ev.EntryJWEs))
			}
			for i, jwe := range ev.EntryJWEs {
				m := all[k+i]
				if pt := open(t, jwe, key, kid, seal.RangePL(ns, since(k+i), m["id"].(string))); string(pt) != string(canonical([]any{m})) {
					t.Fatalf("%s event %d: %s", ns, k+i, pt)
				}
			}
		}
		k := 0
		for _, p := range e.pages("/ns/"+ns+"/rev/"+head+"/log", "") {
			n := min(3, len(all)-k)
			body := p.body
			if sealed {
				body = open(t, string(p.body), key, kid, seal.RangePL(ns, since(k), all[k+n-1]["id"].(string)))
			}
			if want := canonical(anyOf(all[k : k+n])); string(body) != string(want) {
				t.Fatalf("%s page from %d: %s", ns, k, body)
			}
			k += n
		}
		if k != len(all) {
			t.Fatalf("%s: pages end at %d of %d", ns, k, len(all))
		}
	}
	fill("p", false)
	fill("s", true)
	for _, ns := range []string{"p", "p-br", "s", "s-br"} {
		check(ns, ns[0] == 's')
	}
}
