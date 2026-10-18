package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// withLogPageBytes sets the deployment's logPageBytes (§6.6).
func withLogPageBytes(n int) envOpt {
	return func(o *core.Options) {
		if o.Maximums == (core.Limits{}) {
			o.Maximums = o.Limits
			if o.Maximums == (core.Limits{}) {
				o.Maximums = core.DefaultLimits()
			}
		}
		o.Maximums.LogPageBytes = n
	}
}

// patchBytes is the bytes of an entry's patch set as served (canonical).
func patchBytes(m map[string]any) int {
	p, ok := m["patches"]
	if !ok {
		return 0
	}
	return len(jsonv.Canonical(jsonv.FromGo(p)))
}

// §6.6, §7.1 Paging, §7.7: a resource log page ends before an entry whose
// patch set would take it past logPageBytes, as served, but always holds
// one, so an entry larger than the bound is a page of its own; X-Log-Next
// names its last entry, the long-poll page from the same since is the
// same, and event-stream catch-up reads the whole range page by page.
// Plain, at-rest (whose stored rows are larger than what is served) and
// compressed rows (PATCHLOG_TEST_STORE_COMPRESSION) page alike. Namespace
// logs carry no patch sets: their pages are bounded by the page size.
func TestLogPageBytes(t *testing.T) {
	t.Parallel()
	const bound = 3000
	e := newSealedEnv(t, withLogPageBytes(bound))
	big := func(i int) string { return strings.Repeat(string(rune('a'+i%26)), 900) }
	var layouts [][]int
	for _, ns := range []string{"p", "r"} {
		doc := map[string]any{"read": "public"}
		if ns == "r" {
			doc["encryption"] = map[string]any{"level": "at-rest"}
		}
		e.mkNS(ns, doc)
		revs := []string{e.create(ns, "a", map[string]any{})}
		for i := 1; i < 9; i++ {
			v := any(big(i))
			if i == 5 {
				v = strings.Repeat("Z", 5000) // over the bound alone
			}
			revs = append(revs, e.appendRev(ns, "a", revs[i-1], ops(op("add", "/k"+string(rune('0'+i)), v))))
		}
		head := revs[len(revs)-1]
		ps := e.pages("/r/"+ns+"/a/rev/"+head+"/log", "")
		var got []string
		var layout []int
		for i, p := range ps {
			size := 0
			for _, m := range p.entries {
				size += patchBytes(m)
			}
			if len(p.entries) > 1 && size > bound {
				t.Fatalf("%s page %d: %d entries, %d bytes", ns, i, len(p.entries), size)
			}
			if i+1 < len(ps) {
				// The next entry wouldn't have fitted.
				if size+patchBytes(ps[i+1].entries[0]) <= bound || p.next != p.entries[len(p.entries)-1]["id"] {
					t.Fatalf("%s page %d ends early: %d bytes, next %d; X-Log-Next %s", ns, i, size, patchBytes(ps[i+1].entries[0]), p.next)
				}
			}
			// The long-poll page from the same since is the same.
			lp := e.get("/r/" + ns + "/a/log?live=long-poll&since=" + p.since)
			expect(t, lp, 200)
			if !bytes.Equal(lp.Body, p.body) || lp.H.Get("X-Revision") != p.entries[len(p.entries)-1]["id"] || lp.H.Get("X-Log-Next") != "" {
				t.Fatalf("%s long-poll from %q: %s %v", ns, p.since, lp.Body, lp.H)
			}
			got = append(got, entryIDs(p.entries)...)
			layout = append(layout, len(p.entries))
		}
		if strings.Join(got, ",") != strings.Join(revs, ",") {
			t.Fatalf("%s pages %v, want %v", ns, got, revs)
		}
		layouts = append(layouts, layout)
		// The entry over the bound is a page of its own.
		var alone bool
		for _, p := range ps {
			alone = alone || len(p.entries) == 1 && p.entries[0]["id"] == revs[5]
		}
		if !alone {
			t.Fatalf("%s: the large entry shares a page: %v", ns, layout)
		}

		// Event-stream catch-up replays the range, a page per fetch.
		ch, _, cancel := e.openSSE("/r/"+ns+"/a/events?since="+revs[0], nil)
		for _, want := range revs[1:] {
			if ev := next(t, ch); ev.id != want {
				t.Fatalf("%s SSE: %s, want %s", ns, ev.id, want)
			}
		}
		cancel()
		// The namespace log: one page, its entries carry no patch sets.
		if ns := e.pages("/ns/"+ns+"/rev/"+e.nsHead(ns)+"/log", ""); len(ns) != 1 {
			t.Fatalf("namespace log in %d pages", len(ns))
		}
	}
	if len(layouts[0]) != len(layouts[1]) {
		t.Fatalf("plain pages %v, at rest %v", layouts[0], layouts[1])
	}
	for i := range layouts[0] {
		if layouts[0][i] != layouts[1][i] {
			t.Fatalf("plain pages %v, at rest %v", layouts[0], layouts[1])
		}
	}

	// Deployment only: a namespace document can't set it.
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/x", ifNoneMatch: "*", author: "admin",
		body: addRoot(map[string]any{"limits": map[string]any{"logPageBytes": 1024}})}), 422, "invalid")
}

// §7.1 Paging, §E.2.2: at E2 a resource log page is bounded by the JWEs it
// serves, one per entry, not by the plaintext they hold, so where padding
// makes entries alike their pages are alike: patch sets a byte apart in
// one bucket page the same way, and a page holds as many JWEs as fit. The
// entries sealed for a page are stored, so the next read serves the same
// bytes, and the long-poll page from the same since is the same. Unpadded
// JWEs are compressed and may be shorter than their plaintext, so a page
// of them may end sooner, but never past the bound.
func TestLogPageBytesSealed(t *testing.T) {
	t.Parallel()
	write := func(e *tenv, ns string, sizes []int) string {
		head := e.wr(ns, "x", "", withNonce(addRoot(map[string]any{"v": strings.Repeat("q", sizes[0])})))
		for _, n := range sizes[1:] {
			head = e.wr(ns, "x", head, withNonce(ops(op("replace", "/v", strings.Repeat("q", n)))))
		}
		return head
	}
	type page struct {
		since string
		body  []byte
		lens  []int
	}
	read := func(e *tenv, ns, head string) []page {
		var out []page
		for _, p := range e.pages("/r/"+ns+"/x/rev/"+head+"/log", "") {
			var arr []string
			if err := json.Unmarshal(p.body, &arr); err != nil || len(arr) == 0 {
				t.Fatalf("%s: page %s", ns, p.body)
			}
			pg := page{since: p.since, body: p.body}
			for _, s := range arr {
				pg.lens = append(pg.lens, len(s))
			}
			out = append(out, pg)
		}
		return out
	}
	sum := func(xs []int) (n int) {
		for _, x := range xs {
			n += x
		}
		return n
	}
	sizes := func(last int) []int { return []int{1000, 1000, 1000, 1000, 1000, last} }
	padded := map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "pad": true}}

	// The length of one padded entry's JWE, served without a bound.
	m := newSealedEnv(t)
	m.mkNS("m", padded)
	jwe := read(m, "m", write(m, "m", sizes(1000)))[0].lens[0]

	bound := 2*jwe + jwe/2
	e := newSealedEnv(t, withLogPageBytes(bound))
	var first []int
	for _, c := range []struct {
		ns   string
		last int
	}{{"a", 1000}, {"b", 1001}, {"c", 1003}, {"d", 990}} {
		e.mkNS(c.ns, padded)
		head := write(e, c.ns, sizes(c.last))
		ps := read(e, c.ns, head)
		var layout []int
		for i, p := range ps {
			if len(p.lens) > 1 && sum(p.lens) > bound {
				t.Fatalf("%s page %d: JWEs %v over %d", c.ns, i, p.lens, bound)
			}
			if i+1 < len(ps) && sum(p.lens)+ps[i+1].lens[0] <= bound {
				t.Fatalf("%s page %d ends early: JWEs %v, next %d, bound %d", c.ns, i, p.lens, ps[i+1].lens[0], bound)
			}
			lp := e.get("/r/" + c.ns + "/x/log?live=long-poll&since=" + p.since)
			expect(t, lp, 200)
			if !bytes.Equal(lp.Body, p.body) {
				t.Fatalf("%s long-poll from %q: %s, page %s", c.ns, p.since, lp.Body, p.body)
			}
			layout = append(layout, len(p.lens))
		}
		for i, p := range read(e, c.ns, head) {
			if !bytes.Equal(p.body, ps[i].body) {
				t.Fatalf("%s page %d sealed again: %s, was %s", c.ns, i, p.body, ps[i].body)
			}
		}
		if first == nil {
			first = layout
		} else if fmt.Sprint(layout) != fmt.Sprint(first) {
			t.Fatalf("%s pages %v, a %v: page ends depend on exact sizes", c.ns, layout, first)
		}
	}

	// Unpadded: compressed JWEs, pages within the bound.
	e.mkNS("u", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}})
	for i, p := range read(e, "u", write(e, "u", sizes(1000))) {
		if len(p.lens) > 1 && sum(p.lens) > bound {
			t.Fatalf("unpadded page %d: JWEs %v over %d", i, p.lens, bound)
		}
	}
}
