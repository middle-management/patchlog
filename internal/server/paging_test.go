package server

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// withLogPageSize sets the deployment's log page size (§6.6).
func withLogPageSize(n int) envOpt {
	return func(o *core.Options) {
		if o.Maximums == (core.Limits{}) {
			o.Maximums = o.Limits
			if o.Maximums == (core.Limits{}) {
				o.Maximums = core.DefaultLimits()
			}
		}
		o.Maximums.LogPageSize = n
	}
}

type logPage struct {
	since, next string
	body        []byte
	entries     []map[string]any // plain pages
}

// pages reads the log range path (…/rev/{id}/log) after since page by page,
// checking every page's headers, and returns them in order.
func (e *tenv) pages(path, since string, bearer ...string) []logPage {
	e.t.Helper()
	var out []logPage
	for {
		p := path
		if since != "" {
			p += "?since=" + since
		}
		r := e.get(p, bearer...)
		expect(e.t, r, 200)
		if !strings.HasPrefix(r.H.Get("Cache-Control"), "public, ") && r.H.Get("Cache-Control") != ccImmutable {
			e.t.Fatalf("page %s: Cache-Control %q", p, r.H.Get("Cache-Control"))
		}
		pg := logPage{since: since, next: r.H.Get("X-Log-Next"), body: r.Body}
		if !isJOSE(r) {
			for _, x := range r.Arr() {
				if m, ok := x.(map[string]any); ok {
					pg.entries = append(pg.entries, m)
				}
			}
		}
		out = append(out, pg)
		if pg.next == "" {
			return out
		}
		if len(out) > 100 {
			e.t.Fatal("no end to the pages")
		}
		since = pg.next
	}
}

func entryIDs(es []map[string]any) []string {
	var out []string
	for _, m := range es {
		out = append(out, m["id"].(string))
	}
	return out
}

// §7.1 Paging: a range longer than the log page size answers its first
// page, oldest first, with X-Log-Next naming the page's last entry, the
// since of the next page, an immutable range up to the same id. Pages are
// prefixes of their range, cache as immutable, and the long-poll pages the
// same way (§7.7) without X-Log-Next.
func TestLogPaging(t *testing.T) {
	e := newEnv(t, withLogPageSize(2))
	e.mkNS("docs", map[string]any{"read": "public"})
	revs := e.chain("docs", "a", 5)
	e.create("docs", "b", map[string]any{})
	head := e.nsHead("docs")
	full := e.plainNSLog("docs", head) // unpaged (limit 0)
	if len(full.Entries) != 7 {
		t.Fatalf("namespace log %d entries", len(full.Entries))
	}
	wantIDs := entryIDs(full.Entries)

	// Namespace log: pages of 2, 2, 2, 1.
	ps := e.pages("/ns/docs/rev/"+head+"/log", "")
	if len(ps) != 4 {
		t.Fatalf("%d pages", len(ps))
	}
	var got []map[string]any
	for i, p := range ps {
		if n := len(p.entries); n != 2 && !(i == 3 && n == 1) {
			t.Fatalf("page %d has %d entries", i, n)
		}
		if p.next != "" && p.next != p.entries[len(p.entries)-1]["id"] {
			t.Fatalf("page %d: X-Log-Next %s isn't its last entry", i, p.next)
		}
		got = append(got, p.entries...)
	}
	if strings.Join(entryIDs(got), ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("pages %v, want %v", entryIDs(got), wantIDs)
	}
	if string(canonical(anyOf(got))) != string(canonical(anyOf(full.Entries))) {
		t.Fatal("paged entries differ from the whole range")
	}
	// Each page is the same whatever id the range runs to: a range up to
	// an older id pages alike, and ends there without X-Log-Next.
	mid := wantIDs[4]
	ps2 := e.pages("/ns/docs/rev/"+mid+"/log", "")
	if len(ps2) != 3 || !bytes.Equal(ps2[0].body, ps[0].body) || !bytes.Equal(ps2[1].body, ps[1].body) ||
		len(ps2[2].entries) != 1 || ps2[2].entries[0]["id"] != mid {
		t.Fatalf("range up to %s: %d pages", mid, len(ps2))
	}
	// A page from a later since; the empty range at the id itself.
	if p := e.pages("/ns/docs/rev/"+head+"/log", wantIDs[5]); len(p) != 1 || len(p[0].entries) != 1 || p[0].entries[0]["id"] != head {
		t.Fatalf("last page %v", p)
	}
	if r := e.get("/ns/docs/rev/" + head + "/log?since=" + head); r.Code != 200 || len(r.Arr()) != 0 || r.H.Get("X-Log-Next") != "" {
		t.Fatalf("empty range %d %s %v", r.Code, r.Body, r.H)
	}
	// Errors are those of the range, on every page.
	expect(t, e.get("/ns/docs/rev/"+mid+"/log?since="+head), 404)
	expect(t, e.get("/ns/docs/rev/"+mid+"/log?since="+hashID(t, "", nil)), 404)

	// Resource log: pages of 2, 2, 1, chained by parent.
	rps := e.pages("/r/docs/a/rev/"+revs[4]+"/log", "")
	if len(rps) != 3 {
		t.Fatalf("%d resource pages", len(rps))
	}
	prev := ""
	var n int
	for _, p := range rps {
		for _, m := range p.entries {
			if par, _ := m["parent"].(string); par != prev {
				t.Fatalf("entry %s: parent %q, want %q", m["id"], par, prev)
			}
			prev = m["id"].(string)
			n++
		}
	}
	if n != 5 || prev != revs[4] || rps[0].next != revs[1] || rps[1].next != revs[3] {
		t.Fatalf("resource pages: %d entries ending at %s; next %s %s", n, prev, rps[0].next, rps[1].next)
	}
	if p := e.pages("/r/docs/a/rev/"+revs[2]+"/log", revs[0]); len(p) != 1 || len(p[0].entries) != 2 {
		t.Fatalf("a range of one page %v", p)
	}
	if r := e.get("/r/docs/a/rev/" + revs[2] + "/log?since=" + revs[2]); r.Code != 200 || len(r.Arr()) != 0 || r.H.Get("X-Log-Next") != "" {
		t.Fatalf("empty resource range %d %s", r.Code, r.Body)
	}
	expect(t, e.get("/r/docs/a/rev/"+revs[2]+"/log?since="+revs[3]), 404)

	// Long-poll answers are pages too: as long, the same entries, the last
	// one named by X-Namespace-Revision (X-Revision), and no X-Log-Next.
	lp := e.get("/ns/docs/log?since=&live=long-poll")
	expect(t, lp, 200)
	if !bytes.Equal(lp.Body, ps[0].body) || lp.H.Get("X-Namespace-Revision") != wantIDs[1] || lp.H.Get("X-Log-Next") != "" {
		t.Fatalf("namespace long-poll %s %v", lp.Body, lp.H)
	}
	lr := e.get("/r/docs/a/log?since=" + revs[1] + "&live=long-poll")
	expect(t, lr, 200)
	if !bytes.Equal(lr.Body, rps[1].body) || lr.H.Get("X-Revision") != revs[3] || lr.H.Get("X-Log-Next") != "" {
		t.Fatalf("resource long-poll %s %v", lr.Body, lr.H)
	}
	// Without live, the URL redirects to the immutable range, which pages.
	r := e.get("/ns/docs/log?since=" + wantIDs[1])
	expect(t, r, 302)
	if loc := r.H.Get("Location"); loc != "/ns/docs/rev/"+head+"/log?since="+wantIDs[1] {
		t.Fatalf("Location %s", loc)
	}
}

func anyOf(es []map[string]any) []any {
	out := make([]any, len(es))
	for i, m := range es {
		out[i] = m
	}
	return out
}

// Every page of a range that crosses a pruning horizon answers 410, so a
// page can't pass for a range that was cut short (§7.1, §8.6); ranges from
// the horizon page as usual.
func TestLogPagingPruned(t *testing.T) {
	e := newEnv(t, withLogPageSize(2))
	e.mkNS("main", map[string]any{"read": "public"})
	revs := e.chain("main", "a", 7)
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("main", "a", map[string]any{"horizon": revs[3]}, "admin"), 200)
	lg := e.get("/r/main/a/rev/" + revs[6] + "/log?since=" + revs[0])
	expectCode(t, lg, 410, "pruned")
	if lg.Str("horizon") != revs[3] {
		t.Fatalf("410 %s", lg.Body)
	}
	// The first page alone (revs[1], revs[2]) would lie below the horizon
	// too; a later since below it still crosses.
	expectCode(t, e.get("/r/main/a/rev/"+revs[6]+"/log?since="+revs[1]), 410, "pruned")
	ps := e.pages("/r/main/a/rev/"+revs[6]+"/log", revs[2])
	var got []string
	for _, p := range ps {
		got = append(got, entryIDs(p.entries)...)
	}
	if strings.Join(got, ",") != strings.Join(revs[3:], ",") || len(ps) != 2 {
		t.Fatalf("pages from below the horizon %v (%d pages)", got, len(ps))
	}
}

// Sealed pages carry their own bounds (§7.1, §E.2.2): a namespace page is
// one JWE with pl.range [since, last], the page actually served, and the
// same bytes as the long-poll page from that since; a resource page is
// its entries' JWEs, which chain to X-Log-Next.
func TestSealedLogPaging(t *testing.T) {
	e := newSealedEnv(t, withLogPageSize(2))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	var ids []string
	parent := ""
	for i := range 5 {
		p := withNonce(ops(op("add", "/n", float64(i))))
		if parent == "" {
			p = withNonce(addRoot(map[string]any{"v": encMarker}))
		}
		parent = e.wr("s", "x", parent, p)
		ids = append(ids, parent)
	}
	head := e.nsHead("s")
	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	ke := keys["s#1"]
	kr := resKey(t, ke, "s", "x")
	plain := e.plainNSLog("s", head)
	if len(plain.Entries) != 6 {
		t.Fatalf("%d entries", len(plain.Entries))
	}

	ps := e.pages("/ns/s/rev/"+head+"/log", "")
	if len(ps) != 3 {
		t.Fatalf("%d sealed pages", len(ps))
	}
	var got []any
	for i, p := range ps {
		last := head
		if p.next != "" {
			last = p.next
		}
		pt := open(t, string(p.body), ke, "s#1", seal.RangePL("s", p.since, last))
		arr := jsonv.MustParse(pt).([]any)
		if len(arr) != 2 || arr[1].(map[string]any)["id"] != last {
			t.Fatalf("page %d: %s", i, pt)
		}
		// The page isn't bound to the whole range.
		if _, err := seal.OpenExpect(string(p.body), ke, "s#1", seal.RangePL("s", p.since, head)); p.next != "" && err == nil {
			t.Fatalf("page %d opens as the whole range", i)
		}
		got = append(got, arr...)
		// The long-poll page from the same since is the same stored JWE.
		lp := e.get("/ns/s/log?live=long-poll&since=" + p.since)
		expect(t, lp, 200)
		if !bytes.Equal(lp.Body, p.body) {
			t.Fatalf("long-poll page %d differs from the range page", i)
		}
	}
	if string(canonical(got)) != string(canonical(anyOf(plain.Entries))) {
		t.Fatal("sealed pages differ from the plain log")
	}

	rps := e.pages("/r/s/x/rev/"+ids[4]+"/log", "")
	if len(rps) != 3 || rps[0].next != ids[1] || rps[1].next != ids[3] {
		t.Fatalf("sealed resource pages %d", len(rps))
	}
	prev := ""
	for _, p := range rps {
		for _, x := range jsonv.MustParse(p.body).([]any) {
			h, err := seal.ParseHeader(x.(string))
			if err != nil {
				t.Fatal(err)
			}
			id := h.PL["id"].(string)
			m := jsonv.MustParse(open(t, x.(string), kr, "s#1", seal.ResourcePL("s", "x", id, "rev"))).(map[string]any)
			if par, _ := m["parent"].(string); par != prev || m["id"] != id {
				t.Fatalf("sealed entry %s doesn't chain from %q", id, prev)
			}
			prev = id
		}
		if want := p.next; want != "" && prev != want {
			t.Fatalf("page ends at %s, X-Log-Next %s", prev, want)
		}
	}
	if prev != ids[4] || strings.Contains(string(rps[0].body), encMarker) {
		t.Fatalf("sealed resource log ends at %s", prev)
	}
	// Stored once: the same pages again, after a cache flush.
	e.e.FlushCaches()
	again := e.pages("/ns/s/rev/"+head+"/log", "")
	for i := range ps {
		if !bytes.Equal(again[i].body, ps[i].body) {
			t.Fatalf("page %d changed", i)
		}
	}
}

// /heads lists resources in ascending byte order of name, after after,
// including those a branch reads through, on SQLite and Postgres alike
// (§7.4): '-' < '.' < digits < '_' < letters, which a collation that
// ignores punctuation (en_US) would sort otherwise.
func TestHeadsByteOrder(t *testing.T) { testHeadsByteOrder(t) }

// The same on a Postgres database whose default collation isn't byte order
// (ICU "en"): the order never comes from the database's collation.
func TestHeadsByteOrderCollated(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only (" + pgtest.Env + ")")
	}
	url := pgtest.NewDBCollated(t, "en")
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var lt bool
	if err := db.QueryRow(`SELECT 'a_b' < 'a0'`).Scan(&lt); err != nil || !lt {
		t.Fatalf("the database collates in byte order (%v), so this test proves nothing", err)
	}
	testHeadsByteOrder(t, withPath(url))
}

func testHeadsByteOrder(t *testing.T, opts ...envOpt) {
	e := newEnv(t, append([]envOpt{withLogPageSize(2)}, opts...)...)
	e.mkNS("main", map[string]any{"read": "public"})
	baseNames := []string{"b", "a_b", "a.b", "a0", "z9", "ab"}
	for _, n := range baseNames {
		e.create("main", n, map[string]any{"n": n})
	}
	expect(t, e.branch("main", map[string]any{"name": "rel"}, "alice"), 201)
	// The branch adds its own names, writes over a read-through one, and
	// tombstones another.
	for _, n := range []string{"a-b", "a", "b.c", "a_a"} {
		e.create("rel", n, map[string]any{"n": n})
	}
	e.appendRev("rel", "ab", e.head("rel", "ab"), ops(op("replace", "/n", "branch")))
	e.del("rel", "z9", e.head("rel", "z9"))
	// A base change after at isn't seen.
	e.create("main", "a.a", map[string]any{})

	heads := func(ns string) []string {
		t.Helper()
		head := e.nsHead(ns)
		var names []string
		after := ""
		for i := 0; ; i++ {
			p := "/ns/" + ns + "/rev/" + head + "/heads"
			if after != "" {
				p += "?after=" + after
			}
			r := e.get(p)
			expect(t, r, 200)
			items := r.Obj()["items"].([]any)
			if len(items) > 2 {
				t.Fatalf("a page of %d", len(items))
			}
			for _, x := range items {
				names = append(names, x.(map[string]any)["resource"].(string))
			}
			next := r.Str("next")
			if next == "" {
				return names
			}
			if next != names[len(names)-1] || i > 20 {
				t.Fatalf("next %s after %v", next, names)
			}
			after = next
		}
	}
	want := "a,a-b,a.b,a0,a_a,a_b,ab,b,b.c,z9"
	if got := strings.Join(heads("rel"), ","); got != want {
		t.Fatalf("branch heads %s, want %s", got, want)
	}
	if got := strings.Join(heads("main"), ","); got != "a.a,a.b,a0,a_b,ab,b,z9" {
		t.Fatalf("base heads %s", got)
	}
	// after needn't be a resource name: it is a byte-order bound.
	r := e.get("/ns/rel/rev/" + e.nsHead("rel") + "/heads?after=a-")
	if items := r.Obj()["items"].([]any); items[0].(map[string]any)["resource"] != "a-b" {
		t.Fatalf("after=a- %s", r.Body)
	}
	r = e.get("/ns/rel/rev/" + e.nsHead("rel") + "/heads?after=a_")
	if items := r.Obj()["items"].([]any); items[0].(map[string]any)["resource"] != "a_a" {
		t.Fatalf("after=a_ %s", r.Body)
	}
	// Kinds: the branch's tombstone, its own head over a read-through one.
	for _, x := range e.get("/ns/rel/rev/" + e.nsHead("rel") + "/heads?after=ab").Obj()["items"].([]any) {
		m := x.(map[string]any)
		if m["resource"] == "z9" && m["kind"] != "tombstone" {
			t.Fatalf("z9 %v", m)
		}
	}
}

// A remote branch (§G.3) mirrors its base and follows the base's log
// through paged ranges: logs longer than the base's page size on both
// sides.
func TestRemoteBranchPaged(t *testing.T) {
	a, b, _ := pair(t, []envOpt{withLogPageSize(2)}, []envOpt{withLogPageSize(3)})
	f := populateA(t, a)
	// More history than one page for derby's chain.
	d := f.lateD
	for i := range 4 {
		d = a.appendRev("main", "derby", d, ops(op("replace", "/score", strings.Repeat("1", i+1)+"-0")))
	}
	at := a.nsHead("main")
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
	if h := b.head("rel", "derby"); h != d {
		t.Fatalf("derby head %s, want %s", h, d)
	}
	// B serves the mirrored chain, page by page, as A does.
	pa, pb := a.pages("/r/main/derby/rev/"+d+"/log", ""), b.pages("/r/rel/derby/rev/"+d+"/log", "")
	var la, lb []string
	for _, p := range pa {
		la = append(la, entryIDs(p.entries)...)
	}
	for _, p := range pb {
		lb = append(lb, entryIDs(p.entries)...)
	}
	if strings.Join(la, ",") != strings.Join(lb, ",") || len(la) != 7 || len(pa) != 4 || len(pb) != 3 {
		t.Fatalf("derby logs A %v (%d pages), B %v (%d pages)", la, len(pa), lb, len(pb))
	}
	// Following: A purges after at; B applies it from A's paged log.
	for i := range 3 {
		a.create("main", "n"+string(rune('a'+i)), map[string]any{})
	}
	expect(t, a.purge("main", "old", f.o1, "admin"), 204)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Fatal(err)
	}
	expect(t, b.get("/r/rel/old"), 410)
	if b.head("rel", "derby") != d {
		t.Fatal("derby changed")
	}
}

// A resource's range in a branch of a branch crosses its bases' chains
// (§7.6): pages run oldest first across the segments, chained by parent at
// each fork, from any since (in a base's segment, at a fork, in the
// branch's own), and are the whole range cut into pages (§7.1 Paging).
func TestLogPagingBranch(t *testing.T) {
	e := newEnv(t, withLogPageSize(2))
	e.mkNS("main", map[string]any{"read": "public"})
	revs := e.chain("main", "a", 3)
	expect(t, e.branch("main", map[string]any{"name": "br"}, "alice"), 201)
	// After the branch: not in the branch's range.
	later := e.appendRev("main", "a", revs[2], ops(op("replace", "/n", 9.0)))
	for i := 0; i < 3; i++ {
		revs = append(revs, e.appendRev("br", "a", revs[len(revs)-1], ops(op("replace", "/n", float64(10+i)))))
	}
	expect(t, e.branch("br", map[string]any{"name": "br2"}, "alice"), 201)
	for i := 0; i < 2; i++ {
		revs = append(revs, e.appendRev("br2", "a", revs[len(revs)-1], ops(op("replace", "/n", float64(20+i)))))
	}
	head := revs[len(revs)-1]
	if e.head("br2", "a") != head {
		t.Fatal("branch head")
	}
	whole, err := e.e.ResourceLog(context.Background(), "br2", "a", head, "", 0, core.Credentials{})
	if err != nil || whole.Status != 200 || len(whole.Entries) != len(revs) {
		t.Fatalf("whole range %v %+v", err, whole)
	}
	for i, since := range append([]string{""}, revs...) {
		ps := e.pages("/r/br2/a/rev/"+head+"/log", since)
		var got []map[string]any
		prev := since
		for j, p := range ps {
			if len(p.entries) > 2 || len(p.entries) == 0 && len(ps) > 1 {
				t.Fatalf("since %q: page %d has %d entries", since, j, len(p.entries))
			}
			if p.next != "" && p.next != p.entries[len(p.entries)-1]["id"] {
				t.Fatalf("since %q: page %d: X-Log-Next %s isn't its last entry", since, j, p.next)
			}
			for _, m := range p.entries {
				if par, _ := m["parent"].(string); par != prev {
					t.Fatalf("since %q: entry %s has parent %q, want %q", since, m["id"], par, prev)
				}
				prev = m["id"].(string)
			}
			got = append(got, p.entries...)
		}
		if string(canonical(anyOf(got))) != string(canonical(anyOf(whole.Entries[i:]))) {
			t.Fatalf("since %q: pages %v, want %v", since, entryIDs(got), entryIDs(whole.Entries[i:]))
		}
	}
	// A range up to an id of a base's segment pages alike; a since off the
	// ancestry is 404.
	ps := e.pages("/r/br2/a/rev/"+revs[4]+"/log", "")
	if len(ps) != 3 || ps[2].entries[0]["id"] != revs[4] || ps[1].next != revs[3] {
		t.Fatalf("range up to %s: %d pages", revs[4], len(ps))
	}
	expect(t, e.get("/r/br2/a/rev/"+head+"/log?since="+later), 404)
}

// An e2e range whose since is a prune's horizon holds only the entries
// after it, paged like any other: the horizon's sealed snapshot is served
// as /rev/{H}, never as a log entry (§7.1 Paging, §8.6). A later page's
// since is the horizon when the resource was pruned at the previous page's
// last entry between the two reads; that page is no different.
func TestE2ELogPageFromSnapshot(t *testing.T) {
	f := newE2E(t, withArchive(t, t.TempDir()), withLogPageSize(2))
	e := f.tenv
	k := seal.NewKey()
	revs := []string{etagOf(e.writeRaw("e", "p", "", sealed(t, k, "e#1", "e", "p", "", addRoot(map[string]any{"n": 0.0})), f.writerG))}
	for i := 1; i < 6; i++ {
		revs = append(revs, etagOf(e.writeRaw("e", "p", revs[i-1], sealed(t, k, "e#1", "e", "p", revs[i-1], ops(op("replace", "/n", float64(i)))), f.writerG)))
	}
	e.clock.Advance(10 * time.Minute)
	path := "/r/e/p/rev/" + revs[5] + "/log"
	r := e.get(path, f.readerG)
	expect(t, r, 200)
	if got := entryIDs(anyMaps(r.Arr())); strings.Join(got, ",") != strings.Join(revs[:2], ",") || r.H.Get("X-Log-Next") != revs[1] {
		t.Fatalf("first page %v, next %q", got, r.H.Get("X-Log-Next"))
	}
	snap, err := seal.SealSnapshot(k, "e#1", "e", "p", revs[1], map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.prune("e", "p", map[string]any{"horizon": revs[1], "snapshot": snap}, f.writerG), 200)
	r = e.get(path+"?since="+revs[1], f.readerG)
	expect(t, r, 200)
	arr := anyMaps(r.Arr())
	if got := entryIDs(arr); strings.Join(got, ",") != strings.Join(revs[2:4], ",") || arr[0]["parent"] != revs[1] || r.H.Get("X-Log-Next") != revs[3] {
		t.Fatalf("page from the horizon: %v, next %q", arr, r.H.Get("X-Log-Next"))
	}
	r = e.get(path+"?since="+revs[3], f.readerG)
	expect(t, r, 200)
	if got := entryIDs(anyMaps(r.Arr())); strings.Join(got, ",") != strings.Join(revs[4:], ",") || r.H.Get("X-Log-Next") != "" {
		t.Fatalf("last page %v, next %q", got, r.H.Get("X-Log-Next"))
	}
	// A range from the horizon that fits one page, and an empty one.
	r = e.get("/r/e/p/rev/"+revs[3]+"/log?since="+revs[1], f.readerG)
	expect(t, r, 200)
	if got := entryIDs(anyMaps(r.Arr())); strings.Join(got, ",") != strings.Join(revs[2:4], ",") || r.H.Get("X-Log-Next") != "" {
		t.Fatalf("single page %v, next %q", got, r.H.Get("X-Log-Next"))
	}
	r = e.get("/r/e/p/rev/"+revs[1]+"/log?since="+revs[1], f.readerG)
	expect(t, r, 200)
	if len(r.Arr()) != 0 {
		t.Fatalf("empty range at the horizon: %s", r.Body)
	}
	// The snapshot is the horizon's revision: immutable and conditional.
	r = e.get("/r/e/p/rev/"+revs[1], f.readerG)
	expect(t, r, 200)
	if string(r.Body) != snap || r.H.Get("Content-Type") != seal.ContentType || r.H.Get("X-E2E") != "snapshot" || r.H.Get("X-Revision") != revs[1] {
		t.Fatalf("/rev/{H}: %v %s", r.H, r.Body)
	}
	expect(t, e.do(req{method: "GET", path: "/r/e/p/rev/" + revs[1], bearer: f.readerG, ifNoneMatch: `"` + revs[1] + `"`}), 304)
	keys := map[string][]byte{"e#1": k}
	mustEqual(t, f.fold("e", "p", revs[5], keys, f.readerG), map[string]any{"n": 5.0})
	mustEqual(t, f.fold("e", "p", revs[3], keys, f.readerG), map[string]any{"n": 3.0})
	mustEqual(t, f.fold("e", "p", revs[1], keys, f.readerG), map[string]any{"n": 1.0})
	// Other revisions still redirect to the fold from the horizon (§13).
	r = e.get("/r/e/p/rev/"+revs[4], f.readerG)
	if r.Code != 302 || r.H.Get("Location") != "/r/e/p/rev/"+revs[4]+"/log?since="+revs[1] {
		t.Fatalf("/rev/%s: %d %v", revs[4], r.Code, r.H)
	}
}

func anyMaps(xs []any) []map[string]any {
	out := []map[string]any{}
	for _, x := range xs {
		out = append(out, x.(map[string]any))
	}
	return out
}

// /heads at an earlier namespace revision skips names that have no head
// there, however many lie between two that do: a page is filled from
// chunks of names, not from one (§7.4).
func TestHeadsSkipsNamesAbsentAtAt(t *testing.T) {
	e := newEnv(t, withLogPageSize(2))
	e.mkNS("main", map[string]any{"read": "public"})
	for _, n := range []string{"a", "m", "z"} {
		e.create("main", n, map[string]any{})
	}
	at := e.nsHead("main")
	// Created after at: eleven names between a and m, and more after z.
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "zz", "zzz"} {
		e.create("main", n, map[string]any{})
	}
	var names []string
	for after, i := "", 0; i < 10; i++ {
		p := "/ns/main/rev/" + at + "/heads"
		if after != "" {
			p += "?after=" + after
		}
		r := e.get(p)
		expect(t, r, 200)
		for _, x := range r.Obj()["items"].([]any) {
			names = append(names, x.(map[string]any)["resource"].(string))
		}
		if after = r.Str("next"); after == "" {
			break
		}
	}
	if got := strings.Join(names, ","); got != "a,m,z" {
		t.Fatalf("heads at at: %s", got)
	}
}
