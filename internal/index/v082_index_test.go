package index_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V82-05 (v0.82), SVC-10: an index cookie ends on any change to the entry
// of the key that verified its grant, or to a role it read through,
// reads:{ns} markers included (SERVICES §A.4 gs, §B.11.9 gs; CONFORMANCE
// scenario 120).

// newV82Whole is newV77Docs's setup with keys k1 and k2 that have no
// scope rules, so their grants read docs whole: their marker is
// reads:docs, which every such reader shares whatever its key.
func newV82Whole(t *testing.T) *v77docs {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	d := &v77docs{t: t, s: s, admin: clienttest.NewKey("admin"), k1: clienttest.NewKey("k1"), k2: clienttest.NewKey("k2")}
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{d.admin.Entry("*"), d.k1.Entry("read"), d.k2.Entry("read")},
		"roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}}))
	d.w = s.Client(t, client.WithBearer(d.admin.Grant(t, s.Now(), "user:root", []string{"docs"}, []string{"read", "create", "append", "config"})))
	sch := must(d.w.CreateDoc(ctx, "docs", "schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	for _, n := range []string{"a", "b", "secret"} {
		must(d.w.CreateDoc(ctx, "docs", n, map[string]any{"$schema": "/r/docs/schema/rev/" + sch.ID, "title": "word " + n}))
	}
	ev := must(edge.New([]byte("s3cret"), "", ""))
	d.x = startSvcWith(t, s.Client(t, client.WithBearer(d.admin.Grant(t, s.Now(), "svc:indexer", []string{"docs"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"docs"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		})
	d.x.caughtUp("docs")
	return d
}

// v82Grant is k's grant for sub with the role reader, expiring exp from
// now: the exp bounds its cookies', so two grants with different exps get
// different cookies for one prefix.
func v82Grant(d *v77docs, k clienttest.Key, sub string, exp time.Time) string {
	return k.Grant(d.t, d.s.Now(), sub, []string{"docs"}, []string{"read"}, map[string]any{"roles": []any{"reader"}, "exp": exp.Format(time.RFC3339)})
}

// v82Paths are the URLs a cookie of prefixes is read at: the head pointer
// of docs' results under its prefix, and /_refs under its own.
func v82Paths(prefixes map[string]string) []string {
	return []string{prefixes["docs"] + "?q=word", prefixes["_refs"] + "?to=" + url.QueryEscape("/r/docs/schema")}
}

// v82Status is the status of each of paths under cookies, redirects
// followed, joined.
func v82Status(t *testing.T, x *svc, paths []string, cookies []*http.Cookie) string {
	t.Helper()
	var out []string
	for _, p := range paths {
		got, _ := p37Follow(t, x, p, cookies, "")
		out = append(out, http.StatusText(got.status))
		if got.status == 403 && (got.header.Get("Cache-Control") != "no-store" || !strings.Contains(got.body["message"].(string), "exchange the grant again")) {
			t.Errorf("%s: 403 %v %v, want no-store and \"exchange the grant again\"", p, got.body, got.header)
		}
	}
	return strings.Join(out, ",")
}

const (
	v82Reads  = "OK,OK"
	v82Refuse = "Forbidden,Forbidden"
)

// TestV082ReadsCookieEndsOnKeyChange (SVC-10; §A.4 gs: a cookie is 403
// "where a marker's key, rules or roles would end a gs cookie (§B.11.9
// gs), its key being the one that verified the grant in {ns}, reads:{ns}
// markers included"; §B.11.9 gs: "gone or changes in any member";
// scenario 120): li reads docs whole through k1, so her cookie's marker is
// reads:docs. Once docs changes any member of k1 (its groups scope, its
// sub scope, its maxTtl, its pub), removes it, or changes the role she
// read through, her cookie is 403 at /docs/g/{gs}, at the at URL it was
// answered at, and at /_refs, until she exchanges again; a change to
// another key or role leaves it read. Before v0.82 a reads:{ns} cookie
// was never checked and read the namespace whole until it expired.
func TestV082ReadsCookieEndsOnKeyChange(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		op   map[string]any
		// again is what exchanging the same grant again gives: 200 where
		// k1 still verifies it, 401 where it no longer does; 0 where the
		// cookie holds.
		again int
	}{
		{"k1's groups scope", map[string]any{"op": "add", "path": "/keys/1/groups", "value": map[string]any{"allow": []any{"fans"}}}, 200},
		{"k1's sub scope", map[string]any{"op": "add", "path": "/keys/1/sub", "value": "user:.*"}, 200},
		{"k1's maxTtl", map[string]any{"op": "add", "path": "/keys/1/maxTtl", "value": "PT2H"}, 200},
		{"k1's can", map[string]any{"op": "replace", "path": "/keys/1/can", "value": []any{"read", "append"}}, 200},
		{"k1's pub", map[string]any{"op": "replace", "path": "/keys/1/pub", "value": clienttest.NewKey("k1").Pub}, 401},
		{"k1 removed", map[string]any{"op": "remove", "path": "/keys/1"}, 401},
		{"reader gains a verb", map[string]any{"op": "replace", "path": "/roles/reader/can", "value": []any{"read", "append"}}, 200},
		{"k2's sub scope", map[string]any{"op": "add", "path": "/keys/2/sub", "value": "user:.*"}, 0},
		{"another role added", map[string]any{"op": "add", "path": "/roles/other", "value": map[string]any{"can": []any{"read"}}}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newV82Whole(t)
			li := d.reader(d.k1)
			prefixes, cookies := d.exchange(li)
			paths := v82Paths(prefixes)
			got, at := p37Follow(t, d.x, paths[0], cookies, "")
			if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "a,b,secret" {
				t.Fatalf("a whole reader under the cookie: %d %v", got.status, got.body)
			}
			paths = append(paths, at)
			if got := v82Status(t, d.x, paths, cookies); got != v82Reads+",OK" {
				t.Fatalf("under the cookie: %s", got)
			}
			d.patch(c.op)
			if c.again == 0 {
				if got := v82Status(t, d.x, paths, cookies); got != v82Reads+",OK" {
					t.Errorf("under the cookie after a change to another key or role: %s", got)
				}
				return
			}
			if got := v82Status(t, d.x, paths, cookies); got != v82Refuse+",Forbidden" {
				t.Errorf("under the cookie after the change: %s, want 403 at each", got)
			}
			r := p37Do(t, d.x, "POST", "/edge-grants", li, "", nil, "")
			if r.status != c.again {
				t.Fatalf("exchanging again: %d %v, want %d", r.status, r.body, c.again)
			}
			if c.again != 200 {
				// k1 no longer verifies her grant, and nothing revives
				// the cookie.
				if got := v82Status(t, d.x, paths, cookies); got != v82Refuse+",Forbidden" {
					t.Errorf("under the cookie after a refused exchange: %s", got)
				}
				return
			}
			if got := v82Status(t, d.x, paths, r.cookies); got != v82Reads+",OK" {
				t.Errorf("under the cookie of the new exchange: %s", got)
			}
		})
	}
}

// TestV082CookieWithoutEntry (SVC-10; design: stored data fails closed):
// a cookie whose key was recorded without its entry digest, or with no
// row at all, as every cookie minted before this release (migration 011),
// is 403 until its reader exchanges again: reads:{ns} cookies had no row
// and read whole. None is grandfathered.
func TestV082CookieWithoutEntry(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, q string }{
		{"no entry", `UPDATE edge_gs_keys SET entry = ''`},
		{"no row", `DELETE FROM edge_gs_keys`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newV82Whole(t)
			li := d.reader(d.k1)
			prefixes, cookies := d.exchange(li)
			paths := v82Paths(prefixes)
			if got := v82Status(t, d.x, paths, cookies); got != v82Reads {
				t.Fatalf("under the cookie: %s", got)
			}
			if n := must(d.x.ix.ExecForTest(context.Background(), c.q)); n == 0 {
				t.Fatal("no edge_gs_keys row for a reads:docs marker")
			}
			if got := v82Status(t, d.x, paths, cookies); got != v82Refuse {
				t.Errorf("under a cookie recorded without its key's entry: %s, want 403", got)
			}
			_, cookies = d.exchange(li)
			if got := v82Status(t, d.x, paths, cookies); got != v82Reads {
				t.Errorf("exchanged again: %s", got)
			}
		})
	}
}

// TestV082CookieWindowOtherReaders (SVC-10; §A.4 gs: "403 until the
// reader exchanges again"; the v0.76 rule that one reader's exchange
// never rescues another's cookie, TestV076PubSharedMarker): readers of
// docs whole share the marker reads:docs and its prefixes whatever their
// key. A cookie carries its prefix and exp alone, so the index keeps the
// keys per marker and exp, and gives a cookie through other keys, or
// through a key whose entry has changed, another exp:
//
//   - al and bo read through k1, cy through k2, each with a cookie of its
//     own exp; di reads through k2 with a grant that expires when al's
//     does, and her cookie is another, expiring a second earlier;
//   - once k1's sub scope changes, al's and bo's cookies are 403; cy's
//     and di's, which no exchange through k1 minted, still read;
//   - bo exchanges again, then cy: each reads under its new cookie, and
//     al's stays 403 at the prefix, at an at URL already answered and at
//     /_refs, through the same key and through another: no exchange but
//     one for her own cookie vouches for it;
//   - al exchanges again and reads under her new cookie, which is
//     another: the one she held stays 403.
func TestV082CookieWindowOtherReaders(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	now := d.s.Now()
	alExp := now.Add(10 * time.Minute)
	al := v82Grant(d, d.k1, "user:al", alExp)
	bo := v82Grant(d, d.k1, "user:bo", now.Add(5*time.Minute))
	cy := v82Grant(d, d.k2, "user:cy", now.Add(7*time.Minute))
	di := v82Grant(d, d.k2, "user:di", alExp)
	prefixes, alC := d.exchange(al)
	_, boC := d.exchange(bo)
	_, cyC := d.exchange(cy)
	_, diC := d.exchange(di)
	if alC[0].Name != diC[0].Name || alC[0].Value == diC[0].Value {
		t.Fatalf("al's and di's cookies, through k1 and k2 for one prefix: %v, %v", alC[0], diC[0])
	}
	paths := v82Paths(prefixes)
	_, at := p37Follow(t, d.x, paths[0], alC, "")
	paths = append(paths, at)
	const reads, refused = v82Reads + ",OK", v82Refuse + ",Forbidden"
	for name, c := range map[string][]*http.Cookie{"al": alC, "bo": boC, "cy": cyC, "di": diC} {
		if got := v82Status(t, d.x, paths, c); got != reads {
			t.Fatalf("%s under its cookie: %s", name, got)
		}
	}
	d.patch(map[string]any{"op": "add", "path": "/keys/1/sub", "value": "user:.*"})
	for name, c := range map[string][]*http.Cookie{"al": alC, "bo": boC} {
		if got := v82Status(t, d.x, paths, c); got != refused {
			t.Errorf("%s under its cookie once k1 changed: %s, want 403", name, got)
		}
	}
	for name, c := range map[string][]*http.Cookie{"cy": cyC, "di": diC} {
		if got := v82Status(t, d.x, paths, c); got != reads {
			t.Errorf("%s, through k2, under a cookie no exchange through k1 minted: %s", name, got)
		}
	}
	_, boC = d.exchange(bo)
	if got := v82Status(t, d.x, paths, boC); got != reads {
		t.Errorf("bo, exchanged again: %s", got)
	}
	if got := v82Status(t, d.x, paths, alC); got != refused {
		t.Errorf("al's cookie after bo exchanged again through k1: %s, want 403", got)
	}
	_, cyC = d.exchange(cy)
	if got := v82Status(t, d.x, paths, cyC); got != reads {
		t.Errorf("cy, exchanged again: %s", got)
	}
	if got := v82Status(t, d.x, paths, alC); got != refused {
		t.Errorf("al's cookie after cy exchanged again through k2: %s, want 403", got)
	}
	_, alC2 := d.exchange(al)
	if got := v82Status(t, d.x, paths, alC2); got != reads {
		t.Errorf("al once she exchanged again: %s", got)
	}
	if got := v82Status(t, d.x, paths, alC); got != refused {
		t.Errorf("the cookie al held before, once she exchanged again: %s, want 403", got)
	}
}

// TestV082ExchangeTwoKeysOneMarker (SVC-10; §A.4 gs): one exchange with
// two grants, through k1 and k2, gives one cookie for reads:docs, which
// both keys vouch for: it is 403 once either changes. Before v0.82
// nothing was recorded for it.
func TestV082ExchangeTwoKeysOneMarker(t *testing.T) {
	t.Parallel()
	for i, path := range []string{"/keys/1/sub", "/keys/2/sub"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			d := newV82Whole(t)
			exp := d.s.Now().Add(10 * time.Minute)
			body := must(json.Marshal(map[string]any{"grants": []any{v82Grant(d, d.k1, "user:al", exp), v82Grant(d, d.k2, "user:cy", exp)}}))
			r := p37Do(t, d.x, "POST", "/edge-grants", "", string(body), nil, "")
			if r.status != 200 || len(r.cookies) != 2 {
				t.Fatalf("exchange: %d %v, %d cookies", r.status, r.body, len(r.cookies))
			}
			prefixes := map[string]string{}
			for _, p := range r.body["prefixes"].([]any) {
				prefixes[strings.Split(p.(string), "/")[1]] = p.(string)
			}
			paths := v82Paths(prefixes)
			if got := v82Status(t, d.x, paths, r.cookies); got != v82Reads {
				t.Fatalf("under the cookie: %s", got)
			}
			d.patch(map[string]any{"op": "add", "path": path, "value": "user:.*"})
			if got := v82Status(t, d.x, paths, r.cookies); got != v82Refuse {
				t.Errorf("under the cookie once key %d changed: %s, want 403", i+1, got)
			}
		})
	}
}

// TestV082ScopeCookieEndsOnAnyMember (SVC-10; §B.11.9 gs, v0.82: "or a
// key or role they came from, is gone or changes in any member"): li's
// cookie for a scope marker, through k1 with the role reader, is 403 once
// docs changes a member of k1 that its scope digest doesn't read (its sub
// scope, its maxTtl), or gives reader another verb, until she exchanges
// again, which gives the same marker. Before v0.82 only a change to the
// rules, the pub or read ended it.
func TestV082ScopeCookieEndsOnAnyMember(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		op   map[string]any
	}{
		{"k1's sub scope", map[string]any{"op": "add", "path": "/keys/1/sub", "value": "user:.*"}},
		{"k1's maxTtl", map[string]any{"op": "add", "path": "/keys/1/maxTtl", "value": "PT2H"}},
		{"reader gains a verb", map[string]any{"op": "replace", "path": "/roles/reader/can", "value": []any{"read", "append"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newV77Docs(t)
			li := d.reader(d.k1)
			prefixes, cookies := d.exchange(li)
			if !strings.HasPrefix(prefixes["docs"], "/docs/g/") {
				t.Fatalf("prefixes %v", prefixes)
			}
			paths := v82Paths(prefixes)
			if got := v82Status(t, d.x, paths, cookies); got != v82Reads {
				t.Fatalf("under the cookie: %s", got)
			}
			d.patch(c.op)
			if got := v82Status(t, d.x, paths, cookies); got != v82Refuse {
				t.Errorf("under the cookie after the change: %s, want 403", got)
			}
			again, cookies := d.exchange(li)
			if again["docs"] != prefixes["docs"] {
				t.Errorf("exchanged again: %s, was %s (the scope digest reads none of what changed)", again["docs"], prefixes["docs"])
			}
			if got := v82Status(t, d.x, paths, cookies); got != v82Reads {
				t.Errorf("exchanged again: %s", got)
			}
		})
	}
}

// TestV082GCookieEndsOnAnyMember (SVC-10; §B.11.9 gs, v0.82): a partial
// reader's cookie for reads:matches:g:{gs}, through catalog-01 with the
// role reader, is 403 once matches changes catalog-01's maxTtl, which no
// scope digest reads, or gives reader another verb, judged by matches's
// document at the checkpoint, until the reader exchanges again.
func TestV082GCookieEndsOnAnyMember(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		op   map[string]any
	}{
		{"catalog-01's maxTtl", map[string]any{"op": "replace", "path": "/keys/1/maxTtl", "value": "PT20M"}},
		{"reader gains a verb", map[string]any{"op": "replace", "path": "/roles/reader/can", "value": []any{"read", "append"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			w := newV75X(t, false)
			prefix, cookies := pub76Cookie(t, w)
			must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{c.op}))
			w.x.caughtUp("matches")
			w.x.ix.ExpireGrantChecks()
			got, _ := p37Follow(t, w.x, prefix, cookies, "")
			if got.status != 403 || !strings.Contains(got.body["message"].(string), "exchange the grant again") {
				t.Errorf("under the cookie after the change: %d %v", got.status, got.body)
			}
			if again, _ := pub76Cookie(t, w); again != prefix {
				t.Errorf("exchanged again: %s, was %s", again, prefix)
			}
		})
	}
}

// TestV082EntryDigest (SVC-10; the reference's EntryDigest, the same at
// the origin and at the index): text(trunc160(sha256(canonical({"key":
// K, "roles": R})))), over the key's whole entry and each read role's
// whole definition, so any member of either changes it; no roles are {}.
func TestV082EntryDigest(t *testing.T) {
	t.Parallel()
	key := map[string]any{"kid": "k1", "alg": "ed25519", "pub": "P", "can": []any{"read"}}
	roles := map[string]any{"reader": map[string]any{"can": []any{"read"}}}
	want := ids.Of([]byte(`{"key":{"alg":"ed25519","can":["read"],"kid":"k1","pub":"P"},"roles":{"reader":{"can":["read"]}}}`)).String()
	got := index.EntryDigestForTest(key, roles)
	if got != want {
		t.Errorf("EntryDigest %s, want %s", got, want)
	}
	if none := index.EntryDigestForTest(key, nil); none != ids.Of([]byte(`{"key":{"alg":"ed25519","can":["read"],"kid":"k1","pub":"P"},"roles":{}}`)).String() {
		t.Errorf("EntryDigest with no roles: %s", none)
	}
	key["maxTtl"] = "PT1H"
	if index.EntryDigestForTest(key, roles) == got {
		t.Error("a new member of the key leaves the digest unchanged")
	}
	if index.EntryDigestForTest(nil, roles) != "" {
		t.Error("no key has a digest")
	}
}

// TestV082BranchCookieFollowsBaseKey (SVC-10; §C.4: a branch's keys
// follow its base; EntryDigest takes "for a branch, the effective key's
// source entry"): li reads branch docs-b whole through k1, which docs-b
// copied from docs at creation. Her reads:docs-b cookie is judged by the
// entry docs gives k1 now: it is 403 once docs changes k1's sub scope,
// until she exchanges again, and once docs removes k1, though docs-b's
// own document still holds the copy.
func TestV082BranchCookieFollowsBaseKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, k1 := clienttest.NewKey("admin"), clienttest.NewKey("k1")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs"))).CreateNamespace(ctx, "docs", map[string]any{"read": "grant",
		"keys": []any{admin.Entry("*"), k1.Entry("read")}, "roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}}))
	both := []string{"docs", "docs-b"}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", both, []string{"read", "create", "append", "config", "branch"})))
	must(w.CreateDoc(ctx, "docs", "a", map[string]any{"title": "word a"}))
	must(w.CreateBranch(ctx, "docs", client.BranchRequest{Name: "docs-b"}))
	x := startSvcWith(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", both, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"docs"}, untyped: true, branches: true, now: s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
		})
	x.caughtUp("docs")
	x.caughtUp("docs-b")
	li := k1.Grant(t, s.Now(), "user:li", []string{"docs-b"}, []string{"read"}, map[string]any{"roles": []any{"reader"}})
	exchange := func() (string, []*http.Cookie) {
		t.Helper()
		return v081Exchange(t, x, li, "docs-b")
	}
	status := func(prefix string, cookies []*http.Cookie) int {
		t.Helper()
		got, _ := p37Follow(t, x, prefix, cookies, "")
		return got.status
	}
	patch := func(op map[string]any) {
		t.Helper()
		must(w.PatchConfig(ctx, "docs", must(w.NSHead(ctx, "docs")).Config, []any{op}))
		x.caughtUp("docs")
		x.ix.ExpireGrantChecks()
	}
	prefix, cookies := exchange()
	if got := status(prefix, cookies); got != 200 {
		t.Fatalf("under the cookie: %d", got)
	}
	patch(map[string]any{"op": "add", "path": "/keys/1/sub", "value": "user:.*"})
	if got := status(prefix, cookies); got != 403 {
		t.Errorf("under the cookie once the base changed k1's sub scope: %d, want 403", got)
	}
	prefix, cookies = exchange()
	if got := status(prefix, cookies); got != 200 {
		t.Fatalf("exchanged again: %d", got)
	}
	patch(map[string]any{"op": "remove", "path": "/keys/1"})
	if got := status(prefix, cookies); got != 403 {
		t.Errorf("under the cookie once the base removed k1, which the branch copied: %d, want 403", got)
	}
	if r := p37Do(t, x, "POST", "/edge-grants", li, "", nil, ""); r.status != 401 {
		t.Errorf("exchanging again once k1 is gone: %d %v, want 401", r.status, r.body)
	}
}

// TestV082StarKeyCookie (SVC-10; §A.4 gs): a whole reader through a key
// that grants every verb ("*") reads under her reads:docs cookie, whose
// key is recorded as any other's; it is 403 once that key changes in any
// member, until she exchanges again.
func TestV082StarKeyCookie(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	root := d.admin.Grant(t, d.s.Now(), "user:root", []string{"docs"}, []string{"read"})
	prefixes, cookies := d.exchange(root)
	paths := v82Paths(prefixes)
	if got := v82Status(t, d.x, paths, cookies); got != v82Reads {
		t.Fatalf("under a cookie minted through a * key: %s", got)
	}
	d.patch(map[string]any{"op": "add", "path": "/keys/0/maxTtl", "value": "PT2H"})
	if got := v82Status(t, d.x, paths, cookies); got != v82Refuse {
		t.Errorf("under the cookie once the * key changed: %s, want 403", got)
	}
	_, cookies = d.exchange(root)
	if got := v82Status(t, d.x, paths, cookies); got != v82Reads {
		t.Errorf("exchanged again: %s", got)
	}
}
