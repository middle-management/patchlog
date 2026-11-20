package index_test

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/index"
)

// V75-05 (v0.75): the index's answers for namespaces §B.11.9 covers
// (§A.4 Private namespaces, Across namespaces): a partial reader's marker
// is reads:{ns}:g:{gs}, gs the origin's; its hits are filtered by
// visibility; its answers are at the combined checkpoint of every
// namespace visibility reads, which they list as namespaces and min may
// name; covered branches judge their bases at baseAt.

// v75x is two private namespaces against a real core: cat-season and
// matches, whose key reader-01 has a scope rule allowing /resource derby
// and shared only, so its grants read matches only in part; matches holds
// derby, shared, secret and opener, each referencing /r/target/x. One
// index follows matches, minting edge grants of its own.
type v75x struct {
	t      *testing.T
	s      *clienttest.Server
	k, cat clienttest.Key
	admin  *client.Client
	x      *svc
	schema string
}

func newV75X(t *testing.T, branches bool) *v75x {
	t.Helper()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	w.x = w.start(branches, "matches")
	return w
}

// newV75XOn is newV75X's setup on s, with no index started.
func newV75XOn(t *testing.T, s *clienttest.Server) *v75x {
	t.Helper()
	ctx := context.Background()
	w := &v75x{t: t, s: s, k: clienttest.NewKey("k"), cat: clienttest.NewKey("reader-01")}
	mk := func(ns string, doc map[string]any) {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	mk("schemas", map[string]any{"read": "public", "keys": []any{w.k.Entry("*")}})
	// cat-reader's scope rule tests /resource by type: its grants read
	// cat-season in part (catReader).
	catReader := w.cat.Entry("read")
	catReader["kid"], catReader["rules"] = "cat-reader", []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}
	mk("cat-season", map[string]any{"read": "grant", "keys": []any{w.k.Entry("*"), catReader}})
	key := w.cat.Entry("read")
	key["maxTtl"] = "PT15M"
	key["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": v75Visible}}
	mk("matches", map[string]any{"read": "grant", "keys": []any{w.k.Entry("*"), key},
		"roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}})
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	w.admin = s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "user:root", all,
		[]string{"read", "create", "append", "delete", "restore", "purge", "config", "branch"})))
	w.schema = "/r/schemas/page/rev/" + must(w.admin.CreateDoc(ctx, "schemas", "page", pageSchema(true))).ID
	for n, kind := range map[string]string{"derby": "cup", "shared": "league", "secret": "cup", "opener": "cup"} {
		w.put("matches", n, w.page(n, kind))
	}
	return w
}

// v75Visible is the schema reader-01's rule tests /resource with: the
// names its grants read in matches.
var v75Visible = map[string]any{"pattern": "^(derby|shared)$"}

// start starts an index following nss, minting edge grants of its own.
func (w *v75x) start(branches bool, nss ...string) *svc {
	w.t.Helper()
	ev := must(edge.New([]byte("s3cret"), "", ""))
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	x := startSvcWith(w.t, w.s.Client(w.t, client.WithBearer(w.k.Grant(w.t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(w.t.TempDir(), "i.db"), ns: nss, untyped: true, branches: branches, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), index.DefaultExchangeRate, ev
		})
	for _, ns := range nss {
		x.caughtUp(ns)
	}
	return x
}

// catReader is a partial reader of cat-season: a cat-reader grant for
// sub in groups.
func (w *v75x) catReader(sub string, groups ...any) string {
	return clienttest.Mint(w.t, w.cat.Priv, map[string]any{"kid": "cat-reader", "sub": sub, "groups": groups, "ns": []any{"cat-season"},
		"can": []any{"read"}, "exp": w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
}

func v75Parents(names ...string) []any {
	out := []any{}
	for _, n := range names {
		out = append(out, map[string]any{"href": "/r/cat-season/" + n})
	}
	return out
}

func (w *v75x) page(title, kind string) map[string]any {
	return map[string]any{"$schema": w.schema, "title": title, "kind": kind, "related": []any{"/r/target/x"}}
}

// put writes doc as ns/name's head, creating or replacing it.
func (w *v75x) put(ns, name string, doc map[string]any) {
	w.t.Helper()
	ctx := context.Background()
	h, err := w.admin.Head(ctx, ns, name)
	if err == nil && h.State == client.Live {
		must(w.admin.Append(ctx, ns, name, h.ID, []any{map[string]any{"op": "replace", "path": "", "value": doc}}))
		return
	}
	must(w.admin.CreateDoc(ctx, ns, name, doc))
}

func (w *v75x) head(ns string) string {
	w.t.Helper()
	return must(w.admin.NSHead(context.Background(), ns)).ID
}

// reader is reader-01's grant for sub in groups, with the reader role,
// reading ns in part.
func (w *v75x) reader(sub string, groups []any, ns ...string) string {
	w.t.Helper()
	if len(ns) == 0 {
		ns = []string{"matches"}
	}
	return w.cat.Grant(w.t, w.s.Now(), sub, ns, []string{"read"}, map[string]any{"groups": groups, "roles": []any{"reader"},
		"exp": w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
}

// readerVia is reader through key k, with a block rule on /resource that
// makes it a partial reader of matches as reader-01's scope rule does.
func (w *v75x) readerVia(sub string, groups []any) string {
	w.t.Helper()
	return w.k.Grant(w.t, w.s.Now(), sub, []string{"matches"}, []string{"read"}, map[string]any{"groups": groups, "roles": []any{"reader"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": v75Visible}},
		"exp":   w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
}

// pointer asks path with token and returns the at URL it redirects to,
// its gs and its at.
func (w *v75x) pointer(path, token string) (loc, gs, at string) {
	w.t.Helper()
	r := w.x.raw(path, token)
	loc = r.header.Get("Location")
	p := strings.Split(strings.SplitN(loc, "?", 2)[0], "/")
	if r.status != 302 || len(p) != 6 || p[2] != "g" || p[4] != "at" || r.header.Get("Cache-Control") != "private, no-store" {
		w.t.Fatalf("GET %s: %d %q %v %v", path, r.status, loc, r.body, r.header)
	}
	return loc, p[3], p[5]
}

func v75Namespaces(t *testing.T, body map[string]any) map[string]string {
	t.Helper()
	m, ok := body["namespaces"].(map[string]any)
	if !ok {
		t.Fatalf("no namespaces in %v", body)
	}
	out := map[string]string{}
	for k, v := range m {
		out[k] = v.(string)
	}
	return out
}

// TestV075IndexCheckpoint (MUST-11, SVC-4, §A.4 Private namespaces):
// where §B.11.9 covers matches, a partial reader's answers are at the
// index's checkpoint of matches, which they list as namespaces, its hits,
// facets and counts filtered by visibility; an unrestricted reader's
// list no namespaces.
func TestV075IndexCheckpoint(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	q := "/matches?counts=%2Fkind&schema=" + url.QueryEscape(w.schema)
	loc, _, at := w.pointer(q, fan)
	cp := w.x.ix.Checkpoint("matches")
	want := map[string]string{"matches": cp}
	if at != cp {
		t.Fatalf("at %s, want %s", at, cp)
	}
	b := w.x.search(loc, fan)
	if got := strings.Join(resources(b), ","); got != "derby,shared" {
		t.Errorf("fan sees %s, want derby,shared", got)
	}
	if b["at"] != at || !maps.Equal(v75Namespaces(t, b), want) {
		t.Errorf("answer at %v namespaces %v, want %s %v", b["at"], b["namespaces"], at, want)
	}
	if c := b["counts"].(map[string]any)["/kind"].(map[string]any); c["cup"] != 1.0 || c["league"] != 1.0 {
		t.Errorf("counts %v", c)
	}
	r := w.x.raw(loc, fan)
	if tags := r.header.Get("Cache-Tag"); !strings.Contains(tags, "idx:matches") {
		t.Errorf("Cache-Tag %q", tags)
	}
	if r := w.x.raw(q+"&min=schemas:"+w.head("schemas"), fan); r.status != 400 {
		t.Errorf("min=schemas: %d %v", r.status, r.body)
	}
	// An unrestricted reader keeps matches' own ns_id and every hit.
	all := w.k.Grant(t, w.s.Now(), "user:root", []string{"matches"}, []string{"read"})
	_, _, uat := w.pointer(q, all)
	ub := w.x.search(q, all)
	if uat != cp || ub["namespaces"] != nil || strings.Join(resources(ub), ",") != "derby,opener,secret,shared" {
		t.Errorf("unrestricted: at %s, %v", uat, ub)
	}
}

// TestV075IndexPagesFilled (MUST-11, §A.4 Private namespaces): every page
// but the last holds limit visible hits, the hidden ones skipped.
func TestV075IndexPagesFilled(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	for _, n := range []string{"a1", "a2", "a3", "a4", "a5"} {
		w.put("matches", n, w.page(n, "cup"))
	}
	w.x.caughtUp("matches")
	fan := w.k.Grant(t, w.s.Now(), "user:fan", []string{"matches"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^(a1|a3|a5|derby|shared)$"}}}})
	var got []string
	path := "/matches?limit=2"
	for range 10 {
		b := w.x.search(path, fan)
		hits := resources(b)
		got = append(got, hits...)
		next, _ := b["next"].(string)
		if next == "" {
			break
		}
		if len(hits) != 2 {
			t.Errorf("a page but the last with %d hits: %v", len(hits), hits)
		}
		path = "/matches?after=" + next + "&limit=2"
	}
	if strings.Join(got, ",") != "a1,a3,a5,derby,shared" {
		t.Errorf("pages %v", got)
	}
}

// TestV075IndexSubjectSets (SVC-5, §A.4, §B.11.9 gs): two partial readers
// with the same rules through the same key, whatever their groups, share
// a subject set, the gs inside the marker reads:matches:g:{gs} being the
// origin's own, at the index's checkpoint of matches; a reader with other
// rules gets another.
func TestV075IndexSubjectSets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	intern := w.reader("user:intern", []any{"interns"})
	_, fgs, fat := w.pointer("/matches", fan)
	_, igs, _ := w.pointer("/matches", intern)
	if fgs != igs {
		t.Fatalf("fans and interns: gs %s and %s", fgs, igs)
	}
	narrow := w.cat.Grant(t, w.s.Now(), "user:fan", []string{"matches"}, []string{"read"}, map[string]any{"roles": []any{"reader"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^d"}}},
		"exp":   w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	if _, ngs, _ := w.pointer("/matches", narrow); ngs == fgs {
		t.Errorf("other rules share gs %s", ngs)
	}
	if got := resources(w.x.search("/matches", narrow)); strings.Join(got, ",") != "derby" {
		t.Errorf("narrow sees %v", got)
	}
	// The origin's own subject set for the same grant, which its exchange
	// gives a partial reader as the prefix /ns/matches/g/{gs} (§B.11.9
	// Edge grants): the gs inside the index's marker is the origin's.
	req := must(http.NewRequestWithContext(ctx, "POST", w.s.URL+"/edge-grants", nil))
	req.Header.Set("Authorization", "Bearer "+fan)
	res := must(noFollow.Do(req))
	var body struct{ Prefixes []string }
	err := json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || len(body.Prefixes) != 1 || !strings.HasPrefix(body.Prefixes[0], "/ns/matches/g/") {
		t.Fatalf("the origin's exchange: %d %v %v", res.StatusCode, err, body)
	}
	ogs := strings.TrimPrefix(body.Prefixes[0], "/ns/matches/g/")
	if want := grantcheck.SubjectSetID([]string{"reads:matches:g:" + ogs}); fgs != want {
		t.Errorf("index gs %s, want that of reads:matches:g:%s (%s)", fgs, ogs, want)
	}
	if want := w.x.ix.Checkpoint("matches"); fat != want {
		t.Errorf("index at %s, want %s", fat, want)
	}
}

// TestV075IndexCookies (SVC-5, §B.11.9 gs, §B.11.5): the index's edge
// grant for a partial reader stands for its marker reads:matches:g:{gs},
// whose subjects and filter it records: a read under the cookie alone is
// filtered by visibility as under the grant, after a restart too; once
// the rules the scope digest covers change, the cookie is 403 at the new
// at, until the reader exchanges again.
func TestV075IndexCookies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	r := p37Do(t, w.x, "POST", "/edge-grants", fan, "", nil, "")
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	_, gs, _ := w.pointer("/matches", fan)
	var prefix string
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/matches/") {
			prefix = p.(string)
		}
	}
	if prefix != "/matches/g/"+gs {
		t.Fatalf("prefixes %v, want /matches/g/%s", r.body["prefixes"], gs)
	}
	got, _ := p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("under the cookie: %d %v", got.status, got.body)
	}
	// So across namespaces, under the /_refs cookie, whose marker in
	// matches is the same.
	var refs string
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/_refs/") {
			refs = p.(string)
		}
	}
	got, _ = p37Follow(t, w.x, refs+"?to=/r/target/x", r.cookies, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "matches/derby,matches/shared" || v75Namespaces(t, got.body)["matches"] == "" {
		t.Fatalf("/_refs under the cookie: %d %v", got.status, got.body)
	}
	// A restart reads what the marker stands for from the database.
	w.x.stop()
	w.x = startSvcWith(t, w.x.core, svcOpts{db: w.x.dbPath, ns: []string{"matches"}, untyped: true, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), index.DefaultExchangeRate
		})
	w.x.caughtUp("matches")
	got, _ = p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("under the cookie after a restart: %d %v", got.status, got.body)
	}
	// reader-01's scope rule changes: the cookie no longer stands for it.
	doc := must(w.admin.NSDoc(ctx, "matches", w.head("matches"))).Value
	keys := doc["keys"].([]any)
	keys[1].(map[string]any)["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "minLength": 1}}}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": keys}}))
	w.x.caughtUp("matches")
	got, _ = p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 403 {
		t.Errorf("under the cookie once the rules changed: %d %v", got.status, got.body)
	}
}

// TestV075IndexRefs (SVC-6, §A.4 Across namespaces): /_refs by a partial
// reader of covered matches is at the checkpoint of matches, which
// namespaces lists, its hits from matches filtered by visibility.
func TestV075IndexRefs(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	_, _, loc := w.x.refsPointer("?to=/r/target/x", fan)
	want := map[string]string{"matches": w.x.ix.Checkpoint("matches")}
	b := w.x.search(loc, fan)
	if got := refsAllHits(b); got != "matches/derby matches/shared" {
		t.Errorf("hits %s", got)
	}
	if !maps.Equal(v75Namespaces(t, b), want) {
		t.Errorf("namespaces %v, want %v", b["namespaces"], want)
	}
}
