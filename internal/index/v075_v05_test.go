package index_test

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V75-05 (v0.75): the index's answers for namespaces §B.11.9 covers
// (§A.4 Private namespaces, Across namespaces): a partial reader's marker
// is reads:{ns}:g:{gs}, gs the origin's; its hits are filtered by
// visibility; its answers are at the combined checkpoint of every
// namespace visibility reads, which they list as namespaces and min may
// name; covered branches judge their bases at baseAt.

// v75x is the catalog setup of §B.11.3 against a real core: cat-season
// trusts matches, whose key catalog-01 has requireAt cat-season and a
// scope rule testing /resource by type, so its grants read matches only
// in part. root gives group:fans reader; season is under root, tr under
// root with inherit false (only chiefs); matches.derby and matches.shared
// are placed in season, matches.secret in tr; matches holds derby,
// shared, secret and opener (never placed), each referencing /r/target/x.
// One index follows matches, minting edge grants of its own.
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
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	w := &v75x{t: t, s: s, k: clienttest.NewKey("k"), cat: clienttest.NewKey("catalog-01")}
	mk := func(ns string, doc map[string]any) {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	mk("schemas", map[string]any{"read": "public", "keys": []any{w.k.Entry("*")}})
	// cat-reader's scope rule tests /resource by type: its grants read
	// cat-season in part (catReader).
	catReader := w.cat.Entry("read")
	catReader["kid"], catReader["rules"] = "cat-reader", []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}
	mk("cat-season", map[string]any{"read": "grant", "keys": []any{w.k.Entry("*"), catReader}, "catalog": map[string]any{"trust": []any{"matches"}}})
	key := w.cat.Entry("read")
	key["requireAt"], key["maxTtl"] = "cat-season", "PT15M"
	key["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}
	mk("matches", map[string]any{"read": "grant", "keys": []any{w.k.Entry("*"), key},
		"roles":    map[string]any{"reader": map[string]any{"can": []any{"read"}}},
		"catalogs": map[string]any{"cat-season": map[string]any{"place": []any{}}}})
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	w.admin = s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "user:root", all,
		[]string{"read", "create", "append", "delete", "restore", "purge", "config", "branch"})))
	w.schema = "/r/schemas/page/rev/" + must(w.admin.CreateDoc(ctx, "schemas", "page", pageSchema(true))).ID
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:fans": []any{"reader"}}})
	w.put("cat-season", "season", map[string]any{"parents": v75Parents("root")})
	w.put("cat-season", "tr", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"inherit": false, "group:chiefs": []any{"reader"}}})
	for _, n := range []string{"derby", "shared"} {
		w.put("cat-season", "matches."+n, map[string]any{"parents": v75Parents("season")})
	}
	w.put("cat-season", "matches.secret", map[string]any{"parents": v75Parents("tr")})
	for n, kind := range map[string]string{"derby": "cup", "shared": "league", "secret": "cup", "opener": "cup"} {
		w.put("matches", n, w.page(n, kind))
	}
	w.x = w.start(branches, "matches")
	return w
}

// start starts an index following nss, minting edge grants of its own.
func (w *v75x) start(branches bool, nss ...string) *svc {
	w.t.Helper()
	ev := must(edge.New([]byte("s3cret"), "", ""))
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	x := startSvcWith(w.t, w.s.Client(w.t, client.WithBearer(w.k.Grant(w.t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: filepath.Join(w.t.TempDir(), "i.db"), ns: nss, untyped: true, branches: branches, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
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

// reader is catalog-01's grant for sub in groups, with the reader role,
// reading ns in part.
func (w *v75x) reader(sub string, groups []any, ns ...string) string {
	w.t.Helper()
	if len(ns) == 0 {
		ns = []string{"matches"}
	}
	return w.cat.Grant(w.t, w.s.Now(), sub, ns, []string{"read"}, map[string]any{"groups": groups, "roles": []any{"reader"},
		"at": map[string]any{"ns": "cat-season", "id": w.head("cat-season")}, "exp": w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
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

// TestV075IndexCombinedCheckpoint (MUST-11, SVC-4, §A.4 Private
// namespaces): where §B.11.9 covers matches, a partial reader's answers
// are at the combined checkpoint of matches and cat-season, which they
// list as namespaces, and min may name cat-season; when the catalog moves
// derby out of the fans' reach while matches is unchanged, the query is
// redirected to a new at whose answer leaves derby out of hits, facets
// and counts. Before v0.75 the at was matches' ns_id, without namespaces,
// and derby stayed.
func TestV075IndexCombinedCheckpoint(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	q := "/matches?counts=%2Fkind&schema=" + url.QueryEscape(w.schema)
	loc, _, at := w.pointer(q, fan)
	want := map[string]string{"matches": w.x.ix.Checkpoint("matches"), "cat-season": w.head("cat-season")}
	if at != grantcheck.CombinedAt(want) {
		t.Fatalf("at %s, want the combined checkpoint of %v", at, want)
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
	if tags := r.header.Get("Cache-Tag"); !strings.Contains(tags, "idx:matches") || !strings.Contains(tags, "idx:cat-season") {
		t.Errorf("Cache-Tag %q", tags)
	}
	// min may name cat-season (a namespace at covers): redirected, never
	// 400; one naming another namespace is.
	if r := w.x.raw(q+"&min=cat-season:"+w.head("cat-season"), fan); r.status != 302 {
		t.Errorf("min=cat-season: %d %v", r.status, r.body)
	}
	if r := w.x.raw(q+"&min=schemas:"+w.head("schemas"), fan); r.status != 400 {
		t.Errorf("min=schemas: %d %v", r.status, r.body)
	}

	// The catalog moves derby under tr; matches doesn't change.
	cp := w.x.ix.Checkpoint("matches")
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75Parents("tr")})
	if r := w.x.raw(loc, fan); r.status != 200 {
		t.Errorf("the old at, kept: %d", r.status)
	}
	loc2, _, at2 := w.pointer(q, fan)
	if at2 == at || w.x.ix.Checkpoint("matches") != cp {
		t.Fatalf("at %s after the catalog moved (was %s); matches %s (was %s)", at2, at, w.x.ix.Checkpoint("matches"), cp)
	}
	b = w.x.search(loc2, fan)
	if got := strings.Join(resources(b), ","); got != "shared" {
		t.Errorf("after the move fan sees %s, want shared", got)
	}
	if ns := v75Namespaces(t, b); ns["cat-season"] != w.head("cat-season") || ns["matches"] != cp {
		t.Errorf("namespaces %v", ns)
	}
	if c := b["counts"].(map[string]any)["/kind"].(map[string]any); c["cup"] != nil || c["league"] != 1.0 {
		t.Errorf("counts after the move %v", c)
	}
	for _, h := range b["hits"].([]any) {
		if _, ok := h.(map[string]any)["/kind"]; !ok {
			t.Errorf("hit without its facet: %v", h)
		}
	}
	// An at URL whose at is neither current nor kept: redirected.
	stale := strings.Replace(loc2, "/at/"+at2, "/at/"+cp, 1)
	if r := w.x.raw(stale, fan); r.status != 302 || r.header.Get("Location") != loc2 {
		t.Errorf("stale at: %d %s, want %s", r.status, r.header.Get("Location"), loc2)
	}
	// A direct $access entry for user:fan makes its sub decide: a new gs
	// at the next at, while the grant still reads the kept answer at loc2
	// under its gs as of that at.
	w.put("cat-season", "fanclub", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"user:fan": []any{"reader"}}})
	loc3, gs3, _ := w.pointer(q, fan)
	if strings.Contains(loc2, "/g/"+gs3+"/") {
		t.Fatalf("gs unchanged by a direct entry: %s", loc3)
	}
	if r := w.x.raw(loc2, fan); r.status != 200 || strings.Join(resources(r.body), ",") != "shared" {
		t.Errorf("the kept answer at its own gs: %d %v", r.status, r.body)
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
	for _, n := range []string{"a1", "a3", "a5"} {
		w.put("cat-season", "matches."+n, map[string]any{"parents": v75Parents("season")})
	}
	for _, n := range []string{"a1", "a2", "a3", "a4", "a5"} {
		w.put("matches", n, w.page(n, "cup"))
	}
	w.x.caughtUp("matches")
	fan := w.reader("user:fan", []any{"fans"})
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
// with the same key-scope rule, one in fans (whom root's $access gives
// reader) and one in interns (whom it gives nothing), get different
// subject sets, the gs inside each marker reads:matches:g:{gs} being the
// origin's own, at the origin's at; the interns reader sees nothing.
// Before v0.75 both had reads:matches:scope:{digest} and saw derby.
func TestV075IndexSubjectSets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	intern := w.reader("user:intern", []any{"interns"})
	_, fgs, fat := w.pointer("/matches", fan)
	_, igs, _ := w.pointer("/matches", intern)
	if fgs == igs {
		t.Fatalf("fans and interns share gs %s", fgs)
	}
	if got := resources(w.x.search("/matches", intern)); len(got) != 0 {
		t.Errorf("intern sees %v", got)
	}
	if got := strings.Join(resources(w.x.search("/matches", fan)), ","); got != "derby,shared" {
		t.Errorf("fan sees %s", got)
	}
	// The origin's own subject sets for the same grants, which its
	// exchange gives a partial reader as the prefix /ns/matches/g/{gs}
	// (§B.11.9 Edge grants): the gs inside the index's marker is the
	// origin's, and the index's at the combined checkpoint over the
	// origin's heads (§B.11.9 URLs).
	for _, c := range []struct{ tok, gs string }{{fan, fgs}, {intern, igs}} {
		req := must(http.NewRequestWithContext(ctx, "POST", w.s.URL+"/edge-grants", nil))
		req.Header.Set("Authorization", "Bearer "+c.tok)
		res := must(noFollow.Do(req))
		var body struct{ Prefixes []string }
		err := json.NewDecoder(res.Body).Decode(&body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || len(body.Prefixes) != 1 || !strings.HasPrefix(body.Prefixes[0], "/ns/matches/g/") {
			t.Fatalf("the origin's exchange: %d %v %v", res.StatusCode, err, body)
		}
		ogs := strings.TrimPrefix(body.Prefixes[0], "/ns/matches/g/")
		if want := grantcheck.SubjectSetID([]string{"reads:matches:g:" + ogs}); c.gs != want {
			t.Errorf("index gs %s, want that of reads:matches:g:%s (%s)", c.gs, ogs, want)
		}
	}
	if want := grantcheck.CombinedAt(map[string]string{"matches": w.head("matches"), "cat-season": w.head("cat-season")}); fat != want {
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
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "matches/derby,matches/shared" || v75Namespaces(t, got.body)["cat-season"] == "" {
		t.Fatalf("/_refs under the cookie: %d %v", got.status, got.body)
	}
	// A restart reads what the marker stands for from the database.
	w.x.stop()
	w.x = startSvcWith(t, w.x.core, svcOpts{db: w.x.dbPath, ns: []string{"matches"}, untyped: true, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
		})
	w.x.caughtUp("matches")
	got, _ = p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("under the cookie after a restart: %d %v", got.status, got.body)
	}
	// catalog-01's scope rule changes: the cookie no longer stands for it.
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
// reader of covered matches is at the combined checkpoint over matches
// and cat-season, which namespaces lists and min may name, its hits from
// matches filtered by visibility. Before v0.75 at covered matches alone,
// min=cat-season:… was 400 and every hit the rules allow was shown.
func TestV075IndexRefs(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	at, _, loc := w.x.refsPointer("?to=/r/target/x", fan)
	want := map[string]string{"matches": w.x.ix.Checkpoint("matches"), "cat-season": w.head("cat-season")}
	if at != grantcheck.CombinedAt(want) {
		t.Errorf("at %s, want the combined checkpoint of %v", at, want)
	}
	b := w.x.search(loc, fan)
	if got := refsAllHits(b); got != "matches/derby matches/shared" {
		t.Errorf("hits %s", got)
	}
	if !maps.Equal(v75Namespaces(t, b), want) {
		t.Errorf("namespaces %v, want %v", b["namespaces"], want)
	}
	r := w.x.raw(loc, fan)
	if tags := r.header.Get("Cache-Tag"); !strings.Contains(tags, "idx:cat-season") {
		t.Errorf("Cache-Tag %q", tags)
	}
	if r := w.x.raw("/_refs?to=/r/target/x&min=cat-season:"+w.head("cat-season"), fan); r.status != 302 {
		t.Errorf("min=cat-season: %d %v", r.status, r.body)
	}
	// The catalog moves: a new at, derby gone.
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75Parents("tr")})
	at2, _, loc2 := w.x.refsPointer("?to=/r/target/x&min=cat-season:"+w.head("cat-season"), fan)
	if at2 == at {
		t.Fatal("at unchanged after the catalog moved")
	}
	if got := refsAllHits(w.x.search(loc2, fan)); got != "matches/shared" {
		t.Errorf("hits after the move %s", got)
	}
}

// TestV075IndexBranch (SVC-15, §B.11.9 Branches): in a covered branch's
// preview index a partial reader sees a document only where its base had
// a live one as of the branch's at, and its root's catalog places it: so
// final, created only in matches-r7, is never its hit, though placed,
// while an unrestricted reader sees it. The base at baseAt joins at.
func TestV075IndexBranch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, true)
	base := w.head("matches")
	must(w.admin.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	w.put("matches-r7", "final", w.page("final", "cup"))
	w.put("cat-season", "matches.final", map[string]any{"parents": v75Parents("season")})
	w.x.caughtUp("matches-r7")
	fan := w.reader("user:fan", []any{"fans"}, "matches-r7")
	loc, _, at := w.pointer("/matches-r7", fan)
	b := w.x.search(loc, fan)
	if got := strings.Join(resources(b), ","); got != "derby,shared" {
		t.Errorf("fan sees %s in the branch, want derby,shared", got)
	}
	ns := v75Namespaces(t, b)
	if ns["matches"] != base || ns["matches-r7"] != w.x.ix.Checkpoint("matches-r7") || ns["cat-season"] != w.head("cat-season") || at != grantcheck.CombinedAt(ns) {
		t.Errorf("namespaces %v at %s (base at %s)", ns, at, base)
	}
	all := w.k.Grant(t, w.s.Now(), "user:root", []string{"matches-r7"}, []string{"read"})
	if got := resources(w.x.search("/matches-r7", all)); !slices.Contains(got, "final") {
		t.Errorf("unrestricted reader sees %v in the branch", got)
	}
	// Across the base and the branch: one ns_id for matches, its own
	// checkpoint, the branch's standing for the base at baseAt.
	both := w.reader("user:fan", []any{"fans"}, "matches", "matches-r7")
	_, _, rloc := w.x.refsPointer("?to=/r/target/x", both)
	rb := w.x.search(rloc, both)
	if got := refsAllHits(rb); got != "matches/derby matches/shared matches-r7/derby matches-r7/shared" {
		t.Errorf("/_refs across the base and the branch: %s", got)
	}
	if ns := v75Namespaces(t, rb); ns["matches"] != w.x.ix.Checkpoint("matches") || ns["matches-r7"] == "" || ns["cat-season"] == "" || len(ns) != 3 {
		t.Errorf("/_refs namespaces %v", ns)
	}
}

// TestV075IndexUncovered: a namespace whose catalog doesn't trust it is
// read as before v0.75: the scope marker, matches' own ns_id, every hit
// the grant's rules allow.
func TestV075IndexUncovered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
	fan := w.reader("user:fan", []any{"fans"})
	_, _, at := w.pointer("/matches", fan)
	b := w.x.search("/matches", fan)
	if at != w.x.ix.Checkpoint("matches") || b["namespaces"] != nil || strings.Join(resources(b), ",") != "derby,opener,secret,shared" {
		t.Errorf("uncovered: at %s, %v", at, b)
	}
}

// TestV075IndexCatalog (§A.4, §B.11.9 Catalogs): a catalog §B.11.9 covers,
// followed as a namespace of its own, answers a partial reader with the
// nodes the node test shows it, at the combined checkpoint over the
// catalog and its trusted members: never a placement whose item doesn't
// exist (final), nor one under tr; folders count only through a key
// whose rules don't refer to /resource, which catalog-01's do.
func TestV075IndexCatalog(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	w.put("cat-season", "matches.final", map[string]any{"parents": v75Parents("season")})
	x := w.start(false, "cat-season", "matches")
	fan := w.catReader("user:fan", "fans")
	r := x.raw("/cat-season", fan)
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.HasPrefix(loc, "/cat-season/g/") {
		t.Fatalf("pointer: %d %s %v", r.status, loc, r.body)
	}
	b := x.search(loc, fan)
	if got := strings.Join(resources(b), ","); got != "matches.derby,matches.shared" {
		t.Errorf("fan sees %s in cat-season", got)
	}
	want := map[string]string{"cat-season": x.ix.Checkpoint("cat-season"), "matches": x.ix.Checkpoint("matches")}
	if ns := v75Namespaces(t, b); !maps.Equal(ns, want) || b["at"] != grantcheck.CombinedAt(want) {
		t.Errorf("namespaces %v at %v, want %v", ns, b["at"], want)
	}
	all := w.k.Grant(t, w.s.Now(), "user:root", []string{"cat-season"}, []string{"read"})
	if got := resources(x.search("/cat-season", all)); len(got) != 7 {
		t.Errorf("unrestricted reader sees %v", got)
	}
}

// TestV075IndexCookieKeepsAll (§B.11.5, §B.11.9 gs): a cookie whose
// subjects leave out some of the reader's groups ("partial") is 403 at a
// checkpoint where a deciding rule tests /principal/groups otherwise than
// by naming groups, so every group decides, while a cookie whose subjects
// keep every group is still served.
func TestV075IndexCookieKeepsAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	exchange := func(tok string) (string, []*http.Cookie) {
		r := p37Do(t, w.x, "POST", "/edge-grants", tok, "", nil, "")
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.body)
		}
		for _, p := range r.body["prefixes"].([]any) {
			if strings.HasPrefix(p.(string), "/matches/") {
				return p.(string), r.cookies
			}
		}
		t.Fatalf("no prefix for matches: %v", r.body)
		return "", nil
	}
	ip, ic := exchange(w.reader("user:intern", []any{"fans", "interns"}))
	fp, fc := exchange(w.reader("user:fan", []any{"fans"}))
	for _, c := range []struct {
		prefix  string
		cookies []*http.Cookie
	}{{ip, ic}, {fp, fc}} {
		if got, _ := p37Follow(t, w.x, c.prefix, c.cookies, ""); got.status != 200 {
			t.Fatalf("%s: %d %v", c.prefix, got.status, got.body)
		}
	}
	// A role neither grant carries, whose rule tests the groups by a
	// negation: every group decides.
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/roles/outsider",
		"value": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups",
			"schema": map[string]any{"contains": map[string]any{"const": "chiefs"}}}}}}}}))
	w.x.caughtUp("matches")
	if got, _ := p37Follow(t, w.x, ip, ic, ""); got.status != 403 {
		t.Errorf("a partial subject set where every group decides: %d %v", got.status, got.body)
	}
	if got, _ := p37Follow(t, w.x, fp, fc, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Errorf("a whole subject set: %d %v", got.status, got.body)
	}
}
