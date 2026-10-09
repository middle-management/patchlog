package index_test

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/seal"
)

// pageSchema is a schema whose x-ref locations cover the three reference
// forms (§6.5); "copy" holds an embedded copy that is not a reference.
func pageSchema(related bool) map[string]any {
	rel := map[string]any{"type": "array", "items": map[string]any{"type": "string", "x-ref": map[string]any{}}}
	if !related {
		rel = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	}
	return map[string]any{
		"$schema": d2020, "type": "object",
		"properties": map[string]any{
			"$schema": map[string]any{"type": "string"},
			"title":   map[string]any{"type": "string", "x-index": "text"},
			"hero":    map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}},
			"related": rel,
			"trigger": map[string]any{"type": "string", "x-ref": map[string]any{"key": "/triggers"}},
			"body":    map[string]any{"type": "string"},
			"copy":    map[string]any{"type": "object"},
			"kind":    map[string]any{"type": "string", "x-index": "facet"},
		},
	}
}

func refHits(t *testing.T, body map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range body["hits"].([]any) {
		m := h.(map[string]any)
		var rs []string
		for _, r := range m["refs"].([]any) {
			rm := r.(map[string]any)
			rs = append(rs, rm["path"].(string)+"="+rm["ref"].(string))
		}
		out[m["resource"].(string)] = strings.Join(rs, " ")
	}
	return out
}

func TestReferenceQueries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	for _, ns := range []string{"schemas", "pages", "logic"} {
		must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
	}
	rev1 := must(c.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	p1 := "/r/schemas/page/rev/" + rev1.ID
	// The head of the schema no longer marks "related": documents that pin
	// revision 1 are still walked with it (§A.1, §A.2).
	rev2 := must(c.Append(ctx, "schemas", "page", rev1.ID, []any{
		map[string]any{"op": "replace", "path": "/properties/related", "value": pageSchema(false)["properties"].(map[string]any)["related"]},
	}))
	p2 := "/r/schemas/page/rev/" + rev2.ID
	other := must(c.CreateDoc(ctx, "schemas", "other", pageSchema(true)))
	po := "/r/schemas/other/rev/" + other.ID

	r3 := must(c.CreateDoc(ctx, "logic", "route-3", map[string]any{"triggers": []any{map[string]any{"id": "t-42"}}}))
	pinned := "/r/logic/route-3/rev/" + r3.ID
	live := "/r/logic/route-3"
	entry := "/r/logic/route-3#t-42"
	mk := func(name, schema string, f map[string]any) *client.WriteResult {
		if schema != "" {
			f["$schema"] = schema
		}
		return must(c.CreateDoc(ctx, "pages", name, f))
	}
	mk("a", p1, map[string]any{"title": "A", "kind": "x", "related": []any{live, "/r/logic/route-4"}, "hero": pinned, "trigger": entry,
		"body": "see " + live + " and " + pinned, "copy": map[string]any{"related": []any{live}}})
	mk("b", p1, map[string]any{"title": "B", "related": []any{"/r/logic/route-4"}})
	mk("c", "", map[string]any{"title": "C untyped", "related": []any{live}, "hero": pinned}) // no $schema: no references
	mk("d", po, map[string]any{"title": "D", "kind": "x", "related": []any{live}})
	mk("e", p2, map[string]any{"title": "E, schema head without x-ref", "related": []any{live}})
	mk("f", p1, map[string]any{"title": "F", "related": []any{"/r/pages/a", "/r/logic/route-5/rev/1" + strings.Repeat("a", 32)}})

	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pages"}, untyped: true})
	x.caughtUp("pages")
	enc := func(s string) string { return url.QueryEscape(s) }

	// Any form: live, pinned, entry. Untyped (c), prose and embedded copies
	// (a's body and copy), and a schema head without x-ref (e) don't count.
	b := x.expect("/pages?ref="+enc(live), "a", "d")
	if got := refHits(t, b); got["a"] != "/hero="+pinned+" /related/0="+live+" /trigger="+entry || got["d"] != "/related/0="+live {
		t.Errorf("refs %v", got)
	}

	// One pinned revision, which also finds f's dangling-looking pin only
	// for its own target.
	b = x.expect("/pages?ref="+enc(pinned), "a")
	if got := refHits(t, b); got["a"] != "/hero="+pinned {
		t.Errorf("pinned refs %v", got)
	}
	x.expect("/pages?ref="+enc("/r/logic/route-5/rev/1"+strings.Repeat("a", 32)), "f")
	x.expect("/pages?ref=" + enc("/r/logic/route-5/rev/1"+strings.Repeat("b", 32)))

	// One entry, pinned or not.
	b = x.expect("/pages?ref="+enc("/r/logic/route-3#t-42"), "a")
	if got := refHits(t, b); got["a"] != "/trigger="+entry {
		t.Errorf("entry refs %v", got)
	}
	x.expect("/pages?ref=" + enc("/r/logic/route-3#t-43"))

	// Same-namespace target, other namespaces, unreferenced targets.
	x.expect("/pages?ref="+enc("/r/pages/a"), "f")
	x.expect("/pages?ref="+enc("/r/logic/route-4"), "a", "b")
	x.expect("/pages?ref=" + enc("/r/logic/nothing"))

	// Combined with the other filters.
	x.expect("/pages?ref="+enc(live)+"&schema="+enc("/r/schemas/other"), "d")
	x.expect("/pages?ref="+enc(live)+"&schema="+enc("/r/schemas/page"), "a")
	x.expect("/pages?ref="+enc(live)+"&q=D", "d")
	x.expect("/pages?ref="+enc("/r/logic/route-4")+"&sort=/title&limit=1", "a")

	// Without q or sort, a ref query pages as /_refs does (§A.4): after is
	// a bare resource name, a plain bound, and next the after of the
	// following page. Counts still count every hit. Queries with q or sort
	// keep their offsets.
	route4 := "/pages?ref=" + enc("/r/logic/route-4")
	if b := x.expect(route4+"&limit=1", "a"); b["next"] != "a" {
		t.Errorf("next %v", b["next"])
	}
	if b := x.expect(route4+"&limit=1&after=a", "b"); b["next"] != nil {
		t.Errorf("next on the last page %v", b["next"])
	}
	x.expect("/pages?ref="+enc(live)+"&after=a0", "d")
	if b := x.expect("/pages?ref="+enc(live)+"&after=a&counts=/kind", "d"); fmt.Sprint(b["counts"]) != "map[/kind:[map[count:2 value:x]]]" {
		t.Errorf("counts after a: %v", b["counts"])
	}
	if b := x.expect(route4+"&sort=/title&limit=1", "a"); !strings.Contains(fmt.Sprint(b["next"]), "after=1") {
		t.Errorf("next with sort %v", b["next"])
	}
	x.expect(route4+"&sort=/title&after=1", "b")
	for _, q := range []string{route4 + "&sort=/title&after=a", route4 + "&q=B&after=a", route4 + "&after=a&after=b"} {
		if r := x.raw(q, ""); r.status != 400 {
			t.Errorf("%s: %d", q, r.status)
		}
	}

	// Without ref, hits carry no refs.
	if _, ok := x.search("/pages?q=A", "")["hits"].([]any)[0].(map[string]any)["refs"]; ok {
		t.Error("refs without ref=")
	}

	// Bad input (§7): malformed, empty, repeated, unknown parameters.
	for _, q := range []string{
		"ref=garbage", "ref=", "ref=/r/logic", "ref=/r/Logic/x", "ref=/r/logic/route-3/rev/xyz",
		"ref=" + enc("/r/logic/route-3#"), "ref=" + enc("/r/logic/route-3#a b"), "ref=/r/logic/route-3%23",
		"ref=" + enc(live) + "&ref=" + enc("/r/logic/route-4"), "refs=" + enc(live),
	} {
		if r := x.raw("/pages?"+q, ""); r.status != 400 {
			t.Errorf("%s: %d", q, r.status)
		}
	}

	// Cache tags: every hit's resource, so a purge removes the result.
	r := x.raw("/pages/at/"+x.ix.Checkpoint("pages")+"?ref="+enc(live), "")
	if r.status != 200 || !strings.Contains(r.header.Get("Cache-Tag"), "r:pages/a") || !strings.Contains(r.header.Get("Cache-Tag"), "r:pages/d") {
		t.Errorf("tags %v", r.header)
	}

	// Updates drop stale references: a loses the hero and the entry, and
	// its live reference moves.
	h := must(c.Head(ctx, "pages", "a"))
	must(c.Append(ctx, "pages", "a", h.ID, []any{
		map[string]any{"op": "remove", "path": "/hero"}, map[string]any{"op": "remove", "path": "/trigger"},
		map[string]any{"op": "replace", "path": "/related/0", "value": "/r/logic/route-9"},
	}))
	x.caughtUp("pages")
	x.expect("/pages?ref="+enc(live), "d")
	x.expect("/pages?ref=" + enc(pinned))
	x.expect("/pages?ref=" + enc("/r/logic/route-3#t-42"))
	x.expect("/pages?ref="+enc("/r/logic/route-9"), "a")

	// Moving a document to the schema revision whose x-ref is gone drops
	// its references; typing an untyped one adds them.
	h = must(c.Head(ctx, "pages", "d"))
	must(c.Append(ctx, "pages", "d", h.ID, []any{map[string]any{"op": "replace", "path": "/$schema", "value": p2}}))
	h = must(c.Head(ctx, "pages", "c"))
	must(c.Append(ctx, "pages", "c", h.ID, []any{map[string]any{"op": "add", "path": "/$schema", "value": p1}}))
	x.caughtUp("pages")
	x.expect("/pages?ref="+enc(live), "c")
	x.expect("/pages?ref="+enc(pinned), "c")

	// Delete and purge.
	rows := x.ix.CountRows("pages")
	h = must(c.Head(ctx, "pages", "c"))
	must(c.Delete(ctx, "pages", "c", h.ID))
	x.caughtUp("pages")
	x.expect("/pages?ref=" + enc(live))
	if n := x.ix.CountRows("pages"); n >= rows {
		t.Errorf("rows %d after delete, %d before", n, rows)
	}
	h = must(c.Head(ctx, "pages", "f"))
	must(c.Purge(ctx, "pages", "f", h.ID, false))
	x.caughtUp("pages")
	x.expect("/pages?ref=" + enc("/r/pages/a"))
	x.expect("/pages?ref="+enc("/r/logic/route-4"), "a", "b")

	// A restart keeps them; a rebuild replays to the same answer.
	x.stop()
	y := startSvc(t, c, svcOpts{db: x.dbPath, ns: []string{"pages"}, untyped: true, rebuild: true})
	y.caughtUp("pages")
	y.expect("/pages?ref="+enc("/r/logic/route-9"), "a")
	y.expect("/pages?ref="+enc("/r/logic/route-4"), "a", "b")

	// A purged namespace leaves no references.
	cfg := must(c.NSHead(ctx, "pages")).Config
	must(c.PatchConfig(ctx, "pages", cfg, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(c.PurgeNamespace(ctx, "pages", must(c.NSHead(ctx, "pages")).ID))
	waitFor(t, "purge-ns", func() bool { return y.raw("/pages", "").status == 410 })
	if n := y.ix.CountRows("pages"); n != 0 {
		t.Errorf("%d rows left after purge-ns", n)
	}
}

// An index database written before v0.44 has no refs table: opening it
// replays the logs instead of serving an index that never saw a reference.
func TestReferenceUpgrade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	for _, ns := range []string{"schemas", "pages"} {
		must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
	}
	sch := must(c.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	must(c.CreateDoc(ctx, "pages", "a", map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{"/r/pages/b"}}))
	db := filepath.Join(t.TempDir(), "i.db")
	x := startSvc(t, c, svcOpts{db: db, ns: []string{"pages"}})
	x.caughtUp("pages")
	x.stop()
	// Simulate the old database.
	{
		o := startSvc(t, c, svcOpts{db: db, ns: []string{"pages"}, noRun: true})
		if _, err := o.ix.DropRefsForTest(); err != nil {
			t.Fatal(err)
		}
		o.stop()
	}
	y := startSvc(t, c, svcOpts{db: db, ns: []string{"pages"}})
	y.caughtUp("pages")
	y.expect("/pages?ref=%2Fr%2Fpages%2Fb", "a")
}

// Private namespaces: reference queries follow the catalog-listing rules,
// are routed under the reader's subject set, keep the encoded query, and
// show only what the reader may read.
func TestReferencePrivate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create", "append"})))
	sch := must(writer.CreateDoc(ctx, "sec", "schema", pageSchema(true)))
	ref := "/r/sec/schema/rev/" + sch.ID
	for _, n := range []string{"a", "b"} {
		must(writer.CreateDoc(ctx, "sec", n, map[string]any{"$schema": ref, "related": []any{"/r/other/thing"}, "trigger": "/r/other/thing#t-1"}))
	}
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})))
	x := startSvc(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now})
	x.caughtUp("sec")

	q := "?ref=" + url.QueryEscape("/r/other/thing#t-1")
	if r := x.raw("/sec"+q, ""); r.status != 401 {
		t.Errorf("no grant: %d", r.status)
	}
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"})
	r := x.raw("/sec"+q, bob)
	if r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/g/") || !strings.HasSuffix(r.header.Get("Location"), "/sec"+q) {
		t.Fatalf("pointer: %d %v", r.status, r.header)
	}
	b := x.search("/sec"+q, bob)
	if got := refHits(t, b); fmt.Sprint(got) != "map[a:/trigger=/r/other/thing#t-1 b:/trigger=/r/other/thing#t-1]" {
		t.Errorf("refs %v", got)
	}
	// Private results are not served to shared caches.
	if cc := x.raw(strings.Replace(r.header.Get("Location"), "/sec", "/sec/at/"+x.ix.Checkpoint("sec"), 1), bob).header.Get("Cache-Control"); !strings.Contains(cc, "private") {
		t.Errorf("Cache-Control %q", cc)
	}
}

// Sealed namespaces: a reference result is sealed like any other (§E.2.6),
// refs included.
func TestReferenceSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"sec", "schemas"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "sec" {
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"read", "create", "append", "purge", "config"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, all)), client.WithKeys(client.NewKeys(nil)))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	ref := "/r/schemas/page/rev/" + sch.ID
	must(createNonced(w, "sec", "a", map[string]any{"$schema": ref, "title": "secret", "related": []any{"/r/other/thing"}}))
	must(createNonced(w, "sec", "b", map[string]any{"$schema": ref, "title": "secret"}))

	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})), client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("sec")

	f := x.fetch("/sec?ref="+url.QueryEscape("/r/other/thing"), "")
	if f.header.Get("Content-Type") != seal.ContentType || strings.Contains(string(f.body), "other") {
		t.Fatalf("not sealed: %s %s", f.header.Get("Content-Type"), f.body)
	}
	pt := must(derived.OpenView(string(f.body), epochKeys(t, w, "sec"), derived.View{NS: "sec", Target: f.path}))
	b := decodeJSON(t, pt)
	if got := refHits(t, b); fmt.Sprint(got) != "map[a:/related/0=/r/other/thing]" {
		t.Errorf("refs %v in %s", got, pt)
	}
}

// Branch preview indexes match targets as written, and hits are the
// branch's versions of the referrers (§A.4).
func TestReferenceBranchPreview(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	for _, ns := range []string{"schemas", "pages"} {
		must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
	}
	sch := must(c.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	ref := "/r/schemas/page/rev/" + sch.ID
	must(c.CreateDoc(ctx, "pages", "a", map[string]any{"$schema": ref, "related": []any{"/r/pages/b"}}))
	must(c.CreateDoc(ctx, "pages", "b", map[string]any{"$schema": ref, "related": []any{"/r/pages/a"}}))
	must(c.CreateBranch(ctx, "pages", client.BranchRequest{Name: "pages-draft"}))
	h := must(c.Head(ctx, "pages-draft", "a"))
	must(c.Append(ctx, "pages-draft", "a", h.ID, []any{map[string]any{"op": "replace", "path": "/related/0", "value": "/r/pages/new"}}))

	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pages"}, branches: true})
	x.caughtUp("pages")
	x.caughtUp("pages-draft")
	e := func(p string) string { return url.QueryEscape(p) }
	x.expect("/pages?ref="+e("/r/pages/b"), "a")
	x.expect("/pages?ref=" + e("/r/pages/new"))
	// The branch's own version of a, and b read through from the base,
	// both as written: the target is named in the base's terms.
	b := x.expect("/pages-draft?ref="+e("/r/pages/new"), "a")
	if got := refHits(t, b); got["a"] != "/related/0=/r/pages/new" {
		t.Errorf("draft refs %v", got)
	}
	x.expect("/pages-draft?ref=" + e("/r/pages/b"))
	x.expect("/pages-draft?ref="+e("/r/pages/a"), "b")
	if u := b["hits"].([]any)[0].(map[string]any)["url"].(string); !strings.Contains(u, "/r/pages-draft/a/rev/") {
		t.Errorf("draft hit url %s", u)
	}
}
