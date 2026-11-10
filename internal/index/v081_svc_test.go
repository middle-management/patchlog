package index_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// v081Exchange exchanges tok at x and returns the prefix it gives for
// kind (a namespace, or "_refs") and the cookies.
func v081Exchange(t *testing.T, x *svc, tok, kind string) (string, []*http.Cookie) {
	t.Helper()
	r := p37Do(t, x, "POST", "/edge-grants", tok, "", nil, "")
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/"+kind+"/") {
			return p.(string), r.cookies
		}
	}
	t.Fatalf("no prefix for %s: %v", kind, r.body)
	return "", nil
}

// TestV081SvcIndexAllGroups (§B.11.9 gs, v0.78; CONFORMANCE Tree-derived
// access 78): a partial reader's gs holds every group of the caller, so
// li and bo, who differ only in contractors and interns, which nothing
// names, have different markers (before v0.78 both were fans and
// "partial"), and both see what fans see.
func TestV081SvcIndexAllGroups(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans", "contractors"})
	bo := w.reader("user:bo", []any{"fans", "interns"})
	_, lgs, _ := w.pointer("/matches", li)
	_, bgs, _ := w.pointer("/matches", bo)
	if lgs == bgs {
		t.Errorf("li and bo share gs %s", lgs)
	}
	for _, tok := range []string{li, bo} {
		if got := strings.Join(resources(w.x.search("/matches", tok)), ","); got != "derby,shared" {
			t.Errorf("hits %s", got)
		}
	}
}

// TestV081SvcIndexStoredPartial (§B.11.5, §B.11.9 gs, v0.78): a g: marker
// whose subjects were recorded holding "partial", under an earlier draft,
// is 403 under its cookie at once, whatever the catalogs' rules: no gs
// leaves a group out, and served as recorded it would show what a group
// it left out hides.
func TestV081SvcIndexStoredPartial(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	prefix, cks := v081Exchange(t, w.x, w.reader("user:fan", []any{"fans"}), "matches")
	got, at := p37Follow(t, w.x, prefix, cks, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("the cookie: %d %v", got.status, got.body)
	}
	if err := w.x.ix.PlantPartial(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{prefix, at} {
		if got, _ := p37Follow(t, w.x, path, cks, ""); got.status != 403 || got.header.Get("Cache-Control") != "no-store" {
			t.Errorf("a stored partial set at %s: %d %q %v", path, got.status, got.header.Get("Cache-Control"), got.body)
		}
	}
}

// TestV081SvcIndexNowRoles (§A.4 gs markers, §C.2 item 5, v0.78): a role
// with a rule on /now doesn't count for read, so a grant carrying it and
// prefixed (/resource ^pub-) gets docs' scope marker and reads pub- names
// alone, on a query and on /_refs; once prefixed gains a rule on /now,
// the marker's cookie is 403 until the reader exchanges again, and the
// grant then has no marker.
func TestV081SvcIndexNowRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	clock := map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": "2999-01-01T00:00:00Z"}}
	pubOnly := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^pub-"}}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{
		"read": "public", "keys": []any{admin.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs"))).CreateNamespace(ctx, "docs", map[string]any{
		"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")},
		"roles": map[string]any{
			"clock":    map[string]any{"can": []any{"read"}, "rules": []any{clock}},
			"prefixed": map[string]any{"can": []any{"read"}, "rules": []any{pubOnly}},
		},
	}))
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"docs", "schemas"}, []string{"read", "create", "config"})))
	sch := "/r/schemas/page/rev/" + must(root.CreateDoc(ctx, "schemas", "page", pageSchema(true))).ID
	target := "/r/target/x"
	for _, n := range []string{"pub-a", "b"} {
		must(root.CreateDoc(ctx, "docs", n, map[string]any{"$schema": sch, "title": "doc " + n, "related": []any{target}}))
	}
	ev := must(edge.New([]byte("s3cret"), "", ""))
	x := startSvcWith(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"docs"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"docs"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		})
	x.caughtUp("docs")

	tok := issuer.Grant(t, s.Now(), "user:li", []string{"docs"}, nil, map[string]any{"roles": []any{"clock", "prefixed"}})
	only := issuer.Grant(t, s.Now(), "user:li", []string{"docs"}, nil, map[string]any{"roles": []any{"prefixed"}})
	if got := strings.Join(resources(x.search("/docs", tok)), ","); got != "pub-a" {
		t.Errorf("query hits %s", got)
	}
	q := "?to=" + url.QueryEscape(target)
	_, gs, loc := x.refsPointer(q, tok)
	if _, gsOnly, _ := x.refsPointer(q, only); gs != gsOnly {
		t.Errorf("/_refs gs %s, without the /now role %s", gs, gsOnly)
	}
	if got := refsAllHits(x.search(loc, tok)); got != "docs/pub-a" {
		t.Errorf("/_refs hits %s", got)
	}
	if r := x.raw("/docs", issuer.Grant(t, s.Now(), "user:li", []string{"docs"}, nil, map[string]any{"roles": []any{"clock"}})); r.status != 403 {
		t.Errorf("the /now role alone: %d %v", r.status, r.body)
	}

	_, cks := v081Exchange(t, x, tok, "_refs")
	got, _ := p37Follow(t, x, loc, cks, "")
	if got.status != 200 || refsAllHits(got.body) != "docs/pub-a" {
		t.Fatalf("the cookie on /_refs: %d %v", got.status, got.body)
	}
	dprefix, dcks := v081Exchange(t, x, tok, "docs")
	if got, _ := p37Follow(t, x, dprefix, dcks, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "pub-a" {
		t.Fatalf("the cookie on docs: %d %v", got.status, got.body)
	}

	// prefixed gains a rule on /now: it no longer counts for read.
	must(root.PatchConfig(ctx, "docs", must(root.NSHead(ctx, "docs")).Config, []any{
		map[string]any{"op": "add", "path": "/roles/prefixed/rules/-", "value": clock}}))
	x.caughtUp("docs")
	x.ix.ExpireGrantChecks()
	if got, _ := p37Follow(t, x, dprefix, dcks, ""); got.status != 403 {
		t.Errorf("the old cookie on docs: %d %v", got.status, got.body)
	}
	if got, _ := p37Follow(t, x, "/_refs/g/"+gs+q, cks, ""); got.status != 403 {
		t.Errorf("the old cookie on /_refs: %d %v", got.status, got.body)
	}
	if r := x.raw("/docs", tok); r.status != 403 {
		t.Errorf("the grant once every role refers to /now: %d %v", r.status, r.body)
	}
}
