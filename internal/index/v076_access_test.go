package index_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V76-02 (v0.76): the index's markers are per namespace (§A.4 Across
// namespaces): a grant gets a marker in a namespace where it allows read,
// its read rules don't refer to /now and, fixing /resource, pass for a
// name they fix; a namespace without one is left out, and only a reader
// left with none is refused.

// TestV076AccessExchangePerNamespace (FSVC-2; §A.4 Across namespaces:
// "the service's exchange refusing only as Coverage says", Coverage: "Only
// a reader who may see none of the namespaces gets 401 or 403"): a grant
// naming pa, which it reads, and pb, where it verifies but its key doesn't
// sign read, is exchanged for /pa/g/{gs} and /_refs/g/{gs over pa's
// marker} alone, the gs a query of /_refs redirects it to. Before v0.76
// the 403 in pb refused the whole exchange.
func TestV076AccessExchangePerNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := p37Setup(t, svcedge.DefaultExchangeRate)
	op := w.s.Client(t, client.WithBearer(w.admin.Grant(t, w.s.Now(), "user:root", []string{"pb"}, []string{"read", "config"})))
	must(op.PatchConfig(ctx, "pb", must(op.NSHead(ctx, "pb")).Config, []any{map[string]any{"op": "replace", "path": "/keys/1", "value": w.issuer.Entry("append")}}))
	w.x.caughtUp("pb")
	w.x.ix.ExpireGrantChecks()
	amy := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pa", "pb"}, []string{"read"})
	if r := w.x.raw("/pb?limit=5", amy); r.status != 403 {
		t.Fatalf("a query of pb, which amy's grant doesn't read: %d %v", r.status, r.body)
	}
	prefixes, cookies := w.exchange(t, w.x, amy)
	if _, ok := prefixes["pb"]; ok || prefixes["pa"] != "/pa/g/"+w.x.gsOf("pa", amy) || len(prefixes) != 2 {
		t.Fatalf("prefixes %v, want /pa/g/%s and /_refs/g/… alone", prefixes, w.x.gsOf("pa", amy))
	}
	_, gs, _ := w.x.refsPointer("?to="+url.QueryEscape("/r/target/x"), amy)
	if prefixes["_refs"] != "/_refs/g/"+gs || gs != grantcheck.SubjectSetID([]string{"reads:pa"}) {
		t.Errorf("/_refs prefix %s, want /_refs/g/%s, over pa's marker alone", prefixes["_refs"], gs)
	}
	if got, _ := p37Follow(t, w.x, prefixes["pa"], cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "a,b" {
		t.Errorf("pa under the cookie: %d %v", got.status, got.body)
	}
	if got, _ := p37Follow(t, w.x, prefixes["_refs"]+"?to="+url.QueryEscape("/r/target/x"), cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "pa/a,pa/b,pub/p" {
		t.Errorf("/_refs under the cookie: %d %v", got.status, got.body)
	}
	// One that doesn't verify in pb (an unknown key there) is left out
	// alike; only a grant reading none of them is refused.
	other := w.admin.Grant(t, w.s.Now(), "user:amy", []string{"pb"}, []string{"read"})
	if r := p37Do(t, w.x, "POST", "/edge-grants", other, "", nil, ""); r.status != 200 {
		t.Errorf("the admin key, which reads pb: %d %v", r.status, r.body)
	}
	if r := p37Do(t, w.x, "POST", "/edge-grants", w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pb"}, []string{"read"}), "", nil, ""); r.status != 403 || len(r.cookies) != 0 {
		t.Errorf("a grant reading none of the namespaces it names: %d %v (%d cookies)", r.status, r.body, len(r.cookies))
	}
	expired := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pa", "pb"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(-time.Minute).Format(time.RFC3339)})
	if r := p37Do(t, w.x, "POST", "/edge-grants", expired, "", nil, ""); r.status != 401 || len(r.cookies) != 0 {
		t.Errorf("an expired grant: %d %v (%d cookies)", r.status, r.body, len(r.cookies))
	}
}

// TestV076AccessFixedNames (FSVC-3; §A.4 Across namespaces: a marker
// reads:{ns}:scope:{digest} "for one where it allows read otherwise, its
// rules passing now for a name it fixes if it fixes /resource"; Private
// namespaces: "a reader with no marker for {ns} gets 401 or 403"): a grant
// whose rules fix /resource and pass for none of the names they fix has
// no marker in pa: a query of pa is 403, and /_refs, which it names pa
// alone for, leaves pa out, answering as for no grant. Before
// v0.76 the query was redirected to an empty answer under its own gs, and
// /_refs counted pa as seen.
func TestV076AccessFixedNames(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	test := func(v string) map[string]any { return map[string]any{"op": "test", "path": "/resource", "value": v} }
	none := w.issuer.Grant(t, w.s.Now(), "user:fay", []string{"pa"}, []string{"read"}, map[string]any{"rules": []any{test("a"), test("b")}})
	if r := w.x.raw("/pa?limit=5", none); r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("a query of pa: %d %v %v", r.status, r.body, r.header)
	}
	// On /_refs pa is left out: what is left is pub, which everyone
	// sees, at the empty set's gs.
	q := "?to=" + url.QueryEscape("/r/target/x")
	_, pubGs, _ := w.x.refsPointer(q, "")
	if _, gs, loc := w.x.refsPointer(q, none); gs != pubGs {
		t.Errorf("/_refs naming pa alone: gs %s, want the empty set's %s", gs, pubGs)
	} else if ns := v75Namespaces(t, w.x.search(loc, none)); len(ns) != 1 || ns["pub"] == "" {
		t.Errorf("/_refs naming pa alone covers %v, want pub alone", ns)
	}
	// Fixing a, which they allow: pa's scope marker, its one hit.
	one := w.issuer.Grant(t, w.s.Now(), "user:fay", []string{"pa"}, []string{"read"}, map[string]any{"rules": []any{test("a")}})
	if got := resources(w.x.search("/pa?limit=5", one)); strings.Join(got, ",") != "a" {
		t.Errorf("a grant fixing a: %v", got)
	}
}

// TestV076AccessForeignRefsVerified (FSVC-4; changelog v0.76 "a grant at
// another gs's /_refs URL is 403, not 401"; §B.11.5 keeps 401 for a
// request without a grant that verifies): at another subject set's /_refs
// URL, a grant that verifies only in pub, a public namespace the service
// follows, is 403, no-store, not 401; a grant naming no namespace the
// service follows, one that doesn't decode, and none at all stay 401.
// Before v0.76 the first was 401 too.
func TestV076AccessForeignRefsVerified(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	q := "?to=" + url.QueryEscape("/r/target/x")
	_, _, bobLoc := w.x.refsPointer(q, w.bob)
	pub := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pub"}, []string{"read"})
	if r := w.x.raw(bobLoc, pub); r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Cache-Control") != "no-store" || r.header.Get("WWW-Authenticate") != "" {
		t.Errorf("a grant verifying in pub alone, at bob's gs: %d %v %v", r.status, r.body, r.header)
	}
	for name, tok := range map[string]string{
		"naming no followed namespace": w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"elsewhere"}, []string{"read"}),
		"not a grant":                  "not-a-grant",
		"none":                         "",
	} {
		if r := w.x.raw(bobLoc, tok); r.status != 401 || r.body["code"] != "unauthenticated" || r.header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s, at bob's gs: %d %v %v", name, r.status, r.body, r.header)
		}
	}
}

// TestV076AccessExchangePurged (§A.4 Across namespaces: the exchange
// refuses "only as Coverage says", and Coverage "leaves out ... purged
// ones"; "Only a reader who may see none of the namespaces gets 401 or
// 403"): a grant naming pa, which it reads, and pb, purged, is exchanged
// for pa's prefixes alone, as one naming an unreadable pb is; once pa is
// unreadable too, nothing is left but the purge and a 403, and the
// answer is 403, the purged namespace left out as at /_refs. Only a
// grant whose refusals are all purges is 410 (TestV073P37ExchangePurged).
// Before, the purge refused the whole exchange with 410.
func TestV076AccessExchangePurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := p37Setup(t, svcedge.DefaultExchangeRate)
	op := w.s.Client(t, client.WithBearer(w.admin.Grant(t, w.s.Now(), "user:root", []string{"pa", "pb"}, []string{"read", "config", "purge-ns"})))
	cfg := must(op.NSHead(ctx, "pb")).Config
	must(op.PatchConfig(ctx, "pb", cfg, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	must(op.PurgeNamespace(ctx, "pb", must(op.NSHead(ctx, "pb")).ID))
	amy := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pa", "pb"}, []string{"read"})
	waitFor(t, "the index to apply the purge of pb", func() bool {
		w.x.ix.ExpireGrantChecks()
		return w.x.raw("/pb?limit=5", amy).status == 410
	})
	prefixes, cookies := w.exchange(t, w.x, amy)
	if _, ok := prefixes["pb"]; ok || prefixes["pa"] != "/pa/g/"+w.x.gsOf("pa", amy) || len(prefixes) != 2 {
		t.Fatalf("prefixes %v, want /pa/g/%s and /_refs/g/… alone", prefixes, w.x.gsOf("pa", amy))
	}
	if prefixes["_refs"] != "/_refs/g/"+grantcheck.SubjectSetID([]string{"reads:pa"}) {
		t.Errorf("/_refs prefix %s, want the gs over pa's marker alone", prefixes["_refs"])
	}
	if got, _ := p37Follow(t, w.x, prefixes["pa"], cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "a,b" {
		t.Errorf("pa under the cookie: %d %v", got.status, got.body)
	}
	must(op.PatchConfig(ctx, "pa", must(op.NSHead(ctx, "pa")).Config, []any{map[string]any{"op": "replace", "path": "/keys/1", "value": w.issuer.Entry("append")}}))
	w.x.caughtUp("pa")
	w.x.ix.ExpireGrantChecks()
	if r := p37Do(t, w.x, "POST", "/edge-grants", amy, "", nil, ""); r.status != 403 || r.body["code"] != "forbidden" || len(r.cookies) != 0 {
		t.Errorf("pa unreadable, pb purged: %d %v (%d cookies)", r.status, r.body, len(r.cookies))
	}
}
