package index_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/seal"
)

// v073P22World is pa and pb (read: grant) and pub (public), each with an
// untyped document a, followed by one index. amy reads pa, bob pa and pb.
type v073P22World struct {
	s        *clienttest.Server
	x        *svc
	root     *client.Client
	admin    clienttest.Key
	issuer   clienttest.Key
	amy, bob string
}

func v073P22Setup(t *testing.T, extra ...string) *v073P22World {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	nss := append([]string{"pa", "pb", "pub"}, extra...)
	for _, ns := range nss {
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		if ns == "pub" {
			doc["read"] = "public"
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append", "config", "purge-ns"})))
	for _, ns := range nss {
		must(root.CreateDoc(ctx, ns, "a", map[string]any{"title": ns, "related": []any{"/r/target/x"}}))
	}
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, untyped: true, now: s.Now, minWait: 300 * time.Millisecond})
	for _, ns := range nss {
		x.caughtUp(ns)
	}
	return &v073P22World{s: s, x: x, root: root, admin: admin, issuer: issuer,
		amy: issuer.Grant(t, s.Now(), "user:amy", []string{"pa"}, []string{"read"}),
		bob: issuer.Grant(t, s.Now(), "user:bob", []string{"pa", "pb"}, []string{"read"})}
}

// TestV073MinRefusedListed (IX-10, §A.5, §12.1): a 400 for refused mins
// lists every one refused, as given, in its body's min, no-store, with one
// message for a namespace the reader can't see and one the service doesn't
// follow; a min it accepts isn't listed. So on /_refs, and for malformed
// mins.
func TestV073MinRefusedListed(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	x := w.x
	pb, pub := x.ix.Checkpoint("pb"), x.ix.Checkpoint("pub")
	refused := func(r resp, want ...string) {
		t.Helper()
		if r.status != 400 || r.body["code"] != "bad_input" || r.header.Get("Cache-Control") != "no-store" || fmt.Sprint(r.body["min"]) != fmt.Sprint(want) {
			t.Errorf("%d %v %v, want min %v", r.status, r.body, r.header, want)
		}
	}
	both := x.raw("/pa?limit=5&min=pb:"+pb+"&min=pub:"+pub+"&min=zz:"+pb, w.amy)
	refused(both, "pb:"+pb, "zz:"+pb)
	hidden, unknown := x.raw("/pa?min=pb:"+pb, w.amy), x.raw("/pa?min=zz:"+pb, w.amy)
	refused(hidden, "pb:"+pb)
	refused(unknown, "zz:"+pb)
	if hidden.body["message"] != unknown.body["message"] || both.body["message"] != hidden.body["message"] {
		t.Errorf("messages differ: %v, %v, %v", hidden.body["message"], unknown.body["message"], both.body["message"])
	}
	// /_refs: the same body.
	q := "/_refs?to=" + url.QueryEscape("/r/target/x")
	refs := x.raw(q+"&min=pb:"+pb+"&min=pa:"+x.ix.Checkpoint("pa")+"&min=zz:"+pb, w.amy)
	refused(refs, "pb:"+pb, "zz:"+pb)
	if refs.body["message"] != hidden.body["message"] {
		t.Errorf("/_refs message %v", refs.body["message"])
	}
	// Malformed ones are listed too, as the tree service lists them.
	refused(x.raw("/pa?min=garbage&min=pb:"+pb+"&min=pa:zzz", w.amy), "garbage", "pa:zzz")
	refused(x.raw(q+"&min="+pb, w.amy), pb)
}

// TestV073RefsMinPurged (IX-11, §A.4 Coverage, §A.5): on /_refs, a min
// naming a purged namespace the service follows counts as reached and
// redirects to the current at without a read check, whoever asks, from
// the pointer and from a kept at whose answer would include every other
// min.
func TestV073RefsMinPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := v073P22Setup(t, "gone")
	x := w.x
	must(w.root.PatchConfig(ctx, "gone", must(w.root.NSHead(ctx, "gone")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.root.PurgeNamespace(ctx, "gone", must(w.root.NSHead(ctx, "gone")).ID))
	waitFor(t, "the purge", func() bool { return x.ix.Checkpoint("gone") == purged })

	q := "?to=" + url.QueryEscape("/r/target/x")
	for name, tok := range map[string]string{"anonymous": "", "amy": w.amy} {
		_, _, loc := x.refsPointer(q, tok)
		if r := x.raw("/_refs"+q+"&min=gone:"+purged, tok); r.status != 302 || r.header.Get("Location") != loc {
			t.Errorf("%s, pointer: %d %s %v, want %s", name, r.status, r.header.Get("Location"), r.body, loc)
		}
	}
	// A kept at that includes amy's min of pa still goes to the current at
	// once a purged namespace's min is given too.
	_, _, old := x.refsPointer(q, w.amy)
	paAt := x.ix.Checkpoint("pa")
	if r := x.raw(old+"&min=pa:"+paAt, w.amy); r.status != 302 || r.header.Get("Location") != old {
		t.Fatalf("kept at with pa's min: %d %s", r.status, r.header.Get("Location"))
	}
	must(w.root.CreateDoc(ctx, "pa", "b", map[string]any{"title": "pa"}))
	x.caughtUp("pa")
	_, _, cur := x.refsPointer(q, w.amy)
	if cur == old {
		t.Fatal("pa's write didn't move amy's at")
	}
	if r := x.raw(old+"&min=pa:"+paAt+"&min=gone:"+purged, w.amy); r.status != 302 || r.header.Get("Location") != cur {
		t.Errorf("kept at with a purged min: %d %s, want %s", r.status, r.header.Get("Location"), cur)
	}
}

// TestV073BareMinOnce (IX-13, §A.5): a bare ?min={ns_id} is given at most
// once on a query of one namespace; the same value twice is one, as min
// is a set. Two different ones are 400.
func TestV073BareMinOnce(t *testing.T) {
	t.Parallel()
	w := v073Setup(t, map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}})
	w.doc(t, "a", map[string]any{"title": "one"})
	x := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"items"}, minWait: 300 * time.Millisecond})
	first := x.caughtUp("items")
	w.doc(t, "b", map[string]any{"title": "two"})
	cur := x.caughtUp("items")
	if r := x.raw("/items?min="+first+"&min="+first, ""); r.status != 302 || r.header.Get("Location") != "/items/at/"+cur {
		t.Errorf("the same bare min twice: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	if r := x.raw("/items?min="+first+"&min="+cur, ""); r.status != 400 || r.body["code"] != "bad_input" {
		t.Errorf("two bare mins: %d %v", r.status, r.body)
	}
	// The {ns}:{ns_id} form repeats.
	if r := x.raw("/items?min=items:"+first+"&min=items:"+cur, ""); r.status != 302 || r.header.Get("Location") != "/items/at/"+cur {
		t.Errorf("two qualified mins: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
}

// TestV073MinSkippedNamespace (carry-over of P08, §A.4, §A.5, §12.1): a min
// naming a followed namespace whose keys the service can't fetch for now
// is answered alike by a query of another namespace and by /_refs: 503
// behind, at once, to a reader who may see it, and the 400 listing it to
// one who can't.
func TestV073MinSkippedNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	keys := []any{admin.Entry("*"), issuer.Entry("read")}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": keys,
		"encryption": map[string]any{"level": "sealed"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pub"))).CreateNamespace(ctx, "pub", map[string]any{"read": "public", "keys": keys}))
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:w", []string{"sec", "pub"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	id := must(createNonced(w, "sec", "a", map[string]any{"title": "secret"})).NSID
	must(w.CreateDoc(ctx, "pub", "a", map[string]any{"related": []any{"/r/target/x"}}))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	// The first POST /keys (opening sec's document) passes; later ones,
	// for the epoch key, fail with a 503: sec is skipped for now.
	fk := &v073FailKeys{path: "/ns/sec/keys", after: 1, rt: transport}
	fk.armed.Store(true)
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec", "pub"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec", "pub"}, untyped: true, now: s.Now,
		hc: &http.Client{Transport: fk}, minWait: time.Minute}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("pub")
	waitFor(t, "sec skipped", func() bool {
		for _, st := range x.raw("/_status", "").body["namespaces"].([]any) {
			if m := st.(map[string]any); m["ns"] == "sec" && m["skipped"] == true {
				return true
			}
		}
		return false
	})
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec", "pub"}, []string{"read"})
	amy := issuer.Grant(t, s.Now(), "user:amy", []string{"pub"}, []string{"read"})
	q := "/_refs?to=" + url.QueryEscape("/r/target/x")
	for _, p := range []string{"/pub?min=sec:" + id, q + "&min=sec:" + id} {
		start := time.Now()
		r := x.raw(p, bob)
		if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s, a reader of sec: %d %v %v", p, r.status, r.body, r.header)
		}
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%s: waited %s for a namespace the index can't follow now", p, d)
		}
		if r := x.raw(p, amy); r.status != 400 || fmt.Sprint(r.body["min"]) != "[sec:"+id+"]" {
			t.Errorf("%s, a grant that doesn't read sec: %d %v", p, r.status, r.body)
		}
	}
}

// gsOf asks /{ns}?q=… with tok and returns the subject set its pointer
// redirects to.
func (s *svc) gsOf(ns, tok string) string {
	s.t.Helper()
	r := s.raw("/"+ns+"?limit=5", tok)
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.HasPrefix(loc, "/"+ns+"/g/") {
		s.t.Fatalf("/%s pointer: %d %s %v", ns, r.status, loc, r.body)
	}
	return strings.Split(loc, "/")[3]
}

// TestV073PrivateGsMarkers (IX-14, IX-15, §A.4): a private namespace's
// results are served under gs = SubjectSetID([marker]), as /_refs computes
// it: reads:{ns} for a grant that would be issued a namespace-wide edge
// grant, whatever its subjects and groups, else reads:{ns}:scope:{digest},
// shared by readers limited by the same rules and /principal values. A
// grant whose read rules refer to /now finds the namespace unreadable:
// 403, and /_refs leaves it out.
func TestV073PrivateGsMarkers(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	x, s, is := w.x, w.s, w.issuer
	whole := grantcheck.SubjectSetID([]string{"reads:pa"})
	for _, tok := range []string{
		w.amy,
		is.Grant(t, s.Now(), "user:cy", []string{"pa"}, []string{"read"}, map[string]any{"groups": []any{"editors"}}),
		is.Grant(t, s.Now(), "user:dee", []string{"pa", "pb"}, []string{"read"}, map[string]any{"groups": []any{"x", "y"}}),
	} {
		if gs := x.gsOf("pa", tok); gs != whole {
			t.Errorf("a whole reader's gs %s, want %s", gs, whole)
		}
	}
	// The same subject set as amy's /_refs answer, which reads pa alone of
	// the private namespaces.
	q := "?to=" + url.QueryEscape("/r/target/x")
	if _, gs, _ := x.refsPointer(q, w.amy); gs != whole {
		t.Errorf("amy's /_refs gs %s, want %s", gs, whole)
	}
	onlyA := func(sub string, groups ...any) string {
		return is.Grant(t, s.Now(), sub, []string{"pa"}, []string{"read"}, map[string]any{"groups": groups,
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	}
	li, lu := x.gsOf("pa", onlyA("user:li", "editors")), x.gsOf("pa", onlyA("user:lu", "x"))
	if li != lu || li == whole {
		t.Errorf("readers limited alike: gs %s and %s (whole %s)", li, lu, whole)
	}
	if _, gs, _ := x.refsPointer(q, onlyA("user:li", "editors")); gs != li {
		t.Errorf("a limited reader's /_refs gs %s, want %s", gs, li)
	}
	notA := is.Grant(t, s.Now(), "user:mo", []string{"pa"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"not": map[string]any{"const": "a"}}}}})
	if gs := x.gsOf("pa", notA); gs == li || gs == whole {
		t.Errorf("other rules share gs %s", gs)
	}
	// A rule on /now, even one that passes now: unreadable.
	soon := is.Grant(t, s.Now(), "user:soon", []string{"pa"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": "2999-01-01T00:00:00Z"}}}})
	if r := x.raw("/pa?limit=5", soon); r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("a rule on /now: %d %v %v", r.status, r.body, r.header)
	}
	if _, gs, loc := x.refsPointer(q, soon); gs != grantcheck.SubjectSetID(nil) || fmt.Sprint(x.search(loc, soon)["namespaces"]) != "map[pub:"+x.ix.Checkpoint("pub")+"]" {
		t.Errorf("a rule on /now, /_refs: %s", loc)
	}
}

// TestV073ForeignGs (IX-16, §A.4, §B.11.5): a grant reads only at its own
// gs: at another gs's at URL it is 403 forbidden, no-store, with or
// without min, on a query and on /_refs; without a grant /_refs answers
// 401. Only the pointer and an at URL without /g/{gs} redirect into the
// reader's gs.
func TestV073ForeignGs(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	x := w.x
	at := x.ix.Checkpoint("pa")
	bobGs, amyGs := x.gsOf("pb", w.bob), x.gsOf("pa", w.amy)
	q := "?to=" + url.QueryEscape("/r/target/x")
	_, bobRefs, bobLoc := x.refsPointer(q, w.bob)
	for _, p := range []string{
		"/pa/g/" + bobGs + "/at/" + at + "?limit=5",
		"/pa/g/" + bobGs + "/at/" + at + "?limit=5&min=pa:" + at,
		bobLoc, bobLoc + "&min=pa:" + at,
	} {
		r := x.raw(p, w.amy)
		if r.status != 403 || r.body["code"] != "forbidden" || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Location") != "" {
			t.Errorf("%s: %d %v %v", p, r.status, r.body, r.header)
		}
	}
	if r := x.raw(bobLoc, ""); r.status != 401 || r.body["code"] != "unauthenticated" {
		t.Errorf("/_refs at bob's gs without a grant: %d %v", r.status, r.body)
	}
	// Redirected into the reader's own gs: the pointer, and an at URL
	// without /g/{gs}.
	own := "/pa/g/" + amyGs + "/at/" + at + "?limit=5"
	for _, p := range []string{"/pa?limit=5", "/pa/at/" + at + "?limit=5"} {
		if r := x.raw(p, w.amy); r.status != 302 || r.header.Get("Location") != own {
			t.Errorf("%s: %d %s", p, r.status, r.header.Get("Location"))
		}
	}
	if r := x.raw(own, w.amy); r.status != 200 {
		t.Errorf("own gs: %d %v", r.status, r.body)
	}
	if _, gs, _ := x.refsPointer(q, w.amy); gs == bobRefs {
		t.Errorf("amy shares bob's /_refs gs %s", gs)
	}
}

// TestV073PrivatePointerNoStore (IX-17, §A.4 table): a 302 whose Location
// adds /g/{gs} is Cache-Control: private, no-store, on a query and on
// /_refs, as is any redirect decided by a grant; a public pointer keeps
// the head-pointer class.
func TestV073PrivatePointerNoStore(t *testing.T) {
	t.Parallel()
	w := v073P22Setup(t)
	x := w.x
	q := "/_refs?to=" + url.QueryEscape("/r/target/x")
	for _, p := range []string{"/pa?limit=5", "/pa/at/" + x.ix.Checkpoint("pa") + "?limit=5", q} {
		r := x.raw(p, w.amy)
		if r.status != 302 || !strings.Contains(r.header.Get("Location"), "/g/") || r.header.Get("Cache-Control") != "private, no-store" {
			t.Errorf("%s: %d %s %v", p, r.status, r.header.Get("Location"), r.header)
		}
	}
	if r := x.raw("/pub?limit=5", ""); r.status != 302 || r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" {
		t.Errorf("public pointer: %d %v", r.status, r.header)
	}
}
