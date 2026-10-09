package index_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/seal"
)

// refsAllHits lists the hits of a /_refs answer as ns/resource.
func refsAllHits(body map[string]any) string {
	var out []string
	for _, h := range body["hits"].([]any) {
		m := h.(map[string]any)
		out = append(out, m["ns"].(string)+"/"+m["resource"].(string))
	}
	return strings.Join(out, " ")
}

// refsPointer asks GET /_refs{query} and returns the at and gs it
// redirects to, and the Location.
func (s *svc) refsPointer(query, token string) (at, gs, loc string) {
	s.t.Helper()
	r := s.raw("/_refs"+query, token)
	loc = r.header.Get("Location")
	p := strings.Split(strings.SplitN(loc, "?", 2)[0], "/")
	if r.status != 302 || len(p) != 6 || p[1] != "_refs" || p[2] != "at" || p[4] != "g" {
		s.t.Fatalf("GET /_refs%s: %d %q %v", query, r.status, loc, r.body)
	}
	return p[3], p[5], loc
}

// GET /_refs asks every namespace the index follows that the reader may
// read (§A.4 "Across namespaces"): two readers who see different
// namespaces get different subject sets and checkpoints, and writes in a
// namespace one can't see never move its at.
func TestRefsAcrossNamespaces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	for _, ns := range []string{"schemas", "pub", "pa", "pb"} {
		doc := map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}
		if ns == "pa" || ns == "pb" {
			doc = map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"schemas", "pub", "pa", "pb"}, []string{"read", "create", "append", "purge"})))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	mk := func(ns, name string, f map[string]any) {
		f["$schema"] = "/r/schemas/page/rev/" + sch.ID
		must(w.CreateDoc(ctx, ns, name, f))
	}
	mk("pub", "p1", map[string]any{"related": []any{x}})
	mk("pub", "p2", map[string]any{"related": []any{"/r/target/y"}})
	mk("pa", "a1", map[string]any{"related": []any{x, "/r/pa/a1"}})
	mk("pa", "a2", map[string]any{"trigger": x + "#t-1"})
	mk("pb", "b1", map[string]any{"related": []any{x}})
	mk("pb", "b2", map[string]any{"related": []any{"/r/target/y", x}})

	nss := []string{"pub", "pa", "pb"}
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	idx := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, now: s.Now})
	for _, ns := range nss {
		idx.caughtUp(ns)
	}
	editors := map[string]any{"groups": []any{"editors"}}
	amy := issuer.Grant(t, s.Now(), "user:amy", []string{"pa"}, []string{"read"}, editors)
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"pa", "pb"}, []string{"read"}, editors)
	li := issuer.Grant(t, s.Now(), "user:li", []string{"pb"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b1"}}})
	q := "?to=" + url.QueryEscape(x)

	// amy reads pa and the public namespace: a private pointer and answer.
	amyAt, amyGs, amyLoc := idx.refsPointer(q, amy)
	if r := idx.raw("/_refs"+q, amy); r.header.Get("Cache-Control") != "private, no-cache" || r.header.Get("Vary") != "Authorization" || !strings.HasSuffix(amyLoc, q) {
		t.Errorf("pointer %s %v", amyLoc, r.header)
	}
	r := idx.raw(amyLoc, amy)
	if r.status != 200 || refsAllHits(r.body) != "pa/a1 pa/a2 pub/p1" {
		t.Fatalf("amy: %d %v", r.status, r.body)
	}
	if fmt.Sprint(r.body["namespaces"]) != fmt.Sprint(map[string]any{"pa": idx.ix.Checkpoint("pa"), "pub": idx.ix.Checkpoint("pub")}) || r.body["at"] != amyAt {
		t.Errorf("namespaces %v at %v", r.body["namespaces"], r.body["at"])
	}
	h := r.body["hits"].([]any)
	if a1 := h[0].(map[string]any); fmt.Sprint(a1["refs"]) != "[map[path:/related/0 ref:"+x+"]]" || a1["self"] != nil ||
		!strings.HasPrefix(a1["url"].(string), clienttest.Origin+"/r/pa/a1/rev/") || a1["schema"] == nil {
		t.Errorf("a1 %v", a1)
	}
	if a2 := h[1].(map[string]any); fmt.Sprint(a2["refs"]) != "[map[path:/trigger ref:"+x+"#t-1]]" {
		t.Errorf("a2 %v", a2)
	}
	if r.header.Get("Cache-Control") != "private, max-age=300" || r.header.Get("CDN-Cache-Control") != "no-store" ||
		r.header.Get("Cache-Tag") != "idx:pa,idx:pub,r:pa/a1,r:pa/a2,r:pub/p1" || r.header.Get("X-Namespace-Revision") != amyAt {
		t.Errorf("headers %v", r.header)
	}
	if b := idx.search("/_refs?to="+url.QueryEscape("/r/pa/a1"), amy); refsAllHits(b) != "pa/a1" || b["hits"].([]any)[0].(map[string]any)["self"] != true {
		t.Errorf("self %v", b)
	}

	// bob reads both private namespaces: another subject set and at.
	bobAt, bobGs, bobLoc := idx.refsPointer(q, bob)
	if bobGs == amyGs || bobAt == amyAt {
		t.Errorf("bob shares amy's gs or at: %s %s", bobLoc, amyLoc)
	}
	if got := refsAllHits(idx.search(bobLoc, bob)); got != "pa/a1 pa/a2 pb/b1 pb/b2 pub/p1" {
		t.Errorf("bob: %s", got)
	}
	// li reads one resource of pb: filtered per item, under its own gs.
	_, liGs, liLoc := idx.refsPointer(q, li)
	if got := refsAllHits(idx.search(liLoc, li)); got != "pb/b1 pub/p1" || liGs == bobGs {
		t.Errorf("li: %s (gs %s)", got, liGs)
	}
	// Without a grant, or with one that reads nothing private here, the
	// public answer: public caching, tagged with the public namespace.
	_, anonGs, anonLoc := idx.refsPointer(q, "")
	if r := idx.raw("/_refs"+q, ""); r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" || r.header.Get("Cache-Tag") != "ns:pub" {
		t.Errorf("public pointer %v", r.header)
	}
	r = idx.raw(anonLoc, "")
	if r.status != 200 || refsAllHits(r.body) != "pub/p1" || r.header.Get("Cache-Control") != "public, max-age=86400, s-maxage=31536000, immutable" || r.header.Get("Cache-Tag") != "idx:pub,r:pub/p1" {
		t.Errorf("anonymous: %d %v %v", r.status, r.body, r.header)
	}
	other := issuer.Grant(t, s.Now(), "user:zed", []string{"elsewhere"}, []string{"read"}, editors)
	if _, gs, _ := idx.refsPointer(q, other); gs != anonGs || anonGs == amyGs {
		t.Errorf("a grant reading nothing private: gs %s, anonymous %s", gs, anonGs)
	}

	// A write in pb moves bob's at, not amy's.
	mk("pb", "b3", map[string]any{"related": []any{x}})
	pbHead := idx.caughtUp("pb")
	if at, _, _ := idx.refsPointer(q, amy); at != amyAt {
		t.Errorf("a write amy can't see moved her at")
	}
	if at, _, loc := idx.refsPointer(q, bob); at == bobAt || !strings.Contains(refsAllHits(idx.search(loc, bob)), "pb/b3") {
		t.Errorf("bob's at after the write: %s", loc)
	}

	// min: only for namespaces the answer covers, in the {ns}:{ns_id} form.
	for _, m := range []string{"pb:" + pbHead, "nope:" + pbHead, pbHead, "pa:garbage"} {
		if r := idx.raw("/_refs"+q+"&min="+url.QueryEscape(m), amy); r.status != 400 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("amy min=%s: %d %v", m, r.status, r.body)
		}
	}
	if _, _, loc := idx.refsPointer(q+"&min=pa:"+idx.ix.Checkpoint("pa"), amy); loc != amyLoc {
		t.Errorf("amy with min: %s", loc)
	}
	if _, _, loc := idx.refsPointer(q+"&min=pb:"+pbHead, bob); !strings.Contains(refsAllHits(idx.search(loc, bob)), "pb/b3") {
		t.Errorf("bob with min: %s", loc)
	}

	// An answer is kept at its at after the namespaces move on; an at
	// whose answer isn't kept redirects to the current one.
	mk("pa", "a4", map[string]any{"related": []any{x}})
	idx.caughtUp("pa")
	newAt, _, newLoc := idx.refsPointer(q, amy)
	if newAt == amyAt || refsAllHits(idx.search(newLoc, amy)) != "pa/a1 pa/a2 pa/a4 pub/p1" {
		t.Fatalf("after a write in pa: %s", newLoc)
	}
	if r := idx.raw(amyLoc, amy); r.status != 200 || refsAllHits(r.body) != "pa/a1 pa/a2 pub/p1" {
		t.Errorf("kept answer: %d %v", r.status, r.body)
	}
	for _, p := range []string{
		"/_refs/at/" + idx.ix.Checkpoint("pa") + "/g/" + amyGs + q, // never computed
		"/_refs/at/" + amyAt + "/g/" + amyGs + "?to=" + x,          // not canonical
		"/_refs/at/" + amyAt + "/g/" + amyGs + q + "&min=pa:" + idx.ix.Checkpoint("pa"),
	} {
		if r := idx.raw(p, amy); r.status != 302 || r.header.Get("Location") != newLoc {
			t.Errorf("%s: %d %s", p, r.status, r.header.Get("Location"))
		}
	}
	// Someone else's subject set redirects to one's own, at the same at.
	if r := idx.raw(bobLoc, amy); r.status != 302 || r.header.Get("Location") != "/_refs/at/"+bobAt+"/g/"+amyGs+q {
		t.Errorf("foreign gs: %d %s", r.status, r.header.Get("Location"))
	}

	// Pages: in namespace, then resource order.
	var pages []string
	b := idx.search("/_refs"+q+"&limit=2", bob)
	for {
		pages = append(pages, refsAllHits(b))
		next, ok := b["next"].(string)
		if !ok {
			break
		}
		if !strings.HasPrefix(next, "/_refs/at/"+b["at"].(string)+"/g/") {
			t.Fatalf("next %s", next)
		}
		b = idx.search(next, bob)
	}
	if got := strings.Join(pages, " | "); got != "pa/a1 pa/a2 | pa/a4 pb/b1 | pb/b2 pb/b3 | pub/p1" {
		t.Errorf("pages %s", got)
	}

	// Bad input.
	for _, p := range []string{
		"/_refs", "/_refs?to=garbage", "/_refs" + q + "&to=" + url.QueryEscape("/r/target/y"), "/_refs" + q + "&q=x",
		"/_refs" + q + "&limit=0", "/_refs/at/zzz/g/" + amyGs + q,
	} {
		if r := idx.raw(p, amy); r.status != 400 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
	for _, p := range []string{"/_refs/x", "/_refs/at/" + amyAt + q, "/_refs/at/" + amyAt + "/g/zzz" + q} {
		if r := idx.raw(p, amy); r.status != 404 {
			t.Errorf("%s: %d", p, r.status)
		}
	}

	// A purge drops the kept answers that show the resource.
	must(w.Purge(ctx, "pa", "a1", must(w.Head(ctx, "pa", "a1")).ID, false))
	idx.caughtUp("pa")
	for _, loc := range []string{amyLoc, newLoc} {
		if r := idx.raw(loc, amy); r.status != 302 {
			t.Errorf("%s after the purge: %d %v", loc, r.status, r.body)
		}
	}
	if got := refsAllHits(idx.search("/_refs"+q, amy)); got != "pa/a2 pa/a4 pub/p1" {
		t.Errorf("after the purge: %s", got)
	}
	idx.mu.Lock()
	purged := slices.ContainsFunc(idx.purges, func(tags []string) bool { return slices.Contains(tags, "r:pa/a1") })
	idx.mu.Unlock()
	if !purged {
		t.Error("r:pa/a1 not purged")
	}

	// An index of private namespaces only: a reader needs a grant, and
	// behind a verifying edge (§9) the answer comes through it.
	ev := must(edge.New([]byte("s3cret"), ""))
	y := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "y.db"), ns: []string{"pa", "pb"}, now: s.Now}, func(o *indexOpts) { o.Edge = ev })
	y.caughtUp("pa")
	y.caughtUp("pb")
	for _, tok := range []string{"", "garbage"} {
		if r := y.raw("/_refs"+q, tok); r.status != 401 || r.header.Get("WWW-Authenticate") != "Bearer" || r.body["message"] != "missing or unverifiable grant" {
			t.Errorf("token %q: %d %v", tok, r.status, r.body)
		}
	}
	// Refusals name no namespace: one the reader can't see is like one the
	// service doesn't follow.
	if r := y.raw("/_refs"+q, other); r.status != 403 || r.body["message"] != "the grant reads no namespace the service follows" {
		t.Errorf("a grant for no namespace followed: %d %v", r.status, r.body)
	}
	get := func(path, secret string) *http.Response {
		req := must(http.NewRequest("GET", y.http.URL+path, nil))
		req.Header.Set("Authorization", "Bearer "+bob)
		if secret != "" {
			req.Header.Set(edge.DefaultHeader, secret)
		}
		res := must(noFollow.Do(req))
		res.Body.Close()
		return res
	}
	if res := get("/_refs"+q, ""); res.StatusCode != 403 {
		t.Errorf("without the edge: %d", res.StatusCode)
	}
	res := get("/_refs"+q, "s3cret")
	for res.StatusCode == 302 {
		res = get(res.Header.Get("Location"), "s3cret")
	}
	if res.StatusCode != 200 || res.Header.Get("CDN-Cache-Control") != "max-age=31536000" {
		t.Errorf("through the edge: %d %v", res.StatusCode, res.Header)
	}
}

// An answer is served at its at only while the reader may still see every
// namespace it covers: a namespace that turns private moves no subject set
// (public ones add no marker), so the at URL alone doesn't say.
func TestRefsAfterPrivate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	for _, ns := range []string{"schemas", "pub", "pub2", "pa"} {
		doc := map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}
		if ns == "pa" {
			doc = map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"schemas", "pub", "pub2", "pa"}, []string{"read", "create", "config"})))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	for _, d := range []struct{ ns, name, ref string }{{"pub", "p1", x}, {"pub2", "q1", "/r/target/y"}, {"pa", "a1", x}} {
		must(w.CreateDoc(ctx, d.ns, d.name, map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{d.ref}}))
	}
	nss := []string{"pub", "pub2", "pa"}
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	idx := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, now: s.Now})
	for _, ns := range nss {
		idx.caughtUp(ns)
	}
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"pa"}, []string{"read"}, map[string]any{"groups": []any{"editors"}})
	q := "?to=" + url.QueryEscape(x)
	_, _, anonLoc := idx.refsPointer(q, "")
	_, _, bobLoc := idx.refsPointer(q, bob)
	if a, b := refsAllHits(idx.search(anonLoc, "")), refsAllHits(idx.search(bobLoc, bob)); a != "pub/p1" || b != "pa/a1 pub/p1" {
		t.Fatalf("before: %q %q", a, b)
	}

	must(w.PatchConfig(ctx, "pub", must(w.NSHead(ctx, "pub")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	idx.caughtUp("pub")
	for _, c := range []struct{ loc, token, want string }{{anonLoc, "", ""}, {bobLoc, bob, "pa/a1"}} {
		if r := idx.raw(c.loc, c.token); r.status != 302 {
			t.Errorf("%s after pub went private: %d %v", c.loc, r.status, r.body)
		}
		if got := refsAllHits(idx.search("/_refs"+q, c.token)); got != c.want {
			t.Errorf("current answer for %q: %q", c.token, got)
		}
	}
}

// Hits from sealed and e2e namespaces are sealed per entry (§E.2.6), once;
// an e2e namespace whose keys the index doesn't hold is left out.
func TestRefsAcrossSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	levels := map[string]string{"schemas": "", "plain": "", "sec": "sealed", "e": "e2e", "e2": "e2e"}
	for ns, level := range levels {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if level != "" {
			doc["encryption"] = map[string]any{"level": level}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"schemas", "plain", "sec", "e", "e2"}
	wJWK, wPriv, _ := seal.GenerateRecipient()
	iJWK, iPriv, _ := seal.GenerateRecipient()
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "purge", "config"}, map[string]any{"enc": wJWK})),
		client.WithKeys(client.NewKeys(wPriv)))
	sch := must(w.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	x := "/r/target/x"
	doc := map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{x}}
	must(w.CreateDoc(ctx, "plain", "p", doc))
	must(createNonced(w, "sec", "s", doc))
	ad := w.E2E(wPriv)
	must(ad.InitKeyring(ctx, "e", iPriv.PublicKey()))
	must(ad.InitKeyring(ctx, "e2"))
	must(ad.CreateDocSealed(ctx, "e", "d", doc))
	must(ad.CreateDocSealed(ctx, "e2", "d", doc))

	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", all[1:], []string{"read"}, map[string]any{"enc": iJWK})), client.WithKeys(client.NewKeys(iPriv)))
	opts := svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: all[1:], now: s.Now}
	withKey := func(o *indexOpts) { o.Recipient = iPriv }
	idx := startSvcWith(t, ic, opts, withKey)
	for _, ns := range []string{"plain", "sec", "e"} {
		idx.caughtUp(ns)
	}
	waitFor(t, "e2 skipped", func() bool {
		for _, st := range idx.raw("/_status", "").body["namespaces"].([]any) {
			if st := st.(map[string]any); st["ns"] == "e2" && st["skipped"] == true {
				return true
			}
		}
		return false
	})

	f := idx.fetch("/_refs?to="+url.QueryEscape(x), "")
	b := decodeJSON(t, f.body)
	if fmt.Sprint(b["namespaces"]) != fmt.Sprint(map[string]any{"e": idx.ix.Checkpoint("e"), "plain": idx.ix.Checkpoint("plain"), "sec": idx.ix.Checkpoint("sec")}) || refsAllHits(b) != "e/d plain/p sec/s" {
		t.Fatalf("answer %s", f.body)
	}
	hits := b["hits"].([]any)
	if p := hits[1].(map[string]any); fmt.Sprint(p["refs"]) != "[map[path:/related/0 ref:"+x+"]]" {
		t.Errorf("plain hit %v", p)
	}
	// Keys in the clear, for a grant without enc.
	kc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec"}, []string{"read"})))
	keyOf := map[string]func(string) []byte{"sec": derived.ItemKey(epochKeys(t, kc, "sec"), "sec", "s")}
	ke := must(ad.Key(ctx, "e#1"))
	keyOf["e"] = derived.ItemKey(func(kid string) []byte {
		if kid == "e#1" {
			return ke
		}
		return nil
	}, "e", "d")
	for _, i := range []int{0, 2} {
		hit := hits[i].(map[string]any)
		ns, name := hit["ns"].(string), hit["resource"].(string)
		jwe, _ := hit["sealed"].(string)
		if len(hit) != 5 || jwe == "" || hit["id"] == nil || hit["url"] == nil {
			t.Fatalf("sealed hit %v", hit)
		}
		if pl := must(seal.ParseHeader(jwe)).PL; fmt.Sprint(pl) != fmt.Sprint(map[string]any{"ns": ns, "name": name, "view": f.path}) {
			t.Errorf("pl %v", pl)
		}
		v := decodeJSON(t, must(derived.OpenItem(jwe, keyOf[ns], derived.View{NS: ns, Target: f.path}, ns, name)))
		if fmt.Sprint(v["refs"]) != "[map[path:/related/0 ref:"+x+"]]" || v["schema"] == nil {
			t.Errorf("%s/%s opens to %v", ns, name, v)
		}
	}
	if strings.Contains(f.header.Get("Cache-Tag"), "e2") {
		t.Errorf("tags %s", f.header.Get("Cache-Tag"))
	}

	// Sealed once: stored, and served unchanged after a restart.
	if tags := idx.ix.SealedViews()[f.path]; !strings.Contains(tags, "r:sec/s") || !strings.Contains(tags, "idx:e") {
		t.Fatalf("stored %q", tags)
	}
	idx.stop()
	idx = startSvcWith(t, ic, opts, withKey)
	idx.caughtUp("sec")
	if again := idx.fetch(f.path, ""); again.path != f.path || string(again.body) != string(f.body) {
		t.Fatalf("resealed after a restart: %s", again.body)
	}

	// A purge removes the stored answer.
	must(w.Purge(ctx, "sec", "s", must(w.Head(ctx, "sec", "s")).ID, false))
	idx.caughtUp("sec")
	if _, ok := idx.ix.SealedViews()[f.path]; ok {
		t.Error("the stored answer survived the purge")
	}
	if r := idx.raw(f.path, ""); r.status != 302 {
		t.Errorf("after the purge: %d", r.status)
	}
	if got := refsAllHits(idx.search("/_refs?to="+url.QueryEscape(x), "")); got != "e/d plain/p" {
		t.Errorf("after the purge: %s", got)
	}

	// A stored answer is not served once a namespace it covers turns
	// private, though the anonymous subject set stays the same.
	must(createNonced(w, "sec", "s2", doc))
	idx.caughtUp("sec")
	f = idx.fetch("/_refs?to="+url.QueryEscape(x), "")
	if got := refsAllHits(decodeJSON(t, f.body)); got != "e/d plain/p sec/s2" {
		t.Fatalf("with s2: %s", got)
	}
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	idx.caughtUp("sec")
	idx.stop()
	idx = startSvcWith(t, ic, opts, withKey)
	idx.caughtUp("sec")
	if _, ok := idx.ix.SealedViews()[f.path]; !ok {
		t.Fatal("the answer with s2 is not stored")
	}
	if r := idx.raw(f.path, ""); r.status != 302 {
		t.Errorf("after sec went private: %d %v", r.status, r.body)
	}
	if got := refsAllHits(idx.search("/_refs?to="+url.QueryEscape(x), "")); got != "e/d plain/p" {
		t.Errorf("after sec went private: %s", got)
	}
}
