package index_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// TestMinOtherNamespace (§A.5, v0.74 Open 84): on a query of one
// namespace, a min naming any other is 400, the body's min listing it,
// whether the service follows it and the reader may see it or not (v0.51
// redirected the former to the current checkpoint); a min naming the
// queried namespace redirects there in one hop, without min. min is a
// set: given twice, it counts once. A single-valued parameter given twice
// is 400.
func TestMinOtherNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	for _, ns := range []string{"pa", "pb", "pub"} {
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		if ns == "pub" {
			doc["read"] = "public"
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	nss := []string{"pa", "pb", "pub"}
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append"})))
	for _, ns := range nss {
		must(root.CreateDoc(ctx, ns, "a", map[string]any{"title": ns}))
	}
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, untyped: true, now: s.Now})
	for _, ns := range nss {
		x.caughtUp(ns)
	}
	amy := issuer.Grant(t, s.Now(), "user:amy", []string{"pa"}, []string{"read"})
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"pa", "pb"}, []string{"read"})
	old := map[string]string{}
	for tok, name := range map[string]string{amy: "amy", bob: "bob"} {
		r := x.raw("/pa?limit=5", tok)
		if loc := r.header.Get("Location"); r.status != 302 || !strings.HasPrefix(loc, "/pa/g/") {
			t.Fatalf("%s: %d %s", name, r.status, loc)
		}
		old[name] = r.header.Get("Location")
	}
	// pa moves on: its current checkpoint is no longer the one of the URLs
	// above, whose results are kept.
	must(root.CreateDoc(ctx, "pa", "b", map[string]any{"title": "pa"}))
	cur := x.caughtUp("pa")
	pubAt := must(root.CreateDoc(ctx, "pub", "b", map[string]any{"title": "pub"})).NSID
	pbAt := must(root.CreateDoc(ctx, "pb", "b", map[string]any{"title": "pb"})).NSID
	x.caughtUp("pub")
	x.caughtUp("pb")
	current := func(loc string) string {
		i := strings.Index(loc, "/at/")
		return loc[:i] + "/at/" + cur + "?limit=5"
	}
	for _, c := range []struct {
		who, tok, url, want string
	}{
		// The queried namespace: one hop to the current checkpoint, from
		// the at URL and from the pointer.
		{"amy", amy, old["amy"] + "&min=pa:" + cur, current(old["amy"])},
		{"amy", amy, "/pa?limit=5&min=pa:" + cur, current(old["amy"])},
		// A set: the same min twice is one.
		{"bob", bob, old["bob"] + "&min=pa:" + cur + "&min=pa:" + cur, current(old["bob"])},
	} {
		if r := x.raw(c.url, c.tok); r.status != 302 || r.header.Get("Location") != c.want {
			t.Errorf("%s %s: %d %s, want %s", c.who, c.url, r.status, r.header.Get("Location"), c.want)
		}
	}
	// A followed namespace the reader may see: 400, listing it, once.
	for _, c := range []struct {
		who, tok, url, min string
	}{
		{"amy", amy, old["amy"] + "&min=pub:" + pubAt, "pub:" + pubAt},
		{"amy", amy, "/pa?limit=5&min=pub:" + pubAt, "pub:" + pubAt},
		{"bob", bob, old["bob"] + "&min=pb:" + pbAt, "pb:" + pbAt},
		{"bob", bob, old["bob"] + "&min=pb:" + pbAt + "&min=pb:" + pbAt, "pb:" + pbAt},
	} {
		if r := x.raw(c.url, c.tok); r.status != 400 || fmt.Sprint(r.body["min"]) != fmt.Sprint([]string{c.min}) {
			t.Errorf("%s %s: %d %v, want 400 listing %s", c.who, c.url, r.status, r.body, c.min)
		}
	}
	for _, c := range []struct {
		who, tok, url string
	}{
		// pb is followed, but amy's grant doesn't read it.
		{"amy", amy, old["amy"] + "&min=pb:" + pbAt},
		{"amy", amy, "/pa?limit=5&min=pb:" + pbAt},
		// zz isn't followed.
		{"bob", bob, old["bob"] + "&min=zz:" + pbAt},
		// limit may not repeat (§7, §A.5).
		{"bob", bob, "/pa?limit=5&limit=5"},
	} {
		if r := x.raw(c.url, c.tok); r.status != 400 || r.body["code"] != "bad_input" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: %d %v", c.who, c.url, r.status, r.body)
		}
	}
	// One answer for a namespace the reader can't see and one the index
	// doesn't follow, so a min can't probe which private namespaces are
	// indexed, even anonymously on a public result.
	pubOld := x.raw("/pub?limit=5", "").header.Get("Location")
	if !strings.HasPrefix(pubOld, "/pub/at/") {
		t.Fatalf("public pointer: %q", pubOld)
	}
	hidden, unknown := x.raw(pubOld+"&min=pb:"+pbAt, ""), x.raw(pubOld+"&min=zz:"+pbAt, "")
	if hidden.status != 400 || unknown.status != 400 || hidden.body["message"] != unknown.body["message"] || hidden.body["code"] != unknown.body["code"] {
		t.Errorf("hidden %d %v, unknown %d %v", hidden.status, hidden.body, unknown.status, unknown.body)
	}
}

// TestMinPurgedSealed (§A.5, §8.5): on a query of one namespace, a min
// naming a purged sealed namespace, whose document is 410 purged, is 400
// whoever reads it, as one naming any other namespace is since v0.74
// (Open 84): the purged-namespace exemption is /_refs' and tree
// listings'. Never a 502.
func TestMinPurgedSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pa"))).CreateNamespace(ctx, "pa",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	nss := []string{"pa", "sec"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", nss, []string{"read", "create", "config", "purge-ns"})),
		client.WithKeys(client.NewKeys(nil)))
	must(createNonced(w, "sec", "a", map[string]any{"title": "secret"}))
	must(w.CreateDoc(ctx, "pa", "a", map[string]any{"title": "pa"}))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("sec")
	cur := x.caughtUp("pa")
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.PurgeNamespace(ctx, "sec", must(w.NSHead(ctx, "sec")).ID))
	waitFor(t, "the purge", func() bool { return x.ix.Checkpoint("sec") == purged })

	reader := k.Grant(t, s.Now(), "user:r", nss, []string{"read"})
	r := x.raw("/pa?q=pa&min=sec:"+purged, reader)
	if r.status != 400 || fmt.Sprint(r.body["min"]) != fmt.Sprint([]string{"sec:" + purged}) {
		t.Errorf("a reader of sec: %d %v", r.status, r.body)
	}
	if r := x.raw("/pa?q=pa&min=pa:"+cur, reader); r.status != 302 {
		t.Errorf("a min naming pa: %d %v", r.status, r.body)
	}
	// A grant that doesn't read sec: the 400 of a namespace not followed.
	paOnly := k.Grant(t, s.Now(), "user:p", []string{"pa"}, []string{"read"})
	hidden, unknown := x.raw("/pa?q=pa&min=sec:"+purged, paOnly), x.raw("/pa?q=pa&min=zz:"+purged, paOnly)
	if hidden.status != 400 || hidden.body["code"] != "bad_input" || hidden.body["message"] != unknown.body["message"] {
		t.Errorf("a grant for pa only: %d %v, unknown %d %v", hidden.status, hidden.body, unknown.status, unknown.body)
	}
}
