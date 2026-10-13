package index_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// TestMinOtherNamespace (§A.5, v0.51): a min naming a namespace that a
// result's at doesn't cover, but that the service follows and the reader
// may see, redirects to the current checkpoint in one hop, without min; a
// min naming a namespace the reader can't see, or one the service doesn't
// follow, is 400. min is a set: given twice, it counts once. A
// single-valued parameter given twice is 400.
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
		// A followed namespace the reader may see: one hop to the current
		// checkpoint, from the at URL and from the pointer.
		{"amy", amy, old["amy"] + "&min=pub:" + pubAt, current(old["amy"])},
		{"amy", amy, "/pa?limit=5&min=pub:" + pubAt, current(old["amy"])},
		{"bob", bob, old["bob"] + "&min=pb:" + pbAt, current(old["bob"])},
		// A set: the same min twice is one.
		{"bob", bob, old["bob"] + "&min=pb:" + pbAt + "&min=pb:" + pbAt, current(old["bob"])},
	} {
		if r := x.raw(c.url, c.tok); r.status != 302 || r.header.Get("Location") != c.want {
			t.Errorf("%s %s: %d %s, want %s", c.who, c.url, r.status, r.header.Get("Location"), c.want)
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
}
