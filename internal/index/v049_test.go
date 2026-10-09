package index_test

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// TestPurgedAfterReadCheck (§8.5, §12): a purged namespace answers 410
// purged with head, its purge-ns entry, after the read check, as the
// core's URLs of it do.
func TestPurgedAfterReadCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec",
		map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create", "config", "purge-ns"})))
	must(root.CreateDoc(ctx, "sec", "a", map[string]any{"title": "x"}))
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now})
	x.caughtUp("sec")
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"})
	ptr := x.raw("/sec", bob).header.Get("Location")

	must(root.PatchConfig(ctx, "sec", must(root.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(root.PurgeNamespace(ctx, "sec", must(root.NSHead(ctx, "sec")).ID))
	waitFor(t, "the purge", func() bool { return x.ix.Checkpoint("sec") == purged })
	for tok, want := range map[string]int{
		"": 401, "garbage": 401,
		issuer.Grant(t, s.Now(), "user:bob", []string{"other"}, []string{"read"}): 403,
	} {
		if r := x.raw("/sec?q=x", tok); r.status != want {
			t.Errorf("token %.10q: %d %v, want %d", tok, r.status, r.body, want)
		}
	}
	for _, u := range []string{"/sec?q=x", ptr, ptr + "/at/" + purged} {
		if r := x.raw(u, bob); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != purged || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v %v", u, r.status, r.body, r.header)
		}
	}
}

// TestReadsUnrestrictedRoles (§C.5, B8): a grant reads a namespace whole
// when one of its read roles has no rule on /resource and passes, whatever
// its other roles (roles are alternatives): it shares a plain reader's
// subject set and results, here and in /_refs. One whose only read roles
// test /resource, or whose other read role has a rule on /now that fails,
// is filtered per resource under a subject set of its own, and in /_refs
// rules on /now in it make the namespace unreadable (§A.4).
func TestReadsUnrestrictedRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	before := func(at string) []any {
		return []any{map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": at}}}
	}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{
		"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read", "append")},
		"roles": map[string]any{
			"reader": map[string]any{"can": []any{"read"}},
			"writer": map[string]any{"can": []any{"read", "append"}, "rules": []any{
				map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^draft-"}}}},
			"current": map[string]any{"can": []any{"read"}, "rules": before("2999-01-01T00:00:00Z")},
			"expired": map[string]any{"can": []any{"read"}, "rules": before("2000-01-01T00:00:00Z")},
		},
	}))
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create"})))
	sch := must(root.CreateDoc(ctx, "sec", "page", pageSchema(true)))
	target := "/r/target/x"
	for _, n := range []string{"a", "b", "draft-1"} {
		must(root.CreateDoc(ctx, "sec", n, map[string]any{"$schema": "/r/sec/page/rev/" + sch.ID, "title": "secret " + n, "related": []any{target}}))
	}
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now})
	x.caughtUp("sec")

	gsOf := func(tok string) string {
		t.Helper()
		r := x.raw("/sec?q=secret", tok)
		loc := r.header.Get("Location")
		if r.status != 302 || !strings.HasPrefix(loc, "/g/") {
			t.Fatalf("pointer: %d %s %v", r.status, loc, r.body)
		}
		return strings.Split(loc, "/")[2]
	}
	q := "?to=" + url.QueryEscape(target)
	plain := issuer.Grant(t, s.Now(), "user:amy", []string{"sec"}, []string{"read"}, map[string]any{"groups": []any{"editors"}})
	plainGs := gsOf(plain)
	_, plainRefs, _ := x.refsPointer(q, plain)
	for _, tc := range []struct {
		name, sub string
		roles     []any
		whole     bool
		hits      string
	}{
		{"reader and writer (B8)", "user:bob", []any{"reader", "writer"}, true, "a,b,draft-1"},
		{"current and writer", "user:cy", []any{"current", "writer"}, true, "a,b,draft-1"},
		{"writer", "user:dee", []any{"writer"}, false, "draft-1"},
		{"expired and writer", "user:ed", []any{"expired", "writer"}, false, "draft-1"},
	} {
		tok := issuer.Grant(t, s.Now(), tc.sub, []string{"sec"}, nil, map[string]any{"groups": []any{"editors"}, "roles": tc.roles})
		if gs := gsOf(tok); (gs == plainGs) != tc.whole {
			t.Errorf("%s: gs %s, a plain reader's %s", tc.name, gs, plainGs)
		}
		if got := strings.Join(resources(x.search("/sec?q=secret", tok)), ","); got != tc.hits {
			t.Errorf("%s: hits %s", tc.name, got)
		}
		if tc.roles[0] == "expired" {
			// Rules on /now in its read roles: sec is unreadable, and the
			// only namespace followed.
			if r := x.raw("/_refs"+q, tok); r.status != 403 {
				t.Errorf("%s: /_refs %d %v", tc.name, r.status, r.body)
			}
			continue
		}
		_, gs, loc := x.refsPointer(q, tok)
		if (gs == plainRefs) != tc.whole || strings.ReplaceAll(refsAllHits(x.search(loc, tok)), "sec/", "") != strings.ReplaceAll(tc.hits, ",", " ") {
			t.Errorf("%s: /_refs %s, a plain reader's gs %s", tc.name, loc, plainRefs)
		}
	}
	// A grant whose reads can't differ between resources and that doesn't
	// read the namespace reads none of it.
	tok := issuer.Grant(t, s.Now(), "user:fay", []string{"sec"}, nil, map[string]any{"roles": []any{"expired"}})
	if r := x.raw("/sec?q=secret", tok); r.status != 403 {
		t.Errorf("expired alone: %d %v", r.status, r.body)
	}
}
