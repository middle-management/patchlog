package tree_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// privateWorld is an authenticated core with a private catalog "cat"
// trusting the private content namespace "sec", both defining roles doc
// (plus reader read and append), and the folder top holding sec.a,
// hidden and sec.draft-1.
func privateWorld(t *testing.T, roles map[string]any) (s *clienttest.Server, admin, reader clienttest.Key, root *client.Client) {
	ctx := context.Background()
	s = clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, reader = clienttest.NewKey("admin"), clienttest.NewKey("reader")
	for _, ns := range []string{"sec", "cat"} {
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), reader.Entry("read", "append")}, "roles": roles}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	root = s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec", "cat"}, []string{"read", "create", "append", "config", "purge-ns"})))
	must(root.CreateDoc(ctx, "cat", "top", map[string]any{"title": "Top", "parents": []any{}}))
	must(root.CreateDoc(ctx, "cat", "hidden", map[string]any{"title": "Hidden", "parents": parents("top@b")}))
	for n, order := range map[string]string{"a": "a", "draft-1": "c"} {
		must(root.CreateDoc(ctx, "sec", n, map[string]any{"t": n}))
		must(root.CreateDoc(ctx, "cat", "sec."+n, map[string]any{"parents": parents("top@" + order)}))
	}
	return s, admin, reader, root
}

// TestReadsUnrestrictedRoles (§C.5, B8): a grant reads the catalog and a
// content namespace whole when one of its read roles there has no rule on
// /resource and passes, whatever its other roles (roles are
// alternatives): it shares a plain reader's subject set, sees every node
// and item head, and may have unfiltered listings. One whose only read
// roles test /resource, or whose other read role has a rule on /now that
// fails, is filtered per node and item under a subject set of its own.
func TestReadsUnrestrictedRoles(t *testing.T) {
	t.Parallel()
	before := func(at string) []any {
		return []any{map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": at}}}
	}
	s, admin, reader, _ := privateWorld(t, map[string]any{
		"reader": map[string]any{"can": []any{"read"}},
		"writer": map[string]any{"can": []any{"read", "append"}, "rules": []any{
			map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": `^(top|sec\.draft-.*|draft-.*)$`}}}},
		"current": map[string]any{"can": []any{"read"}, "rules": before("2999-01-01T00:00:00Z")},
		"expired": map[string]any{"can": []any{"read"}, "rules": before("2000-01-01T00:00:00Z")},
	})
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"}))), svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")

	groups := map[string]any{"groups": []any{"eds"}}
	plain := reader.Grant(t, s.Now(), "user:amy", []string{"cat", "sec"}, []string{"read"}, groups)
	ptr := func(tok string) string { return x.raw("/cat/children?of=top", tok).header.Get("Location") }
	plainLoc := ptr(plain)
	heads := func(b map[string]any) string {
		var out []string
		for _, e := range b["children"].([]any) {
			if e.(map[string]any)["head"] != nil {
				out = append(out, e.(map[string]any)["name"].(string))
			}
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		name, sub string
		roles     []any
		whole     bool
	}{
		{"reader and writer (B8)", "user:bob", []any{"reader", "writer"}, true},
		{"current and writer", "user:cy", []any{"current", "writer"}, true},
		{"writer", "user:dee", []any{"writer"}, false},
		{"expired and writer", "user:ed", []any{"expired", "writer"}, false},
	} {
		tok := reader.Grant(t, s.Now(), tc.sub, []string{"cat", "sec"}, nil, map[string]any{"groups": []any{"eds"}, "roles": tc.roles})
		if loc := ptr(tok); (loc == plainLoc) != tc.whole {
			t.Errorf("%s: %s, a plain reader's %s", tc.name, loc, plainLoc)
		}
		b := x.get("/cat/children?of=top", tok)
		names, hs := names(b["children"]), heads(b)
		problems := x.raw(x.raw("/cat/problems", tok).header.Get("Location"), tok).status
		if tc.whole && (names != "sec.a,hidden,sec.draft-1" || hs != "sec.a,sec.draft-1" || problems != 200) ||
			!tc.whole && (names != "sec.draft-1" || hs != "sec.draft-1" || problems != 403) {
			t.Errorf("%s: children %s, heads %s, problems %d", tc.name, names, hs, problems)
		}
	}
}

// TestPurgedCatalog (§8.5, §12): a purged catalog answers 410 purged with
// head, its purge-ns entry, after the read check, as the core's URLs of
// it do.
func TestPurgedCatalog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, admin, reader, root := privateWorld(t, map[string]any{})
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:tree", []string{"sec", "cat"}, []string{"read"}))), svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")
	bob := reader.Grant(t, s.Now(), "user:bob", []string{"cat"}, []string{"read"})
	loc := x.raw("/cat/children?of=top", bob).header.Get("Location")

	must(root.PatchConfig(ctx, "cat", must(root.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(root.PurgeNamespace(ctx, "cat", must(root.NSHead(ctx, "cat")).ID))
	waitFor(t, "the purge", func() bool { return x.s.Checkpoint("cat") == purged })
	for tok, want := range map[string]int{
		"": 401, "garbage": 401,
		reader.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"}): 403,
	} {
		if r := x.raw("/cat/roots", tok); r.status != want {
			t.Errorf("token %.10q: %d %v, want %d", tok, r.status, r.body, want)
		}
	}
	for _, u := range []string{"/cat/roots", loc, strings.Replace(loc, "/children?of=top", "/problems", 1)} {
		if r := x.raw(u, bob); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != purged || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v %v", u, r.status, r.body, r.header)
		}
	}
}
