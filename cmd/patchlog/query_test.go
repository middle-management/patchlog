package main

// These tests run search and tree ls against the real index and tree
// services, started in-process on a clienttest core (as internal/index's and
// internal/tree's tests start them).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/tree"
)

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

const draft2020 = "https://json-schema.org/draft/2020-12/schema"

// serviceCore is a dev-mode core with a typed namespace matches and a
// catalog cat trusting it.
func serviceCore(t *testing.T) (*clienttest.Server, *client.Client) {
	t.Helper()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	ctx := context.Background()
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	return s, c
}

func TestSearchCommand(t *testing.T) {
	t.Parallel()
	s, c := serviceCore(t)
	ctx := context.Background()
	schema := must(c.CreateDoc(ctx, "schemas", "match", map[string]any{
		"$schema": draft2020, "type": "object",
		"properties": map[string]any{
			"$schema": map[string]any{"type": "string"},
			"title":   map[string]any{"type": "string", "x-index": "text"},
			"status":  map[string]any{"type": "string", "x-index": "facet"},
			"league":  map[string]any{"type": "string", "x-index": "facet"},
			"kickoff": map[string]any{"type": "string", "x-index": "sort"},
		},
	}))
	ref := "/r/schemas/match/rev/" + schema.ID
	put := func(name, title, status, league, kickoff string) *client.WriteResult {
		return must(c.CreateDoc(ctx, "matches", name, map[string]any{"$schema": ref, "title": title, "status": status, "league": league, "kickoff": kickoff}))
	}
	put("derby", "The Derby", "done", "allsvenskan", "2026-10-04")
	put("cup", "Cup semi final", "planned", "cup", "2026-10-05")
	last := put("final", "Cup final", "planned", "cup", "2026-10-06")

	ix := must(index.Open(ctx, index.Options{
		Client: c, DB: filepath.Join(t.TempDir(), "index.db"), Namespaces: []string{"matches"}, MinWait: 5 * time.Second,
		RepurgeInterval: -1, Logf: t.Logf,
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)},
	}))
	srv := httptest.NewServer(ix.Handler())
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { ix.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done; srv.Close(); ix.Close() })
	_ = s

	search := func(args ...string) (string, string) {
		t.Helper()
		cmd, ok := command(t, append([]string{"search"}, append(args, "--index", srv.URL)...)...).(*searchCmd)
		if !ok {
			t.Fatalf("%q is not search", args)
		}
		var out, errw strings.Builder
		if err := cmd.exec(ctx, &out, &errw); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		return out.String(), errw.String()
	}

	// --min waits for the index to have our last write.
	out, _ := search("matches", "cup*", "--min", "matches:"+last.NSID, "--sort=-/kickoff", "--counts", "/status")
	want := "final  /kickoff=2026-10-06  /league=cup  /status=planned\n" +
		"cup  /kickoff=2026-10-05  /league=cup  /status=planned\n" +
		"counts /status  planned=2\n"
	if strings.Join(strings.Fields(out), " ") != strings.Join(strings.Fields(want), " ") {
		t.Errorf("search cup*:\n%s\nwant\n%s", out, want)
	}

	out, _ = search("matches", "--facet", "/league=allsvenskan")
	if !strings.HasPrefix(out, "derby ") || strings.Count(out, "\n") != 1 {
		t.Errorf("--facet: %q", out)
	}

	// Paging: next is the after of the following page.
	out, errw := search("matches", "--sort", "/kickoff", "--limit", "2")
	if strings.Count(out, "\n") != 2 || !strings.HasPrefix(errw, "more: --at ") {
		t.Fatalf("page 1: %q %q", out, errw)
	}
	var at, after string
	if _, err := fmt.Sscanf(errw, "more: --at %s --after %s", &at, &after); err != nil {
		t.Fatalf("more: %q: %v", errw, err)
	}
	out, errw = search("matches", "--sort", "/kickoff", "--limit", "2", "--at", at, "--after", after)
	if !strings.HasPrefix(out, "final ") || strings.Count(out, "\n") != 1 || errw != "" {
		t.Errorf("page 2: %q %q", out, errw)
	}
	out, _ = search("matches", "--sort", "/kickoff", "--limit", "2", "--all")
	if strings.Count(out, "\n") != 3 || !strings.HasSuffix(strings.TrimSpace(out), "/status=planned") || !strings.Contains(out, "final") {
		t.Errorf("--all: %q", out)
	}

	// --json is the answer as served.
	out, _ = search("matches", "Derby", "--json")
	var res struct {
		Hits []struct{ Resource string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Hits) != 1 || res.Hits[0].Resource != "derby" {
		t.Errorf("--json: %v %s", err, out)
	}

	// Refusals name the problem.
	cmd := command(t, "search", "nosuch", "--index", srv.URL).(*searchCmd)
	if err := cmd.exec(ctx, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "namespace not indexed") || !strings.Contains(err.Error(), "404") {
		t.Errorf("unknown namespace: %v", err)
	}
	cmd = command(t, "search", "matches", "--facet", "nope", "--index", srv.URL).(*searchCmd)
	if err := cmd.exec(ctx, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "PATH=VALUE") {
		t.Errorf("bad --facet: %v", err)
	}
}

func TestTreeLsCommand(t *testing.T) {
	t.Parallel()
	_, c := serviceCore(t)
	ctx := context.Background()
	href := func(p string) []any { return []any{map[string]any{"href": "/r/cat/" + p}} }
	must(c.CreateDoc(ctx, "cat", "league", map[string]any{"title": "League", "parents": []any{}}))
	must(c.CreateDoc(ctx, "cat", "cups", map[string]any{"title": "Cups", "parents": []any{}}))
	must(c.CreateDoc(ctx, "cat", "round-1", map[string]any{"title": "Round 1", "parents": href("league")}))
	must(c.CreateDoc(ctx, "cat", "round-2", map[string]any{"title": "Round 2", "parents": href("league")}))
	must(c.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "The Derby"}))
	must(c.CreateDoc(ctx, "cat", "matches.derby", map[string]any{"parents": href("round-1")}))

	svc := must(tree.Open(ctx, tree.Options{
		Client: c, Catalog: "cat", DB: filepath.Join(t.TempDir(), "tree.db"), MinWait: 5 * time.Second,
		CheckerTTL: time.Millisecond, RepurgeInterval: -1, Logf: t.Logf,
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)},
	}))
	srv := httptest.NewServer(svc.Handler())
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done; srv.Close(); svc.Close() })
	// Until it has applied the namespaces it can't tell they are public.
	for _, ns := range []string{"cat", "matches"} {
		waitUntil(t, "the tree service to follow "+ns, func() bool {
			h, err := c.NSHead(ctx, ns)
			return err == nil && svc.Checkpoint(ns) == h.ID
		})
	}

	ls := func(args ...string) (string, string) {
		t.Helper()
		cmd, ok := command(t, append([]string{"tree", "ls"}, append(args, "--tree", srv.URL)...)...).(*treeLsCmd)
		if !ok {
			t.Fatalf("%q is not tree ls", args)
		}
		var out, errw strings.Builder
		if err := cmd.exec(ctx, &out, &errw); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		return out.String(), errw.String()
	}
	fields := func(s string) string { return strings.Join(strings.Fields(s), " ") }

	// A write after the service caught up is waited for with --min.
	late := must(c.CreateDoc(ctx, "cat", "late", map[string]any{"title": "Late", "parents": []any{}}))
	out, _ := ls("cat", "--min", "cat:"+late.NSID)
	if fields(out) != "folder cups Cups folder late Late folder league League" {
		t.Errorf("roots: %q", out)
	}
	out, _ = ls("cat", "league")
	if fields(out) != "folder round-1 Round 1 folder round-2 Round 2" {
		t.Errorf("children of league: %q", out)
	}
	out, _ = ls("cat", "round-1")
	if fields(out) != "item matches.derby" {
		t.Errorf("children of round-1: %q", out)
	}

	// Paging: a page of one, then all.
	out, errw := ls("cat", "league", "--limit", "1")
	if fields(out) != "folder round-1 Round 1" || !strings.HasPrefix(errw, "more (2 in all): --at ") {
		t.Fatalf("page 1: %q %q", out, errw)
	}
	var at, after string
	if _, err := fmt.Sscanf(errw, "more (2 in all): --at %s --after %s", &at, &after); err != nil {
		t.Fatalf("more: %q: %v", errw, err)
	}
	out, errw = ls("cat", "league", "--limit", "1", "--at", at, "--after", after)
	if fields(out) != "folder round-2 Round 2" || errw != "" {
		t.Errorf("page 2: %q %q", out, errw)
	}
	out, _ = ls("cat", "league", "--limit", "1", "--all")
	if fields(out) != "folder round-1 Round 1 folder round-2 Round 2" {
		t.Errorf("--all: %q", out)
	}

	out, _ = ls("cat", "--json")
	var roots struct{ Roots []struct{ Name string } }
	if err := json.Unmarshal([]byte(out), &roots); err != nil || len(roots.Roots) != 3 {
		t.Errorf("--json: %v %s", err, out)
	}

	cmd := command(t, "tree", "ls", "cat", "nosuch", "--tree", srv.URL).(*treeLsCmd)
	if err := cmd.exec(ctx, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "no such node") {
		t.Errorf("unknown node: %v", err)
	}
}

// TestTreeSubcommandParse: tree ls is a subcommand of the tree service
// command, whose own flags, --catalog required among them, still parse and
// are still required without it.
func TestTreeSubcommandParse(t *testing.T) {
	svc, ok := command(t, "tree", "--api", "http://x", "--catalog", "cat", "--db", "t.db").(*treeCmd)
	if !ok || svc.API != "http://x" || len(svc.Catalog) != 1 || svc.DB != "t.db" || svc.Ls != nil {
		t.Errorf("tree service: %+v", svc)
	}
	ls, ok := command(t, "tree", "ls", "cat", "a", "--bearer", "g", "--min", "cat:1x").(*treeLsCmd)
	if !ok || ls.Catalog != "cat" || ls.Path != "a" || ls.Bearer != "g" || len(ls.Min) != 1 || ls.Tree != "http://localhost:8082" {
		t.Errorf("tree ls: %+v", ls)
	}
	if code, msg := runStatus("tree"); code != 2 || !strings.Contains(msg, "--catalog is required") {
		t.Errorf("tree without --catalog: %d %q", code, msg)
	}
	t.Setenv("PATCHLOG_TREE", "http://tree:1")
	t.Setenv("PATCHLOG_INDEX", "http://index:2")
	if ls := command(t, "tree", "ls", "cat").(*treeLsCmd); ls.Tree != "http://tree:1" {
		t.Errorf("PATCHLOG_TREE: %q", ls.Tree)
	}
	if s := command(t, "search", "ns").(*searchCmd); s.Index != "http://index:2" {
		t.Errorf("PATCHLOG_INDEX: %q", s.Index)
	}
}
