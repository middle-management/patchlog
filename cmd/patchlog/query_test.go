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

// serviceCore is a dev-mode core with a typed namespace matches.
func serviceCore(t *testing.T) (*clienttest.Server, *client.Client) {
	t.Helper()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	ctx := context.Background()
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
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
