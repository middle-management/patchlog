package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// clientRun parses a client command line against the server at api and
// runs it, returning stdout, stderr and its error.
func clientRun(t *testing.T, ctx context.Context, api string, args ...string) (string, string, error) {
	t.Helper()
	cmd, ok := command(t, append(args, "--api", api, "--author", "alice")...).(clientCommand)
	if !ok {
		t.Fatalf("%q is not a client command", args)
	}
	var out, errw bytes.Buffer
	err := cmd.exec(ctx, &out, &errw)
	return out.String(), errw.String(), err
}

// TestClientCommands runs the README's short tour with the client
// commands: each write supplies its precondition (§7.2), --if pins one,
// and the reads, logs and watch see what was written.
func TestClientCommands(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	must := func(args ...string) (string, string) {
		t.Helper()
		out, errw, err := clientRun(t, ctx, s.URL, args...)
		if err != nil {
			t.Fatalf("%q: %v\n%s", args, err, errw)
		}
		return out, errw
	}
	jsonOut := func(out string) any {
		t.Helper()
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return v
	}

	cfg, msg := must("ns", "create", "matches", `{"read":"public"}`)
	if !strings.Contains(msg, "created namespace matches") || len(strings.TrimSpace(cfg)) == 0 {
		t.Fatalf("ns create: %q %q", cfg, msg)
	}
	must("put", "matches/derby", `{"score":"0-0"}`)
	if _, _, err := clientRun(t, ctx, s.URL, "put", "matches/derby", `{"score":"9-9"}`); err == nil {
		t.Fatal("put of an existing resource: not refused")
	}
	r1, _ := must("patch", "matches/derby", `[{"op":"replace","path":"/score","value":"1-0"}]`)
	r1 = strings.TrimSpace(r1)
	must("patch", "matches/derby", "--if", r1, `[{"op":"replace","path":"/score","value":"2-0"}]`)
	if _, _, err := clientRun(t, ctx, s.URL, "patch", "matches/derby", "--if", r1, `[{"op":"replace","path":"/score","value":"1-1"}]`); !client.IsStale(err) {
		t.Fatalf("patch --if a moved head: %v", err)
	}
	out, _ := must("get", "matches/derby")
	if got := jsonOut(out); !reflect.DeepEqual(got, map[string]any{"score": "2-0"}) {
		t.Fatalf("get: %v", got)
	}
	out, _ = must("get", "matches/derby", "--rev", r1)
	if got := jsonOut(out); !reflect.DeepEqual(got, map[string]any{"score": "1-0"}) {
		t.Fatalf("get --rev: %v", got)
	}
	out, _ = must("log", "matches/derby")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 3 || !strings.Contains(lines[1], r1) || !strings.Contains(lines[2], `"2-0"`) {
		t.Fatalf("log: %s", out)
	}

	must("ns", "config", "matches", `[{"op":"add","path":"/x-description","value":"football"}]`)
	out, _ = must("ns", "get", "matches")
	if got := jsonOut(out).(map[string]any); got["x-description"] != "football" || got["read"] != "public" {
		t.Fatalf("ns get: %v", got)
	}
	if _, _, err := clientRun(t, ctx, s.URL, "ns", "config", "matches", "--if", strings.TrimSpace(cfg), `[{"op":"remove","path":"/x-description"}]`); !client.IsStale(err) {
		t.Fatalf("ns config --if a replaced config: %v", err)
	}

	must("put", "matches/final", `{}`)
	out, _ = must("rm", "matches/final", "--json")
	if id := jsonOut(out).(map[string]any)["id"]; id == "" || id == nil {
		t.Fatalf("rm --json: %s", out)
	}
	if _, _, err := clientRun(t, ctx, s.URL, "get", "matches/final"); err == nil || !strings.Contains(err.Error(), "tombstoned") {
		t.Fatalf("get of a deleted resource: %v", err)
	}
	if _, _, err := clientRun(t, ctx, s.URL, "get", "matches"); err == nil || !strings.Contains(err.Error(), "NS/NAME") {
		t.Fatalf("get without a name: %v", err)
	}

	nsLog, _ := must("ns", "log", "matches")
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	watched := &syncWriter{w: &bytes.Buffer{}}
	cmd := command(t, "watch", "matches", "--api", s.URL).(*watchCmd)
	go func() {
		for wctx.Err() == nil && strings.Count(watched.String(), "\n") < strings.Count(nsLog, "\n") {
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()
	cmd.exec(wctx, watched, &bytes.Buffer{})
	if watched.String() != nsLog || !strings.Contains(nsLog, "tombstone  final") {
		t.Fatalf("watch printed\n%s\nns log printed\n%s", watched.String(), nsLog)
	}
}

// TestClientEnv checks --api, --bearer and --author default to
// $PATCHLOG_API, $PATCHLOG_BEARER and $PATCHLOG_AUTHOR, the client
// commands' and the tools' alike, and a flag overrides them.
func TestClientEnv(t *testing.T) {
	t.Setenv("PATCHLOG_API", "http://env:1")
	t.Setenv("PATCHLOG_BEARER", "g")
	t.Setenv("PATCHLOG_AUTHOR", "bob")
	g := command(t, "get", "a/b").(*getCmd)
	j := command(t, "janitor", "--ns", "x", "--author", "carol").(*janitorCmd)
	if g.API != "http://env:1" || g.Bearer != "g" || g.Author != "bob" || j.API != "http://env:1" || j.Author != "carol" {
		t.Fatalf("get %+v, janitor %+v", g.toolArgs, j.toolArgs)
	}
}

// TestRootHelpGroups checks every command is in a group of the root help.
func TestRootHelpGroups(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if code := run([]string{"--help"}, &out, &out); code != 0 {
		t.Fatalf("--help: %d", code)
	}
	ty := reflect.TypeOf(cli{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		_, name, _ := strings.Cut(strings.Split(f.Tag.Get("arg"), ",")[0], ":")
		if f.Tag.Get("group") == "" || !strings.Contains(out.String(), "\n  "+name+" ") {
			t.Errorf("%s: group %q, not in\n%s", name, f.Tag.Get("group"), out.String())
		}
	}
	for _, g := range []string{"Server commands:", "Client commands:"} {
		if !strings.Contains(out.String(), g) {
			t.Errorf("no %q", g)
		}
	}
}

// syncWriter serialises writes, for a buffer another goroutine reads.
type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.String()
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
