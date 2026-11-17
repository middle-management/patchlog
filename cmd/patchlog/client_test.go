package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
	if _, _, err := clientRun(t, ctx, s.URL, "get", "matches/final"); err == nil || !strings.Contains(err.Error(), "is deleted") {
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

// TestClientErrors: a client command that fails returns its error, which
// runClient exits 1 with, and a missing resource is named plainly.
func TestClientErrors(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	if _, _, err := clientRun(t, context.Background(), s.URL, "ns", "create", "m"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"get", "m/nope"}, {"patch", "m/nope", "[]"}, {"rm", "m/nope"}} {
		cmd := command(t, append(args, "--api", s.URL, "--author", "a")...).(clientCommand)
		err := execClient(cmd, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "m/nope doesn't exist") {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// TestUndoRedoBranch: CLI writes carry a gesture each, or one --gesture
// names; undo and redo act on the author's stack, or on a gesture given
// as the action that was written; branch create copies the base.
func TestUndoRedoBranch(t *testing.T) {
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
	doc := func(res string) any {
		t.Helper()
		out, _, err := clientRun(t, ctx, s.URL, "get", res)
		if err != nil {
			return err.Error()
		}
		var v map[string]any
		json.Unmarshal([]byte(out), &v)
		return v["n"]
	}
	gesture := func(out, _ string) string {
		t.Helper()
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil || v["gesture"] == "" {
			t.Fatalf("%v: %s", err, out)
		}
		return v["gesture"].(string)
	}

	must("ns", "create", "m")
	g1 := gesture(must("put", "m/a", `{"n":1}`, "--json"))
	g2 := gesture(must("patch", "m/a", `[{"op":"replace","path":"/n","value":2}]`, "--json"))
	if g1 == g2 {
		t.Fatal("two writes, one gesture")
	}
	must("patch", "m/a", `[{"op":"replace","path":"/n","value":3}]`, "--gesture", g2)
	must("put", "m/b", `{"n":1}`, "--gesture", g2)

	out, _ := must("undo", "m", "--list")
	if !strings.Contains(out, "done (2)") || !strings.Contains(out, g2+"  ") || !strings.Contains(out, "a, b") {
		t.Fatalf("undo --list:\n%s", out)
	}
	out, _ = must("undo", "m", "--plan")
	if !strings.Contains(out, "undo of "+g2) || !strings.Contains(out, "b: deleted again") || doc("m/a") != 3.0 {
		t.Fatalf("undo --plan wrote, or said:\n%s", out)
	}
	_, msg := must("undo", "m")
	if !strings.Contains(msg, "undid "+g2) || doc("m/a") != 1.0 || doc("m/b") != "m/b is deleted (tombstone "+tombstone(t, s.URL, "m/b")+")" {
		t.Fatalf("undo: %q, a %v, b %v", msg, doc("m/a"), doc("m/b"))
	}
	_, msg = must("redo", "m")
	if !strings.Contains(msg, "redid "+g2) || doc("m/a") != 3.0 || doc("m/b") != 1.0 {
		t.Fatalf("redo: %q, a %v, b %v", msg, doc("m/a"), doc("m/b"))
	}
	if _, _, err := clientRun(t, ctx, s.URL, "redo", "m"); err == nil || !strings.Contains(err.Error(), "nothing to redo") {
		t.Fatalf("redo with nothing undone: %v", err)
	}
	// g2 was undone and redone: undo and redo find it by the gesture the
	// writes carried.
	must("undo", "m", g2)
	if doc("m/a") != 1.0 {
		t.Fatalf("undo %s: a %v", g2, doc("m/a"))
	}
	if _, _, err := clientRun(t, ctx, s.URL, "undo", "m", g2); err == nil || !strings.Contains(err.Error(), "undone already") {
		t.Fatalf("undo of an undone action: %v", err)
	}
	must("redo", "m", g2)
	if doc("m/a") != 3.0 {
		t.Fatalf("redo %s: a %v", g2, doc("m/a"))
	}
	// Undoing the create conflicts with the writes after it: the plan
	// shows them and fails, writing nothing.
	if out, _, err := clientRun(t, ctx, s.URL, "undo", "m", g1, "--plan"); !client.IsUndoConflict(err) || !strings.Contains(out, "CONFLICT a: overlap") || doc("m/a") != 3.0 {
		t.Fatalf("undo --plan of a conflicting action: %v\n%s", err, out)
	}

	name, _ := must("branch", "create", "m", "r1", "--patch", `[{"op":"add","path":"/x-note","value":"draft"}]`)
	if strings.TrimSpace(name) != "r1" {
		t.Fatalf("branch create printed %q", name)
	}
	must("patch", "r1/a", `[{"op":"replace","path":"/n","value":9}]`)
	if doc("r1/a") != 9.0 || doc("m/a") != 3.0 {
		t.Fatalf("branch r1/a %v, base m/a %v", doc("r1/a"), doc("m/a"))
	}
	out, _ = must("branch", "list", "m")
	if !strings.HasPrefix(out, "r1 ") {
		t.Fatalf("branch list: %q", out)
	}
	out, _ = must("ns", "get", "r1")
	if !strings.Contains(out, `"x-note": "draft"`) {
		t.Fatalf("branch document: %s", out)
	}
}

// tombstone is the head id of a deleted resource.
func tombstone(t *testing.T, api, res string) string {
	t.Helper()
	c, err := client.New(api)
	if err != nil {
		t.Fatal(err)
	}
	ns, name, _ := strings.Cut(res, "/")
	h, err := c.Head(context.Background(), ns, name)
	if err != nil {
		t.Fatal(err)
	}
	return h.ID
}

// TestBlobCommands: blob put uploads and prints the reference, or with
// --at writes it; blob get reads it back by --at or by id (and nonce),
// checked against the id.
func TestBlobCommands(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	dir := t.TempDir()
	must := func(args ...string) (string, string) {
		t.Helper()
		out, errw, err := clientRun(t, ctx, s.URL, args...)
		if err != nil {
			t.Fatalf("%q: %v\n%s", args, err, errw)
		}
		return out, errw
	}
	photo := filepath.Join(dir, "photo.png")
	data := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{7}, 5000)...)
	if err := os.WriteFile(photo, data, 0o600); err != nil {
		t.Fatal(err)
	}
	must("ns", "create", "d")
	must("put", "d/r", `{"title":"x"}`)

	must("blob", "put", "d/r", photo, "--at", "/photo")
	out, _ := must("get", "d/r")
	var doc map[string]any
	json.Unmarshal([]byte(out), &doc)
	ref, _ := doc["photo"].(map[string]any)
	if ref["type"] != "image/png" || ref["size"] != float64(len(data)) || ref["$blob"] == nil {
		t.Fatalf("reference at /photo: %v", doc)
	}
	got := filepath.Join(dir, "got.png")
	must("blob", "get", "d/r", "--at", "/photo", "-o", got)
	if b, _ := os.ReadFile(got); !bytes.Equal(b, data) {
		t.Fatal("blob get --at returned other bytes")
	}

	// Without --at: the reference is printed, the blob pending until a
	// write references it.
	out, _ = must("blob", "put", "d/r", photo, "--nonce", "--type", "application/octet-stream")
	var ref2 map[string]any
	if err := json.Unmarshal([]byte(out), &ref2); err != nil || ref2["nonce"] == nil || ref2["type"] != "application/octet-stream" {
		t.Fatalf("blob put printed %s", out)
	}
	bid, nonce := ref2["$blob"].(string), ref2["nonce"].(string)
	if _, _, err := clientRun(t, ctx, s.URL, "blob", "get", "d/r", bid, "--nonce", nonce); err == nil {
		t.Fatal("a pending blob was served")
	}
	must("patch", "d/r", `[{"op":"add","path":"/raw","value":`+strings.TrimSpace(out)+`}]`)
	out, _ = must("blob", "get", "d/r", bid, "--nonce", nonce)
	if out != string(data) {
		t.Fatal("blob get by id returned other bytes")
	}
	if _, _, err := clientRun(t, ctx, s.URL, "blob", "get", "d/r", bid); err == nil || !strings.Contains(err.Error(), "--nonce") {
		t.Fatalf("blob get without its nonce: %v", err)
	}
	for _, args := range [][]string{{"blob", "get", "d/r", "--at", "/title"}, {"blob", "get", "d/r"}, {"blob", "get", "d/r", bid, "--at", "/photo"}} {
		if _, _, err := clientRun(t, ctx, s.URL, args...); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}

// TestGetFollow: get --follow waits for a resource that doesn't exist
// yet, prints each revision as one line of JSON and a tombstone as null,
// and ends with an error when the resource is purged.
func TestGetFollow(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("alice"))
	if _, err := c.CreateNamespace(ctx, "m", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	cmd := command(t, "get", "m/d", "--follow", "--api", s.URL).(*getCmd)
	out := &syncWriter{w: &bytes.Buffer{}}
	done := make(chan error, 1)
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	go func() { done <- cmd.exec(fctx, out, io.Discard) }()
	waitLines := func(n int) {
		t.Helper()
		for strings.Count(out.String(), "\n") < n {
			if fctx.Err() != nil {
				t.Fatalf("follow printed %q, want %d lines", out.String(), n)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	time.Sleep(100 * time.Millisecond) // following before the create
	w, err := c.CreateDoc(ctx, "m", "d", map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	waitLines(1)
	if w, err = c.Append(ctx, "m", "d", w.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}}); err != nil {
		t.Fatal(err)
	}
	waitLines(2)
	tomb, err := c.Delete(ctx, "m", "d", w.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitLines(3)
	if got := out.String(); got != "{\"n\":1}\n{\"n\":2}\nnull\n" {
		t.Fatalf("follow printed %q", got)
	}
	if _, err := c.Purge(ctx, "m", "d", tomb.ID, false); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "purged") {
			t.Fatalf("follow after the purge: %v", err)
		}
	case <-fctx.Done():
		t.Fatal("follow didn't end with the purge")
	}
}
