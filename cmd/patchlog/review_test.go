package main

// Regression tests for the review of PR #24.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// A flag's value that happens to be a secret flag's name isn't that
// flag: --author bearer with --bearer-file is not "both given".
func TestFlagGivenSkipsValues(t *testing.T) {
	if flagGiven([]string{"get", "docs/x", "--author", "bearer"}, "bearer") {
		t.Error("the value bearer counted as --bearer")
	}
	if !flagGiven([]string{"get", "--bearer=x"}, "bearer") || !flagGiven([]string{"-bearer", "x"}, "bearer") {
		t.Error("--bearer=x or -bearer x not seen")
	}
	if flagGiven([]string{"--", "--bearer"}, "bearer") {
		t.Error("an argument after -- counted")
	}
}

// dav's --bearer-file (and $PATCHLOG_BEARER_FILE, which a profile sets)
// is read into --bearer as every command's is.
func TestDavBearerFile(t *testing.T) {
	cleanEnv(t)
	f := filepath.Join(t.TempDir(), "g")
	if err := os.WriteFile(f, []byte("the-grant\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATCHLOG_BEARER_FILE", f)
	cmd := command(t, "dav", "--ns", "docs").(*davCmd)
	if err := resolveSecretFiles(cmd, []string{"dav", "--ns", "docs"}, &bytes.Buffer{}); err != nil || cmd.Bearer != "the-grant" {
		t.Fatalf("dav bearer %q, %v", cmd.Bearer, err)
	}
}

// Undo and redo of the stack's last action undo the stack owner's writes
// only, even when another author wrote under the same gesture id; and
// undo --plan --json of a conflicting action fails as the text form does.
func TestUndoOwnerAndPlanJSON(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	as := func(author string, args ...string) (string, error) {
		t.Helper()
		cmd := command(t, append(args, "--api", s.URL, "--author", author)...).(clientCommand)
		var out bytes.Buffer
		err := cmd.exec(ctx, &out, &bytes.Buffer{})
		return out.String(), err
	}
	must := func(author string, args ...string) string {
		t.Helper()
		out, err := as(author, args...)
		if err != nil {
			t.Fatalf("%s %q: %v", author, args, err)
		}
		return out
	}
	doc := func(res string) any {
		t.Helper()
		out, err := as("x", "get", res)
		if err != nil {
			return err.Error()
		}
		var v map[string]any
		json.Unmarshal([]byte(out), &v)
		return v["n"]
	}
	must("alice", "ns", "create", "m")
	must("alice", "put", "m/a", `{"n":1}`)
	must("bob", "put", "m/b", `{"n":1}`)
	g := client.NewGesture()
	must("alice", "patch", "m/a", `[{"op":"replace","path":"/n","value":2}]`, "--gesture", g)
	must("bob", "patch", "m/b", `[{"op":"replace","path":"/n","value":2}]`, "--gesture", g)

	must("bob", "undo", "m") // bob's last action is g: his write to b only
	if doc("m/b") != 1.0 || doc("m/a") != 2.0 {
		t.Fatalf("bob's undo: a %v (alice's, want 2), b %v (want 1)", doc("m/a"), doc("m/b"))
	}
	must("bob", "redo", "m")
	if doc("m/b") != 2.0 || doc("m/a") != 2.0 {
		t.Fatalf("bob's redo: a %v, b %v", doc("m/a"), doc("m/b"))
	}

	// alice's create of a conflicts with her later write to it.
	st, err := s.Client(t).UndoStack(ctx, "m", "alice")
	if err != nil || len(st.Done) == 0 {
		t.Fatalf("alice's stack %+v %v", st, err)
	}
	out, err := as("alice", "undo", "m", st.Done[0].Target, "--plan", "--json")
	if !client.IsUndoConflict(err) || !strings.Contains(out, `"conflicts"`) {
		t.Fatalf("undo --plan --json of a conflicting action: %v\n%s", err, out)
	}
}

// --at ” is the root pointer: blob put writes the reference as the
// document, and blob get reads it there.
func TestBlobAtRoot(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	f := filepath.Join(t.TempDir(), "b.txt")
	if err := os.WriteFile(f, []byte("root blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"ns", "create", "d"}, {"put", "d/r", `{}`}, {"blob", "put", "d/r", f, "--at", ""}} {
		if _, errw, err := clientRun(t, ctx, s.URL, args...); err != nil {
			t.Fatalf("%q: %v %s", args, err, errw)
		}
	}
	out, _, err := clientRun(t, ctx, s.URL, "get", "d/r")
	if err != nil || !strings.Contains(out, `"$blob"`) {
		t.Fatalf("the document after --at '': %v %s", err, out)
	}
	out, _, err = clientRun(t, ctx, s.URL, "blob", "get", "d/r", "--at", "")
	if err != nil || out != "root blob" {
		t.Fatalf("blob get --at '': %v %q", err, out)
	}
}

// A write whose namespace's level can't be told (a grant that reads
// neither the namespace document nor a level from /keys) sends nothing,
// unless --plain or --expect-level tells it; then it goes out.
func TestWriteRefusedWhenLevelUnknown(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var content []string // requests that carried a document or patch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"spec":"x","auth":"grants","origin":"http://x"}`))
		case r.URL.Path == "/ns/n" || strings.HasPrefix(r.URL.Path, "/ns/n/rev"):
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"forbidden"}`))
		case r.URL.Path == "/ns/n/keys":
			w.WriteHeader(422)
			w.Write([]byte(`{"code":"invalid","message":"the grant has no enc"}`))
		case r.Method == "PATCH" || r.Method == "PUT" || r.Method == "POST":
			mu.Lock()
			content = append(content, r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"forbidden","message":"stub"}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"not_found"}`))
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	f := filepath.Join(t.TempDir(), "b")
	os.WriteFile(f, []byte("x"), 0o600)
	bf := batchFile(t)
	for _, args := range [][]string{
		{"put", "n/d", `{"secret":1}`},
		{"patch", "n/d", `[{"op":"add","path":"/secret","value":1}]`},
		{"blob", "put", "n/d", f},
		{"restore", "n/d"},
		{"batch", "n", bf},
	} {
		_, _, err := clientRun(t, ctx, srv.URL, args...)
		if err == nil || !strings.Contains(err.Error(), "can't tell whether namespace n is encrypted") {
			t.Errorf("%q: %v", args, err)
		}
	}
	mu.Lock()
	if len(content) != 0 {
		t.Errorf("content sent with the level unknown: %q", content)
	}
	mu.Unlock()
	// Told: --plain sends it (the stub refuses it, 403).
	if _, _, err := clientRun(t, ctx, srv.URL, "put", "n/d", `{"a":1}`, "--plain"); err == nil || strings.Contains(err.Error(), "can't tell") {
		t.Errorf("put --plain: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(content) != 1 {
		t.Errorf("put --plain sent %q", content)
	}
}

// restore and batch, which can't seal, refuse an e2e namespace rather
// than send its content in the clear.
func TestPlainWritesRefuseE2E(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{KeyStore: testKeyStore(t)})
	ctx := context.Background()
	if _, err := s.Client(t, client.WithAuthor("a")).CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"restore", "e/d"}, {"batch", "e", batchFile(t)}} {
		_, _, err := clientRun(t, ctx, s.URL, args...)
		if err == nil || !strings.Contains(err.Error(), "end-to-end encrypted") {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// batchFile is a file holding a batch that creates one resource.
func batchFile(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(f, []byte(`{"items":[{"resource":"d","ifNoneMatch":"*","steps":[[{"op":"add","path":"","value":{"secret":1}}]]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}
