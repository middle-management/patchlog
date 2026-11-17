package main

// Regression tests for the review of PR #24.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
