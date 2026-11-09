package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
)

// v077Tool runs `patchlog rebase` or `patchlog merge release` with args in
// a child process (each exits on failure), returning its output and
// whether it exited 0.
func v077Tool(t *testing.T, test string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$")
	cmd.Env = append(os.Environ(), "V077_TOOL=1", "V077_ARGS="+strings.Join(args, "\x1f"))
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// v077Child runs the tool the parent asked for, in the child process.
func v077Child() bool {
	if os.Getenv("V077_TOOL") != "1" {
		return false
	}
	args := strings.Split(os.Getenv("V077_ARGS"), "\x1f")
	switch args[0] {
	case "rebase":
		rebaseCmd(args[1:])
	case "release":
		releaseCmd(args[1:])
	}
	return true
}

// v077PurgedInSuccessor is a development core where r7 (a branch of
// matches) changed derby, was rebased into succ without a switch, derby
// was purged in succ only, and r7 changed derby again: a rebase with a
// switch can't record derby in succ.
func v077PurgedInSuccessor(t *testing.T, succ string) (*clienttest.Server, *client.Client) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	op := func(path string, v any) []any {
		return []any{map[string]any{"op": "replace", "path": path, "value": v}}
	}
	if _, err := c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}); err != nil {
		t.Fatal(err)
	}
	appendTo := func(ns string, patches []any) {
		h, err := c.Head(ctx, ns, "derby")
		if err == nil {
			_, err = c.Append(ctx, ns, "derby", h.ID, patches)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	appendTo("r7", op("/score", "1-0"))
	if _, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: succ}); err != nil {
		t.Fatal(err)
	}
	h, err := c.Head(ctx, succ, "derby")
	if err == nil {
		_, err = c.Purge(ctx, succ, "derby", h.ID, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	appendTo("r7", op("/score", "2-0"))
	return s, c
}

// v077Frozen returns ns's frozen flag and successor.
func v077Frozen(t *testing.T, c *client.Client, ns string) (bool, string) {
	t.Helper()
	ctx := context.Background()
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	frozen, _ := d.Value["frozen"].(bool)
	succ, _ := d.Value["successor"].(string)
	return frozen, succ
}

// OTHER-5 (§F.5 Switch, "or a person has given up the rest"): `patchlog
// rebase -switch` stops on a resource the successor can't record (here
// purged in it only), saying so and naming -leave-out; with -leave-out it
// switches and prints what it gave up.
func TestV077RebaseLeaveOutFlag(t *testing.T) {
	if v077Child() {
		return
	}
	t.Parallel()
	s, c := v077PurgedInSuccessor(t, "r7b")
	base := []string{"rebase", "-api", s.URL, "-author", "alice", "-branch", "r7", "-new", "r7b", "-switch"}
	out, ok := v077Tool(t, "TestV077RebaseLeaveOutFlag", base...)
	if ok || !strings.Contains(out, "derby") || !strings.Contains(out, "-leave-out") {
		t.Fatalf("rebase -switch: ok %v\n%s", ok, out)
	}
	if frozen, _ := v077Frozen(t, c, "r7"); frozen {
		t.Fatalf("r7 frozen without -leave-out\n%s", out)
	}
	out, ok = v077Tool(t, "TestV077RebaseLeaveOutFlag", append(base, "-leave-out")...)
	if !ok || !strings.Contains(out, "left out, only in the frozen r7: derby") {
		t.Fatalf("rebase -switch -leave-out: ok %v\n%s", ok, out)
	}
	if frozen, succ := v077Frozen(t, c, "r7"); !frozen || succ != "r7b" {
		t.Fatalf("r7 frozen %v with successor %q\n%s", frozen, succ, out)
	}
}

// OTHER-5 (§F.5, §F.9): `patchlog merge release rebase -leave-out` gives
// up, for each branch's switch, what its successor can't record.
func TestV077ReleaseRebaseLeaveOutFlag(t *testing.T) {
	if v077Child() {
		return
	}
	t.Parallel()
	ctx := context.Background()
	s, c := v077PurgedInSuccessor(t, "r7-b")
	if _, err := c.CreateNamespace(ctx, "releases", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	h, err := c.NSHead(ctx, "r7")
	if err != nil {
		t.Fatal(err)
	}
	nd, err := c.NSDoc(ctx, "r7", h.ID)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := nd.Value["base"].(map[string]any)["at"].(string)
	if _, err := release.Write(ctx, c, release.Ref{NS: "releases", Name: "rel"}, "", &release.Doc{Name: "rel", Branches: map[string]release.Branch{"matches": {NS: "r7", At: at}}}); err != nil {
		t.Fatal(err)
	}
	base := []string{"release", "rebase", "-api", s.URL, "-author", "alice", "-suffix", "-b"}
	out, ok := v077Tool(t, "TestV077ReleaseRebaseLeaveOutFlag", append(base, "/r/releases/rel")...)
	if ok || !strings.Contains(out, "derby") || !strings.Contains(out, "-leave-out") {
		t.Fatalf("release rebase: ok %v\n%s", ok, out)
	}
	out, ok = v077Tool(t, "TestV077ReleaseRebaseLeaveOutFlag", append(base, "-leave-out", "/r/releases/rel")...)
	if !ok || !strings.Contains(out, "left out, only in the frozen r7: derby") {
		t.Fatalf("release rebase -leave-out: ok %v\n%s", ok, out)
	}
	if frozen, succ := v077Frozen(t, c, "r7"); !frozen || succ != "r7-b" {
		t.Fatalf("r7 frozen %v with successor %q\n%s", frozen, succ, out)
	}
}
