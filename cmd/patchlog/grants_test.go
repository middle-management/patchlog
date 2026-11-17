package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/sig"
)

func inspect(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := command(t, append([]string{"grant", "inspect"}, args...)...).(*grantInspectCmd)
	var out bytes.Buffer
	err := cmd.exec(strings.NewReader(stdin), &out, time.Now())
	return out.String(), err
}

func TestGrantInspect(t *testing.T) {
	t.Parallel()
	admin := clienttest.NewKey("admin")
	signer := sig.Key{Kid: "k1", Priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
	now := time.Now()
	tok := admin.Grant(t, now, "user:alice", []string{"docs", "wiki"}, []string{"read", "append"},
		map[string]any{"signers": []any{signer.Entry()}})
	g := must(grant.Decode(tok, 0))
	g = must(g.Narrow(map[string]any{"can": []any{"read"}, "exp": now.Add(10 * time.Minute).Format(time.RFC3339)}))
	g = must(g.Seal())
	tok = g.Encode()

	out, err := inspect(t, "", tok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 block(s), sealed: yes", "block 0 (root)", "block 1 (narrowing)", "kid      admin",
		"sub      user:alice", "ns       docs, wiki", "can      read, append", "can      read\n", "(in 59m)", "(in 9m)", "signers  k1 (Ed25519)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}

	// stdin, and JSON.
	jo, err := inspect(t, tok+"\n", "-", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Sealed   bool
		Verified bool
		Blocks   []map[string]any
	}
	if err := json.Unmarshal([]byte(jo), &v); err != nil {
		t.Fatal(err, jo)
	}
	if !v.Sealed || v.Verified || len(v.Blocks) != 2 || v.Blocks[0]["kid"] != "admin" || v.Blocks[0]["expired"] != false {
		t.Fatalf("%s", jo)
	}

	// An expired grant says so; garbage is an error.
	old := admin.Grant(t, now.Add(-3*time.Hour), "user:alice", []string{"docs"}, []string{"read"})
	if out, _ := inspect(t, "", old); !strings.Contains(out, "expired 2h ago") {
		t.Errorf("expired: %s", out)
	}
	if _, err := inspect(t, "", "garbage"); err == nil || !strings.Contains(err.Error(), "not a grant") {
		t.Errorf("garbage: %v", err)
	}
	if _, err := inspect(t, "  \n", "-"); err == nil {
		t.Error("an empty stdin was accepted")
	}
}

func TestGrantCheckShow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	admin := clienttest.NewKey("admin")
	oper := s.Client(t, client.WithBearer(s.OperatorGrant(t, "req")))
	must(oper.CreateNamespace(ctx, "req", map[string]any{"keys": []any{admin.Entry("*")}, "signatures": "required"}))

	k := sig.Key{Kid: "k1", Priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
	now := s.Now()
	alice := admin.Grant(t, now, "user:alice", []string{"req"}, []string{"read", "create"}, map[string]any{"signers": []any{k.Entry()}})
	root := admin.Grant(t, now, "user:root", []string{"req"}, []string{"read"})
	c := s.Client(t, client.WithBearer(alice)).With(client.WithSigner(k))
	must(c.Create(ctx, "req", "a", client.GenesisPatches(map[string]any{"n": 1})))
	log := must(c.Log(ctx, "req", "a", "", ""))
	gid := log[0].Grant.ID

	run := func(args ...string) (string, string, error) {
		t.Helper()
		return clientRun(t, ctx, s.URL, args...)
	}

	// check: allowed, with what it allows.
	out, _, err := run("grant", "check", "req", alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allowed in req (as of head ", "sub      user:alice", "key      admin", "can      create, read", "reads    every resource"} {
		if !strings.Contains(out, want) {
			t.Errorf("check: missing %q in\n%s", want, out)
		}
	}
	jo, _, err := run("grant", "check", "req", alice, "--json")
	var m map[string]any
	if err != nil || json.Unmarshal([]byte(jo), &m) != nil || m["allowed"] != true || m["sub"] != "user:alice" {
		t.Fatalf("check --json: %v %s", err, jo)
	}

	// refused: a namespace it doesn't name, an expired grant, an unknown key.
	other := admin.Grant(t, now, "user:alice", []string{"elsewhere"}, []string{"read"})
	_, _, err = run("grant", "check", "req", other, "--bearer", root)
	if err == nil || !strings.Contains(err.Error(), "refused: the grant does not apply to namespace") {
		t.Errorf("other namespace: %v", err)
	}
	expired := admin.Grant(t, now.Add(-3*time.Hour), "user:alice", []string{"req"}, []string{"read"})
	if _, _, err = run("grant", "check", "req", expired, "--bearer", root); err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
		t.Errorf("expired: %v", err)
	}
	stranger := clienttest.NewKey("stranger").Grant(t, now, "user:eve", []string{"req"}, []string{"read"})
	jo, _, err = run("grant", "check", "req", stranger, "--bearer", root, "--json")
	if err == nil || !strings.Contains(jo, `"allowed": false`) {
		t.Errorf("unknown key: %v %s", err, jo)
	}

	// show: the recorded grant.
	out, _, err = run("grant", "show", "req", gid, "--bearer", root)
	if err != nil || !strings.Contains(out, "grant "+gid) || !strings.Contains(out, `"user:alice"`) {
		t.Fatalf("show: %v\n%s", err, out)
	}
	jo, _, err = run("grant", "show", "req", gid, "--bearer", root, "--json")
	if err != nil || json.Unmarshal([]byte(jo), &m) != nil || m["id"] != gid {
		t.Fatalf("show --json: %v %s", err, jo)
	}
	missing := strings.Repeat("A", 43)
	if _, _, err = run("grant", "show", "req", missing, "--bearer", root); err == nil {
		t.Error("an unknown grant was shown")
	}
}
