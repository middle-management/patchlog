package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// E2E-10: patchlog e2e migrate-keyring is removed (v0.78, "Reading this
// spec": no client reads a keyring in the format before v0.63): it says
// so, names the v0.26.1 client's tool to run before upgrading, and exits
// non-zero.
func TestV081MigrateKeyringRemoved(t *testing.T) {
	t.Parallel()
	var out, errw bytes.Buffer
	if code := runE2E([]string{"migrate-keyring", "-ns", "e", "-identity", "x"}, &out, &errw); code == 0 {
		t.Fatalf("migrate-keyring exited 0")
	}
	if msg := errw.String(); !strings.Contains(msg, "removed in v0.81") || !strings.Contains(msg, "v0.26.1") || out.Len() != 0 {
		t.Fatalf("migrate-keyring said %q / %q", msg, out.String())
	}
	if code := runE2E(nil, &out, &errw); code != 2 {
		t.Fatalf("no subcommand: %d", code)
	}
}

// KEYS-11: patchlog e2e seal-status prints how near a resource's K_r of
// the current epoch is to the message bound (§E.2.1), as the client counts
// it from the log.
func TestV081SealStatusCommand(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, _ := seal.GenerateRecipient()
	if _, err := c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	x := c.E2E(priv).WithoutValidation()
	if _, err := x.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.CreateSealed(ctx, "e", "d", client.GenesisPatches(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	if code := runE2E([]string{"seal-status", "-api", s.URL, "-author", "alice", "-ns", "e", "-name", "d", "-json"}, &out, &errw); code != 0 {
		t.Fatalf("seal-status: %d %s", code, errw.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if got["kid"] != "e#1" || got["sealed"] != 1.0 || got["rotationDue"] != false || got["bound"] != float64(client.DefaultSealBound) {
		t.Fatalf("seal-status %v", got)
	}
	line := sealStatusLine(&client.SealStatus{NS: "e", Name: "d", Kid: "e#1", Sealed: 3, Bound: 4, Margin: 1, RotationDue: true})
	if !strings.Contains(line, "rotation due") {
		t.Fatalf("line %q", line)
	}
	if code := runE2E([]string{"seal-status", "-api", s.URL}, &out, &errw); code != 2 {
		t.Fatalf("seal-status without -ns and -name: %d", code)
	}
}
