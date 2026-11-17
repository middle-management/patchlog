package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// identityFiles writes a new X25519 identity to dir as NAME.jwk (private)
// and NAME.pub.jwk (public), as patchlog bundle keygen makes them, and
// returns both paths.
func identityFiles(t *testing.T, dir, name string) (priv, pub string) {
	t.Helper()
	jwk, key, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	priv, pub = filepath.Join(dir, name+".jwk"), filepath.Join(dir, name+".pub.jwk")
	for f, v := range map[string]any{priv: seal.RecipientPrivateJWK(key), pub: jwk} {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return priv, pub
}

// encRun parses a client command line against api, without --author, and
// runs it, returning stdout, stderr and its error.
func encRun(t *testing.T, ctx context.Context, api string, args ...string) (string, string, error) {
	t.Helper()
	cmd, ok := command(t, append(args, "--api", api)...).(clientCommand)
	if !ok {
		t.Fatalf("%q is not a client command", args)
	}
	var out, errw bytes.Buffer
	err := cmd.exec(ctx, &out, &errw)
	return out.String(), errw.String(), err
}

func jsonValue(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v: %q", err, s)
	}
	return v
}

func testKeyStore(t *testing.T) *keystore.Local {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// An e2e namespace administered, written and read back with the CLI: the
// admin creates the keyring and adds a reader, who writes and reads the
// documents, logs and blobs with --identity and --keyring-sender; the
// server holds only ciphertext; without --identity the commands refuse
// rather than print it; a rotation keeps the readers given and lists the
// others unless --yes.
func TestE2ECommands(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{KeyStore: testKeyStore(t)})
	ctx := context.Background()
	dir := t.TempDir()
	admin, adminPub := identityFiles(t, dir, "admin")
	reader, readerPub := identityFiles(t, dir, "reader")
	outsider, _ := identityFiles(t, dir, "outsider")
	asReader := []string{"--identity", reader, "--keyring-sender", adminPub}
	run := func(args ...string) (string, string, error) {
		t.Helper()
		return clientRun(t, ctx, s.URL, args...)
	}
	must := func(args ...string) (string, string) {
		t.Helper()
		out, errw, err := run(args...)
		if err != nil {
			t.Fatalf("%q: %v\n%s", args, err, errw)
		}
		return out, errw
	}
	// with is the command line args with the flags id after it.
	with := func(id []string, args ...string) []string { return append(append([]string{}, args...), id...) }

	must("ns", "create", "e", `{"encryption":{"level":"e2e"}}`)
	if _, _, err := run("e2e", "init", "e"); err == nil || !strings.Contains(err.Error(), "--identity ADMIN.jwk") {
		t.Fatalf("init without --identity: %v", err)
	}
	out, msg := must("e2e", "init", "e", "--identity", admin)
	if strings.TrimSpace(out) == "" || !strings.Contains(msg, "the key of e#1, wrapped for you and 0 more") {
		t.Fatalf("init: %q %q", out, msg)
	}
	_, msg = must("e2e", "add-reader", "e", readerPub, "--identity", admin)
	if !strings.Contains(msg, "(reader.pub.jwk)") {
		t.Fatalf("add-reader: %q", msg)
	}
	out, _ = must("e2e", "readers", "e", readerPub, "--identity", admin)
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 || !strings.Contains(out, "to ") || !strings.Contains(out, "(reader.pub.jwk)  from ") || !strings.Contains(out, "(you)") {
		t.Fatalf("readers: %q", out)
	}

	// The admin creates, the reader appends and both read it back.
	must("put", "e/d", `{"n":0,"title":"zqx-marker"}`, "--identity", admin)
	r1, _ := must(with(asReader, "patch", "e/d", `[{"op":"replace","path":"/n","value":1}]`)...)
	r1 = strings.TrimSpace(r1)
	for _, id := range [][]string{asReader, {"--identity", admin}} {
		out, _ := must(with(id, "get", "e/d")...)
		if got := jsonValue(t, out); !reflect.DeepEqual(got, map[string]any{"n": 1.0, "title": "zqx-marker"}) {
			t.Fatalf("get %q: %v", id, got)
		}
	}
	out, _ = must(with(asReader, "log", "e/d")...)
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 || !strings.Contains(lines[1], `"replace"`) || !strings.Contains(lines[0], "zqx-marker") {
		t.Fatalf("log: %q", out)
	}
	out, _ = must(with(asReader, "log", "e/d", "--json")...)
	if !strings.Contains(out, `"op":"replace"`) || strings.Contains(out, `"sealed"`) {
		t.Fatalf("log --json: %q", out)
	}
	// The server holds only ciphertext.
	es, err := s.Client(t).Log(ctx, "e", "d", r1, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if b, _ := json.Marshal(e.Raw); !strings.Contains(string(b), `"op":"sealed"`) || strings.Contains(string(b), "zqx-marker") {
			t.Fatalf("stored entry %s", b)
		}
	}

	// Without --identity: a clear error, never the ciphertext; with a key
	// the keyring doesn't hold: no key opens it.
	for _, args := range [][]string{{"get", "e/d"}, {"log", "e/d"}, {"patch", "e/d", `[]`}, {"put", "e/x", `{}`}} {
		out, _, err := run(args...)
		if err == nil || !strings.Contains(err.Error(), "end-to-end encrypted") || !strings.Contains(err.Error(), "--identity") || out != "" {
			t.Fatalf("%q without --identity: %q %v", args, out, err)
		}
	}
	if out, _, err := run("get", "e/d", "--identity", outsider, "--keyring-sender", adminPub); err == nil || out != "" || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("get by an outsider: %q %v", out, err)
	}
	// The keyring itself is plaintext, read without --identity.
	if out, _ := must("get", "e/keyring"); !strings.Contains(out, `"keys"`) {
		t.Fatalf("keyring: %q", out)
	}

	// Blobs: encrypted by the client under a key the reference carries.
	data := []byte("zqx blob bytes")
	f := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	must(with(asReader, "blob", "put", "e/d", f, "--at", "/file")...)
	got := filepath.Join(dir, "got.txt")
	must(with(asReader, "blob", "get", "e/d", "--at", "/file", "-o", got)...)
	if b, _ := os.ReadFile(got); !bytes.Equal(b, data) {
		t.Fatalf("blob %q", b)
	}
	if _, _, err := run(with(asReader, "blob", "get", "e/d", "abc")...); err == nil || !strings.Contains(err.Error(), "--at") {
		t.Fatalf("blob get by id: %v", err)
	}

	// --follow folds each revision as it is written.
	fctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, _, err := encRun(t, fctx, s.URL, with(asReader, "get", "e/d", "--follow", "--author", "alice")...)
		done <- result{out, err}
	}()
	time.Sleep(500 * time.Millisecond)
	must(with(asReader, "patch", "e/d", `[{"op":"replace","path":"/n","value":2}]`)...)
	time.Sleep(500 * time.Millisecond)
	cancel()
	res := <-done
	if lines := strings.Split(strings.TrimSpace(res.out), "\n"); res.err != nil || len(lines) != 2 || !strings.Contains(lines[1], `"n":2`) {
		t.Fatalf("follow: %q %v", res.out, res.err)
	}

	// Rotation: the readers not given are listed, and kept with their keys.
	if _, msg, err := run("e2e", "rotate", "e", "--identity", admin); err == nil || !strings.Contains(msg, "readers not given") {
		t.Fatalf("rotate dropping a reader: %v %q", err, msg)
	}
	out, _ = must("e2e", "rotate", "e", readerPub, "--identity", admin, "--json")
	if got := jsonValue(t, out).(map[string]any); got["epoch"] != 2.0 || len(got["revoked"].([]any)) != 0 {
		t.Fatalf("rotate: %v", got)
	}
	must(with(asReader, "patch", "e/d", `[{"op":"replace","path":"/n","value":3}]`)...)
	out, _ = must(with(asReader, "get", "e/d")...)
	if n := jsonValue(t, out).(map[string]any)["n"]; n != 3.0 {
		t.Fatalf("after rotation: %v", out)
	}
	if st, err := s.Client(t).E2E(nil).SealStatus(ctx, "e", "d"); err != nil || st.Kid != "e#2" {
		t.Fatalf("seal status %+v %v", st, err)
	}
	must(with(asReader, "rm", "e/d")...)
}

// A sealed namespace through the CLI with grants: writes add their
// $nonce, a grant whose enc wraps the keys reads with --identity and is
// told to give it without, e2e keys shows what /keys gives without the
// keys themselves unless --show-keys, and blobs are read through their
// reference.
func TestSealedCommands(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: testKeyStore(t)})
	ctx := context.Background()
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "s")))
	if _, err := op.CreateNamespace(ctx, "s", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rPriv, rPub := identityFiles(t, dir, "r")
	var enc any
	b, _ := os.ReadFile(rPub)
	json.Unmarshal(b, &enc)
	w := k.Grant(t, s.Now(), "user:w", []string{"s", "p"}, []string{"read", "create", "append", "delete"})
	r := k.Grant(t, s.Now(), "user:r", []string{"s"}, []string{"read"}, map[string]any{"enc": enc})
	run := func(args ...string) (string, string, error) {
		t.Helper()
		return encRun(t, ctx, s.URL, args...)
	}
	must := func(args ...string) (string, string) {
		t.Helper()
		out, errw, err := run(args...)
		if err != nil {
			t.Fatalf("%q: %v\n%s", args, err, errw)
		}
		return out, errw
	}

	must("put", "s/a", `{"v":1}`, "--bearer", w)
	must("patch", "s/a", `[{"op":"replace","path":"/v","value":2}]`, "--bearer", w)
	out, _ := must("get", "s/a", "--bearer", r, "--identity", rPriv, "--meta")
	doc := jsonValue(t, out).(map[string]any)
	if doc["v"] != 2.0 || !seal.ValidNonce(doc["$nonce"].(string)) {
		t.Fatalf("get: %v", doc)
	}
	if out, _, err := run("get", "s/a", "--bearer", r); err == nil || out != "" || !strings.Contains(err.Error(), "--identity") {
		t.Fatalf("get without --identity: %q %v", out, err)
	}
	out, _ = must("log", "s/a", "--bearer", r, "--identity", rPriv)
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 || !strings.Contains(lines[1], `"replace"`) {
		t.Fatalf("log: %q", out)
	}

	out, _ = must("e2e", "keys", "s", "--bearer", r)
	if !strings.Contains(out, "level sealed, epoch 1") || !strings.Contains(out, "s#1  wrapped  give --identity") {
		t.Fatalf("keys: %q", out)
	}
	out, _ = must("e2e", "keys", "s", "--bearer", r, "--identity", rPriv)
	if !strings.Contains(out, "opens with --identity") || strings.Contains(out, "key ") {
		t.Fatalf("keys --identity: %q", out)
	}
	out, _ = must("e2e", "keys", "s", "--bearer", r, "--identity", rPriv, "--show-keys", "--json")
	ks := jsonValue(t, out).(map[string]any)["keys"].([]any)
	if key, _ := ks[0].(map[string]any)["key"].(string); len(ks) != 1 || len(key) != 43 {
		t.Fatalf("keys --show-keys: %v", ks)
	}

	data := []byte("zqx sealed blob")
	f := filepath.Join(dir, "b.bin")
	os.WriteFile(f, data, 0o600)
	must("blob", "put", "s/a", f, "--at", "/b", "--bearer", w)
	got := filepath.Join(dir, "got.bin")
	must("blob", "get", "s/a", "--at", "/b", "-o", got, "--bearer", r, "--identity", rPriv)
	if b, _ := os.ReadFile(got); !bytes.Equal(b, data) {
		t.Fatalf("blob %q", b)
	}
	if _, _, err := run("blob", "get", "s/a", "abc", "--bearer", r, "--identity", rPriv); err == nil || !strings.Contains(err.Error(), "--at") {
		t.Fatalf("blob get by id: %v", err)
	}
	must("rm", "s/a", "--bearer", w)

	// A plain namespace is unchanged by --identity.
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "p"))).CreateNamespace(ctx, "p", map[string]any{"keys": []any{k.Entry("*")}}); err != nil {
		t.Fatal(err)
	}
	must("put", "p/a", `{"v":1}`, "--bearer", w, "--identity", rPriv)
	out, _ = must("get", "p/a", "--bearer", w, "--identity", rPriv)
	if got := jsonValue(t, out); !reflect.DeepEqual(got, map[string]any{"v": 1.0}) {
		t.Fatalf("plain get: %v", got)
	}
	if _, _, err := run("e2e", "keys", "p", "--bearer", w); err == nil || !strings.Contains(err.Error(), "neither sealed nor e2e") {
		t.Fatalf("keys of a plain namespace: %v", err)
	}
}
