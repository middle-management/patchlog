package playground

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 Addendum E Levels (P35 x the playground; ENC-39, F-E1 default): the
// playground folds across a raise from sealed to e2e as the Go client does.
// The fold redirect of a revision written end to end starts at the last
// revision from before the raise, which /rev serves sealed as at E2 (no
// X-E2E), and a revision from before the raise reads as its sealed
// document.
func TestV073W4IntPlaygroundFoldsAcrossRaiseWithNode(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: newTestKeyStore(t), Archiver: arch})
	writer := clienttest.NewKey("writer")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"keys": []any{writer.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	verbs := []string{"read", "create", "append", "config"}
	plain := s.Client(t, client.WithBearer(writer.Grant(t, s.Now(), "user:writer", []string{"e"}, verbs)))
	r1, err := plain.Create(ctx, "e", "p", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := plain.Append(ctx, "e", "p", r1.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}, map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	pre, err := plain.FetchKeys(ctx, "e", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range pre {
		keys[k.Kid] = base64.RawURLEncoding.EncodeToString(k.Key)
	}
	s.Clock.Advance(time.Minute)
	h, err := plain.NSHead(ctx, "e")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.PatchConfig(ctx, "e", h.Config, []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}); err != nil {
		t.Fatal(err)
	}
	jwk, priv, _ := seal.GenerateRecipient()
	bearer := writer.Grant(t, s.Now(), "user:writer", []string{"e"}, verbs, map[string]any{"enc": jwk})
	w := s.Client(t, client.WithBearer(bearer)).E2E(priv)
	for kid, k := range keys {
		b, _ := base64.RawURLEncoding.DecodeString(k)
		w.AddKey(kid, b)
	}
	if _, err := w.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	r3, err := w.AppendSealed(ctx, "e", "p", r2.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 3.0}})
	if err != nil {
		t.Fatal(err)
	}
	k2, err := w.Key(ctx, seal.Kid("e", 2))
	if err != nil {
		t.Fatal(err)
	}
	keys[seal.Kid("e", 2)] = base64.RawURLEncoding.EncodeToString(k2)

	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	fns := []string{"async function decrypted(r, ns, resource, wantPL) { return openSealed(ns, r.text.trim(), resource, wantPL); }"}
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "foldTarget", "readDoc", "nsChainOK", "openSealed", "openSnapshot", "foldLog"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	dir := t.TempDir()
	hp := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(hp, []byte(strings.Replace(foldHarness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"base": s.URL, "bearer": bearer, "ids": []string{r3.ID, r2.ID}, "keys": keys})
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	cmd := exec.Command(node, hp, sealJS, inPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var out map[string]struct {
		Doc     map[string]any
		Err     string
		Since   string
		Flagged int
		Paths   []string
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	if o := out[r3.ID]; o.Err != "" || o.Flagged != 0 || o.Doc["n"] != 3.0 || o.Since != r2.ID {
		t.Fatalf("fold across the raise: %v (%q, %d flagged, since %q, want %s); requests %v", o.Doc, o.Err, o.Flagged, o.Since, r2.ID, o.Paths)
	}
	if o := out[r2.ID]; o.Err != "" || o.Doc["n"] != 2.0 {
		t.Fatalf("revision from before the raise: %v (%q); requests %v", o.Doc, o.Err, o.Paths)
	}
}
