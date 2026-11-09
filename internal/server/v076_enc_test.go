package server

import (
	"crypto/ecdh"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// §1 Conformance, §G.5.2, §12.1 (v0.76, B-63): remote branch R of A's N,
// on a server with a key store; A raises N to sealed and R's raise fails
// (its config writes are over the patch set maximum). A read of a resource
// R reads through, and a PATCH with a test op, answer 502 upstream naming
// A, without Retry-After, as for a level the server lacks, never 503 and
// never the clear; a purge still works (204).
func TestV076EncFailedRaiseIs502(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	y := a.create("m", "y", map[string]any{"v": 2.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	b = reopen(func(o *core.Options) {
		o.Limits, o.Maximums = core.DefaultLimits(), core.DefaultMaximums()
		o.Limits.PatchSetSize, o.Maximums.PatchSetSize = 128<<10, 128<<10
	})
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if l := levelOf(b.configOf("r")); l != "" {
		t.Fatalf("raised to %q although its config writes fail", l)
	}
	upstream := func(what string, r *resp) {
		t.Helper()
		expectCode(t, r, 502, "upstream")
		if r.H.Get("Retry-After") != "" || r.Str("origin") != originA {
			t.Fatalf("%s: %v %s, want 502 upstream with origin %s and no Retry-After", what, r.H, r.Body, originA)
		}
	}
	upstream("read", b.get("/r/r/x/rev/"+x))
	upstream("read through rx", b.get("/r/rx/x/rev/"+x))
	upstream("PATCH with a test op", b.write("PATCH", "r", "x", x, ops(op("test", "/v", 1.0))))
	expect(t, b.purge("r", "y", y, "admin"), 204)
}

// §E.3.2, §C.7 (v0.76): in an e2e namespace, a keyring write whose
// document carries a $nonce that isn't of the fresh form is 422 invalid;
// a fresh one is written.
func TestV076EncKeyringNonceFresh(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	_, admin, _ := seal.GenerateRecipient()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	kr, err := seal.BuildKeyringV2(admin, "e", 1, seal.NewKey(), []*ecdh.PublicKey{admin.PublicKey(), readerPub})
	if err != nil {
		t.Fatal(err)
	}
	keys := kr.Value()["keys"]
	expectCode(t, e.write("PATCH", "e", "keyring", "", addRoot(map[string]any{"keys": keys, "$nonce": "not-a-nonce"}), f.adminG), 422, "invalid")
	e.create("e", "keyring", map[string]any{"keys": keys, "$nonce": seal.NewNonce()}, f.adminG)
}

// §E.2.2 Epochs, §2.1 Protection (v0.76, B-66): a check that judges a blob
// by its epoch fixes it as a request for the blob would. Sealed source s
// with read public, raised from none, and a blob whose referencing
// revisions, written before the raise, have no epoch yet: a Blob-From
// copy by a caller with the current epoch's key succeeds, and fixes the
// newest of them under that epoch; after a rotation, GET …/blob/{bid}
// redirects to the epoch the copy fixed, never the new one.
func TestV076EncCheckFixesBlobEpoch(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{"s": {"read": "public"}})
	bid := p.blobIn("s", "a", []byte("bytes from before the raise"))
	expect(t, p.patchNS("s", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), p.star), 201)
	w := p.grant(p.k, "user:w", []string{"s"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.copyBlob("s", "b", bid, blobPath("s", "a", bid), "", w), 201)
	p.rotate("s", 2)
	g := p.get(blobPath("s", "a", bid))
	expect(t, g, 302)
	if want := blobPath("s", "a", bid) + "/e/1"; g.H.Get("Location") != want {
		t.Fatalf("redirect to %q, want %q, the epoch the copy's check fixed", g.H.Get("Location"), want)
	}
}

// §E.2.2 Epochs, §6.1 Read permission (v0.76): resolving a schema revision
// written before its namespace was sealed judges it by its epoch, and so
// fixes it: after a rotation the revision is still served under the epoch
// the write's check fixed.
func TestV076EncCheckFixesRevEpoch(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{"docs": {"read": "grant"}, "schemas": {"read": "public"}})
	x := p.wr("schemas", "match", "", withNonce(addRoot(map[string]any{"$schema": dialect, "type": "object"})), p.star)
	expect(t, p.patchNS("schemas", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), p.star), 201)
	wk := p.grant(p.k, "user:w", []string{"docs", "schemas"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": "/r/schemas/match/rev/" + x}), wk), 201)
	p.rotate("schemas", 2)
	g := p.get("/r/schemas/match/rev/" + x)
	expect(t, g, 200)
	if want := `"` + x + `.1"`; g.H.Get("ETag") != want {
		t.Fatalf("ETag %s, want %s: the epoch the write's check fixed", g.H.Get("ETag"), want)
	}
}
