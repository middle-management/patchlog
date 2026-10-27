package client_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// p29Env is an e2e namespace "e" whose * key k signs the grants, and an
// admin view whose recipient key wraps the keyring, with every verb on e
// and on its branch eb.
type p29Env struct {
	s     *clienttest.Server
	k     clienttest.Key
	grant string
	c     *client.Client
	x     *client.E2E
	priv  *ecdh.PrivateKey
}

var p29Verbs = []string{"read", "create", "append", "restore", "delete", "config", "branch", "prune"}

func newP29Env(t *testing.T, enc map[string]any) *p29Env {
	t.Helper()
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Archiver: arch})
	k := clienttest.NewKey("k")
	if enc == nil {
		enc = map[string]any{"level": "e2e"}
	}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": enc}))
	v := &p29Env{s: s, k: k}
	var jwk map[string]any
	jwk, v.priv, _ = seal.GenerateRecipient()
	v.grant = k.Grant(t, s.Now(), "user:a", []string{"e", "eb"}, p29Verbs, map[string]any{"enc": jwk})
	v.c = s.Client(t, client.WithBearer(v.grant))
	v.x = v.c.E2E(v.priv)
	if enc["level"] == "e2e" {
		must(v.x.InitKeyring(ctx, "e"))
	}
	return v
}

// raw GETs path with the env's grant.
func (v *p29Env) raw(t *testing.T, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", v.s.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+v.grant)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

// entry is the log entry id of ns/name.
func (v *p29Env) entry(t *testing.T, ns, name, id string) client.LogEntry {
	t.Helper()
	for _, e := range must(v.c.Log(context.Background(), ns, name, id, "")) {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("%s not in the log of %s/%s", id, ns, name)
	return client.LogEntry{}
}

func p29Kr(t *testing.T, ke []byte, ns, name string) []byte {
	t.Helper()
	return must(seal.ResourceKey(ke, ns, name))
}

// v0.73 §E.3.1 (ENC-23): E3 patch sets and prune snapshots are sealed under
// the resource's K_r = HKDF(K_e, ns, name), ns being pl.ns; readers try
// K_r, then K_e, under which ciphertext stored before v0.65 was sealed.
func TestV073P29SealsUnderResourceKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	ke := must(v.x.Key(ctx, "e#1"))
	kr := p29Kr(t, ke, "e", "d")
	ps := v.entry(t, "e", "d", w.ID).Patches
	if _, err := seal.OpenPatchSet(ps, kr, "e#1", "e", "d", ""); err != nil {
		t.Fatalf("the patch set doesn't open under K_r: %v", err)
	}
	if _, err := seal.OpenPatchSet(ps, ke, "e#1", "e", "d", ""); err == nil {
		t.Fatal("the patch set opens under K_e")
	}
	// A patch set sealed under K_e, as before v0.65, still folds.
	legacy := must(seal.SealPatchSet(ke, "e#1", "e", "d", w.ID, ops(op("replace", "/n", 2))))
	l := must(v.c.Append(ctx, "e", "d", w.ID, legacy))
	d := must(v.x.DocE2E(ctx, "e", "d", l.ID))
	if len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("fold over a K_e patch set: %+v", d)
	}
	// The snapshot too.
	v.s.Clock.Advance(10 * time.Minute)
	must(v.x.PruneE2E(ctx, "e", "d", l.ID))
	st, b := v.raw(t, "/r/e/d/rev/"+l.ID)
	if st != 200 {
		t.Fatalf("snapshot: %d %s", st, b)
	}
	jwe := strings.TrimSpace(string(b))
	if _, err := seal.OpenSnapshot(jwe, kr, "e#1", "e", "d", l.ID); err != nil {
		t.Fatalf("the snapshot doesn't open under K_r: %v", err)
	}
	if _, err := seal.OpenSnapshot(jwe, ke, "e#1", "e", "d", l.ID); err == nil {
		t.Fatal("the snapshot opens under K_e")
	}
	if d := must(v.x.DocE2E(ctx, "e", "d", l.ID)); d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("fold from the snapshot %+v", d)
	}
}

// p29Snapshot seals a snapshot of ns/name at h under the K_r of kid.
func p29Snapshot(t *testing.T, ke []byte, kid, ns, name, h string, doc any) string {
	t.Helper()
	kns, _, _ := seal.ParseKid(kid)
	return must(seal.SealSnapshot(p29Kr(t, ke, kns, name), kid, ns, name, h, jsonv.FromGo(doc)))
}

// v0.73 §E.3.1 (ENC-22): a prune snapshot's kid is set by the newest
// revision in the horizon's chain that isn't a tombstone and whose patch
// set isn't []: the epoch of its sealed op, here one before a rotation,
// not the epoch in force. The server checks it (422 invalid), and the
// client seals accordingly.
func TestV073P29SnapshotKid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	w2 := must(v.x.AppendSealed(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2))))
	k1 := must(v.x.Key(ctx, "e#1"))
	if e := must(v.x.RotateEpoch(ctx, "e")); e != 2 {
		t.Fatalf("rotated to %d", e)
	}
	k2 := must(v.x.Key(ctx, "e#2"))
	del := must(v.c.Delete(ctx, "e", "d", w2.ID))
	r := must(v.x.RestoreSealed(ctx, "e", "d", del.ID, nil)) // [] keeps w2's document
	v.s.Clock.Advance(10 * time.Minute)
	doc := map[string]any{"n": 2.0}
	for kid, key := range map[string][]byte{"e#2": k2, "e#3": k2} {
		_, err := v.c.Prune(ctx, "e", "d", client.PruneRequest{Horizon: r.ID, Snapshot: p29Snapshot(t, key, kid, "e", "d", r.ID, doc)})
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Status != 422 || ae.Code != "invalid" {
			t.Fatalf("snapshot under %s, w2 being of e#1: %v, want 422 invalid", kid, err)
		}
	}
	must(v.x.PruneE2E(ctx, "e", "d", r.ID))
	_, b := v.raw(t, "/r/e/d/rev/"+r.ID)
	if h := must(seal.ParseHeader(strings.TrimSpace(string(b)))); h.Kid != "e#1" {
		t.Fatalf("the client sealed the snapshot under %s, want e#1", h.Kid)
	}
	if d := must(v.x.DocE2E(ctx, "e", "d", r.ID)); d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("fold from the snapshot %+v", d)
	}
	// Content written in epoch 2 sets e#2; an e#1 snapshot is refused.
	f1 := must(v.x.CreateDocSealed(ctx, "e", "f", map[string]any{"n": 1.0}))
	f2 := must(v.x.AppendSealed(ctx, "e", "f", f1.ID, ops(op("replace", "/n", 2))))
	v.s.Clock.Advance(10 * time.Minute)
	if _, err := v.c.Prune(ctx, "e", "f", client.PruneRequest{Horizon: f2.ID, Snapshot: p29Snapshot(t, k1, "e#1", "e", "f", f2.ID, doc)}); err == nil {
		t.Fatal("snapshot under e#1 of content written in e#2")
	}
	must(v.x.PruneE2E(ctx, "e", "f", f2.ID))
	_, b = v.raw(t, "/r/e/f/rev/"+f2.ID)
	if h := must(seal.ParseHeader(strings.TrimSpace(string(b)))); h.Kid != "e#2" {
		t.Fatalf("snapshot of f under %s, want e#2", h.Kid)
	}
}

// P29 review, P35, Addendum E Levels (Invariant, After a raise): content
// from before a raise to e2e is never served at a weaker level, so from
// sealed it is served sealed under the last epoch before the raise. A
// raise from sealed needs the new epoch (422 invalid without it); after
// it, the log and the revision from before stay JWEs, never the plaintext.
// A raise from at-rest goes through too. What such a raise records, and
// the snapshot kid of content from before it (ENC-22), are tested in
// internal/core (TestV073P29RaiseToE2E, TestV073P29SnapshotKidBeforeRaise).
func TestV073P29RaiseFromSealedStaysSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed"})
	w := must(v.c.Create(ctx, "e", "d", ops(op("add", "", map[string]any{"secret": "s3cr3t"}), op("add", "/$nonce", seal.NewNonce()))))
	h := must(v.c.NSHead(ctx, "e"))
	_, err := v.c.PatchConfig(ctx, "e", h.Config, ops(op("replace", "/encryption", map[string]any{"level": "e2e"})))
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Code != "invalid" {
		t.Fatalf("raise from sealed without a new epoch: %v, want 422 invalid", err)
	}
	must(v.c.PatchConfig(ctx, "e", h.Config, ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2}))))
	if lv := must(v.c.EncryptionLevel(ctx, "e")); lv != "e2e" {
		t.Fatalf("level %q", lv)
	}
	for _, path := range []string{"/r/e/d/rev/" + w.ID + "/log", "/r/e/d/rev/" + w.ID} {
		if st, b := v.raw(t, path); st != 200 || bytes.Contains(b, []byte("s3cr3t")) {
			t.Fatalf("%s after the raise: %d %s", path, st, b)
		}
	}
	// From at-rest the content was in the clear before, and the raise
	// goes through.
	must(v.s.Client(t, client.WithBearer(v.s.OperatorGrant(t, "a"))).CreateNamespace(ctx, "a",
		map[string]any{"read": "grant", "keys": []any{v.k.Entry("*")}, "encryption": map[string]any{"level": "at-rest"}}))
	ac := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:a", []string{"a"}, p29Verbs, nil)))
	ah := must(ac.NSHead(ctx, "a"))
	must(ac.PatchConfig(ctx, "a", ah.Config, ops(op("replace", "/encryption", map[string]any{"level": "e2e"}))))
}

// v0.73 §E.3.2 (ENC-25): a revision that isn't padded as its namespace
// padded is flagged and still folded, and OpenLog gives its patches, as
// merges and undo fold it; one that doesn't apply is flagged and folded as
// [], the fold going on from its parent's document. A genesis applies to
// null (§6.2 step 3).
func TestV073P29FoldFlagsAndApplies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "e2e", "pad": true})
	g := must(v.x.CreateSealed(ctx, "e", "d", ops(op("test", "", nil), op("add", "", map[string]any{"n": 0.0}))))
	if d := must(v.x.DocE2E(ctx, "e", "d", g.ID)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 0.0 {
		t.Fatalf("a genesis applying to null: %+v", d)
	}
	kr := p29Kr(t, must(v.x.Key(ctx, "e#1")), "e", "d")
	unpadded := must(seal.SealPatchSet(kr, "e#1", "e", "d", g.ID, ops(op("replace", "/n", 1))))
	u := must(v.c.Append(ctx, "e", "d", g.ID, unpadded))
	d := must(v.x.DocE2E(ctx, "e", "d", u.ID))
	if len(d.Flagged) != 1 || !strings.Contains(d.Flagged[0].Message, "padded") || d.Value.(map[string]any)["n"] != 1.0 || d.ValidID != g.ID {
		t.Fatalf("unpadded revision: %+v", d)
	}
	es, flags := must2(v.x.OpenLog(ctx, "e", "d", must(v.c.Log(ctx, "e", "d", u.ID, ""))))
	if flags[1] != "" || !es[1].HasPatches {
		t.Fatalf("OpenLog of the unpadded revision: %+v %q", es[1], flags[1])
	}
	bad := must(v.x.WithoutValidation().AppendSealed(ctx, "e", "d", u.ID, ops(op("remove", "/nope", nil))))
	next := must(v.x.WithoutValidation().AppendSealed(ctx, "e", "d", bad.ID, ops(op("add", "/m", 2))))
	d = must(v.x.DocE2E(ctx, "e", "d", next.ID))
	if len(d.Flagged) != 2 || d.Flagged[1].ID != bad.ID || !strings.Contains(d.Flagged[1].Message, "doesn't apply") {
		t.Fatalf("flags %+v", d.Flagged)
	}
	sameJSON(t, d.Value, map[string]any{"n": 1, "m": 2})
}

// v0.73 §E.2.2 (ENC-26): padding is judged by the namespace document in
// force at the revision's entry: for a batch that changes the
// configuration, the one it produces; and a revision written while pad was
// on stays judged so after pad is turned off.
func TestV073P29PaddingInForce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0.0}))
	kr := p29Kr(t, must(v.x.Key(ctx, "e#1")), "e", "d")
	batch := func(parent string, pad bool, n int) string {
		t.Helper()
		h := must(v.c.NSHead(ctx, "e"))
		ps := must(seal.SealPatchSet(kr, "e#1", "e", "d", parent, ops(op("replace", "/n", n))))
		res := must(v.c.Batch(ctx, "e", client.BatchRequest{
			Config: &client.BatchConfig{IfMatch: h.Config, Patches: []any{op("add", "/encryption/pad", pad)}},
			Items:  []client.BatchItem{{Resource: "d", IfMatch: parent, Steps: []client.Step{client.PatchStep(jsonv.MustParse(ps))}}},
		}, false))
		return res.Items[0].IDs[0]
	}
	on := batch(w.ID, true, 1) // unpadded, in the batch that turns pad on
	d := must(v.x.DocE2E(ctx, "e", "d", on))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != on {
		t.Fatalf("an unpadded item of the batch turning pad on: flags %+v", d.Flagged)
	}
	off := batch(on, false, 2) // unpadded, in the batch that turns pad off
	d = must(v.x.DocE2E(ctx, "e", "d", off))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != on {
		t.Fatalf("after pad is off: flags %+v, want the earlier revision only", d.Flagged)
	}
	if d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("value %v", d.Value)
	}
}

// v0.73 Addendum E Levels, §E.3.1 (ENC-27, E3 half): readers accept a
// base's ns in pl and kid only for entries up to where the branch's chain
// forked from the base. A server that splices an entry sealed under the
// base's key after the fork into the branch's log (played by the
// transport) gets it flagged; read-through entries still fold.
func TestV073P29BaseNSOnlyUpToFork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	fork := must(v.x.AppendSealed(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2))))
	must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	// Read through: the base's entries fold in the branch.
	if d := must(v.x.DocE2E(ctx, "eb", "d", fork.ID)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("read-through fold %+v", d)
	}
	// An entry sealed under the base's key, with the base's pl, on the fork.
	kr := p29Kr(t, must(v.x.Key(ctx, "e#1")), "e", "d")
	forged := must(seal.SealPatchSet(kr, "e#1", "e", "d", fork.ID, ops(op("replace", "/n", 3))))
	fv := jsonv.MustParse(forged)
	fid := must(client.ExpectedRevision(fork.ID, fv))
	entry := map[string]any{"id": fid, "parent": fork.ID, "kind": "rev", "patches": fv, "author": "user:a", "created": "2026-10-04T12:00:00Z"}
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/r/eb/d/rev/" + fid:
			h := http.Header{}
			h.Set("X-E2E", "fold")
			h.Set("Location", "/r/eb/d/rev/"+fid+"/log")
			return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		case "/r/eb/d/rev/" + fid + "/log":
			r2 := req.Clone(req.Context())
			r2.URL.Path = "/r/eb/d/rev/" + fork.ID + "/log"
			res, err := base.RoundTrip(r2)
			if err != nil {
				return nil, err
			}
			var arr []any
			json.NewDecoder(res.Body).Decode(&arr)
			res.Body.Close()
			b, _ := json.Marshal(append(arr, entry))
			res.Body = io.NopCloser(bytes.NewReader(b))
			res.ContentLength = int64(len(b))
			res.Header.Del("Content-Length")
			res.Header.Del("X-Log-Next")
			return res, nil
		}
		return base.RoundTrip(req)
	})
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	d := must(x.DocE2E(ctx, "eb", "d", fid))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != fid || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("an entry sealed under the base past the fork: %+v", d)
	}
}

// v0.73 §E.3.2 (ENC-12): a client seals only under a key whose keyring
// entry's from it trusts to distribute keys; reads may still open keys
// from other senders it knows. An entry wrapped by another key it knows,
// not trusted, is refused for writes; once trusted, writes go through.
func TestV073P29SealsOnlyUnderTrustedFrom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	wJWK, wPriv, _ := seal.GenerateRecipient()
	_, evil, _ := seal.GenerateRecipient()
	w0 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0.0}))
	// The keyring gets an entry for the writer from another sender, wrapping
	// a key of its choosing (anyone can wrap to a thumbprint).
	kr, head := must2(v.x.Keyring(ctx, "e"))
	if err := kr.Add(evil, wPriv.PublicKey(), "e#1", seal.NewKey()); err != nil {
		t.Fatal(err)
	}
	must(v.c.Append(ctx, "e", client.KeyringName, head, []any{op("replace", "", kr.Value())}))
	wc := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:w", []string{"e"}, []string{"read", "create", "append"}, map[string]any{"enc": wJWK})))
	trusting := wc.E2E(wPriv).WithSenders(evil.PublicKey()).WithTrusted(v.priv.PublicKey())
	if _, err := trusting.Key(ctx, "e#1"); err != nil {
		t.Fatalf("reads open a key from a known sender: %v", err)
	}
	if _, err := trusting.SealPatches(ctx, "e", "d", w0.ID, ops(op("replace", "/n", 1))); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("sealing under a key from an untrusted sender: %v", err)
	}
	if _, err := trusting.CreateDocSealed(ctx, "e", "f", map[string]any{"n": 1.0}); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("creating under a key from an untrusted sender: %v", err)
	}
	// Trusted by the client: writes seal under it.
	wc2 := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:w", []string{"e"}, []string{"read", "create", "append"}, map[string]any{"enc": wJWK})),
		client.WithTrustedKeyringSenders(evil.PublicKey()))
	if _, err := wc2.E2E(wPriv).CreateDocSealed(ctx, "e", "f", map[string]any{"n": 1.0}); err != nil {
		t.Fatalf("sealing under a key from a trusted sender: %v", err)
	}
	// Without any trust configured, every known sender is trusted.
	if _, err := wc.E2E(wPriv).WithSenders(evil.PublicKey()).CreateDocSealed(ctx, "e", "g", map[string]any{"n": 1.0}); err != nil {
		t.Fatalf("sealing with no trust configured: %v", err)
	}
}

// v0.73 §6.2 step 3 (wave-2 carry-over): a create applies to the document
// null, so a genesis that tests it, which the core takes, folds in undo
// as in the core: a gesture over such a resource is undone.
func TestV073P29UndoOverNullGenesis(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "u", map[string]any{}))
	w := must(c.Create(ctx, "u", "a", ops(op("test", "", nil), op("add", "", map[string]any{"n": 0.0}))))
	g := client.NewGesture()
	must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))
	must(c.Undo(ctx, "u", g))
	if d, _ := docOf(t, c, "u", "a"); d["n"] != 0.0 {
		t.Fatalf("after the undo %v", d)
	}
}

// p29Injecting returns a transport that answers POST /ns/{ns}/keys with
// one entry for kid that the server made itself, as entry gives it, and,
// with hideKeyring, refuses GET of the keyring resource, as for a writer
// limited to some resources (§C.5).
func p29Injecting(ns string, entry map[string]any, hideKeyring bool) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	return roundTrip(func(req *http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-store")
		answer := func(status int, v any) (*http.Response, error) {
			b, _ := json.Marshal(v)
			return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}, nil
		}
		switch {
		case req.Method == "POST" && req.URL.Path == "/ns/"+ns+"/keys":
			return answer(200, map[string]any{"epoch": 1, "level": "e2e", "pad": false, "keys": []any{entry}})
		case hideKeyring && strings.HasPrefix(req.URL.Path, "/r/"+ns+"/"+client.KeyringName):
			return answer(403, map[string]any{"error": "forbidden", "code": "forbidden"})
		}
		return base.RoundTrip(req)
	})
}

// P29 review (blocking), §E.3.2 (ENC-12): a client seals only under a key
// whose keyring entry's from it trusts, and anyone, the server included,
// can wrap a key to a thumbprint. A key /keys relays without a sender,
// wrapped in base mode without from or given in the clear, is never one:
// with the keyring readable, the writer seals under the admin's entry for
// it instead, configured as every tool is by default (known senders only)
// or with a trusted sender; without it, the write is ErrUntrustedKey.
// Reads may still open such a key.
func TestV073P29RelayedKeyWithoutFromNeverSeals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w0 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0.0}))
	real := must(v.x.Key(ctx, "e#1"))
	wJWK, wPriv, _ := seal.GenerateRecipient()
	must(v.x.AddReader(ctx, "e", wPriv.PublicKey(), false))
	grant := v.k.Grant(t, v.s.Now(), "user:w", []string{"e"}, []string{"read", "create", "append"}, map[string]any{"enc": wJWK})

	evil := seal.NewKey()
	wrapped := must(seal.WrapKey(wPriv.PublicKey(), "e#1", "", evil))
	entries := map[string]map[string]any{
		"base mode without from": {"kid": "e#1", "wrapped": base64.RawURLEncoding.EncodeToString(wrapped.Wrapped)},
		"in the clear":           {"kid": "e#1", "key": base64.RawURLEncoding.EncodeToString(evil)},
	}
	for what, entry := range entries {
		views := map[string]func(c *client.Client) *client.E2E{
			"known senders":  func(c *client.Client) *client.E2E { return c.E2E(wPriv).WithSenders(v.priv.PublicKey()) },
			"trusted sender": func(c *client.Client) *client.E2E { return c.E2E(wPriv).WithTrusted(v.priv.PublicKey()) },
		}
		for how, view := range views {
			wc := v.s.Client(t, client.WithBearer(grant), client.WithHTTPClient(&http.Client{Transport: p29Injecting("e", entry, false)}))
			body, err := view(wc).SealPatches(ctx, "e", "d", w0.ID, ops(op("replace", "/n", 1)))
			if err != nil {
				t.Fatalf("%s, %s, keyring readable: %v", what, how, err)
			}
			if _, err := seal.OpenPatchSet(jsonv.MustParse(body), p29Kr(t, evil, "e", "d"), "e#1", "e", "d", w0.ID); err == nil {
				t.Fatalf("%s, %s: sealed under the key the server chose", what, how)
			}
			if _, err := seal.OpenPatchSet(jsonv.MustParse(body), p29Kr(t, real, "e", "d"), "e#1", "e", "d", w0.ID); err != nil {
				t.Fatalf("%s, %s: not sealed under the admin's key: %v", what, how, err)
			}
			// The keyring hidden, the relayed key is all there is.
			lc := v.s.Client(t, client.WithBearer(grant), client.WithHTTPClient(&http.Client{Transport: p29Injecting("e", entry, true)}))
			lx := view(lc)
			if _, err := lx.SealPatches(ctx, "e", "d", w0.ID, ops(op("replace", "/n", 1))); !errors.Is(err, client.ErrUntrustedKey) {
				t.Fatalf("%s, %s, keyring hidden: %v, want ErrUntrustedKey", what, how, err)
			}
			if k, err := lx.Key(ctx, "e#1"); err != nil || !bytes.Equal(k, evil) {
				t.Fatalf("%s, %s: reads open the relayed key: %v", what, how, err)
			}
		}
	}

	// A key holder that read with the injected key first doesn't pass it
	// on: AddReader wraps the admin's key for the new reader.
	ak := v.s.Client(t, client.WithBearer(grant), client.WithHTTPClient(&http.Client{Transport: p29Injecting("e", entries["base mode without from"], false)})).
		E2E(wPriv).WithSenders(v.priv.PublicKey())
	if k := must(ak.Key(ctx, "e#1")); !bytes.Equal(k, evil) {
		t.Fatal("the view reads with the relayed key first")
	}
	_, rPriv, _ := seal.GenerateRecipient()
	must(ak.AddReader(ctx, "e", rPriv.PublicKey(), false))
	kr, _ := must2(v.x.Keyring(ctx, "e"))
	if k, err := kr.EpochKey(rPriv, "e#1", []*ecdh.PublicKey{wPriv.PublicKey()}); err != nil || !bytes.Equal(k, real) {
		t.Fatalf("the new reader's entry: %v, admin's key %v", err, bytes.Equal(k, real))
	}
	if k := must(ak.Key(ctx, "e#1")); !bytes.Equal(k, real) {
		t.Fatal("after sealing, the view still holds the relayed key")
	}
}

// P29 review, §E.3.2 (ENC-12): a keyring stored in the format before
// v0.63 has no from, so nothing seals under its keys, relayed or read in
// it, whatever senders the view knows or trusts; reads still open them.
// The error names the remedy, migrate-keyring. The stored legacy keyring
// and its relay are played by the transport, as in TestV073E2EMigrateKeyring.
func TestV073P29LegacyKeyringNeverSeals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w0 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0.0}))
	ke := must(v.x.Key(ctx, "e#1"))
	legacy := must(seal.BuildKeyring("e", 1, ke, []*ecdh.PublicKey{v.priv.PublicKey()}))
	body, _ := json.Marshal(legacy.Value())
	relay := rewriteKeys(t, "e", func(m map[string]any) {
		delete(m, "from")
		m["wrapped"] = base64.RawURLEncoding.EncodeToString(legacyWrap(t, v.priv.PublicKey(), "e#1", ke))
	})
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		res, err := relay.RoundTrip(req)
		if err != nil || req.Method != "GET" || !strings.HasPrefix(req.URL.Path, "/r/e/keyring/rev/") || res.StatusCode != 200 {
			return res, err
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		res.Body = io.NopCloser(bytes.NewReader(body))
		res.ContentLength = int64(len(body))
		res.Header.Del("Content-Length")
		return res, nil
	})
	c := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt}))
	for how, x := range map[string]*client.E2E{
		"own key only":   c.E2E(v.priv),
		"trusted sender": c.E2E(v.priv).WithTrusted(v.priv.PublicKey()),
	} {
		_, err := x.SealPatches(ctx, "e", "d", w0.ID, ops(op("replace", "/n", 1)))
		if !errors.Is(err, client.ErrUntrustedKey) || !strings.Contains(err.Error(), "migrate-keyring") {
			t.Fatalf("%s: sealing under a legacy keyring's key: %v", how, err)
		}
		if d := must(x.DocE2E(ctx, "e", "d", w0.ID)); d.Value.(map[string]any)["n"] != 0.0 {
			t.Fatalf("%s: reads open it: %+v", how, d)
		}
	}
}

// P29 review, Addendum E Levels, §E.3.1 (ENC-27): undo reads a resource's
// log after its hint, and the base's ns is accepted only for entries up to
// the branch's fork whether or not the range starts at the genesis, the
// hint being the fork itself or the branch's own revision past it. An
// entry sealed under the base's key that the server splices into the
// branch's log past the fork, before the gesture (played by the
// transport), is flagged and folded as [], so the undo doesn't take what it
// says into the document it writes back.
func TestV073P29UndoRangeAfterForkFlagsBaseEntry(t *testing.T) {
	t.Parallel()
	for _, hintAtFork := range []bool{false, true} {
		ctx := context.Background()
		v := newP29Env(t, nil)
		w1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0, "x": 0.0}))
		fork := must(v.x.AppendSealed(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2))))
		must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
		kw := must(v.x.InitKeyring(ctx, "eb"))
		hint, since, want := fork, kw.NSID, 2.0
		if !hintAtFork {
			p1 := must(v.x.AppendSealed(ctx, "eb", "d", fork.ID, ops(op("replace", "/n", 3))))
			hint, since, want = p1, p1.NSID, 3.0
		}
		g := client.NewGesture()
		g1 := must(v.x.AppendSealed(ctx, "eb", "d", hint.ID, ops(op("replace", "/n", 4)), client.WithGesture(g)))

		// The base's key seals what the server splices in after the hint.
		kr := p29Kr(t, must(v.x.Key(ctx, "e#1")), "e", "d")
		forged := jsonv.MustParse(must(seal.SealPatchSet(kr, "e#1", "e", "d", hint.ID, ops(op("replace", "/x", 9)))))
		fid := must(client.ExpectedRevision(hint.ID, forged))
		entry := map[string]any{"id": fid, "parent": hint.ID, "kind": "rev", "patches": forged, "author": "user:z", "created": "2026-10-04T12:00:00Z"}
		base := http.DefaultTransport.(*http.Transport).Clone()
		rt := roundTrip(func(req *http.Request) (*http.Response, error) {
			res, err := base.RoundTrip(req)
			if err != nil || req.Method != "GET" || req.URL.Path != "/r/eb/d/rev/"+g1.ID+"/log" || res.StatusCode != 200 {
				return res, err
			}
			var arr []any
			json.NewDecoder(res.Body).Decode(&arr)
			res.Body.Close()
			b, _ := json.Marshal(append([]any{entry}, arr...))
			res.Body = io.NopCloser(bytes.NewReader(b))
			res.ContentLength = int64(len(b))
			res.Header.Del("Content-Length")
			return res, nil
		})
		c := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt}))
		plan, err := c.PlanUndo(ctx, "eb", g, client.UndoE2E(c.E2E(v.priv)), client.UndoSince(since))
		if err != nil {
			t.Fatalf("hint at the fork %v: %v", hintAtFork, err)
		}
		if len(plan.Resources) != 1 || len(plan.Conflicts) != 0 {
			t.Fatalf("hint at the fork %v: plan %+v", hintAtFork, plan)
		}
		if d := plan.Resources[0].Doc.(map[string]any); d["n"] != want || d["x"] != 0.0 {
			t.Fatalf("hint at the fork %v: an entry sealed under the base past the fork is folded into what the undo writes: %v", hintAtFork, d)
		}
	}
}

// P29 review (ENC-27): OpenLog places a branch's forks against what the
// range follows, a leading horizon marker or else the first entry's
// parent, so an entry sealed under the base past the fork is flagged
// whether or not the range starts with a marker; a range from the genesis
// still folds the base's entries up to the fork.
func TestV073P29OpenLogPlacesForksWithoutMarker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	fork := must(v.x.AppendSealed(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2))))
	must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	after := must(v.x.AppendSealed(ctx, "e", "d", fork.ID, ops(op("replace", "/n", 9))))
	spliced := v.entry(t, "e", "d", after.ID)
	if _, flags := must2(v.x.OpenLog(ctx, "eb", "d", []client.LogEntry{{ID: fork.ID}, spliced})); flags[1] == "" {
		t.Fatalf("after a marker for the fork: %q", flags)
	}
	if _, flags := must2(v.x.OpenLog(ctx, "eb", "d", []client.LogEntry{spliced})); flags[0] == "" {
		t.Fatal("a range after the fork without a marker opens the base's entry past the fork without a flag")
	}
	if es, flags := must2(v.x.OpenLog(ctx, "eb", "d", must(v.c.Log(ctx, "eb", "d", fork.ID, "")))); len(es) != 2 || flags[0] != "" || flags[1] != "" {
		t.Fatalf("read-through range from the genesis: %q", flags)
	}
}

// P29 review, §E.3.2 (ENC-25), §6.2 step 3: a revision whose patch set
// doesn't apply, or doesn't parse as one, is flagged and the fold goes on
// from its parent's document as if it were []; for a genesis that is null.
// A resource whose only revision is such a genesis folds to null with the
// genesis flagged and its author named, and the next revision applies to
// null.
func TestV073P29FlaggedGenesisFoldsToNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	g := must(v.x.WithoutValidation().CreateSealed(ctx, "e", "d", ops(op("replace", "/x", 1))))
	d, err := v.x.DocE2E(ctx, "e", "d", g.ID)
	if err != nil {
		t.Fatalf("a genesis that doesn't apply: %v", err)
	}
	if d.Value != nil || len(d.Flagged) != 1 || d.Flagged[0].ID != g.ID || d.Flagged[0].Author != "user:a" || !strings.Contains(d.Flagged[0].Message, "doesn't apply") || d.ValidID != "" {
		t.Fatalf("fold %+v", d)
	}
	next := must(v.x.WithoutValidation().AppendSealed(ctx, "e", "d", g.ID, ops(op("add", "", map[string]any{"n": 1.0}))))
	if d := must(v.x.DocE2E(ctx, "e", "d", next.ID)); len(d.Flagged) != 1 || d.ValidID != next.ID {
		t.Fatalf("after the flagged genesis: %+v", d)
	} else {
		sameJSON(t, d.Value, map[string]any{"n": 1})
	}

	// One that opens but isn't a patch set.
	kr := p29Kr(t, must(v.x.Key(ctx, "e#1")), "e", "f")
	notOps := must(seal.SealPatchSet(kr, "e#1", "e", "f", "", map[string]any{"op": "add"}))
	f := must(v.c.Create(ctx, "e", "f", notOps))
	if d, err := v.x.DocE2E(ctx, "e", "f", f.ID); err != nil || d.Value != nil || len(d.Flagged) != 1 || !strings.Contains(d.Flagged[0].Message, "patch set") {
		t.Fatalf("a genesis that isn't a patch set: %+v, %v", d, err)
	}
}
