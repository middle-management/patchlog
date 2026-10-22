package client_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
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

// v0.73 Addendum E Levels (ENC-22, ENC-38): after a raise from sealed, a
// prune snapshot whose newest content revision is from before the raise
// is sealed under the epoch that revision is served under, not the epoch
// in force.
func TestV073P29SnapshotKidBeforeRaise(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed"})
	w1 := must(v.c.Create(ctx, "e", "d", ops(op("add", "", map[string]any{"n": 1.0}), op("add", "/$nonce", seal.NewNonce()))))
	w2 := must(v.c.Append(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2), op("replace", "/$nonce", seal.NewNonce()))))
	h := must(v.c.NSHead(ctx, "e"))
	if _, err := v.c.PatchConfig(ctx, "e", h.Config, ops(op("replace", "/encryption", map[string]any{"level": "e2e"}))); err == nil {
		t.Fatal("raise from sealed without a new epoch")
	}
	must(v.c.PatchConfig(ctx, "e", h.Config, ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2}))))
	v.s.Clock.Advance(10 * time.Minute)
	key := seal.NewKey() // the server checks the header only
	doc := map[string]any{"n": 2.0}
	if _, err := v.c.Prune(ctx, "e", "d", client.PruneRequest{Horizon: w2.ID, Snapshot: p29Snapshot(t, key, "e#2", "e", "d", w2.ID, doc)}); err == nil {
		t.Fatal("snapshot of pre-raise content under the epoch in force")
	}
	must(v.c.Prune(ctx, "e", "d", client.PruneRequest{Horizon: w2.ID, Snapshot: p29Snapshot(t, key, "e#1", "e", "d", w2.ID, doc)}))
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
