package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// V01 (v0.74): E3 gate checks and prunes at a horizon from before a raise.

// v074JWE is a compact JWE with protected header hdr, as sent, and random
// IV, ciphertext and tag: the server checks the header without a key.
func v074JWE(hdr string) string {
	b64 := base64.RawURLEncoding
	rnd := func(n int) string {
		b := make([]byte, n)
		rand.Read(b)
		return b64.EncodeToString(b)
	}
	return b64.EncodeToString([]byte(hdr)) + ".." + rnd(12) + "." + rnd(32) + "." + rnd(16)
}

// v074Engine is an engine with a key store, an archiver and
// authentication disabled, whose clock the test moves.
func v074Engine(t *testing.T) (*Engine, *p29Clock) {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: p36T0}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Archiver: p29Archiver{}, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, now
}

// v0.74 §E.3.1 Patch sets, §E.2.2 (LEVELS-9): a sealed op's protected
// header, and a prune snapshot's, is canonical JSON with no members but
// alg, enc, kid and pl; otherwise the write is 422 invalid.
func TestV074V01E3HeaderCanonical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e, now := v074Engine(t)
	mkNS(t, e, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}})
	write := func(parent, hdr string) (*WriteResult, error) {
		return e.WriteResource(ctx, p29Req("e"), Item{Resource: "d", IfMatch: parent, IfNoneMatch: parent == "",
			Steps: []Step{{Patches: []any{map[string]any{"op": "sealed", "value": v074JWE(hdr)}}}}})
	}
	canonical := `{"alg":"dir","enc":"A256GCM","kid":"e#1","pl":{"name":"d","ns":"e","parent":""}}`
	for name, hdr := range map[string]string{
		"an extra member":      `{"alg":"dir","enc":"A256GCM","kid":"e#1","pl":{"name":"d","ns":"e","parent":""},"typ":"JWE"}`,
		"members out of order": `{"enc":"A256GCM","alg":"dir","kid":"e#1","pl":{"name":"d","ns":"e","parent":""}}`,
		"pl out of order":      `{"alg":"dir","enc":"A256GCM","kid":"e#1","pl":{"ns":"e","name":"d","parent":""}}`,
		"spaces":               `{"alg": "dir","enc":"A256GCM","kid":"e#1","pl":{"name":"d","ns":"e","parent":""}}`,
	} {
		if st, body := p29Status(t, second(write("", hdr))); st != 422 || body["code"] != "invalid" {
			t.Errorf("sealed op whose header has %s: %d %v, want 422 invalid", name, st, body)
		}
	}
	w, err := write("", canonical)
	if err != nil {
		t.Fatalf("a canonical header: %v", err)
	}
	d1 := w.Items[0].IDs[0]
	w, err = write(d1, `{"alg":"dir","enc":"A256GCM","kid":"e#1","pl":{"name":"d","ns":"e","parent":"`+d1+`"}}`)
	if err != nil {
		t.Fatal(err)
	}
	d2 := w.Items[0].IDs[0]
	now.Advance(10 * time.Minute) // past what a prune protects

	// A prune's snapshot of d2.
	prune := func(hdr string) error {
		return second(e.Prune(ctx, p29Req("e"), "d", PruneRequest{Horizon: d2, Snapshot: v074JWE(hdr)}))
	}
	for name, hdr := range map[string]string{
		"an extra member":      `{"alg":"dir","enc":"A256GCM","kid":"e#1","pl":{"id":"` + d2 + `","name":"d","ns":"e"},"cty":"json"}`,
		"members out of order": `{"kid":"e#1","alg":"dir","enc":"A256GCM","pl":{"id":"` + d2 + `","name":"d","ns":"e"}}`,
		"spaces":               `{"alg":"dir", "enc":"A256GCM","kid":"e#1","pl":{"id":"` + d2 + `","name":"d","ns":"e"}}`,
	} {
		if st, body := p29Status(t, prune(hdr)); st != 422 || body["code"] != "invalid" {
			t.Errorf("snapshot whose header has %s: %d %v, want 422 invalid", name, st, body)
		}
	}
	if err := prune(`{"alg":"dir","enc":"A256GCM","kid":"e#1","pl":{"id":"` + d2 + `","name":"d","ns":"e"}}`); err != nil {
		t.Fatalf("a snapshot with a canonical header: %v", err)
	}
}

// v0.74 Addendum E Levels, After a raise (LEVELS-11, Open 5): an E3 prune
// whose horizon is from before a raise from sealed first stores the
// horizon's sealing if none is stored, so /rev/{H} serves exactly those
// bytes afterwards.
func TestV074V01PreRaisePruneStoresSealing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e, now := v074Engine(t)
	cfg := mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "x", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())}}}})
	if err != nil {
		t.Fatal(err)
	}
	x1 := w.Items[0].IDs[0]
	w, err = e.WriteResource(ctx, p29Req("s"), Item{Resource: "x", IfMatch: x1, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}, map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}}}}})
	if err != nil {
		t.Fatal(err)
	}
	h := w.Items[0].IDs[0]
	// Raised without reading /rev/{h}: no sealing of it is stored.
	if _, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}}); err != nil {
		t.Fatal(err)
	}
	stored := func() string {
		var jwe string
		if err := e.read(ctx, func(t *tx) error {
			n := t.nsByName("s")
			row := t.findInAncestry(t.resolve(n, "x", nil).head, mustID(h))
			var c int
			t.must(t.QueryRow(`SELECT COUNT(*) FROM sealed WHERE ns = ? AND rev_seq = ? AND kind = 'doc'`, n.id, row.seq).Scan(&c))
			if c == 1 {
				t.must(t.QueryRow(`SELECT jwe FROM sealed WHERE ns = ? AND rev_seq = ? AND kind = 'doc'`, n.id, row.seq).Scan(&jwe))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return jwe
	}
	if stored() != "" {
		t.Fatal("a sealing of the horizon is stored before the prune")
	}
	now.Advance(10 * time.Minute) // past what a prune protects
	kr, err := seal.ResourceKey(seal.NewKey(), "s", "x")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := seal.SealSnapshot(kr, "s#1", "s", "x", h, jsonv.FromGo(map[string]any{"n": 2.0}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Prune(ctx, p29Req("s"), "x", PruneRequest{Horizon: h, Snapshot: snap}); err != nil {
		t.Fatalf("prune at a pre-raise horizon: %v", err)
	}
	jwe := stored()
	if jwe == "" {
		t.Fatal("no sealing of the horizon stored by the prune")
	}
	if kid := kidOf(jwe); kid != "s#1" {
		t.Errorf("the stored sealing's kid %q, want s#1, the epoch the revision was written in", kid)
	}
	r, err := e.ResourceRev(ctx, "s", "x", h, who.Cred)
	if err != nil || r.Status != 200 || r.JWE != jwe {
		t.Fatalf("/rev/{H} after the prune: %v %+v, want the stored sealing", err, r)
	}
}

// v0.74 Addendum E Levels, Branches of a raised base, and §E.2.3 At E3: a
// branch's /keys gives the raised base's pre-raise keys "for the base
// epochs §E.2.3 selects", which no more than the base's historyEpochs at
// at caps, so the base lowering historyEpochs, or rotating, after the
// branch's at withholds none of them, as it withholds none of the base's
// keyring epochs; the raised namespace's own window still follows its
// current epoch and document. The server's own key checks for pre-raise
// content read through the branch (preRaiseKeysOpen: blob copies, a
// batch's local source, schema resolution) take the same epochs.
func TestV074V01BranchPreRaiseKeysHistoryAtAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p36NewEnv(t)
	e.create(t, "s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	e.advance(time.Hour)
	e.config(t, "s", p29Add("/encryption/epoch", 2.0))
	e.advance(time.Hour)
	e.config(t, "s", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 3.0, "historyEpochs": 2.0}})
	e.advance(10 * time.Minute)
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	branch := func(name string) {
		t.Helper()
		if _, err := e.CreateBranch(ctx, e.star(t, "s", name), BranchRequest{Name: name, IfNoneMatch: true}); err != nil {
			t.Fatal(err)
		}
		e.advance(10 * time.Minute)
	}
	reader := func(ns string) Credentials {
		return e.mint(t, "user:r", []string{ns}, []string{"read"}, map[string]any{"enc": jwk, "nbf": p36T0.Add(-time.Hour).Format(time.RFC3339)})
	}
	keys := func(ns string) string {
		t.Helper()
		got, _ := p36Keys(t, e, ns, reader(ns), KeysRequest{}, priv)
		return got
	}
	// z's at: epoch 3, historyEpochs 2, so from epoch 1.
	branch("z")
	// y's at: epoch 3, historyEpochs 1, so from epoch 2.
	e.config(t, "s", map[string]any{"op": "replace", "path": "/encryption/historyEpochs", "value": 1.0})
	branch("y")
	for ns, want := range map[string]string{"s": "s#2", "z": "s#1,s#2", "y": "s#2"} {
		if got := keys(ns); got != want {
			t.Errorf("before the base changes: /keys of %s %q, want %q", ns, got, want)
		}
	}
	// The base drops its history, then rotates: its own readers lose the
	// pre-raise epochs, a branch's keep what the base had at at.
	e.config(t, "s", map[string]any{"op": "replace", "path": "/encryption/historyEpochs", "value": 0.0})
	e.advance(10 * time.Minute)
	e.config(t, "s", map[string]any{"op": "replace", "path": "/encryption/epoch", "value": 4.0})
	e.advance(10 * time.Minute)
	for ns, want := range map[string]string{"s": "", "z": "s#1,s#2", "y": "s#2"} {
		if got := keys(ns); got != want {
			t.Errorf("after historyEpochs 0 and epoch 4: /keys of %s %q, want %q", ns, got, want)
		}
	}
	if err := e.read(ctx, func(t2 *tx) error {
		s := t2.nsByName("s")
		p := &preRaise{m: s, raise: t2.e2eRaiseOf(s)}
		for _, c := range []struct {
			ns    string
			epoch int
			want  bool
		}{{"s", 2, false}, {"z", 1, true}, {"z", 2, true}, {"y", 1, false}, {"y", 2, true}} {
			n := t2.nsByName(c.ns)
			if got := t2.preRaiseKeysOpen(n, p, "doc", map[int]bool{c.epoch: true}, []Credentials{reader(c.ns)}); got != c.want {
				t.Errorf("pre-raise key check in %s for epoch %d: %v, want %v", c.ns, c.epoch, got, c.want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
