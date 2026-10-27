package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// Wave-4 integration tests: behaviour that two wave-4 packages decide
// together.

// v0.73 §G.3, §G.5.2, Addendum E Levels (P35 x P36; MF-37, ENC-39,
// ENC-42): a remote branch of a source really raised from sealed to e2e,
// now that the source makes that raise (P35), not a proxy's rewrite of
// its document. B mirrors the history from before the raise, its /keys
// gives the source's pre-raise keys as at E2, and it serves what it reads
// through from before the raise as the source does: sealed under the
// epoch the source serves it under, kid and pl naming the source, never
// B's internal shadow.
func TestV073W4IntRemoteBranchOfRaisedSource(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/encryption/epoch", 2.0)), root()), 201)
	x2 := a.wr("m", "x", x1, withNonce(ops(op("replace", "/v", 2.0))), root())
	ak, kr := a.keysOf("m", nil, a.grant(kA, "user:k", []string{"m"}, []string{"read"}, map[string]any{"nbf": t0.Add(-time.Hour).Format(time.RFC3339)}))
	expect(t, kr, 200)
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 3.0})), root()), 201)
	raised := a.nsHead("m", root())
	srcRev := a.get("/r/m/x/rev/"+x2, root())
	expect(t, srcRev, 200)
	if h, err := seal.ParseHeader(string(srcRev.Body)); err != nil || h.Kid != "m#2" {
		t.Fatalf("the source's pre-raise revision: %v %+v", err, h)
	}

	// B's endpoint grant has enc, B's key pair, and an nbf reaching back
	// before the source's first epoch, as /keys needs for the epochs
	// before the raise (§E.2.3, Levels).
	bJWK, bID, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bID
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"m"}, []string{"read", "export"}, map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)

	readerJWK, readerPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"}, map[string]any{"enc": readerJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})
	_, kr = b.keysOf("r", nil, g)
	got := p36Keys(t, kr, func(w seal.WrappedKey) ([]byte, error) { return seal.UnwrapKey(readerPriv, w) })
	for _, kid := range []string{"m#1", "m#2"} {
		if !bytes.Equal(got[kid], ak[kid]) {
			t.Fatalf("B's /keys: %s isn't the source's key (%v)", kid, got)
		}
	}

	r := b.get("/r/r/x/rev/"+x2, g)
	expect(t, r, 200)
	h, err := seal.ParseHeader(string(r.Body))
	if err != nil {
		t.Fatalf("B's answer for the source's pre-raise revision: %v (%s)", err, r.Body)
	}
	want := seal.ResourcePL("m", "x", x2, seal.KindDoc)
	if h.Kid != "m#2" || h.PL["ns"] != "m" {
		t.Fatalf("B serves the source's pre-raise revision under kid %q pl %v, want m#2 and pl naming m", h.Kid, h.PL)
	}
	if _, err := seal.OpenExpect(string(r.Body), resKey(t, ak["m#2"], "m", "x"), "m#2", want); err != nil {
		t.Fatalf("B's sealing doesn't open as the source's does: %v", err)
	}
	// Its log entries from before the raise too, each under the epoch the
	// source serves it under (rev_epochs), never in the clear.
	l := b.get("/r/r/x/rev/"+x2+"/log", g)
	expect(t, l, 200)
	var entries []string
	if err := json.Unmarshal(l.Body, &entries); err != nil || len(entries) != 2 {
		t.Fatalf("B's log of the source's pre-raise revisions isn't two sealed entries: %v %s", err, l.Body)
	}
	for i, c := range []struct{ id, kid string }{{x1, "m#1"}, {x2, "m#2"}} {
		if _, err := seal.OpenExpect(entries[i], resKey(t, ak[c.kid], "m", "x"), c.kid, seal.ResourcePL("m", "x", c.id, seal.KindRev)); err != nil {
			t.Errorf("entry %d: %v", i, err)
		}
	}
}
