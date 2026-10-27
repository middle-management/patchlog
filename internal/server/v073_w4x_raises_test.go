package server

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// w4x (raises lens), §G.3, §G.5.2, Addendum E Levels: a remote branch of a
// source raised from sealed can be created with an endpoint grant without
// nbf, which the source's /keys gave its only epoch while sealed, and
// serves the source's content from before the raise.
func TestV073W4xRemoteBranchEndpointGrantWithoutNbf(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	a.clock.Advance(time.Hour)
	x2 := a.wr("m", "x", x1, withNonce(ops(op("replace", "/v", 2.0))), root())
	// At E2 the endpoint grant B will use (no nbf) gets m#1, the only epoch.
	bJWK0, _, _ := seal.GenerateRecipient()
	_, kr0 := a.keysOf("m", nil, a.grant(kA, "svc:b", []string{"m"}, []string{"read", "export"}, map[string]any{"enc": bJWK0}))
	expect(t, kr0, 200)
	t.Logf("source /keys at E2 for a no-nbf grant: %s", kr0.Body)
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), root()), 201)
	raised := a.nsHead("m", root())
	srcRev := a.get("/r/m/x/rev/"+x2, root())
	expect(t, srcRev, 200)
	if h, err := seal.ParseHeader(string(srcRev.Body)); err != nil || h.Kid != "m#1" {
		t.Fatalf("the source's pre-raise revision: %v %+v", err, h)
	}

	// B's endpoint grant has enc and B's key pair, and no nbf: the
	// source's /keys gives it the last epoch before the raise as at E2
	// (§E.2.3, Addendum E Levels), here m#1, the only one, as it did
	// while the source was sealed.
	bJWK, bID, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bID
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"m"}, []string{"read", "export"}, map[string]any{"enc": bJWK})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)

	readerJWK, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"}, map[string]any{"enc": readerJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})
	r := b.get("/r/r/x/rev/"+x2, g)
	t.Logf("B /r/r/x/rev/{pre-raise}: %d %s", r.Code, r.Body)
	l := b.get("/r/r/x/rev/"+x2+"/log", g)
	t.Logf("B log: %d %.200s", l.Code, l.Body)
	if r.Code != 200 || l.Code != 200 {
		t.Errorf("the remote branch was created (201) but can't serve its source's pre-raise content: %d / %d", r.Code, l.Code)
	}
}
