package server

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// Addendum E Levels, §7.8, §E.2.2 (v0.74): a pre-raise blob is one any
// pre-raise revision references, and it keeps its epoch URLs under the
// epochs of the still served pre-raise revisions referencing it, also
// read through a remote branch's shadow of a level that had no raise of
// its own. Here A's eb is an e2e branch of e, raised from sealed before
// eb was made, and eb wrote on x end to end since; B's remote branch of
// eb (chain [eb, e]) serves e's pre-raise blob as A serves it through eb:
// …/blob/{bid} redirects to its epoch, and the epoch URL is A's bytes,
// never the plaintext. The blob eb wrote end to end, which no pre-raise
// revision references, has no epoch URLs there either: 404 not_offered.
func TestV074RemoteShadowPreRaiseBlob(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("e", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"e", "eb"}, allVerbs) }
	g := root()
	data := []byte("e's blob in epoch 1")
	bid := a.upload("e", "x", "text/plain", data, g)
	x1 := a.wr("e", "x", "", withNonce(addRoot(map[string]any{"v": 1.0, "b": ref(bid, "text/plain", len(data), "")})), g)
	a.clock.Advance(time.Hour)
	g = root()
	expect(t, a.do(req{method: "PATCH", path: "/ns/e", ifMatch: a.configID("e", g), body: ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), bearer: g}), 201)
	expect(t, a.branch("e", map[string]any{"name": "eb"}, g), 201)
	// eb writes on x end to end, with a blob of its own, so x's chain in
	// eb starts with eb's segment, which has no raise.
	ref2 := a.uploadE2E("eb", "x", []byte("eb's blob, end to end"), g)
	bid2 := ref2["$blob"].(string)
	ebEpoch := int(a.nsDoc("eb", g)["encryption"].(map[string]any)["epoch"].(float64))
	w := a.do(req{method: "PATCH", path: "/r/eb/x", ifMatch: x1, raw: p35Sealed(t, seal.NewKey(), "eb#"+strconv.Itoa(ebEpoch), "eb", "x", x1, ops(op("add", "/c", ref2)), bid2), hasRaw: true, bearer: g})
	expect(t, w, 201)
	at := a.nsHead("eb", g)

	// A, through eb: the pre-raise blob keeps its epoch URL, the blob
	// written end to end has none.
	pa := blobPath("eb", "x", bid)
	if r := a.get(pa, g); r.Code != 302 || r.H.Get("Location") != pa+"/e/1" {
		t.Fatalf("A's …/blob/{bid} through eb: %d %v", r.Code, r.H)
	}
	ra := a.get(pa+"/e/1", g)
	expect(t, ra, 200)
	expectCode(t, a.get(blobPath("eb", "x", bid2)+"/e/1", g), 404, "not_offered")

	bJWK, bID, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bID
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"e", "eb"}, []string{"read", "export"}, map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	doc := e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})
	doc["base"] = map[string]any{"origin": originA, "ns": "eb", "at": at, "chain": []any{"eb", "e"}}
	expect(t, b.mkRemote("rel", addRoot(doc)), 201)
	gb := b.grant(kB, "user:reader", []string{"rel"}, []string{"read"})

	pb := blobPath("rel", "x", bid)
	if r := b.get(pb, gb); r.Code != 302 || r.H.Get("Location") != pb+"/e/1" || bytes.Contains(r.Body, data) {
		t.Fatalf("B's …/blob/{bid}: %d %v, want 302 to %s/e/1 as A answers", r.Code, r.H, pb)
	}
	rb := b.get(pb+"/e/1", gb)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("B's epoch URL of the pre-raise blob: %d, want 200 with A's bytes (%.120s)", rb.Code, rb.Body)
	}
	expectCode(t, b.get(blobPath("rel", "x", bid2)+"/e/1", gb), 404, "not_offered")
}
