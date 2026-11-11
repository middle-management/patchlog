package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// XT-1 (7), E2E-3, E2E-4 and E2E-6 end to end (§7.1, §8.6, §E.3.1,
// §G.5.2; v0.82: "A tombstone's /rev/{T} is 410 with { tombstone, last },
// so a pruner and a mirroring remote branch learn its parent there"): the
// reference's client writes x in m, an e2e namespace of A, deletes it and
// prunes at the tombstone T. It learns T's parent P from A's 410 for
// /rev/{T}, checks it against T's id, and stores the snapshot of P, whose
// pl names P. B then takes a remote branch r of m: it learns P the same
// way and mirrors that snapshot. A reader of r at B, with m#1's key and no
// access to A, gets what the writer wrote: x's head is the tombstone, its
// /rev/{T} the 410 naming P, and the document at P opens from the
// mirrored snapshot, byte for byte A's.
func TestV082XTombstoneHorizonPrunedMirroredRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning,
		withArchive(t, t.TempDir()), withoutRetentionLoop)
	a.opPriv = aPriv
	s := &v081Source{a: a, kA: newKey("admin")}
	a.mkNS("m", e2eDoc(map[string]any{"read": "grant", "keys": []any{s.kA.entry("*")}}))
	s.root = func() string { return a.grant(s.kA, "user:root", []string{"m"}, allVerbs) }

	// The writer: the client, with a keyring of its own making.
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	wc, err := plclient.New(a.srv.URL, plclient.WithBearer(a.grant(s.kA, "user:root", []string{"m"}, allVerbs, map[string]any{"enc": jwk})))
	if err != nil {
		t.Fatal(err)
	}
	wx := wc.E2E(priv)
	if _, err := wx.InitKeyring(ctx, "m"); err != nil {
		t.Fatal(err)
	}
	x1, err := wx.CreateDocSealed(ctx, "m", "x", map[string]any{"v": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	x2, err := wx.AppendSealed(ctx, "m", "x", x1.ID, []any{map[string]any{"op": "replace", "path": "/v", "value": 2.0}})
	if err != nil {
		t.Fatal(err)
	}
	tomb, err := wc.Delete(ctx, "m", "x", x2.ID)
	if err != nil {
		t.Fatal(err)
	}
	P, T := x2.ID, tomb.ID
	a.clock.Advance(10 * time.Minute)

	// The tombstone's own /rev at an origin, as a client reads it: T and
	// its parent, which rehashes to T (§3.4).
	gone := func(what string, c *plclient.Client, ns string) {
		t.Helper()
		_, err := c.Doc(ctx, ns, "x", T)
		var ae *plclient.APIError
		if !errors.As(err, &ae) || ae.Status != 410 || ae.Tombstone() != T || ae.Last() != P {
			t.Fatalf("%s: /rev/{T}: %v, want 410 naming tombstone %s and last %s", what, err, T, P)
		}
		pid, err := ids.Parse(ae.Last())
		if err != nil || ids.Tombstone(pid).String() != T {
			t.Fatalf("%s: last %s doesn't rehash to the tombstone %s", what, ae.Last(), T)
		}
		h, err := c.Head(ctx, ns, "x")
		if err != nil || h.State != plclient.Tombstoned || h.ID != T || h.Last != P {
			t.Fatalf("%s: the head: %+v %v", what, h, err)
		}
	}
	gone("A", wc, "m")

	// The client prunes at T: the snapshot it stores is P's.
	if res, err := wx.PruneE2E(ctx, "m", "x", T); err != nil || res.Horizon != T {
		t.Fatalf("PruneE2E at the tombstone: %+v %v", res, err)
	}
	snap := a.get("/r/m/x/rev/"+P, s.root())
	if snap.Code != 200 || snap.H.Get("Content-Type") != seal.ContentType {
		t.Fatalf("A at P after the prune: %d %.200s", snap.Code, snap.Body)
	}
	if h, err := seal.ParseHeader(string(snap.Body)); err != nil || h.Expect("m#1", seal.SnapshotPL("m", "x", P)) != nil {
		t.Fatalf("A's snapshot header: %+v %v", h, err)
	}
	gone("A, pruned", wc, "m")
	if r := a.get("/r/m/x/rev/"+x1.ID, s.root()); r.Code == 200 {
		t.Fatalf("A below the horizon: %d", r.Code)
	}

	// B's remote branch of m at A's head mirrors it.
	s.at = a.nsHead("m", s.root())
	b := newV081B(t, s, a.srv.URL)
	_, reader := v081Remote(t, b, s, "r")
	if r := b.get("/r/r/x/rev/"+P, reader); r.Code != 200 || string(r.Body) != string(snap.Body) {
		t.Fatalf("B at P: %d %.200s, want A's snapshot byte for byte", r.Code, r.Body)
	}

	// The reader at B: m#1's epoch key, and no way to A.
	ke, err := wx.Key(ctx, "m#1")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := plclient.New(b.srv.URL, plclient.WithBearer(reader))
	if err != nil {
		t.Fatal(err)
	}
	gone("B", rc, "r")
	d, err := rc.E2EKeys(map[string][]byte{"m#1": ke}).DocE2E(ctx, "r", "x", P)
	if err != nil {
		t.Fatalf("the reader's document at P, from B's mirrored snapshot: %v", err)
	}
	if got := string(jsonv.Canonical(d.Value)); got != `{"v":2}` {
		t.Fatalf("the reader's document at P: %s, want {\"v\":2}", got)
	}
}
