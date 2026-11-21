package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// XT-1 (7), E2E-3, E2E-4 and E2E-6 end to end (§7.1, §8.6, §E.3.1;
// v0.82: "A tombstone's /rev/{T} is 410 with { tombstone, last }, so a
// pruner learns its parent there"): the reference's client writes x in m,
// an e2e namespace, deletes it and prunes at the tombstone T. It learns
// T's parent P from the 410 for /rev/{T}, checks it against T's id, and
// stores the snapshot of P, whose pl names P.
func TestV082XTombstoneHorizonPruned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning,
		withArchive(t, t.TempDir()), withoutRetentionLoop)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", e2eDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }

	// The writer: the client, with a keyring of its own making.
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	wc, err := plclient.New(a.srv.URL, plclient.WithBearer(a.grant(kA, "user:root", []string{"m"}, allVerbs, map[string]any{"enc": jwk})))
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
	snap := a.get("/r/m/x/rev/"+P, root())
	if snap.Code != 200 || snap.H.Get("Content-Type") != seal.ContentType {
		t.Fatalf("A at P after the prune: %d %.200s", snap.Code, snap.Body)
	}
	if h, err := seal.ParseHeader(string(snap.Body)); err != nil || h.Expect("m#1", seal.SnapshotPL("m", "x", P)) != nil {
		t.Fatalf("A's snapshot header: %+v %v", h, err)
	}
	gone("A, pruned", wc, "m")
	if r := a.get("/r/m/x/rev/"+x1.ID, root()); r.Code == 200 {
		t.Fatalf("A below the horizon: %d", r.Code)
	}
}
