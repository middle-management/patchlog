package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// KEYS-11 (§E.2.1 Message bound: at E3 only clients seal under K_r, and the
// key holder that rotates keeps each K_r within the bound): a view counts
// the sealings under each resource's K_r of an epoch, its own and those
// the log shows, reports rotation due once the margin is reached, and
// refuses a sealing past the bound. Writes run WithoutValidation, so they
// fold nothing and the test holds on either side of the E3 read change.
func TestV081SealBoundRotationDue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if client.DefaultSealBound != 1<<32 || client.DefaultSealMargin != 1<<31 {
		t.Fatalf("defaults %d %d", client.DefaultSealBound, client.DefaultSealMargin)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, _ := seal.GenerateRecipient()
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	must(c.E2E(priv).InitKeyring(ctx, "e"))
	x := c.E2E(priv).WithoutValidation().WithSealBound(4, 1)

	status := func(x *client.E2E, name string) *client.SealStatus {
		t.Helper()
		return must(x.SealStatus(ctx, "e", name))
	}
	if st := status(x, "d"); st.Sealed != 0 || st.RotationDue || st.Kid != "e#1" || st.Bound != 4 || st.Margin != 1 {
		t.Fatalf("before any write: %+v", st)
	}
	head := must(x.CreateSealed(ctx, "e", "d", client.GenesisPatches(map[string]any{"n": 0}))).ID
	g := head
	head = must(x.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 1)))).ID
	// A refused write was sealed all the same: it counts, once, however
	// often it was resent.
	if _, err := x.AppendSealed(ctx, "e", "d", g, ops(op("replace", "/n", 9))); !client.IsStale(err) {
		t.Fatalf("append on a stale parent: %v", err)
	}
	if st := status(x, "d"); st.Sealed != 3 || !st.RotationDue {
		t.Fatalf("after three sealings (one refused), within the margin: %+v", st)
	}
	head = must(x.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 2)))).ID
	if st := status(x, "d"); st.Sealed != 4 || !st.RotationDue {
		t.Fatalf("after four sealings: %+v", st)
	}
	if _, err := x.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 3))); !errors.Is(err, client.ErrSealBound) {
		t.Fatalf("a fifth sealing under a bound of 4: %v", err)
	}
	if _, err := x.SealPatches(ctx, "e", "d", head, ops(op("replace", "/n", 3))); !errors.Is(err, client.ErrSealBound) {
		t.Fatalf("SealPatches past the bound: %v", err)
	}
	// Another resource's K_r has its own count.
	must(x.CreateSealed(ctx, "e", "other", client.GenesisPatches(map[string]any{})))

	// A fresh view knows only what the log shows: the three writes that
	// were stored, not the refused one; once it has counted them, it
	// refuses past the bound too.
	y := c.E2E(priv).WithoutValidation().WithSealBound(4, 1)
	if st := status(y, "d"); st.Sealed != 3 || !st.RotationDue || st.Partial {
		t.Fatalf("a fresh view: %+v", st)
	}
	head = must(y.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 3)))).ID
	if _, err := y.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 4))); !errors.Is(err, client.ErrSealBound) {
		t.Fatalf("a fresh view past the bound: %v", err)
	}

	// Rotating starts a new K_r: the count is the new epoch's.
	if e := must(c.E2E(priv).RotateEpoch(ctx, "e")); e != 2 {
		t.Fatalf("rotated to %d", e)
	}
	if st := status(y, "d"); st.Kid != "e#2" || st.Sealed != 0 || st.RotationDue {
		t.Fatalf("after rotation: %+v", st)
	}
	must(y.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 4))))
}
