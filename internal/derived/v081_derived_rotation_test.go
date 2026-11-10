package derived_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
)

// §E.2.4, §E.2.3, §A.4 Unavailable namespaces, §E.2.6: Check judges
// whether the service can consume a sealed namespace by the key of the
// epoch current now. One whose epoch it read (Info) before a rotation,
// and whose grant gets the current epoch's key only, gets no key of the
// epoch Info names from /keys: that is no want of keys, and the
// namespace isn't skipped. Its encryption as the core has it now is
// recorded, so Recheck, after the follower delivers the rotation, judges
// nothing again.
func TestV081CheckAfterRotationSinceInfo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
	if _, err := c.CreateNamespace(ctx, "sec", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	k := derived.NewKeys(c, nil)
	if in, err := k.Info(ctx, "sec"); err != nil || in.Epoch != 1 {
		t.Fatalf("info %+v %v", in, err)
	}
	if _, err := s.Engine.RotateEpoch(ctx, "sec", "system:rotate"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.FetchKeys(ctx, "sec", []int{1}, nil); err != nil || len(got) != 0 {
		t.Fatalf("keys of sec#1 after the rotation: %v %v", got, err)
	}
	if reason, permanent, retry := k.Check(ctx, "sec", false); reason != "" || permanent || retry {
		t.Fatalf("check: %q %v %v", reason, permanent, retry)
	}
	if st := fmt.Sprint(k.Status([]string{"sec"})); st != "[{sec sealed 2 true false }]" {
		t.Fatalf("status %s", st)
	}
	if _, err := k.EpochKey(ctx, "sec", 2); err != nil {
		t.Fatal(err)
	}
	if reason, lacks := k.Recheck(ctx, "sec", false); reason != "" || lacks {
		t.Fatalf("recheck: %q %v", reason, lacks)
	}
}
