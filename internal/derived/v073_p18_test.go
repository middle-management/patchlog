package derived_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
)

// P18, ENC-14 (§E.2.3): with historyEpochs h, a reader gets keys for the
// current epoch and the h before it, so the per-resource keys a service
// hands out (catalog /read-grants) cover h+1 epochs. The service's grant
// has an nbf before the first epoch: without one, or with authentication
// disabled, /keys gives the current epoch alone (§E.2.3, v0.74).
func TestV073ResourceKeysHistoryEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks, Auth: true})
	k := clienttest.NewKey("k")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "public", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed", "historyEpochs": 1}}); err != nil {
		t.Fatal(err)
	}
	g := k.Grant(t, s.Now(), "svc:derived", []string{"sec"}, []string{"read", "config"}, map[string]any{"nbf": s.Now().Add(-time.Hour).Format(time.RFC3339)})
	c := s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil)))
	for _, e := range []float64{2, 3} {
		h, err := c.NSHead(ctx, "sec")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.PatchConfig(ctx, "sec", h.Config, []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": e}}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := derived.NewKeys(c, nil).ResourceKeys(ctx, "sec", "a")
	if err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range got {
		kids = append(kids, k.Kid)
	}
	if strings.Join(kids, ",") != "sec#3,sec#2" {
		t.Fatalf("per-resource keys of %v, want sec#3 and sec#2", kids)
	}
}

// P18 review (ENC-14, §7.4): historyEpochs 0 is the current epoch alone,
// not "no cap".
func TestV073ResourceKeysHistoryEpochsZero(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
	if _, err := c.CreateNamespace(ctx, "sec", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "historyEpochs": 0}}); err != nil {
		t.Fatal(err)
	}
	h, err := c.NSHead(ctx, "sec")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PatchConfig(ctx, "sec", h.Config, []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": 2}}); err != nil {
		t.Fatal(err)
	}
	got, err := derived.NewKeys(c, nil).ResourceKeys(ctx, "sec", "a")
	if err != nil || len(got) != 1 || got[0].Kid != "sec#2" {
		t.Fatalf("per-resource keys %+v %v, want sec#2 alone", got, err)
	}
	if in := derived.InfoOf(map[string]any{"encryption": map[string]any{"level": "sealed"}}); in.HistoryCapped {
		t.Fatal("no historyEpochs read as a cap")
	}
}
