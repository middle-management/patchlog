package derived_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// xrev2-leaks, target 3: Check with an Info read before an E3 rotation that
// leaves the service out of the new epoch's readers. rotatedSince must not
// turn the stale epoch's refusal into a pass: the namespace is skipped.
// Control: the same with the service among the new readers passes.
func TestV081XLCheckRotationLeavesServiceOut(t *testing.T) {
	t.Parallel()
	for _, in := range []bool{false, true} {
		ctx := context.Background()
		ks, err := keystore.New(keystore.Generate())
		if err != nil {
			t.Fatal(err)
		}
		s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
		k := clienttest.NewKey("k")
		if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
			"encryption": map[string]any{"level": "e2e"}}); err != nil {
			t.Fatal(err)
		}
		adminJWK, admin, _ := seal.GenerateRecipient()
		svcJWK, svc, _ := seal.GenerateRecipient()
		ac := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"e"}, []string{"read", "create", "append", "config"},
			map[string]any{"enc": adminJWK})))
		ax := ac.E2E(admin)
		if _, err := ax.InitKeyring(ctx, "e", svc.PublicKey()); err != nil {
			t.Fatal(err)
		}
		sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:x", []string{"e"}, []string{"read"}, map[string]any{"enc": svcJWK})),
			client.WithKeyringSenders(admin.PublicKey()))
		keys := derived.NewKeys(sc, svc)
		info, err := keys.Info(ctx, "e")
		if err != nil || info.Level != derived.LevelE2E {
			t.Fatalf("info: %+v %v", info, err)
		}
		if in {
			if _, err := ax.RotateEpoch(ctx, "e", svc.PublicKey()); err != nil {
				t.Fatal(err)
			}
		} else if _, err := ax.RotateEpoch(ctx, "e"); err != nil {
			t.Fatal(err)
		}
		reason, permanent, retry := keys.Check(ctx, "e", false)
		t.Logf("service among readers %v: info epoch %d; check %q %v %v; status %v", in, info.Epoch, reason, permanent, retry, keys.Status([]string{"e"}))
		if in && reason != "" {
			t.Errorf("control: the service reads the new epoch, yet check says %q", reason)
		}
		// Check, with Info cached from before the rotation, passes on the
		// stale epoch's key (pre-existing: rotatedSince runs only on a
		// non-retryable failure). The follower delivering the rotation's
		// config entry must then skip it (Observe, Recheck).
		h, err := sc.NSHead(ctx, "e")
		if err != nil {
			t.Fatal(err)
		}
		d, err := sc.NSDoc(ctx, "e", h.ID)
		if err != nil {
			t.Fatal(err)
		}
		keys.Observe("e", d.Value)
		reason, lacks := keys.Recheck(ctx, "e", false)
		t.Logf("recheck: %q %v skipped %q", reason, lacks, keys.Skipped("e"))
		if in && (reason != "" || lacks) {
			t.Errorf("control: recheck %q %v", reason, lacks)
		}
		if !in {
			if reason == "" || !lacks || keys.Skipped("e") == "" {
				t.Errorf("the rotation left the service out, yet Recheck passes: %q %v", reason, lacks)
			}
			if _, _, err := keys.Current(ctx, "e"); err == nil {
				t.Errorf("Current gives a key though the service reads no key of the current epoch")
			}
		}
	}
}

// refuseKeys answers POST /ns/{ns}/keys 403 once on is set.
type refuseKeys struct {
	rt http.RoundTripper
	on *atomic.Bool
}

func (f refuseKeys) RoundTrip(r *http.Request) (*http.Response, error) {
	if !f.on.Load() || r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/keys") {
		return f.rt.RoundTrip(r)
	}
	b := []byte(`{"code":"forbidden","message":"injected"}`)
	return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: r}, nil
}

// xrev2-leaks, target 3, through rotatedSince: Info read at epoch 1, a
// rotation since, and /keys refusing the service every epoch (non-
// retryable). Check re-reads the encryption (epoch 2), is refused its key
// too, and must skip the namespace; Current must give no key. Control:
// without the refusal, Check passes on epoch 2 after the rotation.
func TestV081XLCheckRotatedSinceRefused(t *testing.T) {
	t.Parallel()
	for _, refused := range []bool{false, true} {
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
		on := &atomic.Bool{}
		sc := s.Client(t, client.WithAuthor("svc"), client.WithKeys(client.NewKeys(nil)),
			client.WithTransport(func(rt http.RoundTripper) http.RoundTripper { return refuseKeys{rt, on} }))
		k := derived.NewKeys(sc, nil)
		if in, err := k.Info(ctx, "sec"); err != nil || in.Epoch != 1 {
			t.Fatalf("info %+v %v", in, err)
		}
		if _, err := s.Engine.RotateEpoch(ctx, "sec", "system:rotate"); err != nil {
			t.Fatal(err)
		}
		on.Store(refused)
		reason, permanent, retry := k.Check(ctx, "sec", false)
		t.Logf("refused %v: check %q %v %v; status %v", refused, reason, permanent, retry, k.Status([]string{"sec"}))
		if !refused {
			if reason != "" {
				t.Errorf("control: %q", reason)
			}
			continue
		}
		if reason == "" {
			t.Errorf("refused every key, Check passes after re-reading the rotation")
		}
		if _, key, err := k.Current(ctx, "sec"); err == nil {
			t.Errorf("Current gives a key (epoch %d) though /keys refuses every epoch", key.Epoch)
		}
	}
}
