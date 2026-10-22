package client_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// e2eAdminEnv is an e2e namespace "e" whose * key signs the grants, an
// admin view (its recipient key wraps the keyring) and a reader grant.
type e2eAdminEnv struct {
	s           *clienttest.Server
	k           clienttest.Key
	admin       *client.Client
	ax          *client.E2E
	adminPriv   *ecdh.PrivateKey
	readerJWK   map[string]any
	readerPriv  *ecdh.PrivateKey
	readerGrant string
	writerJWK   map[string]any
	writerPriv  *ecdh.PrivateKey
}

func newE2EAdminEnv(t *testing.T) *e2eAdminEnv {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	v := &e2eAdminEnv{s: s, k: k}
	var aJWK map[string]any
	aJWK, v.adminPriv, _ = seal.GenerateRecipient()
	v.readerJWK, v.readerPriv, _ = seal.GenerateRecipient()
	v.writerJWK, v.writerPriv, _ = seal.GenerateRecipient()
	v.admin = s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:a", []string{"e"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": aJWK})))
	v.ax = v.admin.E2E(v.adminPriv)
	v.readerGrant = k.Grant(t, s.Now(), "user:r", []string{"e"}, []string{"read"}, map[string]any{"enc": v.readerJWK})
	return v
}

// P18, ENC-11 (§E.3.2): the admin functions write the keyring document,
// each entry wrapped in HPKE auth mode under the view's own recipient
// key, which from names; a reader opens an entry only with that key's
// public key, given with WithSenders or WithKeyringSenders.
func TestV073E2EKeyringAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newE2EAdminEnv(t)
	must(v.ax.InitKeyring(ctx, "e", v.readerPriv.PublicKey()))
	w := must(v.ax.CreateDocSealed(ctx, "e", "p", map[string]any{"n": 1.0}))
	kr, _ := must2(v.ax.Keyring(ctx, "e"))
	admin := seal.Thumbprint(v.adminPriv.PublicKey())
	if len(kr.Entries) != 2 || kr.Current("e") != 1 {
		t.Fatalf("keyring %+v", kr)
	}
	for _, e := range kr.Entries {
		if e.From != admin || e.Kid != "e#1" {
			t.Fatalf("entry %+v", e)
		}
	}
	// The stored document is exactly the §E.3.2 form.
	_, d, err := v.admin.Load(ctx, "e", client.KeyringName)
	if err != nil {
		t.Fatal(err)
	}
	if m := d.Value.(map[string]any); len(m) != 1 || m["keys"] == nil {
		t.Fatalf("keyring document %v", m)
	}

	// A reader that doesn't know the admin's key can't open its entry.
	rc := v.s.Client(t, client.WithBearer(v.readerGrant))
	if _, err := rc.E2E(v.readerPriv).DocE2E(ctx, "e", "p", w.ID); err == nil {
		t.Fatal("an entry from an unknown sender opened")
	}
	if _, err := rc.E2E(v.readerPriv).WithSenders(v.adminPriv.PublicKey()).DocE2E(ctx, "e", "p", w.ID); err != nil {
		t.Fatalf("WithSenders: %v", err)
	}
	rc2 := v.s.Client(t, client.WithBearer(v.readerGrant), client.WithKeyringSenders(v.adminPriv.PublicKey()))
	if _, err := rc2.E2E(v.readerPriv).DocE2E(ctx, "e", "p", w.ID); err != nil {
		t.Fatalf("WithKeyringSenders: %v", err)
	}
	// A relayed entry carries the admin's thumbprint as from.
	got := must(rc.FetchKeys(ctx, "e", nil, nil))
	if len(got) != 1 || got[0].From != admin || got[0].Wrapped.From != admin {
		t.Fatalf("relayed %+v", got)
	}

	// Adding a reader and rotating write the same form.
	must(v.ax.AddReader(ctx, "e", v.writerPriv.PublicKey(), false))
	e2 := must(v.ax.RotateEpoch(ctx, "e", v.writerPriv.PublicKey()))
	kr, _ = must2(v.ax.Keyring(ctx, "e"))
	if e2 != 2 || len(kr.Recipients("e#1")) != 3 || len(kr.Recipients("e#2")) != 2 {
		t.Fatalf("after rotation %v %v", kr.Recipients("e#1"), kr.Recipients("e#2"))
	}
	for _, e := range kr.Entries {
		if e.From != admin {
			t.Fatalf("entry %+v", e)
		}
	}
	// KeyringReaders: the keys the view knows that hold the newest epoch.
	readers := v.ax.WithSenders(v.writerPriv.PublicKey(), v.readerPriv.PublicKey()).KeyringReaders(kr)
	if len(readers) != 2 {
		t.Fatalf("readers of e#2: %d", len(readers))
	}
	// Administration needs the view's own recipient key.
	if _, err := v.admin.E2EKeys(nil).InitKeyring(ctx, "e"); err == nil {
		t.Fatal("InitKeyring without a recipient key")
	}
}

// P18, ENC-11 (CHANGELOG): a keyring stored in the format before v0.63 is
// refused as a write, so MigrateKeyring wraps it again in the keyring
// document, for the readers the caller gives each epoch. The stored
// legacy document is played by the transport.
func TestV073E2EMigrateKeyring(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newE2EAdminEnv(t)
	must(v.ax.InitKeyring(ctx, "e"))
	ke := must(v.ax.Key(ctx, "e#1"))
	legacy, err := seal.BuildKeyring("e", 1, ke, []*ecdh.PublicKey{v.adminPriv.PublicKey(), v.readerPriv.PublicKey(), v.writerPriv.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(legacy.Value())
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(req)
		if err != nil || req.Method != "GET" || !strings.HasPrefix(req.URL.Path, "/r/e/keyring/rev/") || res.StatusCode != 200 {
			return res, err
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		res.Body = io.NopCloser(bytes.NewReader(body))
		res.ContentLength = int64(len(body))
		res.Header.Del("Content-Length")
		return res, nil
	})
	aJWK := seal.RecipientJWK(v.adminPriv.PublicKey())
	old := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:a", []string{"e"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": aJWK})),
		client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.adminPriv)
	if _, _, err := old.Keyring(ctx, "e"); !errors.Is(err, client.ErrLegacyKeyring) {
		t.Fatalf("Keyring of a legacy document: %v", err)
	}
	if _, err := old.AddReader(ctx, "e", v.readerPriv.PublicKey(), false); !errors.Is(err, client.ErrLegacyKeyring) {
		t.Fatalf("AddReader on a legacy document: %v", err)
	}
	lk, _ := must2(old.LegacyKeyring(ctx, "e"))
	if lk.NS != "e" || lk.Current != 1 {
		t.Fatalf("legacy %+v", lk)
	}
	// Epoch 1 for the reader only: the writer in the stored lists is left
	// out, as the caller decides; the admin keeps its own entry.
	if _, err := old.MigrateKeyring(ctx, "e", map[int][]*ecdh.PublicKey{}); err == nil {
		t.Fatal("migrating without readers for epoch 1")
	}
	must(old.MigrateKeyring(ctx, "e", map[int][]*ecdh.PublicKey{1: {v.readerPriv.PublicKey()}}))
	kr, _ := must2(v.ax.Keyring(ctx, "e"))
	got := kr.Recipients("e#1")
	want := []string{seal.Thumbprint(v.adminPriv.PublicKey()), seal.Thumbprint(v.readerPriv.PublicKey())}
	if len(got) != 2 || !(got[0] == want[0] && got[1] == want[1] || got[0] == want[1] && got[1] == want[0]) {
		t.Fatalf("migrated recipients %v", got)
	}
	k, err := kr.EpochKey(v.readerPriv, "e#1", []*ecdh.PublicKey{v.adminPriv.PublicKey()})
	if err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("migrated entry: %v", err)
	}
}
