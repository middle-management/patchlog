package client_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// legacyWrap wraps key, the K_e of kid, for pub under the HPKE info
// keyrings were stored with before v0.63 ("patchlog-keys-v1" LF kid), as
// a keyring written by v0.22.0 holds it.
func legacyWrap(t *testing.T, pub *ecdh.PublicKey, kid string, key []byte) []byte {
	t.Helper()
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	w, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-keys-v1\n"+kid), key)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// rewriteKeys returns a transport that passes the keys of every 200 answer
// of POST /ns/{ns}/keys through edit.
func rewriteKeys(t *testing.T, ns string, edit func(m map[string]any)) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	return roundTrip(func(req *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(req)
		if err != nil || req.URL.Path != "/ns/"+ns+"/keys" || res.StatusCode != 200 {
			return res, err
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		var a map[string]any
		if err := json.Unmarshal(b, &a); err != nil {
			t.Errorf("keys answer: %v", err)
		}
		for _, x := range a["keys"].([]any) {
			edit(x.(map[string]any))
		}
		b, _ = json.Marshal(a)
		res.Body = io.NopCloser(bytes.NewReader(b))
		res.ContentLength = int64(len(b))
		res.Header.Del("Content-Length")
		return res, nil
	})
}

// W1X: a keyring stored before v0.63 holds keys wrapped under the old
// info, and /keys relays its entries as stored, without from (§E.2.3,
// §E.3.2), so a reader whose grant carries enc opens them as
// Keyring.EpochKey opens such a keyring, under the old info when the
// current one fails; and a relayed entry it can't open is no reason to
// stop before the keyring. Since v0.63 servers refuse to have such a
// keyring written (P18), so the relay of a stored one is played by the
// transport; MigrateKeyring wraps such keyrings again (v073_p18_test.go).
func TestW1XRelayedLegacyKeyringEntries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "secret"))).CreateNamespace(ctx, "secret",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	aJWK, aPriv, _ := seal.GenerateRecipient()
	rJWK, rPriv, _ := seal.GenerateRecipient()
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:a", []string{"secret"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": aJWK})))
	ax := admin.E2E(aPriv)
	must(ax.InitKeyring(ctx, "secret", rPriv.PublicKey()))
	must(ax.CreateDocSealed(ctx, "secret", "p", map[string]any{"n": 1.0}))
	kr, _, err := ax.Keyring(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	kid := seal.Kid("secret", kr.Current("secret"))
	ke, err := ax.Key(ctx, kid)
	if err != nil {
		t.Fatal(err)
	}
	readerGrant := k.Grant(t, s.Now(), "user:r", []string{"secret"}, []string{"read"}, map[string]any{"enc": rJWK})

	// The relayed entry of a stored legacy keyring, under the old info.
	legacy := rewriteKeys(t, "secret", func(m map[string]any) {
		delete(m, "from")
		m["wrapped"] = base64.RawURLEncoding.EncodeToString(legacyWrap(t, rPriv.PublicKey(), kid, ke))
	})
	rd := s.Client(t, client.WithBearer(readerGrant), client.WithHTTPClient(&http.Client{Transport: legacy}))
	if _, d, err := rd.E2E(rPriv).LoadE2E(ctx, "secret", "p"); err != nil {
		t.Fatalf("relayed entry of a keyring stored before v0.63: %v", err)
	} else if d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("p %v", d.Value)
	}

	// A relayed entry that opens under neither info: the keyring, which
	// this reader may read, still gives the key, from an admin it knows.
	broken := rewriteKeys(t, "secret", func(m map[string]any) {
		w, _ := base64.RawURLEncoding.DecodeString(m["wrapped"].(string))
		w[len(w)-1] ^= 1
		m["wrapped"] = base64.RawURLEncoding.EncodeToString(w)
	})
	bad := s.Client(t, client.WithBearer(readerGrant), client.WithHTTPClient(&http.Client{Transport: broken}))
	if _, d, err := bad.E2E(rPriv).WithSenders(aPriv.PublicKey()).LoadE2E(ctx, "secret", "p"); err != nil {
		t.Fatalf("relayed entry that doesn't open, keyring readable: %v", err)
	} else if d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("p %v", d.Value)
	}
}
