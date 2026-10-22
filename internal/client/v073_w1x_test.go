package client_test

import (
	"bytes"
	"context"
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

// legacyRewrap wraps every entry of kr again under the HPKE info keyrings
// were stored with before v0.63 ("patchlog-keys-v1" LF kid), as a keyring
// written by v0.22.0 is.
func legacyRewrap(t *testing.T, kr *seal.Keyring, keys map[int][]byte) {
	t.Helper()
	for e, entries := range kr.Epochs {
		for rid := range entries {
			pk, err := hpke.NewDHKEMPublicKey(kr.Recipients[rid])
			if err != nil {
				t.Fatal(err)
			}
			w, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-keys-v1\n"+seal.Kid(kr.NS, e)), keys[e])
			if err != nil {
				t.Fatal(err)
			}
			entries[rid] = w
		}
	}
}

// W1X: a keyring stored before v0.63 holds keys wrapped under the old
// info. /keys relays its entries as stored (§E.2.3, §E.3.2), so a reader
// whose grant carries enc opens them as Keyring.EpochKey opens the keyring
// itself, under the old info when the current one fails; and a relayed
// entry it can't open is no reason to stop before the keyring.
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
	kr, head, err := ax.Keyring(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	ke, err := ax.Key(ctx, seal.Kid("secret", kr.Current))
	if err != nil {
		t.Fatal(err)
	}
	legacyRewrap(t, kr, map[int][]byte{kr.Current: ke})
	must(admin.Append(ctx, "secret", client.KeyringName, head, []any{map[string]any{"op": "replace", "path": "", "value": kr.Value()}}))
	readerGrant := k.Grant(t, s.Now(), "user:r", []string{"secret"}, []string{"read"}, map[string]any{"enc": rJWK})

	// The relayed entry, under the old info.
	rd := s.Client(t, client.WithBearer(readerGrant))
	if _, d, err := rd.E2E(rPriv).LoadE2E(ctx, "secret", "p"); err != nil {
		t.Fatalf("relayed entry of a keyring stored before v0.63: %v", err)
	} else if d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("p %v", d.Value)
	}

	// A relayed entry that opens under neither info: the keyring, which
	// this reader may read, still gives the key.
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(req)
		if err != nil || req.URL.Path != "/ns/secret/keys" || res.StatusCode != 200 {
			return res, err
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		var a map[string]any
		if err := json.Unmarshal(b, &a); err != nil {
			t.Errorf("keys answer: %v", err)
		}
		for _, x := range a["keys"].([]any) {
			m := x.(map[string]any)
			w, _ := base64.RawURLEncoding.DecodeString(m["wrapped"].(string))
			w[len(w)-1] ^= 1
			m["wrapped"] = base64.RawURLEncoding.EncodeToString(w)
		}
		b, _ = json.Marshal(a)
		res.Body = io.NopCloser(bytes.NewReader(b))
		res.ContentLength = int64(len(b))
		res.Header.Del("Content-Length")
		return res, nil
	})
	bad := s.Client(t, client.WithBearer(readerGrant), client.WithHTTPClient(&http.Client{Transport: rt}))
	if _, d, err := bad.E2E(rPriv).LoadE2E(ctx, "secret", "p"); err != nil {
		t.Fatalf("relayed entry that doesn't open, keyring readable: %v", err)
	} else if d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("p %v", d.Value)
	}

	// The re-wrap the CHANGELOG names until the server takes the §E.3.2
	// document: AddReader with history, per reader, wraps that reader's
	// entries under the current info.
	must(admin.E2E(aPriv).AddReader(ctx, "secret", rPriv.PublicKey(), true))
	got := must(rd.FetchKeys(ctx, "secret", []int{kr.Current}, nil))
	if len(got) != 1 {
		t.Fatalf("relayed %v", got)
	}
	if k, err := seal.UnwrapKey(rPriv, got[0].Wrapped); err != nil || !bytes.Equal(k, ke) {
		t.Fatalf("after AddReader, the relayed entry under the current info: %v", err)
	}
}
