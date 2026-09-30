// Package derived is what the consumer services (the index of Addendum A,
// the tree and catalog services of Addendum B) share for encrypted source
// namespaces (Addendum E): reading them with keys, and sealing the views
// they derive from them (§E.2.5, §E.2.6, §E.3.2).
//
// Reading. A sealed (E2) namespace is read with the service's own grant and
// a client built WithKeys: keys come from POST /ns/{ns}/keys, wrapped (HPKE)
// to the grant's enc when it has one, and unwrapped with the service's
// X25519 private key (NewKeys' recipient). An end-to-end (E3) namespace is
// read only when that key is a recipient of the namespace's keyring:
// documents are folded with client.E2E. Without keys the namespace is
// skipped and the reason reported (Keys.Check, Keys.Status); ciphertext is
// never consumed as content.
//
// Sealing (§E.2.6). Values a view derives from a sealed or e2e namespace's
// content (scores, facets, titles, …) are sealed in the compact JWE format
// of §E.2.2 (alg "dir", enc "A256GCM", kid "{ns}#{e}") under that
// namespace's epoch key current when the view is produced; names, ids,
// URLs, heads, structure, at, order and cursors stay in the clear. view is
// the request target (path and query) of the …/at/{at}/… URL the response
// is served at, as the service's redirect gives it, so the ciphertext is
// bound to one query, subject set and checkpoint:
//
//	whole response (SealView):  pl { "ns", "view" }, sealed under K_e,
//	                            served as Content-Type application/jose
//	one entry (SealItem):       pl { "ns", "name", "view" }, sealed under
//	                            K_r = HKDF(K_e, ns, name) of the entry's
//	                            resource, as { …clear, "sealed": "<JWE>" }
//
// Entries use the per-resource key, like the revisions they derive from
// (§E.2.1), so a reader holding only some per-resource keys opens exactly
// the entries of those resources. Nothing is compressed (a view mixes
// content of many resources and authors); a namespace with encryption.pad
// pads what is sealed for it to its size bucket (§E.2.2).
package derived

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/seal"
)

// Encryption levels of a namespace document's encryption.level.
const (
	LevelAtRest = "at-rest"
	LevelSealed = "sealed"
	LevelE2E    = "e2e"
)

// Protected reports whether views derived from a namespace at level must
// be sealed: sealed (E2) and e2e (E3). At-rest (E1) changes nothing on the
// wire.
func Protected(level string) bool { return level == LevelSealed || level == LevelE2E }

// View identifies one derived response: what its pl claims bind.
type View struct {
	// NS is the namespace whose epoch key seals the whole response.
	NS string
	// Target is the request target, path and query, of the …/at/{at}/…
	// URL the response is served at.
	Target string
}

// PL is the pl of the whole response: { ns, view }.
func (v View) PL() seal.PL { return seal.PL{"ns": v.NS, "view": v.Target} }

// ItemPL is the pl of one entry derived from resource name of namespace
// ns: { ns, name, view }.
func (v View) ItemPL(ns, name string) seal.PL {
	return seal.PL{"ns": ns, "name": name, "view": v.Target}
}

// Marshal encodes a view body as JSON, as the services write it.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Key is what seals for one namespace: its current epoch, epoch key and
// whether it pads (Keys.Current).
type Key struct {
	NS    string
	Epoch int
	K     []byte // K_e
	Pad   bool
}

func (k Key) seal(key []byte, pl seal.PL, body any) (string, error) {
	b, err := Marshal(body)
	if err != nil {
		return "", err
	}
	if k.Pad {
		return seal.SealPadded(key, seal.Kid(k.NS, k.Epoch), pl, b)
	}
	return seal.SealUncompressed(key, seal.Kid(k.NS, k.Epoch), pl, b)
}

// SealView seals a whole response body under K_e of k.NS (= v.NS).
func SealView(k Key, v View, body any) (string, error) {
	if k.NS != v.NS {
		return "", fmt.Errorf("derived: view of %s sealed with a key of %s", v.NS, k.NS)
	}
	return k.seal(k.K, v.PL(), body)
}

// SealItem seals the sealed values of one entry, derived from k.NS/name,
// under that resource's K_r.
func SealItem(k Key, v View, name string, values any) (string, error) {
	kr, err := seal.ResourceKey(k.K, k.NS, name)
	if err != nil {
		return "", err
	}
	return k.seal(kr, v.ItemPL(k.NS, name), values)
}

// OpenView decrypts a sealed view: keyOf returns the epoch key K_e of the
// kid the JWE names (nil if the reader has none), and the JWE must be bound
// to v.
func OpenView(jwe string, keyOf func(kid string) []byte, v View) ([]byte, error) {
	return open(jwe, keyOf, v.NS, v.PL())
}

// OpenItem decrypts one sealed entry derived from ns/name: keyOf returns
// K_r of that resource for the kid the JWE names (ItemKey derives it from
// epoch keys).
func OpenItem(jwe string, keyOf func(kid string) []byte, v View, ns, name string) ([]byte, error) {
	return open(jwe, keyOf, ns, v.ItemPL(ns, name))
}

// ItemKey returns a keyOf for OpenItem that derives K_r of ns/name from
// the epoch keys epochKeyOf returns.
func ItemKey(epochKeyOf func(kid string) []byte, ns, name string) func(string) []byte {
	return func(kid string) []byte {
		ke := epochKeyOf(kid)
		if ke == nil {
			return nil
		}
		kr, err := seal.ResourceKey(ke, ns, name)
		if err != nil {
			return nil
		}
		return kr
	}
}

func open(jwe string, keyOf func(string) []byte, ns string, pl seal.PL) ([]byte, error) {
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, err
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, err
	}
	if kns != ns {
		return nil, seal.ErrMismatch
	}
	k := keyOf(h.Kid)
	if k == nil {
		return nil, ErrNoKey
	}
	return seal.OpenExpect(jwe, k, h.Kid, pl)
}

// ErrNoKey reports a sealed view or entry under a kid the caller has no
// key for.
var ErrNoKey = errors.New("derived: no key for the sealed view")

// ParseRecipientKey parses a service's X25519 private key: the 32-byte
// scalar in base64url (padded or not), as in a JWK's d.
func ParseRecipientKey(s string) (*ecdh.PrivateKey, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("derived: the X25519 private key must be 32 bytes in base64url")
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// LoadRecipientKey reads ParseRecipientKey's format from a file.
func LoadRecipientKey(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRecipientKey(string(b))
}

// EncodeRecipientKey is the inverse of ParseRecipientKey.
func EncodeRecipientKey(k *ecdh.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(k.Bytes())
}
