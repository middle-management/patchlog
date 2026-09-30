package seal

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// NewKey returns a fresh random 256-bit key (an epoch key K_e, a row key…).
func NewKey() []byte {
	k := make([]byte, KeySize)
	rand.Read(k)
	return k
}

// Kid is the key id of epoch e of namespace ns: "{ns}#{e}" (§E.2.1).
// Per-resource keys use the same kid: the key is derived, the header names
// the epoch.
func Kid(ns string, epoch int) string { return ns + "#" + strconv.Itoa(epoch) }

// ParseKid splits "{ns}#{e}". The epoch must be a canonical non-negative
// decimal.
func ParseKid(kid string) (ns string, epoch int, err error) {
	i := strings.LastIndexByte(kid, '#')
	if i <= 0 || i == len(kid)-1 {
		return "", 0, fmt.Errorf("%w: kid %q", ErrFormat, kid)
	}
	e, err := strconv.Atoi(kid[i+1:])
	if err != nil || e < 0 || strconv.Itoa(e) != kid[i+1:] {
		return "", 0, fmt.Errorf("%w: kid %q", ErrFormat, kid)
	}
	return kid[:i], e, nil
}

// ResourceKeySalt is the HKDF salt of per-resource keys.
const ResourceKeySalt = "patchlog-e2"

// ResourceKey derives K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2",
// info = ns ‖ 0x0A ‖ name), 32 bytes (§E.2.1).
func ResourceKey(epochKey []byte, ns, name string) ([]byte, error) {
	if len(epochKey) != KeySize {
		return nil, ErrKeySize
	}
	return hkdf.Key(sha256.New, epochKey, []byte(ResourceKeySalt), ns+"\n"+name, KeySize)
}

// ---- Recipients (X25519 JWK) ----

// ParseRecipientJWK parses the `enc` member of a grant's root block,
// { "kty": "OKP", "crv": "X25519", "x": "<base64url>" }. v is a jsonv model
// value (map[string]any) or its JSON text ([]byte or string). Members other
// than kty, crv and x are ignored.
func ParseRecipientJWK(v any) (*ecdh.PublicKey, error) {
	switch t := v.(type) {
	case []byte:
		p, err := jsonv.Parse(t)
		if err != nil {
			return nil, fmt.Errorf("%w: jwk: %v", ErrFormat, err)
		}
		v = p
	case string:
		p, err := jsonv.Parse([]byte(t))
		if err != nil {
			return nil, fmt.Errorf("%w: jwk: %v", ErrFormat, err)
		}
		v = p
	}
	m, ok := v.(map[string]any)
	if !ok || m["kty"] != "OKP" || m["crv"] != "X25519" {
		return nil, fmt.Errorf("%w: jwk must be OKP/X25519", ErrFormat)
	}
	xs, _ := m["x"].(string)
	x, err := b64.DecodeString(xs)
	if err != nil || len(x) != 32 {
		return nil, fmt.Errorf("%w: jwk x", ErrFormat)
	}
	pub, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk x: %v", ErrFormat, err)
	}
	return pub, nil
}

// ParseRecipientPrivate parses an X25519 private key: a private JWK
// { "kty": "OKP", "crv": "X25519", "d": "<base64url>", "x"? } (x, if
// present, must match), or the bare base64url of the 32 bytes of d. Used
// for key holders' identity files.
func ParseRecipientPrivate(b []byte) (*ecdh.PrivateKey, error) {
	s := strings.TrimSpace(string(b))
	var d []byte
	var x string
	if strings.HasPrefix(s, "{") {
		v, err := jsonv.Parse([]byte(s))
		if err != nil {
			return nil, fmt.Errorf("%w: jwk: %v", ErrFormat, err)
		}
		m, _ := v.(map[string]any)
		if m == nil || m["kty"] != "OKP" || m["crv"] != "X25519" {
			return nil, fmt.Errorf("%w: jwk must be OKP/X25519", ErrFormat)
		}
		ds, _ := m["d"].(string)
		if d, err = b64.DecodeString(ds); err != nil {
			return nil, fmt.Errorf("%w: jwk d", ErrFormat)
		}
		x, _ = m["x"].(string)
	} else {
		var err error
		if d, err = b64.DecodeString(s); err != nil {
			return nil, fmt.Errorf("%w: private key: %v", ErrFormat, err)
		}
	}
	if len(d) != 32 {
		return nil, fmt.Errorf("%w: an X25519 private key has 32 bytes", ErrFormat)
	}
	priv, err := ecdh.X25519().NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if x != "" && x != b64.EncodeToString(priv.PublicKey().Bytes()) {
		return nil, fmt.Errorf("%w: jwk x doesn't match d", ErrFormat)
	}
	return priv, nil
}

// RecipientPrivateJWK returns the private JWK model value {kty, crv, x, d}
// of priv (keep it secret).
func RecipientPrivateJWK(priv *ecdh.PrivateKey) map[string]any {
	m := RecipientJWK(priv.PublicKey())
	m["d"] = b64.EncodeToString(priv.Bytes())
	return m
}

// RecipientJWK returns the JWK model value {kty, crv, x} of pub.
func RecipientJWK(pub *ecdh.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "X25519", "x": b64.EncodeToString(pub.Bytes())}
}

// RecipientID is the stable id of a recipient public key:
// text(trunc160(sha256(canonical({kty, crv, x})))), a 33-character id.
func RecipientID(pub *ecdh.PublicKey) string {
	return ids.Of(jsonv.Canonical(RecipientJWK(pub))).String()
}

// GenerateRecipient makes a new X25519 key pair and returns its public JWK
// and the private key (for tests and the CLI).
func GenerateRecipient() (jwk map[string]any, priv *ecdh.PrivateKey, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return RecipientJWK(priv.PublicKey()), priv, nil
}

// ---- HPKE key wrapping ----

// Suite names the HPKE ciphersuite of wrapped keys: base mode,
// KEM DHKEM(X25519, HKDF-SHA256) 0x0020, KDF HKDF-SHA256 0x0001,
// AEAD AES-256-GCM 0x0002.
const Suite = "hpke-base-0x0020-0x0001-0x0002"

// WrapInfoPrefix prefixes the HPKE info string: info = prefix ‖ context.
const WrapInfoPrefix = "patchlog-keys-v1\n"

// WrappedKey is the wire form of a key wrapped to one recipient:
//
//	{ "kid": "{ns}#{e}", "resource"?: name, "suite": Suite, "wrapped": base64url(enc ‖ ct) }
//
// The HPKE context is kid, or kid ‖ "\n" ‖ resource for a per-resource key,
// so a wrapped key can't be presented as another epoch's or resource's.
type WrappedKey struct {
	Kid      string
	Resource string // "" for an epoch key
	Wrapped  []byte // HPKE enc ‖ ciphertext
}

func wrapContext(kid, resource string) []byte {
	c := WrapInfoPrefix + kid
	if resource != "" {
		c += "\n" + resource
	}
	return []byte(c)
}

var (
	hpkeKDF  = hpke.HKDFSHA256()
	hpkeAEAD = hpke.AES256GCM()
)

// WrapKey wraps key (K_e, or K_r when resource is non-empty) for recipient.
func WrapKey(recipient *ecdh.PublicKey, kid, resource string, key []byte) (WrappedKey, error) {
	if len(key) != KeySize {
		return WrappedKey{}, ErrKeySize
	}
	pk, err := hpke.NewDHKEMPublicKey(recipient)
	if err != nil {
		return WrappedKey{}, err
	}
	w, err := hpke.Seal(pk, hpkeKDF, hpkeAEAD, wrapContext(kid, resource), key)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{Kid: kid, Resource: resource, Wrapped: w}, nil
}

// UnwrapKey recovers the key in w with the recipient's private key.
func UnwrapKey(priv *ecdh.PrivateKey, w WrappedKey) ([]byte, error) {
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	k, err := hpke.Open(sk, hpkeKDF, hpkeAEAD, wrapContext(w.Kid, w.Resource), w.Wrapped)
	if err != nil || len(k) != KeySize {
		return nil, ErrDecrypt
	}
	return k, nil
}

// Value returns the JSON model value of w.
func (w WrappedKey) Value() map[string]any {
	m := map[string]any{"kid": w.Kid, "suite": Suite, "wrapped": b64.EncodeToString(w.Wrapped)}
	if w.Resource != "" {
		m["resource"] = w.Resource
	}
	return m
}

// MarshalJSON returns canonical JSON of Value.
func (w WrappedKey) MarshalJSON() ([]byte, error) { return jsonv.Canonical(w.Value()), nil }

// ParseWrappedKey parses the model value (or JSON text) of a WrappedKey. A
// missing suite means Suite; any other suite is rejected.
func ParseWrappedKey(v any) (WrappedKey, error) {
	if b, ok := v.([]byte); ok {
		p, err := jsonv.Parse(b)
		if err != nil {
			return WrappedKey{}, fmt.Errorf("%w: wrapped key: %v", ErrFormat, err)
		}
		v = p
	}
	m, ok := v.(map[string]any)
	if !ok {
		return WrappedKey{}, fmt.Errorf("%w: wrapped key", ErrFormat)
	}
	var w WrappedKey
	w.Kid, _ = m["kid"].(string)
	if r, ok := m["resource"]; ok {
		if w.Resource, ok = r.(string); !ok || w.Resource == "" {
			return WrappedKey{}, fmt.Errorf("%w: wrapped key resource", ErrFormat)
		}
	}
	if s, ok := m["suite"]; ok && s != Suite {
		return WrappedKey{}, fmt.Errorf("%w: unsupported suite", ErrFormat)
	}
	ws, _ := m["wrapped"].(string)
	wb, err := b64.DecodeString(ws)
	if err != nil || w.Kid == "" || len(wb) == 0 {
		return WrappedKey{}, fmt.Errorf("%w: wrapped key", ErrFormat)
	}
	w.Wrapped = wb
	return w, nil
}

// UnmarshalJSON parses JSON produced by MarshalJSON.
func (w *WrappedKey) UnmarshalJSON(b []byte) error {
	p, err := ParseWrappedKey(b)
	if err != nil {
		return err
	}
	*w = p
	return nil
}
