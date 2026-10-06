// Package sig implements author signatures (§C.3, §C.3.1): the signing
// input, the Signature header form "<alg>:<kid>:<sig>", and the signer
// key entries a grant's root block lists.
package sig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
)

// Alg is the only signature algorithm (§C.3.1).
const Alg = "Ed25519"

var b64 = base64.RawURLEncoding

// tombstoneBody stands in for canonical(patches) when signing a tombstone
// (§C.3.1). A canonical patch set starts with "[", so the two never collide.
var tombstoneBody = []byte("tombstone")

// Digest is sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖
// 0x0A ‖ bytes(parent) ‖ 0x0A ‖ body) (§C.3). parent is nil for a genesis.
// body is canonical(patches), or nil for a tombstone.
func Digest(origin, ns, name string, parent *ids.ID, body []byte) []byte {
	if body == nil {
		body = tombstoneBody
	}
	h := sha256.New()
	h.Write([]byte("patchlog-sig-v2\n"))
	h.Write([]byte(origin))
	h.Write([]byte{0x0A})
	h.Write([]byte(ns))
	h.Write([]byte{0x0A})
	h.Write([]byte(name))
	h.Write([]byte{0x0A})
	if parent != nil {
		h.Write(parent[:])
	}
	h.Write([]byte{0x0A})
	h.Write(body)
	return h.Sum(nil)
}

// Signature is a parsed Signature header.
type Signature struct {
	Alg, Kid string
	Sig      []byte
}

// String is the header form.
func (s Signature) String() string { return s.Alg + ":" + s.Kid + ":" + b64.EncodeToString(s.Sig) }

// Parse parses "<alg>:<kid>:<sig>". An algorithm other than Ed25519 parses
// (it is stored unverified unless its kid is listed); the sig must be
// unpadded base64url.
func Parse(h string) (Signature, error) {
	parts := strings.Split(h, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Signature{}, errors.New(`a signature is "<alg>:<kid>:<sig>"`)
	}
	raw, err := b64.DecodeString(parts[2])
	if err != nil {
		return Signature{}, errors.New("the sig of a signature must be base64url without padding")
	}
	return Signature{Alg: parts[0], Kid: parts[1], Sig: raw}, nil
}

// Signer is a key entry of a root block's signers (§C.3.1).
type Signer struct {
	Kid, Alg string
	Pub      ed25519.PublicKey
}

// ParseSigners parses a root block's signers member: an array of
// { "kid", "alg", "pub" } with unique kids containing no ":", alg
// "Ed25519" and pub 43 base64url characters. Anything else is an error.
func ParseSigners(v any) ([]Signer, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("signers must be an array")
	}
	out := make([]Signer, 0, len(arr))
	seen := map[string]bool{}
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("signers[%d] must be an object", i)
		}
		for k := range m {
			if k != "kid" && k != "alg" && k != "pub" {
				return nil, fmt.Errorf("signers[%d] has unknown member %q", i, k)
			}
		}
		kid, _ := m["kid"].(string)
		alg, _ := m["alg"].(string)
		pub, _ := m["pub"].(string)
		if kid == "" || strings.Contains(kid, ":") {
			return nil, fmt.Errorf("signers[%d].kid must be a non-empty string without ':'", i)
		}
		if seen[kid] {
			return nil, fmt.Errorf("signers[%d].kid %q is repeated", i, kid)
		}
		seen[kid] = true
		if alg != Alg {
			return nil, fmt.Errorf("signers[%d].alg must be %q", i, Alg)
		}
		raw, err := b64.DecodeString(pub)
		if err != nil || len(pub) != 43 || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signers[%d].pub must be an Ed25519 key in base64url without padding", i)
		}
		out = append(out, Signer{Kid: kid, Alg: alg, Pub: ed25519.PublicKey(raw)})
	}
	return out, nil
}

// Find returns the signer with kid.
func Find(signers []Signer, kid string) (Signer, bool) {
	for _, s := range signers {
		if s.Kid == kid {
			return s, true
		}
	}
	return Signer{}, false
}

// Verify checks s against signer over digest.
func Verify(signer Signer, s Signature, digest []byte) bool {
	return s.Alg == Alg && s.Kid == signer.Kid && len(s.Sig) == ed25519.SignatureSize &&
		ed25519.Verify(signer.Pub, digest, s.Sig)
}

// Key is a private signing key with its kid, for clients and tools.
type Key struct {
	Kid  string
	Priv ed25519.PrivateKey
}

// Entry is the signers entry for k, to list in a root block.
func (k Key) Entry() map[string]any {
	return map[string]any{"kid": k.Kid, "alg": Alg, "pub": b64.EncodeToString(k.Priv.Public().(ed25519.PublicKey))}
}

// Sign signs digest, returning the header form.
func (k Key) Sign(digest []byte) string {
	return Signature{Alg: Alg, Kid: k.Kid, Sig: ed25519.Sign(k.Priv, digest)}.String()
}

// SignPatches signs a revision of ns/name on parent with canonical patches.
func (k Key) SignPatches(origin, ns, name string, parent *ids.ID, canonicalPatches []byte) string {
	return k.Sign(Digest(origin, ns, name, parent, canonicalPatches))
}

// SignTombstone signs a tombstone of ns/name on parent.
func (k Key) SignTombstone(origin, ns, name string, parent ids.ID) string {
	return k.Sign(Digest(origin, ns, name, &parent, nil))
}

// ParseKey parses "kid:seed" with the seed in base64url (32 bytes), the
// form tools take on their command lines and in the environment.
func ParseKey(s string) (Key, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return Key{}, errors.New(`a signing key is "<kid>:<seed>"`)
	}
	seed, err := b64.DecodeString(strings.TrimRight(s[i+1:], "="))
	if err != nil || len(seed) != ed25519.SeedSize {
		return Key{}, errors.New("the seed of a signing key must be 32 bytes in base64url")
	}
	return Key{Kid: s[:i], Priv: ed25519.NewKeyFromSeed(seed)}, nil
}
