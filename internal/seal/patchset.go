package seal

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// OpSealed is the reserved op of an E3 sealed patch set (§6.2, §E.3.1).
const OpSealed = "sealed"

// SealPatchSet encrypts patches (a jsonv model value, normally []any of
// RFC 6902 ops) as canonical JSON under key with pl {ns, name, parent} and
// returns the canonical JSON of the one-element patch set
// [{"op":"sealed","value":"<JWE>"}]. parent is "" for genesis.
//
// The caller MUST keep the returned bytes until the write is acknowledged:
// the IV is random, so re-sealing gives another id (§E.3.1).
func SealPatchSet(key []byte, kid, ns, name, parent string, patches any) ([]byte, error) {
	return SealPatchSetPad(key, kid, ns, name, parent, patches, false)
}

// SealedJWE reports whether patchSet (a model value or JSON text) is exactly
// one sealed op with a string value, and no other members than an optional
// declared blob list (SealedOp), and returns the JWE.
func SealedJWE(patchSet any) (string, bool) {
	jwe, _, ok := SealedOp(patchSet)
	return jwe, ok
}

// SealedOp parses a sealed patch set (a model value or JSON text): one
// sealed op, {"op": "sealed", "value": "<JWE>", "blobs"?: [ids]}. It
// returns the JWE and the declared blob list (§E.3.1), nil when the op has
// no "blobs" member. ok is false for anything else, including a "blobs"
// that isn't an array of strings; whether those are blob ids is the
// caller's to check.
func SealedOp(patchSet any) (jwe string, blobs []string, ok bool) {
	if b, isBytes := patchSet.([]byte); isBytes {
		p, err := jsonv.Parse(b)
		if err != nil {
			return "", nil, false
		}
		patchSet = p
	}
	arr, isArr := patchSet.([]any)
	if !isArr || len(arr) != 1 {
		return "", nil, false
	}
	op, isObj := arr[0].(map[string]any)
	if !isObj || op["op"] != OpSealed {
		return "", nil, false
	}
	s, _ := op["value"].(string)
	if s == "" {
		return "", nil, false
	}
	switch len(op) {
	case 2:
	case 3:
		list, isList := op["blobs"].([]any)
		if !isList {
			return "", nil, false
		}
		blobs = make([]string, len(list))
		for i, x := range list {
			if blobs[i], isList = x.(string); !isList {
				return "", nil, false
			}
		}
	default:
		return "", nil, false
	}
	return s, blobs, true
}

// WithBlobs returns the sealed patch set sealed (canonical JSON of one
// sealed op, as SealPatchSet returns it) with its declared blob list set to
// blobs (§E.3.1), or without one when blobs is empty.
func WithBlobs(sealed []byte, blobs []string) ([]byte, error) {
	jwe, _, ok := SealedOp(sealed)
	if !ok {
		return nil, fmt.Errorf("%w: not a sealed patch set", ErrFormat)
	}
	op := map[string]any{"op": OpSealed, "value": jwe}
	if len(blobs) > 0 {
		list := make([]any, len(blobs))
		for i, b := range blobs {
			list[i] = b
		}
		op["blobs"] = list
	}
	return jsonv.Canonical([]any{op}), nil
}

// OpenPatchSet decrypts a sealed patch set (model value or JSON text),
// verifying that it is bound to kid and {ns, name, parent}, and returns the
// plaintext patches as a model value.
func OpenPatchSet(patchSet any, key []byte, kid, ns, name, parent string) (any, error) {
	v, _, err := OpenPatchSetPadded(patchSet, key, kid, ns, name, parent)
	return v, err
}

// OpenPatchSetPadded is OpenPatchSet that also reports whether the
// plaintext was padded to its bucket (IsPadded), for readers of a
// namespace with "pad" (§E.3.1).
func OpenPatchSetPadded(patchSet any, key []byte, kid, ns, name, parent string) (any, bool, error) {
	jwe, ok := SealedJWE(patchSet)
	if !ok {
		return nil, false, fmt.Errorf("%w: not a sealed patch set", ErrFormat)
	}
	h, pt, err := Open(jwe, key)
	if err != nil {
		return nil, false, err
	}
	if err := h.Expect(kid, PatchSetPL(ns, name, parent)); err != nil {
		return nil, false, err
	}
	v, err := jsonv.Parse(pt)
	if err != nil {
		return nil, false, fmt.Errorf("%w: patches: %v", ErrFormat, err)
	}
	return v, IsPadded(h, pt), nil
}

// SealSnapshot seals an E3 prune snapshot (§8.6): the document doc of
// revision id, as canonical JSON, with pl {ns, name, id, kind: "snapshot"}.
func SealSnapshot(key []byte, kid, ns, name, id string, doc any) (string, error) {
	return SealSnapshotPad(key, kid, ns, name, id, doc, false)
}

// OpenSnapshot decrypts a prune snapshot bound to kid and {ns, name, id}.
func OpenSnapshot(jwe string, key []byte, kid, ns, name, id string) (any, error) {
	pt, err := OpenExpect(jwe, key, kid, SnapshotPL(ns, name, id))
	if err != nil {
		return nil, err
	}
	v, err := jsonv.Parse(pt)
	if err != nil {
		return nil, fmt.Errorf("%w: snapshot: %v", ErrFormat, err)
	}
	return v, nil
}

// ---- $nonce (§C.7, §E.2.5) ----

// NoncePath is the pointer of the nonce member.
const NoncePath = "/$nonce"

var nonceEnc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewNonce returns 128 fresh random bits as 26 lowercase base32 characters.
func NewNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return nonceEnc.EncodeToString(b)
}

// ValidNonce reports whether s matches ^[a-z2-7]{26}$.
func ValidNonce(s string) bool {
	if len(s) != 26 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// HasFreshNonce reports whether patches (a model value or JSON text of an
// RFC 6902 patch set) sets /$nonce to a fresh-looking nonce: some op is an
// `add` or `replace` of exactly "/$nonce" with a string matching
// ^[a-z2-7]{26}$, and it is the last op touching /$nonce or anything below
// it (as path, or as `from` of a move; `test` ops are ignored), so a later op can't undo it. Used by
// the gate for sealed namespaces.
func HasFreshNonce(patches any) bool {
	if b, ok := patches.([]byte); ok {
		p, err := jsonv.Parse(b)
		if err != nil {
			return false
		}
		patches = p
	}
	arr, ok := patches.([]any)
	if !ok {
		return false
	}
	touches := func(p any) bool {
		s, ok := p.(string)
		return ok && (s == NoncePath || strings.HasPrefix(s, NoncePath+"/"))
	}
	fresh := false
	for _, e := range arr {
		op, ok := e.(map[string]any)
		if !ok {
			return false
		}
		name, _ := op["op"].(string)
		if name == "test" {
			continue
		}
		if touches(op["path"]) {
			v, _ := op["value"].(string)
			fresh = (name == "add" || name == "replace") && op["path"] == NoncePath && ValidNonce(v)
		} else if name == "move" && touches(op["from"]) {
			fresh = false
		}
	}
	return fresh
}
