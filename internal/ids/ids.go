// Package ids implements content-addressed identifiers (§3.2–§3.5).
package ids

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
)

// Size is the binary length of an id.
const Size = 20

// ID is the binary form of an id. The zero value is not a valid id; use
// *ID or a separate flag for "no parent".
type ID [Size]byte

var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// String is the 33-character text form: "1" + base32lower(bytes).
func (id ID) String() string { return "1" + enc.EncodeToString(id[:]) }

// ErrFormat reports a malformed text id.
var ErrFormat = errors.New("malformed id")

// Parse parses the text form.
func Parse(s string) (ID, error) {
	var id ID
	if len(s) != 33 || s[0] != '1' {
		return id, ErrFormat
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return id, ErrFormat
		}
	}
	b, err := enc.DecodeString(s[1:])
	if err != nil || len(b) != Size {
		return id, ErrFormat
	}
	copy(id[:], b)
	// Reject non-canonical encodings (non-zero trailing bits).
	if id.String() != s {
		return ID{}, ErrFormat
	}
	return id, nil
}

// FromBytes converts a stored 20-byte slice.
func FromBytes(b []byte) ID {
	var id ID
	copy(id[:], b)
	return id
}

// Hash computes trunc160(sha256(parent ‖ 0x0A ‖ body)). parent is nil for
// the first entry of a chain.
func Hash(parent *ID, body []byte) ID {
	h := sha256.New()
	if parent != nil {
		h.Write(parent[:])
	}
	h.Write([]byte{0x0A})
	h.Write(body)
	var id ID
	copy(id[:], h.Sum(nil))
	return id
}

// Revision is the revision id of §3.3 over canonical patches.
func Revision(parent *ID, canonicalPatches []byte) ID { return Hash(parent, canonicalPatches) }

// Tombstone is the tombstone id of §3.4.
func Tombstone(parent ID) ID { return Hash(&parent, []byte("tombstone")) }

// Of is trunc160(sha256(b)), used for grant ids and revocation ids.
func Of(b []byte) ID {
	sum := sha256.Sum256(b)
	var id ID
	copy(id[:], sum[:Size])
	return id
}
