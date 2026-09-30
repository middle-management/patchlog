// Package keystore holds the key-encryption key (KEK) of encryption at rest
// (Addendum E.1) and wraps the core's data keys with it. Local keeps the
// master key in a file on the origin; adapters for a key management service
// implement the same core.KeyStore interface.
//
// # Master key file
//
// A master key file holds 32 random bytes, either raw or as base64 (standard
// or URL alphabet, padded or not) or hex text, optionally followed by a
// newline. The file must not be accessible by group or others (mode 0600 or
// stricter); LoadFile refuses it otherwise. LoadFile with create set writes a
// new random key, base64-encoded, with mode 0600 if the file doesn't exist.
//
// # Wrapped keys
//
// A wrapped key is 1 version byte (0x01) ‖ 12-byte random nonce ‖
// AES-256-GCM(KEK, nonce, key, aad), where aad is the caller's (the core
// binds each data key to its scope).
package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
)

// KeySize is the size of the master key and of the keys it wraps.
const KeySize = 32

const wrapVersion = 0x01

// Local wraps keys with a master key held in memory.
type Local struct {
	aead cipher.AEAD
	name string
}

// New returns a Local key store for a 32-byte master key.
func New(kek []byte) (*Local, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("the master key must be %d bytes, not %d", KeySize, len(kek))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The name identifies the master key without revealing it, so a data
	// key wrapped under another master key is reported clearly.
	h := sha256.Sum256(append([]byte("patchlog-kek-id\x00"), kek...))
	return &Local{aead: aead, name: "local:" + hex.EncodeToString(h[:8])}, nil
}

// Generate returns a new random master key.
func Generate() []byte {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// LoadFile loads the master key from path. With create, a missing file is
// created with a new random key and mode 0600. A file readable or writable
// by group or others is refused.
func LoadFile(path string, create bool) (*Local, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) && create {
		k := Generate()
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("creating master key file: %w", err)
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(k) + "\n"); err != nil {
			f.Close()
			os.Remove(path)
			return nil, fmt.Errorf("writing master key file: %w", err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		return New(k)
	}
	if err != nil {
		return nil, fmt.Errorf("master key file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("master key file %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("master key file %s has mode %04o; it must not be accessible by group or others (chmod 600)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("master key file: %w", err)
	}
	k, err := parseKey(b)
	if err != nil {
		return nil, fmt.Errorf("master key file %s: %w", path, err)
	}
	return New(k)
}

func parseKey(b []byte) ([]byte, error) {
	if len(b) == KeySize {
		return b, nil
	}
	s := strings.TrimSpace(string(b))
	if k, err := hex.DecodeString(s); err == nil && len(k) == KeySize {
		return k, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == KeySize {
			return k, nil
		}
	}
	return nil, fmt.Errorf("want %d bytes, raw, hex or base64", KeySize)
}

// Name identifies the master key (a hash prefix, not the key).
func (l *Local) Name() string { return l.name }

// Wrap encrypts key under the master key, bound to aad.
func (l *Local) Wrap(_ context.Context, key, aad []byte) ([]byte, error) {
	out := make([]byte, 1+l.aead.NonceSize(), 1+l.aead.NonceSize()+len(key)+l.aead.Overhead())
	out[0] = wrapVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return l.aead.Seal(out, out[1:], key, aad), nil
}

// ErrUnwrap is returned for a wrapped key that doesn't open under this master
// key and aad: another master key wrapped it, or it was tampered with.
var ErrUnwrap = errors.New("the key does not unwrap under this master key")

// Unwrap decrypts a key Wrap returned.
func (l *Local) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	ns := l.aead.NonceSize()
	if len(wrapped) < 1+ns+l.aead.Overhead() || wrapped[0] != wrapVersion {
		return nil, errors.New("malformed wrapped key")
	}
	k, err := l.aead.Open(nil, wrapped[1:1+ns], wrapped[1+ns:], aad)
	if err != nil {
		return nil, ErrUnwrap
	}
	return k, nil
}
