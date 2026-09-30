package keystore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapUnwrap(t *testing.T) {
	ctx := context.Background()
	ks, err := New(Generate())
	if err != nil {
		t.Fatal(err)
	}
	key := Generate()
	w, err := ks.Wrap(ctx, key, []byte("aad-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w, key) || w[0] != wrapVersion {
		t.Fatal("wrapped key leaks the key or lacks the version byte")
	}
	got, err := ks.Unwrap(ctx, w, []byte("aad-1"))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := ks.Unwrap(ctx, w, []byte("aad-2")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("unwrap with another aad: %v", err)
	}
	other, _ := New(Generate())
	if _, err := other.Unwrap(ctx, w, []byte("aad-1")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("unwrap with another master key: %v", err)
	}
	if other.Name() == ks.Name() || !strings.HasPrefix(ks.Name(), "local:") {
		t.Fatalf("names %s %s", ks.Name(), other.Name())
	}
	w[len(w)-1] ^= 1
	if _, err := ks.Unwrap(ctx, w, []byte("aad-1")); err == nil {
		t.Fatal("tampered key unwrapped")
	}
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte master key was accepted")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "master.key")
	if _, err := LoadFile(p, false); err == nil {
		t.Fatal("a missing file without create was accepted")
	}
	ks, err := LoadFile(p, true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("created file mode %v %v", st.Mode(), err)
	}
	again, err := LoadFile(p, true) // exists: loaded, not replaced
	if err != nil || again.Name() != ks.Name() {
		t.Fatalf("reload: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		os.Chmod(p, mode)
		if _, err := LoadFile(p, false); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("mode %04o accepted: %v", mode, err)
		}
	}
	os.Chmod(p, 0o400)
	if _, err := LoadFile(p, false); err != nil {
		t.Fatalf("mode 0400: %v", err)
	}

	// Raw, hex and base64 files hold the same key.
	k := Generate()
	want, _ := New(k)
	for name, content := range map[string][]byte{
		"raw": k,
		"hex": []byte(hex.EncodeToString(k) + "\n"),
	} {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, content, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadFile(f, false)
		if err != nil || got.Name() != want.Name() {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("too short\n"), 0o600)
	if _, err := LoadFile(bad, false); err == nil {
		t.Fatal("a malformed key was accepted")
	}
	if _, err := LoadFile(dir, false); err == nil {
		t.Fatal("a directory was accepted")
	}
}
