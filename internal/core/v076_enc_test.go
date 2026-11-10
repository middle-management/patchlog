package core

import (
	"context"
	"crypto/ecdh"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// §G.5.2 E3 sources (v0.76): a remote branch's deeper shadow, one below
// its first, is readable for its keys only while the follower's latest
// read of its current namespace document succeeded (remote_chain_read):
// not before the first success, not after a failure; the first shadow, and
// any namespace that isn't a shadow, always are. On SQLite and, with
// PATCHLOG_TEST_PG, on Postgres.
func TestV076EncChainReadable(t *testing.T) {
	t.Parallel()
	e := openBlobEngine(t)
	ctx := context.Background()
	var first, deeper, branch int64
	if err := e.update(ctx, func(t *tx) error {
		deeper = t.mustInsert(`INSERT INTO namespaces (name) VALUES ('~v076-1') RETURNING ns`)
		first = t.mustInsert(`INSERT INTO namespaces (name, base) VALUES ('~v076-0', ?) RETURNING ns`, deeper)
		branch = t.mustInsert(`INSERT INTO namespaces (name, base) VALUES ('v076', ?) RETURNING ns`, first)
		_, err := t.Exec(`INSERT INTO remote_bases (shadow, branch, origin, ns, at, checkpoint) VALUES (?,?,?,?,?,?)`, first, branch, "https://a.example", "eb", "x", "x")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	readable := func() (f, d, b bool) {
		if err := e.read(ctx, func(t *tx) error {
			f, d, b = t.chainReadable(t.nsByID(first)), t.chainReadable(t.nsByID(deeper)), t.chainReadable(t.nsByID(branch))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	mark := func(ok bool) {
		if err := e.update(ctx, func(t *tx) error { t.chainRead(deeper, ok); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		what string
		mark func()
		want bool
	}{
		{"before any read", func() {}, false},
		{"after a successful read", func() { mark(true) }, true},
		{"after a failed read", func() { mark(false) }, false},
		{"after a successful read again", func() { mark(true) }, true},
	} {
		c.mark()
		f, d, b := readable()
		if !f || !b || d != c.want {
			t.Fatalf("%s: first %v, deeper %v, branch %v; want true, %v, true", c.what, f, d, b, c.want)
		}
	}
}

// §E.3.2, §C.7 (v0.76): a keyring's $nonce is of the fresh form. v0.78
// keeps no compatibility with one stored before v0.76, when the gate took
// a $nonce of any form, or mirrored from such a remote base: /keys relays
// none of its entries (keyringEntries, E2E-10), failing closed until a key
// holder wraps it again.
func TestV076EncStoredKeyringNonceRelayed(t *testing.T) {
	_, admin, _ := seal.GenerateRecipient()
	_, reader, _ := seal.GenerateRecipient()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, seal.NewKey(), []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]int{seal.NewNonce(): 1, "x": 0, "": 0} {
		d := kr.Value()
		d["$nonce"] = n
		if got := keyringEntries(d, reader.PublicKey(), []int{1}); len(got) != want {
			t.Fatalf("stored keyring with $nonce %q: relayed %v, want %d entries", n, got, want)
		}
	}
}
