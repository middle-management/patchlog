package core

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"io"
	"testing"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// P34, CIS-34 (§8.6, §G.5.1.1): a resource's archive key is derived from
// its data key, one way and per key: a fixed data key gives a fixed key
// pair, which another data key doesn't.
func TestV073ArchiveIdentityDerivation(t *testing.T) {
	t.Parallel()
	dek := make([]byte, dekSize)
	for i := range dek {
		dek[i] = byte(i)
	}
	id := archiveIdentity(dek)
	if got := seal.Thumbprint(id.PublicKey()); got != "im_d7GrwWBLzFVLpj7w4J6XIO_NA9mekuA717dd-XZA" {
		t.Fatalf("thumbprint of the archive key of 00…1f: %s", got)
	}
	if !id.Equal(archiveIdentity(dek)) {
		t.Fatal("the derivation isn't deterministic")
	}
	dek[0] ^= 1
	if id.Equal(archiveIdentity(dek)) {
		t.Fatal("two data keys give one archive key")
	}
}

// P34, CIS-34 (§8.6): Engine.ReadArchive reads the three forms an archive
// can have: a plain bundle as it is; a sealed bundle (§G.5.1.1) to the
// resource's archive key, as the archiver writes it now; and the
// chunked "PLAR" format encrypted archives had before v0.73, which stays
// readable. A sealed bundle to another key is ErrNotRecipient, and
// ArchiveReader reads the keys before it is called, so it needs no
// transaction of its own.
func TestV073ReadArchiveForms(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Limits: lim, Purger: discardPurger{}, KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	mkNS(t, e, "enc", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	mkNS(t, e, "plain", map[string]any{"read": "public"})
	for _, ns := range []string{"enc", "plain"} {
		if _, err := put(e, ns, "a", "", 1); err != nil {
			t.Fatal(err)
		}
	}
	bundleBytes := []byte(`{"authors":true,"bundle":1}` + "\n" + `{"a":1}` + "\n")
	var dek []byte
	var sealed bytes.Buffer
	if err := e.update(ctx, func(t2 *tx) error {
		n := t2.nsByName("enc")
		own := t2.resource(n.id, "a")
		dek = t2.dek(own.id, false)
		sw, err := t2.archiveBundleSealer(n, own.id)(&sealed)
		if err != nil {
			return err
		}
		if _, err := sw.Write(bundleBytes); err != nil {
			return err
		}
		if pn := t2.nsByName("plain"); t2.archiveBundleSealer(pn, t2.resource(pn.id, "a").id) != nil {
			t.Error("a sealer for a namespace without encryption")
		}
		return sw.Close()
	}); err != nil {
		t.Fatal(err)
	}
	var legacy bytes.Buffer
	lw, err := sealArchive(&legacy, dek)
	if err != nil {
		t.Fatal(err)
	}
	lw.Write(bundleBytes)
	lw.Close()
	_, eve, _ := seal.GenerateRecipient()
	var other bytes.Buffer
	ow, _ := seal.NewBundleWriter(&other, []*ecdh.PublicKey{eve.PublicKey()})
	ow.Write(bundleBytes)
	ow.Close()

	read := func(ns string, b []byte) ([]byte, error) {
		r, err := e.ReadArchive(ctx, ns, "a", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	}
	for name, c := range map[string]struct {
		ns string
		b  []byte
	}{
		"plain bundle":            {"plain", bundleBytes},
		"plain bundle, encrypted": {"enc", bundleBytes},
		"sealed bundle":           {"enc", sealed.Bytes()},
		"legacy chunked (PLAR)":   {"enc", legacy.Bytes()},
	} {
		got, err := read(c.ns, c.b)
		if err != nil || !bytes.Equal(got, bundleBytes) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if !bytes.HasPrefix(sealed.Bytes(), []byte(`{"id":`)) || bytes.Contains(sealed.Bytes(), []byte(`{"a":1}`)) {
		t.Fatal("the sealer's output isn't a sealed bundle")
	}
	if _, err := read("enc", other.Bytes()); !errors.Is(err, seal.ErrNotRecipient) {
		t.Fatalf("a sealed bundle to another key: %v", err)
	}
	// Encrypted archives where the namespace isn't encrypted.
	for _, b := range [][]byte{sealed.Bytes(), legacy.Bytes()} {
		if _, err := read("plain", b); err == nil {
			t.Fatal("an encrypted archive of a namespace without encryption was read")
		}
	}
	// ArchiveReader's function reads inside a write transaction (a
	// restore's), on a database with one connection too.
	open := e.ArchiveReader(ctx, "enc", "a")
	if err := e.update(ctx, func(*tx) error {
		r, err := open(bytes.NewReader(sealed.Bytes()))
		if err != nil {
			return err
		}
		got, err := io.ReadAll(r)
		if err == nil && !bytes.Equal(got, bundleBytes) {
			err = errors.New("wrong bundle")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
