package core

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"

	"github.com/middle-management/patchlog/internal/seal"
)

// Encrypted archives (§8.6 in encrypted namespaces, §G.5.1.1). Each
// resource's archive is a sealed bundle whose only recipient is the
// resource's archive key, an X25519 key pair the server holds for that
// resource only:
//
//	d   = HKDF-SHA256(secret = the resource's DEK, salt = none, info = "patchlog-archive-key-v1"), 32 bytes
//	key = the X25519 private key d; kid = its thumbprint (§E.2.3)
//
// So the key is held as the data key is, wrapped by the key store, and a
// purge, which destroys the data key (deleteDEKs), destroys it too (§E.1):
// copies of the archive that survive can't be read. The bundle's lines are
// padded (§E.2.2) when the namespace pads its sealed payloads. Their lines
// are written and read back without seal's line bound (MaxBundleLine), as
// a plain bundle's are: a pruned attachment is one blob line, and one that
// -max-blob-size allows can be longer sealed than that bound, which would
// leave the archive, the only copy of the pruned bytes, unreadable.
// Archives written before v0.73 are in a chunked AES-256-GCM format of
// their own ("PLAR", crypt.go), which Engine.ReadArchive still reads.

// archiveKeyInfo is the HKDF info of a resource's archive key.
const archiveKeyInfo = "patchlog-archive-key-v1"

// archiveIdentity derives a resource's archive key from its data key.
func archiveIdentity(dek []byte) *ecdh.PrivateKey {
	d, err := hkdf.Key(sha256.New, dek, nil, archiveKeyInfo, 32)
	if err != nil {
		panic(err)
	}
	k, err := ecdh.X25519().NewPrivateKey(d)
	if err != nil {
		panic(err)
	}
	return k
}

// archiveBundleSealer returns the Seal function of an archive of res, a
// resource of n: a sealed bundle to res's archive key (§8.6, §G.5.1.1).
// nil if res is not encrypted, whose archives are plain bundles.
func (t *tx) archiveBundleSealer(n *nsRow, res int64) func(io.Writer) (io.WriteCloser, error) {
	if t.resLevel(res) < levelAtRest {
		return nil
	}
	pub := archiveIdentity(t.dek(res, true)).PublicKey()
	pad := t.config(n.configSeq).Pad
	return func(w io.Writer) (io.WriteCloser, error) {
		sw, err := seal.NewBundleWriter(w, []*ecdh.PublicKey{pub})
		if err != nil {
			return nil, err
		}
		sw.Pad = pad
		sw.MaxLine = -1 // read back without a bound (Engine.ArchiveReader)
		return sw, nil
	}
}

// ErrNotEncrypted is returned by ArchiveIdentity for a resource whose
// namespace isn't encrypted: its archives are plain bundles.
var ErrNotEncrypted = errors.New("the resource's namespace isn't encrypted; its archives are plain bundles")

// ArchiveIdentity returns the archive key of ns/name (§8.6): the only
// recipient of the sealed bundles its archives are in an encrypted
// namespace, with which bundle tools can open them too (seal.OpenBundle,
// bundle.Unseal; an archive with a line longer than seal.MaxBundleLine,
// the blob line of an attachment over about 144 MiB, or 128 MiB padded,
// opens with seal.OpenBundleMax and no bound, as Engine.ReadArchive opens
// it). It needs the key store. An unpurged resource whose data key is
// gone, or a purged one, is ErrArchiveKeyDestroyed (§8.3, §E.1);
// one outside encrypted namespaces is ErrNotEncrypted.
func (e *Engine) ArchiveIdentity(ctx context.Context, ns, name string) (*ecdh.PrivateKey, error) {
	dek, err := e.archiveDEK(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	return archiveIdentity(dek), nil
}

// archiveDEK reads the data key that ns/name's encrypted archives are
// opened with, in a read transaction of its own; the errors are
// ArchiveIdentity's.
func (e *Engine) archiveDEK(ctx context.Context, ns, name string) ([]byte, error) {
	var dek []byte
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return ErrArchiveKeyDestroyed
		}
		own := t.resource(n.id, name)
		if n.purged || own == nil || own.state == statePurged {
			return ErrArchiveKeyDestroyed
		}
		if t.resLevel(own.id) < levelAtRest {
			return ErrNotEncrypted
		}
		if t.e.opt.KeyStore == nil {
			return errNoKeyStore
		}
		k, err := t.loadDEK(own.id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrArchiveKeyDestroyed
		}
		dek = k
		return err
	})
	if err != nil {
		return nil, err
	}
	return dek, nil
}
