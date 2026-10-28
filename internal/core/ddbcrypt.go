package core

// Encryption at rest on DynamoDB (Addendum E.1). The key hierarchy is
// SQL's: the key store wraps a data key per resource of an encrypted
// namespace, and one for the deployment's grants (ddb/crypt.go stores
// them). The row format is too (sealRow), carried in a string attribute
// as ddb.Sealed followed by the rest in base64url; its aad binds a value
// to its namespace, resource, kind and key (the revision id, a document's
// position), as SQL's binds it to a resource row. Core seals what it
// writes (ddb.Commit.Seal and its own puts) and opens what it reads; the
// store opens what it folds itself through Store.Open.
//
// An encrypted resource's blob bytes are its own: stored under a hash
// derived from the owner and the bytes' sha-256 (ownedHash), sealed with
// the owner's key, and named so by the attachments and pending entries
// (ddb.BlobRow.Owner). Bytes a resource takes from another's are copied
// under its own key, as SQL's attachBlob does.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
)

// ddbKeys caches unwrapped data keys by resource ("ns\x00name"; "" for
// the grants key). A purge forgets them.
type ddbKeys struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *ddbKeys) get(id string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[id]
}

func (k *ddbKeys) put(id string, key []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil || len(k.m) >= 4096 {
		k.m = map[string][]byte{}
	}
	k.m[id] = key
}

func (k *ddbKeys) flush() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m = nil
}

// ownerOf names resource name of ns as a data key's owner.
func ownerOf(ns, name string) string { return ns + "\x00" + name }

// ddbDEKAAD binds a wrapped data key to its resource; the grants key's is
// SQL's.
func ddbDEKAAD(ns, name string) []byte {
	if ns == "" {
		return dekAAD(grantsDEK)
	}
	return []byte("patchlog-dek-v1-ddb\x00" + ns + "\x00" + name)
}

// ddbRowAAD binds an encrypted value to its namespace, resource, kind and
// key.
func ddbRowAAD(kind, ns, name, key string) []byte {
	return []byte("patchlog-e1-ddb\x00" + kind + "\x00" + ns + "\x00" + name + "\x00" + key)
}

// dekFor is name's data key in ns (ns "": the grants key), created if
// create is set and there is none. A key that can't be had is a 500, as
// on SQL.
func (b *ddbBackend) dekFor(ctx context.Context, ns, name string, create bool) ([]byte, error) {
	id := ""
	if ns != "" {
		id = ownerOf(ns, name)
	}
	if k := b.keys.get(id); k != nil {
		return k, nil
	}
	ks := b.e.opt.KeyStore
	if ks == nil {
		return nil, errNoKeyStore
	}
	w, err := b.store.DEK(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	aad := ddbDEKAAD(ns, name)
	if w == nil {
		if !create {
			return nil, encUnavailable("the data key of this content is missing (destroyed by a purge?)")
		}
		k := make([]byte, dekSize)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		wrapped, err := ks.Wrap(ctx, k, aad)
		if err != nil {
			return nil, encUnavailable(fmt.Sprintf("wrapping a data key with key store %s: %v", ks.Name(), err))
		}
		if w, err = b.store.PutDEK(ctx, ns, name, ddb.WrappedDEK{Wrapped: wrapped, KeyStore: ks.Name()}, b.e.now().UnixMilli()); err != nil {
			return nil, err
		}
	}
	k, err := ks.Unwrap(ctx, w.Wrapped, aad)
	if err != nil {
		return nil, unwrapErr(ks, w.KeyStore, err)
	}
	b.keys.put(id, k)
	return k, nil
}

// sealValue encrypts a value of name in ns with its data key.
func sealValue(dek []byte, kind, ns, name, key, plain string) string {
	row := sealRow(dek, ddbRowAAD(kind, ns, name, key), []byte(plain))
	return ddb.Sealed + base64.RawURLEncoding.EncodeToString(row[1:])
}

// openValue is Store.Open: a value sealValue encrypted, opened.
func (b *ddbBackend) openValue(ctx context.Context, ns, name, kind, key, raw string) (string, error) {
	if !strings.HasPrefix(raw, ddb.Sealed) {
		return raw, nil
	}
	body, err := base64.RawURLEncoding.DecodeString(raw[len(ddb.Sealed):])
	if err != nil {
		return "", encUnavailable("an encrypted value is malformed")
	}
	dek, err := b.dekFor(ctx, ns, name, false)
	if err != nil {
		return "", err
	}
	plain, err := openRow(dek, ddbRowAAD(kind, ns, name, key), append([]byte{rowVersion}, body...))
	if err != nil {
		return "", encUnavailable(fmt.Sprintf("an encrypted value of %s/%s does not decrypt: %v", ns, name, err))
	}
	return string(plain), nil
}

// sealer is a commit's Seal for ns's resources names, their data keys
// created first: nil if ns isn't encrypted at rest.
func (b *ddbBackend) sealer(ctx context.Context, ns string, level int, names []string) (func(name, kind, key, plain string) string, error) {
	if level < levelAtRest {
		return nil, nil
	}
	keys := map[string][]byte{}
	for _, n := range names {
		k, err := b.dekFor(ctx, ns, n, true)
		if err != nil {
			return nil, err
		}
		keys[n] = k
	}
	return func(name, kind, key, plain string) string {
		return sealValue(keys[name], kind, ns, name, key, plain)
	}, nil
}

// nsLevelOf is ns's encryption level (a shadow's: its branch's), for
// work outside a check.
func (b *ddbBackend) nsLevelOf(ctx context.Context, ns string) (int, error) {
	l := levelNone
	err := b.gateRead(ctx, func(t *gate) error {
		if n := t.nsByName(ns); n != nil {
			l = t.nsLevel(n)
		}
		return nil
	})
	return l, err
}

// ownerFor is whose key encrypts name's blob bytes in ns at level: "" for
// plaintext.
func ownerFor(level int, ns, name string) string {
	if level < levelAtRest {
		return ""
	}
	return ownerOf(ns, name)
}

// ownedHash is where an encrypted resource keeps bytes of sha-256 hash.
func ownedHash(owner string, hash []byte) []byte {
	h := sha256.Sum256(append([]byte("patchlog-ddb-bytes\x00"+owner+"\x00"), hash...))
	return h[:]
}

// putOwnedBytes stores data, of sha-256 hash, as owner's ("" plaintext)
// and returns the hash that names them.
func (b *ddbBackend) putOwnedBytes(ctx context.Context, owner string, hash, data []byte) ([]byte, error) {
	if owner == "" {
		return hash, b.putBytes(ctx, hash, data)
	}
	ns, name, _ := strings.Cut(owner, "\x00")
	dek, err := b.dekFor(ctx, ns, name, true)
	if err != nil {
		return nil, err
	}
	key := ownedHash(owner, hash)
	h := hex.EncodeToString(key)
	return key, b.putFile(ctx, "r/"+h[:2]+"/"+h, key, sealRow(dek, ddbRowAAD("bytes", ns, name, string(key)), data))
}

// openOwned opens bytes owner's key encrypted.
func (b *ddbBackend) openOwned(ctx context.Context, owner string, key, data []byte) ([]byte, error) {
	ns, name, _ := strings.Cut(owner, "\x00")
	dek, err := b.dekFor(ctx, ns, name, false)
	if err != nil {
		return nil, err
	}
	plain, err := openRow(dek, ddbRowAAD("bytes", ns, name, string(key)), data)
	if err != nil {
		return nil, encUnavailable(fmt.Sprintf("blob bytes of %s/%s do not decrypt: %v", ns, name, err))
	}
	return plain, nil
}

// archiveDEK is sqlArchiveDEK on the table.
func (b *ddbBackend) archiveDEK(ctx context.Context, ns, name string) ([]byte, error) {
	n, err := b.store.Namespace(ctx, ns)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if n == nil || n.Purged {
		return nil, ErrArchiveKeyDestroyed
	}
	rr, err := b.store.Resource(ctx, ns, name)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	if rr == nil || rr.Purged {
		return nil, ErrArchiveKeyDestroyed
	}
	if lvl, err := b.nsLevelOf(ctx, ns); err != nil {
		return nil, err
	} else if lvl < levelAtRest {
		return nil, ErrNotEncrypted
	}
	if b.e.opt.KeyStore == nil {
		return nil, errNoKeyStore
	}
	if w, err := b.store.DEK(ctx, ns, name); err != nil || w == nil {
		if err == nil {
			err = ErrArchiveKeyDestroyed
		}
		return nil, err
	}
	return b.dekFor(ctx, ns, name, false)
}

// checkKeyStore is checkKeyStore of crypt.go on the table: with a key
// store, one stored data key must unwrap.
func (b *ddbBackend) checkKeyStore(ctx context.Context) error {
	ks := b.e.opt.KeyStore
	if ks == nil {
		return nil
	}
	ns, name, w, err := b.store.AnyDEK(ctx)
	if err != nil || w == nil {
		return err
	}
	if _, err := ks.Unwrap(ctx, w.Wrapped, ddbDEKAAD(ns, name)); err != nil {
		return fmt.Errorf("encryption at rest: %s", unwrapErr(ks, w.KeyStore, err).Body["message"])
	}
	return nil
}

// encryptNamespace encrypts ns's content that is still plaintext after a
// config change raised it to encryption at rest (encryptNamespace of
// crypt.go), its remote shadows' too, and the grants its entries were
// written under; then the marker the commit wrote. It is idempotent: the
// sweep finishes one interrupted.
func (b *ddbBackend) encryptNamespace(ctx context.Context, ns string) error {
	for _, x := range append([]string{ns}, b.shadowsOf(ctx, ns)...) {
		x := x
		seal := func(name, kind, key, plain string) (string, error) {
			dek, err := b.dekFor(ctx, x, name, true)
			if err != nil {
				return "", err
			}
			return sealValue(dek, kind, x, name, key, plain), nil
		}
		reown := func(bl *ddb.BlobRow) ([]byte, string, error) {
			data, file, ok, err := b.store.Bytes(ctx, bl.Hash)
			if err != nil || !ok {
				if err == nil {
					err = fmt.Errorf("blob bytes %x are missing", bl.Hash)
				}
				return nil, "", err
			}
			if file != "" {
				f, err := b.e.blobs.open(file)
				if err != nil {
					return nil, "", err
				}
				data, err = io.ReadAll(f)
				f.Close()
				if err != nil {
					return nil, "", err
				}
			}
			owner := ownerOf(x, bl.Name)
			key, err := b.putOwnedBytes(ctx, owner, bl.Hash, data)
			return key, owner, err
		}
		grants, err := b.store.EncryptContent(ctx, x, seal, reown)
		if err != nil {
			return err
		}
		for _, gid := range grants {
			g, err := b.store.Grant(ctx, gid)
			if err != nil {
				return err
			}
			if g == nil || isSealed(string(g.Blocks)) {
				continue
			}
			id, err := ids.Parse(gid)
			if err != nil {
				continue
			}
			dek, err := b.dekFor(ctx, "", "", true)
			if err != nil {
				return err
			}
			g.Blocks = sealRow(dek, grantAAD(id[:]), g.Blocks)
			if err := b.store.PutGrant(ctx, gid, *g, true); err != nil {
				return err
			}
			b.grantsSealed.add(gid)
		}
	}
	return b.store.DoneEncrypting(ctx, ns)
}

// encrypted runs encryptNamespace after the commit that raised ns's
// level; what fails is left to the sweep.
func (b *ddbBackend) encrypted(ctx context.Context, ns string) {
	if err := b.encryptNamespace(ctx, ns); err != nil {
		log.Printf("ddb: %s raised to encryption at rest, its content left to the sweep: %v", ns, err)
	}
}
