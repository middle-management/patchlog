package core

// Encryption at rest (Addendum E.1).
//
// Key hierarchy. A KeyStore (Options.KeyStore; internal/keystore for a local
// master key, a KMS adapter later) holds the key-encryption key. It wraps
// data keys (DEKs, 32 random bytes), stored in the deks table:
//
//   - one per resource row (deks.res = resources.res) of a namespace whose
//     encryption.level is at-rest or higher, created at its first encrypted
//     write. A branch's own rows, and a remote branch's shadow rows, have
//     their own resource rows and so their own keys; read-through decrypts a
//     base's rows with the base's keys.
//   - one for the whole deployment (deks.res = 0), for grants.blocks: a
//     grant is stored once, however many namespaces it is used in.
//
// A DEK is wrapped with aad "patchlog-dek-v1" 0x00 ‖ be64(res), so a
// wrapped key can't be moved to another resource. Purging a resource, or a
// namespace, deletes its DEKs (cryptographic purge, §E.1): its rows, and any
// archive or backup of them, can no longer be decrypted.
//
// Row format. An encrypted value of revisions.patches, heads.doc,
// snapshots.doc or grants.blocks is stored as a BLOB:
//
//	0x01 ‖ nonce (12 random bytes) ‖ AES-256-GCM(DEK, nonce, plaintext, aad)
//
// with aad = "patchlog-e1" 0x00 ‖ table ‖ 0x00 ‖ be64(res) ‖ key, where key is
// the revision id for revisions, be64(seq) for heads and snapshots, and the
// grant id for grants (res 0). Plaintext values stay canonical JSON TEXT,
// which never starts with 0x01, so the version byte tells the two apart and
// reads handle a mix (a namespace being encrypted, rows restored from an
// archive). Ids are computed over the plaintext canonical patches as always.
// The in-memory document cache keeps plaintext: the origin is trusted.

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/middle-management/patchlog/internal/ids"
)

// KeyStore wraps and unwraps data keys with a key-encryption key it holds
// (Addendum E.1). internal/keystore has a local implementation.
type KeyStore interface {
	// Name identifies the key-encryption key (not secret). It is stored
	// with every wrapped key, so a mismatch is reported clearly.
	Name() string
	// Wrap encrypts key, bound to aad.
	Wrap(ctx context.Context, key, aad []byte) ([]byte, error)
	// Unwrap decrypts a wrapped key; it fails if aad differs.
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// Encryption levels, in order (Addendum E).
const (
	levelNone = iota
	levelAtRest
	levelSealed
	levelE2E
)

var levelNames = []string{"", "at-rest", "sealed", "e2e"}

func levelOf(s string) int {
	for i, n := range levelNames {
		if n == s {
			return i
		}
	}
	return levelNone
}

const (
	rowVersion = 0x01
	dekSize    = 32
	grantsDEK  = 0 // deks.res of the deployment key for grants
)

func encUnavailable(msg string, kv ...any) *Error {
	return apiErr(500, "encryption_unavailable", append([]any{"message", msg}, kv...)...)
}

var errNoKeyStore = encUnavailable("this data is encrypted at rest and the server has no key store configured")

// dekCache keeps unwrapped data keys.
type dekCache struct {
	mu  sync.Mutex
	max int
	m   map[int64][]byte
}

func newDEKCache(max int) *dekCache { return &dekCache{max: max, m: map[int64][]byte{}} }

func (c *dekCache) get(res int64) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[res]
}

func (c *dekCache) put(res int64, k []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for r := range c.m {
			delete(c.m, r)
			if len(c.m) < c.max*3/4 {
				break
			}
		}
	}
	c.m[res] = k
}

func (c *dekCache) flush() {
	c.mu.Lock()
	c.m = map[int64][]byte{}
	c.mu.Unlock()
}

func be64(n int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return b[:]
}

func dekAAD(res int64) []byte { return append([]byte("patchlog-dek-v1\x00"), be64(res)...) }

func rowAAD(table string, res int64, key []byte) []byte {
	b := make([]byte, 0, 32+len(table)+len(key))
	b = append(b, "patchlog-e1\x00"...)
	b = append(b, table...)
	b = append(b, 0)
	b = append(b, be64(res)...)
	return append(b, key...)
}

func revAAD(res int64, id ids.ID) []byte         { return rowAAD("revisions", res, id[:]) }
func docAAD(table string, res, seq int64) []byte { return rowAAD(table, res, be64(seq)) }
func grantAAD(id []byte) []byte                  { return rowAAD("grants", grantsDEK, id) }

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// sealRow encrypts a stored value (row format above).
func sealRow(dek, aad, plain []byte) []byte {
	aead := newGCM(dek)
	out := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(plain)+aead.Overhead())
	out[0] = rowVersion
	if _, err := rand.Read(out[1:]); err != nil {
		panic(err)
	}
	return aead.Seal(out, out[1:], plain, aad)
}

func openRow(dek, aad, row []byte) ([]byte, error) {
	aead := newGCM(dek)
	n := aead.NonceSize()
	if len(row) < 1+n+aead.Overhead() || row[0] != rowVersion {
		return nil, errors.New("malformed encrypted row")
	}
	return aead.Open(nil, row[1:1+n], row[1+n:], aad)
}

// isSealed tells an encrypted stored value from plaintext canonical JSON.
func isSealed(b string) bool { return len(b) > 0 && b[0] == rowVersion }

// --- levels -----------------------------------------------------------------

// nsLevel is a namespace's encryption level. A remote branch's shadow
// (§G.3) follows its branch.
func (t *tx) nsLevel(n *nsRow) int {
	if n.isShadow() {
		if l, ok := t.shadowLevels[n.name]; ok {
			return l
		}
		var cfg sql.NullInt64
		err := t.QueryRow(`SELECT config_seq FROM namespaces WHERE name = ? AND base = ?`, n.name[1:], n.id).Scan(&cfg)
		if err == nil && cfg.Valid {
			return t.config(cfg.Int64).level
		}
		return levelNone
	}
	return t.config(n.configSeq).level
}

// resLevel is the encryption level of the namespace a resource row
// belongs to.
func (t *tx) resLevel(res int64) int {
	if l, ok := t.resLevels[res]; ok {
		return l
	}
	n, err := scanNS(t.QueryRow(`SELECT `+nsColsN+` FROM namespaces n JOIN resources r ON r.ns = n.ns WHERE r.res = ?`, res))
	t.must(err)
	l := t.nsLevel(n)
	if t.resLevels == nil {
		t.resLevels = map[int64]int{}
	}
	t.resLevels[res] = l
	return l
}

const nsColsN = `n.ns, n.name, n.base, n.base_at, n.base_config_seq, n.frozen, n.purged, n.head_seq, n.config_seq`

// --- data keys --------------------------------------------------------------

// dek returns the data key of res (grantsDEK for grants), creating it if
// create is set and it doesn't exist. It panics with a 500 when the key
// can't be had: no key store, a key store that can't unwrap it, or a key a
// purge destroyed.
func (t *tx) dek(res int64, create bool) []byte {
	if k, ok := t.newDEKs[res]; ok {
		return k
	}
	if k := t.e.deks.get(res); k != nil {
		return k
	}
	ks := t.e.opt.KeyStore
	if ks == nil {
		panic(errNoKeyStore)
	}
	k, err := t.loadDEK(res)
	if errors.Is(err, sql.ErrNoRows) {
		if !create || !t.write {
			panic(encUnavailable("the data key of this content is missing (destroyed by a purge?)"))
		}
		k = make([]byte, dekSize)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		w, err := ks.Wrap(t.context(), k, dekAAD(res))
		if err != nil {
			panic(encUnavailable(fmt.Sprintf("wrapping a data key with key store %s: %v", ks.Name(), err)))
		}
		_, err = t.Exec(`INSERT INTO deks (res, wrapped, keystore, created) VALUES (?,?,?,?)`, res, w, ks.Name(), t.now.UnixMilli())
		t.must(err)
		// Cached only once committed: a rolled-back key must never be
		// used again.
		if t.newDEKs == nil {
			t.newDEKs = map[int64][]byte{}
		}
		t.newDEKs[res] = k
		return k
	}
	if err != nil {
		panic(err)
	}
	t.e.deks.put(res, k)
	return k
}

// loadDEK reads and unwraps a data key from storage, bypassing the cache.
// A key that doesn't exist is sql.ErrNoRows; one that doesn't unwrap is a
// 500 panic naming the key stores involved.
func (t *tx) loadDEK(res int64) ([]byte, error) {
	ks := t.e.opt.KeyStore
	if ks == nil {
		panic(errNoKeyStore)
	}
	var wrapped []byte
	var name string
	if err := t.QueryRow(`SELECT wrapped, keystore FROM deks WHERE res = ?`, res).Scan(&wrapped, &name); err != nil {
		return nil, err
	}
	k, err := ks.Unwrap(t.context(), wrapped, dekAAD(res))
	if err != nil {
		panic(unwrapErr(ks, name, err))
	}
	return k, nil
}

func unwrapErr(ks KeyStore, wrappedBy string, err error) *Error {
	msg := fmt.Sprintf("the key store %s cannot unwrap a data key (wrapped by %s): %v", ks.Name(), wrappedBy, err)
	if wrappedBy != ks.Name() {
		msg += "; is this the right master key?"
	}
	return encUnavailable(msg)
}

func (t *tx) context() context.Context {
	if t.ctx == nil {
		return context.Background()
	}
	return t.ctx
}

// deleteDEKs destroys the data keys of the resources matched by where (a
// condition on resources), making their encrypted rows and archives
// unreadable (§8.3, §E.1).
func (t *tx) deleteDEKs(where string, args ...any) {
	_, err := t.Exec(`DELETE FROM deks WHERE res IN (SELECT res FROM resources WHERE `+where+`)`, args...)
	t.must(err)
	t.flushDEKs = true
}

// --- stored values ----------------------------------------------------------

// putPatches is the stored form of a revision's canonical patch set.
func (t *tx) putPatches(res int64, id ids.ID, canon []byte) any {
	if t.resLevel(res) < levelAtRest {
		return string(canon)
	}
	return sealRow(t.dek(res, true), revAAD(res, id), canon)
}

// putDoc is the stored form of a document in heads or snapshots.
func (t *tx) putDoc(table string, res, seq int64, doc []byte) any {
	if t.resLevel(res) < levelAtRest {
		return string(doc)
	}
	return sealRow(t.dek(res, true), docAAD(table, res, seq), doc)
}

// patchesOf returns a revision's canonical patch set (the row must have one).
func (t *tx) patchesOf(r *revRow) []byte {
	return t.openValue(r.res, r.patches.String, func() []byte { return revAAD(r.res, r.id) })
}

// docOf returns a stored heads or snapshots document.
func (t *tx) docOf(table string, res, seq int64, raw string) []byte {
	return t.openValue(res, raw, func() []byte { return docAAD(table, res, seq) })
}

func (t *tx) openValue(res int64, raw string, aad func() []byte) []byte {
	if !isSealed(raw) {
		return []byte(raw)
	}
	b, err := openRow(t.dek(res, false), aad(), []byte(raw))
	if err != nil {
		panic(encUnavailable(fmt.Sprintf("an encrypted row of resource %d does not decrypt: %v", res, err)))
	}
	return b
}

// storeGrantBlocks stores a grant's non-bearer form, encrypted under the
// deployment grants key when it is used in an encrypted namespace; a grant
// stored in plaintext earlier is encrypted then.
func (t *tx) storeGrantBlocks(id, blocks []byte, encrypt bool) {
	if !encrypt {
		_, err := t.Exec(`INSERT OR IGNORE INTO grants (id, blocks) VALUES (?, ?)`, id, string(blocks))
		t.must(err)
		return
	}
	var cur string
	err := t.QueryRow(`SELECT blocks FROM grants WHERE id = ?`, id).Scan(&cur)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = t.Exec(`INSERT INTO grants (id, blocks) VALUES (?, ?)`, id, sealRow(t.dek(grantsDEK, true), grantAAD(id), blocks))
	case err == nil && !isSealed(cur):
		_, err = t.Exec(`UPDATE grants SET blocks = ? WHERE id = ?`, sealRow(t.dek(grantsDEK, true), grantAAD(id), []byte(cur)), id)
	}
	t.must(err)
}

// --- turning encryption on ----------------------------------------------------

// encryptNamespace encrypts the stored rows of n (and of its remote shadow)
// that are still plaintext, after its level was raised to at-rest: patch
// sets, head and intermediate snapshots, and the grants its revisions were
// written with. It runs in the config write's transaction, so the
// namespace is never observed half-way; reads handle mixed rows anyway.
func (t *tx) encryptNamespace(n *nsRow) {
	t.resLevels = nil
	nss := []int64{n.id}
	if sh := t.remoteShadow(n); sh != nil {
		nss = append(nss, sh.id)
	}
	for _, ns := range nss {
		var resIDs []int64
		rows, err := t.Query(`SELECT res FROM resources WHERE ns = ? AND state != ?`, ns, statePurged)
		t.must(err)
		for rows.Next() {
			var r int64
			t.must(rows.Scan(&r))
			resIDs = append(resIDs, r)
		}
		rows.Close()
		for _, res := range resIDs {
			t.encryptResource(res)
		}
		var grants [][]byte
		rows, err = t.Query(`SELECT DISTINCT grant_id FROM revisions WHERE grant_id IS NOT NULL AND res IN (SELECT res FROM resources WHERE ns = ?)`, ns)
		t.must(err)
		for rows.Next() {
			var g []byte
			t.must(rows.Scan(&g))
			grants = append(grants, g)
		}
		rows.Close()
		for _, g := range grants {
			var cur string
			if err := t.QueryRow(`SELECT blocks FROM grants WHERE id = ?`, g).Scan(&cur); err == nil {
				t.storeGrantBlocks(g, []byte(cur), true)
			}
		}
	}
}

func (t *tx) encryptResource(res int64) {
	type revVal struct {
		seq int64
		id  []byte
		val string
	}
	var revs []revVal
	rows, err := t.Query(`SELECT seq, id, patches FROM revisions WHERE res = ? AND patches IS NOT NULL`, res)
	t.must(err)
	for rows.Next() {
		var r revVal
		t.must(rows.Scan(&r.seq, &r.id, &r.val))
		if !isSealed(r.val) {
			revs = append(revs, r)
		}
	}
	rows.Close()
	for _, r := range revs {
		_, err := t.Exec(`UPDATE revisions SET patches = ? WHERE seq = ?`, t.putPatches(res, ids.FromBytes(r.id), []byte(r.val)), r.seq)
		t.must(err)
	}
	for _, table := range []string{"heads", "snapshots"} {
		type docVal struct {
			seq int64
			val string
		}
		var docs []docVal
		rows, err := t.Query(`SELECT seq, doc FROM `+table+` WHERE res = ?`, res)
		t.must(err)
		for rows.Next() {
			var d docVal
			t.must(rows.Scan(&d.seq, &d.val))
			if !isSealed(d.val) {
				docs = append(docs, d)
			}
		}
		rows.Close()
		for _, d := range docs {
			_, err := t.Exec(`UPDATE `+table+` SET doc = ? WHERE res = ? AND seq = ?`, t.putDoc(table, res, d.seq, []byte(d.val)), res, d.seq)
			t.must(err)
		}
	}
}

// --- configuration checks -----------------------------------------------------

// checkEncryption checks a namespace document's encryption level (§7.4,
// Addendum E): a key store is needed for any level, a level is never
// lowered or removed, and a branch is at least at its base's level.
// cur is nil for a new namespace; baseLevel is -1 if there is no base.
func (t *tx) checkEncryption(cur, cfg *Config, baseLevel int) *Error {
	if cfg.level > levelNone && t.e.opt.KeyStore == nil {
		return invalid("/encryption: no key store configured on this server")
	}
	if cur != nil && cfg.level < cur.level {
		return invalid("/encryption: the encryption level cannot be lowered or removed")
	}
	if baseLevel >= 0 && cfg.level < baseLevel {
		return invalid("/encryption: a branch cannot have a lower encryption level than its base")
	}
	return nil
}

// lowerDependents lists the unpurged branches of n below level: raising n
// to level would leave copies of its content less protected (§7.4).
func (t *tx) lowerDependents(n *nsRow, level int) []string {
	var out []string
	for _, b := range t.branchesOf(n) {
		if !b.purged && t.config(b.configSeq).level < level {
			out = append(out, b.name)
		}
	}
	return out
}

// --- archives -----------------------------------------------------------------

// Encrypted archives (§8.6 in encrypted namespaces). The bundle is the
// standard full-history bundle, encrypted as a chunked stream:
//
//	header = "PLAR" ‖ 0x01 ‖ salt (32 random bytes) ‖ be32(chunk size)
//	key    = HKDF-SHA256(secret = the resource's DEK, salt, info = "patchlog-archive-v1")
//	chunk  = be32(len(ct)) ‖ ct,  ct = AES-256-GCM(key, nonce_i, plaintext_i, aad = header)
//	nonce_i = 0x000000 ‖ be64(i) ‖ final (0x01 for the last chunk, else 0x00)
//
// Every chunk but the last holds exactly chunk size plaintext bytes; the
// last, possibly empty, is marked final, so truncation and reordering are
// detected. Purging the resource destroys the DEK, which makes the archive
// unreadable wherever copies of it survive.
const (
	archiveMagic = "PLAR\x01"
	archiveChunk = 64 << 10
	archiveHdr   = len(archiveMagic) + 32 + 4
)

func archiveKey(dek, salt []byte) []byte {
	k, err := hkdf.Key(sha256.New, dek, salt, "patchlog-archive-v1", 32)
	if err != nil {
		panic(err)
	}
	return k
}

type archiveWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	hdr   []byte
	buf   []byte
	n     uint64
	err   error
	close bool
}

// sealArchive returns a writer that encrypts an archive to w under a key
// derived from dek.
func sealArchive(w io.Writer, dek []byte) (io.WriteCloser, error) {
	hdr := make([]byte, archiveHdr)
	copy(hdr, archiveMagic)
	if _, err := rand.Read(hdr[len(archiveMagic) : len(archiveMagic)+32]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(hdr[archiveHdr-4:], archiveChunk)
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &archiveWriter{w: w, hdr: hdr, aead: newGCM(archiveKey(dek, hdr[len(archiveMagic):len(archiveMagic)+32])), buf: make([]byte, 0, archiveChunk)}, nil
}

func chunkNonce(i uint64, final bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], i)
	if final {
		n[11] = 1
	}
	return n
}

func (a *archiveWriter) flush(final bool) error {
	ct := a.aead.Seal(nil, chunkNonce(a.n, final), a.buf, a.hdr)
	a.n++
	a.buf = a.buf[:0]
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := a.w.Write(l[:]); err != nil {
		return err
	}
	_, err := a.w.Write(ct)
	return err
}

func (a *archiveWriter) Write(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	n := 0
	for len(p) > 0 {
		// A full chunk is written only once more data follows, so Close
		// can always mark the last one final.
		if len(a.buf) == cap(a.buf) {
			if a.err = a.flush(false); a.err != nil {
				return n, a.err
			}
		}
		k := copy(a.buf[len(a.buf):cap(a.buf)], p)
		a.buf = a.buf[:len(a.buf)+k]
		p, n = p[k:], n+k
	}
	return n, nil
}

func (a *archiveWriter) Close() error {
	if a.err != nil {
		return a.err
	}
	if a.close {
		return nil
	}
	a.close = true
	return a.flush(true)
}

type archiveReader struct {
	r    *bufio.Reader
	aead cipher.AEAD
	hdr  []byte
	max  int
	buf  []byte
	n    uint64
	done bool
}

// openArchive decrypts an archive sealArchive wrote. r is positioned at
// the header.
func openArchive(r *bufio.Reader, dek []byte) (io.Reader, error) {
	hdr := make([]byte, archiveHdr)
	if _, err := io.ReadFull(r, hdr); err != nil || string(hdr[:len(archiveMagic)]) != archiveMagic {
		return nil, errors.New("not an encrypted archive")
	}
	max := int(binary.BigEndian.Uint32(hdr[archiveHdr-4:]))
	if max <= 0 || max > 16<<20 {
		return nil, errors.New("encrypted archive: bad chunk size")
	}
	return &archiveReader{r: r, hdr: hdr, max: max, aead: newGCM(archiveKey(dek, hdr[len(archiveMagic):len(archiveMagic)+32]))}, nil
}

func (a *archiveReader) Read(p []byte) (int, error) {
	for len(a.buf) == 0 {
		if a.done {
			return 0, io.EOF
		}
		var l [4]byte
		if _, err := io.ReadFull(a.r, l[:]); err != nil {
			return 0, errors.New("encrypted archive: truncated")
		}
		n := int(binary.BigEndian.Uint32(l[:]))
		if n < a.aead.Overhead() || n > a.max+a.aead.Overhead() {
			return 0, errors.New("encrypted archive: bad chunk")
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(a.r, ct); err != nil {
			return 0, errors.New("encrypted archive: truncated")
		}
		pt, err := a.aead.Open(nil, chunkNonce(a.n, false), ct, a.hdr)
		if err != nil {
			pt, err = a.aead.Open(nil, chunkNonce(a.n, true), ct, a.hdr)
			if err != nil {
				return 0, errors.New("encrypted archive: a chunk does not decrypt (wrong key, or tampered)")
			}
			a.done = true
			if _, err := a.r.ReadByte(); err != io.EOF {
				return 0, errors.New("encrypted archive: data after the final chunk")
			}
		} else if len(pt) != a.max {
			return 0, errors.New("encrypted archive: short chunk before the end")
		}
		a.n++
		a.buf = pt
	}
	k := copy(p, a.buf)
	a.buf = a.buf[k:]
	return k, nil
}

// ErrArchiveKeyDestroyed is returned by OpenArchive for an encrypted
// archive of a resource whose data key a purge destroyed (§8.3).
var ErrArchiveKeyDestroyed = errors.New("the archive is encrypted and its data key was destroyed (the resource was purged)")

// OpenArchive returns the bundle of an archive of ns/name read from r:
// r itself for a plaintext archive, the decrypted stream for one written in
// an encrypted namespace. An encrypted archive of a purged resource is
// ErrArchiveKeyDestroyed.
func (e *Engine) OpenArchive(ctx context.Context, ns, name string, r io.Reader) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	head, _ := br.Peek(len(archiveMagic))
	if string(head) != archiveMagic {
		return br, nil
	}
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
	return openArchive(br, dek)
}

// archiveSealer returns the Seal function of an archive of res, or nil if
// res is not encrypted.
func (t *tx) archiveSealer(res int64) func(io.Writer) (io.WriteCloser, error) {
	if t.resLevel(res) < levelAtRest {
		return nil
	}
	dek := t.dek(res, true)
	return func(w io.Writer) (io.WriteCloser, error) { return sealArchive(w, dek) }
}

// checkKeyStore runs at Open: with a key store, one stored data key must
// unwrap (a wrong master key fails here, not on the first read); without
// one, encrypted namespaces are reported, and their content answers 500.
func (e *Engine) checkKeyStore() error {
	ctx := context.Background()
	var wrapped []byte
	var res int64
	var name string
	err := e.db.QueryRowContext(ctx, `SELECT res, wrapped, keystore FROM deks ORDER BY res LIMIT 1`).Scan(&res, &wrapped, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	ks := e.opt.KeyStore
	if ks == nil {
		log.Printf("warning: the database holds data encrypted at rest (Addendum E.1) but no key store is configured; encrypted content will answer 500")
		return nil
	}
	if _, err := ks.Unwrap(ctx, wrapped, dekAAD(res)); err != nil {
		return fmt.Errorf("encryption at rest: %s", unwrapErr(ks, name, err).Body["message"])
	}
	return nil
}
