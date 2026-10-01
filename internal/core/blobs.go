package core

// Blobs (§7.8).
//
// Tables (db.go, pgschema.go; D.2 with additions):
//
//   - blobs: attachments, one row per resource and blob, with ref_seq (the
//     first revision of the resource that referenced it) and pruned (set
//     once pruning ended the attachment: reads answer 410).
//   - blob_pending: pending entries, one per resource, blob and uploader
//     (root sub and kid, or the author in development mode). They expire
//     after blobGrace: reads of the table ignore older rows, and a sweep on
//     the leader deletes them (SweepBlobs).
//   - blob_refs: which revisions reference which blob (§5), as intervals of
//     the resource's chain [from_seq, to_seq). Pruning (which attachments
//     a kept document still needs), branch read-through and batch sources
//     (whether a document in the history as seen references a blob) and
//     archives (which blobs an archived range references) read it.
//   - blob_epochs: in sealed namespaces, each blob's sealing per epoch,
//     stored once (sealedblobs.go, §E.2.2).
//   - blob_bytes: the bytes, by (owner, sha256). D.2 puts bytes outside the
//     database; storing them in a table keeps one backend for both
//     dialects, encryption at rest and transactional garbage collection.
//     Values are at most blobSize (64 MiB by default).
//
// Ownership and encryption at rest (Addendum E.1). Bytes of a resource in
// a namespace below at-rest are stored once for the whole deployment, with
// owner 0, however many resources and uploaders name them. In an encrypted
// namespace each resource's bytes are its own: owner is the resource row,
// and the bytes are encrypted under that resource's data key (row format
// of crypt.go, aad "blob_bytes" ‖ res ‖ hash), as D.2 suggests ("files are
// named by resource and hash"). A blob taken from another resource (a base,
// a batch source, a copy) whose owner differs is copied and re-encrypted.
// Purging a resource destroys its data key and deletes its bytes, so
// nothing of them stays recoverable; turning encryption on moves a
// resource's plaintext bytes under its own key (encryptResource).
//
// Garbage collection. Bytes are deleted by the transaction that removes
// (or marks pruned) the last row naming them (gcBytes). On Postgres two
// namespaces may share owner-0 bytes, so the collector first locks the
// bytes row (SELECT … FOR UPDATE) and only then, in a new statement that
// sees every commit before the lock, looks for rows naming it; whoever
// adds a row naming bytes first touches (updates) or inserts the bytes
// row, which waits for that lock. So a concurrent upload of the same bytes
// can't lose them.
//
// Locks (Postgres, pglock.go). An upload takes its namespace's lock shared
// (it adds rows, as reads of the namespace's configuration decide), and a
// copy also its source's: purges, freezes and configuration changes, which
// take it exclusively, are ordered with it. Attaching happens in the
// write's transaction under its exclusive lock, pruning and purges under
// theirs, and the grace sweep takes each namespace's lock exclusively.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// SealedBlobType is the media type of sealed blobs (§E.2.2), the only one
// an e2e namespace accepts (§E.3.1).
const SealedBlobType = "application/vnd.patchlog.sealed-blob"

// pendingMin is the least a pending entry counts toward blobPending (§6.6).
const pendingMin = 4 << 10

// blobRow is an attachment or a pending entry.
type blobRow struct {
	res     int64
	bid     ids.ID
	typ     string
	nonce   string // "" if none
	size    int64
	hash    []byte
	owner   int64
	pruned  bool
	pending bool
}

func (b *blobRow) matches(r blobRef) bool {
	return b.typ == r.typ && b.size == r.size && b.nonce == r.nonce
}

const blobCols = `res, bid, type, nonce, size, hash, owner, pruned`

func scanBlobRow(row interface{ Scan(...any) error }) (*blobRow, error) {
	b := &blobRow{}
	var bid []byte
	var nonce sql.NullString
	err := row.Scan(&b.res, &bid, &b.typ, &nonce, &b.size, &b.hash, &b.owner, &b.pruned)
	b.bid, b.nonce = ids.FromBytes(bid), nonce.String
	return b, err
}

// attachedBlob returns res's attachment of bid, pruned or not, or nil.
func (t *tx) attachedBlob(res int64, bid ids.ID) *blobRow {
	b, err := scanBlobRow(t.QueryRow(`SELECT `+blobCols+` FROM blobs WHERE res = ? AND bid = ?`, res, bid[:]))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	return b
}

// pendingBlob returns uploader's pending entry of bid in res, if it was
// created at or after cutoff (blobGrace), or nil.
func (t *tx) pendingBlob(res int64, bid ids.ID, uploader string, cutoff int64) *blobRow {
	b, err := scanBlobRow(t.QueryRow(`SELECT res, bid, type, nonce, size, hash, owner, 0 FROM blob_pending
		WHERE res = ? AND bid = ? AND uploader = ? AND created >= ?`, res, bid[:], uploader, cutoff))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	b.pending = true
	return b
}

// uploaderOf is the uploader of §7.8: the principal as rate limits know
// it, root sub and kid (§6.6); in development mode, the author.
func uploaderOf(a *actor) string {
	if a.verified != nil {
		return string(jsonv.Canonical([]any{a.principal.ID, a.verified.Key.Kid}))
	}
	return string(jsonv.Canonical([]any{a.principal.ID}))
}

// blobCutoff is the creation time before which a pending entry has expired.
func (t *tx) blobCutoff(cfg *Config) int64 { return t.now.Add(-cfg.Limits.BlobGrace).UnixMilli() }

// referencedUpTo reports whether a document of res's chain up to seq max
// references bid.
func (t *tx) referencedUpTo(res, max int64, bid ids.ID) bool {
	var ok bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_refs WHERE res = ? AND bid = ? AND from_seq <= ?)`, res, bid[:], max).Scan(&ok))
	return ok
}

// historyBlob finds bid among the attachments of the resources whose
// chains make up the history ending at head (§7.6: crossing foreign
// parents), skipping res skip, where a document of that history references
// it. It returns the attachment, or else a pruned one, or nil.
func (t *tx) historyBlob(head *revRow, skip int64, bid ids.ID) (live, pruned *blobRow) {
	for _, seg := range t.ancestry(head) {
		if seg.res == skip {
			continue
		}
		b := t.attachedBlob(seg.res, bid)
		if b == nil || !t.referencedUpTo(seg.res, seg.max, bid) {
			continue
		}
		if !b.pruned {
			return b, nil
		}
		if pruned == nil {
			pruned = b
		}
	}
	return nil, pruned
}

// --- references ---------------------------------------------------------------

// blobRef is one well-formed reference in a document (§7.8).
type blobRef struct {
	bid   ids.ID
	typ   string
	size  int64
	nonce string
	ptr   string
}

// blobRefsOf lists a document's blob references, which checkBlobRefs found
// well-formed. Schema documents have none.
func blobRefsOf(doc any) []blobRef {
	if m, ok := doc.(map[string]any); ok {
		if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
			return nil
		}
	}
	var out []blobRef
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		switch x := v.(type) {
		case []any:
			for i, e := range x {
				walk(e, ptr+"/"+strconv.Itoa(i))
			}
		case map[string]any:
			if s, ok := x["$blob"].(string); ok {
				id, err := ids.Parse(s)
				if err != nil {
					return
				}
				r := blobRef{bid: id, ptr: ptr}
				r.typ, _ = x["type"].(string)
				f, _ := x["size"].(float64)
				r.size = int64(f)
				r.nonce, _ = x["nonce"].(string)
				out = append(out, r)
				return
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], ptr+"/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(k))
			}
		}
	}
	walk(doc, "")
	return out
}

// batchSource is a batch's local source (§7.5), through which blobs are
// available to its items if the batch may read the source (§7.8).
type batchSource struct {
	raw      any
	req      Request
	resolved bool
	n        *nsRow
	atSeq    int64
	readable map[string]bool
}

func (bs *batchSource) resolve(t *tx) {
	if bs.resolved {
		return
	}
	bs.resolved = true
	m, ok := bs.raw.(map[string]any)
	if !ok {
		return
	}
	if _, remote := m["origin"]; remote {
		return // another deployment's blobs are uploaded (§G.3)
	}
	ns, _ := m["ns"].(string)
	at, _ := m["at"].(string)
	id, err := ids.Parse(at)
	if !ValidNSName(ns) || err != nil {
		return
	}
	n := t.nsByName(ns)
	if n == nil || n.purged {
		return
	}
	seq, ok := t.nsLogSeq(n.id, id)
	if !ok {
		return
	}
	bs.n, bs.atSeq = n, seq
}

// blob finds bid attached to name in the source and referenced by a
// document in its history as of source.at, if the batch passes the read
// check on the source (§7.8 Availability).
func (bs *batchSource) blob(t *tx, name string, bid ids.ID) *blobRow {
	bs.resolve(t)
	if bs.n == nil {
		return nil
	}
	ok, seen := bs.readable[name]
	if !seen {
		ok = t.sourceReadable(bs.n, name, bs.req)
		if bs.readable == nil {
			bs.readable = map[string]bool{}
		}
		bs.readable[name] = ok
	}
	if !ok {
		return nil
	}
	v := t.resolve(bs.n, name, &bs.atSeq)
	if v.state == Purged || v.head == nil {
		return nil
	}
	b, _ := t.historyBlob(v.head, 0, bid)
	return b
}

// blobSourceOf is a batch's source for blob availability, or nil.
func blobSourceOf(req Request, source any, isBatch bool) *batchSource {
	if !isBatch || source == nil {
		return nil
	}
	return &batchSource{raw: source, req: req}
}

// sourceReadable is the read check of a copy's or a batch's source
// (§7.8): a read of /r/{ns}/{name} against that namespace's keys, with the
// grant in Source-Authorization, or the request's own.
func (t *tx) sourceReadable(n *nsRow, name string, req Request) bool {
	cred := req.Cred
	if req.SourceCred.Bearer != "" {
		cred = req.SourceCred
	}
	_, err := t.reader(n, cred, name)
	return err == nil
}

// checkBlobs is the availability check of step 4 (§6.2, §7.8): every
// reference of every step's resulting document names a blob available to
// the item's resource and matches its type, size and nonce. It records each
// step's blobs and where they come from, for step 7.
func (t *tx) checkBlobs(n *nsRow, s *itemState, a *actor, bs *batchSource) *Error {
	cutoff := t.blobCutoff(t.config(n.configSeq))
	uploader := uploaderOf(a)
	var lastLive []ids.ID // at E3, the last live document's declared list
	known := s.parent == nil
	for _, step := range s.steps {
		step.blobs = nil
		if step.del {
			continue
		}
		if step.sealed {
			// E3: the blobs the sealed op declares, in plaintext (§E.3.1).
			list := step.declared
			if step.keepsList {
				if !known {
					lastLive = t.declaredAt(t.lastLive(s.parent))
				}
				list = lastLive
			}
			lastLive, known = list, true
			if err := t.checkDeclared(n, s, step, list, uploader, cutoff, bs); err != nil {
				return err
			}
			continue
		}
		refs := blobRefsOf(step.doc)
		step.blobs = map[ids.ID]*blobRow{}
		for _, r := range refs {
			src, ok := step.blobs[r.bid]
			if !ok {
				src = t.availableBlob(n, s, uploader, cutoff, r.bid, bs)
				if src == nil {
					return blobErr(r.ptr, "the blob is not available to this resource (§7.8)")
				}
				step.blobs[r.bid] = src
			}
			if !src.matches(r) {
				return blobErr(r.ptr, "the reference doesn't match the blob's type, size or nonce (§7.8)")
			}
		}
	}
	return nil
}

// availableBlob finds where a blob available to an item's resource comes
// from (§7.8 Availability), or nil.
func (t *tx) availableBlob(n *nsRow, s *itemState, uploader string, cutoff int64, bid ids.ID, bs *batchSource) *blobRow {
	var own int64
	if s.view != nil && s.view.own != nil {
		own = s.view.own.id
		if b := t.attachedBlob(own, bid); b != nil && !b.pruned {
			return b
		}
		if b := t.pendingBlob(own, bid, uploader, cutoff); b != nil {
			return b
		}
	}
	if n.isBranch() && s.view != nil && s.view.head != nil {
		// Attached to the same resource in a base and referenced by a
		// document in the history as the branch sees it. A remote
		// branch's bases are shadows, which mirror the base's blobs with
		// its chains (§G.3, remote_blobs.go).
		if b, _ := t.historyBlob(s.view.head, own, bid); b != nil {
			return b
		}
	}
	if bs != nil {
		if b := bs.blob(t, s.Resource, bid); b != nil {
			return b
		}
	}
	return nil
}

// --- attaching (step 7) ---------------------------------------------------------

// attachStep records which blobs the document of revision seq of res
// references (blob_refs) and attaches them (§7.8 Attached): a write
// attaches every blob its resulting document references to its own
// resource, in the revision's transaction.
func (t *tx) attachStep(res int64, step *stepState, seq int64) {
	open := map[ids.ID]bool{}
	rows, err := t.Query(`SELECT bid FROM blob_refs WHERE res = ? AND to_seq IS NULL`, res)
	t.must(err)
	for rows.Next() {
		var b []byte
		t.must(rows.Scan(&b))
		open[ids.FromBytes(b)] = true
	}
	rows.Close()
	for bid := range open {
		if _, still := step.blobs[bid]; !still {
			_, err := t.Exec(`UPDATE blob_refs SET to_seq = ? WHERE res = ? AND bid = ? AND to_seq IS NULL`, seq, res, bid[:])
			t.must(err)
		}
	}
	bids := make([]ids.ID, 0, len(step.blobs))
	for bid := range step.blobs {
		bids = append(bids, bid)
	}
	sort.Slice(bids, func(i, j int) bool { return bytes.Compare(bids[i][:], bids[j][:]) < 0 })
	for _, bid := range bids {
		if !open[bid] {
			_, err := t.Exec(`INSERT INTO blob_refs (res, bid, from_seq) VALUES (?,?,?)`, res, bid[:], seq)
			t.must(err)
		}
		t.attachBlob(res, step.blobs[bid], seq)
	}
}

// attachBlob attaches src's blob to res at revision seq, unless it is
// attached already, and deletes every pending entry for it: an attached
// blob is available to every writer (D.2).
func (t *tx) attachBlob(res int64, src *blobRow, seq int64) {
	bid := src.bid
	cur := t.attachedBlob(res, bid)
	if cur != nil && !cur.pruned {
		return
	}
	owner := t.bytesOwner(res)
	if src.owner == owner {
		if !t.touchBytes(owner, src.hash) {
			panic(fmt.Errorf("the bytes of blob %s are missing", bid))
		}
	} else {
		t.putBytes(owner, src.hash, t.readBytes(src.owner, src.hash))
	}
	var nonce any
	if src.nonce != "" {
		nonce = src.nonce
	}
	if cur != nil {
		// A row marked pruned is reused (D.2).
		_, err := t.Exec(`UPDATE blobs SET type = ?, nonce = ?, size = ?, hash = ?, owner = ?, created = ?, ref_seq = ?, pruned = 0 WHERE res = ? AND bid = ?`,
			src.typ, nonce, src.size, src.hash, owner, t.now.UnixMilli(), seq, res, bid[:])
		t.must(err)
	} else {
		_, err := t.Exec(`INSERT INTO blobs (res, bid, type, nonce, size, hash, owner, created, ref_seq, pruned) VALUES (?,?,?,?,?,?,?,?,?,0)`,
			res, bid[:], src.typ, nonce, src.size, src.hash, owner, t.now.UnixMilli(), seq)
		t.must(err)
	}
	t.deletePending(`res = ? AND bid = ?`, res, bid[:])
}

// deletePending deletes the pending entries matched by where and collects
// the bytes no row names any more.
func (t *tx) deletePending(where string, args ...any) {
	type key struct {
		owner int64
		hash  string
	}
	var keys []key
	rows, err := t.Query(`SELECT DISTINCT owner, hash FROM blob_pending WHERE `+where, args...)
	t.must(err)
	for rows.Next() {
		var k key
		var h []byte
		t.must(rows.Scan(&k.owner, &h))
		k.hash = string(h)
		keys = append(keys, k)
	}
	rows.Close()
	if len(keys) == 0 {
		return
	}
	_, err = t.Exec(`DELETE FROM blob_pending WHERE `+where, args...)
	t.must(err)
	for _, k := range keys {
		t.gcBytes(k.owner, []byte(k.hash))
	}
}

// --- bytes ----------------------------------------------------------------------

// bytesOwner is the owner of res's blob bytes: res itself in a namespace
// encrypted at rest (or more), else 0, the shared plaintext store.
func (t *tx) bytesOwner(res int64) int64 {
	if t.resLevel(res) >= levelAtRest {
		return res
	}
	return 0
}

func bytesAAD(owner int64, hash []byte) []byte { return rowAAD("blob_bytes", owner, hash) }

// touchBytes locks a bytes row (Postgres: against a concurrent collector)
// and reports whether it exists.
func (t *tx) touchBytes(owner int64, hash []byte) bool {
	r, err := t.Exec(`UPDATE blob_bytes SET owner = owner WHERE owner = ? AND hash = ?`, owner, hash)
	t.must(err)
	n, err := r.RowsAffected()
	t.must(err)
	return n > 0
}

// putBytes stores plaintext bytes under owner, encrypted under the owner's
// data key unless owner is 0, unless they are stored already.
func (t *tx) putBytes(owner int64, hash, plain []byte) {
	if t.touchBytes(owner, hash) {
		return
	}
	data := plain
	if owner != 0 {
		data = sealRow(t.dek(owner, true), bytesAAD(owner, hash), plain)
	}
	_, err := t.Exec(`INSERT INTO blob_bytes (owner, hash, data) VALUES (?,?,?) ON CONFLICT (owner, hash) DO UPDATE SET owner = excluded.owner`, owner, hash, data)
	t.must(err)
}

// readBytes returns the plaintext bytes stored under owner.
func (t *tx) readBytes(owner int64, hash []byte) []byte {
	var data []byte
	err := t.QueryRow(`SELECT data FROM blob_bytes WHERE owner = ? AND hash = ?`, owner, hash).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		panic(fmt.Errorf("blob bytes %x of owner %d are missing", hash, owner))
	}
	t.must(err)
	if owner == 0 {
		return data
	}
	plain, err := openRow(t.dek(owner, false), bytesAAD(owner, hash), data)
	if err != nil {
		panic(encUnavailable(fmt.Sprintf("blob bytes of resource %d do not decrypt: %v", owner, err)))
	}
	return plain
}

// gcBytes deletes the bytes stored under (owner, hash) if no attachment
// or pending entry names them any more. On Postgres the bytes row is
// locked first, so a transaction adding a row that names them (which
// touches or inserts it, putBytes) is ordered with this one, and the check
// after the lock sees its commit.
func (t *tx) gcBytes(owner int64, hash []byte) {
	if t.e.pg && t.write {
		var one int
		err := t.QueryRow(`SELECT 1 FROM blob_bytes WHERE owner = ? AND hash = ? FOR UPDATE`, owner, hash).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return
		}
		t.must(err)
	}
	var used bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blobs WHERE owner = ? AND hash = ? AND pruned = 0)
		OR EXISTS (SELECT 1 FROM blob_pending WHERE owner = ? AND hash = ?)`, owner, hash, owner, hash).Scan(&used))
	if !used {
		_, err := t.Exec(`DELETE FROM blob_bytes WHERE owner = ? AND hash = ?`, owner, hash)
		t.must(err)
	}
}

// purgeBlobs ends every attachment and pending entry of the resources
// matched by where (a condition on res, §8.3, §8.5) and deletes their
// bytes: their own (owner = res, whose data keys the purge destroys too)
// and the shared ones nothing else names.
func (t *tx) purgeBlobs(where string, args ...any) {
	var shared [][]byte
	seen := map[string]bool{}
	for _, table := range []string{"blobs", "blob_pending"} {
		rows, err := t.Query(`SELECT DISTINCT hash FROM `+table+` WHERE owner = 0 AND `+where, args...)
		t.must(err)
		for rows.Next() {
			var h []byte
			t.must(rows.Scan(&h))
			if !seen[string(h)] {
				seen[string(h)] = true
				shared = append(shared, h)
			}
		}
		rows.Close()
	}
	for _, table := range []string{"blobs", "blob_pending", "blob_refs"} {
		_, err := t.Exec(`DELETE FROM `+table+` WHERE `+where, args...)
		t.must(err)
	}
	_, err := t.Exec(`DELETE FROM blob_bytes WHERE owner <> 0 AND owner IN (SELECT res FROM resources WHERE `+where+`)`, args...)
	t.must(err)
	for _, h := range shared {
		t.gcBytes(0, h)
	}
}

// pruneBlobs ends the attachments of res that no document kept after a
// prune to horizon hseq references (§7.8, §8.6): the documents at or after
// the horizon and those at the kept revisions. Their bytes go unless
// something else names them; the archive has them.
func (t *tx) pruneBlobs(res, hseq int64, kept []int64) {
	rows, err := t.Query(`SELECT `+blobCols+` FROM blobs WHERE res = ? AND pruned = 0`, res)
	t.must(err)
	var all []*blobRow
	for rows.Next() {
		b, err := scanBlobRow(rows)
		t.must(err)
		all = append(all, b)
	}
	rows.Close()
	for _, b := range all {
		var alive bool
		t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_refs WHERE res = ? AND bid = ? AND (to_seq IS NULL OR to_seq > ?))`, res, b.bid[:], hseq).Scan(&alive))
		for _, k := range kept {
			if alive {
				break
			}
			t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_refs WHERE res = ? AND bid = ? AND from_seq <= ? AND (to_seq IS NULL OR to_seq > ?))`, res, b.bid[:], k, k).Scan(&alive))
		}
		if alive {
			continue
		}
		_, err := t.Exec(`UPDATE blobs SET pruned = 1 WHERE res = ? AND bid = ?`, res, b.bid[:])
		t.must(err)
		t.gcBytes(b.owner, b.hash)
	}
}

// encryptBlobs moves res's plaintext blob bytes under its own data key,
// after its namespace became encrypted at rest (encryptResource).
func (t *tx) encryptBlobs(res int64) {
	var hashes [][]byte
	seen := map[string]bool{}
	for _, q := range []string{
		`SELECT DISTINCT hash FROM blobs WHERE res = ? AND owner = 0 AND pruned = 0`,
		`SELECT DISTINCT hash FROM blob_pending WHERE res = ? AND owner = 0`,
	} {
		rows, err := t.Query(q, res)
		t.must(err)
		for rows.Next() {
			var h []byte
			t.must(rows.Scan(&h))
			if !seen[string(h)] {
				seen[string(h)] = true
				hashes = append(hashes, h)
			}
		}
		rows.Close()
	}
	for _, h := range hashes {
		t.putBytes(res, h, t.readBytes(0, h))
	}
	_, err := t.Exec(`UPDATE blobs SET owner = ? WHERE res = ? AND owner = 0`, res, res)
	t.must(err)
	_, err = t.Exec(`UPDATE blob_pending SET owner = ? WHERE res = ? AND owner = 0`, res, res)
	t.must(err)
	for _, h := range hashes {
		t.gcBytes(0, h)
	}
}

// --- uploading -------------------------------------------------------------------

// BlobUpload is a PUT /r/{ns}/{name}/blob/{bid} (§7.8): an upload, or with
// From a copy.
type BlobUpload struct {
	Type  string // the Content-Type header as sent
	Nonce string // Blob-Nonce, "" if absent
	// From is Blob-From: /r/{ns2}/{name2}/blob/{bid} for a copy, else "".
	From string
	// Body is the upload's body; Length its Content-Length, -1 if unknown.
	Body   io.Reader
	Length int64
	// HasBody reports, for a copy, whether a body was sent (400).
	HasBody bool
}

// blobGate is what an upload's checks decided.
type blobGate struct {
	n        *nsRow
	cfg      *Config
	a        *actor
	uploader string
	typ      string
	nonce    string
	src      *blobRow // a copy's source
	maxSize  int64
	pendUsed int64 // the uploader's pending bytes in the namespace, but this blob's
	pendMax  int64
	cutoff   int64
	rate     []draw
}

// parseBlobType is the type of §3.7: the Content-Type lowercased, without
// parameters.
func parseBlobType(ct string) (string, bool) {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", false
	}
	mt = strings.ToLower(mt)
	return mt, blobTypeRe.MatchString(mt)
}

// parseBlobURL parses a Blob-From value, /r/{ns}/{name}/blob/{bid}.
func parseBlobURL(s string) (ns, name string, bid ids.ID, ok bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "r" || parts[4] != "blob" {
		return "", "", bid, false
	}
	id, err := ids.Parse(parts[5])
	if err != nil || !ValidNSName(parts[2]) || !ValidResourceName(parts[3]) {
		return "", "", bid, false
	}
	return parts[2], parts[3], id, true
}

// nsRank ranks namespaces for copies, as for imports (§G.5.1): public,
// then private and sealed alike, then e2e.
func (t *tx) nsRank(n *nsRow) int {
	cfg := t.config(n.configSeq)
	switch {
	case cfg.level == levelE2E:
		return 2
	case cfg.level == levelSealed || cfg.Read != "public":
		return 1
	}
	return 0
}

// gateBlob runs an upload's checks in the order of §7.8, as far as they go
// without the body. With draw, it draws the rate-limit tokens.
func (t *tx) gateBlob(req Request, name string, bid ids.ID, up *BlobUpload, draw bool) (*blobGate, *Error) {
	n := t.nsByName(req.NS)
	if n == nil {
		return nil, t.absentNS(req.NS, req.Cred)
	}
	if n.purged {
		return nil, gone()
	}
	cfg := t.config(n.configSeq)
	a, err := t.authenticate(n.name, n, cfg, req.Cred, nil)
	if err != nil {
		return nil, err
	}
	// 1. Authorisation, with create, append and restore as candidate verbs,
	// then the rate limits.
	var first *Error
	allowed := false
	for _, verb := range []string{"create", "append", "restore"} {
		e := t.authorize(a, verb, name)
		if e == nil {
			allowed = true
			break
		}
		if first == nil {
			first = e
		}
	}
	if !allowed {
		return nil, first
	}
	g := &blobGate{n: n, cfg: cfg, a: a, uploader: uploaderOf(a), maxSize: int64(cfg.Limits.BlobSize), cutoff: t.blobCutoff(cfg)}
	if draw {
		g.rate = t.writeDraws(n, cfg, a, []string{name}, 1)
		if up.From == "" {
			// The bytes, as declared; the rest is charged once read.
			declared := min(max(up.Length, 0), g.maxSize+1)
			g.rate = append(g.rate, t.blobDraw(n, cfg, a, declared))
		}
		if err := t.admit(g.rate); err != nil {
			return nil, err
		}
	}
	// 2. A purged resource.
	if t.resolve(n, name, nil).state == Purged {
		return nil, gone()
	}
	// 3. A frozen namespace.
	if cfg.Frozen {
		e := apiErr(409, "frozen")
		if cfg.Successor != "" {
			e.Body["successor"] = cfg.Successor
		}
		return nil, e
	}
	size := up.Length
	if up.From != "" {
		// A copy: the same bid, then the source as a read.
		sns, sname, sbid, ok := parseBlobURL(up.From)
		if !ok {
			return nil, badInput("Blob-From must be /r/{ns}/{name}/blob/{bid}")
		}
		if sbid != bid {
			return nil, apiErr(422, "blob", "message", "Blob-From must name the same blob id")
		}
		src := t.copySource(n, req, sns, sname, bid)
		if src == nil {
			return nil, notFound()
		}
		if up.HasBody {
			return nil, badInput("a copy has an empty body")
		}
		g.src, g.typ, g.nonce, size = src, src.typ, src.nonce, src.size
	} else {
		typ, ok := parseBlobType(up.Type)
		if !ok {
			return nil, badInput("the Content-Type must be a media type, type/subtype")
		}
		if up.Nonce != "" && !seal.ValidNonce(up.Nonce) {
			return nil, badInput("Blob-Nonce must be 26 base32 characters")
		}
		g.typ, g.nonce = typ, up.Nonce
	}
	if cfg.level == levelE2E && g.typ != SealedBlobType {
		return nil, apiErr(415, "bad_input", "message", "an e2e namespace accepts only "+SealedBlobType+" blobs (§E.3.1)")
	}
	// 5. Sizes: blobSize and the uploader's pending bytes.
	if al := t.allowanceOf(cfg, a); al != nil && al.BlobPending > 0 {
		g.pendMax = int64(al.BlobPending)
	} else {
		g.pendMax = int64(cfg.Limits.BlobPending)
	}
	var res int64
	if r := t.resource(n.id, name); r != nil {
		res = r.id
	}
	t.must(t.QueryRow(`SELECT COALESCE(SUM(CASE WHEN p.size < ? THEN ? ELSE p.size END), 0)
		FROM blob_pending p JOIN resources r ON r.res = p.res
		WHERE r.ns = ? AND p.uploader = ? AND p.created >= ? AND NOT (p.res = ? AND p.bid = ?)`,
		pendingMin, pendingMin, n.id, g.uploader, g.cutoff, res, bid[:]).Scan(&g.pendUsed))
	if size >= 0 {
		if err := g.checkSize(size); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// checkSize is check 5 for a body of size bytes.
func (g *blobGate) checkSize(size int64) *Error {
	if size > g.maxSize {
		return limitErr(413, fmt.Sprintf("a blob is larger than blobSize (%d bytes)", g.maxSize))
	}
	if g.pendUsed+max(size, pendingMin) > g.pendMax {
		return limitErr(413, fmt.Sprintf("the uploader's pending blobs would exceed blobPending (%d bytes)", g.pendMax))
	}
	return nil
}

// copySource finds a copy's source blob (§7.8 Copying): readable by the
// request (or its Source-Authorization), of no higher rank than the target,
// and one that reading would serve. Anything else is nil (404).
func (t *tx) copySource(target *nsRow, req Request, ns, name string, bid ids.ID) *blobRow {
	sn := t.nsByName(ns)
	if sn == nil || sn.purged {
		return nil
	}
	if !t.sourceReadable(sn, name, req) {
		return nil
	}
	if t.nsRank(sn) > t.nsRank(target) {
		return nil
	}
	ans := t.servableBlob(sn, name, bid)
	if ans.status != 200 {
		return nil
	}
	return ans.row
}

// UploadBlob uploads or copies a blob (§7.8). It answers 201 (nil error)
// whether or not the bytes were stored already.
func (e *Engine) UploadBlob(ctx context.Context, req Request, name, bidText string, up BlobUpload) error {
	bid, perr := ids.Parse(bidText)
	if perr != nil {
		return badInput("malformed blob id")
	}
	// The checks that need no body, outside the write lock; the rate-limit
	// tokens are drawn here, once.
	var g *blobGate
	err := e.read(ctx, func(t *tx) error {
		gg, err := t.gateBlob(req, name, bid, &up, true)
		g = gg
		return asErr(err)
	})
	if err != nil {
		return err
	}
	var data []byte
	if up.From == "" {
		data, err = io.ReadAll(io.LimitReader(up.Body, g.maxSize+1))
		if err != nil {
			return badInput("could not read the body")
		}
		if err := g.checkSize(int64(len(data))); err != nil {
			return err
		}
		if extra := int64(len(data)) - min(max(up.Length, 0), g.maxSize+1); extra > 0 {
			d := g.rate[len(g.rate)-1]
			d.cost = float64(extra)
			e.rate.charge(e.now(), d)
		}
		if ids.Blob(g.typ, g.nonce, data) != bid {
			return apiErr(422, "blob_mismatch", "message", "the body doesn't hash to the blob id (§3.7)")
		}
	}
	return e.update(ctx, func(t *tx) error {
		g, gerr := t.gateBlob(req, name, bid, &up, false)
		if gerr != nil {
			return gerr
		}
		size := int64(len(data))
		if g.src != nil {
			size = g.src.size
		}
		if err := g.checkSize(size); err != nil {
			return err
		}
		res := t.ensureResource(g.n, name)
		owner := t.bytesOwner(res)
		var hash []byte
		if g.src != nil {
			hash = g.src.hash
			if g.src.owner == owner {
				if !t.touchBytes(owner, hash) {
					return notFound()
				}
			} else {
				t.putBytes(owner, hash, t.readBytes(g.src.owner, hash))
			}
		} else {
			h := sha256.Sum256(data)
			hash = h[:]
			t.putBytes(owner, hash, data)
		}
		// An earlier entry of this uploader may name other bytes (its
		// namespace was encrypted since): collected after the upsert.
		var oldOwner int64
		var oldHash []byte
		hadOld := t.QueryRow(`SELECT owner, hash FROM blob_pending WHERE res = ? AND bid = ? AND uploader = ?`, res, bid[:], g.uploader).Scan(&oldOwner, &oldHash) == nil
		var nonce any
		if g.nonce != "" {
			nonce = g.nonce
		}
		// Uploading again restarts the grace time (§7.8).
		_, err := t.Exec(`INSERT INTO blob_pending (res, bid, uploader, type, nonce, size, hash, owner, created) VALUES (?,?,?,?,?,?,?,?,?)
			ON CONFLICT (res, bid, uploader) DO UPDATE SET type = excluded.type, nonce = excluded.nonce, size = excluded.size,
			hash = excluded.hash, owner = excluded.owner, created = excluded.created`,
			res, bid[:], g.uploader, g.typ, nonce, size, hash, owner, t.now.UnixMilli())
		t.must(err)
		if hadOld && (oldOwner != owner || !bytes.Equal(oldHash, hash)) {
			t.gcBytes(oldOwner, oldHash)
		}
		return nil
	})
}

// ensureResource returns name's resource row in n, inserting one without
// entries if there is none (a pending blob needs a row, D.2).
func (t *tx) ensureResource(n *nsRow, name string) int64 {
	if r := t.resource(n.id, name); r != nil {
		return r.id
	}
	_, err := t.Exec(`INSERT INTO resources (ns, name) VALUES (?, ?) ON CONFLICT (ns, name) DO NOTHING`, n.id, name)
	t.must(err)
	r := t.resource(n.id, name)
	if r == nil {
		panic(errors.New("inserting a resource row failed"))
	}
	return r.id
}

// --- reading ---------------------------------------------------------------------

// blobAnswer is what reading a blob would answer (§7.8 Reading).
type blobAnswer struct {
	status  int // 200, 404 or 410
	row     *blobRow
	pruned  *blobRow // 410 because pruning ended its attachment
	horizon string
	archive string
}

// servableBlob decides what GET /r/{ns}/{name}/blob/{bid} answers, access
// aside: the blobs attached to the resource and, in a branch, the base's
// blobs the branch's view references (§7.6). Pending and unknown blobs are
// 404; a purge, or pruning that ended the attachment, 410.
func (t *tx) servableBlob(n *nsRow, name string, bid ids.ID) blobAnswer {
	if n.purged {
		return blobAnswer{status: 410}
	}
	v := t.resolve(n, name, nil)
	if v.state == Purged {
		return blobAnswer{status: 410}
	}
	var pruned *blobRow
	var own int64
	if v.own != nil {
		own = v.own.id
		if b := t.attachedBlob(own, bid); b != nil {
			if !b.pruned {
				return blobAnswer{status: 200, row: b}
			}
			pruned = b
		}
	}
	if n.isBranch() && v.head != nil {
		live, p := t.historyBlob(v.head, own, bid)
		if live != nil {
			return blobAnswer{status: 200, row: live}
		}
		if pruned == nil {
			pruned = p
		}
	}
	if pruned != nil {
		ans := blobAnswer{status: 410, pruned: pruned, horizon: t.horizonID(pruned.res)}
		// The newest archive of a range that references the blob.
		err := t.QueryRow(`SELECT a.url FROM archives a WHERE a.res = ? AND EXISTS (SELECT 1 FROM blob_refs r
			WHERE r.res = a.res AND r.bid = ? AND r.from_seq <= a.to_seq AND (r.to_seq IS NULL OR r.to_seq > a.from_seq))
			ORDER BY a.seq DESC LIMIT 1`, pruned.res, bid[:]).Scan(&ans.archive)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
		return ans
	}
	return blobAnswer{status: 404}
}

// Blob is the answer of GET /r/{ns}/{name}/blob/{bid}, or in a sealed
// namespace of …/blob/{bid}/e/{e} (ReadSealedBlob).
type Blob struct {
	Status  int // 200, 404, 410; in sealed namespaces 302 to Epoch
	Epoch   int // the epoch a sealed namespace's 302 names (§E.2.2)
	NoStore bool
	Type    string
	Data    []byte
	Code    string // "pruned" for a 410 whose attachment pruning ended
	Horizon string
	Archive string
	Public  bool
}

// ReadBlob serves a blob (§7.8 Reading). Access is that of the resource.
func (e *Engine) ReadBlob(ctx context.Context, ns, name, bidText string, cred Credentials) (*Blob, error) {
	var out *Blob
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		out = &Blob{Public: t.cachePublic(n)}
		bid, perr := ids.Parse(bidText)
		if perr != nil {
			out.Status = 404
			return nil
		}
		ans := t.servableBlob(n, name, bid)
		out.Status = ans.status
		if ans.pruned != nil {
			out.Code, out.Horizon, out.Archive = "pruned", ans.horizon, ans.archive
		}
		if ans.status != 200 {
			return nil
		}
		if t.isSealedNS(n) {
			// Sealed namespaces never serve the plaintext: 302 to the blob
			// sealed under an epoch (§E.2.2, sealedblobs.go).
			t.sealedBlobHead(n, name, bid, out)
			return nil
		}
		out.Type, out.Data = ans.row.typ, t.readBytes(ans.row.owner, ans.row.hash)
		return nil
	})
	return out, err
}

// BlobStats counts what blob storage holds, for operators and tests.
type BlobStats struct {
	Attached  int // attachments in force
	Pruned    int // attachments pruning ended
	Pending   int // pending entries, expired or not
	Bytes     int // stored byte strings (blob_bytes rows)
	Encrypted int // of them, encrypted under a resource's data key
	Size      int64
}

// BlobStats counts the rows of blob storage.
func (e *Engine) BlobStats(ctx context.Context) (*BlobStats, error) {
	s := &BlobStats{}
	err := e.read(ctx, func(t *tx) error {
		t.must(t.QueryRow(`SELECT COUNT(*) FROM blobs WHERE pruned = 0`).Scan(&s.Attached))
		t.must(t.QueryRow(`SELECT COUNT(*) FROM blobs WHERE pruned = 1`).Scan(&s.Pruned))
		t.must(t.QueryRow(`SELECT COUNT(*) FROM blob_pending`).Scan(&s.Pending))
		t.must(t.QueryRow(`SELECT COUNT(*), COALESCE(SUM(octet_length(data)), 0) FROM blob_bytes`).Scan(&s.Bytes, &s.Size))
		t.must(t.QueryRow(`SELECT COUNT(*) FROM blob_bytes WHERE owner <> 0`).Scan(&s.Encrypted))
		return nil
	})
	return s, err
}

// --- the grace sweep -------------------------------------------------------------

// SweepBlobs deletes the pending entries older than their namespace's
// blobGrace, and the bytes nothing names any more (§7.8, D.2). Each
// namespace is swept in its own write transaction. It returns how many
// entries it deleted.
func (e *Engine) SweepBlobs(ctx context.Context) (int, error) {
	var nss []int64
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT DISTINCT r.ns FROM blob_pending p JOIN resources r ON r.res = p.res ORDER BY r.ns`)
		t.must(err)
		for rows.Next() {
			var ns int64
			t.must(rows.Scan(&ns))
			nss = append(nss, ns)
		}
		rows.Close()
		return nil
	})
	if err != nil {
		return 0, err
	}
	total := 0
	for _, ns := range nss {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var n int
		err := e.update(ctx, func(t *tx) error {
			nr := t.nsByIDLocked(ns, lockExclusive)
			cutoff := t.blobCutoff(t.config(nr.configSeq))
			where := `created < ? AND res IN (SELECT res FROM resources WHERE ns = ?)`
			t.must(t.QueryRow(`SELECT COUNT(*) FROM blob_pending WHERE `+where, cutoff, ns).Scan(&n))
			t.deletePending(where, cutoff, ns)
			return nil
		})
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// blobSweepLoop runs SweepBlobs every interval on the leader until Close.
func (e *Engine) blobSweepLoop(interval time.Duration) {
	defer e.bg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-e.stop:
				case <-ctx.Done():
				}
				cancel()
			}()
			if e.leader(ctx) {
				if _, err := e.SweepBlobs(ctx); err != nil && ctx.Err() == nil {
					log.Printf("blob sweep: %v", err)
				}
			}
			cancel()
		}
	}
}

// defaultBlobLimits fills blob limits left zero by options from before
// blobs existed.
func defaultBlobLimits(l *Limits, d Limits) {
	if l.BlobSize == 0 {
		l.BlobSize = d.BlobSize
	}
	if l.BlobPending == 0 {
		l.BlobPending = d.BlobPending
	}
	if l.BlobGrace == 0 {
		l.BlobGrace = d.BlobGrace
	}
	if l.BlobRate == (Rate{}) {
		l.BlobRate = d.BlobRate
	}
}
