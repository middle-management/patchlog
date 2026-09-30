package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// Archiver stores pruning archives (§8.6). The core hands it the pruned
// range as an ArchiveBundle; the implementation encodes it as a
// full-history bundle (§G.4.1) and streams it to storage. See
// internal/archive for the file:// implementation.
//
// Archives are keyed per resource and horizon:
//
//	{ns}/{name}/{horizon}.jsonl
//
// where horizon is the id of the new horizon, the first revision the prune
// keeps. The archive holds the revisions from the previous horizon (or
// genesis) up to the one before the new horizon; an incremental archive
// names the last revision of the one before it in `requires`.
type Archiver interface {
	// Check reports whether dest may be written. "" is the operator's
	// default destination, and is an error if there is none.
	Check(dest string) error
	// Write stores the archive under key in dest ("" = the default) and
	// returns its URL. It must not leave a partial archive at the URL.
	Write(ctx context.Context, dest, key string, b *ArchiveBundle) (url string, err error)
	// Delete removes an archive written earlier. An archive that is already
	// gone is not an error.
	Delete(ctx context.Context, url string) error
	// Open reads an archive back (restore, §D.4).
	Open(ctx context.Context, url string) (io.ReadCloser, error)
}

// ArchiveBundle is one resource's pruned range, to be written as a
// full-history bundle with authors.
type ArchiveBundle struct {
	Origin   string
	Created  time.Time
	NS, Name string
	At       string // the namespace head when the archive was taken
	Head     string // the last entry's id
	Requires string // "" from genesis, else the entry before the first one
	// Entries calls yield for each entry in chain order, streaming from the
	// database. It stops at the first error yield returns.
	Entries func(yield func(ArchiveEntry) error) error
	// Seal, when set, is an encrypted namespace's (Addendum E.1): the
	// archiver writes the encoded bundle through the writer it returns
	// and closes it, so the archive is stored encrypted under a key
	// derived from the resource's data key (crypt.go). Engine.OpenArchive
	// reads it back.
	Seal func(w io.Writer) (io.WriteCloser, error)
}

// ArchiveEntry is one history line of an archive.
type ArchiveEntry struct {
	ID, Parent, Kind string // Kind "rev" or "tombstone"
	Patches          any    // jsonv value; revisions only
	Author, Created  string
	Signature        string
}

// ArchiveKey is the archive naming scheme.
func ArchiveKey(ns, name, horizon string) string { return ns + "/" + name + "/" + horizon + ".jsonl" }

// archiveDest resolves where a prune of a resource under rule archives to.
// ok is false if there is nowhere to archive: no archiver, no default, or a
// rule destination the operator doesn't (or no longer does) allow.
func (t *tx) archiveDest(rule *RetentionRule) (dest string, ok bool) {
	a := t.e.opt.Archiver
	if a == nil {
		return "", false
	}
	if rule != nil {
		dest = rule.Archive
	}
	if a.Check(dest) != nil {
		return "", false
	}
	return dest, true
}

// writeArchive writes res's entries from fromSeq up to (excluding) h as an
// archive and records it. It returns the archive's URL.
func (t *tx) writeArchive(n *nsRow, name string, res int64, fromSeq int64, h *revRow, dest string) (string, error) {
	var lastSeq int64
	t.must(t.QueryRow(`SELECT MAX(seq) FROM revisions WHERE res = ? AND seq < ?`, res, h.seq).Scan(&lastSeq))
	first := t.rev(fromSeq)
	b := &ArchiveBundle{
		Origin:  t.e.opt.Origin,
		Created: t.now,
		NS:      n.name,
		Name:    name,
		At:      t.nsLogID(n.headSeq.Int64).String(),
		Head:    t.rev(lastSeq).id.String(),
	}
	if b.Origin == "" {
		b.Origin = "http://localhost"
	}
	if first.parentSeq.Valid {
		b.Requires = t.rev(first.parentSeq.Int64).id.String()
	}
	b.Seal = t.archiveSealer(res)
	b.Entries = func(yield func(ArchiveEntry) error) error {
		after := fromSeq - 1
		for {
			// Batches, so no query is open while yield writes.
			rows, err := t.Query(`SELECT `+revCols+` FROM revisions WHERE res = ? AND seq > ? AND seq <= ? ORDER BY seq LIMIT 256`, res, after, lastSeq)
			if err != nil {
				return err
			}
			var batch []*revRow
			for rows.Next() {
				r, err := scanRev(rows)
				if err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, r)
			}
			rows.Close()
			if len(batch) == 0 {
				return nil
			}
			for _, r := range batch {
				le := t.logEntry(r)
				if r.kind == kindRev && le.Patches == nil {
					return fmt.Errorf("revision %s has no patch set to archive", le.ID)
				}
				if err := yield(ArchiveEntry{ID: le.ID, Parent: le.Parent, Kind: le.Kind, Patches: le.Patches,
					Author: le.Author, Created: le.Created, Signature: le.Signature}); err != nil {
					return err
				}
				after = r.seq
			}
		}
	}
	key := ArchiveKey(n.name, name, h.id.String())
	ctx := t.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := t.e.opt.Archiver.Write(ctx, dest, key, b)
	if err != nil {
		return "", fmt.Errorf("writing archive %s: %w", key, err)
	}
	_, err = t.Exec(`INSERT INTO archives (res, from_seq, to_seq, key, url, created) VALUES (?,?,?,?,?,?)`,
		res, fromSeq, lastSeq, key, u, t.now.UnixMilli())
	t.must(err)
	return u, nil
}

// archiveURL returns the URL of the newest archive holding revision seq of
// res, or "".
func (t *tx) archiveURL(res, seq int64) string {
	var u string
	err := t.QueryRow(`SELECT url FROM archives WHERE res = ? AND from_seq <= ? AND to_seq >= ? ORDER BY seq DESC LIMIT 1`, res, seq, seq).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	t.must(err)
	return u
}

// prunedInfo is the horizon and archive of the 410 of §7.1.
func (t *tx) prunedInfo(pe *prunedError) (horizon, archive string) {
	return t.horizonID(pe.res), t.archiveURL(pe.res, pe.seq)
}

// deleteArchives deletes the archives of the resources matched by where
// (a condition on archives.res) and their rows (§8.3: purge reaches
// archives).
func (t *tx) deleteArchives(where string, args ...any) {
	rows, err := t.Query(`SELECT seq, url FROM archives WHERE `+where, args...)
	t.must(err)
	var seqs []int64
	var urls []string
	for rows.Next() {
		var s int64
		var u string
		t.must(rows.Scan(&s, &u))
		seqs = append(seqs, s)
		urls = append(urls, u)
	}
	rows.Close()
	if len(seqs) == 0 {
		return
	}
	if t.e.opt.Archiver == nil {
		t.must(errors.New("the resource has archives but no archiver is configured to delete them"))
	}
	ctx := t.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	done := map[string]bool{}
	for i, s := range seqs {
		if !done[urls[i]] {
			if err := t.e.opt.Archiver.Delete(ctx, urls[i]); err != nil {
				t.must(fmt.Errorf("deleting archive %s: %w", urls[i], err))
			}
			done[urls[i]] = true
		}
		_, err := t.Exec(`DELETE FROM archives WHERE seq = ?`, s)
		t.must(err)
	}
}

// ArchiveRecord is an archive of an unpurged resource.
type ArchiveRecord struct {
	NS, Name string
	Key, URL string
	From, To string // ids of the first and last archived entries
	Created  string
}

// Archives lists the archives of unpurged resources, optionally only of one
// namespace or one resource, in chain order per resource.
func (e *Engine) Archives(ctx context.Context, ns, name string) ([]ArchiveRecord, error) {
	var out []ArchiveRecord
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT n.name, r.name, a.key, a.url, a.from_seq, a.to_seq, a.created
			FROM archives a JOIN resources r ON r.res = a.res JOIN namespaces n ON n.ns = r.ns
			WHERE n.purged = 0 AND r.state != ? AND (? = '' OR n.name = ?) AND (? = '' OR r.name = ?)
			ORDER BY n.name, r.name, a.from_seq, a.seq`, statePurged, ns, ns, name, name)
		t.must(err)
		type raw struct {
			rec      ArchiveRecord
			from, to int64
			created  int64
		}
		var rs []raw
		for rows.Next() {
			var x raw
			t.must(rows.Scan(&x.rec.NS, &x.rec.Name, &x.rec.Key, &x.rec.URL, &x.from, &x.to, &x.created))
			rs = append(rs, x)
		}
		rows.Close()
		for _, x := range rs {
			x.rec.From, x.rec.To = t.rev(x.from).id.String(), t.rev(x.to).id.String()
			x.rec.Created = formatTime(x.created)
			out = append(out, x.rec)
		}
		return nil
	})
	return out, err
}

// RestoreResult reports a restore of one resource.
type RestoreResult struct {
	Restored int  // patch sets re-inserted
	Present  int  // entries whose patch set was already there, or tombstones
	Skipped  int  // entries with no matching kept row, or whose id didn't match
	Purged   bool // the resource is purged, so nothing was restored (§8.3)
	Cleared  bool // every pruned patch set is back, so the horizon was cleared
}

// RestoreResource re-inserts archived patch sets of ns/name (§D.4, an
// offline task): each entry whose recomputed id matches the kept row gets
// its patch set back. Once no revision below the horizon lacks its patch
// set, horizon_seq and keep are cleared. Documents kept at the old horizon
// stay as snapshots, and intermediate snapshots are rebuilt over the
// restored range so no fold grows past the D.4 bound. Purged resources are
// skipped. entries is called once, inside the write transaction.
func (e *Engine) RestoreResource(ctx context.Context, ns, name string, entries func(yield func(ArchiveEntry) error) error) (*RestoreResult, error) {
	out := &RestoreResult{}
	err := e.update(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		own := t.resource(n.id, name)
		if n.purged || (own != nil && own.state == statePurged) {
			out.Purged = true
			return entries(func(ArchiveEntry) error { return nil })
		}
		if own == nil {
			return notFound()
		}
		err := entries(func(en ArchiveEntry) error {
			id, err := ids.Parse(en.ID)
			if err != nil {
				out.Skipped++
				return nil
			}
			row, err := scanRev(t.QueryRow(`SELECT `+revCols+` FROM revisions WHERE res = ? AND id = ?`, own.id, id[:]))
			if errors.Is(err, sql.ErrNoRows) {
				out.Skipped++
				return nil
			}
			t.must(err)
			if row.kind == kindTombstone || row.patches.Valid {
				out.Present++
				return nil
			}
			if en.Kind != "rev" || en.Patches == nil {
				out.Skipped++
				return nil
			}
			var parent *ids.ID
			parentText := ""
			if row.parentSeq.Valid {
				p := t.rev(row.parentSeq.Int64).id
				parent, parentText = &p, p.String()
			}
			canon := jsonv.Canonical(en.Patches)
			if en.Parent != parentText || ids.Revision(parent, canon) != row.id {
				out.Skipped++
				return nil
			}
			if _, err := patch.Parse(jsonv.MustParse(canon)); err != nil {
				out.Skipped++
				return nil
			}
			_, err = t.Exec(`UPDATE revisions SET patches = ? WHERE seq = ?`, t.putPatches(own.id, row.id, canon), row.seq)
			t.must(err)
			out.Restored++
			return nil
		})
		if err != nil {
			return err
		}
		if out.Restored > 0 {
			t.flushDocs = true
		}
		if !own.horizonSeq.Valid {
			return nil
		}
		var missing bool
		t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ? AND seq < ? AND kind = 0 AND patches IS NULL)`, own.id, own.horizonSeq.Int64).Scan(&missing))
		if missing {
			return nil
		}
		if err := t.rebuildSnapshots(own.id, own.horizonSeq.Int64); err != nil {
			return err
		}
		_, err = t.Exec(`UPDATE resources SET horizon_seq = NULL, keep = NULL WHERE res = ?`, own.id)
		t.must(err)
		t.flushDocs = true
		t.tags = append(t.tags, "r:"+n.name+"/"+name)
		out.Cleared = true
		return nil
	})
	return out, err
}

// rebuildSnapshots folds res's chain from its first entry up to (excluding)
// upTo and writes an intermediate snapshot wherever D.4's thresholds are
// reached since the previous one. Existing snapshots (kept documents) stay
// and count as snapshots.
func (t *tx) rebuildSnapshots(res, upTo int64) error {
	var doc any
	exists := false
	var count, size int
	after := int64(0)
	for {
		rows, err := t.Query(`SELECT seq, id, kind, patches FROM revisions WHERE res = ? AND seq > ? AND seq < ? ORDER BY seq LIMIT 512`, res, after, upTo)
		t.must(err)
		type r struct {
			seq     int64
			id      []byte
			kind    int
			patches sql.NullString
		}
		var batch []r
		for rows.Next() {
			var x r
			t.must(rows.Scan(&x.seq, &x.id, &x.kind, &x.patches))
			batch = append(batch, x)
		}
		rows.Close()
		if len(batch) == 0 {
			return nil
		}
		for _, x := range batch {
			after = x.seq
			if x.kind != kindRev {
				continue
			}
			canon := t.patchesOf(&revRow{res: res, id: ids.FromBytes(x.id), patches: x.patches})
			ops, err := patch.Parse(jsonv.MustParse(canon))
			if err != nil {
				return err
			}
			doc, _, err = patch.Apply(doc, exists, ops, patch.Options{})
			if err != nil {
				return err
			}
			exists = true
			count++
			size += len(canon)
			var has bool
			t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM snapshots WHERE seq = ?)`, x.seq).Scan(&has))
			if has {
				count, size = 0, 0
				continue
			}
			if count >= t.e.opt.SnapshotEveryRevisions || size >= t.e.opt.SnapshotEveryBytes {
				_, err := t.Exec(`INSERT INTO snapshots (seq, res, doc) VALUES (?,?,?)`, x.seq, res, t.putDoc("snapshots", res, x.seq, jsonv.Canonical(doc)))
				t.must(err)
				count, size = 0, 0
			}
		}
	}
}
