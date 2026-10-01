package core

// Blobs of sealed namespaces (§7.8, §E.2.2).
//
// A blob outlives epochs, so GET /r/{ns}/{name}/blob/{bid} answers 302 to
// …/blob/{bid}/e/{e}, the latest epoch the blob is served under, and that
// URL serves the blob in the binary sealed form (seal.SealBlob) with the
// header {enc, kid "{ns}#{e}", pl {ns, name, blob}}, under the resource's
// K_r of epoch e, so per-resource readers can open it.
//
// Epochs served. They are exactly those under which this namespace serves a
// revision whose document references the blob: blob_refs says which
// revisions reference it, and each revision's epoch is the one it was
// written in (rev_epochs) or, for content without one (read through from a
// base, or written before the namespace became sealed), that of its stored
// sealing (sealed.go), which exists once a reader fetched it. Revisions
// pruned away (below the horizon and not kept) don't count. D.2 keeps a
// row per served epoch in blob_epochs; here the epochs are derived from
// those tables when asked, and blob_epochs holds only what can't be: the
// stored sealings, and a marker (data NULL) for an epoch whose referencing
// revisions pruning removed, which answers 410 as in §7.1. Other epochs
// are 404 with no-store: a branch may yet serve a read-through revision
// under a new epoch.
//
// Stored once, served forever. An epoch's sealing is produced on its first
// read and stored (INSERT … ON CONFLICT), the first one stored winning when
// two instances seal at once; only the stored bytes are served, with ETag
// "{bid}.{e}". Purges delete the rows, and so does pruning that ends the
// attachment. With a blob directory a sealing is a file the row names, as
// blob bytes are (blobstore.go): the row stays the arbiter of which one won,
// and a loser's file is deleted.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// servedRev is the condition that a revision row r (of resource row rs)
// is still served: at or after its resource's horizon, or kept (§8.6).
const servedRev = `(rs.horizon_seq IS NULL OR r.seq >= rs.horizon_seq OR EXISTS (SELECT 1 FROM snapshots k WHERE k.seq = r.seq))`

// refRevs joins the revisions whose documents reference a blob (blob_refs
// intervals) with their resource rows.
const refRevs = ` FROM blob_refs b JOIN revisions r ON r.res = b.res AND r.seq >= b.from_seq AND (b.to_seq IS NULL OR r.seq < b.to_seq)
	JOIN resources rs ON rs.res = r.res`

// blobEpochs lists the epochs under which n serves a revision of the
// history ending at head whose document references bid (§E.2.2).
func (t *tx) blobEpochs(n *nsRow, head *revRow, bid ids.ID) map[int]bool {
	out := map[int]bool{}
	if head == nil {
		return out
	}
	where := ` WHERE b.res = ? AND b.bid = ? AND r.seq <= ? AND r.kind = 0 AND ` + servedRev
	for _, seg := range t.ancestry(head) {
		var segNS int64
		t.must(t.QueryRow(`SELECT ns FROM resources WHERE res = ?`, seg.res).Scan(&segNS))
		own := segNS == n.id
		if own {
			// n's own revisions are sealed under the epoch they were written in.
			rows, err := t.Query(`SELECT DISTINCT e.epoch`+refRevs+` JOIN rev_epochs e ON e.seq = r.seq`+where, seg.res, bid[:], seg.max)
			t.must(err)
			for rows.Next() {
				var e int
				t.must(rows.Scan(&e))
				out[e] = true
			}
			rows.Close()
		}
		// Content without an epoch of its own: that of its stored sealing.
		q := `SELECT substr(s.jwe, 1, 4096)` + refRevs + ` JOIN sealed s ON s.ns = ? AND s.rev_seq = r.seq AND s.kind IN ('doc', 'entry')` + where
		args := []any{n.id, seg.res, bid[:], seg.max}
		if own {
			q += ` AND NOT EXISTS (SELECT 1 FROM rev_epochs e WHERE e.seq = r.seq)`
		}
		rows, err := t.Query(q, args...)
		t.must(err)
		for rows.Next() {
			var prefix string
			t.must(rows.Scan(&prefix))
			if e, ok := jweEpoch(prefix); ok {
				out[e] = true
			}
		}
		rows.Close()
	}
	return out
}

// jweEpoch is the epoch of the kid in a stored JWE's protected header.
func jweEpoch(jwe string) (int, bool) {
	seg, _, _ := strings.Cut(jwe, ".")
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return 0, false
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		return 0, false
	}
	m, _ := v.(map[string]any)
	kid, _ := m["kid"].(string)
	_, e, err := seal.ParseKid(kid)
	return e, err == nil
}

// latestEpoch is the largest of eps, or 0.
func latestEpoch(eps map[int]bool) int {
	best := 0
	for e := range eps {
		best = max(best, e)
	}
	return best
}

// sealedBlobHead fills the answer of GET /r/{ns}/{name}/blob/{bid} for a
// blob n serves (status 200 so far): 302 to the latest epoch it is served
// under, or 404 (no-store) if there is none yet (§E.2.2).
func (t *tx) sealedBlobHead(n *nsRow, name string, bid ids.ID, out *Blob) {
	v := t.resolve(n, name, nil)
	if e := latestEpoch(t.blobEpochs(n, v.head, bid)); e > 0 {
		out.Status, out.Epoch = 302, e
		return
	}
	out.Status, out.NoStore = 404, true
}

// sealedBlobJob is the sealing of a blob under one epoch, to store.
type sealedBlobJob struct {
	ns    int64
	name  string
	bid   ids.ID
	epoch int
	key   []byte
	kid   string
	pl    seal.PL
	plain []byte
	pad   bool
}

// ReadSealedBlob answers GET /r/{ns}/{name}/blob/{bid}/e/{e} (§E.2.2): the
// blob sealed under epoch e, if n serves it under e. Other epochs are 404
// with NoStore, or 410 pruned once pruning removed every revision of the
// epoch that references it. Only sealed namespaces have this URL.
func (e *Engine) ReadSealedBlob(ctx context.Context, ns, name, bidText, epochText string, cred Credentials) (*Blob, error) {
	b, err := e.OpenSealedBlob(ctx, ns, name, bidText, epochText, cred)
	if err != nil {
		return nil, err
	}
	return b.readAll()
}

// OpenSealedBlob is ReadSealedBlob with the bytes in Content, read from
// their file if stored in one.
func (e *Engine) OpenSealedBlob(ctx context.Context, ns, name, bidText, epochText string, cred Credentials) (*Blob, error) {
	return readAgain(func() (*Blob, error) { return e.openSealedBlob(ctx, ns, name, bidText, epochText, cred, true) })
}

func (e *Engine) openSealedBlob(ctx context.Context, ns, name, bidText, epochText string, cred Credentials, again bool) (*Blob, error) {
	var out *Blob
	var job *sealedBlobJob
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
		ep, eerr := strconv.Atoi(epochText)
		if perr != nil || eerr != nil || ep < 1 || strconv.Itoa(ep) != epochText || !t.isSealedNS(n) {
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
		v := t.resolve(n, name, nil)
		var data []byte
		var file sql.NullString
		var row bool
		err := t.QueryRow(`SELECT data, file FROM blob_epochs WHERE ns = ? AND name = ? AND bid = ? AND epoch = ?`, n.id, name, bid[:], ep).Scan(&data, &file)
		switch {
		case err == nil:
			row = true
		case !errors.Is(err, sql.ErrNoRows):
			t.must(err)
		}
		if !t.blobEpochs(n, v.head, bid)[ep] {
			if row {
				// Every revision of that epoch referencing it was pruned.
				out.Status, out.Code = 410, "pruned"
				out.Horizon = t.horizonID(ans.row.res)
				return nil
			}
			out.Status, out.NoStore = 404, true
			return nil
		}
		out.Type = SealedBlobType
		switch {
		case file.Valid:
			out.setContent(fileContent(t.openFile(file.String)))
			return nil
		case data != nil:
			out.setContent(memContent(data))
			return nil
		}
		k, err := seal.ResourceKey(t.epochKey(n.id, ep), n.name, name)
		t.must(err)
		job = &sealedBlobJob{ns: n.id, name: name, bid: bid, epoch: ep, key: k, kid: seal.Kid(n.name, ep),
			pl: seal.BlobPL(n.name, name, bid.String()), plain: t.readBytes(ans.row.owner, ans.row.hash), pad: t.config(n.configSeq).Pad}
		return nil
	})
	if err != nil {
		out.Close()
		return nil, err
	}
	if job == nil {
		return out, nil
	}
	sealed, err := seal.SealBlob(job.key, job.kid, job.pl, job.plain, job.pad)
	if err != nil {
		return nil, err
	}
	stored, err := e.storeSealedBlob(ctx, job, sealed)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		// Purged or pruned meanwhile: answer as a read now would.
		if again {
			return e.openSealedBlob(ctx, ns, name, bidText, epochText, cred, false)
		}
		return &Blob{Status: 404, NoStore: true, Public: out.Public}, nil
	}
	out.setContent(memContent(stored))
	return out, nil
}

// storeSealedBlob stores job's sealing unless one is stored already, and
// returns the stored bytes: the first stored wins (§E.2.2). It returns nil
// if the blob is no longer served under the epoch (a purge or a prune
// committed since the read).
func (e *Engine) storeSealedBlob(ctx context.Context, job *sealedBlobJob, sealed []byte) ([]byte, error) {
	var out []byte
	err := e.update(ctx, func(t *tx) error {
		// Shared: purges and prunes, which delete or mark these rows,
		// lock exclusively.
		n := t.nsByIDLocked(job.ns, lockShared)
		if n == nil || n.purged || t.servableBlob(n, job.name, job.bid).status != 200 {
			return nil
		}
		if !t.blobEpochs(n, t.resolve(n, job.name, nil).head, job.bid)[job.epoch] {
			return nil
		}
		var data, file any = sealed, nil
		mine := t.storeFile(epochFile(job.ns, job.bid[:], job.epoch), sealed)
		if mine != "" {
			data, file = nil, mine
		}
		_, err := t.Exec(`INSERT INTO blob_epochs (ns, name, bid, epoch, data, file, created) VALUES (?,?,?,?,?,?,?)
			ON CONFLICT (ns, name, bid, epoch) DO UPDATE SET data = excluded.data, file = excluded.file, created = excluded.created
			WHERE blob_epochs.data IS NULL AND blob_epochs.file IS NULL`,
			job.ns, job.name, job.bid[:], job.epoch, data, file, t.now.UnixMilli())
		t.must(err)
		var stored sql.NullString
		t.must(t.QueryRow(`SELECT data, file FROM blob_epochs WHERE ns = ? AND name = ? AND bid = ? AND epoch = ?`, job.ns, job.name, job.bid[:], job.epoch).Scan(&out, &stored))
		switch {
		case stored.String == mine && mine != "":
			out = sealed
		case stored.Valid:
			out = t.readFile(stored.String)
		}
		if mine != "" && stored.String != mine {
			t.discardFile(mine)
		}
		return nil
	})
	return out, err
}

// deleteBlobEpochs deletes the stored sealings of blobs matching where, a
// condition on ns and name (purges, §8.3, §8.5).
func (t *tx) deleteBlobEpochs(where string, args ...any) {
	t.dropEpochFiles(where, args...)
	_, err := t.Exec(`DELETE FROM blob_epochs WHERE `+where, args...)
	t.must(err)
}

// dropEpochFiles deletes the files of the sealings matching where once the
// transaction, which deletes or clears their rows, commits.
func (t *tx) dropEpochFiles(where string, args ...any) {
	rows, err := t.Query(`SELECT file FROM blob_epochs WHERE file IS NOT NULL AND `+where, args...)
	t.must(err)
	for rows.Next() {
		var f string
		t.must(rows.Scan(&f))
		t.dropFile(f)
	}
	rows.Close()
}

// resourceBlobEpochs lists, for every blob attached to own, the epochs n
// serves it under: what a prune compares against afterwards.
func (t *tx) resourceBlobEpochs(n *nsRow, own *resRow) map[ids.ID]map[int]bool {
	out := map[ids.ID]map[int]bool{}
	if !own.headSeq.Valid {
		return out
	}
	head := t.rev(own.headSeq.Int64)
	rows, err := t.Query(`SELECT bid FROM blobs WHERE res = ? AND pruned = 0`, own.id)
	t.must(err)
	var bids []ids.ID
	for rows.Next() {
		var b []byte
		t.must(rows.Scan(&b))
		bids = append(bids, ids.FromBytes(b))
	}
	rows.Close()
	for _, bid := range bids {
		out[bid] = t.blobEpochs(n, head, bid)
	}
	return out
}

// pruneBlobEpochs runs after a prune of resource name (row res) of n, given
// the epochs each blob was served under before (§E.2.2): the sealings of a
// blob whose attachment ended go, and an epoch no longer served is marked
// (410), its sealing deleted.
func (t *tx) pruneBlobEpochs(n *nsRow, name string, res int64, before map[ids.ID]map[int]bool) {
	bids := make([]ids.ID, 0, len(before))
	for bid := range before {
		bids = append(bids, bid)
	}
	sort.Slice(bids, func(i, j int) bool { return string(bids[i][:]) < string(bids[j][:]) })
	var head *revRow
	for _, bid := range bids {
		if b := t.attachedBlob(res, bid); b == nil || b.pruned {
			t.deleteBlobEpochs(`ns = ? AND name = ? AND bid = ?`, n.id, name, bid[:])
			continue
		}
		if head == nil {
			head = t.rev(t.resource(n.id, name).headSeq.Int64)
		}
		now := t.blobEpochs(n, head, bid)
		for ep := range before[bid] {
			if now[ep] {
				continue
			}
			t.dropEpochFiles(`ns = ? AND name = ? AND bid = ? AND epoch = ?`, n.id, name, bid[:], ep)
			_, err := t.Exec(`INSERT INTO blob_epochs (ns, name, bid, epoch, data, created) VALUES (?,?,?,?,NULL,?)
				ON CONFLICT (ns, name, bid, epoch) DO UPDATE SET data = NULL, file = NULL`, n.id, name, bid[:], ep, t.now.UnixMilli())
			t.must(err)
		}
	}
}
