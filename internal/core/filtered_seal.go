package core

import (
	"context"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// Filtered answers in sealed namespaces (§7.9 Sealed namespaces, §E.2.2
// Filtered answers, v0.89).
//
// A partial reader's only key is its view's K_view (§E.2.3). Each filtered
// answer, a log range or long-poll answer, a /heads page or an event, is
// one JWE under the K_view of the current epoch, with the unfiltered
// form's pl and view added, whose plaintext is { body, keys }: body the
// answer as §7.9 gives it, keys a view's keys JWE for each visible
// revision the body names, tombstones and revisions of purged resources
// excepted (v0.90), in the order it first names them. A view's keys for
// a revision, { key, log?, blobs }, hold its K_rev, its K_log only where
// §7.9 shows its entry with patches (its parent, or the document a
// tombstone parent deleted, is visible), and the K_blob of each blob its
// document references; they are sealed once under the K_view of the
// revision's epoch and stored (kind "keys", keyed by view, name and id),
// which fixes that epoch as serving the revision would (revEpochFixed). A resource log entry the body shows with patches is its
// stored JWE under its K_log, so content stays under its revision's epoch;
// any other entry is plain inside the answer. To an unrestricted reader's
// /ns/{ns} cookie at a view's URL the answers are sealed under K_n instead
// and carry no keys ("keys": []): it derives every key from K_e.
//
// Answers are sealed when produced and never stored, each sealing counted
// under K_view (jobSealKey), and the inner sealings (the stored keys and
// entries) are stored first (finishSeal), the first stored winning, so
// the answer carries the bytes every reader gets.

// sealKeys is the sealed kind of a view's keys for a revision.
const sealKeys = "keys"

// namedRev is a revision of resource name a filtered answer names.
type namedRev struct {
	name string
	row  *revRow
}

// fsealing is the sealing of one filtered answer at E2.
type fsealing struct {
	ns   int64
	kid  string
	k    []byte
	pl   seal.PL
	pad  bool
	view string // counted under K_view; "" under K_n
	// keys are the view's keys of the revisions the body names; inner the
	// stored entries it holds, which body reads once they are sealed.
	keys, inner []*sealJob
	body        func() any
}

// filteredSealing prepares the sealing of a filtered answer of fv in n
// with the unfiltered form's pl, naming revs, if n is sealed: nil
// otherwise. body is called once the inner sealings are stored.
func (t *tx) filteredSealing(n *nsRow, fv *fview, pl seal.PL, revs []namedRev, inner []*sealJob, body func() any) *fsealing {
	cfg := t.config(n.configSeq)
	if cfg.level != levelSealed {
		return nil
	}
	e := cfg.Epoch
	fs := &fsealing{ns: n.id, kid: seal.Kid(n.name, e), pl: seal.WithView(pl, fv.view), pad: cfg.Pad, inner: inner, body: body}
	if fv.unrestricted {
		fs.k = t.namespaceKey(n, e)
		return fs
	}
	fs.k, fs.view = t.viewKey(n, e, fv.view), fv.view
	seen := map[ids.ID]bool{}
	purged := map[int64]bool{}
	for _, r := range revs {
		if r.row == nil || r.row.kind == kindTombstone || seen[r.row.id] {
			continue
		}
		seen[r.row.id] = true
		// None for a purged resource's revisions, whose view keys the
		// purge removed (§E.2.2 Filtered answers, §8.3 Effect, v0.90).
		p, ok := purged[r.row.res]
		if !ok {
			p = t.resPurged(r.row.res)
			purged[r.row.res] = p
		}
		if p {
			continue
		}
		fs.keys = append(fs.keys, t.viewKeysJob(n, fv.view, r.name, r.row, t.parentShown(fv, r.name, r.row)))
	}
	return fs
}

// parentShown reports whether §7.9 shows row's resource log entry with
// patches to fv: a genesis, or one whose parent revision, or the document
// a tombstone parent deleted, is visible.
func (t *tx) parentShown(fv *fview, name string, row *revRow) bool {
	if !row.parentSeq.Valid {
		return true
	}
	return fv.visible(t, name, t.rev(row.parentSeq.Int64))
}

// viewKeysJob prepares the sealing of view's keys for revision row of
// resource name, served by n (§E.2.2): stored once, under the K_view of
// the revision's epoch, with pl { ns, view, name, id, kind: "keys" }.
func (t *tx) viewKeysJob(n *nsRow, view, name string, row *revRow, withLog bool) *sealJob {
	id := row.id.String()
	j := &sealJob{kind: sealKeys, key: view + "/" + name + "/" + id, name: name, revSeq: row.seq, view: view}
	if t.stored(n, j) {
		return j
	}
	e := t.revEpoch(n, row)
	kr := t.resourceKey(n, e, name)
	vk := seal.ViewKeys{Blobs: map[string][]byte{}}
	var err error
	vk.Key, err = seal.RevKey(kr, id)
	t.must(err)
	if withLog {
		vk.Log, err = seal.LogKey(kr, id)
		t.must(err)
	}
	if _, derr := t.docBytesAt(row); derr == nil {
		// The blobs its document references; none once it is no longer
		// stored (§E.2.2).
		for _, bid := range t.revBlobs(row) {
			vk.Blobs[bid], err = seal.BlobKey(kr, bid)
			t.must(err)
		}
	}
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.viewKey(n, e, view), seal.ViewKeysPL(n.name, view, name, id), vk.Plaintext()
	j.pad = t.config(n.configSeq).Pad
	return j
}

// revBlobs lists the ids of the blobs revision row's document references
// (blob_refs), in text form.
func (t *tx) revBlobs(row *revRow) []string {
	rows, err := t.Query(`SELECT bid FROM blob_refs WHERE res = ? AND from_seq <= ? AND (to_seq IS NULL OR ? < to_seq) ORDER BY bid`, row.res, row.seq, row.seq)
	t.must(err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b []byte
		t.must(rows.Scan(&b))
		out = append(out, ids.FromBytes(b).String())
	}
	t.must(rows.Err())
	return out
}

// sealFiltered stores fs's inner sealings, then seals the answer, counted
// first, and returns its JWE (§E.2.2).
func (e *Engine) sealFiltered(ctx context.Context, fs *fsealing) (string, error) {
	if err := e.finishSeal(ctx, fs.ns, append(append([]*sealJob(nil), fs.inner...), fs.keys...)); err != nil {
		return "", err
	}
	keys := make([]string, len(fs.keys))
	for i, j := range fs.keys {
		keys[i] = j.jwe
	}
	j := &sealJob{kid: fs.kid, k: fs.k, pl: fs.pl, plain: seal.FilteredPlaintext(fs.body(), keys), pad: fs.pad, view: fs.view}
	if err := e.finishSeal(ctx, fs.ns, []*sealJob{j}); err != nil {
		return "", err
	}
	return j.jwe, nil
}

// sealFilteredLog seals lg's filtered answer, prepared with the read
// (Log.fseals): one JWE as its Range, or, for events, one per entry as its
// EntryJWEs. lg is then Sealed.
func (e *Engine) sealFilteredLog(ctx context.Context, lg *Log) error {
	if lg == nil || lg.fseals == nil {
		return nil
	}
	jwes := make([]string, len(lg.fseals))
	for i, fs := range lg.fseals {
		j, err := e.sealFiltered(ctx, fs)
		if err != nil {
			return err
		}
		jwes[i] = j
	}
	lg.Sealed = true
	if lg.fsEvents {
		lg.EntryJWEs = jwes
	} else if len(jwes) == 1 {
		lg.Range = jwes[0]
	}
	lg.fseals = nil
	return nil
}

// filteredRangeSealing prepares the sealing of lg, a page of n's log as fv
// sees it after since (filteredRange), if n is sealed: as one range or
// long-poll answer, pl { ns, view, range: [since, last] }, last the last
// entry scanned or, where none was, the range's end toID; or, for events,
// one per entry, pl { ns, view, event: id }.
func (t *tx) filteredRangeSealing(n *nsRow, fv *fview, since, toID string, lg *Log, events bool) {
	if lg.Status != 200 || t.config(n.configSeq).level != levelSealed {
		return
	}
	lg.fsEvents = events
	if events {
		for i, m := range lg.Entries {
			m := m
			id, _ := m["id"].(string)
			fs := t.filteredSealing(n, fv, seal.NamespaceEventPL(n.name, id), lg.named[i], nil, func() any { return m })
			lg.fseals = append(lg.fseals, fs)
		}
		return
	}
	last := lg.Last
	if last == since {
		last = toID
	}
	var revs []namedRev
	for _, rs := range lg.named {
		revs = append(revs, rs...)
	}
	entries := make([]any, len(lg.Entries))
	for i, m := range lg.Entries {
		entries[i] = m
	}
	lg.fseals = []*fsealing{t.filteredSealing(n, fv, seal.RangePL(n.name, since, last), revs, nil, func() any { return entries })}
}

// filteredHeadsSealing prepares the sealing of a filtered /heads page of n
// at cp after after, page holding rows, for fv: pl { ns, view, at, after },
// body the page as served, { heads, next? } (§7.9 /heads). nil if n isn't
// sealed.
func (t *tx) filteredHeadsSealing(n *nsRow, fv *fview, after string, page *HeadsPage, rows []headItem) *fsealing {
	var revs []namedRev
	for _, h := range rows {
		if h.state == Live && h.row != nil {
			revs = append(revs, namedRev{h.name, h.row})
		}
	}
	body := map[string]any{"heads": mapsAsAny(page.Items)}
	if page.Next != "" {
		body["next"] = page.Next
	}
	pl := seal.PL{"ns": n.name, "at": fv.cp.at, "after": after}
	return t.filteredSealing(n, fv, pl, revs, nil, func() any { return body })
}

func mapsAsAny(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

// resourceRangeSealing prepares the sealing of a resource log range or
// long-poll answer, or its events, as partial reader fv reads it at the
// resource's URLs in sealed n (§7.9 Log entries): entries are the range's,
// out the entries judgeEntries shows, in order, with shown[i] the row of
// out[i] where it is a revision or tombstone shown as itself (nil for a
// hidden stand-in), and patches[i] whether it is shown with patches. A
// revision shown with patches is its stored JWE under its K_log in the
// body. A range is pl { ns, view, name, range: [since, last] }, an event
// its unfiltered pl with view, a hidden event's kind "hidden".
func (t *tx) resourceRangeSealing(n *nsRow, fv *fview, name, since, last string, out []map[string]any, shown []*revRow, patches []bool, entryValue func(*revRow) []byte, events bool) []*fsealing {
	body := make([]any, len(out))
	var inner []*sealJob
	var revs []namedRev
	type slot struct {
		i int
		j *sealJob
	}
	var slots []slot
	for i, m := range out {
		body[i] = m
		row := shown[i]
		if row == nil {
			continue
		}
		revs = append(revs, namedRev{name, row})
		if row.kind == kindRev && patches[i] {
			j := t.resJob(n, name, row, sealEntry, func() []byte { return entryValue(row) })
			inner = append(inner, j)
			slots = append(slots, slot{i, j})
		}
	}
	fill := func() {
		for _, s := range slots {
			body[s.i] = s.j.jwe
		}
	}
	if !events {
		pl := seal.PL{"ns": n.name, "name": name, "range": []any{since, last}}
		return []*fsealing{t.filteredSealing(n, fv, pl, revs, inner, func() any { fill(); return body })}
	}
	var out2 []*fsealing
	for i, m := range out {
		i, m := i, m
		id, _ := m["id"].(string)
		kind, _ := m["kind"].(string)
		var rs []namedRev
		var in []*sealJob
		if row := shown[i]; row != nil {
			rs = []namedRev{{name, row}}
			for _, s := range slots {
				if s.i == i {
					in = []*sealJob{s.j}
				}
			}
		}
		out2 = append(out2, t.filteredSealing(n, fv, seal.ResourcePL(n.name, name, id, kind), rs, in, func() any {
			fill()
			return body[i]
		}))
	}
	return out2
}
