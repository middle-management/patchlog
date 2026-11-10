package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Pending pre-raise sealings of remote branches (§G.5.2 E3 sources, §G.3
// Reading through, migration 014_remote_pending_sealings).
//
// B stores and serves a sealing A made of content from before its raise
// from sealed only once it has opened it with A's key of that epoch and
// verified it against the mirrored entry, document or blob: nothing is
// stored unopened. One B couldn't fetch at creation, because A refused it
// (a 4xx), answered 410, or failed transiently (no answer, a 5xx, 408 or
// 429), is recorded in remote_pending_sealings with A's last answer, and
// every sync of the branch (followRemote) fetches it again
// (retryPreSealings): once it opens and verifies, it is stored, the first
// stored winning, and its row deleted. Until then the URLs needing it
// answer 502 upstream, or 410 pruned with A's horizon once A answered
// that, which is final (preRaiseUnfetched); post-raise content and the
// sealings B has stay readable.
//
// One whose epoch key B's grant doesn't get (A's /keys refuses it or omits
// it) is never pending: creation fails 422, as for a base B can't read
// (fetchPreSealings, §G.3 Creating one).

// Kinds of a pending sealing beside the sealed table's sealEntry and
// sealDoc: a sealed blob at an epoch URL (blob_epochs).
const pendBlob = "blob"

// A's last answer for a pending sealing (remote_pending_sealings.answer).
const (
	pendNone       = "none"       // not asked yet
	pendRefused    = "refused"    // a 4xx other than 408, 429 and 410 pruned, or left out of a log page A served
	pendTransient  = "transient"  // no answer, a 5xx, 408 or 429 (noAnswer)
	pendPruned     = "pruned"     // 410 pruned: final, B answers 410 with A's horizon
	pendUnverified = "unverified" // served, but it didn't open to the mirrored content
)

// pendingSealing is a sealing of A's B lacks: kind sealEntry or sealDoc of
// revision ref, or pendBlob of blob ref, under epoch, whose kid and pl A
// seals it with and which opens to content whose digest is want.
type pendingSealing struct {
	kind, ref string
	epoch     int
	kid       string
	pl        seal.PL
	want      [32]byte
	answer    string
	horizon   string
}

// pendingAnswer classifies A's answer to a sealing B asked for that isn't
// a 200: err (no answer), or status st with body.
func pendingAnswer(st int, body []byte, err error) (answer, horizon string) {
	switch {
	case err != nil || transientStatus(st):
		return pendTransient, ""
	case st == 410:
		var b struct{ Code, Horizon string }
		if json.Unmarshal(body, &b) == nil && b.Code == "pruned" {
			return pendPruned, b.Horizon
		}
	}
	return pendRefused, ""
}

// contentDigest is the digest a pending sealing must open to: of v's
// canonical JSON, an entry or a document.
func contentDigest(v any) [32]byte {
	return sha256.Sum256(jsonv.Canonical(v))
}

// openPreSealing reports whether jwe, A's sealing of an entry or a
// document from before its raise, opens under kr as one under kid for pl,
// to JSON whose canonical digest is want (§G.5.2: "only once it has opened
// and verified it").
func openPreSealing(jwe string, kr []byte, kid string, pl seal.PL, want [32]byte) bool {
	pt, err := seal.OpenExpect(string(bytes.TrimSpace([]byte(jwe))), kr, kid, pl)
	if err != nil {
		return false
	}
	v, err := jsonv.Parse(pt)
	return err == nil && contentDigest(v) == want
}

// openPreBlob reports whether body, A's sealing of a blob from before its
// raise, is one under kid for pl that opens under kr to bytes whose digest
// is want.
func openPreBlob(body, kr []byte, kid string, pl seal.PL, want [32]byte) bool {
	h, err := seal.ParseBlobHeader(body)
	if err != nil || h.Kid != kid || !bytes.Equal(jsonv.Canonical(map[string]any(h.PL)), jsonv.Canonical(map[string]any(pl))) {
		return false
	}
	_, pt, err := seal.OpenBlob(body, kr)
	return err == nil && sha256.Sum256(pt) == want
}

// recordPending records s as pending for resource name of shadow sh, the
// sealing of a mirrored revision seq (for a blob, one referencing it).
func (t *tx) recordPending(sh int64, name string, seq int64, s pendingSealing) {
	var hz any
	if s.horizon != "" {
		hz = s.horizon
	}
	_, err := t.Exec(`INSERT INTO remote_pending_sealings (shadow, name, kind, ref, epoch, rev_seq, kid, pl, want, answer, horizon, updated)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		sh, name, s.kind, s.ref, s.epoch, seq, s.kid, string(jsonv.Canonical(map[string]any(s.pl))), s.want[:], s.answer, hz, t.now.UnixMilli())
	t.must(err)
}

// pendingPruned is the horizon A named when it answered 410 pruned for the
// sealing of kind of ref (a revision or blob id) of resource name that
// shadow sh lacks, if it did.
func (t *tx) pendingPruned(sh *nsRow, kind, name, ref string) (string, bool) {
	var hz sql.NullString
	err := t.QueryRow(`SELECT horizon FROM remote_pending_sealings WHERE shadow = ? AND name = ? AND kind = ? AND ref = ? AND answer = ? LIMIT 1`,
		sh.id, name, kind, ref, pendPruned).Scan(&hz)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	t.must(err)
	return hz.String, true
}

// deletePendingSealings deletes the pending sealings matching where (a purge's,
// purgeShadow and purgeShadowNS).
func (t *tx) deletePendingSealings(where string, args ...any) {
	_, err := t.Exec(`DELETE FROM remote_pending_sealings WHERE `+where, args...)
	t.must(err)
}

// storePreBlob stores data, A's sealing of blob bid of resource name under
// epoch, under shadow sh, unless one is stored.
func (t *tx) storePreBlob(sh int64, name string, bid ids.ID, epoch int, data []byte) {
	var exists bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_epochs WHERE ns = ? AND name = ? AND bid = ? AND epoch = ?)`, sh, name, bid[:], epoch).Scan(&exists))
	if exists {
		return
	}
	var stored, file any = data, nil
	if f := t.storeFile(epochFile(sh, bid[:], epoch), data); f != "" {
		stored, file = nil, f
	}
	_, err := t.Exec(`INSERT INTO blob_epochs (ns, name, bid, epoch, data, file, created) VALUES (?,?,?,?,?,?,?)`,
		sh, name, bid[:], epoch, stored, file, t.now.UnixMilli())
	t.must(err)
}

// pendingRow is a row of remote_pending_sealings retryPreSealings asks A
// for again, with the namespace of A's chain its shadow mirrors (ns) and
// K_r of its epoch (kr).
type pendingRow struct {
	shadow       int64
	ns, name     string
	revSeq       int64
	parent       string // the mirrored revision's parent's id, "" for genesis
	parentKnown  bool
	s            pendingSealing
	kr           []byte
	jwe          string // fetched: an entry's or document's sealing
	blob         []byte // fetched: a blob's
	fetchedOK    bool
	fetchAnswer  string
	fetchHorizon string
}

// retryPreSealings asks A again, at each sync of remote branch b
// (followRemote), for each pre-raise sealing a shadow of b lacks that A
// hasn't answered 410 pruned for: a resource's log entries from its log
// up to the latest pending one (fetchPreEntries: an entry is pruned only
// where its own range is 410 pruned), documents at /rev/{id} and blobs at their
// epoch URLs, with the endpoint's grant. Each that opens, under the key of
// its epoch the shadow holds, to the mirrored content is stored, the first
// stored winning, and its row deleted; otherwise A's answer is recorded,
// 410 pruned being final. A row whose resource has been purged since is
// dropped, never stored (§8.3). A row whose epoch key the shadow lacks
// stays as it is. Errors are reported; rows stay pending.
func (e *Engine) retryPreSealings(ctx context.Context, ep RemoteEndpoint, baseURL string, b *remoteBase) error {
	var rows []*pendingRow
	var dropped [][2]any
	if err := e.read(ctx, func(t *tx) error {
		bn := t.nsByID(b.branch)
		if bn == nil || bn.purged {
			return nil
		}
		for _, sh := range t.remoteShadows(bn) {
			rows = append(rows, t.pendingRows(sh, &dropped)...)
		}
		return nil
	}); err != nil || len(rows) == 0 && len(dropped) == 0 {
		return err
	}
	var errs []error
	// Entries: one log read per resource, up to its latest pending entry.
	type resKey struct {
		shadow int64
		name   string
	}
	logs := map[resKey][]*pendingRow{}
	for _, r := range rows {
		if r.s.kind == sealEntry {
			k := resKey{r.shadow, r.name}
			logs[k] = append(logs[k], r)
		}
	}
	for _, rs := range logs {
		last := rs[0]
		for _, r := range rs {
			if r.revSeq > last.revSeq {
				last = r
			}
		}
		entries := make([]preEntry, len(rs))
		for i, r := range rs {
			entries[i] = preEntry{id: r.s.ref, parent: r.parent, parentKnown: r.parentKnown}
		}
		got, answers := fetchPreEntries(ctx, ep, baseURL, "/r/"+last.ns+"/"+last.name, last.s.ref, entries)
		for _, r := range rs {
			if jwe, ok := got[r.s.ref]; ok {
				r.jwe, r.fetchedOK = jwe, true
			} else {
				r.fetchAnswer, r.fetchHorizon = answers[r.s.ref][0], answers[r.s.ref][1]
			}
		}
	}
	for _, r := range rows {
		switch r.s.kind {
		case sealDoc:
			st, _, body, err := rawGet(ctx, ep, baseURL, "/r/"+r.ns+"/"+r.name+"/rev/"+r.s.ref, nil)
			if err == nil && st == 200 {
				r.jwe, r.fetchedOK = string(body), true
			} else {
				r.fetchAnswer, r.fetchHorizon = pendingAnswer(st, body, err)
			}
		case pendBlob:
			st, _, body, err := rawGet(ctx, ep, baseURL, "/r/"+r.ns+"/"+r.name+"/blob/"+r.s.ref+"/e/"+strconv.Itoa(r.s.epoch), nil)
			if err == nil && st == 200 {
				r.blob, r.fetchedOK = body, true
			} else {
				r.fetchAnswer, r.fetchHorizon = pendingAnswer(st, body, err)
			}
		}
		if r.fetchedOK {
			ok := false
			if r.s.kind == pendBlob {
				ok = openPreBlob(r.blob, r.kr, r.s.kid, r.s.pl, r.s.want)
			} else {
				ok = openPreSealing(r.jwe, r.kr, r.s.kid, r.s.pl, r.s.want)
			}
			if !ok {
				r.fetchedOK, r.fetchAnswer = false, pendUnverified
				errs = append(errs, fmt.Errorf("/r/%s/%s: its sealing of %s %s from before its raise doesn't open to what the branch mirrored", r.ns, r.name, r.s.kind, r.s.ref))
			}
		}
	}
	errs = append(errs, e.update(ctx, func(t *tx) error {
		for _, d := range dropped {
			_, err := t.Exec(`DELETE FROM remote_pending_sealings WHERE shadow = ? AND name = ?`, d[0], d[1])
			t.must(err)
		}
		for _, r := range rows {
			t.settlePending(r)
		}
		return nil
	}))
	return errors.Join(errs...)
}

// pendingRows are shadow sh's pending sealings A hasn't answered 410
// pruned for, with the keys that open them; the resources of rows whose
// resource is purged, or gone, are added to dropped.
func (t *tx) pendingRows(sh *nsRow, dropped *[][2]any) []*pendingRow {
	if sh.purged {
		return nil
	}
	q, err := t.Query(`SELECT p.name, p.kind, p.ref, p.epoch, p.rev_seq, p.kid, p.pl, p.want, p.answer, COALESCE(r.state, ?),
			rv.seq IS NOT NULL AND (rv.parent_seq IS NULL OR pv.seq IS NOT NULL), pv.id
		FROM remote_pending_sealings p LEFT JOIN resources r ON r.ns = p.shadow AND r.name = p.name
		LEFT JOIN revisions rv ON rv.seq = p.rev_seq LEFT JOIN revisions pv ON pv.seq = rv.parent_seq
		WHERE p.shadow = ? AND p.answer <> ? ORDER BY p.name, p.rev_seq, p.kind, p.ref, p.epoch`, statePurged, sh.id, pendPruned)
	t.must(err)
	var out []*pendingRow
	seenDrop := map[string]bool{}
	for q.Next() {
		r := &pendingRow{shadow: sh.id}
		var pl string
		var want, parent []byte
		var state int
		t.must(q.Scan(&r.name, &r.s.kind, &r.s.ref, &r.s.epoch, &r.revSeq, &r.s.kid, &pl, &want, &r.s.answer, &state, &r.parentKnown, &parent))
		if parent != nil {
			r.parent = ids.FromBytes(parent).String()
		}
		if state == statePurged {
			if !seenDrop[r.name] {
				seenDrop[r.name] = true
				*dropped = append(*dropped, [2]any{sh.id, r.name})
			}
			continue
		}
		if json.Unmarshal([]byte(pl), &r.s.pl) != nil || len(want) != len(r.s.want) {
			continue
		}
		copy(r.s.want[:], want)
		out = append(out, r)
	}
	t.must(q.Err())
	q.Close()
	if len(out) == 0 {
		return nil
	}
	kns := t.kidName(sh)
	keep := out[:0]
	for _, r := range out {
		r.ns = kns
		if !t.hasEpochKey(sh.id, r.s.epoch) {
			continue
		}
		kr, err := seal.ResourceKey(t.epochKey(sh.id, r.s.epoch), kns, r.name)
		if err != nil {
			continue
		}
		r.kr = kr
		keep = append(keep, r)
	}
	return keep
}

// settlePending stores what retryPreSealings fetched and verified for r,
// and deletes its row, or records A's answer, unless r's resource has been
// purged meanwhile (§8.3), whose row is deleted, or A answered 410 pruned
// meanwhile, which stands.
func (t *tx) settlePending(r *pendingRow) {
	var state int
	err := t.QueryRow(`SELECT state FROM resources WHERE ns = ? AND name = ?`, r.shadow, r.name).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) || err == nil && state == statePurged {
		_, err := t.Exec(`DELETE FROM remote_pending_sealings WHERE shadow = ? AND name = ?`, r.shadow, r.name)
		t.must(err)
		return
	}
	t.must(err)
	where := `shadow = ? AND name = ? AND kind = ? AND ref = ? AND epoch = ? AND answer <> ?`
	args := []any{r.shadow, r.name, r.s.kind, r.s.ref, r.s.epoch, pendPruned}
	if !r.fetchedOK {
		var hz any
		if r.fetchHorizon != "" {
			hz = r.fetchHorizon
		}
		_, err := t.Exec(`UPDATE remote_pending_sealings SET answer = ?, horizon = ?, updated = ? WHERE `+where,
			append([]any{r.fetchAnswer, hz, t.now.UnixMilli()}, args...)...)
		t.must(err)
		return
	}
	res, err := t.Exec(`DELETE FROM remote_pending_sealings WHERE `+where, args...)
	t.must(err)
	if n, _ := res.RowsAffected(); n == 0 {
		return
	}
	switch r.s.kind {
	case pendBlob:
		bid, err := ids.Parse(r.s.ref)
		if err != nil {
			return
		}
		t.storePreBlob(r.shadow, r.name, bid, r.s.epoch, r.blob)
	default:
		_, err := t.Exec(`INSERT INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
			r.shadow, r.s.kind, r.name+"/"+r.s.ref, r.name, r.revSeq, r.jwe, t.now.UnixMilli())
		t.must(err)
	}
}

// fetchSealedLog reads the log of a resource at path, …/rev/{id}/log, as
// A serves it sealed, after from ("" for genesis), every page (§7.1
// Paging), and returns each entry's JWE by id; or, where a page isn't a
// 200 array, A's answer (pendingAnswer) with the entries of the pages
// before.
func fetchSealedLog(ctx context.Context, ep RemoteEndpoint, baseURL, path, from string) (map[string]string, string, string) {
	out := map[string]string{}
	for since := from; ; {
		var q url.Values
		if since != "" {
			q = url.Values{"since": {since}}
		}
		st, hdr, body, err := rawGet(ctx, ep, baseURL, path, q)
		if err != nil || st != 200 {
			ans, hz := pendingAnswer(st, body, err)
			return out, ans, hz
		}
		var page []any
		if json.Unmarshal(body, &page) != nil {
			return out, pendUnverified, ""
		}
		for _, v := range page {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if h, err := seal.ParseHeader(s); err == nil {
				if id, ok := h.PL["id"].(string); ok {
					out[id] = s
				}
			}
		}
		next := hdr.Get("X-Log-Next")
		if next == "" || next == since {
			return out, "", ""
		}
		since = next
	}
}

// preEntry is a log entry from before its source's raise whose sealing B
// asks A for (fetchPreEntries): its id, and its parent's, "" for genesis,
// where parentKnown.
type preEntry struct {
	id, parent  string
	parentKnown bool
}

// fetchPreEntries fetches A's sealings of entries, log entries from before
// its raise of resource what (/r/{ns}/{name}), from its log up to last,
// …/rev/{last}/log, every page (fetchSealedLog). It returns the sealings
// it got, by id, and for each entry it didn't get A's answer for it and
// the horizon A named. A range is 410 pruned where any revision in it has
// its patch set pruned (§7.1), which says nothing of a later entry in it,
// so an entry the range is 410 pruned for is asked for again in a range of
// its own, …/rev/{id}/log?since={parent} (since may lie below the
// horizon), and is pruned only if A answers that 410 pruned too: §G.5.2
// answers 410 only "where A has pruned it". One whose parent isn't known
// isn't asked again, and is refused, which isn't final.
func fetchPreEntries(ctx context.Context, ep RemoteEndpoint, baseURL, what, last string, entries []preEntry) (map[string]string, map[string][2]string) {
	got, ans, hz := fetchSealedLog(ctx, ep, baseURL, what+"/rev/"+last+"/log", "")
	if ans == "" {
		ans = pendRefused // served, but without the entry
	}
	answers := map[string][2]string{}
	for _, e := range entries {
		if _, ok := got[e.id]; ok {
			continue
		}
		switch {
		case ans != pendPruned:
			answers[e.id] = [2]string{ans, hz}
		case !e.parentKnown:
			answers[e.id] = [2]string{pendRefused, ""}
		default:
			one, a, h := fetchSealedLog(ctx, ep, baseURL, what+"/rev/"+e.id+"/log", e.parent)
			if jwe, ok := one[e.id]; ok {
				got[e.id] = jwe
				continue
			}
			if a == "" {
				a = pendRefused
			}
			answers[e.id] = [2]string{a, h}
		}
	}
	return got, answers
}

// logPending logs what creation left pending for resource what.
func logPending(what string, ps *preSealings) {
	n := 0
	for _, xs := range ps.pending {
		n += len(xs)
	}
	for _, m := range ps.blobAnswers {
		n += len(m)
	}
	if n > 0 {
		log.Printf("remote base %s: %d of its sealings from before its raise couldn't be fetched; the branch answers what needs them 502 upstream until a sync opens and verifies them (§G.5.2)", what, n)
	}
}
