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
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/verify"
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
// a 200: err (no answer, or one longer than B reads, errTooLarge), or
// status st with body. A 410 pruned with a horizon is pruned with A's
// horizon, which callers take only if it is a revision of the resource's
// chain after the sealing's (prunedIn, horizonIn, verifyHorizonPast); any
// other 4xx, a redirect (rawGet follows none) or an answer too long is a
// refusal, which isn't final.
func pendingAnswer(st int, body []byte, err error) (answer, horizon string) {
	switch {
	case errors.Is(err, errTooLarge):
		return pendRefused, ""
	case err != nil || transientStatus(st):
		return pendTransient, ""
	case st == 410:
		var b struct{ Code, Horizon string }
		if json.Unmarshal(body, &b) == nil && b.Code == "pruned" && b.Horizon != "" {
			return pendPruned, b.Horizon
		}
	}
	return pendRefused, ""
}

// trimJWE is a JWE A served, without the whitespace around it, which
// openPreSealing ignores: what B stores, and serves, of it.
func trimJWE(body []byte) string {
	return string(bytes.TrimSpace(body))
}

// strictJWE reports whether jwe is a compact JWE of the form B's own
// sealings take (§E.2.2, alg dir): five segments of base64url, the
// encrypted key's empty, and nothing else. Base64 decoding skips CR and
// LF, so A could otherwise inflate a sealing that still opens, inside
// its segments, where trimJWE doesn't reach, and B would store and serve
// it at that length.
func strictJWE(jwe string) bool {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 || parts[1] != "" {
		return false
	}
	for i, p := range parts {
		if i == 1 {
			continue
		}
		if p == "" {
			return false
		}
		for j := 0; j < len(p); j++ {
			c := p[j]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// pendingJWEMax bounds A's sealing of the content of mirrored revision
// seq, as creation bounds it (jweFor): of its document (kind sealDoc), or
// of its log entry as the shadow serves it; 0, for caps.jwe, where B no
// longer holds that content.
func (t *tx) pendingJWEMax(kind string, seq int64) int64 {
	row := t.rev(seq)
	if !row.patches.Valid {
		return 0
	}
	if kind == sealDoc {
		b, err := t.docBytesAt(row)
		if err != nil {
			return 0
		}
		return jweFor(len(b))
	}
	return jweFor(len(jsonv.Canonical(t.logEntry(row).value())))
}

// contentDigest is the digest a pending sealing must open to: of v's
// canonical JSON, an entry or a document.
func contentDigest(v any) [32]byte {
	return sha256.Sum256(jsonv.Canonical(v))
}

// openPreSealing reports whether jwe, A's sealing of an entry or a
// document from before its raise, is a strict compact JWE (strictJWE)
// that opens under kr as one under kid for pl, to JSON whose canonical
// digest is want (§G.5.2: "only once it has opened and verified it").
func openPreSealing(jwe string, kr []byte, kid string, pl seal.PL, want [32]byte) bool {
	if !strictJWE(jwe) {
		return false
	}
	pt, err := seal.OpenExpect(jwe, kr, kid, pl)
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
// sealing of a mirrored revision seq (for a blob, one referencing it),
// due at the next sync.
func (t *tx) recordPending(sh int64, name string, seq int64, s pendingSealing) {
	var hz any
	if s.horizon != "" {
		hz = s.horizon
	}
	_, err := t.Exec(`INSERT INTO remote_pending_sealings (shadow, name, kind, ref, epoch, rev_seq, kid, pl, want, answer, horizon, updated, tries, due)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT DO NOTHING`,
		sh, name, s.kind, s.ref, s.epoch, seq, s.kid, string(jsonv.Canonical(map[string]any(s.pl))), s.want[:], s.answer, hz, t.now.UnixMilli(), t.now.UnixMilli())
	t.must(err)
}

// pendingPruned is the horizon A named when it answered 410 pruned for the
// sealing of kind of ref (a revision or blob id) of resource name under
// epoch (any, for epoch < 0) that shadow sh lacks, if it did. A row this
// version recorded pruned (due set) had its horizon checked then (prunedIn,
// settlePending); one recorded before v0.26.1, or by a v0.26.0 instance
// since (due 0), may hold anything A named, and counts only if its horizon
// is a revision of the mirrored chain after the sealing's (horizonIn),
// until a sync checks it for good (pendingFixes).
func (t *tx) pendingPruned(sh *nsRow, kind, name, ref string, epoch int) (string, bool) {
	q := `SELECT horizon, rev_seq, due FROM remote_pending_sealings WHERE shadow = ? AND name = ? AND kind = ? AND ref = ? AND answer = ?`
	args := []any{sh.id, name, kind, ref, pendPruned}
	if epoch >= 0 {
		q += ` AND epoch = ?`
		args = append(args, epoch)
	}
	var hz sql.NullString
	var revSeq, due int64
	err := t.QueryRow(q+` LIMIT 1`, args...).Scan(&hz, &revSeq, &due)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	t.must(err)
	if !hz.Valid || due == 0 && !t.horizonIn(sh.id, name, hz.String, revSeq) {
		return "", false
	}
	return hz.String, true
}

// horizonIn reports whether hz, a horizon A named for a sealing of
// resource name of shadow sh, is a revision of its mirrored chain after
// revSeq, the sealing's revision (for a blob, the first one referencing
// it), as A's horizon for it is (§8.6: A keeps the horizon's own document
// and entry): with one past the mirrored head that A's log verifies
// (verifyHorizonPast), the only horizon B takes for it. Anything else A
// names, of any size, is never stored or served.
func (t *tx) horizonIn(sh int64, name, hz string, revSeq int64) bool {
	id, err := ids.Parse(hz)
	if err != nil {
		return false
	}
	var ok bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions rv JOIN resources r ON r.res = rv.res
		WHERE r.ns = ? AND r.name = ? AND rv.id = ? AND rv.seq > ?)`, sh, name, id[:], revSeq).Scan(&ok))
	return ok
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
// for again, with the namespace of A's chain its shadow mirrors (ns), K_r
// of its epoch (kr), its failed retries so far (tries), for an entry or a
// document the longest sealing of it B takes (maxJWE, jweFor of the
// content it mirrored; 0 for caps.jwe) and, for a blob, the size of the
// blob it mirrored (blobSize, 0 if unknown).
type pendingRow struct {
	shadow       int64
	ns, name     string
	revSeq       int64
	parent       string // the mirrored revision's parent's id, "" for genesis
	parentKnown  bool
	s            pendingSealing
	kr           []byte
	tries        int
	head         string // the id of the shadow's head of the resource, B's mirrored head
	horizonPast  bool   // A's 410 pruned names a horizon after head, which A's log verifies (verifyHorizonPast)
	maxJWE       int64
	blobSize     int64
	jwe          string // fetched: an entry's or document's sealing, trimmed
	blob         []byte // fetched: a blob's
	fetchedOK    bool
	fetchAnswer  string
	fetchHorizon string
}

// maxPendingPerSync bounds the pending sealings one sync of a remote
// branch asks A for (retryPreSealings), the longest due first: the rest
// wait for the next sync.
const maxPendingPerSync = 64

// maxPendingBackoff bounds how long a pending sealing waits between two
// syncs asking for it (pendingBackoff).
const maxPendingBackoff = 4 * time.Hour

// pendingBackoff is how long a pending sealing waits after its tries-th
// failed retry before a sync asks A for it again. The sync after it was
// recorded and the one after its first failed retry ask at once, a
// failure often passing; from its second failed retry on it waits a
// minute, doubling at each, up to maxPendingBackoff, so a base that
// refuses it, or serves junk, isn't asked at every sync for ever.
func pendingBackoff(tries int) time.Duration {
	switch {
	case tries < 2:
		return 0
	case tries-2 >= 16:
		return maxPendingBackoff
	}
	return min(time.Minute<<(tries-2), maxPendingBackoff)
}

// retryPreSealings asks A again, at each sync of remote branch b
// (followRemote), for the pre-raise sealings a shadow of b lacks that A
// hasn't answered 410 pruned for and that are due (pendingBackoff), at
// most maxPendingPerSync of them: a resource's log entries from its log
// up to the latest pending one (fetchPreEntries: an entry is pruned only
// where its own range is 410 pruned), documents at /rev/{id} and blobs at
// their epoch URLs, with the endpoint's grant, reading no more of A's
// answers than preCaps. Each that opens, under the key of its epoch the
// shadow holds, to the mirrored content is stored, the first stored
// winning, and its row deleted; otherwise A's answer is recorded, 410
// pruned being final where its horizon is in the chain (horizonIn), and
// the row waits longer. Each is settled as soon as it is fetched, so B
// holds one answer of A's at a time. A row whose resource has been purged
// since is dropped, never stored (§8.3). A row whose epoch key the shadow
// lacks stays as it is. Asking A stops at half the base's FollowTimeout:
// rows not asked yet are left as they are, and the error says so. Errors
// are reported; rows stay pending. Rows A answered 410 pruned for before
// v0.26.1 are kept so only where their horizon is in the chain, and are
// otherwise refused, to be asked again (pendingFixes).
func (e *Engine) retryPreSealings(ctx context.Context, ep RemoteEndpoint, baseURL string, b *remoteBase) error {
	wctx := ctx // the settling writes, which outlast asking A
	ctx, cancel := context.WithTimeout(ctx, e.opt.Remote.FollowTimeout/2)
	defer cancel()
	caps := e.preCaps()
	type resKey struct {
		shadow int64
		name   string
	}
	var rows []*pendingRow
	var fix pendingFixes
	logs := map[resKey][]*pendingRow{}
	chains := map[resKey][]string{}
	var order []resKey
	if err := e.read(ctx, func(t *tx) error {
		bn := t.nsByID(b.branch)
		if bn == nil || bn.purged {
			return nil
		}
		budget := maxPendingPerSync
		for _, sh := range t.remoteShadows(bn) {
			if budget <= 0 {
				break
			}
			rs := t.pendingRows(sh, budget, &fix)
			budget -= len(rs)
			rows = append(rows, rs...)
		}
		// Entries: one log read per resource, up to its latest pending
		// entry, through its mirrored chain up to there.
		for _, r := range rows {
			if r.s.kind != sealEntry {
				continue
			}
			k := resKey{r.shadow, r.name}
			if logs[k] == nil {
				order = append(order, k)
			}
			logs[k] = append(logs[k], r)
		}
		for _, k := range order {
			last := logs[k][0]
			for _, r := range logs[k] {
				if r.revSeq > last.revSeq {
					last = r
				}
			}
			chains[k] = t.chainTo(last.revSeq)
		}
		return nil
	}); err != nil || len(rows) == 0 && fix.empty() {
		return err
	}
	var errs []error
	if !fix.empty() {
		errs = append(errs, e.update(wctx, func(t *tx) error {
			for _, d := range fix.dropped {
				t.deletePendingSealings(`shadow = ? AND name = ?`, d[0], d[1])
			}
			key := `shadow = ? AND name = ? AND kind = ? AND ref = ? AND epoch = ? AND answer = ? AND due = 0`
			for _, k := range fix.confirm {
				_, err := t.Exec(`UPDATE remote_pending_sealings SET due = ? WHERE `+key, append([]any{t.now.UnixMilli()}, append(k[:], pendPruned)...)...)
				t.must(err)
			}
			for _, k := range fix.demote {
				_, err := t.Exec(`UPDATE remote_pending_sealings SET answer = ?, horizon = NULL, updated = ? WHERE `+key,
					append([]any{pendRefused, t.now.UnixMilli()}, append(k[:], pendPruned)...)...)
				t.must(err)
			}
			return nil
		}))
	}
	// verify opens what was fetched for r; what doesn't open to the
	// mirrored content is dropped, and r unverified.
	verify := func(r *pendingRow) {
		if !r.fetchedOK {
			return
		}
		var ok bool
		if r.s.kind == pendBlob {
			ok = openPreBlob(r.blob, r.kr, r.s.kid, r.s.pl, r.s.want)
		} else {
			ok = openPreSealing(r.jwe, r.kr, r.s.kid, r.s.pl, r.s.want)
		}
		if !ok {
			r.fetchedOK, r.fetchAnswer, r.fetchHorizon, r.jwe, r.blob = false, pendUnverified, "", "", nil
			errs = append(errs, fmt.Errorf("/r/%s/%s: its sealing of %s %s from before its raise doesn't open to what the branch mirrored", r.ns, r.name, r.s.kind, r.s.ref))
		}
	}
	// past checks, for a 410 pruned whose horizon isn't a revision of the
	// mirrored chain, whether it is one after B's head that A's log
	// verifies (§8.6 lets A prune past the at of a remote branch it
	// doesn't know of, §G.3).
	pastOK := map[[3]string]bool{}
	past := func(r *pendingRow) {
		if r.fetchedOK || r.fetchAnswer != pendPruned || r.head == "" {
			return
		}
		var in bool
		if err := e.read(ctx, func(t *tx) error {
			in = t.horizonIn(r.shadow, r.name, r.fetchHorizon, r.revSeq)
			return nil
		}); err != nil || in {
			return
		}
		k := [3]string{r.ns + "/" + r.name, r.head, r.fetchHorizon}
		ok, seen := pastOK[k]
		if !seen {
			ok = verifyHorizonPast(ctx, ep, baseURL, "/r/"+r.ns+"/"+r.name, r.head, r.fetchHorizon, caps)
			pastOK[k] = ok
		}
		r.horizonPast = ok
	}
	settle := func(rs ...*pendingRow) {
		errs = append(errs, e.update(wctx, func(t *tx) error {
			for _, r := range rs {
				t.settlePending(r)
			}
			return nil
		}))
		for _, r := range rs {
			r.jwe, r.blob = "", nil
		}
	}
	for _, k := range order {
		if ctx.Err() != nil {
			break
		}
		rs := logs[k]
		entries := make([]preEntry, len(rs))
		for i, r := range rs {
			entries[i] = preEntry{id: r.s.ref, parent: r.parent, parentKnown: r.parentKnown, max: r.maxJWE}
		}
		got, answers := fetchPreEntries(ctx, ep, baseURL, "/r/"+rs[0].ns+"/"+rs[0].name, chains[k], entries, caps)
		for _, r := range rs {
			if jwe, ok := got[r.s.ref]; ok {
				r.jwe, r.fetchedOK = jwe, true
			} else {
				r.fetchAnswer, r.fetchHorizon = answers[r.s.ref][0], answers[r.s.ref][1]
			}
			verify(r)
			past(r)
		}
		clear(got)
		settle(rs...)
	}
	for _, r := range rows {
		if r.s.kind == sealEntry {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		switch r.s.kind {
		case sealDoc:
			limit := caps.jwe
			if r.maxJWE > 0 {
				limit = r.maxJWE
			}
			st, _, body, err := rawGet(ctx, ep, baseURL, "/r/"+r.ns+"/"+r.name+"/rev/"+r.s.ref, nil, limit)
			if err == nil && st == 200 {
				r.jwe, r.fetchedOK = trimJWE(body), true
			} else {
				r.fetchAnswer, r.fetchHorizon = pendingAnswer(st, body, err)
			}
		case pendBlob:
			size := r.blobSize
			if size <= 0 {
				size = int64(e.opt.Maximums.BlobSize)
			}
			st, _, body, err := rawGet(ctx, ep, baseURL, "/r/"+r.ns+"/"+r.name+"/blob/"+r.s.ref+"/e/"+strconv.Itoa(r.s.epoch), nil, caps.blob(size))
			if err == nil && st == 200 {
				r.blob, r.fetchedOK = body, true
			} else {
				r.fetchAnswer, r.fetchHorizon = pendingAnswer(st, body, err)
			}
		default:
			continue
		}
		verify(r)
		past(r)
		settle(r)
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, fmt.Errorf("asking again for its sealings from before its raise: %w", err))
	}
	return errors.Join(errs...)
}

// maxChainWalk bounds the mirrored chain chainTo walks.
const maxChainWalk = 1 << 20

// chainTo is the mirrored chain up to revision seq: the ids of seq and its
// ancestors, oldest first.
func (t *tx) chainTo(seq int64) []string {
	q, err := t.Query(`WITH RECURSIVE c (seq, parent, id, n) AS (
			SELECT seq, parent_seq, id, 0 FROM revisions WHERE seq = ?
			UNION ALL SELECT r.seq, r.parent_seq, r.id, c.n + 1 FROM revisions r JOIN c ON r.seq = c.parent WHERE c.n < ?)
		SELECT id FROM c ORDER BY n DESC`, seq, maxChainWalk)
	t.must(err)
	defer q.Close()
	var out []string
	for q.Next() {
		var id []byte
		t.must(q.Scan(&id))
		out = append(out, ids.FromBytes(id).String())
	}
	t.must(q.Err())
	return out
}

// pendingFixes are changes to rows of remote_pending_sealings that
// pendingRows finds, which retryPreSealings writes: the resources whose
// rows to drop, theirs being purged or gone (shadow, name), and the rows
// recorded 410 pruned before v0.26.1 (due 0), whose horizon is kept for
// good where it is in the chain (confirm) and is otherwise a refusal,
// asked again (demote), each by its key (shadow, name, kind, ref, epoch).
type pendingFixes struct {
	dropped         [][2]any
	confirm, demote [][5]any
}

func (f *pendingFixes) empty() bool {
	return len(f.dropped) == 0 && len(f.confirm) == 0 && len(f.demote) == 0
}

// pendingRows are up to limit of shadow sh's pending sealings A hasn't
// answered 410 pruned for that are due and that it holds the epoch keys
// to open, the longest due first, with those keys. Rows it can't open
// are skipped, and don't count. The fixes it finds are added to fix.
func (t *tx) pendingRows(sh *nsRow, limit int, fix *pendingFixes) []*pendingRow {
	if sh.purged {
		return nil
	}
	q, err := t.Query(`SELECT p.name, p.kind, p.ref, p.epoch, p.rev_seq, p.kid, p.pl, p.want, p.answer, COALESCE(p.horizon, ''), p.tries, COALESCE(r.state, ?),
			rv.seq IS NOT NULL AND (rv.parent_seq IS NULL OR pv.seq IS NOT NULL), pv.id
		FROM remote_pending_sealings p LEFT JOIN resources r ON r.ns = p.shadow AND r.name = p.name
		LEFT JOIN revisions rv ON rv.seq = p.rev_seq LEFT JOIN revisions pv ON pv.seq = rv.parent_seq
		WHERE p.shadow = ? AND (p.answer <> ? AND p.due <= ? OR p.answer = ? AND p.due = 0)
		ORDER BY p.due, p.name, p.rev_seq, p.kind, p.ref, p.epoch`,
		statePurged, sh.id, pendPruned, t.now.UnixMilli(), pendPruned)
	t.must(err)
	var out, legacy []*pendingRow
	seenDrop := map[string]bool{}
	for q.Next() {
		r := &pendingRow{shadow: sh.id}
		var pl, hz string
		var want, parent []byte
		var state int
		t.must(q.Scan(&r.name, &r.s.kind, &r.s.ref, &r.s.epoch, &r.revSeq, &r.s.kid, &pl, &want, &r.s.answer, &hz, &r.tries, &state, &r.parentKnown, &parent))
		if parent != nil {
			r.parent = ids.FromBytes(parent).String()
		}
		switch {
		case state == statePurged:
			if !seenDrop[r.name] {
				seenDrop[r.name] = true
				fix.dropped = append(fix.dropped, [2]any{sh.id, r.name})
			}
			continue
		case r.s.answer == pendPruned:
			r.s.horizon = hz
			legacy = append(legacy, r)
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
	for _, r := range legacy {
		key := [5]any{sh.id, r.name, r.s.kind, r.s.ref, r.s.epoch}
		if t.horizonIn(sh.id, r.name, r.s.horizon, r.revSeq) {
			fix.confirm = append(fix.confirm, key)
		} else {
			fix.demote = append(fix.demote, key)
		}
	}
	if len(out) == 0 {
		return nil
	}
	kns := t.kidName(sh)
	keep := out[:0]
	for _, r := range out {
		if len(keep) >= limit {
			break
		}
		r.ns = kns
		if !t.hasEpochKey(sh.id, r.s.epoch) {
			continue
		}
		kr, err := seal.ResourceKey(t.epochKey(sh.id, r.s.epoch), kns, r.name)
		if err != nil {
			continue
		}
		r.kr = kr
		if r.s.kind != pendBlob {
			r.maxJWE = t.pendingJWEMax(r.s.kind, r.revSeq)
		}
		var head []byte
		if err := t.QueryRow(`SELECT rv.id FROM resources s JOIN revisions rv ON rv.seq = s.head_seq WHERE s.ns = ? AND s.name = ?`,
			sh.id, r.name).Scan(&head); err == nil {
			r.head = ids.FromBytes(head).String()
		} else if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
		if r.s.kind == pendBlob {
			if bid, err := ids.Parse(r.s.ref); err == nil {
				var size sql.NullInt64
				t.must(t.QueryRow(`SELECT MAX(b.size) FROM blobs b JOIN resources s ON s.res = b.res WHERE s.ns = ? AND s.name = ? AND b.bid = ?`,
					sh.id, r.name, bid[:]).Scan(&size))
				r.blobSize = size.Int64
			}
		}
		keep = append(keep, r)
	}
	return keep
}

// settlePending stores what retryPreSealings fetched and verified for r,
// and deletes its row, or records A's answer, unless r's resource has been
// purged meanwhile (§8.3), whose row is deleted, or A answered 410 pruned
// meanwhile, which stands. A 410 pruned whose horizon isn't in the chain
// (horizonIn) is recorded as refused. A row not stored waits
// pendingBackoff of its failed retries before it is due again.
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
		ans, hz := r.fetchAnswer, any(nil)
		if ans == pendPruned && !r.horizonPast && !t.horizonIn(r.shadow, r.name, r.fetchHorizon, r.revSeq) {
			ans = pendRefused
		}
		if ans == pendPruned {
			hz = r.fetchHorizon
		}
		tries := r.tries + 1
		_, err := t.Exec(`UPDATE remote_pending_sealings SET answer = ?, horizon = ?, updated = ?, tries = ?, due = ? WHERE `+where,
			append([]any{ans, hz, t.now.UnixMilli(), tries, t.now.Add(pendingBackoff(tries)).UnixMilli()}, args...)...)
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
// A serves it sealed, after from ("" for genesis), page by page (§7.1
// Paging), and returns each entry's JWE by id, trimmed (trimJWE); or,
// where a page isn't a 200 array, A's answer (pendingAnswer) with the
// entries of the pages before. chain is the range's mirrored entries up
// to the URL's id, oldest first, and want the entries of it to keep, each
// with the longest sealing of it taken; the others are read past, from
// pages no longer than caps.page. A page's X-Log-Next must name an entry of chain on that page
// after the page's since (§7.1: "the last entry returned, the since of
// the next page"), so each page moves through the range and there are at
// most as many as its entries; any other is a refusal. Reading stops at
// the page holding the URL's id, or one without X-Log-Next.
func fetchSealedLog(ctx context.Context, ep RemoteEndpoint, baseURL, path, from string, chain []string, want map[string]int64, caps preCaps) (map[string]string, string, string) {
	out := map[string]string{}
	if len(chain) == 0 {
		return out, pendRefused, ""
	}
	pos := make(map[string]int, len(chain))
	for i, id := range chain {
		pos[id] = i
	}
	at := -1 // the position of since in chain
	if from != "" {
		p, ok := pos[from]
		if !ok {
			return out, pendRefused, ""
		}
		at = p
	}
	last := chain[len(chain)-1]
	for since := from; ; {
		var q url.Values
		if since != "" {
			q = url.Values{"since": {since}}
		}
		st, hdr, body, err := rawGet(ctx, ep, baseURL, path, q, caps.page)
		if err != nil || st != 200 {
			ans, hz := pendingAnswer(st, body, err)
			return out, ans, hz
		}
		var page []any
		if json.Unmarshal(body, &page) != nil {
			return out, pendUnverified, ""
		}
		body = nil
		onPage := map[string]bool{}
		for _, v := range page {
			var id, jwe string
			switch v := v.(type) {
			case string:
				jwe = strings.TrimSpace(v)
				if h, err := seal.ParseHeader(jwe); err == nil {
					id, _ = h.PL["id"].(string)
				}
			case map[string]any:
				id, _ = v["id"].(string) // an entry served in the clear
			}
			if p, ok := pos[id]; ok && p > at {
				onPage[id] = true
				if m, ok := want[id]; ok && jwe != "" && int64(len(jwe)) <= m {
					out[id] = jwe
				}
			}
		}
		next := hdr.Get("X-Log-Next")
		if onPage[last] || next == "" {
			return out, "", ""
		}
		p, ok := pos[next]
		if !ok || p <= at || !onPage[next] {
			return out, pendRefused, ""
		}
		since, at = next, p
	}
}

// maxHorizonPages bounds the pages of A's log verifyHorizonPast reads.
const maxHorizonPages = 16

// verifyHorizonPast reports whether hz, a horizon A named in a 410 pruned
// for content of resource what (/r/{ns}/{name}) that isn't a revision of
// B's mirrored chain, is one after head, B's mirrored head: whether A
// serves the range …/rev/{hz}/log?since={head} in the clear, each entry's
// id recomputed and chained from head to hz (§7.1). It reads at most
// maxHorizonPages pages, each no longer than caps.page, each moving to
// its last entry (X-Log-Next). Where the range isn't served so (A pruned
// revisions between head and hz too, or serves them sealed), it isn't
// verified.
func verifyHorizonPast(ctx context.Context, ep RemoteEndpoint, baseURL, what, head, hz string, caps preCaps) bool {
	if _, err := ids.Parse(hz); err != nil || hz == head {
		return false
	}
	var all []client.LogEntry
	for since, pages := head, 0; ; pages++ {
		if pages == maxHorizonPages {
			return false
		}
		st, hdr, body, err := rawGet(ctx, ep, baseURL, what+"/rev/"+hz+"/log", url.Values{"since": {since}}, caps.page)
		if err != nil || st != 200 {
			return false
		}
		v, err := jsonv.Parse(body)
		page, ok := v.([]any)
		if err != nil || !ok || len(page) == 0 {
			return false
		}
		for _, x := range page {
			e, err := client.ParseLogEntry(x)
			if err != nil {
				return false
			}
			all = append(all, e)
		}
		last := all[len(all)-1].ID
		if last == hz {
			break
		}
		if hdr.Get("X-Log-Next") != last {
			return false
		}
		since = last
	}
	got, err := verify.VerifyResourceLog(all, head)
	return err == nil && got == hz
}

// preEntry is a log entry from before its source's raise whose sealing B
// asks A for (fetchPreEntries): its id, and its parent's, "" for genesis,
// where parentKnown, and the longest sealing of it B takes (jweFor), 0 for
// caps.jwe.
type preEntry struct {
	id, parent  string
	parentKnown bool
	max         int64
}

// fetchPreEntries fetches A's sealings of entries, log entries from before
// its raise of resource what (/r/{ns}/{name}), from its log up to the last
// entry of chain, the mirrored chain up to there, …/rev/{last}/log, every
// page (fetchSealedLog). It returns the sealings it got, by id, and for
// each entry it didn't get A's answer for it and the horizon A named. A
// range is 410 pruned where any revision in it has its patch set pruned
// (§7.1), which says nothing of a later entry in it, so an entry the range
// is 410 pruned for is asked for again in a range of its own,
// …/rev/{id}/log?since={parent} (since may lie below the horizon), and is
// pruned only if A answers that 410 pruned too: §G.5.2 answers 410 only
// "where A has pruned it". One whose parent isn't known isn't asked
// again, and is refused, which isn't final.
func fetchPreEntries(ctx context.Context, ep RemoteEndpoint, baseURL, what string, chain []string, entries []preEntry, caps preCaps) (map[string]string, map[string][2]string) {
	answers := map[string][2]string{}
	if len(chain) == 0 {
		for _, e := range entries {
			answers[e.id] = [2]string{pendRefused, ""}
		}
		return map[string]string{}, answers
	}
	want := make(map[string]int64, len(entries))
	for _, e := range entries {
		want[e.id] = caps.jwe
		if e.max > 0 {
			want[e.id] = e.max
		}
	}
	got, ans, hz := fetchSealedLog(ctx, ep, baseURL, what+"/rev/"+chain[len(chain)-1]+"/log", "", chain, want, caps)
	if ans == "" {
		ans = pendRefused // served, but without the entry
	}
	pos := make(map[string]int, len(chain))
	for i, id := range chain {
		pos[id] = i
	}
	for _, e := range entries {
		if _, ok := got[e.id]; ok {
			continue
		}
		i, inChain := pos[e.id]
		switch {
		case ans != pendPruned:
			answers[e.id] = [2]string{ans, hz}
		case !e.parentKnown || !inChain:
			answers[e.id] = [2]string{pendRefused, ""}
		default:
			one, a, h := fetchSealedLog(ctx, ep, baseURL, what+"/rev/"+e.id+"/log", e.parent, chain[:i+1], map[string]int64{e.id: want[e.id]}, caps)
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
