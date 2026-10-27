package core

// End-to-end namespaces (Addendum E, level E3).
//
// The server never sees plaintext content. It is an ordered,
// access-controlled log of opaque entries:
//
//   - Writes. A create, append or restore of a resource carries one reserved
//     op, [{"op":"sealed","value":"<JWE>"}] (or [] for a restore), whose
//     protected header binds kid "{ns}#{e}" and pl {ns, name, parent}. The
//     gate (§6.2) doesn't apply it and skips schema validation; it checks the
//     header without a key: pl must be exactly this write's {ns, name,
//     parent}, kid the namespace's epoch in force (for a batch's items, the
//     configuration its config change produces), and no zip (§E.3.1).
//     A declared blob must be a sealed blob without a nonce. That is a
//     consistency check that catches client
//     bugs and replays under another name early, not a security boundary: a
//     writer can always seal garbage, and readers verify pl when they
//     decrypt. The envelope has writes [] and no doc, so any namespace,
//     grant, key or role rule that reads writes or /doc (or the whole
//     envelope) fails the write as a whole: 422 rule for namespace rules, 403
//     for the others (§6.2, §E.3.2). Deletes, config, branch and prune
//     writes are checked as usual.
//   - Ids are over ciphertext (§3.3), so idempotent retries work unchanged
//     as long as the client resends the same bytes (§E.3.1). No $nonce is
//     needed (§C.7): the IV is random.
//   - Storage. Patch sets are stored as sent, and encrypted at rest as well
//     (E1 machinery). No documents: no head documents, no intermediate
//     snapshots, no document cache; the $schema index (§6.1) sees nothing.
//   - The keyring. The reserved resource "keyring" holds the keyring
//     document (seal.KeyringV2, §E.3.2) in plaintext: epoch keys wrapped
//     in HPKE auth mode, each entry naming its recipient (to) and the
//     admin key that wrapped it (from) by thumbprint. Key-holding admin
//     clients write it with ordinary plaintext writes, which the gate
//     checks as outside E3 plus seal.ParseKeyringV2, kids naming the
//     namespace and epochs not after encryption.epoch (checkKeyring). It is
//     the only plaintext resource of an e2e namespace.
//   - Epochs. encryption.epoch works as at E2, but the server holds no key:
//     e2e_epochs records when each epoch began (for POST /keys and kid
//     checks). A key holder rotates by re-wrapping the keyring and bumping
//     the epoch, in one batch.
//   - Raises (Addendum E Levels). A config write, or a batch's config
//     change, may raise a namespace to e2e from none, at-rest or sealed,
//     starting a new epoch (from sealed, the current one plus one;
//     checkEncryption). e2e_raises records the raising configuration and
//     what was in force before (e2eRaiseOf). Writes from the raising
//     entry on are sealed ops; what was stored before stays plaintext on
//     the server.
//   - Reads. GET /r/{ns}/{name}/rev/{id} answers 302 to
//     /r/{ns}/{name}/rev/{id}/log?since={s} with X-E2E: fold, where s is
//     the latest client-supplied snapshot at or before id (omitted if none).
//     The log serves the stored entries (the ciphertext is inside), never
//     the snapshot: /rev/{s} itself serves it (200 application/jose, or
//     for a tombstone horizon a 410 whose body carries it, both with
//     X-E2E: snapshot; §7.1 Paging). Clients fetch it and fold the range
//     after it. What /rev/{id} serves for other revisions is open (§13).
//   - Prune (§8.6) needs an archive and the horizon's document as a sealed
//     snapshot (pl {ns, name, id, kind: "snapshot"}); keep isn't supported.
//     Retention isn't applied by the server.
//   - Blobs (§E.3.1). Clients encrypt blobs under keys of their own, so the
//     server stores and serves them as uploaded (SealedBlobType only). A
//     sealed op lists the blobs its document references in plaintext,
//     {"op":"sealed","value":"<JWE>","blobs":[ids]}, part of the hashed
//     patch set; a restore with [] keeps the last live document's list.
//     Step 4 checks each is available (checkDeclared) and step 7 attaches
//     them and records the list in blob_refs, which outlives pruning, like
//     a document's references. A prune's snapshot may declare its own list
//     ("blobs" beside "snapshot"), which then stands for the horizon's.
//   - POST /ns/{ns}/keys relays the keyring entries whose to is the
//     thumbprint of the grant's enc, with their from (§E.2.3).

import (
	"crypto/ecdh"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// KeyringName is the reserved resource of an e2e namespace holding its
// keyring (§E.3.2).
const KeyringName = "keyring"

// isE2E reports whether n is an end-to-end namespace.
func (t *tx) isE2E(n *nsRow) bool { return t.nsLevel(n) == levelE2E }

// e2eContent reports whether resource name of n holds sealed content: any
// resource of an e2e namespace but its keyring.
func (t *tx) e2eContent(n *nsRow, name string) bool { return name != KeyringName && t.isE2E(n) }

// e2eConfigWritten records the start of an e2e namespace's epoch: its
// creation (or a branch's), a raise to e2e, and every write that
// increments the epoch. A raise (Addendum E Levels) is recorded too, in
// e2e_raises, with what was in force before it: from then on, the
// raising entry's items included, writes go through the E3 gate, since
// the configuration they are checked under is e2e (§7.5), and what was
// stored before is served at the level before (P35). The new epoch is
// the rotation a revocation made due, if any (§E.2.4).
func (t *tx) e2eConfigWritten(n *nsRow, old, cfg *Config) {
	if cfg.level != levelE2E {
		return
	}
	if old != nil && old.level == levelE2E && old.Epoch == cfg.Epoch {
		return
	}
	_, err := t.Exec(`INSERT INTO e2e_epochs (ns, epoch, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`, n.id, cfg.Epoch, t.now.UnixMilli())
	t.must(err)
	if old == nil || old.level == levelE2E {
		return
	}
	epoch, pad := 0, 0
	if old.level == levelSealed {
		epoch = old.Epoch
		if old.Pad {
			pad = 1
		}
	}
	_, err = t.Exec(`INSERT INTO e2e_raises (ns, config_seq, level, epoch, pad, created) VALUES (?,?,?,?,?,?)`, n.id, n.configSeq, old.level, epoch, pad, t.now.UnixMilli())
	t.must(err)
	_, err = t.Exec(`DELETE FROM rotations_due WHERE ns = ?`, n.id)
	t.must(err)
}

// e2eRaise is a namespace's raise to e2e (Addendum E Levels).
type e2eRaise struct {
	// configSeq is the configuration that made the namespace e2e; seq
	// and id are the namespace entry (config or batch) that wrote it,
	// before which the raise lies in the log.
	configSeq, seq int64
	id             ids.ID
	// level is the level before the raise; from sealed, epoch and pad are
	// the last epoch and pad setting before it, which content stored
	// before the raise keeps (§E.2.2).
	level int
	epoch int
	pad   bool
}

// e2eRaiseOf returns n's raise to e2e, nil for a namespace that was e2e
// from its creation or isn't e2e. The raising entry is the first of n's
// log written under the raising configuration or a later one.
func (t *tx) e2eRaiseOf(n *nsRow) *e2eRaise {
	r := &e2eRaise{}
	var pad int
	err := t.QueryRow(`SELECT config_seq, level, epoch, pad FROM e2e_raises WHERE ns = ?`, n.id).Scan(&r.configSeq, &r.level, &r.epoch, &pad)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	r.pad = pad != 0
	var id []byte
	err = t.QueryRow(`SELECT seq, id FROM ns_log WHERE ns = ? AND config_seq >= ? ORDER BY config_seq, seq LIMIT 1`, n.id, r.configSeq).Scan(&r.seq, &id)
	if errors.Is(err, sql.ErrNoRows) {
		// The raising entry is being appended in this transaction.
		return r
	}
	t.must(err)
	r.id = ids.FromBytes(id)
	return r
}

// preRaiseHead is the seq of resource row res's head as of the entry
// before raise: res's revisions up to it were written before the raise
// and are stored in the clear, those after it from the raising entry on
// (Addendum E Levels). 0 when res had no revision then.
func (t *tx) preRaiseHead(raise *e2eRaise, res int64) int64 {
	if raise.seq == 0 {
		// The raising entry is being appended in this transaction: every
		// stored revision is from before it.
		var max sql.NullInt64
		t.must(t.QueryRow(`SELECT MAX(seq) FROM revisions WHERE res = ?`, res).Scan(&max))
		return max.Int64
	}
	var head int64
	err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq < ? ORDER BY ns_seq DESC LIMIT 1`, res, raise.seq).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return 0
	}
	t.must(err)
	return head
}

// checkSealedHeader checks a JWE's protected header without a key (§E.3.1,
// step 3): no zip (§E.2.2), kid "{ns}#{epoch}" naming n and the given
// epoch, and pl exactly want. A write's sealed op names the epoch in force
// (invariant 6): cfg's, which for a batch's items is the configuration its
// config change produces (§7.5). why says where the epoch comes from, for
// the refusal.
func (t *tx) checkSealedHeader(n *nsRow, jwe string, want seal.PL, what string, epoch int, why string) *Error {
	return t.checkSealedKid(jwe, want, what, n.name, epoch, why)
}

// checkSealedKid is checkSealedHeader with the namespace the kid must name,
// kns: n's own, or for a prune's snapshot of a base's content from before
// its raise from sealed, that base (checkSnapshot).
func (t *tx) checkSealedKid(jwe string, want seal.PL, what, kns string, epoch int, why string) *Error {
	h, err := seal.ParseHeader(jwe)
	if err != nil || strings.Split(jwe, ".")[1] != "" {
		return invalid(fmt.Sprintf("the %s is not a compact JWE with alg dir and enc A256GCM", what))
	}
	if h.Zip != "" {
		return invalid(fmt.Sprintf("the %s's protected header has zip: sealed payloads are never compressed (§E.2.2)", what))
	}
	ns, e, err := seal.ParseKid(h.Kid)
	if err != nil || ns != kns {
		return invalid(fmt.Sprintf("the %s's kid must be %q#{epoch}", what, kns))
	}
	if e != epoch {
		return invalid(fmt.Sprintf("the %s is sealed under epoch %d, not %d, %s (§E.3.1)", what, e, epoch, why))
	}
	if !jsonv.Equal(map[string]any(h.PL), jsonv.FromGo(map[string]any(want))) {
		return apiErr(422, "invalid", "message", fmt.Sprintf("the %s's pl must bind this write exactly", what), "pl", jsonv.FromGo(map[string]any(want)))
	}
	return nil
}

// checkSnapshot checks the header of snapshot, a prune's sealed snapshot of
// revision h of resource name of n (§8.6, §E.3.1): pl {ns, name, id}
// naming n, the resource and h, and the kid snapshotKid gives.
func (t *tx) checkSnapshot(n *nsRow, cfg *Config, name string, h *revRow, snapshot string) *Error {
	kns, epoch, why := t.snapshotKid(n, cfg, h)
	return t.checkSealedKid(snapshot, seal.SnapshotPL(n.name, name, h.id.String()), "snapshot", kns, epoch, why)
}

// snapshotKid is the kid a prune's snapshot of revision h of n must be
// sealed under (§E.3.1), as the namespace it names and the epoch, and why.
// It is set by the newest revision in h's chain, crossing foreign parents,
// that isn't a tombstone and whose patch set isn't []:
//
//   - a sealed op of n's own (its kid names n): that op's epoch;
//   - a patch set from before a raise from sealed, in the clear on the
//     server: the epoch that revision is served under (Addendum E Levels,
//     preRaiseEpoch). For n's own, an epoch of n's; for a base's content
//     that a branch reads through, one of that base's, which the branch
//     serves it under as the base does, so the kid names the base
//     (kidName): an epoch of the branch's own would open, to readers of
//     its later epochs, what Levels keep under the epoch before the raise;
//   - otherwise, a base's op or content from before a raise from none or
//     at-rest: n's epoch in force, cfg's.
//
// A revision below an earlier horizon has no patch set left; the snapshot
// kept at that horizon stands for it, its kid counting where it names n,
// or the base whose horizon it is with an epoch from before that base's
// raise from sealed (F-E2), as clients, which fold from that snapshot, see
// it too.
func (t *tx) snapshotKid(n *nsRow, cfg *Config, h *revRow) (string, int, string) {
	inForce := fmt.Sprintf("namespace %s's epoch in force", n.name)
	// The raise from sealed of the namespace owning a resource row, if any.
	owners := map[int64]*nsRow{}
	raises := map[int64]*e2eRaise{}
	ownerOf := func(res int64) (*nsRow, *e2eRaise) {
		if o, ok := owners[res]; ok {
			return o, raises[res]
		}
		var ns int64
		t.must(t.QueryRow(`SELECT ns FROM resources WHERE res = ?`, res).Scan(&ns))
		o := t.nsByID(ns)
		r := t.e2eRaiseOf(o)
		if r != nil && r.level != levelSealed {
			r = nil
		}
		owners[res], raises[res] = o, r
		return o, r
	}
	for _, seg := range t.ancestry(h) {
		var found *revRow
		var snap string
		// Newest first, a few rows at a time: no query runs while rows
		// are open (Postgres).
		for max := seg.max; found == nil; {
			rows, err := t.Query(`SELECT `+revCols+` FROM revisions WHERE res = ? AND seq <= ? ORDER BY seq DESC LIMIT 16`, seg.res, max)
			t.must(err)
			var page []*revRow
			for rows.Next() {
				r, err := scanRev(rows)
				t.must(err)
				page = append(page, r)
			}
			rows.Close()
			for _, r := range page {
				if jwe := t.e2eSnapshot(r); jwe != "" {
					// An earlier horizon, a tombstone one included.
					found, snap = r, jwe
					break
				}
				if r.kind == kindTombstone {
					continue
				}
				if !r.patches.Valid || string(t.patchesOf(r)) != "[]" {
					found = r
					break
				}
			}
			if len(page) < 16 {
				break
			}
			max = page[len(page)-1].seq - 1
		}
		if found == nil {
			continue
		}
		at := fmt.Sprintf("set by revision %s of its chain", found.id)
		if snap != "" {
			kns, e, err := seal.ParseKid(kidOf(snap))
			if err == nil && kns == n.name {
				return n.name, e, fmt.Sprintf("the epoch of the snapshot kept at horizon %s of its chain", found.id)
			}
			if o, r := ownerOf(found.res); err == nil && o.id != n.id && r != nil && kns == t.kidName(o) && e <= r.epoch {
				return kns, e, fmt.Sprintf("the epoch of the snapshot kept at horizon %s of its chain, from before %s's raise from sealed", found.id, o.name)
			}
			return n.name, cfg.Epoch, inForce
		}
		var canon []byte
		if found.patches.Valid {
			canon = t.patchesOf(found)
		}
		if jwe, _, ok := seal.SealedOp(canon); ok {
			if kns, e, err := seal.ParseKid(kidOf(jwe)); err == nil && kns == n.name {
				return n.name, e, at
			}
			return n.name, cfg.Epoch, inForce
		}
		// In the clear on the server: content from before a raise, n's own
		// or a base's read through.
		if o, r := ownerOf(found.res); r != nil {
			kns := t.kidName(o)
			return kns, t.preRaiseEpoch(o, found, r), fmt.Sprintf("%s, from before %s's raise from sealed, served under %s's epoch", at, o.name, kns)
		}
		return n.name, cfg.Epoch, inForce
	}
	return n.name, cfg.Epoch, inForce
}

// kidOf is the kid of a compact JWE's protected header, "" if it has none.
func kidOf(jwe string) string {
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return ""
	}
	return h.Kid
}

// ownRes reports whether resource row res belongs to n.
func (t *tx) ownRes(n *nsRow, res int64) bool {
	var ns int64
	t.must(t.QueryRow(`SELECT ns FROM resources WHERE res = ?`, res).Scan(&ns))
	return ns == n.id
}

// preRaiseEpoch is the epoch n serves its revision row r from before its
// raise from sealed under (Addendum E Levels, §E.2.2): the epoch r was
// written in (rev_epochs), else the one its first stored sealing fixed,
// else the last epoch before the raise, which stands for the current one
// for content from before it.
func (t *tx) preRaiseEpoch(n *nsRow, r *revRow, raise *e2eRaise) int {
	var e int
	if err := t.QueryRow(`SELECT epoch FROM rev_epochs WHERE seq = ?`, r.seq).Scan(&e); err == nil {
		return e
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	var prefix string
	err := t.QueryRow(`SELECT substr(jwe, 1, 4096) FROM sealed WHERE ns = ? AND rev_seq = ? AND kind IN ('doc', 'entry') ORDER BY created LIMIT 1`, n.id, r.seq).Scan(&prefix)
	if err == nil {
		if e, ok := jweEpoch(prefix); ok {
			return e
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	return raise.epoch
}

// applyStepsE2E is step 3 for a resource of an e2e namespace (§6.2): each
// patch step must be one sealed op bound to this write (or [] for a
// restore); nothing is applied.
func (t *tx) applyStepsE2E(n *nsRow, cfg *Config, s *itemState) *Error {
	var parentID *ids.ID
	tomb := false
	if s.parent != nil {
		p := s.parent.id
		parentID = &p
		tomb = s.parent.kind == kindTombstone
	}
	for j, step := range s.Steps {
		ss := &stepState{del: step.Delete, raw: step.Patches, parentID: parentID}
		if step.Delete {
			if j > 0 && s.Steps[j-1].Delete {
				return doubleDelete()
			}
			if parentID == nil || tomb {
				return gone()
			}
			ss.action, ss.id, ss.writes = "delete", ids.Tombstone(*parentID), []string{}
			tomb = true
		} else {
			switch {
			case parentID == nil:
				ss.action = "create"
			case tomb:
				ss.action = "restore"
			default:
				ss.action = "append"
			}
			ss.canon = s.canon(j)
			if ss.action == "restore" && string(ss.canon) == "[]" {
				ss.keepsList = true
			} else {
				jwe, blobs, ok := seal.SealedOp(step.Patches)
				if !ok {
					if ss.action == "restore" {
						return invalid(`e2e namespaces take a patch set of one sealed op, [{"op":"sealed","value":"<JWE>"}], or [] for a restore (§6.2, §E.3.1)`)
					}
					return invalid(`e2e namespaces take a patch set of one sealed op, [{"op":"sealed","value":"<JWE>"}] (§6.2, §E.3.1)`)
				}
				parent := ""
				if parentID != nil {
					parent = parentID.String()
				}
				if err := t.checkSealedHeader(n, jwe, seal.PatchSetPL(n.name, s.Resource, parent), "sealed patch set", cfg.Epoch, fmt.Sprintf("namespace %s's epoch in force", n.name)); err != nil {
					return err
				}
				var err *Error
				if ss.declared, err = parseDeclared(blobs); err != nil {
					return err
				}
			}
			ss.id = s.revID(j, parentID)
			ss.writes = []string{}
			ss.sealed = true
			tomb = false
		}
		id := ss.id
		parentID = &id
		s.steps = append(s.steps, ss)
	}
	return nil
}

// parseDeclared parses a sealed op's declared blob list (§E.3.1): distinct
// blob ids.
func parseDeclared(list []string) ([]ids.ID, *Error) {
	out := make([]ids.ID, 0, len(list))
	seen := map[ids.ID]bool{}
	for i, s := range list {
		id, err := ids.Parse(s)
		if err != nil {
			return nil, blobErr("/0/blobs/"+strconv.Itoa(i), "the declared blob list holds blob ids (§E.3.1)")
		}
		if seen[id] {
			return nil, blobErr("/0/blobs/"+strconv.Itoa(i), "the declared blob list names a blob twice (§E.3.1)")
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

// checkDeclared is step 4 for a sealed step (§6.2, §E.3.1): every blob of
// its declared list is available to the item's resource, and is a sealed
// blob, the only type an e2e reference has.
func (t *tx) checkDeclared(n *nsRow, s *itemState, step *stepState, list []ids.ID, uploader string, cutoff int64, bs *batchSource) *Error {
	step.blobs = map[ids.ID]*blobRow{}
	for i, bid := range list {
		ptr := "/0/blobs/" + strconv.Itoa(i)
		src := t.availableBlob(n, s, uploader, cutoff, bid, bs)
		if src == nil {
			return blobErr(ptr, "the declared blob is not available to this resource (§7.8, §E.3.1)")
		}
		if src.typ != SealedBlobType {
			return blobErr(ptr, "the declared blob is not a sealed blob (§E.3.1)")
		}
		if src.nonce != "" {
			// A client-encrypted blob's id is over ciphertext and needs
			// no nonce; one with a nonce isn't such a blob (§E.3.1).
			return blobErr(ptr, "the declared blob has a nonce; an end-to-end blob has none (§E.3.1)")
		}
		step.blobs[bid] = src
	}
	return nil
}

// declaredAt is the list of blobs the document at revision row references
// as the server knows it (blob_refs): at E3, the declared list of the
// revision, or for a tombstone that of the last live document (§E.3.1).
func (t *tx) declaredAt(row *revRow) []ids.ID {
	rows, err := t.Query(`SELECT bid FROM blob_refs WHERE res = ? AND from_seq <= ? AND (to_seq IS NULL OR to_seq > ?) ORDER BY bid`, row.res, row.seq, row.seq)
	t.must(err)
	defer rows.Close()
	var out []ids.ID
	for rows.Next() {
		var b []byte
		t.must(rows.Scan(&b))
		out = append(out, ids.FromBytes(b))
	}
	return out
}

// checkKeyring checks the keyring resource's documents in an e2e
// namespace (§E.3.2): the keyring document, { "keys": [{ kid, to, from,
// wrapped }] } with nothing else but a $nonce and no two entries for one
// kid and to (seal.ParseKeyringV2), whose kids name this namespace and
// epochs not after encryption.epoch. A keyring in the format before v0.63
// is refused like any other document: a key holder wraps it again.
func (t *tx) checkKeyring(n *nsRow, cfg *Config, s *itemState) *Error {
	for _, st := range s.steps {
		if st.del {
			continue
		}
		kr, err := seal.ParseKeyringV2(st.doc)
		if err != nil {
			msg := "the keyring resource of an e2e namespace must be a keyring document, { \"keys\": [{ \"kid\", \"to\", \"from\", \"wrapped\" }] } (§E.3.2): " + err.Error()
			if _, lerr := seal.ParseKeyring(st.doc); lerr == nil {
				msg = "the keyring is in the format before v0.63; a key holder wraps its keys again in the §E.3.2 keyring document (client.E2E.MigrateKeyring, patchlog e2e migrate-keyring)"
			}
			return invalid(msg)
		}
		for _, e := range kr.Entries {
			kns, ep, _ := seal.ParseKid(e.Kid)
			if kns != n.name {
				return invalid(fmt.Sprintf("the keyring's kids must name namespace %q, not %q (§E.3.2)", n.name, e.Kid))
			}
			if ep > cfg.Epoch {
				return invalid(fmt.Sprintf("the keyring names epoch %d, after the namespace's encryption.epoch %d; bump the epoch in the same batch", ep, cfg.Epoch))
			}
		}
	}
	return nil
}

// e2eFoldSince is the id of the latest client-supplied snapshot at or
// before row in its ancestry (crossing foreign parents), or "".
func (t *tx) e2eFoldSince(row *revRow) string {
	for _, sg := range t.ancestry(row) {
		var seq sql.NullInt64
		t.must(t.QueryRow(`SELECT MAX(seq) FROM e2e_snapshots WHERE res = ? AND seq <= ?`, sg.res, sg.max).Scan(&seq))
		if seq.Valid {
			return t.rev(seq.Int64).id.String()
		}
	}
	return ""
}

// e2eSnapshot returns the stored snapshot of row, or "".
func (t *tx) e2eSnapshot(row *revRow) string {
	var jwe string
	if err := t.QueryRow(`SELECT jwe FROM e2e_snapshots WHERE seq = ?`, row.seq).Scan(&jwe); err != nil {
		return ""
	}
	return jwe
}

// keysE2E answers POST /ns/{ns}/keys for an e2e namespace (§E.2.3,
// §E.3.2): the keyring entries whose to is the thumbprint of the grant's
// enc, with their from. Those of n's own keyring, for the epochs of the
// §E.2.3 window the request asks; in a branch, those of each base's
// keyring as of at (§F.8.1), whether or not the branch has written its own
// since, for that base's epochs baseEpochs selects, which the request's
// epochs don't narrow. A remote branch's shadows are bases like any other:
// each holds a level of the remote base's chain as of at (§G.5.2).
//
// The epochs before an e2e raise from sealed aren't keyring epochs: the
// origin holds their keys, and gives them as at E2 (Addendum E Levels,
// preRaiseKeys), n's own for the epochs of the same window, and in a branch
// each base's for the base epochs baseEpochs selects, K_r derived with the
// base's namespace; a remote branch's shadow holds those its source gave
// this deployment's grant (fetchPreRaiseKeys).
func (t *tx) keysE2E(n *nsRow, cfg *Config, a *actor, kr KeysRequest) ([]map[string]any, error) {
	enc := recipientOf(a)
	if enc == nil {
		return nil, invalid("e2e namespaces relay only wrapped keys: the grant's root block needs enc, an X25519 public key (§E.2.3, §E.3.2)")
	}
	// Once nothing is refused, the request draws its exchangeRate token,
	// as /edge-grants does (§E.2.3, §C.5.2).
	if err := t.drawExchange(a); err != nil {
		return nil, err
	}
	out := []map[string]any{}
	seen := map[string]bool{} // kids relayed, with name for a K_r
	add := func(entries []map[string]any) {
		for _, e := range entries {
			kid, _ := e["kid"].(string)
			if name, ok := e["name"].(string); ok {
				kid += "\n" + name
			}
			if !seen[kid] {
				seen[kid] = true
				out = append(out, e)
			}
		}
	}
	window := selectEpochs(t.grantEpochsOf(t.keyEpochs(n, cfg.Epoch), cfg, a), kr.Epochs)
	if d := t.ownKeyring(n, nil); d != nil {
		add(keyringEntries(d, enc, window))
	}
	keys, err := t.preRaiseKeys(n, window, a, kr, enc)
	if err != nil {
		return nil, err
	}
	add(keys)
	for child := n; child.isBranch(); {
		b := t.nsByID(child.base.Int64)
		at := child.baseAt.Int64
		epochs := t.baseEpochs(b, at, a)
		if d := t.ownKeyring(b, &at); d != nil {
			add(keyringEntries(d, enc, epochs))
		}
		keys, err := t.preRaiseKeys(b, epochs, a, kr, enc)
		if err != nil {
			return nil, err
		}
		add(keys)
		child = b
	}
	return out, nil
}

// ownKeyring returns the keyring document of n itself as of asOf (nil:
// now), nil if n has no live keyring of its own then: one it reads through
// from a base is that base's.
func (t *tx) ownKeyring(n *nsRow, asOf *int64) any {
	v := t.resolve(n, KeyringName, asOf)
	if v.state != Live || v.head == nil || v.src == nil || v.src.ns != n.id {
		return nil
	}
	d, err := t.docAt(v.head)
	if err != nil {
		return nil
	}
	return d
}

// keyEpochs lists n's epochs up to max with when each began, ascending, as
// the §E.2.3 window reads them at E3: those begun at e2e (e2e_epochs) and,
// after a raise from sealed, the epochs before it, whose keys the origin
// holds (epoch_keys), up to the last one before the raise.
func (t *tx) keyEpochs(n *nsRow, max int) []epochStart {
	all := t.epochStarts(`e2e_epochs`, n.id, max)
	r := t.e2eRaiseOf(n)
	if r == nil || r.level != levelSealed {
		return all
	}
	return append(t.epochStarts(`epoch_keys`, n.id, min(max, r.epoch)), all...)
}

// epochNow is the epoch base b has in force now (§E.2.3): its document's,
// or for a remote branch's shadow, whose document stays as the remote base's
// was at at, the latest of the source's epochs the follower has seen
// (followRemote), if later.
func (t *tx) epochNow(b *nsRow) int {
	cur := t.config(b.configSeq).Epoch
	if !b.isShadow() {
		return cur
	}
	var max sql.NullInt64
	t.must(t.QueryRow(`SELECT MAX(epoch) FROM e2e_epochs WHERE ns = ?`, b.id).Scan(&max))
	if max.Valid && int(max.Int64) > cur {
		return int(max.Int64)
	}
	return cur
}

// baseEpochs lists the epochs of base b whose keys a branch's /keys gives
// from b as of at, b's namespace entry seq (§E.2.3): b's epochs up to the
// one in force at at, starting from the one b had in force at the latest
// nbf among the grant's blocks, or at at if that is earlier; where no
// block has nbf, the epoch b has in force now (epochNow), so none once b
// has moved past its epoch at at. Without a grant (authentication
// disabled), every epoch up to at. They are keyring epochs, and after a
// raise from sealed those before it too (keyEpochs), whose keys the origin
// gives as at E2 (preRaiseKeys); a base at at that isn't e2e gives none.
func (t *tx) baseEpochs(b *nsRow, at int64, a *actor) []int {
	var cseq, created int64
	if err := t.QueryRow(`SELECT config_seq, created FROM ns_log WHERE seq = ?`, at).Scan(&cseq, &created); err != nil {
		return nil
	}
	acfg := t.config(cseq)
	if acfg.level != levelE2E {
		return nil
	}
	atEpoch := acfg.Epoch
	all := t.keyEpochs(b, atEpoch)
	if len(all) == 0 {
		return nil
	}
	first := all[0].e
	if a != nil && a.grant != nil {
		nbf := latestNbf(a)
		switch {
		case nbf == nil:
			if t.epochNow(b) != atEpoch {
				return nil
			}
			first = atEpoch
		case !nbf.Before(time.UnixMilli(created)):
			first = atEpoch
		default:
			for _, x := range all {
				if !x.created.After(*nbf) {
					first = x.e
				}
			}
		}
	}
	var out []int
	for _, x := range all {
		if x.e >= first {
			out = append(out, x.e)
		}
	}
	return out
}

// preRaiseKeys gives grant a, asking /keys of an e2e namespace, the keys of
// owner's epochs from before its raise from sealed among epochs, as /keys
// gives them at E2 (Addendum E Levels, §E.2.3): owner is that namespace or
// one of its bases. A grant whose rules fix /resource (§2.1) gets K_r of
// the names asked, by default every name its rules fix; any other gets K_e
// if it reads the namespace unrestricted. What E2 would refuse with 403 is
// left out instead: names the rules don't fix or the grant may not read,
// and every key for a grant that neither fixes names nor reads
// unrestricted. Kids, and K_r, name the namespace owner's content is
// sealed under (kidName): owner itself, or for a remote branch's shadow
// its source. Keys are wrapped to enc in HPKE base mode, like any key the
// origin hands out (§E.2.3), so they carry no from. Nothing for an owner
// that wasn't raised from sealed: content from before a raise from none or
// at-rest is in the clear.
func (t *tx) preRaiseKeys(owner *nsRow, epochs []int, a *actor, kr KeysRequest, enc *ecdh.PublicKey) ([]map[string]any, error) {
	r := t.e2eRaiseOf(owner)
	if r == nil || r.level != levelSealed {
		return nil, nil
	}
	var pre []int
	for _, e := range epochs {
		if e <= r.epoch {
			pre = append(pre, e)
		}
	}
	if len(pre) == 0 {
		return nil, nil
	}
	names, perResource, none := t.preRaiseScope(a, kr)
	if none {
		return nil, nil
	}
	kns := t.kidName(owner)
	var out []map[string]any
	for _, e := range pre {
		if !t.hasEpochKey(owner.id, e) {
			// A remote branch's shadow holds only the keys its source gave
			// this deployment (fetchPreRaiseKeys).
			continue
		}
		ke := t.epochKey(owner.id, e)
		kid := seal.Kid(kns, e)
		if !perResource {
			w, err := seal.WrapKey(enc, kid, "", ke)
			if err != nil {
				return nil, err
			}
			out = append(out, w.Value())
			continue
		}
		for _, name := range names {
			k, err := seal.ResourceKey(ke, kns, name)
			if err != nil {
				return nil, err
			}
			w, err := seal.WrapKey(enc, kid, name, k)
			if err != nil {
				return nil, err
			}
			out = append(out, w.Value())
		}
	}
	return out, nil
}

// preRaiseScope is keysScope for the keys of epochs from before an e2e
// raise (preRaiseKeys), which leaves out what keysScope refuses: the names
// asked, by default every name a's rules fix, that they fix and a may read
// (perResource), or, for rules that fix no name, K_e if a reads the
// namespace unrestricted; none when a gets no key. Without a grant
// (authentication disabled), K_e.
func (t *tx) preRaiseScope(a *actor, kr KeysRequest) (names []string, perResource, none bool) {
	if a == nil || a.verified == nil {
		return nil, false, false
	}
	fixed, fixes := fixedNames(a)
	if !fixes {
		return nil, false, !t.readsUnrestricted(a)
	}
	in := make(map[string]bool, len(fixed))
	for _, n := range fixed {
		in[n] = true
	}
	want := kr.Resources
	if want == nil {
		want = fixed
	}
	seen := map[string]bool{}
	for _, r := range want {
		if seen[r] || !in[r] {
			continue
		}
		seen[r] = true
		if t.grantRules(a, "read", nil, t.basicEnvelope("read", r, a), false) == nil {
			names = append(names, r)
		}
	}
	sort.Strings(names)
	return names, true, len(names) == 0
}

// hasEpochKey reports whether the key of (ns, epoch) is stored.
func (t *tx) hasEpochKey(ns int64, epoch int) bool {
	var ok bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM epoch_keys WHERE ns = ? AND epoch = ?)`, ns, epoch).Scan(&ok))
	return ok
}

// kidName is the namespace that kids of b's content name: b itself, or for
// a remote branch's shadow the namespace of the remote base's chain it
// mirrors, whose name read-through ciphertext keeps (§G.5.2): the remote
// base for the branch's first shadow, and its base.chain's i-th name for
// the shadow i levels below.
func (t *tx) kidName(b *nsRow) string {
	if !b.isShadow() {
		return b.name
	}
	cur := b.id
	for depth := 0; ; depth++ {
		var branch int64
		var ns string
		err := t.QueryRow(`SELECT branch, ns FROM remote_bases WHERE shadow = ?`, cur).Scan(&branch, &ns)
		if err == nil {
			if depth == 0 {
				return ns
			}
			if base := t.config(t.nsByID(branch).configSeq).Base; base != nil && depth < len(base.Chain) {
				return base.Chain[depth]
			}
			return b.name
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
		// The shadow above reads through this one.
		if t.QueryRow(`SELECT ns FROM namespaces WHERE base = ? AND name LIKE '~%'`, cur).Scan(&cur) != nil {
			return b.name
		}
	}
}

// keyringEntries returns the entries of keyring document d for the
// recipient enc, of the given epochs, as /keys relays them (§E.2.3): the
// entries whose to is enc's thumbprint, with from. Each entry's kid names
// the keyring's owner, checked when it was written; for a remote branch's
// shadow, the remote base (§G.5). A keyring stored in the format before
// v0.63 (seal.Keyring), which the gate refuses to write now, is relayed as
// stored, without from, until a key holder wraps it again.
func keyringEntries(d any, enc *ecdh.PublicKey, epochs []int) []map[string]any {
	want := make(map[int]bool, len(epochs))
	for _, e := range epochs {
		want[e] = true
	}
	var out []map[string]any
	if ring, err := seal.ParseKeyringV2(d); err == nil {
		for _, e := range ring.To(seal.Thumbprint(enc)) {
			if _, ep, err := seal.ParseKid(e.Kid); err == nil && want[ep] {
				out = append(out, e.Relayed().Value())
			}
		}
		return out
	}
	old, err := seal.ParseKeyring(d)
	if err != nil {
		return nil
	}
	for _, e := range epochs {
		if w, err := seal.Lookup(old, enc, e); err == nil {
			out = append(out, w.Value())
		}
	}
	return out
}

// pruneToE2E prunes an e2e resource below h (§8.6). h is the horizon after
// protect; it must be the requested one, since snapshot is sealed for it.
// The pruned range is archived first, snapshot becomes h's kept document,
// and no document is computed.
func (t *tx) pruneToE2E(n *nsRow, cfg *Config, name string, own *resRow, h *revRow, requested ids.ID, pr PruneRequest, dest string, author int64) (*PruneResult, error) {
	snapshot := pr.Snapshot
	cur := own.horizonSeq
	if cur.Valid && h.seq <= cur.Int64 {
		return &PruneResult{Horizon: t.rev(cur.Int64).id.String()}, nil
	}
	var below bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ? AND seq < ?)`, own.id, h.seq).Scan(&below))
	if !below {
		return &PruneResult{Horizon: h.id.String()}, nil
	}
	if h.id != requested {
		return nil, apiErr(422, "invalid", "message", "the horizon moves down to a protected revision (§8.6); seal the snapshot for that one", "horizon", h.id.String())
	}
	if err := t.checkSnapshot(n, cfg, name, h, snapshot); err != nil {
		return nil, err
	}
	// The snapshot needs no list (§8.6, §E.3.1): the server keeps the
	// declared list of every revision, and the snapshot's document is h's
	// (for a tombstone, the last live one's, whose runs a tombstone
	// doesn't close).
	kept := t.declaredAt(h)
	// A horizon whose document is from before a raise to e2e, in the clear
	// on the server (Addendum E Levels, §8.6): /rev/{h} is served as before
	// the raise, so the document is kept, as a prune outside E3 keeps it,
	// and so are its stored sealings after a raise from sealed, which fixed
	// the epoch it is served under (§E.2.2). A document that folds over a
	// sealed op isn't the server's to keep.
	keepDocs := map[int64]*revRow{}
	var keptDoc []byte
	if ll := t.lastLive(h); ll.res == own.id && t.e2eRaiseOf(n) != nil {
		if doc, err := t.docBytesAt(ll); err == nil {
			keepDocs[ll.seq], keptDoc = ll, doc
		}
	}
	from := own.horizonSeq.Int64
	if !cur.Valid {
		t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ?`, own.id).Scan(&from))
	}
	u, err := t.writeArchive(n, name, own.id, from, h, dest)
	if err != nil {
		return nil, err
	}
	res := &PruneResult{Horizon: h.id.String(), Archive: u}
	_, err = t.Exec(`INSERT INTO e2e_snapshots (seq, res, jwe) VALUES (?,?,?) ON CONFLICT (seq) DO UPDATE SET res = excluded.res, jwe = excluded.jwe`, h.seq, own.id, snapshot)
	t.must(err)
	// /rev/{h} now serves the snapshot (§7.1 Paging) instead of the fold
	// redirect it may have been cached as: purge the resource's tag, so a
	// fold that starts at h doesn't get the old redirect from a CDN.
	t.tags = append(t.tags, "r:"+n.name+"/"+name)
	// Attachments end unless the snapshot or a revision after the horizon
	// declares them (§7.8, §E.3.1); the archive written above has them.
	t.pruneBlobsE2E(own.id, h.seq, kept)
	_, err = t.Exec(`UPDATE revisions SET patches = NULL WHERE res = ? AND seq < ? AND kind = 0`, own.id, h.seq)
	t.must(err)
	_, err = t.Exec(`DELETE FROM e2e_snapshots WHERE res = ? AND seq < ?`, own.id, h.seq)
	t.must(err)
	for seq, row := range keepDocs {
		_, err = t.Exec(`INSERT INTO snapshots (seq, res, doc) VALUES (?,?,?) ON CONFLICT (seq) DO UPDATE SET res = excluded.res, doc = excluded.doc`, seq, own.id, t.putDoc("snapshots", own.id, row.seq, keptDoc))
		t.must(err)
	}
	// Below the horizon, the documents and sealings of pre-raise content
	// go but the kept one's (pruneTo).
	for _, seq := range t.droppedBelow(own.id, h.seq, keepDocs, nil) {
		_, err = t.Exec(`DELETE FROM snapshots WHERE seq = ?`, seq)
		t.must(err)
	}
	t.flushDocs = true
	t.deletePrunedSealed(own.id, h.seq, keepDocs)
	_, err = t.Exec(`UPDATE resources SET horizon_seq = ?, keep = '[]' WHERE res = ?`, h.seq, own.id)
	t.must(err)
	target := h.seq
	_, nsID := t.appendNS(n, map[string]any{"resource": name, "kind": "prune", "target": h.id.String()}, &own.id, &target, n.configSeq, author)
	res.NSID = nsID.String()
	return res, nil
}

// pruneBlobsE2E ends the attachments of res that neither kept, the
// snapshot's declared list, nor the declared list of a revision after the
// horizon hseq names (§7.8, §E.3.1). blob_refs keeps every declared list
// after pruning, with the revisions' skeletons; the snapshot's stands for
// the horizon's document, so the horizon's own list counts only through it.
func (t *tx) pruneBlobsE2E(res, hseq int64, kept []ids.ID) {
	keep := map[ids.ID]bool{}
	for _, bid := range kept {
		keep[bid] = true
	}
	var next sql.NullInt64
	t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ? AND seq > ?`, res, hseq).Scan(&next))
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
		alive := keep[b.bid]
		if !alive && next.Valid {
			// An interval [from, to) of the chain covers a revision after
			// the horizon exactly when it reaches past the next one.
			t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_refs WHERE res = ? AND bid = ? AND (to_seq IS NULL OR to_seq > ?))`, res, b.bid[:], next.Int64).Scan(&alive))
		}
		if alive {
			continue
		}
		_, err := t.Exec(`UPDATE blobs SET pruned = 1 WHERE res = ? AND bid = ?`, res, b.bid[:])
		t.must(err)
		t.gcBytes(b.owner, b.hash)
	}
}
