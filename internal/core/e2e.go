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
	"fmt"
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
// creation (or a branch's), and every write that increments the epoch.
func (t *tx) e2eConfigWritten(n *nsRow, old, cfg *Config) {
	if cfg.level != levelE2E {
		return
	}
	if old != nil && old.level == levelE2E && old.Epoch == cfg.Epoch {
		return
	}
	_, err := t.Exec(`INSERT INTO e2e_epochs (ns, epoch, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`, n.id, cfg.Epoch, t.now.UnixMilli())
	t.must(err)
}

// e2eEpochOK reports whether epoch e of n may seal what is checked under
// cfg. A sealed op of a write names the epoch in force (§E.3.1, invariant
// 6): cfg's, which for a batch's items is the configuration its config
// change produces (§7.5). Any other (a prune's snapshot, whose kid follows
// its revision's chain, §8.6) names an epoch that began, at or after n's
// first, and isn't after cfg's current one.
func (t *tx) e2eEpochOK(n *nsRow, cfg *Config, e int, inForce bool) bool {
	if inForce {
		return e == cfg.Epoch
	}
	var first sql.NullInt64
	t.must(t.QueryRow(`SELECT MIN(epoch) FROM e2e_epochs WHERE ns = ?`, n.id).Scan(&first))
	lo := cfg.Epoch
	if first.Valid && int(first.Int64) < lo {
		lo = int(first.Int64)
	}
	return e >= lo && e <= cfg.Epoch
}

// checkSealedHeader checks a JWE's protected header without a key (§E.3.1,
// step 3): no zip (§E.2.2), kid "{ns}#{e}" for the epoch in force with
// inForce (a write's sealed op) or else a usable epoch of n
// (e2eEpochOK), and pl exactly want.
func (t *tx) checkSealedHeader(n *nsRow, cfg *Config, jwe string, want seal.PL, what string, inForce bool) *Error {
	h, err := seal.ParseHeader(jwe)
	if err != nil || strings.Split(jwe, ".")[1] != "" {
		return invalid(fmt.Sprintf("the %s is not a compact JWE with alg dir and enc A256GCM", what))
	}
	if h.Zip != "" {
		return invalid(fmt.Sprintf("the %s's protected header has zip: sealed payloads are never compressed (§E.2.2)", what))
	}
	kns, e, err := seal.ParseKid(h.Kid)
	if err != nil || kns != n.name {
		return invalid(fmt.Sprintf("the %s's kid must be %q#{epoch}", what, n.name))
	}
	if !t.e2eEpochOK(n, cfg, e, inForce) {
		if inForce {
			return invalid(fmt.Sprintf("the %s is sealed under epoch %d, not namespace %s's epoch in force, %d (§E.3.1)", what, e, n.name, cfg.Epoch))
		}
		return invalid(fmt.Sprintf("the %s is sealed under epoch %d, which namespace %s doesn't have (current: %d)", what, e, n.name, cfg.Epoch))
	}
	if !jsonv.Equal(map[string]any(h.PL), jsonv.FromGo(map[string]any(want))) {
		return apiErr(422, "invalid", "message", fmt.Sprintf("the %s's pl must bind this write exactly", what), "pl", jsonv.FromGo(map[string]any(want)))
	}
	return nil
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
				if err := t.checkSealedHeader(n, cfg, jwe, seal.PatchSetPL(n.name, s.Resource, parent), "sealed patch set", true); err != nil {
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
// §E.2.3 window the request asks; in a branch, those of each local base's
// keyring as of at (§F.8.1), whether or not the branch has written its own
// since, for that base's epochs baseEpochs selects, which the request's
// epochs don't narrow; and for a remote branch, those of the shadows it
// reads through.
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
	seen := map[string]bool{} // kids relayed
	add := func(entries []map[string]any) {
		for _, e := range entries {
			if kid, _ := e["kid"].(string); !seen[kid] {
				seen[kid] = true
				out = append(out, e)
			}
		}
	}
	if d := t.ownKeyring(n, nil); d != nil {
		add(keyringEntries(d, enc, selectEpochs(t.grantEpochsOf(t.epochStarts(`e2e_epochs`, n.id, cfg.Epoch), cfg, a), kr.Epochs)))
	}
	for child := n; child.isBranch(); {
		b := t.nsByID(child.base.Int64)
		if b.isShadow() {
			// A remote branch's shadows may hold keyrings of the remote
			// base's own bases, mirrored as foreign parents or read
			// through (§G.5.2): readers need them for the ciphertext
			// those bases sealed.
			for _, sh := range t.remoteShadows(child) {
				add(t.relayKeyring(sh, a, kr, enc))
			}
			break
		}
		at := child.baseAt.Int64
		if d := t.ownKeyring(b, &at); d != nil {
			add(keyringEntries(d, enc, t.baseEpochs(b, at, a)))
		}
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

// baseEpochs lists the epochs of local base b whose keys a branch's /keys
// relays from b's keyring as of at, b's namespace entry seq (§E.2.3): b's
// epochs up to the one in force at at, starting from the one b had in
// force at the latest nbf among the grant's blocks, or at at if that is
// earlier; where no block has nbf, the epoch b has in force now, so none
// once b has moved past its epoch at at. Without a grant (authentication
// disabled), every epoch up to at. Epochs from before an e2e raise are
// not keyring epochs (Levels, P36).
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
	all := t.epochStarts(`e2e_epochs`, b.id, atEpoch)
	if len(all) == 0 {
		return nil
	}
	first := all[0].e
	if a != nil && a.grant != nil {
		nbf := latestNbf(a)
		switch {
		case nbf == nil:
			if t.config(b.configSeq).Epoch != atEpoch {
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

// relayKeyring returns the entries for enc of the keyring as n, a remote
// branch's shadow, sees it, for the epochs of the §E.2.3 window of the
// keyring's owner that the request asks.
func (t *tx) relayKeyring(n *nsRow, a *actor, kr KeysRequest, enc *ecdh.PublicKey) []map[string]any {
	v := t.resolve(n, KeyringName, nil)
	if v.state != Live || v.head == nil {
		return nil
	}
	d, err := t.docAt(v.head)
	if err != nil {
		return nil
	}
	owner := n
	if v.src != nil && v.src.ns != n.id {
		owner = t.nsByID(v.src.ns)
	}
	ocfg := t.config(owner.configSeq)
	return keyringEntries(d, enc, selectEpochs(t.grantEpochsOf(t.epochStarts(`e2e_epochs`, owner.id, ocfg.Epoch), ocfg, a), kr.Epochs))
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
	if err := t.checkSealedHeader(n, cfg, snapshot, seal.SnapshotPL(n.name, name, h.id.String()), "snapshot", false); err != nil {
		return nil, err
	}
	// The snapshot needs no list (§8.6, §E.3.1): the server keeps the
	// declared list of every revision, and the snapshot's document is h's
	// (for a tombstone, the last live one's, whose runs a tombstone
	// doesn't close).
	kept := t.declaredAt(h)
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
