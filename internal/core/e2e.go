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
//     parent} and kid an epoch of the namespace that has begun and isn't
//     after the current one. That is a consistency check that catches client
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
//   - The keyring. The reserved resource "keyring" holds the seal keyring
//     (seal.Keyring) in plaintext: wrapped epoch keys and public JWKs only.
//     Key-holding admin clients write it with ordinary plaintext writes,
//     which the gate checks like any other plus seal.ParseKeyring, ns equal
//     to the namespace and current not after encryption.epoch. It is the
//     only plaintext resource of an e2e namespace.
//   - Epochs. encryption.epoch works as at E2, but the server holds no key:
//     e2e_epochs records when each epoch began (for POST /keys and kid
//     checks). A key holder rotates by re-wrapping the keyring and bumping
//     the epoch, in one batch.
//   - Reads. GET /r/{ns}/{name}/rev/{id} answers 302 to
//     /r/{ns}/{name}/rev/{id}/log?since={s} with X-E2E: fold, where s is
//     the latest client-supplied snapshot at or before id (omitted if none).
//     The log serves the stored entries (the ciphertext is inside), and a
//     range whose since has a snapshot starts with
//     {"id": s, "kind": "snapshot", "snapshot": "<JWE>"}. Clients fold.
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
//   - POST /ns/{ns}/keys relays the keyring's wrapped keys for the grant's
//     enc recipient only.

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/rules"
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

// e2eEpochOK reports whether epoch e of n may seal a write under cfg: it
// began (at or after n's first epoch) and isn't after cfg's current one.
// cfg may be a batch's new configuration, whose epoch isn't recorded yet.
func (t *tx) e2eEpochOK(n *nsRow, cfg *Config, e int) bool {
	var first sql.NullInt64
	t.must(t.QueryRow(`SELECT MIN(epoch) FROM e2e_epochs WHERE ns = ?`, n.id).Scan(&first))
	lo := cfg.Epoch
	if first.Valid && int(first.Int64) < lo {
		lo = int(first.Int64)
	}
	return e >= lo && e <= cfg.Epoch
}

// checkSealedHeader checks a JWE's protected header without a key: kid
// "{ns}#{e}" for a usable epoch of n, and pl exactly want.
func (t *tx) checkSealedHeader(n *nsRow, cfg *Config, jwe string, want seal.PL, what string) *Error {
	h, err := seal.ParseHeader(jwe)
	if err != nil || strings.Split(jwe, ".")[1] != "" {
		return invalid(fmt.Sprintf("the %s is not a compact JWE with alg dir and enc A256GCM", what))
	}
	kns, e, err := seal.ParseKid(h.Kid)
	if err != nil || kns != n.name {
		return invalid(fmt.Sprintf("the %s's kid must be %q#{epoch}", what, n.name))
	}
	if !t.e2eEpochOK(n, cfg, e) {
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
	for _, step := range s.Steps {
		ss := &stepState{del: step.Delete, raw: step.Patches, parentID: parentID}
		if step.Delete {
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
			ss.canon = jsonv.Canonical(step.Patches)
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
				if err := t.checkSealedHeader(n, cfg, jwe, seal.PatchSetPL(n.name, s.Resource, parent), "sealed patch set"); err != nil {
					return err
				}
				var err *Error
				if ss.declared, err = parseDeclared(blobs); err != nil {
					return err
				}
			}
			ss.id = ids.Revision(parentID, ss.canon)
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
// namespace: a keyring of this namespace whose current epoch has begun.
func (t *tx) checkKeyring(n *nsRow, cfg *Config, s *itemState) *Error {
	for _, st := range s.steps {
		if st.del {
			continue
		}
		kr, err := seal.ParseKeyring(st.doc)
		if err != nil {
			return invalid("the keyring resource of an e2e namespace must be a keyring document (§E.3.2): " + err.Error())
		}
		if kr.NS != n.name {
			return invalid(fmt.Sprintf("the keyring's ns must be %q", n.name))
		}
		if kr.Current > cfg.Epoch {
			return invalid(fmt.Sprintf("the keyring names epoch %d, after the namespace's encryption.epoch %d; bump the epoch in the same batch", kr.Current, cfg.Epoch))
		}
	}
	return nil
}

// blindRule reports a rule the server can't evaluate for a sealed write:
// it reads writes, doc or the whole envelope (§6.2).
func blindRule(r *rules.Rule) (string, bool) {
	refs := r.Refs()
	switch {
	case refs["*"]:
		return "", true
	case refs["writes"]:
		return "writes", true
	case refs["doc"]:
		return "/doc", true
	}
	return "", false
}

const blindMsg = "the server can't see writes or /doc of a sealed write in an e2e namespace, so a rule reading them fails the write (§6.2, §E.3.2)"

// checkRulesE2E is step 6 for a sealed create, append or restore: like
// checkRules, but a namespace rule reading writes or /doc fails with 422
// rule, and such a grant, key or role rule with 403.
func (t *tx) checkRulesE2E(cfg *Config, a *actor, env map[string]any) *Error {
	verb := env["action"].(string)
	if a.verified != nil {
		if ok, _ := a.verified.Allows(verb); !ok {
			return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
		}
	}
	for i, r := range cfg.Rules {
		if p, blind := blindRule(r); blind {
			return apiErr(422, "rule", "rule", i, "path", p, "message", blindMsg)
		}
		if _, path, ok := rules.EvalList([]*rules.Rule{r}, env); !ok {
			return apiErr(422, "rule", "rule", i, "path", path)
		}
	}
	return t.grantRulesMode(a, verb, nil, env, false, true)
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

// keysE2E answers POST /ns/{ns}/keys for an e2e namespace (§E.3.2): the
// keyring's entries wrapped to the grant's enc, for the epochs the grant
// may have (the §E.2.3 range). The keyring is read as n sees it, so a
// branch without its own relays its base's.
func (t *tx) keysE2E(n *nsRow, cfg *Config, a *actor, kr KeysRequest) ([]map[string]any, error) {
	enc := recipientOf(a)
	if enc == nil {
		return nil, invalid("e2e namespaces relay only wrapped keys: the grant's root block needs enc, an X25519 public key (§E.2.3, §E.3.2)")
	}
	out := []map[string]any{}
	seen := map[string]bool{}
	rid := seal.RecipientID(enc)
	out = t.relayKeyring(out, seen, n, a, kr, rid)
	// A remote branch's shadows may hold keyrings of the remote base's own
	// bases, mirrored as foreign parents or read through (§G.5.2): readers
	// need them for the ciphertext those bases sealed.
	for _, sh := range t.remoteShadows(n) {
		out = t.relayKeyring(out, seen, sh, a, kr, rid)
	}
	return out, nil
}

// relayKeyring appends to out the entries for rid of the keyring as n sees
// it, unless one of the same namespace was relayed already.
func (t *tx) relayKeyring(out []map[string]any, seen map[string]bool, n *nsRow, a *actor, kr KeysRequest, rid string) []map[string]any {
	v := t.resolve(n, KeyringName, nil)
	if v.state != Live || v.head == nil {
		return out
	}
	d, err := t.docAt(v.head)
	if err != nil {
		return out
	}
	ring, err := seal.ParseKeyring(d)
	if err != nil || seen[ring.NS] {
		return out
	}
	seen[ring.NS] = true
	owner := n
	if v.src != nil && v.src.ns != n.id {
		owner = t.nsByID(v.src.ns)
	}
	ocfg := t.config(owner.configSeq)
	epochs := t.grantEpochsOf(t.epochStarts(`e2e_epochs`, owner.id, ocfg.Epoch), ocfg, a)
	if kr.Epochs != nil {
		want := map[int]bool{}
		for _, x := range kr.Epochs {
			want[x] = true
		}
		var keep []int
		for _, x := range epochs {
			if want[x] {
				keep = append(keep, x)
			}
		}
		epochs = keep
	}
	for _, e := range epochs {
		if w, ok := ring.Epochs[e][rid]; ok {
			// The keyring's ns is its owner's, checked when it was written;
			// for a remote branch's shadow, the remote base's (§G.5).
			out = append(out, seal.WrappedKey{Kid: seal.Kid(ring.NS, e), Wrapped: w}.Value())
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
	if err := t.checkSealedHeader(n, cfg, snapshot, seal.SnapshotPL(n.name, name, h.id.String()), "snapshot"); err != nil {
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
