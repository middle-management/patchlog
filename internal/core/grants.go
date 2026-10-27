package core

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Reading stored grants (§C.3.1): GET /ns/{ns}/grants/{gid} answers
// { id, root, stored } for a grant recorded by an entry of the namespace
// or, in a local branch, of its bases up to their at, recursively. stored
// is the non-bearer form (§C.8) of the first token recorded with that id:
// its authority block, one protobuf SignedBlock in base64url without
// padding, never a narrowing block. Rows stored before v0.73 hold the
// whole chain, of which storedGrant keeps the authority block.
//
// "Recorded by an entry" is read from the namespace log: every entry
// written on a request stores its grant's id (ns_log.grant_id, grantref.go),
// and the revisions and tombstones of a write record the same grant as its
// entry. A remote branch's base is followed no further than the branch
// itself: what it reads through is verified at its base (§G.3).
//
// It needs unrestricted read on the namespace, as every /ns/{ns} URL but
// the gestures listing does (§C.5). A purged namespace answers 410
// "purged" once the read check passes, an unknown grant id included, since
// the content the grant's signatures cover is gone (§8.5). A grant id
// names its root block, and the stored form doesn't change once recorded,
// so the answer is immutable. Sealed namespaces seal it like a log entry,
// under the epoch key, with pl { ns, grant: gid } (§E.2.2): sealed once,
// stored in the sealed table and served identically forever. The epoch is
// the one sealing the namespace's first entry recording it, or the current
// one for a grant only its bases record. Answers sealed before v0.73 held
// stored as an array of every SignedBlock: the answer in today's shape is
// sealed and stored under a key of its own (grantSealKey), in the same
// epoch, the first time it is read, and served from then on. End-to-end
// namespaces serve it in the clear, as their logs are, but marked Private:
// Cache-Control private instead of the immutable class (§9), since a grant
// shows more than a log entry does; but one first recorded before a raise
// from sealed stays sealed as before, under the epoch of the entry that
// first recorded it and the pad setting before the raise, and a branch of
// the raised namespace serves it as the raised namespace does (Addendum E
// Levels, preraise.go).

// GrantDoc is the answer of GET /ns/{ns}/grants/{gid}.
type GrantDoc struct {
	ID   string         `json:"id"`
	Root map[string]any `json:"root"`
	// Stored is the authority SignedBlock in base64url without padding.
	Stored string `json:"stored"`
	// Public: the namespace uses the public cache classes.
	Public bool `json:"-"`
	// Private: an end-to-end namespace's grant, served with
	// Cache-Control private (§C.3.1, §9).
	Private bool `json:"-"`
	// JWE: in a sealed namespace, the sealed answer to serve instead
	// (application/jose).
	JWE string `json:"-"`
}

// Grant serves a grant recorded in ns (§C.3.1).
func (e *Engine) Grant(ctx context.Context, ns, gid string, cred Credentials) (*GrantDoc, error) {
	var out *GrantDoc
	var job *sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.nsReader(n, cred); err != nil {
			return err
		}
		public := t.cachePublic(n)
		if n.purged {
			return t.purgedRead(n)
		}
		id, perr := ids.Parse(gid)
		if perr != nil || !t.recordsGrant(n, id) {
			return nfNS(public)
		}
		g, ok := t.storedGrant(id)
		if !ok {
			return nfNS(public)
		}
		out = &GrantDoc{ID: id.String(), Root: g.Blocks[0].Raw, Stored: base64.RawURLEncoding.EncodeToString(g.Stored()), Public: public}
		switch t.nsLevel(n) {
		case levelSealed:
			nsRowID = n.id
			job = t.grantJob(n, id, func() []byte {
				return jsonv.Canonical(map[string]any{"id": out.ID, "root": out.Root, "stored": out.Stored})
			})
		case levelE2E:
			// Private and no-store for shared caches in either form
			// (§C.3.1, §9). One first recorded before a raise from sealed
			// stays sealed, as the namespace that recorded it serves it
			// (Addendum E Levels, preRaiseGrant).
			out.Private = true
			if m, raise, seq := t.preRaiseGrant(n, id); m != nil {
				nsRowID = m.id
				job = t.preRaiseGrantJob(m, raise, id, seq, func() []byte {
					return jsonv.Canonical(map[string]any{"id": out.ID, "root": out.Root, "stored": out.Stored})
				})
			}
		}
		return nil
	})
	if err == nil && job != nil {
		if err = e.finishSeal(ctx, nsRowID, []*sealJob{job}); err == nil {
			out.JWE = job.jwe
		}
	}
	return out, err
}

// grantSealKey is the sealed table's key of grant id's sealed answer in
// the shape of v0.73, stored as one string (§C.3.1). The key the id alone
// names holds an answer sealed before, with stored an array, which is no
// longer served.
func grantSealKey(id ids.ID) string { return id.String() + "/v0.73" }

// grantJob prepares the sealing of grant id as n serves it (§E.2.2).
func (t *tx) grantJob(n *nsRow, id ids.ID, plain func() []byte) *sealJob {
	j := &sealJob{kind: sealGrant, key: grantSealKey(id)}
	if t.stored(n, j) {
		return j
	}
	e := t.config(n.configSeq).Epoch
	var seq int64
	if err := t.QueryRow(`SELECT seq FROM ns_log WHERE grant_id = ? AND ns = ? ORDER BY seq LIMIT 1`, id[:], n.id).Scan(&seq); err == nil {
		e = t.entryEpoch(n, seq)
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.epochKey(n.id, e), seal.GrantPL(n.name, id.String()), plain()
	j.pad = t.config(n.configSeq).Pad
	return j
}

// preRaiseGrantJob is grantJob for grant id, first recorded by m's entry
// seq before m's raise from sealed: sealed under that entry's epoch, as
// at E2, padded as m padded before the raise (Addendum E Levels).
func (t *tx) preRaiseGrantJob(m *nsRow, raise *e2eRaise, id ids.ID, seq int64, plain func() []byte) *sealJob {
	j := &sealJob{kind: sealGrant, key: grantSealKey(id)}
	if t.stored(m, j) {
		return j
	}
	e := t.preRaiseEntryEpoch(m, raise, seq)
	j.kid, j.k, j.pl, j.plain = seal.Kid(m.name, e), t.epochKey(m.id, e), seal.GrantPL(m.name, id.String()), plain()
	j.pad = raise.pad
	return j
}

// recordsGrant reports whether an entry of n, or of its local bases up to
// their at (recursively), records grant id.
func (t *tx) recordsGrant(n *nsRow, id ids.ID) bool {
	var bound sql.NullInt64 // the namespace's own entries: all of them
	for cur := n; cur != nil && !cur.isShadow(); {
		var found bool
		var err error
		if bound.Valid {
			err = t.QueryRow(`SELECT EXISTS (SELECT 1 FROM ns_log WHERE grant_id = ? AND ns = ? AND seq <= ?)`, id[:], cur.id, bound.Int64).Scan(&found)
		} else {
			err = t.QueryRow(`SELECT EXISTS (SELECT 1 FROM ns_log WHERE grant_id = ? AND ns = ?)`, id[:], cur.id).Scan(&found)
		}
		t.must(err)
		if found {
			return true
		}
		if !cur.base.Valid {
			return false
		}
		bound = cur.baseAt
		cur = t.nsByID(cur.base.Int64)
	}
	return false
}

// storedGrant reads and parses the stored form of grant id, decrypting it
// if it is stored encrypted at rest (§E.1).
func (t *tx) storedGrant(id ids.ID) (*grant.Grant, bool) {
	var blocks []byte
	err := t.QueryRow(`SELECT blocks FROM grants WHERE id = ?`, id[:]).Scan(&blocks)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	t.must(err)
	if isSealed(string(blocks)) {
		plain, err := openRow(t.dek(grantsDEK, false), grantAAD(id[:]), blocks)
		if err != nil {
			panic(encUnavailable(fmt.Sprintf("the stored grant %s does not decrypt: %v", id, err)))
		}
		blocks = plain
	}
	g, err := grant.ParseStored(blocks)
	if err != nil || len(g.Blocks) == 0 || g.ID() != id {
		return nil, false
	}
	return g, true
}
