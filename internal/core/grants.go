package core

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
)

// Reading stored grants (§C.3.1): GET /ns/{ns}/grants/{gid} answers
// { id, root, stored } for a grant recorded by an entry of the namespace
// or, in a local branch, of its bases up to their at, recursively. stored
// is the non-bearer form (§C.8) as the token's protobuf SignedBlocks in
// order, authority first, each in base64url without padding.
//
// "Recorded by an entry" is read from the namespace log: every entry
// written on a request stores its grant's id (ns_log.grant_id, grantref.go),
// and the revisions and tombstones of a write record the same grant as its
// entry. A remote branch's base is followed no further than the branch
// itself: what it reads through is verified at its base (§G.3).
//
// It needs unrestricted read on the namespace, as gestures do, and isn't
// offered in sealed or e2e namespaces (404 not_offered after the read
// check). A grant id names its root block, and the stored form doesn't
// change once recorded, so the answer is immutable.

// GrantDoc is the answer of GET /ns/{ns}/grants/{gid}.
type GrantDoc struct {
	ID     string         `json:"id"`
	Root   map[string]any `json:"root"`
	Stored []string       `json:"stored"`
	// Public: the namespace uses the public cache classes.
	Public bool `json:"-"`
}

// Grant serves a grant recorded in ns (§C.3.1).
func (e *Engine) Grant(ctx context.Context, ns, gid string, cred Credentials) (*GrantDoc, error) {
	var out *GrantDoc
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		a, err := t.reader(n, cred, "")
		if err != nil {
			return err
		}
		// An anonymous reader of a public namespace reads all of it.
		if a != nil && !a.unrestrictedRead() {
			return forbidden("reading a grant needs unrestricted read on the namespace")
		}
		if t.nsLevel(n) >= levelSealed {
			return apiErr(404, "not_offered", "message", "grants aren't served in sealed or end-to-end namespaces: their bundles carry them (§C.3.1)")
		}
		if n.purged {
			return gone()
		}
		public := t.cachePublic(n)
		id, perr := ids.Parse(gid)
		if perr != nil || !t.recordsGrant(n, id) {
			return nfNS(public)
		}
		g, ok := t.storedGrant(id)
		if !ok {
			return nfNS(public)
		}
		out = &GrantDoc{ID: id.String(), Root: g.Blocks[0].Raw, Public: public}
		for _, b := range g.SignedBlocks() {
			out.Stored = append(out.Stored, base64.RawURLEncoding.EncodeToString(b))
		}
		return nil
	})
	return out, err
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
