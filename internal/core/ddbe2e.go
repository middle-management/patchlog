package core

// End-to-end namespaces on DynamoDB (§E.3; e2e.go). The gate's checks
// and the keys relay are the SQL path's; the table keeps each epoch's
// start as a keyless EPOCHKEY item (beginsEpoch), each e2e revision's
// declared blobs on its REV item (declared, standing in for blob_refs),
// no head documents, and a prune's client-sealed snapshot as an E2ESNAP
// item.

import (
	"bytes"
	"slices"

	"github.com/middle-management/patchlog/internal/ids"
)

// e2eEpochOK: as SQL's, the namespace's first epoch from its items.
func (r *ddbReads) e2eEpochOK(n *nsRow, cfg *Config, e int) bool {
	ks, err := r.s.EpochKeys(r.ctx, r.nsName(n.id))
	r.must(err)
	lo := cfg.Epoch
	if len(ks) > 0 && ks[0].Epoch < lo {
		lo = ks[0].Epoch
	}
	return e >= lo && e <= cfg.Epoch
}

// declaredAt: the declared list of row, or for a tombstone that of the
// last live revision before it (§E.3.1).
func (r *ddbReads) declaredAt(row *revRow) []ids.ID {
	for row.kind == kindTombstone && row.parentSeq.Valid {
		row = r.rev(row.parentSeq.Int64)
	}
	if row.kind == kindTombstone {
		return nil
	}
	k := r.revs[row.seq].key
	ri, err := r.s.RevAt(r.ctx, k.ns, k.name, k.pos)
	r.must(err)
	if ri == nil {
		return nil
	}
	var out []ids.ID
	for _, s := range ri.Declared {
		if id, err := ids.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b ids.ID) int { return bytes.Compare(a[:], b[:]) })
	return out
}

func (r *ddbReads) e2eSnapshot(row *revRow) string {
	k := r.revs[row.seq].key
	jwe, err := r.s.E2ESnapshot(r.ctx, k.ns, k.name, k.pos)
	r.must(err)
	return jwe
}

// e2eFoldSince: the latest snapshot at or before row, across its
// ancestry.
func (r *ddbReads) e2eFoldSince(row *revRow) string {
	for _, sg := range r.ancestry(row) {
		k := r.res[sg.res]
		pos, err := r.s.LatestE2ESnapshot(r.ctx, k.ns, k.name, r.revs[sg.max].key.pos)
		r.must(err)
		if pos > 0 {
			return r.rev(r.revHandle(k.ns, k.name, pos)).id.String()
		}
	}
	return ""
}
