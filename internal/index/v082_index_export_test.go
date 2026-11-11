package index

import "context"

// ExecForTest runs q on the index's database and returns the rows it
// changed: tests plant what an earlier release stored (edge_gs_keys rows
// without an entry, or none).
func (ix *Index) ExecForTest(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := ix.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// EntryDigestForTest is entryDigest.
func EntryDigestForTest(key, roles map[string]any) string { return entryDigest(key, roles) }
