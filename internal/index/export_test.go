package index

import "context"

// SealedViews returns the stored sealed results, view → Cache-Tag (tests).
func (ix *Index) SealedViews() map[string]string {
	rows, err := ix.db.Query(`SELECT view, tags FROM sealed_views`)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var v, t string
		if err := rows.Scan(&v, &t); err != nil {
			panic(err)
		}
		out[v] = t
	}
	return out
}

// ExpireGrantChecks drops the namespace documents the grant checker has
// cached (tests): the next check reads them from the core again, as one
// after CheckerTTL would.
func (ix *Index) ExpireGrantChecks() { ix.checker.Invalidate() }

// CountRows counts every row the index holds for ns (tests).
func (ix *Index) CountRows(ns string) int {
	total := 0
	for _, tbl := range []string{"docs", `"text"`, "facet", `"sort"`, "refs"} {
		var n int
		if err := ix.db.QueryRow(`SELECT count(*) FROM `+tbl+` WHERE ns = ?`, ns).Scan(&n); err != nil {
			panic(err)
		}
		total += n
	}
	return total
}

// Pragma returns the value of PRAGMA name on a connection of the index's
// database (tests).
func (ix *Index) Pragma(name string) string {
	var v string
	if err := ix.db.QueryRow(`PRAGMA ` + name).Scan(&v); err != nil {
		panic(err)
	}
	return v
}

// Committed returns the checkpoint of ns the database holds ("" if none),
// which redirects go by (tests). Checkpoint, the one in memory, follows
// it just after each commit (Index.Apply), so a ?min= wait, which ends
// once min is in the seen rows committed with it, can end before
// Checkpoint has moved.
func (ix *Index) Committed(ns string) string {
	id, _, err := ix.committed(context.Background(), ns)
	if err != nil {
		panic(err)
	}
	return id
}

// Repurge sends the second purges that are due (tests).
func (ix *Index) Repurge(ctx context.Context) (int, error) { return ix.repurge.Send(ctx) }

// QueuedRepurges returns the tags of the queued second purges, the oldest
// first (tests).
func (ix *Index) QueuedRepurges() [][]string {
	out, err := ix.repurge.Queued(context.Background())
	if err != nil {
		panic(err)
	}
	return out
}
