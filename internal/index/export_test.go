package index

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

// CountRows counts every row the index holds for ns (tests).
func (ix *Index) CountRows(ns string) int {
	total := 0
	for _, tbl := range []string{"docs", `"text"`, "facet", `"sort"`} {
		var n int
		if err := ix.db.QueryRow(`SELECT count(*) FROM `+tbl+` WHERE ns = ?`, ns).Scan(&n); err != nil {
			panic(err)
		}
		total += n
	}
	return total
}
