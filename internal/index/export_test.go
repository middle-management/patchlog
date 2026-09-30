package index

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
