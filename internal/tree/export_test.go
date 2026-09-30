package tree

// SealedViews returns the stored sealed listings, view → Cache-Tag (tests).
func (s *Service) SealedViews() map[string]string {
	rows, err := s.db.Query(`SELECT view, tags FROM sealed_views`)
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
