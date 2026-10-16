package tree

import "context"

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

// Repurge sends the second purges that are due (tests).
func (s *Service) Repurge(ctx context.Context) (int, error) { return s.repurge.Send(ctx) }

// QueuedRepurges returns the tags of the queued second purges, the oldest
// first (tests).
func (s *Service) QueuedRepurges() [][]string {
	out, err := s.repurge.Queued(context.Background())
	if err != nil {
		panic(err)
	}
	return out
}
