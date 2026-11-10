package tree

import (
	"context"
	"strings"
)

// SealedViews returns the stored sealed listings, URL → Cache-Tag, the
// tags of every reader shape stored at it (tests).
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
		v, _, _ = strings.Cut(v, "\n")
		if out[v] != "" {
			t = out[v] + "," + t
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

// EpochsPending reports whether the epochs backfill (meta "epochs") is
// still to run (tests).
func (s *Service) EpochsPending() bool {
	var v string
	return s.db.QueryRow(`SELECT v FROM meta WHERE k = 'epochs'`).Scan(&v) == nil
}

// BeforeListing sets f to run as each listing starts, outside the graph's
// lock (tests: a checkpoint that moves meanwhile); nil unsets it.
func (s *Service) BeforeListing(f func()) {
	if f == nil {
		s.beforeListing.Store(nil)
		return
	}
	s.beforeListing.Store(&f)
}

// FailVerify sets f to fail the verification of a grant in each
// namespace it returns an error for (tests); nil unsets it.
func (s *Service) FailVerify(f func(ns string) error) {
	if f == nil {
		s.verifyHook.Store(nil)
		return
	}
	s.verifyHook.Store(&f)
}

// BeforeJudge sets f to run as a listing records the epochs it judged,
// outside the graph's lock (tests: a head applied meanwhile); nil unsets
// it.
func (s *Service) BeforeJudge(f func()) {
	if f == nil {
		s.beforeJudge.Store(nil)
		return
	}
	s.beforeJudge.Store(&f)
}

// AfterGeneration sets f to run as each listing has taken its kept
// generation, before it reads the graph (tests: a purge applied
// meanwhile); nil unsets it.
func (s *Service) AfterGeneration(f func()) {
	if f == nil {
		s.afterGeneration.Store(nil)
		return
	}
	s.afterGeneration.Store(&f)
}

// AfterFileSealing sets f to run as each listing has read its file
// metadata's sealing, before it reads the graph (tests: a config change
// applied meanwhile); nil unsets it.
func (s *Service) AfterFileSealing(f func()) {
	if f == nil {
		s.afterFileSealing.Store(nil)
		return
	}
	s.afterFileSealing.Store(&f)
}

// PurgeKept purges the catalog's kept listings that carry any of tags, as
// an apply that purges them does (tests).
func (s *Service) PurgeKept(tags ...string) { s.kept.Purge(s.opt.Catalog, tags) }
