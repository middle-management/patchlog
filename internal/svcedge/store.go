package svcedge

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/dbmigrate"
)

// Rate is a token bucket (§6.6): Rate refills it per second, up to Burst.
type Rate struct{ Rate, Burst float64 }

// DefaultExchangeRate is exchangeRate's default (§6.6): 10/s, burst 100.
var DefaultExchangeRate = Rate{Rate: 10, Burst: 100}

// Store is the state a service keeps for its edge grants in its own
// SQLite database (§B.11.5), shared by every instance of the service that
// opens that database, and kept across restarts and rebuilds:
//
//	edge_subjects(gs, subjects, exp)  the subjects behind each subject set
//	                                  the service minted an edge grant for,
//	                                  until the last of them expires
//	edge_buckets(k, tokens, last)     the exchangeRate buckets of its
//	                                  exchange, one per principal (Draw)
//
// A gs is the digest of its subjects, so what Subjects answers for one
// never changes, and the store keeps the answers it read in memory too.
type Store struct {
	db *sql.DB

	mu   sync.Mutex
	subs map[string]subjectSet
}

// subjectSet is the subjects behind a gs, and the expiry of the last edge
// grant minted for it that the store knows of (Unix seconds).
type subjectSet struct {
	subjects []string
	exp      int64
}

// migrations holds the store's tables, applied under the namespace
// "svcedge" (package dbmigrate) in the database of each service that keeps
// one.
//
//go:embed migrations
var migrations embed.FS

// NewStore opens the store in db, a service's SQLite database, creating
// or migrating its tables.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	if err := dbmigrate.Migrate(ctx, db, migrations, "svcedge"); err != nil {
		return nil, fmt.Errorf("svcedge: schema: %w", err)
	}
	return &Store{db: db, subs: map[string]subjectSet{}}, nil
}

// Record records the subjects behind gs, for an edge grant minted at now
// that expires at exp, and drops the records whose last edge grant has
// expired.
func (s *Store) Record(ctx context.Context, gs string, subjects []string, exp, now time.Time) error {
	b, err := json.Marshal(subjects)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM edge_subjects WHERE exp <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO edge_subjects (gs, subjects, exp) VALUES (?, ?, ?)
		ON CONFLICT (gs) DO UPDATE SET subjects = excluded.subjects, exp = max(exp, excluded.exp)`, gs, string(b), exp.Unix()); err != nil {
		return err
	}
	for k, e := range s.subs {
		if e.exp <= now.Unix() {
			delete(s.subs, k)
		}
	}
	e := s.subs[gs]
	s.subs[gs] = subjectSet{subjects: subjects, exp: max(e.exp, exp.Unix())}
	return nil
}

// Subjects is the subjects behind gs, recorded when an edge grant for it
// was minted, by this instance or another on the same database.
func (s *Store) Subjects(ctx context.Context, gs string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.subs[gs]; ok {
		return e.subjects, true
	}
	var text string
	var exp int64
	if err := s.db.QueryRowContext(ctx, `SELECT subjects, exp FROM edge_subjects WHERE gs = ?`, gs).Scan(&text, &exp); err != nil {
		return nil, false
	}
	var subs []string
	if json.Unmarshal([]byte(text), &subs) != nil {
		return nil, false
	}
	s.subs[gs] = subjectSet{subjects: subs, exp: exp}
	return subs, true
}

// Draw draws one token from the exchangeRate bucket (§6.6) of each of
// keys at rate r, if each holds one, and otherwise draws none and returns
// how long until the emptiest refills one (§C.5.2). A bucket starts full,
// and one idle long enough to have refilled is dropped, being the same as
// none. The check and the draw are one transaction whose first statement
// writes, so it holds the database's write lock from its start (SQLite
// admits one writer): every instance of the service on the database draws
// from the same buckets, and no two draw between one's check and its draw
// (§B.11.5: the buckets are shared across its instances as the origin's
// are).
func (s *Store) Draw(ctx context.Context, now time.Time, r Rate, keys []string) (time.Duration, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	full := time.Duration(r.Burst / r.Rate * float64(time.Second))
	if _, err := tx.ExecContext(ctx, `DELETE FROM edge_buckets WHERE last <= ?`, now.Add(-full).UnixNano()); err != nil {
		return 0, err
	}
	var wait time.Duration
	tokens, lasts := make([]float64, len(keys)), make([]int64, len(keys))
	for i, k := range keys {
		var t float64
		var last int64
		switch err := tx.QueryRowContext(ctx, `SELECT tokens, last FROM edge_buckets WHERE k = ?`, k).Scan(&t, &last); {
		case errors.Is(err, sql.ErrNoRows):
			t, last = r.Burst, now.UnixNano()
		case err != nil:
			return 0, err
		case now.UnixNano() > last:
			// Refilled since, up to Burst; a last ahead of this instance's
			// clock refills nothing until it passes.
			t = min(r.Burst, t+now.Sub(time.Unix(0, last)).Seconds()*r.Rate)
			last = now.UnixNano()
		}
		tokens[i], lasts[i] = t, last
		if t < 1 {
			wait = max(wait, time.Duration((1-t)/r.Rate*float64(time.Second)))
		}
	}
	if wait > 0 {
		return wait, nil
	}
	for i, k := range keys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO edge_buckets (k, tokens, last) VALUES (?, ?, ?)
			ON CONFLICT (k) DO UPDATE SET tokens = excluded.tokens, last = excluded.last`, k, tokens[i]-1, lasts[i]); err != nil {
			return 0, err
		}
	}
	return 0, tx.Commit()
}
