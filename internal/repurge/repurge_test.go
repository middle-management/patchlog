package repurge_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/repurge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rec struct {
	mu     sync.Mutex
	purges [][]string
}

func (r *rec) PurgeTags(tags []string) {
	r.mu.Lock()
	r.purges = append(r.purges, tags)
	r.mu.Unlock()
}

func (r *rec) take() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.purges
	r.purges = nil
	return out
}

// countLock counts how often it is taken.
type countLock struct {
	sync.Mutex
	n int
}

func (l *countLock) Lock() { l.Mutex.Lock(); l.n++ }

func open(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(path, "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newQueue(t *testing.T, db *sql.DB, p repurge.Purger, opt repurge.Options) *repurge.Queue {
	t.Helper()
	opt.Logf = t.Logf
	if err := repurge.Init(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	q := repurge.New(db, p, opt)
	t.Cleanup(q.Close)
	return q
}

// add queues tags in a transaction of their own, committed or not.
func add(t *testing.T, db *sql.DB, q *repurge.Queue, commit bool, tags ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := q.Add(ctx, tx, tags); err != nil {
		t.Fatal(err)
	}
	if commit {
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func queued(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM cdn_repurge`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func tagsQueued(t *testing.T, q *repurge.Queue) [][]string {
	t.Helper()
	out, err := q.Queued(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func send(t *testing.T, q *repurge.Queue) int {
	t.Helper()
	n, err := q.Send(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A purge queued with its commit is sent once due, and its row deleted;
// one whose transaction rolls back is never queued, and no purge (no tags)
// queues nothing. The deletes take Lock.
func TestSendDue(t *testing.T) {
	t.Parallel()
	db := open(t, filepath.Join(t.TempDir(), "s.db"))
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	r := &rec{}
	lk := &countLock{}
	q := newQueue(t, db, r, repurge.Options{Delay: time.Minute, Interval: -1, Now: c.Now, Lock: lk})
	add(t, db, q, true, "r:matches/final", "idx:matches:counts")
	add(t, db, q, false, "r:matches/rolled-back")
	add(t, db, q, true)
	if got := tagsQueued(t, q); !reflect.DeepEqual(got, [][]string{{"r:matches/final", "idx:matches:counts"}}) {
		t.Fatalf("queued %v", got)
	}
	c.Advance(time.Minute - time.Millisecond)
	if n := send(t, q); n != 0 || len(r.take()) != 0 {
		t.Fatalf("sent %d before it was due", n)
	}
	c.Advance(time.Millisecond)
	if n := send(t, q); n != 1 {
		t.Fatalf("sent %d, want 1", n)
	}
	if got := r.take(); !reflect.DeepEqual(got, [][]string{{"r:matches/final", "idx:matches:counts"}}) {
		t.Errorf("sent %v", got)
	}
	if n := queued(t, db); n != 0 {
		t.Errorf("%d left queued", n)
	}
	if lk.n != 1 {
		t.Errorf("the lock was taken %d times, want 1", lk.n)
	}
	if n := send(t, q); n != 0 || len(r.take()) != 0 {
		t.Errorf("sent %d again", n)
	}
}

// A negative Delay disables the second purge: nothing is queued.
func TestDisabled(t *testing.T) {
	t.Parallel()
	db := open(t, filepath.Join(t.TempDir(), "s.db"))
	q := newQueue(t, db, &rec{}, repurge.Options{Delay: -1})
	add(t, db, q, true, "ns:matches")
	if n := queued(t, db); n != 0 {
		t.Errorf("%d queued", n)
	}
}

// Rows beyond one read are all sent; an unreadable one is deleted unsent.
func TestSendMany(t *testing.T) {
	t.Parallel()
	db := open(t, filepath.Join(t.TempDir(), "s.db"))
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	r := &rec{}
	q := newQueue(t, db, r, repurge.Options{Delay: time.Second, Interval: -1, Now: c.Now})
	for i := range 250 {
		add(t, db, q, true, fmt.Sprintf("r:matches/m%03d", i))
	}
	if _, err := db.Exec(`INSERT INTO cdn_repurge (tags, due) VALUES ('not json', 0)`); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Second)
	if n := send(t, q); n != 250 {
		t.Fatalf("sent %d, want 250", n)
	}
	got := r.take()
	if len(got) != 250 || got[0][0] != "r:matches/m000" || got[249][0] != "r:matches/m249" {
		t.Errorf("sent %d: %v … %v", len(got), got[0], got[len(got)-1])
	}
	if n := queued(t, db); n != 0 {
		t.Errorf("%d left queued", n)
	}
}

// The loop sends due rows every Interval, and stops at Close: rows queued
// before a stop are sent by the next start, from the database.
func TestLoopAndRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "s.db")
	db := open(t, path)
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	r := &rec{}
	opt := repurge.Options{Delay: time.Minute, Interval: time.Millisecond, Now: c.Now}
	q := newQueue(t, db, r, opt)
	q.Start()
	add(t, db, q, true, "ns:a")
	c.Advance(time.Minute)
	waitFor(t, "the second purge of ns:a", func() bool { return queued(t, db) == 0 })
	if got := r.take(); !reflect.DeepEqual(got, [][]string{{"ns:a"}}) {
		t.Errorf("sent %v", got)
	}

	// Queued, then stopped before it is due.
	add(t, db, q, true, "ns:b")
	q.Close()
	q.Close() // idempotent
	c.Advance(time.Minute)
	if got := r.take(); len(got) != 0 {
		t.Errorf("sent %v", got)
	}
	db.Close()

	db2 := open(t, path)
	r2 := &rec{}
	q2 := newQueue(t, db2, r2, opt)
	q2.Start()
	waitFor(t, "the second purge of ns:b after the restart", func() bool { return queued(t, db2) == 0 })
	if got := r2.take(); !reflect.DeepEqual(got, [][]string{{"ns:b"}}) {
		t.Errorf("sent after the restart %v", got)
	}
}

// Close without Start returns; a negative Interval runs no loop.
func TestNoLoop(t *testing.T) {
	t.Parallel()
	db := open(t, filepath.Join(t.TempDir(), "s.db"))
	repurge.New(db, &rec{}, repurge.Options{}).Close()
	q := newQueue(t, db, &rec{}, repurge.Options{Interval: -1})
	q.Start()
	q.Close()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
