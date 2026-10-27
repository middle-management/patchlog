// Package repurge is the second CDN purge of a derived service (D.8), as
// the core's (internal/core/repurge.go).
//
// A service sends its cache-tag purges (§A.1, §B.5) right after the
// transaction that needs them commits. But a request that read before the
// commit and answers after the purge went out hands the CDN what the purge
// removed, as immutable, which would keep it at the edge for a year. So
// every purge is sent again once no such response can still be under way:
// the transaction that commits it also queues it (Queue.Add), due Delay
// later, and a loop sends the due ones every Interval (Queue.Send) and
// deletes their rows. The queue commits with the purge, so a crash loses no
// second purge; one sent but not yet deleted when the service stops is sent
// once more, which is harmless.
//
// Storage, in the service's own SQLite database:
//
//	cdn_repurge(id, tags, due)   tags a JSON array, due Unix ms
//
// A service's rebuild keeps the table: what it holds was purged at the
// CDN, which a replay doesn't undo.
package repurge

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/dbmigrate"
)

// DefaultDelay is how long after a purge it is sent again unless set:
// longer than a response under way when the purge's transaction commits
// can still take to reach the CDN, which takes it only within its
// first-byte timeout (75 s in deploy/varnish). A derived service sets no
// response deadline of its own, so a CDN that waits longer needs a longer
// delay. It reads one database of its own, so there is no cache staleness
// or replica lag to add, as the core's RepurgeDelay does.
const DefaultDelay = 2 * time.Minute

// DefaultInterval is how often due second purges are looked for unless set.
const DefaultInterval = 10 * time.Second

// batch bounds the rows Send reads at a time.
const batch = 100

// Purger purges CDN cache tags.
type Purger interface{ PurgeTags(tags []string) }

// Execer runs statements (the purge's *sql.Tx, or a *sql.DB).
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Options configure a Queue.
type Options struct {
	// Delay is how long after a purge it is sent again. Zero means
	// DefaultDelay; negative disables the second purge.
	Delay time.Duration
	// Interval is how often the loop sends the due ones. Zero means
	// DefaultInterval; negative disables the loop: Add still queues, and
	// only a call of Send sends them.
	Interval time.Duration
	// Now is the clock of due times (default time.Now).
	Now func() time.Time
	// Lock, if set, is held around Send's deletes: the service's write
	// lock, so they never commit between the first read and first write of
	// one of its deferred transactions, which SQLite would then fail.
	Lock sync.Locker
	// Name prefixes log lines ("index", "tree").
	Name string
	// Logf logs (default log.Printf).
	Logf func(format string, args ...any)
}

// Queue is a service's queue of second purges.
type Queue struct {
	db  *sql.DB
	p   Purger
	opt Options

	mu   sync.Mutex         // guards stop and done
	stop context.CancelFunc // ends the running loop; nil when none runs
	done chan struct{}      // closed when that loop has returned
}

// New returns the queue of second purges kept in db (its table made by
// Init) and sent to p. Call Stop when done.
func New(db *sql.DB, p Purger, opt Options) *Queue {
	if opt.Delay == 0 {
		opt.Delay = DefaultDelay
	}
	if opt.Interval == 0 {
		opt.Interval = DefaultInterval
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	return &Queue{db: db, p: p, opt: opt}
}

// migrations holds the table, applied under the namespace "repurge"
// (package dbmigrate).
//
//go:embed migrations
var migrations embed.FS

// Init creates or migrates the table in a service's database.
func Init(ctx context.Context, db *sql.DB) error {
	return dbmigrate.Migrate(ctx, db, migrations, "repurge")
}

// Add queues the second purge of tags through ex, the transaction that
// commits the change the first one is sent for.
func (q *Queue) Add(ctx context.Context, ex Execer, tags []string) error {
	if q.opt.Delay < 0 || len(tags) == 0 {
		return nil
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	_, err = ex.ExecContext(ctx, `INSERT INTO cdn_repurge (tags, due) VALUES (?, ?)`, string(raw), q.opt.Now().Add(q.opt.Delay).UnixMilli())
	return err
}

// Send sends the second purges that are due, then deletes their rows, and
// returns how many it sent. It stops at the end of ctx; what it sent and
// didn't delete is sent again.
func (q *Queue) Send(ctx context.Context) (int, error) {
	n := 0
	for {
		type due struct {
			id   int64
			tags []string
		}
		rows, err := q.db.QueryContext(ctx, `SELECT id, tags FROM cdn_repurge WHERE due <= ? ORDER BY id LIMIT ?`, q.opt.Now().UnixMilli(), batch)
		if err != nil {
			return n, err
		}
		var ds []due
		for rows.Next() {
			var d due
			var raw string
			if err := rows.Scan(&d.id, &raw); err != nil {
				rows.Close()
				return n, err
			}
			if json.Unmarshal([]byte(raw), &d.tags) != nil {
				d.tags = nil // unreadable: deleted below
			}
			ds = append(ds, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return n, err
		}
		if len(ds) == 0 {
			return n, nil
		}
		ids := make([]any, len(ds))
		for i, d := range ds {
			if err := ctx.Err(); err != nil {
				return n, err
			}
			if len(d.tags) > 0 {
				q.p.PurgeTags(d.tags)
				n++
			}
			ids[i] = d.id
		}
		if err := q.delete(ctx, ids); err != nil {
			return n, err
		}
		if len(ds) < batch {
			return n, nil
		}
	}
}

// Queued returns the tags of the queued second purges, the oldest first.
func (q *Queue) Queued(ctx context.Context) ([][]string, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT tags FROM cdn_repurge ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var tags []string
		json.Unmarshal([]byte(raw), &tags) // unreadable: nil, as Send drops it
		out = append(out, tags)
	}
	return out, rows.Err()
}

func (q *Queue) delete(ctx context.Context, ids []any) error {
	if q.opt.Lock != nil {
		q.opt.Lock.Lock()
		defer q.opt.Lock.Unlock()
	}
	_, err := q.db.ExecContext(ctx, `DELETE FROM cdn_repurge WHERE id IN (?`+strings.Repeat(`, ?`, len(ids)-1)+`)`, ids...)
	return err
}

// Start runs Send every Interval until Stop, unless the second purge or
// the loop is disabled, or it runs already. A stopped loop starts again.
func (q *Queue) Start() {
	if q.opt.Delay < 0 || q.opt.Interval < 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stop != nil {
		return
	}
	ctx, stop := context.WithCancel(context.Background())
	q.stop, q.done = stop, make(chan struct{})
	go q.loop(ctx, q.done)
}

func (q *Queue) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	tk := time.NewTicker(q.opt.Interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if _, err := q.Send(ctx); err != nil && ctx.Err() == nil {
				q.opt.Logf("%s: cdn repurge: %v", q.opt.Name, err)
			}
		}
	}
}

// Stop stops the loop and waits for it, before the service closes its
// database or another opens it (a release preview's switch). Rows not yet
// due stay queued for the next start.
func (q *Queue) Stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stop == nil {
		return
	}
	q.stop()
	<-q.done
	q.stop, q.done = nil, nil
}
