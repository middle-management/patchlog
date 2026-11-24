package core

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// WAL checkpoints of a SQLite file, off the writer's path (D.3).
//
// SQLite's default runs a PASSIVE checkpoint inside the COMMIT that takes
// the WAL past 1,000 frames: in the write transaction, so under Engine.mu,
// where it was about half of the commit (measured on 4 vCPUs: 239 µs with
// it and 132 without for one small write, 1,443 and 481 µs for 16 in one
// transaction; on EC2's gp3 a goroutine dump found the holder of Engine.mu
// in its fsync). Every connection instead sets wal_autocheckpoint(0)
// (openSQLite), and checkpointLoop runs them alongside the writer:
//
//   - Every CheckpointInterval, a PASSIVE checkpoint. It takes no lock a
//     writer or reader waits for: it copies the frames no reader still
//     needs into the database file and syncs it, and a writer that later
//     finds every frame copied, with no reader in the WAL, starts it over.
//     It does no I/O when there is nothing new.
//   - Readers that always overlap can keep the WAL from starting over (a
//     reader whose snapshot needs frames pins them, and PASSIVE never
//     waits), and under steady writes a writer never finds every frame
//     copied (frames are added while PASSIVE copies), so the WAL would
//     grow for good. Once it holds walLimitFrames, a RESTART checkpoint
//     runs under Engine.mu, so this process's writers queue on the mutex
//     rather than in SQLite's busy handler. It waits for the readers in
//     the WAL to finish (they are short; new ones read the copied database
//     file and don't hold it up), copies the frames the PASSIVE one left
//     and syncs, and the next writer starts the WAL over, in the same
//     file. (TRUNCATE took twice as long, 40 against 17 ms on this host's
//     disk, and the writer then grew the file again.) It waits at most
//     walCheckpointBusy, then gives up: a reader that stays (a long export,
//     a backup) would otherwise stall the writer that long every interval,
//     so after each such failure the next try waits twice as long as the
//     one before, from a second up to walBackoffMax.
//   - Once a PASSIVE checkpoint finds no new frame since the previous one
//     (no write in an interval) and the WAL not empty, a TRUNCATE one, which
//     also empties the file, runs the same way if Engine.mu is free (TryLock: a writer that holds it isn't
//     idle), so a quiet database keeps no WAL.
//
// Durability is as before: synchronous(NORMAL) in WAL mode syncs the WAL
// only at checkpoints, which now come at least every interval while
// anything is written rather than every 1,000 frames, so a power loss
// loses at most what an interval wrote and the OS hadn't yet flushed; a
// process crash loses nothing committed (the WAL is in the OS's cache), and
// the next open replays the WAL. Close stops the loop, then checkpoints
// with TRUNCATE before closing the database, as SQLite does itself when
// its last connection closes. Other processes on the file open it with
// this DSN too, or keep their own autocheckpoint, which is no worse.

// Checkpoint defaults (Options.CheckpointInterval).
const (
	defaultCheckpointInterval = 100 * time.Millisecond
	// walCheckpointBusy bounds how long a RESTART checkpoint waits for
	// readers (and other processes' writers), holding Engine.mu.
	walCheckpointBusy = 250 * time.Millisecond
	// walBackoffMax bounds the wait between RESTART checkpoints that
	// found a reader still in the WAL.
	walBackoffMax = 30 * time.Second
	// walIdleBusy is that bound for the TRUNCATE of an idle WAL, which a
	// write arriving meanwhile would wait for.
	walIdleBusy = 50 * time.Millisecond
	// walRetry is how often a RESTART or TRUNCATE checkpoint tries again
	// while readers are in the WAL.
	walRetry = 100 * time.Microsecond
)

// walLimitFrames is how many frames the WAL may hold before a RESTART
// checkpoint is forced: 64 MiB at the default 4 KiB pages
// (Options.walLimitFrames replaces it in tests).
const walLimitFrames = 16384

// walStats counts checkpoints (tests, benchmarks): PASSIVE ones, RESTART
// and TRUNCATE ones (truncated), and those that gave up on readers.
type walStats struct {
	passive, truncated, busy atomic.Int64
	// held is the time RESTART and TRUNCATE checkpoints took, in
	// nanoseconds: under Engine.mu (or at Close).
	held atomic.Int64
	// frames is the WAL's size in frames at the last checkpoint.
	frames atomic.Int64
}

// checkpointing reports whether this engine checkpoints its WAL itself.
func (e *Engine) checkpointing() bool {
	return !e.pg && e.opt.Path != ":memory:" && e.opt.CheckpointInterval > 0
}

// checkpointLoop runs the checkpoints of a SQLite file (above) until Close.
func (e *Engine) checkpointLoop(interval time.Duration) {
	defer e.bg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	var last int64 = -1 // frames at the last checkpoint, -1 unknown
	var notBefore time.Time
	backoff := time.Duration(0)
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
		}
		frames, done, err := e.checkpoint(context.Background(), "PASSIVE")
		if err != nil {
			log.Printf("WAL checkpoint: %v", err)
			continue
		}
		// Idle: no frame since the last interval, all copied. (A RESTART
		// leaves the WAL at its size until a writer starts it over.)
		idle := frames > 0 && frames == last && done == frames
		switch {
		case idle && e.mu.TryLock():
			frames, _, _, err = e.checkpointWait("TRUNCATE", walIdleBusy)
			e.mu.Unlock()
		case !idle && frames >= e.opt.walLimitFrames && !time.Now().Before(notBefore):
			var busy bool
			e.mu.Lock()
			frames, _, busy, err = e.checkpointWait("RESTART", walCheckpointBusy)
			e.mu.Unlock()
			if busy {
				backoff = min(max(2*backoff, time.Second), walBackoffMax)
				notBefore = time.Now().Add(backoff)
			} else {
				backoff = 0
			}
		}
		if err != nil {
			log.Printf("WAL checkpoint: %v", err)
			continue
		}
		last = frames
	}
}

// checkpoint runs a checkpoint of mode (PASSIVE, RESTART, TRUNCATE) and
// returns the frames in the WAL and those copied into the database: when
// it found the WAL truncated (TRUNCATE) or started over, both are 0.
func (e *Engine) checkpoint(ctx context.Context, mode string) (frames, done int64, err error) {
	var busy int
	if err := e.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(`+mode+`)`).Scan(&busy, &frames, &done); err != nil {
		return 0, 0, err
	}
	e.noteCheckpoint(mode, busy, frames)
	return frames, done, nil
}

func (e *Engine) noteCheckpoint(mode string, busy int, frames int64) {
	switch {
	case busy != 0:
		e.wal.busy.Add(1)
	case mode == "PASSIVE":
		e.wal.passive.Add(1)
	default:
		e.wal.truncated.Add(1)
	}
	e.wal.frames.Store(frames)
}

// checkpointWait runs a RESTART or TRUNCATE checkpoint, trying again for
// at most wait while readers are in the WAL, and reports whether it gave
// up (busy). Callers hold Engine.mu, or have no writer (Close), so no frame
// is added meanwhile and a try after the first only waits for readers.
//
// It tries every walRetry on a connection whose busy timeout is 0, rather
// than leave the wait to SQLite's busy handler, which sleeps 1, 2, 5, 10 ms
// and on between tries: the readers it waits for take well under a
// millisecond, but under steady reads one is nearly always in the WAL
// when it looks, and the writer waited out those sleeps under Engine.mu.
func (e *Engine) checkpointWait(mode string, wait time.Duration) (frames, done int64, busy bool, err error) {
	start := time.Now()
	defer func() { e.wal.held.Add(int64(time.Since(start))) }()
	ctx := context.Background()
	c, err := e.db.Conn(ctx)
	if err != nil {
		return 0, 0, false, err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, `PRAGMA busy_timeout = 0`); err != nil {
		return 0, 0, false, err
	}
	// Back to the DSN's (openSQLite) before the connection returns to the
	// pool.
	defer c.ExecContext(ctx, `PRAGMA busy_timeout = 10000`)
	for {
		var b int
		if err := c.QueryRowContext(ctx, `PRAGMA wal_checkpoint(`+mode+`)`).Scan(&b, &frames, &done); err != nil {
			return 0, 0, false, err
		}
		if b == 0 || time.Since(start) >= wait {
			e.noteCheckpoint(mode, b, frames)
			return frames, done, b != 0, nil
		}
		time.Sleep(walRetry)
	}
}

// closeWAL checkpoints the WAL into the database and truncates it, at
// Close, once no write runs. A reader still open (one not closed by its
// caller) leaves it as it is, for the next open to replay.
func (e *Engine) closeWAL() {
	if !e.checkpointing() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, _, _, err := e.checkpointWait("TRUNCATE", walCheckpointBusy); err != nil {
		log.Printf("WAL checkpoint at close: %v", err)
	}
}

// lockTimes adds up, over a SQLite file's write transactions, the time
// each waited for Engine.mu, held it, and spent in its COMMIT (with the
// checkpoints out of it, the WAL frames' writes): the wall-clock split of
// the writer's time (tests, benchmarks), also recorded as
// patchlog.db.write.lock.
type lockTimes struct {
	txns, wait, held, commit atomic.Int64 // nanoseconds
}

func (l *lockTimes) note(wait, held time.Duration) {
	l.txns.Add(1)
	l.wait.Add(int64(wait))
	l.held.Add(int64(held))
	observeWriteLock("wait", wait)
	observeWriteLock("held", held)
}

func (l *lockTimes) noteCommit(d time.Duration) {
	l.commit.Add(int64(d))
	observeWriteLock("commit", d)
}
