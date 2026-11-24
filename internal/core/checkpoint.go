package core

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// WAL checkpoints of a SQLite file, off the writer's path (D.3).
//
// SQLite's default runs a PASSIVE checkpoint inside the COMMIT that takes
// the WAL past 1,000 frames: in the write transaction, so under Engine.mu,
// where it was about half of the commit (docs/SQLITE-NAMESPACES.md, "The
// problem, measured"). Every connection instead sets wal_autocheckpoint(0)
// (openSQLite), and checkpointLoop runs them alongside the writer:
//
//   - Every CheckpointInterval, a PASSIVE checkpoint. It takes no lock a
//     writer or reader waits for: it copies the frames no reader still
//     needs into the database file and syncs it, and a writer that later
//     finds every frame copied, with no reader in the WAL, starts it over.
//     It does no I/O when there is nothing new.
//   - Readers that always overlap can keep the WAL from starting over (a
//     reader whose snapshot needs frames pins them, and PASSIVE never
//     waits), so the WAL would grow for good: today's autocheckpoint is
//     PASSIVE too and has the same flaw. Once it holds walLimitFrames, a
//     TRUNCATE checkpoint runs under Engine.mu, so this process's writers
//     queue on the mutex rather than in SQLite's busy handler. It waits
//     for the readers in the WAL to finish (they are short; new ones read
//     the copied database file and don't hold it up), copies every frame
//     and truncates the WAL to nothing. It waits at most
//     walCheckpointBusy, then gives up until the next interval.
//   - Once a PASSIVE checkpoint finds no new frame since the previous one
//     (no write in an interval) and the WAL not empty, the same TRUNCATE
//     runs, if Engine.mu is free (TryLock: a writer that holds it isn't
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
	// walCheckpointBusy bounds how long a TRUNCATE checkpoint waits for
	// readers (and other processes' writers), holding Engine.mu.
	walCheckpointBusy = time.Second
	// walIdleBusy is that bound for the TRUNCATE of an idle WAL, which a
	// write arriving meanwhile would wait for.
	walIdleBusy = 50 * time.Millisecond
)

// walLimitFrames is how many frames the WAL may hold before a TRUNCATE
// checkpoint is forced: 64 MiB at the default 4 KiB pages. A variable for
// tests.
var walLimitFrames int64 = 16384

// walStats counts checkpoints (tests, benchmarks).
type walStats struct {
	passive, truncated, busy atomic.Int64
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
		switch {
		case frames >= walLimitFrames:
			e.mu.Lock()
			frames, _, err = e.checkpointTruncate(walCheckpointBusy)
			e.mu.Unlock()
		case frames > 0 && frames == last && done == frames && e.mu.TryLock():
			// Idle: no frame since the last interval, all copied.
			frames, _, err = e.checkpointTruncate(walIdleBusy)
			e.mu.Unlock()
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

// checkpointTruncate runs a TRUNCATE checkpoint that waits at most busy
// for the locks it needs, on a connection of its own whose busy timeout is
// set for it. Callers hold Engine.mu, or have no writer (Close).
func (e *Engine) checkpointTruncate(busy time.Duration) (frames, done int64, err error) {
	ctx := context.Background()
	c, err := e.db.Conn(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, fmt.Sprintf(`PRAGMA busy_timeout = %d`, busy.Milliseconds())); err != nil {
		return 0, 0, err
	}
	// Back to the DSN's (openSQLite) before the connection returns to the
	// pool.
	defer c.ExecContext(ctx, `PRAGMA busy_timeout = 10000`)
	var b int
	if err := c.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&b, &frames, &done); err != nil {
		return 0, 0, err
	}
	e.noteCheckpoint("TRUNCATE", b, frames)
	return frames, done, nil
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
	if _, _, err := e.checkpointTruncate(walCheckpointBusy); err != nil {
		log.Printf("WAL checkpoint at close: %v", err)
	}
}
