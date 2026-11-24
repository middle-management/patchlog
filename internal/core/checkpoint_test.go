package core

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// WAL checkpoints off the writer's path (checkpoint.go), on SQLite files.

// fileEngine opens an engine on a SQLite file in dir, adjusted by opt.
func fileEngine(t *testing.T, path string, opt func(*Options)) *Engine {
	t.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	o := Options{Path: path, BlobDir: filepath.Join(filepath.Dir(path), "blobs"), AuthDisabled: true, RetentionInterval: -1,
		Limits: lim, Purger: discardPurger{}}
	if opt != nil {
		opt(&o)
	}
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// walSize is the size of the WAL file of the database at path, 0 if it
// has none.
func walSize(path string) int64 {
	fi, err := os.Stat(path + "-wal")
	if err != nil {
		return 0
	}
	return fi.Size()
}

// verifyChain verifies ns's whole chain in storage, on either dialect: every
// entry follows the one before it by seq, its id is the hash of the previous
// id and its body (§3.5), and the namespace's head is the last. It returns
// each entry's seq by entry id.
func verifyChain(t *testing.T, e *Engine, ns string) map[string]int64 {
	t.Helper()
	q := `SELECT seq, id, prev_seq, body FROM ns_log WHERE ns = (SELECT ns FROM namespaces WHERE name = ?) ORDER BY seq`
	h := `SELECT head_id FROM namespaces WHERE name = ?`
	if e.pg {
		q, h = strings.Replace(q, "?", "$1", 1), strings.Replace(h, "?", "$1", 1)
	}
	rows, err := e.db.QueryContext(context.Background(), q, ns)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seqs := map[string]int64{}
	var prev *ids.ID
	var prevSeq int64
	for rows.Next() {
		var seq int64
		var id []byte
		var ps *int64
		var body string
		if err := rows.Scan(&seq, &id, &ps, &body); err != nil {
			t.Fatal(err)
		}
		if (prev == nil) != (ps == nil) || ps != nil && *ps != prevSeq {
			t.Fatalf("entry %d follows %v, want %d", seq, ps, prevSeq)
		}
		if want := ids.Hash(prev, []byte(body)); want != ids.FromBytes(id) {
			t.Fatalf("entry %d's id is %s, want %s", seq, ids.FromBytes(id), want)
		}
		p := ids.FromBytes(id)
		prev, prevSeq = &p, seq
		seqs[p.String()] = seq
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var headID []byte
	if err := e.db.QueryRow(h, ns).Scan(&headID); err != nil {
		t.Fatal(err)
	}
	if prev == nil || ids.FromBytes(headID) != *prev {
		t.Fatalf("the namespace's head is %x, its last entry %v", headID, prev)
	}
	return seqs
}

// No connection checkpoints in a commit; the engine checkpoints in the
// background while writes go on, and truncates the WAL once they stop.
func TestCheckpointInBackground(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	e := fileEngine(t, path, func(o *Options) { o.CheckpointInterval = 10 * time.Millisecond })
	mkNS(t, e, "n", map[string]any{"read": "public"})
	// Every connection of the pool, several at once.
	var conns []*sql.Conn
	for i := 0; i < 3; i++ {
		c, err := e.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var n int
		if err := c.QueryRowContext(context.Background(), `PRAGMA wal_autocheckpoint`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("connection %d: wal_autocheckpoint %d %v, want 0", i, n, err)
		}
	}
	for _, c := range conns {
		c.Close()
	}
	h := ""
	for i := 0; i < 300; i++ {
		var err error
		if h, err = put(e, "n", "r", h, i); err != nil {
			t.Fatal(err)
		}
	}
	within(t, 5*time.Second, "a passive checkpoint", func() bool { return e.wal.passive.Load() > 0 })
	within(t, 5*time.Second, "the idle WAL truncated", func() bool { return e.wal.truncated.Load() > 0 && walSize(path) == 0 })
	if hd, err := e.ResourceHead(context.Background(), "n", "r", who.Cred); err != nil || hd.Head != h {
		t.Fatalf("head %+v %v, want %s", hd, err, h)
	}
}

// Readers that always overlap keep a PASSIVE checkpoint from letting the
// WAL start over, so without more it grows with every write; past
// walLimitFrames a TRUNCATE checkpoint waits the readers out and bounds it.
func TestCheckpointWALBounded(t *testing.T) {
	const limit = 200
	const writes = 1500
	run := func(interval time.Duration) (maxWAL int64, e *Engine) {
		path := filepath.Join(t.TempDir(), "p.db")
		e = fileEngine(t, path, func(o *Options) {
			o.CheckpointInterval = interval
			o.walLimitFrames = limit
		})
		mkNS(t, e, "n", map[string]any{"read": "public"})
		stop := make(chan struct{})
		var wg sync.WaitGroup
		// Four readers, each holding a snapshot 2 ms, started 0.5 ms
		// apart: one is always in the WAL.
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(time.Duration(i) * 500 * time.Microsecond)
				for {
					select {
					case <-stop:
						return
					default:
					}
					tx, err := e.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
					if err != nil {
						t.Error(err)
						return
					}
					var n int
					tx.QueryRow(`SELECT count(*) FROM ns_log`).Scan(&n)
					time.Sleep(2 * time.Millisecond)
					tx.Rollback()
				}
			}()
		}
		var max atomic.Int64
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case <-time.After(time.Millisecond):
				}
				if s := walSize(path); s > max.Load() {
					max.Store(s)
				}
			}
		}()
		h := ""
		for i := 0; i < writes; i++ {
			var err error
			if h, err = put(e, "n", "r", h, i); err != nil {
				t.Fatal(err)
			}
		}
		close(stop)
		wg.Wait()
		return max.Load(), e
	}
	// 4 KiB pages, 24 bytes of frame header each.
	const frame = 4096 + 24
	off, _ := run(-1)
	on, e := run(5 * time.Millisecond)
	t.Logf("WAL at most %d frames without checkpoints, %d with (limit %d), %d truncated, %d busy", off/frame, on/frame, limit, e.wal.truncated.Load(), e.wal.busy.Load())
	if e.wal.truncated.Load() == 0 {
		t.Fatal("no TRUNCATE checkpoint ran")
	}
	// The limit plus what the writer adds while a PASSIVE checkpoint
	// copies frames and a TRUNCATE waits for readers: on a loaded host
	// (the whole suite in parallel) a few times the limit, but a fraction
	// of the WAL without checkpoints, which grows with every write.
	if on*3 > off {
		t.Fatalf("the WAL reached %d bytes with checkpoints, %d without", on, off)
	}
	// Once the writes and readers stop, the idle WAL is truncated.
	within(t, 5*time.Second, "the idle WAL truncated", func() bool { return walSize(e.opt.Path) == 0 })
}

// Writes are kept across a close and an open: Close checkpoints the WAL
// into the database and truncates it.
func TestCheckpointCloseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	e := fileEngine(t, path, func(o *Options) { o.CheckpointInterval = time.Hour })
	mkNS(t, e, "n", map[string]any{"read": "public"})
	heads := map[string]string{}
	for i := 0; i < 50; i++ {
		name := fmt.Sprint("r", i%5)
		h, err := put(e, "n", name, heads[name], i)
		if err != nil {
			t.Fatal(err)
		}
		heads[name] = h
	}
	if walSize(path) == 0 {
		t.Fatal("no WAL before close: the test checks nothing")
	}
	seqs := verifyChain(t, e, "n")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if s := walSize(path); s != 0 {
		t.Fatalf("WAL of %d bytes after close", s)
	}
	e = fileEngine(t, path, nil)
	if got := verifyChain(t, e, "n"); len(got) != len(seqs) {
		t.Fatalf("%d entries after reopening, %d before", len(got), len(seqs))
	}
	for name, h := range heads {
		if hd, err := e.ResourceHead(context.Background(), "n", name, who.Cred); err != nil || hd.Head != h {
			t.Fatalf("%s: head %+v %v, want %s", name, hd, err, h)
		}
	}
}

// crashEnv names the database a crashing child process writes to
// (TestCheckpointCrash).
const crashEnv = "PATCHLOG_TEST_CRASH_DB"

// A process killed while writing, with checkpoints in the background and
// groups committing, leaves every write it answered, and a valid chain, to
// the next open.
func TestCheckpointCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	path := filepath.Join(t.TempDir(), "p.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCheckpointCrashChild$")
	cmd.Env = append(os.Environ(), crashEnv+"="+path)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// "<resource> <revision> <entry> <groups committed>" for every write
	// answered.
	type answered struct{ rev, entry string }
	last := map[string]answered{}
	groups := "0"
	var all []answered
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 {
			continue
		}
		groups = f[3]
		a := answered{f[1], f[2]}
		last[f[0]] = a
		all = append(all, a)
		if len(all) == 600 {
			cmd.Process.Kill()
			break
		}
	}
	cmd.Wait()
	if len(all) < 600 {
		t.Fatalf("the child answered %d writes", len(all))
	}
	if groups == "0" {
		t.Fatal("the child committed no group: the test checks no group commit")
	}
	e := fileEngine(t, path, nil)
	seqs := verifyChain(t, e, "n")
	for _, a := range all {
		if _, ok := seqs[a.entry]; !ok {
			t.Fatalf("entry %s, answered, is lost", a.entry)
		}
	}
	// A resource's head is its last answered write's, or a later one's
	// whose answer the kill cut off.
	for name, a := range last {
		hd, err := e.ResourceHead(context.Background(), "n", name, who.Cred)
		if err != nil {
			t.Fatal(err)
		}
		if hd.Head != a.rev && !headDescends(t, e, name, a.rev) {
			t.Fatalf("%s: head %s, the last answered %s", name, hd.Head, a.rev)
		}
	}
	t.Logf("%d writes answered before the kill (%s groups), %d entries after reopening", len(all), groups, len(seqs))
}

// headDescends reports whether the head of resource name of namespace n
// is old or has it as an ancestor.
func headDescends(t *testing.T, e *Engine, name, old string) bool {
	t.Helper()
	found := false
	err := e.read(context.Background(), func(tx *tx) error {
		r := tx.resource(tx.nsByName("n").id, name)
		for seq := r.headSeq; seq.Valid; {
			row := tx.rev(seq.Int64)
			if row.id.String() == old {
				found = true
				return nil
			}
			seq = row.parentSeq
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestCheckpointCrashChild is TestCheckpointCrash's child: it writes to
// the database crashEnv names until it is killed.
func TestCheckpointCrashChild(t *testing.T) {
	path := os.Getenv(crashEnv)
	if path == "" {
		t.Skip("run by TestCheckpointCrash")
	}
	e := fileEngine(t, path, func(o *Options) { o.CheckpointInterval = 2 * time.Millisecond })
	mkNS(t, e, "n", map[string]any{"read": "public"})
	var mu sync.Mutex
	w := bufio.NewWriter(os.Stdout)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprint("r", g)
			h := ""
			for i := 0; ; i++ {
				res, err := write(e, "n", name, h, i)
				if err != nil {
					t.Error(err)
					return
				}
				h = res.Items[0].IDs[0]
				mu.Lock()
				fmt.Fprintf(w, "%s %s %s %d\n", name, h, res.NSID, e.groups.committed.Load())
				w.Flush()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}
