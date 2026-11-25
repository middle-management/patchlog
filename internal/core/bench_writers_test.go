package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// BenchmarkNamespaceWriters appends small documents from concurrent
// writers, each to a resource of its own, in one or several namespaces, on
// a fresh SQLite file (or Postgres database) per run:
//
//	go test ./internal/core -run '^$' -bench NamespaceWriters -benchtime 3s
//
// It reports writes/s, the latency percentiles, the process's CPU and
// disk writes (/proc/self/io, Linux) per write, on SQLite the time under
// the writer's mutex, in COMMIT and in checkpoints holding it per write,
// and with group commit the
// writes per group. The readers=8 cases add eight goroutines that read
// each new revision once (ResourceRev), as consumers following the
// namespaces do; a revision they can't keep up with is skipped.
func BenchmarkNamespaceWriters(b *testing.B) {
	for _, c := range []struct{ ns, writers, readers int }{
		{1, 1, 0}, {1, 4, 0}, {1, 16, 0}, {1, 32, 0},
		{4, 8, 0}, {16, 8, 0}, {16, 2, 0},
		{4, 8, 8}, {16, 8, 8},
	} {
		name := fmt.Sprintf("ns=%d/writers=%d", c.ns, c.ns*c.writers)
		if c.readers > 0 {
			name += fmt.Sprintf("/readers=%d", c.readers)
		}
		b.Run(name, func(b *testing.B) {
			benchNamespaceWriters(b, c.ns, c.writers, c.readers)
		})
	}
}

func benchNamespaceWriters(b *testing.B, nss, perNS, readers int) {
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	path := filepath.Join(b.TempDir(), "bench.db")
	if pgtest.Enabled() {
		path = pgtest.NewDB(b)
	}
	e, err := Open(Options{Path: path, BlobDir: b.TempDir(), AuthDisabled: true, RetentionInterval: -1, Limits: lim, Purger: discardPurger{}})
	if err != nil {
		b.Fatal(err)
	}
	defer e.Close()
	cred := Credentials{Author: "a"}
	type writer struct {
		ns, name, head string
	}
	var ws []*writer
	for n := 0; n < nss; n++ {
		ns := fmt.Sprint("b", n)
		genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}
		if _, err := e.WriteConfig(context.Background(), Request{NS: ns, Cred: cred}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
			b.Fatal(err)
		}
		for w := 0; w < perNS; w++ {
			ws = append(ws, &writer{ns: ns, name: fmt.Sprint("w", w)})
		}
	}
	var fresh chan [3]string // revisions for the readers
	put := func(w *writer, i int) error {
		it := Item{Resource: w.name, IfMatch: w.head, IfNoneMatch: w.head == ""}
		op := "replace"
		if w.head == "" {
			op = "add"
		}
		it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(i)}}}}}
		r, err := e.WriteResource(context.Background(), Request{NS: w.ns, Cred: cred}, it)
		if err != nil {
			return err
		}
		w.head = r.Items[0].IDs[0]
		if fresh != nil {
			select {
			case fresh <- [3]string{w.ns, w.name, w.head}:
			default:
			}
		}
		return nil
	}
	for _, w := range ws {
		if err := put(w, 0); err != nil {
			b.Fatal(err)
		}
	}
	lat := make([]time.Duration, b.N)
	var next atomic.Int64
	var wg sync.WaitGroup
	groups, grouped := e.groups.committed.Load(), e.groups.appended.Load()
	cpu0, disk0 := processCPU(), diskWrites()
	txns0, held0, commit0 := e.lockTimes.txns.Load(), e.lockTimes.held.Load(), e.lockTimes.commit.Load()
	ckpt0 := e.wal.held.Load()
	var reads atomic.Int64
	var rwg sync.WaitGroup
	if readers > 0 {
		fresh = make(chan [3]string, 1024)
		for range readers {
			rwg.Add(1)
			go func() {
				defer rwg.Done()
				for r := range fresh {
					if _, err := e.ResourceRev(context.Background(), r[0], r[1], r[2], cred); err != nil {
						b.Error(err)
						return
					}
					reads.Add(1)
				}
			}()
		}
	}
	b.ResetTimer()
	start := time.Now()
	for _, w := range ws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= b.N {
					return
				}
				t0 := time.Now()
				if err := put(w, i+1); err != nil {
					b.Error(err)
					return
				}
				lat[i] = time.Since(t0)
			}
		}()
	}
	wg.Wait()
	el := time.Since(start)
	b.StopTimer()
	if fresh != nil {
		close(fresh)
		rwg.Wait()
		b.ReportMetric(float64(reads.Load())/float64(b.N), "reads/write")
	}
	cpu, disk := processCPU()-cpu0, diskWrites()-disk0
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	b.ReportMetric(float64(b.N)/el.Seconds(), "writes/s")
	b.ReportMetric(float64(lat[len(lat)/2].Microseconds())/1000, "p50-ms")
	b.ReportMetric(float64(lat[len(lat)*99/100].Microseconds())/1000, "p99-ms")
	b.ReportMetric(float64(cpu.Microseconds())/float64(b.N), "cpu-us/write")
	if disk0 >= 0 {
		b.ReportMetric(float64(disk)/1024/float64(b.N), "disk-KiB/write")
	}
	// SQLite: the writer's time under Engine.mu per write, and of that
	// the COMMIT's (lockTimes).
	if txns := e.lockTimes.txns.Load() - txns0; txns > 0 {
		b.ReportMetric(float64(e.lockTimes.held.Load()-held0)/1e3/float64(b.N), "held-us/write")
		b.ReportMetric(float64(e.lockTimes.commit.Load()-commit0)/1e3/float64(b.N), "commit-us/write")
		// And the checkpoints that hold it to let the WAL start over.
		b.ReportMetric(float64(e.wal.held.Load()-ckpt0)/1e3/float64(b.N), "ckpt-us/write")
	}
	if n := e.groups.committed.Load() - groups; n > 0 {
		g := e.groups.appended.Load() - grouped
		b.ReportMetric(float64(g)/float64(b.N), "grouped/op")
		b.ReportMetric(float64(g)/float64(n), "writes/group")
	}
}

// diskWrites is write_bytes of /proc/self/io: the bytes this process has
// caused to be written to storage. -1 where there is none.
func diskWrites() int64 {
	data, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "write_bytes: "); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
	}
	return -1
}
