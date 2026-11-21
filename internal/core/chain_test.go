package core

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// chainEnv is a namespace n and branches d1 of n, d2 of d1, d3 of d2.
func chainEnv(t *testing.T) *schemaEnv {
	t.Helper()
	s := newSchemaEnv(t)
	s.mkNS("n")
	for i, base := range []string{"n", "d1", "d2"} {
		if _, err := s.e.CreateBranch(context.Background(), s.req(base), BranchRequest{Name: fmt.Sprintf("d%d", i+1), IfNoneMatch: true}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// The rows a write transaction keeps of a branch's chain are dropped by
// every statement of its own that inserts or updates a namespaces row, and
// on Postgres a row is dropped when its namespace's lock is taken in
// another mode: what base returns next is the row as the database has it.
func TestChainRowsDropped(t *testing.T) {
	t.Parallel()
	s := chainEnv(t)
	err := s.e.update(context.Background(), func(t *tx) error {
		d3 := t.nsByName("d3")
		d2 := t.base(d3)
		d1 := t.base(d2)
		n := t.base(d1)
		if d2.name != "d2" || d1.name != "d1" || n.name != "n" || n.isBranch() {
			return fmt.Errorf("chain of d3: %s, %s, %s", d2.name, d1.name, n.name)
		}
		for _, id := range []int64{d2.id, d1.id, n.id} {
			if _, ok := t.kept[id]; !ok {
				return fmt.Errorf("the row of namespace %d isn't kept", id)
			}
		}
		if t.e.pg {
			t.lockNS(d1.id, lockExclusive)
			if _, ok := t.kept[d1.id]; ok {
				return fmt.Errorf("the row of d1 is kept across a change of its lock's mode")
			}
			if _, ok := t.kept[n.id]; !ok {
				return fmt.Errorf("the row of n was dropped with d1's")
			}
			if again := t.base(d2); again.id != d1.id || !sameNS(again, d1) {
				return fmt.Errorf("d1 read again: %+v, was %+v", again, d1)
			}
			t.lockNS(n.id, lockExclusive)
		}
		if _, err := t.Exec(`UPDATE namespaces SET frozen = 1 WHERE ns = ?`, n.id); err != nil {
			return err
		}
		if len(t.kept) != 0 {
			return fmt.Errorf("%d rows kept after an update of namespaces", len(t.kept))
		}
		if !t.base(d1).frozen {
			return fmt.Errorf("the base read after it was frozen isn't frozen")
		}
		if len(t.kept) == 0 {
			return fmt.Errorf("no rows kept after reading the chain again")
		}
		t.mustInsert(`INSERT INTO namespaces (name, frozen) VALUES (?, ?) RETURNING ns`, "other", false)
		if len(t.kept) != 0 {
			return fmt.Errorf("%d rows kept after an insert into namespaces", len(t.kept))
		}
		return errRecheck // roll back
	})
	if err != errRecheck {
		t.Fatal(err)
	}
}

// Under PATCHLOG_TEST_VALIDATE_BOTH, a kept row that differs from the
// database's stops the process: here one changed behind the statement
// wrappers' back.
func TestChainOracle(t *testing.T) {
	if !validateBoth {
		t.Skip("PATCHLOG_TEST_VALIDATE_BOTH isn't set")
	}
	t.Parallel()
	s := chainEnv(t)
	err := s.e.update(context.Background(), func(t *tx) error {
		d2 := t.base(t.nsByName("d3"))
		d1 := t.base(d2)
		if _, err := t.Tx.Exec(`UPDATE namespaces SET frozen = 1 WHERE ns = ` + fmt.Sprint(d1.id)); err != nil {
			return err
		}
		t.base(d2)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "kept row of namespace") {
		t.Fatalf("a stale kept row was used: %v", err)
	}
}

// Every statement of the core that writes namespaces rows is one the
// statement wrappers recognise (writesNS), and none deletes a row: the
// rows and links a transaction keeps rest on both (chain.go).
func TestChainStatementsRecognised(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	write := regexp.MustCompile(`(?i)\b(update|into|delete\s+from)\s+namespaces\b`)
	sites := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(nil, 1<<20)
		for line := 1; sc.Scan(); line++ {
			text := sc.Text()
			if strings.HasPrefix(strings.TrimSpace(text), "//") || strings.Contains(text, "strings.Contains(") || !write.MatchString(text) {
				continue
			}
			sites++
			if !writesNS(text) {
				t.Errorf("%s:%d writes namespaces in a way writesNS doesn't recognise: %s", f, line, strings.TrimSpace(text))
			}
			if !strings.Contains(text, "t.Exec(") && !strings.Contains(text, "t.mustInsert(") && !strings.Contains(text, "u AS (UPDATE namespaces") {
				t.Errorf("%s:%d writes namespaces other than through t.Exec or t.mustInsert: %s", f, line, strings.TrimSpace(text))
			}
		}
		fh.Close()
	}
	if sites < 8 {
		t.Errorf("found %d statements writing namespaces, want at least the 8 there were", sites)
	}
}

// Several locks taken in one statement are taken in ascending key order,
// whatever order they are asked for in: transactions taking the same keys
// exclusively, over and over, never deadlock.
func TestLockAllOrder(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("advisory locks: Postgres only")
	}
	t.Parallel()
	s := newSchemaEnv(t)
	const keys, workers, rounds = 40, 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for i := 0; i < rounds; i++ {
				// A different subset each time, so that any two
				// transactions overlap in several keys.
				want := map[int32]lockMode{}
				for _, k := range rnd.Perm(keys)[:keys/2] {
					want[int32(1_000_000+k)] = lockExclusive
				}
				attempts := 0
				err := s.e.update(context.Background(), func(t *tx) error {
					attempts++
					t.lockAll(want)
					for k := range want {
						if t.locks[k] != lockExclusive {
							return fmt.Errorf("key %d isn't held", k)
						}
					}
					return nil
				})
				if err == nil && attempts > 1 {
					err = fmt.Errorf("a transaction taking all its locks at once ran %d times", attempts)
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(int64(w))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A write to a deep branch that finds a base's lock busy (a config write
// or purge of the base holds it exclusively) rolls back once and runs
// again with the whole chain's locks taken up front, in order, waiting for
// the base's holder: it never fails for the depth of its chain.
func TestChainLockBusy(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("advisory locks: Postgres only")
	}
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("n")
	const depth = 8 // the default branchDepth: as many bases as a write transaction has attempts
	base := "n"
	for i := 1; i <= depth; i++ {
		name := fmt.Sprintf("d%d", i)
		if _, err := s.e.CreateBranch(context.Background(), s.req(base), BranchRequest{Name: name, IfNoneMatch: true}); err != nil {
			t.Fatal(err)
		}
		base = name
	}
	s.put(base, "warm", "", map[string]any{"k": 1.0})
	holding, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- s.e.update(context.Background(), func(t *tx) error {
			// Every base's lock, as a purge that propagates holds them.
			t.nsForWrite("n")
			for i := 1; i < depth; i++ {
				t.nsForWrite(fmt.Sprintf("d%d", i))
			}
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	var attempts atomic.Int32
	s.e.onStatement = func(q string, _ []any) {
		if strings.Contains(q, "pg_try_advisory_xact_lock") {
			attempts.Add(1)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.e.WriteResource(context.Background(), s.req(base), createItem("r", map[string]any{"k": 1.0}))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the write didn't wait for its bases' locks: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write after the bases' locks were released: %v", err)
	}
	if n := attempts.Load(); n != 1 {
		t.Errorf("the write tried its bases' locks %d times, want once", n)
	}
}
