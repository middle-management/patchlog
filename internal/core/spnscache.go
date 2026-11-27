package core

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// nsCache keeps, on Spanner, the namespace rows a write's check read, by
// name, so the next check of the namespace reads only its resource
// (lookupResource). Once Spanner splits namespaces from the resources
// and revisions they hold, the join cost the check up to three remote
// calls and three times the CPU (docs/SPANNER.md, the tenth run).
//
// A row here may be stale, and that is safe:
//   - the re-check reads the namespace row again inside the write
//     transaction and compares what the check depended on (sameNS), so a
//     stale row only sends the write round again, after dropping the
//     entry (drop);
//   - a check that used the cache and refuses or answers runs again
//     without it (checkOutside), so a stale row never refuses a write;
//   - the head, which moves with every write and which sameNS ignores, is
//     never used from here: the write reads it again (appendNS).
//
// Entries go when anything moves what namespace rows hold (an
// invalidation with meta: a configuration write, a freeze, a purge, here
// or through the tailer), and after nsCacheTTL regardless.
type nsCache struct {
	mu  sync.Mutex
	gen uint64
	m   map[string]nsCached
}

type nsCached struct {
	n  nsRow
	at time.Time
}

const (
	nsCacheTTL = 5 * time.Second
	nsCacheMax = 1 << 14
)

func (c *nsCache) get(name string, now time.Time) (nsRow, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[name]
	if !ok || now.Sub(e.at) > nsCacheTTL {
		return nsRow{}, false
	}
	return e.n, true
}

// generation is what put compares, so a row read before a flush isn't
// kept after it.
func (c *nsCache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

func (c *nsCache) put(n *nsRow, gen uint64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if c.m == nil || len(c.m) >= nsCacheMax {
		c.m = map[string]nsCached{}
	}
	c.m[n.name] = nsCached{*n, now}
}

func (c *nsCache) drop(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	delete(c.m, name)
}

func (c *nsCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.m = nil
}

// lookupCached is lookupResource from a cached namespace row: the
// resource, its head and the seq of its revision with id want, in one
// statement without the namespaces table. It reports false when there is
// no row to use.
func (t *tx) lookupCached(name, res string, want *ids.ID) (*nsRow, bool) {
	n, ok := t.e.nsc.get(name, t.now)
	if !ok {
		return nil, false
	}
	t.nsCached = true
	var idArg any
	if want != nil {
		idArg = want[:]
	}
	var nr nullRes
	var hr nullRev
	var xseq sql.NullInt64
	dest := make([]any, 0, 9+16+1)
	dest = nr.dest(dest)
	dest = hr.dest(dest)
	dest = append(dest, &xseq)
	err := t.QueryRow(lookupCachedSQL, idArg, n.id, res).Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		t.memoRes(resKey{n.id, res}, nil)
		return &n, true
	}
	t.must(err)
	r := nr.row()
	t.memoRes(resKey{n.id, res}, r)
	if h := hr.row(); h != nil {
		t.memoRev(h)
	}
	if r != nil && want != nil {
		k := revIDKey{r.id, *want}
		if xseq.Valid {
			if t.memo.idSeq == nil {
				t.memo.idSeq = map[revIDKey]int64{}
			}
			t.memo.idSeq[k] = xseq.Int64
		} else {
			t.memoByID(k, nil)
		}
	}
	return &n, true
}

var lookupCachedSQL = func() string {
	cols := func(alias, list string) string {
		var out []string
		for _, c := range strings.Split(list, ",") {
			out = append(out, alias+"."+strings.TrimSpace(c))
		}
		return strings.Join(out, ", ")
	}
	return `SELECT ` + cols("r", resCols) + `, ` + cols("h", revCols) +
		`, (SELECT seq FROM revisions WHERE res = r.res AND id = ? LIMIT 1)
		FROM resources r LEFT JOIN revisions h ON h.res = r.res AND h.seq = r.head_seq
		WHERE r.ns = ? AND r.name = ?`
}()
