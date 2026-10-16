package follow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/middle-management/patchlog/internal/client"
)

// --- checkpoints -----------------------------------------------------------

// Resumer is a Checkpoint that also keeps how far a snapshot bootstrap
// listed by pages got (Batch.Partial), so a follower that restarts before
// its last page resumes after the last page applied rather than from the
// first. MemoryCheckpoints and SQLCheckpoints are Resumers.
type Resumer interface {
	// LoadBootstrap returns the position (ns_id) of an unfinished
	// snapshot and the cursor of its next page, "" and "" if none.
	LoadBootstrap(ctx context.Context, origin, ns string) (at, after string, err error)
}

// MemoryCheckpoints is an in-memory Checkpoint store, for tests and
// consumers whose derived data is itself in memory.
type MemoryCheckpoints struct {
	mu sync.Mutex
	m  map[[3]string]string
	bs map[[2]string][2]string // unfinished snapshots: at, after
}

// SaveBatch records what applying b reaches: its checkpoint, or for a page
// of a snapshot that later pages complete, how far the snapshot got.
func (m *MemoryCheckpoints) SaveBatch(origin, ns string, b *Batch) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{origin, ns}
	if b.Partial() {
		if m.bs == nil {
			m.bs = map[[2]string][2]string{}
		}
		m.bs[k] = [2]string{b.NewCheckpoint, b.More}
		return
	}
	delete(m.bs, k)
	if m.m == nil {
		m.m = map[[3]string]string{}
	}
	m.m[[3]string{origin, ns}] = b.NewCheckpoint
}

// LoadBootstrap implements Resumer.
func (m *MemoryCheckpoints) LoadBootstrap(_ context.Context, origin, ns string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.bs[[2]string{origin, ns}]
	return p[0], p[1], nil
}

// Load returns the saved ns_id, "" if none.
func (m *MemoryCheckpoints) Load(_ context.Context, origin, ns string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.m[[3]string{origin, ns}], nil
}

// Save records an ns_id.
func (m *MemoryCheckpoints) Save(origin, ns, nsID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[[3]string]string{}
	}
	m.m[[3]string{origin, ns}] = nsID
}

// Execer is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SQLCheckpoints stores checkpoints in a table
//
//	checkpoints(origin TEXT, ns TEXT, ns_id TEXT, PRIMARY KEY (origin, ns))
//
// and unfinished snapshot bootstraps (Resumer) in another, named after it
//
//	checkpoints_bootstrap(origin TEXT, ns TEXT, at_id TEXT, after_name TEXT, PRIMARY KEY (origin, ns))
//
// Save takes the caller's transaction, so the checkpoint commits with the
// derived data (§A.1). Queries use ? placeholders (SQLite, MySQL) unless
// Dollar is set (PostgreSQL); the upsert is INSERT … ON CONFLICT, which
// SQLite ≥ 3.24 and PostgreSQL support.
type SQLCheckpoints struct {
	DB     *sql.DB
	Table  string // default "checkpoints"
	Dollar bool   // use $1, $2, … placeholders
}

var tableRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (s SQLCheckpoints) table() (string, error) {
	t := s.Table
	if t == "" {
		t = "checkpoints"
	}
	if !tableRe.MatchString(t) {
		return "", fmt.Errorf("follow: invalid table name %q", t)
	}
	return t, nil
}

func (s SQLCheckpoints) ph(i int) string {
	if s.Dollar {
		return fmt.Sprintf("$%d", i)
	}
	return "?"
}

// Init creates the table if it doesn't exist.
func (s SQLCheckpoints) Init(ctx context.Context) error {
	t, err := s.table()
	if err != nil {
		return err
	}
	if _, err = s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+t+` (origin TEXT NOT NULL, ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (origin, ns))`); err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+t+`_bootstrap (origin TEXT NOT NULL, ns TEXT NOT NULL, at_id TEXT NOT NULL, after_name TEXT NOT NULL, PRIMARY KEY (origin, ns))`)
	return err
}

// LoadBootstrap implements Resumer.
func (s SQLCheckpoints) LoadBootstrap(ctx context.Context, origin, ns string) (string, string, error) {
	t, err := s.table()
	if err != nil {
		return "", "", err
	}
	var at, after string
	err = s.DB.QueryRowContext(ctx, `SELECT at_id, after_name FROM `+t+`_bootstrap WHERE origin = `+s.ph(1)+` AND ns = `+s.ph(2), origin, ns).Scan(&at, &after)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return at, after, err
}

// SaveBatch records through tx what applying b reaches: b.NewCheckpoint
// (Save), or for a page of a snapshot that later pages complete
// (Batch.Partial), how far the snapshot got, which LoadBootstrap returns
// until its last page is saved. Use it in place of Save in the
// transaction that applies b.
func (s SQLCheckpoints) SaveBatch(ctx context.Context, tx Execer, origin, ns string, b *Batch) error {
	t, err := s.table()
	if err != nil {
		return err
	}
	if b.Partial() {
		_, err = tx.ExecContext(ctx, `INSERT INTO `+t+`_bootstrap (origin, ns, at_id, after_name) VALUES (`+s.ph(1)+`, `+s.ph(2)+`, `+s.ph(3)+`, `+s.ph(4)+`)
			ON CONFLICT (origin, ns) DO UPDATE SET at_id = excluded.at_id, after_name = excluded.after_name`, origin, ns, b.NewCheckpoint, b.More)
		return err
	}
	if b.Snapshot {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+`_bootstrap WHERE origin = `+s.ph(1)+` AND ns = `+s.ph(2), origin, ns); err != nil {
			return err
		}
	}
	return s.Save(ctx, tx, origin, ns, b.NewCheckpoint)
}

// Load returns the saved ns_id, "" if none.
func (s SQLCheckpoints) Load(ctx context.Context, origin, ns string) (string, error) {
	t, err := s.table()
	if err != nil {
		return "", err
	}
	var id string
	err = s.DB.QueryRowContext(ctx, `SELECT ns_id FROM `+t+` WHERE origin = `+s.ph(1)+` AND ns = `+s.ph(2), origin, ns).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// Save records an ns_id through tx (use the transaction that writes the
// derived data).
func (s SQLCheckpoints) Save(ctx context.Context, tx Execer, origin, ns, nsID string) error {
	t, err := s.table()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO `+t+` (origin, ns, ns_id) VALUES (`+s.ph(1)+`, `+s.ph(2)+`, `+s.ph(3)+`)
		ON CONFLICT (origin, ns) DO UPDATE SET ns_id = excluded.ns_id`, origin, ns, nsID)
	return err
}

// --- coalescing --------------------------------------------------------------

// Change is the latest resource-level entry for one resource within a range.
type Change struct {
	Resource string
	Kind     string // head, tombstone or purge
	Target   string
	// EntryID is the namespace entry that carried it (the batch entry for
	// a batch sub-entry; "" for synthetic snapshot units).
	EntryID string
	// Purged is true if the resource was purged anywhere in the range, even
	// if a later entry is shown, so consumers still purge derived data and
	// cache tags.
	Purged bool
}

// Coalesced is the result of Coalesce.
type Coalesced struct {
	// Changes holds the latest head/tombstone/purge per resource, in the
	// order of each resource's latest entry. After a purge-ns only later
	// changes remain.
	Changes []Change
	// Others holds, in order, the entries that are not per-resource
	// changes: config, branch, purge-ns and prune (and a batch's config
	// sub-entry, as a config entry carrying the batch's id).
	Others []client.NSEntry
	// PurgedNS is true if the range contains a purge-ns entry.
	PurgedNS bool
}

// Coalesce reduces a range of units to the latest entry per resource (§10:
// "within a range of entries, only the latest entry per resource matters").
// Batches stay atomic as long as the whole range is applied in one
// transaction, which is what Apply does with WithMaxUnits(0).
func Coalesce(units []Unit) Coalesced {
	var out Coalesced
	idx := map[string]int{}
	var order []Change
	purged := map[string]bool{}
	add := func(e client.NSEntry, entryID string) {
		if e.Kind == "purge" {
			purged[e.Resource] = true
		}
		c := Change{Resource: e.Resource, Kind: e.Kind, Target: e.Target, EntryID: entryID}
		if i, ok := idx[e.Resource]; ok {
			order[i].Resource = "" // superseded
		}
		idx[e.Resource] = len(order)
		order = append(order, c)
	}
	for _, u := range units {
		e := u.Entry
		switch e.Kind {
		case "head", "tombstone", "purge":
			add(e, e.ID)
		case "batch":
			for _, s := range e.Entries {
				if s.Kind == "config" {
					cfg := s
					cfg.ID = e.ID
					out.Others = append(out.Others, cfg)
					continue
				}
				add(s, e.ID)
			}
		case "purge-ns":
			out.PurgedNS = true
			order, idx, purged = nil, map[string]int{}, map[string]bool{}
			out.Others = append(out.Others, e)
		default:
			out.Others = append(out.Others, e)
		}
	}
	for _, c := range order {
		if c.Resource == "" {
			continue
		}
		c.Purged = purged[c.Resource]
		out.Changes = append(out.Changes, c)
	}
	return out
}

// Coalesce is Coalesce(b.Units).
func (b *Batch) Coalesce() Coalesced { return Coalesce(b.Units) }

// --- fetching content -----------------------------------------------------------

// ErrNotLive is returned by FetchDoc when a pruned revision's resource has
// no live head to fall back to (tombstoned, purged or not found).
var ErrNotLive = errors.New("follow: resource has no live head")

// FetchDoc fetches the document at revision id; if that revision lies below
// the pruning horizon (410 pruned), it fetches the resource's current head
// instead (§10 prune). The returned Doc's ID says which revision it is.
// A later entry for the resource will then bring the consumer to the same
// state, so processing stays idempotent.
func FetchDoc(ctx context.Context, c *client.Client, ns, name, id string) (*client.Doc, error) {
	d, err := c.Doc(ctx, ns, name, id)
	if err == nil || !client.IsPruned(err) {
		return d, err
	}
	h, d, err := c.Load(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	if h.State != client.Live {
		return nil, fmt.Errorf("%w (%s/%s is %s)", ErrNotLive, ns, name, h.State)
	}
	return d, nil
}
