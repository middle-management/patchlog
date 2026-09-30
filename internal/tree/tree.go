// Package tree is the tree service of Addendum B (§B.2–§B.9): a namespace
// consumer (§10) that follows a catalog namespace and every content
// namespace its catalog.trust lists (§B.6), keeps folders, placements and
// their edges in SQLite (§B.5) with the checkpoints of all followed
// namespaces committed in the same transaction as the rows derived from
// them, and serves listings on its own origin.
//
// One database holds every followed namespace, and the serving view is an
// in-memory graph replaced only after a commit, so a listing is always
// consistent as of the recorded checkpoints of the catalog and the content
// namespaces together.
//
// Nodes (§B.2): a catalog document whose name has no dot is a folder; a
// name {ns}.{name} is a placement of /r/{ns}/{name}. parents are live links
// to folders of the same catalog. Walks go up only through "walkable"
// edges: the parent exists, is a folder, and neither end is in a cycle.
// Cycles are the strongly connected components of the folder graph (every
// edge inside one is flagged, rather than an arbitrary "closing" edge, so
// the result does not depend on traversal order). Walks are bounded at
// depth 64 and deeper nodes are flagged (§B.5).
//
// A Hook (the catalog of §B.11) can keep more derived tables in the same
// transactions, and a RoleView can widen what a reader may see.
package tree

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// Purger purges the tree service's own cache tags.
type Purger interface{ PurgeTags(tags []string) }

// Hook keeps derived data of its own in the tree service's database, in
// the same transactions as the graph (used by internal/catalog).
type Hook interface {
	// Init creates the hook's tables.
	Init(ctx context.Context, db *sql.DB) error
	// Rebuild recomputes everything from g (on start, and after a failed
	// apply was rolled back and the graph reloaded).
	Rebuild(ctx context.Context, tx *sql.Tx, g *Graph) error
	// Update is called inside an apply transaction with the names of the
	// nodes that changed (added, removed, or with changed document or
	// derived state).
	Update(ctx context.Context, tx *sql.Tx, g *Graph, changed map[string]bool) error
}

// Options configure a Service.
type Options struct {
	// Client reads the core API. It needs read on the catalog and on every
	// trusted content namespace (§C.6).
	Client *client.Client
	// Catalog is the catalog namespace.
	Catalog string
	// DB is the SQLite database path.
	DB string
	// Rebuild drops the database and replays from "".
	Rebuild bool
	// SelfPlacing accepts $parents in trusted content documents as implicit
	// placements (§B.9). An explicit placement for the same item wins.
	SelfPlacing bool
	// MinWait bounds how long ?min= waits (default 2s).
	MinWait time.Duration
	// Now is the clock for grant checks (default time.Now).
	Now func() time.Time
	// CheckerTTL is how long namespace documents are cached for grant
	// checks (default 30s).
	CheckerTTL time.Duration
	// Purger receives cache-tag purges (default: log).
	Purger Purger
	// Logf logs (default log.Printf).
	Logf func(format string, args ...any)
	// OnApply is called after each batch commits.
	OnApply func(b *follow.Batch)
	// FollowOptions are passed to every follower.
	FollowOptions []follow.Option
	// Hook, if set, keeps derived tables in the same transactions.
	Hook Hook
	// RoleView, if set, lets readers see nodes through roles (§B.11.5).
	RoleView RoleView
}

// Service is a running tree service.
type Service struct {
	opt     Options
	c       *client.Client
	db      *sql.DB
	cps     follow.SQLCheckpoints
	origin  string
	checker *grantcheck.Checker

	wmu sync.Mutex // serialises applies across followers

	mu      sync.RWMutex // guards g, cur, purged
	g       *Graph
	cur     map[string]string
	purged  map[string]bool
	changed chan struct{}

	fmu     sync.Mutex
	runCtx  context.Context
	running map[string]context.CancelFunc
	fwg     sync.WaitGroup
}

// Open opens (creating) the database, reads the core's origin and loads
// the graph.
func Open(ctx context.Context, opt Options) (*Service, error) {
	if opt.Client == nil {
		return nil, errors.New("tree: no client")
	}
	if !client.ValidNSName(opt.Catalog) {
		return nil, fmt.Errorf("tree: invalid catalog namespace %q", opt.Catalog)
	}
	if opt.MinWait == 0 {
		opt.MinWait = 2 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.CheckerTTL == 0 {
		opt.CheckerTTL = 30 * time.Second
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	if opt.Purger == nil {
		opt.Purger = logPurger{opt.Logf}
	}
	origin, err := opt.Client.Origin(ctx)
	if err != nil {
		return nil, fmt.Errorf("tree: reading the core's origin: %w", err)
	}
	dsn := "file:" + opt.DB + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Service{
		opt: opt, c: opt.Client, db: db, cps: follow.SQLCheckpoints{DB: db}, origin: origin,
		checker: grantcheck.New(opt.Client, grantcheck.WithClock(opt.Now), grantcheck.WithTTL(opt.CheckerTTL)),
		cur:     map[string]string{}, purged: map[string]bool{}, changed: make(chan struct{}),
		running: map[string]context.CancelFunc{},
	}
	if err := s.init(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Service) init(ctx context.Context) error {
	if s.opt.Rebuild {
		for _, q := range dropStmts {
			if _, err := s.db.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("tree: rebuild: %w", err)
			}
		}
	}
	if err := s.cps.Init(ctx); err != nil {
		return err
	}
	for _, q := range createStmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("tree: schema: %w", err)
		}
	}
	if s.opt.Hook != nil {
		if err := s.opt.Hook.Init(ctx, s.db); err != nil {
			return err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ns, ns_id FROM checkpoints WHERE origin = ?`, s.origin)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns, id string
		if err := rows.Scan(&ns, &id); err != nil {
			rows.Close()
			return err
		}
		s.cur[ns] = id
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT substr(k, 8) FROM meta WHERE k LIKE 'purged:%'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			rows.Close()
			return err
		}
		s.purged[ns] = true
	}
	rows.Close()
	return s.reload(ctx)
}

// reload rebuilds the graph from the database, fixes any drift in the
// derived rows and lets the hook rebuild. Called with mu held (or before
// the service is shared).
func (s *Service) reload(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	g, err := s.loadGraph(ctx, s.db)
	if err != nil {
		return fmt.Errorf("tree: loading the graph: %w", err)
	}
	changed := g.analyze()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for name := range changed {
		if err := s.persistNode(ctx, tx, g, name); err != nil {
			return err
		}
	}
	if s.opt.Hook != nil {
		if err := s.opt.Hook.Rebuild(ctx, tx, g); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.g = g
	return nil
}

// Close closes the database.
func (s *Service) Close() error { return s.db.Close() }

// Origin is the core's canonical origin.
func (s *Service) Origin() string { return s.origin }

// Catalog is the catalog namespace.
func (s *Service) Catalog() string { return s.opt.Catalog }

// Checker is the grant checker the service verifies readers with.
func (s *Service) Checker() *grantcheck.Checker { return s.checker }

// Client is the core client.
func (s *Service) Client() *client.Client { return s.c }

// DB is the service's database (for hooks' queries).
func (s *Service) DB() *sql.DB { return s.db }

// Checkpoint returns the ns_id the service reflects for ns ("" if none).
func (s *Service) Checkpoint(ns string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur[ns]
}

// View calls fn with the graph and the checkpoints under the read lock;
// fn must not keep references past its return.
func (s *Service) View(fn func(g *Graph, cur map[string]string)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.g, s.cur)
}

func (s *Service) state() (cur string, purged bool, changed <-chan struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur[s.opt.Catalog], s.purged[s.opt.Catalog], s.changed
}

// Run follows the catalog and its trusted namespaces until ctx is done.
// Followers of content namespaces start and stop as catalog.trust changes.
func (s *Service) Run(ctx context.Context) error {
	s.fmu.Lock()
	s.runCtx = ctx
	s.fmu.Unlock()
	s.ensureFollowers()
	<-ctx.Done()
	s.fwg.Wait()
	return ctx.Err()
}

// followed is the set of namespaces that should be followed.
func (s *Service) followed() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{s.opt.Catalog}
	for ns := range s.g.Trust {
		out = append(out, ns)
	}
	sort.Strings(out[1:])
	return out
}

func (s *Service) ensureFollowers() {
	want := map[string]bool{}
	for _, ns := range s.followed() {
		want[ns] = true
	}
	s.fmu.Lock()
	defer s.fmu.Unlock()
	if s.runCtx == nil || s.runCtx.Err() != nil {
		return
	}
	for ns, cancel := range s.running {
		if !want[ns] {
			cancel()
			delete(s.running, ns)
		}
	}
	for ns := range want {
		if _, ok := s.running[ns]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(s.runCtx)
		s.running[ns] = cancel
		s.fwg.Add(1)
		go func() {
			defer s.fwg.Done()
			s.follow(ctx, ns)
		}()
	}
}

func (s *Service) follow(ctx context.Context, ns string) {
	s.mu.RLock()
	purged := s.purged[ns]
	s.mu.RUnlock()
	if purged {
		s.opt.Logf("tree: %s was purged; not following", ns)
		return
	}
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) { s.opt.Logf("tree: %s: %v", n, err) }),
	}
	opts = append(opts, s.opt.FollowOptions...)
	pause := time.Second
	for {
		err := follow.New(s.c, ns, s.cps, s, opts...).Run(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, follow.ErrPurged) {
			s.opt.Logf("tree: %s was purged", ns)
			return
		}
		s.opt.Logf("tree: following %s stopped: %v; restarting in %s", ns, err, pause)
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if pause < 30*time.Second {
			pause *= 2
		}
	}
}

// prep is one coalesced change with its fetched content.
type prep struct {
	name   string
	kind   string // head, tombstone or purge
	head   string
	doc    any
	purged bool
}

// Apply implements follow.Handler. The batch's units are coalesced and
// fetched outside the locks, then applied to the graph, the derived rows,
// the hook's tables and the checkpoint in one transaction (§A.1, §B.11.7).
func (s *Service) Apply(ctx context.Context, b *follow.Batch) error {
	co := b.Coalesce()
	isCat := b.NS == s.opt.Catalog
	var cfg *client.NSDoc
	for _, u := range b.Units {
		if u.Config != nil {
			cfg = u.Config
		}
	}
	var preps []prep
	for _, ch := range co.Changes {
		p := prep{name: ch.Resource, kind: ch.Kind, head: ch.Target, purged: ch.Purged}
		if ch.Kind == "head" && (isCat || s.opt.SelfPlacing) {
			doc, err := follow.FetchDoc(ctx, s.c, b.NS, ch.Resource, ch.Target)
			switch {
			case err == nil:
				p.head, p.doc = doc.ID, doc.Value
			case errors.Is(err, follow.ErrNotLive) || client.IsGone(err) || client.IsNotFound(err):
				// Gone since: a later entry says so too.
				p.kind, p.head = "tombstone", ""
			default:
				return err
			}
		}
		preps = append(preps, p)
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	oldTrust := s.g.Trust
	res, err := s.applyLocked(context.WithoutCancel(ctx), b, co, preps, cfg)
	if err != nil {
		if rerr := s.reload(context.Background()); rerr != nil {
			s.opt.Logf("tree: reloading after a failed apply: %v", rerr)
		}
		s.mu.Unlock()
		return err
	}
	s.cur[b.NS] = b.NewCheckpoint
	if co.PurgedNS {
		s.purged[b.NS] = true
	}
	trustChanged := !sameSet(oldTrust, s.g.Trust)
	s.mu.Unlock()

	if len(res.tags) > 0 {
		s.opt.Purger.PurgeTags(res.tags)
	}
	s.mu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
	if cfg != nil {
		s.checker.Observe(b.NS, b.NewCheckpoint)
	}
	if trustChanged {
		s.ensureFollowers()
	}
	if s.opt.OnApply != nil {
		s.opt.OnApply(b)
	}
	return nil
}

type applyResult struct {
	tags []string
}

func (s *Service) applyLocked(ctx context.Context, b *follow.Batch, co follow.Coalesced, preps []prep, cfg *client.NSDoc) (*applyResult, error) {
	g := s.g
	cat := s.opt.Catalog
	res := &applyResult{}
	changed := map[string]bool{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if b.NS == cat {
		if b.Snapshot || co.PurgedNS {
			for name := range g.explicit {
				g.removeExplicit(name)
				changed[name] = true
			}
		}
		if cfg != nil {
			g.setConfig(cfg.Value)
			if err := saveMeta(ctx, tx, "config", canonJSON(cfg.Value)); err != nil {
				return nil, err
			}
		}
		for _, p := range preps {
			changed[p.name] = true
			if p.kind == "head" && p.doc != nil {
				n := ParseNode(cat, p.name, p.head, p.doc)
				g.setExplicit(n)
				if n.ItemNS != "" {
					// A new placement: its item's state is in the items table.
					st, head, err := itemState(ctx, tx, n.ItemNS, n.ItemName)
					if err != nil {
						return nil, err
					}
					g.setItem(p.name, st, head)
				}
			} else {
				g.removeExplicit(p.name)
			}
		}
	} else {
		ns := b.NS
		if b.Snapshot || co.PurgedNS {
			if b.Snapshot {
				if _, err := tx.ExecContext(ctx, `DELETE FROM items WHERE ns = ?`, ns); err != nil {
					return nil, err
				}
			} else if _, err := tx.ExecContext(ctx, `UPDATE items SET state = ?, head = NULL WHERE ns = ?`, ItemPurged, ns); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM self_parents WHERE ns = ?`, ns); err != nil {
				return nil, err
			}
			st := ItemUnknown
			if co.PurgedNS {
				st = ItemPurged
			}
			for _, m := range []map[string]*Node{g.explicit, g.self} {
				for name, n := range m {
					if n.ItemNS == ns {
						g.setItem(name, st, "")
						changed[name] = true
					}
				}
			}
			for name, n := range g.self {
				if n.ItemNS == ns {
					g.removeSelf(name)
					changed[name] = true
				}
			}
		}
		for _, p := range preps {
			st, head := ItemLive, p.head
			switch p.kind {
			case "tombstone":
				st, head = ItemTombstoned, ""
			case "purge":
				st, head = ItemPurged, ""
			}
			var headCol any
			if head != "" {
				headCol = head
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO items (ns, name, state, head) VALUES (?, ?, ?, ?)
				ON CONFLICT (ns, name) DO UPDATE SET state = excluded.state, head = excluded.head`, ns, p.name, st, headCol); err != nil {
				return nil, err
			}
			pl := ns + "." + p.name
			if g.setItem(pl, st, head) {
				changed[pl] = true
			}
			if !s.opt.SelfPlacing {
				continue
			}
			var sn *Node
			if st == ItemLive && p.doc != nil {
				sn = parseSelf(cat, ns, p.name, p.doc)
			}
			if sn != nil {
				m, _ := p.doc.(map[string]any)
				if _, err := tx.ExecContext(ctx, `INSERT INTO self_parents (ns, name, parents) VALUES (?, ?, ?)
					ON CONFLICT (ns, name) DO UPDATE SET parents = excluded.parents`, ns, p.name, canonJSON(m["$parents"])); err != nil {
					return nil, err
				}
				sn.ItemState, sn.ItemHead = st, head
				g.setSelf(sn)
				changed[pl] = true
			} else if g.self[pl] != nil {
				if _, err := tx.ExecContext(ctx, `DELETE FROM self_parents WHERE ns = ? AND name = ?`, ns, p.name); err != nil {
					return nil, err
				}
				g.removeSelf(pl)
				changed[pl] = true
			}
		}
		if co.PurgedNS {
			if err := saveMeta(ctx, tx, "purged:"+ns, "1"); err != nil {
				return nil, err
			}
		}
	}
	if b.NS == cat && co.PurgedNS {
		if err := saveMeta(ctx, tx, "purged:"+cat, "1"); err != nil {
			return nil, err
		}
	}

	// Cache tags (§B.5). Every change a listing depends on moves the
	// combined checkpoint, so cached listings never go stale and need no
	// purge; purges remove content: a purged resource from every cached
	// listing showing it (r:{ns}/{name}, and rs:{catalog} for listings too
	// large to name all they show), a purged namespace from every cached
	// listing whose checkpoint covers it (ns:{ns}).
	if co.PurgedNS {
		res.tags = append(res.tags, "ns:"+b.NS)
	}
	nr := 0
	for _, p := range preps {
		if p.purged {
			res.tags = append(res.tags, "r:"+b.NS+"/"+p.name)
			nr++
		}
	}
	if nr > 0 || co.PurgedNS {
		res.tags = append(res.tags, ManyTag(cat))
	}

	derived := g.analyze()
	for name := range derived {
		changed[name] = true
	}
	names := make([]string, 0, len(changed))
	for name := range changed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := s.persistNode(ctx, tx, g, name); err != nil {
			return nil, err
		}
	}
	if s.opt.Hook != nil {
		if err := s.opt.Hook.Update(ctx, tx, g, changed); err != nil {
			return nil, err
		}
	}
	for _, u := range b.Units {
		if u.Entry.ID != "" {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, u.Entry.ID); err != nil {
				return nil, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen (ns, ns_id) VALUES (?, ?)`, b.NS, b.NewCheckpoint); err != nil {
		return nil, err
	}
	if err := s.cps.Save(ctx, tx, b.Origin, b.NS, b.NewCheckpoint); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

type logPurger struct{ logf func(string, ...any) }

func (l logPurger) PurgeTags(tags []string) { l.logf("tree: purge cache tags %v", tags) }

// ItemState returns the recorded state and head of a content resource
// (ItemUnknown if the service has never seen it).
func (s *Service) ItemState(ctx context.Context, ns, name string) (int, string, error) {
	return itemState(ctx, s.db, ns, name)
}

// Seen reports whether the service has applied ns_id (of any followed
// namespace).
func (s *Service) Seen(ctx context.Context, nsID string) bool {
	var one int
	return s.db.QueryRowContext(ctx, `SELECT 1 FROM seen WHERE ns_id = ? LIMIT 1`, nsID).Scan(&one) == nil
}
