// Package catalog is the catalog service of §B.11: a tree service
// (internal/tree) that also derives access from the tree and issues grants.
//
//   - $access on folders and placements maps subjects (group:… or user:…)
//     to role names (§B.11.1). A node's effective roles are the union, over
//     every walkable path from it up to a root, of the $access entries met
//     along the path, including its own; a path stops collecting after a
//     node with inherit: false, and ends (contributing nothing) at a
//     missing, tombstoned, purged, non-folder or cyclic parent, and at depth
//     64 (§B.11.2). Implicit placements from $parents (§B.9) never derive
//     access.
//   - The acl and effective tables of §B.11.7 are maintained in the tree
//     service's apply transactions (tree.Hook), so effective always reflects
//     the recorded catalog checkpoint, which is the at of every grant issued
//     from it. Only the subtree below a changed node is recomputed.
//   - Tree powers (move, place) come from the catalog namespace's roles and
//     apply only where a role granting them is assigned directly, unless
//     the folder's $access sets inheritPowers: then the roles collected on
//     the walk up count there too. At a folder without $access but with
//     parents, a subject's role has them where it has them at every
//     parent. They count only at live folders that aren't cyclic, through
//     subjects the catalog's key in the catalog may assert, and callers in
//     the admin group need none (§B.11.2, §B.11.4; powers).
//   - Content namespaces define what a role means (§B.11.1): the catalog
//     keeps only roles the content namespace defines with a wanted verb.
//   - A caller's subjects are its sub, if it starts with user:, and
//     group:{g} for each of its groups (§B.11.2). Roles count only through
//     subjects the catalog's key in the content namespace may grant
//     through: its sub scope must match the caller's sub, and its groups
//     scope allow the group (§B.11.2 Through the key, §B.11.5).
//   - A deleted item's effective rows are frozen when its tombstone is
//     seen, and a restore is decided from them, refused if the item's
//     current placement would widen them (§B.11.4, §B.11.7). A move of a
//     deleted item's placement is checked like any other.
//   - A deleted placement's rows are kept apart from its catalog tombstone
//     until it is placed again or purged, whatever becomes of its item,
//     and a re-place by a non-admin is refused if it would widen them
//     (§B.11.4 Place, §B.11.7). One deleted under v0.55, which dropped
//     its rows, has none kept, so only an admin can re-place it.
//   - Listings and /read-grants share one visibility test (§B.11.5,
//     visibility.Node), decided per request from effective and the
//     content namespaces' documents as of the combined checkpoint
//     (tree.Graph.Content).
//
// Callers of the catalog's own API (POST /grants, POST /read-grants, and
// private listings) authenticate with an ordinary core grant for the
// catalog namespace, verified locally with internal/grantcheck (keys,
// revocations and scopes as of the catalog's head). Its root sub and groups
// are the caller's identity (§B.11.6: groups come from the caller's grant,
// the identity provider's; there is no groups namespace). The grant's verbs
// don't matter for the catalog's API: it is only proof of identity.
//
// Decisions (POST /grants, POST /read-grants, POST /merge-grants) are
// taken at one checkpoint, which answers carry beside the grant, and a
// /read-grants answer once beside all its items, as checkpoint,
// { ns: ns_id }: the ns_ids of the catalog, of each named
// item's namespace there, and of the content namespaces whose roles or
// includes the decision read (§B.11.4, checkpointAt), which are all a
// decision depends on, not the combined checkpoint of listings (§B.5).
// So do refusals that are decisions (403, 404, 409, 410), so a client that
// caches decisions keys them by it; the grants' own at stays the
// catalog's ns_id. A refusal decided from state the checkpoint doesn't
// pin (the core's head of a name the service hasn't seen yet, the signing
// key at the head, a merge batch's stale precondition) carries none
// (decidedAt). What a decision reads is as of that checkpoint, as for
// visibility: the roles, their definitions, the catalog's key, includes
// and place lists (configAt, includesAt), and for /read-grants whether a
// namespace is public and its encryption (exposureAt). POST /grants and POST /read-grants take ?min for the
// catalog or any content namespace it trusts: a decision on an item also
// depends on its content namespace (whether the item exists, where its
// head is), so after creating a document it placed, or restoring one, a
// client passes min for both.
//
// Read grants are ordinary core grants fixed to one resource, which the
// origin accepts as they are and its POST /edge-grants (§C.5) exchanges
// for cookies. Listings have edge grants of the service's own, with
// tree.Options.EdgeGrants: its POST /edge-grants exchanges a caller's
// grants for a cookie bound to its subject set, /{catalog}/g/{gs}, or to
// /{catalog}/g/all for a reader of every namespace as a whole, under a
// key and kid of its own (§B.11.5; package tree, edgegrants.go).
package catalog

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/rules"
	"github.com/middle-management/patchlog/internal/telemetry"
	"github.com/middle-management/patchlog/internal/tree"
)

// Options configure a catalog service.
type Options struct {
	// Tree configures the underlying tree service (Hook and RoleView are
	// set by the catalog).
	Tree tree.Options
	// Key signs issued grants; Kid is its id in the catalog namespace and
	// in every trusted content namespace (§B.11.3).
	Key ed25519.PrivateKey
	Kid string
	// TTL is the lifetime of issued grants (default 15 minutes), capped by
	// the key's maxTtl in the target namespace and by the caller's own
	// grant's expiry.
	TTL time.Duration
	// AdminGroup may move nodes without the no-widening check (default
	// "catalog-admins", §B.11.4).
	AdminGroup string
	// MergeKey signs merge grants (§F.8), and nothing else; MergeKid is
	// its id in the catalog namespace. MergeService is the merge
	// service's sub: merge grants are issued only to it, and name it as
	// their root sub. Without MergeKey, POST /merge-grants is refused.
	MergeKey     ed25519.PrivateKey
	MergeKid     string
	MergeService string
	// MergeTTL is the lifetime of merge grants (default 5 minutes), capped
	// by the merge key's maxTtl and by the callers' grants' expiry.
	MergeTTL time.Duration
}

// Service is a running catalog service.
type Service struct {
	opt Options
	t   *tree.Service
	now func() time.Time

	// Guarded by the tree service's lock (hook calls hold it for writing,
	// View for reading).
	eff   map[string]map[string][]string // node -> subject -> roles (sorted)
	users map[string]bool                // user: subjects with direct $access entries
	// Placements whose item is tombstoned, with the effective roles frozen
	// when the tombstone was seen (§B.11.7): restores are resolved from
	// them (§B.11.4). tomb holds every such name, frozen only those with
	// roles; neither is in eff.
	tomb   map[string]bool
	frozen map[string]map[string][]string
	// Deleted placements with the rows they had when their catalog
	// tombstone was seen (§B.11.7), unless their item's are frozen
	// (tomb): a re-place is checked against them (§B.11.4 Place). An
	// empty map is a placement deleted without rows, which the service
	// saw all the same (unplacedRows). None is in eff.
	unplaced map[string]map[string][]string
	// placed holds the names of explicit placements as of the last
	// refresh, so that unplace knows a name whose node is gone was one.
	placed map[string]bool

	// readRoles per content namespace, with the document they were
	// derived from (readRolesOf).
	rrMu    sync.Mutex
	rrCache map[string]rrEntry

	// afterDecide, if set (tests), runs after each try of POST
	// /read-grants decides its items, before the checkpoint is checked.
	afterDecide atomic.Pointer[func(try int)]
}

// Open opens the catalog service.
func Open(ctx context.Context, opt Options) (*Service, error) {
	if len(opt.Key) != ed25519.PrivateKeySize || opt.Kid == "" {
		return nil, errors.New("catalog: a signing key and its kid are required")
	}
	if opt.TTL == 0 {
		opt.TTL = 15 * time.Minute
	}
	if opt.AdminGroup == "" {
		opt.AdminGroup = "catalog-admins"
	}
	if opt.MergeKey != nil {
		switch {
		case len(opt.MergeKey) != ed25519.PrivateKeySize || opt.MergeKid == "":
			return nil, errors.New("catalog: a merge key needs its kid")
		case opt.MergeKid == opt.Kid:
			return nil, errors.New("catalog: the merge key must be a key of its own, not the catalog's (§F.8)")
		case opt.MergeService == "":
			return nil, errors.New("catalog: a merge key needs the merge service's sub")
		}
	}
	if opt.MergeTTL == 0 {
		opt.MergeTTL = 5 * time.Minute
	}
	s := &Service{opt: opt, eff: map[string]map[string][]string{}, users: map[string]bool{},
		tomb: map[string]bool{}, frozen: map[string]map[string][]string{},
		unplaced: map[string]map[string][]string{}, placed: map[string]bool{}, rrCache: map[string]rrEntry{}}
	s.now = opt.Tree.Now
	if s.now == nil {
		s.now = time.Now
	}
	topt := opt.Tree
	topt.Hook = s
	topt.RoleView = s
	t, err := tree.Open(ctx, topt)
	if err != nil {
		return nil, err
	}
	s.t = t
	return s, nil
}

// Tree is the underlying tree service.
func (s *Service) Tree() *tree.Service { return s.t }

// Run follows the catalog and its trusted namespaces until ctx is done.
func (s *Service) Run(ctx context.Context) error { return s.t.Run(ctx) }

// Close closes the database.
func (s *Service) Close() error { return s.t.Close() }

// Handler serves the tree listings (with /edge-grants, given
// tree.Options.EdgeGrants) plus POST /grants, POST /read-grants and POST
// /merge-grants.
func (s *Service) Handler() http.Handler {
	th := s.t.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/grants", "/read-grants", "/merge-grants":
			telemetry.SetRoute(r, r.URL.Path) // one of three fixed paths
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				tree.WriteError(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
				return
			}
			switch r.URL.Path {
			case "/grants":
				s.serveGrants(w, r)
			case "/read-grants":
				s.serveReadGrants(w, r)
			default:
				s.serveMergeGrants(w, r)
			}
		default:
			th.ServeHTTP(w, r)
		}
	})
}

// --- storage (tree.Hook) ------------------------------------------------------

// Init creates or migrates the tables of §B.11.7 (migrations/), applied
// under the namespace "catalog" (package dbmigrate). The spec's
// nodes(node, inherit) is access_nodes here (the tree service has its own
// nodes table), and effective is kept for every node (folders too, for
// listing visibility), keyed by the node's href. Rows with tombstoned = 1
// are a deleted item's, frozen as they were when its tombstone was seen,
// and rows with tombstoned = 2 a deleted placement's, kept as they were
// when its catalog tombstone was seen (§B.11.7). A row with an empty
// subject and role (keptMarker) records a deletion kept without rows.
func (s *Service) Init(ctx context.Context, db *sql.DB) error {
	if err := dbmigrate.Migrate(ctx, db, migrations, "catalog"); err != nil {
		return fmt.Errorf("catalog: schema: %w", err)
	}
	return nil
}

// migrations holds the catalog's tables in the tree service's database.
//
//go:embed migrations
var migrations embed.FS

// Rebuild recomputes acl and effective from the graph. Frozen rows of
// deleted items, and the rows of deleted placements, can't be derived
// from the graph, so they are kept and read back; a placement whose item
// is tombstoned and has none gets none.
func (s *Service) Rebuild(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	for _, q := range []string{`DELETE FROM access_nodes`, `DELETE FROM acl`, `DELETE FROM effective WHERE tombstoned = 0`} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	s.eff, s.placed = map[string]map[string][]string{}, map[string]bool{}
	if err := s.loadFrozen(ctx, tx, g); err != nil {
		return err
	}
	for _, name := range g.Names() {
		if err := s.writeACL(ctx, tx, g, name, false); err != nil {
			return err
		}
		if err := s.refresh(ctx, tx, g, name, false); err != nil {
			return err
		}
	}
	if err := s.sweepKept(ctx, tx, g); err != nil {
		return err
	}
	s.users = directUsers(g)
	return nil
}

// Update recomputes acl for changed nodes and effective for their subtrees.
// The kept rows of names that aren't nodes are swept apart (sweepKept).
func (s *Service) Update(ctx context.Context, tx *sql.Tx, g *tree.Graph, changed map[string]bool) error {
	var names []string
	for name := range changed {
		names = append(names, name)
		if err := s.writeACL(ctx, tx, g, name, true); err != nil {
			return err
		}
	}
	for name := range g.Descendants(names) {
		if err := s.refresh(ctx, tx, g, name, true); err != nil {
			return err
		}
	}
	if err := s.sweepKept(ctx, tx, g); err != nil {
		return err
	}
	s.users = directUsers(g)
	return nil
}

// refresh brings a node's effective rows up to date (§B.11.7): computed
// from the graph, except for a placement whose item is tombstoned. Its rows
// are frozen when the tombstone is first seen, as they were while the item
// was live, and no longer recomputed, so neither placing the deleted item
// again nor moving folders can change who may restore it (§B.11.4). When
// the item is live again, purged or forgotten, the frozen rows go and its
// rows are computed again. A name without an explicit node (an implicit
// placement's doesn't count, §B.9) is unplace's.
func (s *Service) refresh(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string, clear bool) error {
	n := g.Node(name)
	if n == nil || n.Self {
		return s.unplace(ctx, tx, g, name, clear)
	}
	if n.Kind == tree.KindPlacement {
		s.placed[name] = true
	}
	if _, ok := s.unplaced[name]; ok {
		// Placed again: its deleted placement's rows go (§B.11.7).
		if err := s.replaced(ctx, tx, g, name); err != nil {
			return err
		}
	}
	if n.ItemState == tree.ItemTombstoned {
		if s.tomb[name] {
			return nil
		}
		return s.freeze(ctx, tx, g, name)
	}
	if s.tomb[name] {
		if err := s.unfreeze(ctx, tx, g, name); err != nil {
			return err
		}
	}
	e := Effective(g, name, nil)
	if clear && sameEff(e, s.eff[name]) {
		return nil
	}
	return s.writeEffective(ctx, tx, g, name, e, clear)
}

// unplace brings the rows of a name without an explicit node up to date:
// a node deleted, purged, or never one. A purge drops whatever is kept of
// it (§8.3). A placement deleted while its item is tombstoned keeps the
// item's frozen rows, which become its own once the item isn't tombstoned
// any more (sweepKept). Any other placement's rows, as they were when its
// catalog tombstone was seen, none included, are kept apart until it is
// placed again (refresh) or purged (§B.11.7), for re-places (§B.11.4
// Place); a folder's go.
func (s *Service) unplace(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string, clear bool) error {
	if g.Purged != nil && g.Purged(name) {
		return s.dropKept(ctx, tx, g, name)
	}
	was := s.placed[name]
	delete(s.placed, name)
	if _, ok := s.unplaced[name]; ok || s.tomb[name] {
		return nil
	}
	if was {
		if _, err := tx.ExecContext(ctx, `UPDATE effective SET tombstoned = 2 WHERE node = ? AND tombstoned = 0`, g.Href(name)); err != nil {
			return err
		}
		rows := s.eff[name]
		if len(rows) == 0 {
			rows = map[string][]string{}
			if err := keptMarker(ctx, tx, g.Href(name), 2); err != nil {
				return err
			}
		}
		s.unplaced[name] = rows
		delete(s.eff, name)
		return nil
	}
	return s.writeEffective(ctx, tx, g, name, nil, clear)
}

// dropKept drops every row of a purged name, kept ones included (§8.3).
func (s *Service) dropKept(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM effective WHERE node = ?`, g.Href(name)); err != nil {
		return err
	}
	delete(s.eff, name)
	delete(s.frozen, name)
	delete(s.tomb, name)
	delete(s.unplaced, name)
	delete(s.placed, name)
	return nil
}

// keptMarker records that a name's kept rows (tombstoned = kind) are
// none, with a row of no subject, so that a restart (loadFrozen) still
// knows the service saw the deletion (unplacedRows). No subject is
// empty, so the row never counts as a role.
func keptMarker(ctx context.Context, tx *sql.Tx, href string, kind int) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO effective (node, subject, role, tombstoned) VALUES (?, '', '', ?) ON CONFLICT DO NOTHING`, href, kind)
	return err
}

// replaced drops a deleted placement's rows once it is placed again.
func (s *Service) replaced(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM effective WHERE node = ? AND tombstoned = 2`, g.Href(name)); err != nil {
		return err
	}
	delete(s.unplaced, name)
	return nil
}

// unplacedRows is what a re-place of a deleted placement is compared
// with (§B.11.4 Place, §B.11.7): the rows it had when its catalog
// tombstone was seen, or, if its item was tombstoned then, the item's
// frozen rows; either may be none. seen is false if the service holds
// neither: it never saw the placement deleted, or lost its rows (a
// rebuild from scratch, or a deletion from before it kept them); none
// counts.
func (s *Service) unplacedRows(name string) (rows map[string][]string, seen bool) {
	if rows, ok := s.unplaced[name]; ok {
		return rows, true
	}
	if s.tomb[name] {
		return s.frozen[name], true
	}
	return nil, false
}

// freeze marks a node's effective rows as a deleted item's (§B.11.7).
func (s *Service) freeze(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE effective SET tombstoned = 1 WHERE node = ?`, g.Href(name)); err != nil {
		return err
	}
	if e := s.eff[name]; len(e) > 0 {
		s.frozen[name] = e
	} else if err := keptMarker(ctx, tx, g.Href(name), 1); err != nil {
		return err
	}
	delete(s.eff, name)
	s.tomb[name] = true
	return nil
}

// unfreeze drops a node's frozen rows.
func (s *Service) unfreeze(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM effective WHERE node = ? AND tombstoned = 1`, g.Href(name)); err != nil {
		return err
	}
	delete(s.frozen, name)
	delete(s.tomb, name)
	return nil
}

// sweepKept brings the kept rows of names without an explicit node up to
// date, which refresh doesn't see: an apply's changed names are nodes.
// A purge of the catalog drops them all (§8.3). The frozen rows of a
// deleted item whose placement was deleted are its placement's rows too
// (unplace): once the item isn't tombstoned any more (restored outside
// the catalog, purged or forgotten), they stay as the deleted
// placement's, kept until it is placed again (§B.11.7), and a later
// deletion of the item freezes afresh, never reusing them.
func (s *Service) sweepKept(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	gone := func(name string) bool { n := g.Node(name); return n == nil || n.Self }
	purged := func(name string) bool { return g.Purged != nil && g.Purged(name) }
	for name := range s.tomb {
		if !gone(name) {
			continue
		}
		if purged(name) {
			if err := s.dropKept(ctx, tx, g, name); err != nil {
				return err
			}
			continue
		}
		st := tree.ItemUnknown
		if ns, item, ok := tree.SplitPlacement(name); ok {
			var err error
			if st, _, err = tree.ReadItemState(ctx, tx, ns, item); err != nil {
				return err
			}
		}
		if st != tree.ItemTombstoned {
			if err := s.thaw(ctx, tx, g, name); err != nil {
				return err
			}
		}
	}
	if g.Purged == nil {
		return nil
	}
	for name := range s.unplaced {
		if gone(name) && purged(name) {
			if err := s.dropKept(ctx, tx, g, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// thaw makes a deleted placement's frozen rows its own (tombstoned = 2)
// once its item isn't tombstoned any more (sweepKept).
func (s *Service) thaw(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string) error {
	href := g.Href(name)
	if _, err := tx.ExecContext(ctx, `UPDATE effective SET tombstoned = 2 WHERE node = ? AND tombstoned = 1`, href); err != nil {
		return err
	}
	rows := s.frozen[name]
	if len(rows) == 0 {
		rows = map[string][]string{}
		if err := keptMarker(ctx, tx, href, 2); err != nil {
			return err
		}
	}
	s.unplaced[name] = rows
	delete(s.frozen, name)
	delete(s.tomb, name)
	return nil
}

// loadFrozen reads the frozen rows, and the deleted placements' rows,
// back (Rebuild).
func (s *Service) loadFrozen(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	s.tomb, s.frozen, s.unplaced = map[string]bool{}, map[string]map[string][]string{}, map[string]map[string][]string{}
	rows, err := tx.QueryContext(ctx, `SELECT node, subject, role, tombstoned FROM effective WHERE tombstoned IN (1, 2) ORDER BY node, subject, role`)
	if err != nil {
		return err
	}
	defer rows.Close()
	prefix := g.Href("")
	for rows.Next() {
		var href, subj, role string
		var kind int
		if err := rows.Scan(&href, &subj, &role, &kind); err != nil {
			return err
		}
		name, ok := strings.CutPrefix(href, prefix)
		if !ok {
			continue
		}
		kept := s.unplaced
		if kind == 1 {
			kept = s.frozen
			s.tomb[name] = true
			if subj == "" {
				continue // keptMarker: frozen holds only names with roles
			}
		}
		m := kept[name]
		if m == nil {
			m = map[string][]string{}
			kept[name] = m
		}
		if subj != "" {
			m[subj] = append(m[subj], role)
		}
	}
	return rows.Err()
}

func (s *Service) writeACL(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string, clear bool) error {
	href := g.Href(name)
	if clear {
		for _, q := range []string{`DELETE FROM access_nodes WHERE node = ?`, `DELETE FROM acl WHERE node = ?`} {
			if _, err := tx.ExecContext(ctx, q, href); err != nil {
				return err
			}
		}
	}
	n := g.Node(name)
	if n == nil || n.Self {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_nodes (node, inherit) VALUES (?, ?)`, href, b2i(n.Inherit)); err != nil {
		return err
	}
	for subj, roles := range n.Access {
		for _, r := range roles {
			if _, err := tx.ExecContext(ctx, `INSERT INTO acl (node, subject, role) VALUES (?, ?, ?)`, href, subj, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) writeEffective(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string, e map[string][]string, clear bool) error {
	href := g.Href(name)
	if clear {
		if _, err := tx.ExecContext(ctx, `DELETE FROM effective WHERE node = ? AND tombstoned = 0`, href); err != nil {
			return err
		}
	}
	if len(e) == 0 {
		delete(s.eff, name)
		return nil
	}
	s.eff[name] = e
	for subj, roles := range e {
		for _, r := range roles {
			if _, err := tx.ExecContext(ctx, `INSERT INTO effective (node, subject, role) VALUES (?, ?, ?)`, href, subj, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func directUsers(g *tree.Graph) map[string]bool {
	out := map[string]bool{}
	for _, name := range g.Names() {
		n := g.Node(name)
		if n.Self {
			continue
		}
		for subj := range n.Access {
			if strings.HasPrefix(subj, "user:") {
				out[subj] = true
			}
		}
	}
	return out
}

func sameEff(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, x := range a {
		y, ok := b[k]
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
	}
	return true
}

// Effective computes a node's effective roles per subject (§B.11.2).
// override replaces the walkable parents of named nodes (to simulate a
// move). Implicit placements and cyclic nodes get nothing.
func Effective(g *tree.Graph, name string, override map[string][]string) map[string][]string {
	start := g.Node(name)
	if start == nil || start.Self || start.Cyclic {
		return nil
	}
	type item struct {
		n *tree.Node
		d int
	}
	acc := map[string]map[string]bool{}
	visited := map[string]bool{name: true}
	queue := []item{{start, 0}}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		for subj, roles := range it.n.Access {
			m := acc[subj]
			if m == nil {
				m = map[string]bool{}
				acc[subj] = m
			}
			for _, r := range roles {
				m[r] = true
			}
		}
		if !it.n.Inherit || it.d >= tree.MaxDepth {
			continue
		}
		ps, ok := override[it.n.Name]
		if !ok {
			ps = g.WalkableParents(it.n)
		}
		for _, p := range ps {
			if visited[p] {
				continue
			}
			pn := g.Node(p)
			if pn == nil || pn.Kind != tree.KindFolder || pn.Cyclic {
				continue
			}
			visited[p] = true
			queue = append(queue, item{pn, it.d + 1})
		}
	}
	if len(acc) == 0 {
		return nil
	}
	out := map[string][]string{}
	for subj, m := range acc {
		for r := range m {
			out[subj] = append(out[subj], r)
		}
		sort.Strings(out[subj])
	}
	return out
}

// --- subjects and visibility (tree.RoleView) --------------------------------

// userPrefix marks user subjects (§B.11.1).
const userPrefix = "user:"

// UserSubject is the subject a grant's root sub gives (§B.11.2): the sub
// itself if it starts with "user:", otherwise none (""). A bare sub, or
// one of another kind ("group:…", "svc:…"), is no subject, so no $access
// entry is collected through it.
func UserSubject(sub string) string {
	if strings.HasPrefix(sub, userPrefix) {
		return sub
	}
	return ""
}

// groupSubjects is group:{g} for each of a grant's root groups (§B.11.2),
// sorted. A group written with the "group:" prefix gets it again: its
// subject is never that of the unprefixed group, whose $access entries,
// key scope (groups deny lists name groups unprefixed) and admin
// membership it would otherwise take.
func groupSubjects(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if subj := grantcheck.GroupPrefix + g; !contains(out, subj) {
			out = append(out, subj)
		}
	}
	sort.Strings(out)
	return out
}

// Subjects is a caller's subject set (§B.11.2): its root sub if it starts
// with "user:", plus group:{g} for each group of its grant's root block.
func Subjects(v *grant.Verified) map[string]bool {
	out := map[string]bool{}
	if u := UserSubject(v.Principal.ID); u != "" {
		out[u] = true
	}
	for _, g := range groupSubjects(v.Principal.Groups) {
		out[g] = true
	}
	return out
}

// who is a caller as the catalog's keys see it (§B.11.2 Through the key):
// its subject set, and the sub a key's sub scope is matched against. For
// POST /grants that is the grant's root sub, which the signed grant
// carries; for a listing it is the subject set's user: subject, and a set
// without one (hasSub false) fails every sub scope (§B.11.5).
type who struct {
	subs   map[string]bool
	sub    string
	hasSub bool
}

// callerOf is the caller of a verified grant.
func callerOf(v *grant.Verified) who {
	return who{subs: Subjects(v), sub: v.Principal.ID, hasSub: true}
}

// whoOf is a subject set's caller (§B.11.5), and the groups among its
// subjects, as the grant had them (for /principal/groups).
func whoOf(subjects []string) (who, []string) {
	w := who{subs: map[string]bool{}}
	var groups []string
	for _, subj := range subjects {
		w.subs[subj] = true
		if g, ok := strings.CutPrefix(subj, grantcheck.GroupPrefix); ok {
			groups = append(groups, g)
		} else if strings.HasPrefix(subj, userPrefix) {
			w.sub, w.hasSub = subj, true
		}
	}
	return w, groups
}

// through is the subjects of w through which key may grant (§B.11.2
// Through the key, §B.11.3): none if the key has a sub scope that w's sub
// doesn't match; otherwise w's user subject, and each group subject whose
// group the key's groups scope lets it assert. Roles count only when
// collected through them, for grants, visibility and tree powers alike.
func (w who) through(key *grant.Key) map[string]bool {
	out := map[string]bool{}
	if key == nil || key.SubPattern != nil && (!w.hasSub || !key.SubPattern.MatchString(w.sub)) {
		return out
	}
	for subj, ok := range w.subs {
		if !ok {
			continue
		}
		if g, isGroup := strings.CutPrefix(subj, grantcheck.GroupPrefix); isGroup {
			if allowed, _ := key.Groups.Permits([]string{g}); !allowed {
				continue
			}
		}
		out[subj] = true
	}
	return out
}

// rolesFor is the union of a node's roles over subjects.
func (s *Service) rolesFor(name string, subs map[string]bool) map[string]bool {
	out := map[string]bool{}
	for subj, roles := range s.eff[name] {
		if subs[subj] {
			for _, r := range roles {
				out[r] = true
			}
		}
	}
	return out
}

// frozenRolesFor is the union over subjects of the roles a deleted item's
// placement had when its tombstone was seen (§B.11.7).
func (s *Service) frozenRolesFor(name string, subs map[string]bool) map[string]bool {
	out := map[string]bool{}
	for subj, roles := range s.frozen[name] {
		if subs[subj] {
			for _, r := range roles {
				out[r] = true
			}
		}
	}
	return out
}

// Resolve implements tree.RoleView: listings are keyed by the caller's
// group subjects, plus its user subject only if the catalog has direct
// entries for that user, or its key in a content namespace it trusts has
// a sub scope (§B.11.5), and filtered by the visibility test of that
// subject set alone (ForSubjects), since every reader with it shares the
// listing.
//
// What a role means, and the catalog's key, are read from the trusted
// content namespaces' documents as of the content namespaces' ns_ids in
// the combined checkpoint (tree.Graph.Content, replaced in the same apply
// as the checkpoint), never from the grant checker's latest copy, so a
// listing at a given at never changes when a /roles change lands later
// (§B.11.5, §B.11.7). There is nothing to recompute: visibility is decided
// per request from effective and those documents.
func (s *Service) Resolve(ctx context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	var keyed []string
	s.t.View(func(g *tree.Graph, _ map[string]string) { keyed = s.keyedAt(g, v) })
	return keyed, s.ForSubjects(keyed), nil
}

// keyedAt is the subject set Resolve keys v's listings by, as of the
// checkpoint g reflects. Call it under View.
func (s *Service) keyedAt(g *tree.Graph, v *grant.Verified) []string {
	keyed := groupSubjects(v.Principal.Groups)
	if user := UserSubject(v.Principal.ID); user != "" && (s.users[user] || s.subScoped(g)) {
		keyed = append(keyed, user)
		sort.Strings(keyed)
	}
	return keyed
}

// subScoped reports whether the catalog's key has a sub scope in some
// content namespace the catalog trusts, as of the checkpoint g reflects:
// then a reader's sub decides what it sees, and is part of its subject
// set (§B.11.2, §B.11.5). Call it under View.
func (s *Service) subScoped(g *tree.Graph) bool {
	for ns := range g.Trust {
		if c := g.Content[ns]; c != nil {
			if cfg := s.parsed(c).cfg; cfg != nil {
				if k := findKey(cfg.Keys, s.opt.Kid); k != nil && k.SubPattern != nil {
					return true
				}
			}
		}
	}
	return false
}

// ForSubjects implements tree.RoleView for a reader whose edge grant is
// bound to a subject set (§B.11.5): the subjects Resolve keyed it by, the
// groups among them as /principal/groups, and its user: subject, if any,
// as the sub key scopes are matched against, which is all visibility
// reads of a caller. A user subject is among them only if the catalog had
// direct entries for that user, or a sub-scoped key, when the edge grant
// was minted; one it has come to have since doesn't count until the
// reader exchanges again, as for every listing cached for the subject
// set, and meanwhile a sub-scoped key grants the set nothing.
func (s *Service) ForSubjects(subjects []string) tree.Visibility {
	w, groups := whoOf(subjects)
	return &visibility{s: s, who: w, groups: groups}
}

// readRoles are the roles through which the catalog's key may grant read
// in one trusted content namespace (§B.11.2, §B.11.5): roles the
// namespace defines with read, within the key's roles scope, for a key
// that may grant read and whose scope rules can count.
type readRoles struct {
	// key is nil if the namespace doesn't list the catalog's key, the key
	// can't grant read, or one of its scope rules never counts.
	key *grant.Key
	// keyRules are the key's scope rules, evaluated with each role's;
	// keyFolders reports whether they refer only to /principal/groups and
	// /principal/roles, so that roles count through the key for folders
	// too (§B.11.5).
	keyRules   []*rules.Rule
	keyFolders bool
	roles      map[string]*readRole
}

// readRole is one such role, whose rules are evaluated as a read would
// evaluate them (§B.11.5). A role with a rule that refers to /now, or to
// anything in /principal but /principal/groups and /principal/roles,
// never counts and isn't listed: everyone with the same subject set
// shares a listing, and a listing at a given at can't change.
type readRole struct {
	rules []*rules.Rule
	// resource: a rule refers to /resource, so the role counts for items
	// only (§B.11.5).
	resource bool
}

var (
	ptrNow       = pointer.Pointer{"now"}
	ptrResource  = pointer.Pointer{"resource"}
	ptrPrincipal = pointer.Pointer{"principal"}
	ptrGroups    = pointer.Pointer{"principal", "groups"}
	ptrRoles     = pointer.Pointer{"principal", "roles"}
)

// rrEntry is a content namespace's document as of the checkpoint, parsed
// (cfg, nil if malformed), with the readRoles derived from it.
type rrEntry struct {
	doc *tree.NSConfig
	cfg *grantcheck.Config
	rr  *readRoles
}

// parsed is a content namespace's document as of the checkpoint
// (Graph.Content), parsed, cached by the document's identity: a new
// document is a new *tree.NSConfig. Callers must not change what it
// returns.
func (s *Service) parsed(c *tree.NSConfig) rrEntry {
	s.rrMu.Lock()
	e, ok := s.rrCache[c.NS]
	s.rrMu.Unlock()
	if ok && e.doc == c {
		return e
	}
	e = rrEntry{doc: c, rr: &readRoles{roles: map[string]*readRole{}}}
	if cfg, err := grantcheck.ParseConfig(c.NS, "", c.Doc); err == nil {
		e.cfg, e.rr = cfg, s.readRoles(cfg)
	}
	s.rrMu.Lock()
	s.rrCache[c.NS] = e
	s.rrMu.Unlock()
	return e
}

// readRolesOf is the readRoles of a content namespace's document as of
// the checkpoint (Graph.Content).
func (s *Service) readRolesOf(c *tree.NSConfig) *readRoles { return s.parsed(c).rr }

// configAt is ns's document as of the checkpoint g reflects, so a
// decision reflects the checkpoint it reports, as visibility does
// (§B.11.4, §B.11.5): Graph.Content for a content namespace, Graph.Config
// for the catalog. latest, the grant checker's copy at the head, stands in
// where the graph has no valid document, and gives a branch its keys,
// which follow its base (§C.4). Call it under View; don't change what it
// returns.
func (s *Service) configAt(g *tree.Graph, ns string, latest *grantcheck.Config) *grantcheck.Config {
	var cfg *grantcheck.Config
	switch {
	case ns == g.Catalog && g.Config != nil:
		cfg, _ = grantcheck.ParseConfig(ns, "", g.Config)
	case ns != g.Catalog && g.Content[ns] != nil:
		cfg = s.parsed(g.Content[ns]).cfg
	}
	if cfg == nil {
		return latest
	}
	if cfg.Base != "" {
		c := *cfg
		c.Keys = latest.Keys
		cfg = &c
	}
	return cfg
}

func (s *Service) readRoles(cfg *grantcheck.Config) *readRoles {
	out := &readRoles{roles: map[string]*readRole{}}
	key := findKey(cfg.Keys, s.opt.Kid)
	if key == nil || !key.IsStar() && !contains(key.Can, "read") {
		return out
	}
	kr, ok := listableRules(key.Rules)
	if !ok {
		return out
	}
	out.key, out.keyRules, out.keyFolders = key, kr, onlyRoleRefs(kr)
	for r, def := range cfg.Roles {
		if !contains(def.Can, "read") || !roleAllowed(key, r) {
			continue
		}
		if rs, ok := listableRules(def.Rules); ok {
			out.roles[r] = &readRole{rules: rs, resource: refers(rs, ptrResource)}
		}
	}
	return out
}

// listableRules compiles rules that can count for a listing (§B.11.5):
// none may read /now, or anything in /principal but /principal/groups and
// /principal/roles (a pointer above them, such as the whole envelope,
// reads them too). ok is false if one can't, or doesn't compile.
func listableRules(src []any) (_ []*rules.Rule, ok bool) {
	var out []*rules.Rule
	for _, x := range src {
		c, err := rules.Compile(x)
		if err != nil {
			return nil, false
		}
		for _, p := range c.RefPaths() {
			if p.Overlaps(ptrNow) || p.Overlaps(ptrPrincipal) && !p.HasPrefix(ptrGroups) && !p.HasPrefix(ptrRoles) {
				return nil, false
			}
		}
		out = append(out, c)
	}
	return out, true
}

// refers reports whether a rule of rs reads at or below p, or above it.
func refers(rs []*rules.Rule, p pointer.Pointer) bool {
	for _, r := range rs {
		for _, q := range r.RefPaths() {
			if q.Overlaps(p) {
				return true
			}
		}
	}
	return false
}

// onlyRoleRefs reports whether rs refer only to /principal/groups and
// /principal/roles (§B.11.5: a key through which roles count for
// folders).
func onlyRoleRefs(rs []*rules.Rule) bool {
	for _, r := range rs {
		for _, q := range r.RefPaths() {
			if !q.HasPrefix(ptrGroups) && !q.HasPrefix(ptrRoles) {
				return false
			}
		}
	}
	return true
}

// visibility is a subject set's view of the catalog (§B.11.5).
type visibility struct {
	s      *Service
	who    who
	groups []string // the groups among the subjects, as the grant has them (for /principal/groups)

	// folder caches, per namespace's readRoles, whether a role counts for
	// folders: that depends on the subject set and the role alone.
	mu     sync.Mutex
	folder map[*readRoles]map[string]bool
}

// roles is the readRoles of a trusted content namespace as of the
// checkpoint g reflects (nil if it isn't trusted or not followed yet).
func (v *visibility) roles(g *tree.Graph, ns string) *readRoles {
	c := g.Content[ns]
	if !g.Trust[ns] || c == nil {
		return nil
	}
	return v.s.readRolesOf(c)
}

// Node is the visibility test of §B.11.5, the one test listings and
// /read-grants (for catalog nodes and their keys) use. A node is visible
// when the walk up from it (effective) collects, through a subject the
// catalog's key may grant through (who.through: its sub and groups
// scopes), a role that counts for read: one its content namespace defines
// with read, within the key's roles scope, whose own rules and the key's
// scope rules pass as a read would evaluate them, with /principal holding
// only the groups the key may assert and, as roles, that role. For an
// item, that is a role of its own content namespace, with /resource its
// name. For a folder, it is a role of some trusted content namespace whose
// rules don't refer to /resource, through a key whose scope rules refer
// only to /principal/groups and /principal/roles. Roles, their
// definitions and keys are those as of the combined checkpoint. Only live
// nodes are visible: a dangling placement, a deleted item's included,
// grants nothing, and cyclic and implicit nodes collect nothing (§B.11.2).
func (v *visibility) Node(g *tree.Graph, n *tree.Node) bool {
	if n == nil || n.Self || !n.Live() {
		return false
	}
	eff := v.s.eff[n.Name]
	if n.Kind == tree.KindFolder {
		for ns := range g.Trust {
			if v.counts(v.roles(g, ns), eff, "", false) {
				return true
			}
		}
		return false
	}
	return v.counts(v.roles(g, n.ItemNS), eff, n.ItemName, true)
}

// Organising is Node as organising requests judge a node (§B.11.4,
// §B.11.5): a dangling placement is judged as if its item were live,
// from the roles at it computed from the graph as a live item's are
// (Effective; a deleted item's frozen rows aren't its roles at the node),
// through its item's content namespace, which must still be trusted. A
// cyclic or implicit node stays hidden: it collects nothing (§B.5
// Cycles, §B.9).
func (v *visibility) Organising(g *tree.Graph, n *tree.Node) bool {
	switch {
	case n == nil || n.Self || n.Cyclic:
		return false
	case n.Kind == tree.KindFolder || n.Live():
		return v.Node(g, n)
	}
	return v.counts(v.roles(g, n.ItemNS), Effective(g, n.Name, nil), n.ItemName, true)
}

// counts reports whether a role of eff (a node's roles per subject)
// counts for read through rr's key (Node): for an item, named resource;
// otherwise for a folder.
func (v *visibility) counts(rr *readRoles, eff map[string][]string, resource string, item bool) bool {
	if rr == nil || rr.key == nil || !item && !rr.keyFolders {
		return false
	}
	subs := v.who.through(rr.key)
	if len(subs) == 0 {
		return false
	}
	// The read envelope as the gate would build it for a grant the catalog
	// signs carrying that role (§6.4.1, mint): action read, the resource
	// for an item, and a principal holding the caller's groups the key may
	// assert and the role. No writes, doc or patches, so within is true
	// and covers and overlaps are false (§6.4.2); no now, since rules
	// reading it never count.
	var groups []any
	for _, gr := range v.groups {
		if ok, _ := rr.key.Groups.Permits([]string{gr}); ok {
			groups = append(groups, gr)
		}
	}
	for subj, roles := range eff {
		if !subs[subj] {
			continue
		}
		for _, r := range roles {
			def := rr.roles[r]
			switch {
			case def == nil, !item && def.resource:
			case len(def.rules) == 0 && len(rr.keyRules) == 0:
				return true
			case item:
				if passes(rr, def, r, resource, groups) {
					return true
				}
			case v.folderRole(rr, def, r, groups):
				return true
			}
		}
	}
	return false
}

// folderRole is passes for a folder, cached per subject set.
func (v *visibility) folderRole(rr *readRoles, def *readRole, r string, groups []any) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	m := v.folder[rr]
	if m == nil {
		if v.folder == nil {
			v.folder = map[*readRoles]map[string]bool{}
		}
		m = map[string]bool{}
		v.folder[rr] = m
	}
	ok, done := m[r]
	if !done {
		ok = passes(rr, def, r, "", groups)
		m[r] = ok
	}
	return ok
}

// passes evaluates role r's rules and the key's scope rules against the
// read envelope (counts), with /resource resource unless it is "".
func passes(rr *readRoles, def *readRole, r, resource string, groups []any) bool {
	env := map[string]any{"action": "read", "principal": map[string]any{"groups": nonNilAny(groups), "roles": []any{r}}}
	if resource != "" {
		env["resource"] = resource
	}
	if _, _, ok := rules.EvalList(rr.keyRules, env); !ok {
		return false
	}
	_, _, ok := rules.EvalList(def.rules, env)
	return ok
}

// Item: a visible placement's item is visible too, since visibility is
// decided by read (§B.11.5).
func (v *visibility) Item(g *tree.Graph, n *tree.Node) bool { return v.Node(g, n) }

func nonNilAny(xs []any) []any {
	if xs == nil {
		return []any{}
	}
	return xs
}

func findKey(ks []grant.Key, kid string) *grant.Key {
	for i := range ks {
		if ks[i].Kid == kid {
			return &ks[i]
		}
	}
	return nil
}

func roleAllowed(k *grant.Key, r string) bool {
	if k.Roles == nil {
		return true
	}
	ok, _ := k.Roles.Permits([]string{r})
	return ok
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
