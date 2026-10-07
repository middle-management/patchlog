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
//     the walk up count there too (§B.11.2).
//   - Content namespaces define what a role means (§B.11.1): the catalog
//     keeps only roles the content namespace defines with a wanted verb.
//   - Effective roles count only through subjects the catalog's key in the
//     content namespace may assert (§B.11.4 Resolve, §B.11.5).
//   - A deleted item's effective rows are frozen when its tombstone is
//     seen, and a restore is decided from them, refused if the item's
//     current placement would widen them (§B.11.4, §B.11.7). A move of a
//     deleted item's placement is checked like any other.
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
// There are no CDN edge grants in this implementation: read grants are
// ordinary core grants fixed to one resource, which the origin accepts as
// they are and POST /edge-grants (§C.5) exchanges for cookies.
package catalog

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

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

	// readRoles per content namespace, with the document they were
	// derived from (readRolesOf).
	rrMu    sync.Mutex
	rrCache map[string]rrEntry
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
		tomb: map[string]bool{}, frozen: map[string]map[string][]string{}, rrCache: map[string]rrEntry{}}
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

// Handler serves the tree listings plus POST /grants and POST /read-grants.
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

// Init creates the tables of §B.11.7. The spec's nodes(node, inherit) is
// access_nodes here (the tree service has its own nodes table), and
// effective is kept for every node (folders too, for listing visibility),
// keyed by the node's href. Rows with tombstoned = 1 are a deleted item's,
// frozen as they were when its tombstone was seen (§B.11.7).
func (s *Service) Init(ctx context.Context, db *sql.DB) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS access_nodes (node TEXT PRIMARY KEY, inherit INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE IF NOT EXISTS acl (node TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (node, subject, role)) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS effective (node TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL,
			tombstoned INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (node, subject, role)) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS effective_by_subject ON effective (subject, node)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("catalog: schema: %w", err)
		}
	}
	// A database from before tombstoned rows: the rows of placements whose
	// item is tombstoned become its frozen rows.
	var has int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('effective') WHERE name = 'tombstoned'`).Scan(&has); err != nil {
		return fmt.Errorf("catalog: schema: %w", err)
	}
	if has == 0 {
		for _, q := range []string{
			`ALTER TABLE effective ADD COLUMN tombstoned INTEGER NOT NULL DEFAULT 0`,
			fmt.Sprintf(`UPDATE effective SET tombstoned = 1 WHERE node IN (SELECT href FROM nodes WHERE item_state = %d)`, tree.ItemTombstoned),
		} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("catalog: schema: %w", err)
			}
		}
	}
	return nil
}

// Rebuild recomputes acl and effective from the graph. Frozen rows of
// deleted items can't be derived from the graph, so they are kept and
// read back; a placement whose item is tombstoned and has none gets none.
func (s *Service) Rebuild(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	for _, q := range []string{`DELETE FROM access_nodes`, `DELETE FROM acl`, `DELETE FROM effective WHERE tombstoned = 0`} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	s.eff = map[string]map[string][]string{}
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
	if err := s.sweepFrozen(ctx, tx, g); err != nil {
		return err
	}
	s.users = directUsers(g)
	return nil
}

// Update recomputes acl for changed nodes and effective for their subtrees.
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
	if err := s.sweepFrozen(ctx, tx, g); err != nil {
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
// rows are computed again.
func (s *Service) refresh(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string, clear bool) error {
	n := g.Node(name)
	if n != nil && !n.Self && n.ItemState == tree.ItemTombstoned {
		if s.tomb[name] {
			return nil
		}
		return s.freeze(ctx, tx, g, name)
	}
	if s.tomb[name] {
		if n == nil {
			return nil // unplaced while deleted: kept while the item stays tombstoned (sweepFrozen)
		}
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

// freeze marks a node's effective rows as a deleted item's (§B.11.7).
func (s *Service) freeze(ctx context.Context, tx *sql.Tx, g *tree.Graph, name string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE effective SET tombstoned = 1 WHERE node = ?`, g.Href(name)); err != nil {
		return err
	}
	if e := s.eff[name]; len(e) > 0 {
		s.frozen[name] = e
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

// sweepFrozen drops the frozen rows of deleted items that are no longer
// placed (refresh doesn't see them) once the item isn't tombstoned any
// more: restored outside the catalog, or purged. A later deletion then
// freezes afresh, never reusing rows of an earlier one.
func (s *Service) sweepFrozen(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	for name := range s.tomb {
		if g.Node(name) != nil {
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
			if err := s.unfreeze(ctx, tx, g, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadFrozen reads the frozen rows back (Rebuild).
func (s *Service) loadFrozen(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	s.tomb, s.frozen = map[string]bool{}, map[string]map[string][]string{}
	rows, err := tx.QueryContext(ctx, `SELECT node, subject, role FROM effective WHERE tombstoned = 1 ORDER BY node, subject, role`)
	if err != nil {
		return err
	}
	defer rows.Close()
	prefix := g.Href("")
	for rows.Next() {
		var href, subj, role string
		if err := rows.Scan(&href, &subj, &role); err != nil {
			return err
		}
		name, ok := strings.CutPrefix(href, prefix)
		if !ok {
			continue
		}
		s.tomb[name] = true
		m := s.frozen[name]
		if m == nil {
			m = map[string][]string{}
			s.frozen[name] = m
		}
		m[subj] = append(m[subj], role)
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

// UserSubject is the subject for a grant's root sub: "user:{sub}", or the
// sub itself if it already has a "kind:" prefix (grants carry ids such as
// "user:anna").
func UserSubject(sub string) string {
	if strings.Contains(sub, ":") {
		return sub
	}
	return "user:" + sub
}

// Subjects is a caller's subject set (§B.11.2): its user subject plus
// group:{g} for each group of its grant's root block.
func Subjects(v *grant.Verified) map[string]bool {
	out := map[string]bool{UserSubject(v.Principal.ID): true}
	for _, g := range grantcheck.SubjectSet(v, false) {
		out[g] = true
	}
	return out
}

// rolesFor is the union of a node's effective roles over subjects.
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
// entries for that user (§B.11.5), and filtered by the visibility test.
//
// What a role means, and the catalog's key, are read from the trusted
// content namespaces' documents as of the content namespaces' ns_ids in
// the combined checkpoint (tree.Graph.Content, replaced in the same apply
// as the checkpoint), never from the grant checker's latest copy, so a
// listing at a given at never changes when a /roles change lands later
// (§B.11.5, §B.11.7). There is nothing to recompute: visibility is decided
// per request from effective and those documents.
func (s *Service) Resolve(ctx context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	user := UserSubject(v.Principal.ID)
	direct := false
	s.t.View(func(g *tree.Graph, _ map[string]string) { direct = s.users[user] })
	keyed := grantcheck.SubjectSet(v, false)
	if direct {
		keyed = append(keyed, user)
	}
	return keyed, &visibility{s: s, subs: Subjects(v), groups: v.Principal.Groups}, nil
}

// readRoles are the roles through which the catalog's key may grant read
// in one trusted content namespace (§B.11.5): roles the namespace defines
// with read, within the key's roles scope, for a key that may grant read.
type readRoles struct {
	key   *grant.Key // nil: the namespace doesn't list the key, or the key can't grant read
	roles map[string]*readRole
}

// readRole is one such role. A role whose read has rules counts, for
// items only, if they pass as a read of the item would evaluate them, and
// refer neither to /now nor to anything in /principal but
// /principal/groups: everyone with the same subject set shares a listing,
// and a listing at a given at can't change (§B.11.5).
type readRole struct {
	plain bool          // read without rules
	rules []*rules.Rule // otherwise, the rules, evaluated per item
}

var (
	ptrNow       = pointer.Pointer{"now"}
	ptrPrincipal = pointer.Pointer{"principal"}
	ptrGroups    = pointer.Pointer{"principal", "groups"}
)

// rrEntry is a cached readRoles with the document it was derived from.
type rrEntry struct {
	cfg *tree.NSConfig
	rr  *readRoles
}

// readRolesOf is the readRoles of a content namespace's document as of
// the checkpoint (Graph.Content), cached by the document's identity: a
// new document is a new *tree.NSConfig.
func (s *Service) readRolesOf(c *tree.NSConfig) *readRoles {
	s.rrMu.Lock()
	e, ok := s.rrCache[c.NS]
	s.rrMu.Unlock()
	if ok && e.cfg == c {
		return e.rr
	}
	rr := &readRoles{roles: map[string]*readRole{}}
	if cfg, err := grantcheck.ParseConfig(c.NS, "", c.Doc); err == nil {
		rr = s.readRoles(cfg)
	}
	s.rrMu.Lock()
	s.rrCache[c.NS] = rrEntry{c, rr}
	s.rrMu.Unlock()
	return rr
}

func (s *Service) readRoles(cfg *grantcheck.Config) *readRoles {
	out := &readRoles{roles: map[string]*readRole{}}
	key := findKey(cfg.Keys, s.opt.Kid)
	if key == nil || !key.IsStar() && !contains(key.Can, "read") {
		return out
	}
	out.key = key
	for r, def := range cfg.Roles {
		if !contains(def.Can, "read") || !roleAllowed(key, r) {
			continue
		}
		rr := &readRole{plain: len(def.Rules) == 0}
		for _, x := range def.Rules {
			c, err := rules.Compile(x)
			if err != nil || !listable(c) {
				rr = nil
				break
			}
			rr.rules = append(rr.rules, c)
		}
		if rr != nil {
			out.roles[r] = rr
		}
	}
	return out
}

// listable reports whether a rule can count for a listing (§B.11.5): it
// reads neither /now nor anything in /principal but /principal/groups (a
// pointer above them, such as the whole envelope, reads them too).
func listable(r *rules.Rule) bool {
	for _, p := range r.RefPaths() {
		if p.Overlaps(ptrNow) || p.Overlaps(ptrPrincipal) && !p.HasPrefix(ptrGroups) {
			return false
		}
	}
	return true
}

// asserts reports whether a key's groups scope lets the catalog act for a
// subject: a user always, a group only if the key may assert it (§B.11.3,
// §B.11.6).
func asserts(key *grant.Key, subj string) bool {
	g, ok := strings.CutPrefix(subj, grantcheck.GroupPrefix)
	if !ok {
		return true
	}
	allowed, _ := key.Groups.Permits([]string{g})
	return allowed
}

// assertable is the subjects of subs the key may assert: effective roles
// are collected only through them (§B.11.4 Resolve, §B.11.5).
func assertable(key *grant.Key, subs map[string]bool) map[string]bool {
	out := map[string]bool{}
	for subj, ok := range subs {
		if ok && asserts(key, subj) {
			out[subj] = true
		}
	}
	return out
}

// grants reports whether a subject of subs the key may assert collects at
// the node (eff, its effective roles) a role granting read: one without
// rules, or, if env is set (an item), one whose rules pass against env.
func (rr *readRoles) grants(eff map[string][]string, subs map[string]bool, env map[string]any) bool {
	if rr == nil || rr.key == nil {
		return false
	}
	for subj, roles := range eff {
		if !subs[subj] || !asserts(rr.key, subj) {
			continue
		}
		for _, r := range roles {
			def := rr.roles[r]
			switch {
			case def == nil:
			case def.plain:
				return true
			case env != nil:
				if _, _, ok := rules.EvalList(def.rules, env); ok {
					return true
				}
			}
		}
	}
	return false
}

// visibility is a subject set's view of the catalog (§B.11.5).
type visibility struct {
	s      *Service
	subs   map[string]bool
	groups []string // the caller's groups, as its grant has them (for /principal/groups)
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
// when the walk up from it collects, through a subject the catalog's key
// may assert, a role granting read without conditions: for an item, a
// role its content namespace defines with read that the catalog's key
// there may grant (roles and groups scope), without rules or with rules
// that pass as a read of the item would evaluate them; for a folder, such
// a role without rules in some trusted content namespace. Roles, their
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
			if v.roles(g, ns).grants(eff, v.subs, nil) {
				return true
			}
		}
		return false
	}
	rr := v.roles(g, n.ItemNS)
	if rr == nil || rr.key == nil {
		return false
	}
	// The read envelope as the gate would build it for a grant the catalog
	// signs (§6.4.1, mint): action read, the resource, and a principal
	// holding the caller's groups the key may assert. No writes, doc or
	// patches, so within is true and covers and overlaps are false
	// (§6.4.2); no now, since rules reading it never count.
	var groups []any
	for _, gr := range v.groups {
		if ok, _ := rr.key.Groups.Permits([]string{gr}); ok {
			groups = append(groups, gr)
		}
	}
	env := map[string]any{"action": "read", "resource": n.ItemName, "principal": map[string]any{"groups": nonNilAny(groups)}}
	return rr.grants(eff, v.subs, env)
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
