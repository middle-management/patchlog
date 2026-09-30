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
//     apply only where a role granting them is assigned directly (§B.11.2).
//   - Content namespaces define what a role means (§B.11.1): the catalog
//     keeps only roles the content namespace defines with a wanted verb.
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
// ordinary core grants fixed to one resource.
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
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
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
	s := &Service{opt: opt, eff: map[string]map[string][]string{}, users: map[string]bool{}}
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
		case "/grants", "/read-grants":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				tree.WriteError(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
				return
			}
			if r.URL.Path == "/grants" {
				s.serveGrants(w, r)
			} else {
				s.serveReadGrants(w, r)
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
// keyed by the node's href.
func (s *Service) Init(ctx context.Context, db *sql.DB) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS access_nodes (node TEXT PRIMARY KEY, inherit INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE IF NOT EXISTS acl (node TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (node, subject, role)) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS effective (node TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (node, subject, role)) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS effective_by_subject ON effective (subject, node)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("catalog: schema: %w", err)
		}
	}
	return nil
}

// Rebuild recomputes acl and effective from the graph.
func (s *Service) Rebuild(ctx context.Context, tx *sql.Tx, g *tree.Graph) error {
	for _, q := range []string{`DELETE FROM access_nodes`, `DELETE FROM acl`, `DELETE FROM effective`} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	s.eff = map[string]map[string][]string{}
	for _, name := range g.Names() {
		if err := s.writeACL(ctx, tx, g, name, false); err != nil {
			return err
		}
		e := Effective(g, name, nil)
		if err := s.writeEffective(ctx, tx, g, name, e, false); err != nil {
			return err
		}
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
		e := Effective(g, name, nil)
		if sameEff(e, s.eff[name]) {
			continue
		}
		if err := s.writeEffective(ctx, tx, g, name, e, true); err != nil {
			return err
		}
	}
	s.users = directUsers(g)
	return nil
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM effective WHERE node = ?`, href); err != nil {
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

// Resolve implements tree.RoleView: listings are keyed by the caller's
// group subjects, plus its user subject only if the catalog has direct
// entries for that user (§B.11.5).
func (s *Service) Resolve(ctx context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	subs := Subjects(v)
	user := UserSubject(v.Principal.ID)
	var trust []string
	direct := false
	s.t.View(func(g *tree.Graph, _ map[string]string) {
		direct = s.users[user]
		for ns := range g.Trust {
			trust = append(trust, ns)
		}
	})
	keyed := grantcheck.SubjectSet(v, false)
	if direct {
		keyed = append(keyed, user)
	}
	vis := &visibility{s: s, subs: subs, defined: map[string]map[string]bool{}, reads: map[string]map[string]bool{}}
	for _, ns := range trust {
		cfg, err := s.t.Checker().Config(ctx, ns)
		if err != nil {
			continue
		}
		key := findKey(cfg.Keys, s.opt.Kid)
		vis.defined[ns], vis.reads[ns] = map[string]bool{}, map[string]bool{}
		for r, def := range cfg.Roles {
			if key == nil || !roleAllowed(key, r) {
				continue
			}
			vis.defined[ns][r] = true
			for _, c := range def.Can {
				if c == "read" && (key.IsStar() || contains(key.Can, "read")) {
					vis.reads[ns][r] = true
				}
			}
		}
	}
	return keyed, vis, nil
}

type visibility struct {
	s       *Service
	subs    map[string]bool
	defined map[string]map[string]bool // ns -> roles it defines (that the catalog key may assert)
	reads   map[string]map[string]bool // ns -> roles granting read
}

// Node: a folder is visible to anyone with any effective role at it; a
// placement to anyone with a role its content namespace defines, while its
// item is live (a dangling placement grants nothing).
func (v *visibility) Node(g *tree.Graph, n *tree.Node) bool {
	roles := v.s.rolesFor(n.Name, v.subs)
	if n.Kind == tree.KindFolder {
		return len(roles) > 0
	}
	if n.State != tree.StateLive {
		return false
	}
	for r := range roles {
		if v.defined[n.ItemNS][r] {
			return true
		}
	}
	return false
}

// Item: the item's head is visible with a role granting read.
func (v *visibility) Item(g *tree.Graph, n *tree.Node) bool {
	if n.State != tree.StateLive {
		return false
	}
	for r := range v.s.rolesFor(n.Name, v.subs) {
		if v.reads[n.ItemNS][r] {
			return true
		}
	}
	return false
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
