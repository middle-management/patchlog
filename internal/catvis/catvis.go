// Package catvis is §B.11.5's visibility test, the one every reader of a
// catalog's decisions shares: the catalog service's listings and
// /read-grants, the origin's filtered namespace reads (§B.11.9) and the
// index's filtered answers (§A.4).
//
// A node is visible to a subject set when the walk up from it (Effective,
// §B.11.2) collects, through a subject a catalog key may grant through
// (its sub and groups scopes), a role that counts for read: one its
// content namespace defines with read, within the key's roles scope, whose
// own rules and the key's scope rules pass as a read would evaluate them,
// with /principal holding only the groups the key may assert and, as
// roles, that role. For an item, that is a role of its own content
// namespace, with /resource its name. For a folder, it is a role of some
// trusted content namespace whose rules don't refer to /resource, through
// a key whose scope rules refer only to /principal/groups and
// /principal/roles. A rule that refers to /now, or to anything in
// /principal but groups and roles, makes the role not count.
//
// The catalog's key in a content namespace is a set here: the catalog
// service passes its own kid, and the origin and the index pass every key
// of the content namespace whose requireAt names the catalog
// (TrustedCatalogs), through any of which a role counts (§B.11.9 Where).
//
// The package reads nothing itself: a Catalog is built from a graph
// (internal/tree) and the trusted content namespaces' documents as of one
// checkpoint, and is immutable.
package catvis

import (
	"sort"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/rules"
	"github.com/middle-management/patchlog/internal/tree"
)

// Trust is a catalog a content namespace trusts (§B.11.9 Where), with the
// kids of its keys whose requireAt names the catalog.
type Trust struct {
	Catalog string
	Kids    []string
}

// TrustedCatalogs returns the catalogs that ns trusts, sorted: those its
// document's catalogs names whose catalog.trust lists ns, through its keys
// whose requireAt names that catalog (§B.11.3, §B.11.9 Where). A catalog
// with no such key is not trusted. catalogDoc returns a catalog's
// document, nil for one that is absent or unreadable (which is then not
// trusted).
func TrustedCatalogs(ns string, nsDoc map[string]any, catalogDoc func(cat string) map[string]any) []Trust {
	cats, _ := nsDoc["catalogs"].(map[string]any)
	names := make([]string, 0, len(cats))
	for cat := range cats {
		if cat != ns {
			names = append(names, cat)
		}
	}
	sort.Strings(names)
	var out []Trust
	for _, cat := range names {
		kids := requireAtKids(nsDoc, cat)
		if len(kids) == 0 {
			continue
		}
		doc := catalogDoc(cat)
		if doc == nil || !trustList(doc)[ns] {
			continue
		}
		out = append(out, Trust{Catalog: cat, Kids: kids})
	}
	return out
}

// TrustList is a catalog document's catalog.trust (§B.6), without the
// catalog itself, as the tree service reads it.
func TrustList(cat string, doc map[string]any) []string {
	var out []string
	for ns := range trustList(doc) {
		if ns != cat {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

func trustList(doc map[string]any) map[string]bool {
	c, _ := doc["catalog"].(map[string]any)
	arr, _ := c["trust"].([]any)
	out := map[string]bool{}
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out[s] = true
		}
	}
	return out
}

// requireAtKids are the kids of nsDoc's keys whose requireAt is cat,
// sorted.
func requireAtKids(nsDoc map[string]any, cat string) []string {
	keys, _ := nsDoc["keys"].([]any)
	var out []string
	for _, k := range keys {
		m, _ := k.(map[string]any)
		kid, _ := m["kid"].(string)
		if kid != "" && m["requireAt"] == cat && !contains(out, kid) {
			out = append(out, kid)
		}
	}
	sort.Strings(out)
	return out
}

// Content is a trusted content namespace's document as of the checkpoint,
// parsed, with the kids of the catalog's keys there. With a nil Cfg
// nothing counts through it.
type Content struct {
	NS   string
	Cfg  *grantcheck.Config
	Kids []string
}

// Catalog is a catalog's graph and its trusted content namespaces as of
// one checkpoint, ready to judge visibility. It is immutable and safe for
// concurrent use.
type Catalog struct {
	G *tree.Graph
	// rr are each content namespace's readRoles, one per kid, of the
	// namespaces in G.Trust that contents names.
	rr       map[string][]*readRoles
	contents map[string]*Content

	mu  sync.Mutex
	eff map[string]map[string][]string // Effective per name, computed lazily

	profileOnce sync.Once
	profile     Profile
}

// NewCatalog builds a Catalog of g, contents keyed by g's catalog.trust
// members.
func NewCatalog(g *tree.Graph, contents map[string]*Content) *Catalog {
	c := &Catalog{G: g, rr: map[string][]*readRoles{}, contents: map[string]*Content{}, eff: map[string]map[string][]string{}}
	for ns, ct := range contents {
		if ct == nil || !g.Trust[ns] {
			continue
		}
		c.contents[ns] = ct
		if ct.Cfg == nil {
			continue
		}
		for _, kid := range ct.Kids {
			c.rr[ns] = append(c.rr[ns], newReadRoles(ct.Cfg, kid))
		}
	}
	return c
}

// effective is Effective of a node of c.G, memoised.
func (c *Catalog) effective(name string) map[string][]string {
	c.mu.Lock()
	e, ok := c.eff[name]
	c.mu.Unlock()
	if ok {
		return e
	}
	e = Effective(c.G, name, nil)
	c.mu.Lock()
	c.eff[name] = e
	c.mu.Unlock()
	return e
}

// View is a subject set's view of a Catalog (§B.11.5).
type View struct {
	c      *Catalog
	who    who
	groups []string // the groups among the subjects, as the grant has them (for /principal/groups)
	eff    func(name string) map[string][]string

	// folder caches, per readRoles, whether a role counts for folders:
	// that depends on the subject set and the role alone.
	mu     sync.Mutex
	folder map[*readRoles]map[string]bool
}

// View is ViewWith with roles computed from the graph.
func (c *Catalog) View(subjects []string) *View { return c.ViewWith(subjects, nil) }

// ViewWith is subjects' view of c, live nodes' roles per subject given by
// eff (the catalog service's stored effective rows), or computed from the
// graph if eff is nil. The groups among the subjects are /principal/groups,
// and the user: subject is matched against keys' sub scopes; "partial" and
// "scope:…" subjects are ignored.
func (c *Catalog) ViewWith(subjects []string, eff func(name string) map[string][]string) *View {
	if eff == nil {
		eff = c.effective
	}
	w, groups := whoOf(subjects)
	return &View{c: c, who: w, groups: groups, eff: eff}
}

// Node is §B.11.5's node test, the one listings and /read-grants (for
// catalog nodes and their keys) use: live nodes only (a dangling
// placement, a deleted item's included, grants nothing, and cyclic and
// implicit nodes collect nothing, §B.11.2); a folder is visible through
// the folder-role test of any trusted content namespace, a placement
// through its item's namespace with /resource its name. A node detached
// from the graph is never live.
func (v *View) Node(n *tree.Node) bool {
	if n == nil || n.Self || !n.Live() || v.c.G.Node(n.Name) != n {
		return false
	}
	return v.judge(n, v.eff(n.Name))
}

// AsIfLive is Node as organising requests judge a node (§B.11.4,
// §B.11.5), and as §B.11.9 judges a deleted resource: a dangling or
// deleted placement is judged as if its item were live, from the roles at
// it computed from the graph as a live item's are (Effective; a deleted
// item's frozen rows aren't its roles at the node), through its item's
// content namespace, which must still be trusted. It also judges a node
// detached from the graph, such as a deleted catalog node parsed from its
// last live document (EffectiveOf). A cyclic or implicit node stays
// hidden: it collects nothing (§B.5 Cycles, §B.9).
func (v *View) AsIfLive(n *tree.Node) bool {
	if n == nil || n.Self || n.Cyclic {
		return false
	}
	switch g := v.c.G; {
	case g.Node(n.Name) != n:
		return v.judge(n, EffectiveOf(g, n))
	case n.Live():
		return v.judge(n, v.eff(n.Name))
	}
	return v.judge(n, v.c.effective(n.Name))
}

// Placement reports whether the explicit placement {ns}.{name} exists in
// the graph, is neither implicit nor cyclic, and passes AsIfLive: the
// item's state is ignored (§B.11.9 Visible, Deleted resources).
func (v *View) Placement(ns, name string) bool {
	pn := ns + "." + name
	if !v.c.G.Explicit(pn) {
		return false
	}
	n := v.c.G.Node(pn)
	if n == nil || n.Self || n.Cyclic || n.ItemNS != ns || n.ItemName != name {
		return false
	}
	return v.AsIfLive(n)
}

// judge decides a node with roles eff per subject (Node).
func (v *View) judge(n *tree.Node, eff map[string][]string) bool {
	if n.Kind == tree.KindFolder {
		for ns := range v.c.contents {
			for _, rr := range v.c.rr[ns] {
				if v.counts(rr, eff, "", false) {
					return true
				}
			}
		}
		return false
	}
	if n.ItemNS == "" {
		return false
	}
	for _, rr := range v.c.rr[n.ItemNS] {
		if v.counts(rr, eff, n.ItemName, true) {
			return true
		}
	}
	return false
}

// Effective computes a node's effective roles per subject (§B.11.2).
// override replaces the walkable parents of named nodes (to simulate a
// move). Implicit placements and cyclic nodes get nothing.
func Effective(g *tree.Graph, name string, override map[string][]string) map[string][]string {
	start := g.Node(name)
	if start == nil || start.Self || start.Cyclic {
		return nil
	}
	return walk(g, start, override, nil)
}

// EffectiveOf is Effective for a node that may be detached from g, such
// as a deleted node parsed from its last live document (tree.ParseNode):
// it walks up from n's own parents into g.
func EffectiveOf(g *tree.Graph, n *tree.Node) map[string][]string {
	if n == nil || n.Self || n.Cyclic {
		return nil
	}
	if g.Node(n.Name) == n {
		return Effective(g, n.Name, nil)
	}
	var ps []string
	seen := map[string]bool{}
	for _, p := range n.Parents {
		if p.Name != "" && !seen[p.Name] {
			seen[p.Name] = true
			ps = append(ps, p.Name)
		}
	}
	return walk(g, n, nil, ps)
}

// walk is the walk up of Effective from start, whose parents are
// startParents if not nil.
func walk(g *tree.Graph, start *tree.Node, override map[string][]string, startParents []string) map[string][]string {
	type item struct {
		n *tree.Node
		d int
	}
	acc := map[string]map[string]bool{}
	visited := map[string]bool{start.Name: true}
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
		switch {
		case it.n == start && startParents != nil:
			ps = startParents
		case !ok:
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

// --- subjects ----------------------------------------------------------------

// userPrefix marks user subjects (§B.11.1).
const userPrefix = "user:"

// UserSubject is the subject a grant's root sub gives (§B.11.2): the sub
// itself if it starts with "user:", otherwise none ("").
func UserSubject(sub string) string {
	if strings.HasPrefix(sub, userPrefix) {
		return sub
	}
	return ""
}

// GroupSubjects is group:{g} for each of a grant's root groups (§B.11.2),
// sorted. A group written with the "group:" prefix gets it again: its
// subject is never that of the unprefixed group.
func GroupSubjects(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if subj := grantcheck.GroupPrefix + g; !contains(out, subj) {
			out = append(out, subj)
		}
	}
	sort.Strings(out)
	return out
}

// who is a caller as the catalog's keys see it (§B.11.2 Through the key):
// its subject set, and the sub a key's sub scope is matched against. A
// caller without one (hasSub false) fails every sub scope.
type who struct {
	subs   map[string]bool
	sub    string
	hasSub bool
}

// whoOf is a subject set's caller (§B.11.5), and the groups among its
// subjects, as the grant had them (for /principal/groups). Subjects other
// than group: and user: ones ("partial", "scope:…") are ignored.
func whoOf(subjects []string) (who, []string) {
	w := who{subs: map[string]bool{}}
	var groups []string
	for _, subj := range subjects {
		if g, ok := strings.CutPrefix(subj, grantcheck.GroupPrefix); ok {
			w.subs[subj] = true
			groups = append(groups, g)
		} else if strings.HasPrefix(subj, userPrefix) {
			w.subs[subj] = true
			w.sub, w.hasSub = subj, true
		}
	}
	return w, groups
}

// through is the subjects of w through which key may grant (§B.11.2
// Through the key, §B.11.3): none if the key has a sub scope that w's sub
// doesn't match; otherwise w's user subject, and each group subject whose
// group the key's groups scope lets it assert.
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

// --- roles that count for read ---------------------------------------------

// readRoles are the roles through which one catalog key may grant read in
// one trusted content namespace (§B.11.2, §B.11.5): roles the namespace
// defines with read, within the key's roles scope, for a key that may
// grant read and whose scope rules can count.
type readRoles struct {
	// key is nil if the namespace doesn't list the kid, the key can't
	// grant read, or one of its scope rules never counts.
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
// never counts and isn't listed.
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

func newReadRoles(cfg *grantcheck.Config, kid string) *readRoles {
	out := &readRoles{roles: map[string]*readRole{}}
	key := findKey(cfg.Keys, kid)
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

// counts reports whether a role of eff (a node's roles per subject)
// counts for read through rr's key (Node): for an item, named resource;
// otherwise for a folder.
func (v *View) counts(rr *readRoles, eff map[string][]string, resource string, item bool) bool {
	if rr == nil || rr.key == nil || !item && !rr.keyFolders {
		return false
	}
	subs := v.who.through(rr.key)
	if len(subs) == 0 {
		return false
	}
	// The read envelope as the gate would build it for a grant the catalog
	// signs carrying that role (§6.4.1): action read, the resource for an
	// item, and a principal holding the caller's groups the key may assert
	// and the role. No writes, doc or patches, so within is true and
	// covers and overlaps are false (§6.4.2); no now, since rules reading
	// it never count.
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
func (v *View) folderRole(rr *readRoles, def *readRole, r string, groups []any) bool {
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
