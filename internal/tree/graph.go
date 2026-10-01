package tree

import (
	"regexp"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
)

// MaxDepth bounds every walk (§B.5): deeper paths are flagged.
const MaxDepth = 64

// Node kinds (§B.2).
const (
	KindFolder    = 0
	KindPlacement = 1
)

// Node states as stored in nodes.state (§B.5).
const (
	StateLive     = 0
	StateGone     = 1 // not used for stored rows: gone nodes are deleted
	StateDangling = 2
)

// Item states (items.state), matching client.State.
const (
	ItemUnknown    = 0 // never seen in the content namespace
	ItemLive       = 1
	ItemTombstoned = 2
	ItemPurged     = 3
)

// Edge states (edges.state).
const (
	EdgeValid     = 0 // the parent is a live, non-cyclic folder of this catalog
	EdgeDangling  = 1 // the parent does not exist (missing, tombstoned or purged)
	EdgeNotFolder = 2 // the parent is a placement
	EdgeCycle     = 3 // the edge touches a cycle; excluded from traversals
	EdgeInvalid   = 4 // the href is not a live link to a node of this catalog
)

// EdgeStateName names an edge state for the API.
func EdgeStateName(s int) string {
	return [...]string{"valid", "dangling", "not-folder", "cycle", "invalid"}[s]
}

// Parent is one entry of a node's parents (or $parents) as declared.
type Parent struct {
	Href     string
	Name     string // the parent node's name, "" if Href is invalid
	Order    string
	HasOrder bool
	Invalid  string // why Href is not a live link to this catalog
}

// Node is a folder or placement (explicit, from the catalog namespace), or
// an implicit placement from a content document's $parents (§B.9).
type Node struct {
	Name      string
	Kind      int
	Self      bool   // implicit placement (§B.9)
	Head      string // the catalog revision of the node's document ("" for implicit)
	Title     string
	Parents   []Parent
	Access    map[string][]string // $access subject -> role names (without "inherit")
	Inherit   bool                // false: $access has inherit: false
	HasAccess bool

	// Placements.
	ItemNS, ItemName string // "" if the name doesn't split into a valid item
	ItemState        int
	ItemHead         string // last known head revision of a live item

	// Derived by analyze.
	State      int    // StateLive or StateDangling
	Dangling   string // why a placement is dangling: missing, tombstoned, purged, untrusted, invalid
	Cyclic     bool
	Deep       bool // some path to a root is longer than MaxDepth
	Depth      int  // longest walkable path to a root, -1 if none
	EdgeStates []int

	rawParents, rawAccess any // as in the document, for storage
}

type savedRow struct {
	state      int
	dangling   string
	cyclic     bool
	deep       bool
	itemState  int
	itemHead   string
	edgeStates []int
}

func (n *Node) derivedEqual(s *savedRow) bool {
	if s == nil || s.state != n.State || s.dangling != n.Dangling || s.cyclic != n.Cyclic || s.deep != n.Deep ||
		s.itemState != n.ItemState || s.itemHead != n.ItemHead || len(s.edgeStates) != len(n.EdgeStates) {
		return false
	}
	for i := range s.edgeStates {
		if s.edgeStates[i] != n.EdgeStates[i] {
			return false
		}
	}
	return true
}

func (n *Node) snapshot() *savedRow {
	return &savedRow{state: n.State, dangling: n.Dangling, cyclic: n.Cyclic, deep: n.Deep,
		itemState: n.ItemState, itemHead: n.ItemHead, edgeStates: append([]int(nil), n.EdgeStates...)}
}

// Item is the live link of a placement's item, "/r/{ns}/{name}".
func (n *Node) Item() string {
	if n.ItemNS == "" {
		return ""
	}
	return "/r/" + n.ItemNS + "/" + n.ItemName
}

// Live reports whether the node takes part in traversals: a folder, or a
// placement whose item is live in a trusted namespace.
func (n *Node) Live() bool { return n.State == StateLive && !n.Cyclic }

// Graph is the in-memory view of one catalog as of the recorded
// checkpoints. It is read under the service's lock (Service.View).
type Graph struct {
	Catalog string
	// Config is the catalog namespace document as of the catalog checkpoint.
	Config map[string]any
	// Trust is catalog.trust (§B.6).
	Trust map[string]bool
	// Aliases maps a namespace to the branch followed in its place in a
	// release preview (§B.5, §F.9); nil otherwise.
	Aliases map[string]string

	nodes    map[string]*Node // merged: explicit, else implicit
	explicit map[string]*Node
	self     map[string]*Node
	children map[string]map[string]bool // parent name -> child names (every declared edge)
	sccs     [][]string                 // cycles found by the last analysis
	saved    map[string]*savedRow       // derived state the nodes/edges tables hold
}

func newGraph(catalog string) *Graph {
	return &Graph{Catalog: catalog, Trust: map[string]bool{}, nodes: map[string]*Node{},
		explicit: map[string]*Node{}, self: map[string]*Node{}, children: map[string]map[string]bool{},
		saved: map[string]*savedRow{}}
}

// Node returns a node by name (nil if none).
func (g *Graph) Node(name string) *Node { return g.nodes[name] }

// Names returns every node name, sorted.
func (g *Graph) Names() []string {
	out := make([]string, 0, len(g.nodes))
	for n := range g.nodes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Len is the number of nodes.
func (g *Graph) Len() int { return len(g.nodes) }

// Href is the node's live link.
func (g *Graph) Href(name string) string { return "/r/" + g.Catalog + "/" + name }

// Actual is the namespace read in place of ns: its branch in a release
// preview (§B.5), otherwise ns itself.
func (g *Graph) Actual(ns string) string {
	if a := g.Aliases[ns]; a != "" {
		return a
	}
	return ns
}

// ItemHref is the live link of a placement's item where the service reads
// it: in a release preview, in the release's branch of the item's
// namespace (§B.5: placements such as matches.final resolve to the
// release's branch of matches).
func (g *Graph) ItemHref(n *Node) string {
	if n.ItemNS == "" {
		return ""
	}
	return "/r/" + g.Actual(n.ItemNS) + "/" + n.ItemName
}

// WalkableParents returns the parents a walk may go up to from n: edges in
// state EdgeValid (a live, non-cyclic folder), without duplicates, in
// declaration order. A cyclic node has none.
func (g *Graph) WalkableParents(n *Node) []string {
	if n == nil || n.Cyclic {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for i, p := range n.Parents {
		if i < len(n.EdgeStates) && n.EdgeStates[i] == EdgeValid && !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	return out
}

// Child is a walkable child of a folder with its order under that folder.
type Child struct {
	Node     *Node
	Order    string
	HasOrder bool
}

// Children returns the walkable children of a folder (edges in state
// EdgeValid), sorted: ordered siblings by order (code unit order), then
// unordered ones, then by name (§B.2). Dangling placements are included;
// callers filter with Live.
func (g *Graph) Children(parent string) []Child {
	var out []Child
	for c := range g.children[parent] {
		n := g.nodes[c]
		if n == nil || n.Cyclic {
			continue
		}
		for i, p := range n.Parents {
			if p.Name == parent && i < len(n.EdgeStates) && n.EdgeStates[i] == EdgeValid {
				out = append(out, Child{Node: n, Order: p.Order, HasOrder: p.HasOrder})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return childLess(out[i], out[j]) })
	return out
}

func childLess(a, b Child) bool {
	if a.HasOrder != b.HasOrder {
		return a.HasOrder
	}
	if a.HasOrder && a.Order != b.Order {
		return lessUTF16(a.Order, b.Order)
	}
	return a.Node.Name < b.Node.Name
}

// lessUTF16 compares by UTF-16 code units (§B.2 "compared by code unit").
func lessUTF16(a, b string) bool {
	ar, br := []rune(a), []rune(b)
	for i := 0; i < len(ar) && i < len(br); i++ {
		if ar[i] == br[i] {
			continue
		}
		return utf16Key(ar[i]) < utf16Key(br[i])
	}
	return len(ar) < len(br)
}

// utf16Key maps a rune to a key ordering like its first UTF-16 code unit
// (surrogates, 0xD800–0xDFFF, sort before 0xE000–0xFFFF).
func utf16Key(r rune) int {
	if r >= 0x10000 {
		return 0xD800 + int((r-0x10000)>>10)
	}
	return int(r)
}

// Descendants returns names reachable downward from names over every
// declared edge (valid or not), including names themselves.
func (g *Graph) Descendants(names []string) map[string]bool {
	out := map[string]bool{}
	stack := append([]string(nil), names...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[n] {
			continue
		}
		out[n] = true
		for c := range g.children[n] {
			if !out[c] {
				stack = append(stack, c)
			}
		}
	}
	return out
}

// Cycles returns the cycles found by the last analysis (each sorted).
func (g *Graph) Cycles() [][]string { return g.sccs }

// --- mutation ------------------------------------------------------------

func (g *Graph) link(n *Node) {
	for _, p := range n.Parents {
		if p.Name == "" {
			continue
		}
		m := g.children[p.Name]
		if m == nil {
			m = map[string]bool{}
			g.children[p.Name] = m
		}
		m[n.Name] = true
	}
}

func (g *Graph) unlink(n *Node) {
	for _, p := range n.Parents {
		if m := g.children[p.Name]; m != nil {
			delete(m, n.Name)
			if len(m) == 0 {
				delete(g.children, p.Name)
			}
		}
	}
}

// refresh recomputes the merged node for name after explicit or self
// changed, keeping item state.
func (g *Graph) refresh(name string) {
	old := g.nodes[name]
	nw := g.explicit[name]
	if nw == nil {
		nw = g.self[name]
	}
	if old == nw {
		return
	}
	if old != nil {
		g.unlink(old)
		delete(g.nodes, name)
	}
	if nw != nil {
		g.nodes[name] = nw
		g.link(nw)
	}
}

func (g *Graph) setExplicit(n *Node) {
	if old := g.explicit[n.Name]; old != nil {
		n.ItemState, n.ItemHead = old.ItemState, old.ItemHead
	} else if s := g.self[n.Name]; s != nil {
		n.ItemState, n.ItemHead = s.ItemState, s.ItemHead
	}
	g.explicit[n.Name] = n
	g.refresh(n.Name)
}

func (g *Graph) removeExplicit(name string) {
	delete(g.explicit, name)
	g.refresh(name)
}

func (g *Graph) setSelf(n *Node) {
	if e := g.explicit[n.Name]; e != nil {
		n.ItemState, n.ItemHead = e.ItemState, e.ItemHead
	}
	g.self[n.Name] = n
	g.refresh(n.Name)
}

func (g *Graph) removeSelf(name string) {
	delete(g.self, name)
	g.refresh(name)
}

// setItem records an item's state on the explicit and implicit placement
// for it, if any; it reports whether a node exists.
func (g *Graph) setItem(name string, state int, head string) bool {
	found := false
	for _, n := range []*Node{g.explicit[name], g.self[name]} {
		if n != nil {
			n.ItemState, n.ItemHead = state, head
			found = true
		}
	}
	return found
}

// --- parsing ---------------------------------------------------------------

// SplitPlacement splits a placement name "{ns}.{name}" at its first dot.
func SplitPlacement(name string) (ns, item string, ok bool) {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", "", false
	}
	ns, item = name[:i], name[i+1:]
	return ns, item, client.ValidNSName(ns) && client.ValidResourceName(item)
}

var hrefRe = regexp.MustCompile(`^/r/([a-z0-9][a-z0-9_-]{0,63})/([a-z0-9][a-z0-9._-]{0,127})$`)

func validNS(s string) bool { return client.ValidNSName(s) }

// ParseHref parses a live link /r/{ns}/{name}.
func ParseHref(h string) (ns, name string, ok bool) {
	m := hrefRe.FindStringSubmatch(h)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// parseParents parses a parents (or $parents) value. With onlyCatalog,
// entries linking elsewhere are dropped instead of being marked invalid
// (for $parents, which may link to folders of other catalogs, §B.9).
func parseParents(catalog string, v any, onlyCatalog bool) []Parent {
	arr, _ := v.([]any)
	var out []Parent
	for _, e := range arr {
		p := Parent{}
		m, ok := e.(map[string]any)
		if !ok {
			if onlyCatalog {
				continue
			}
			p.Invalid = "entry is not an object"
			out = append(out, p)
			continue
		}
		p.Href, _ = m["href"].(string)
		if o, ok := m["order"].(string); ok {
			p.Order, p.HasOrder = o, true
		}
		ns, name, ok := ParseHref(p.Href)
		switch {
		case !ok && strings.HasPrefix(p.Href, "/r/"+catalog+"/"):
			p.Invalid = "not a live link (pinned or malformed)"
		case !ok:
			if onlyCatalog {
				continue
			}
			p.Invalid = "not a live link"
		case ns != catalog:
			if onlyCatalog {
				continue
			}
			p.Invalid = "links to another namespace"
		default:
			p.Name = name
		}
		out = append(out, p)
	}
	return out
}

// parseAccess parses $access (§B.11.1): subjects (group:… or user:…) to
// role names, and inherit.
func parseAccess(v any) (acc map[string][]string, inherit, has bool) {
	inherit = true
	m, ok := v.(map[string]any)
	if !ok {
		return nil, true, false
	}
	acc = map[string][]string{}
	for k, x := range m {
		if k == "inherit" {
			if b, ok := x.(bool); ok {
				inherit = b
			}
			continue
		}
		if !strings.HasPrefix(k, "group:") && !strings.HasPrefix(k, "user:") {
			continue
		}
		arr, _ := x.([]any)
		seen := map[string]bool{}
		for _, r := range arr {
			if s, ok := r.(string); ok && s != "" && !seen[s] {
				seen[s] = true
				acc[k] = append(acc[k], s)
			}
		}
		sort.Strings(acc[k])
	}
	return acc, inherit, true
}

// ParseNode builds an explicit node from a catalog document.
func ParseNode(catalog, name, head string, doc any) *Node {
	n := &Node{Name: name, Head: head, Inherit: true}
	if strings.Contains(name, ".") {
		n.Kind = KindPlacement
		if ns, item, ok := SplitPlacement(name); ok {
			n.ItemNS, n.ItemName = ns, item
		}
	}
	m, _ := doc.(map[string]any)
	n.Title, _ = m["title"].(string)
	n.Parents = parseParents(catalog, m["parents"], false)
	n.Access, n.Inherit, n.HasAccess = parseAccess(m["$access"])
	n.rawParents, n.rawAccess = m["parents"], m["$access"]
	return n
}

// parseSelf builds an implicit placement from a content document's
// $parents, nil if it names no folder of this catalog.
func parseSelf(catalog, ns, name string, doc any) *Node {
	m, _ := doc.(map[string]any)
	if m == nil {
		return nil
	}
	ps := parseParents(catalog, m["$parents"], true)
	if len(ps) == 0 {
		return nil
	}
	return &Node{Name: ns + "." + name, Kind: KindPlacement, Self: true, Inherit: true,
		ItemNS: ns, ItemName: name, Parents: ps}
}

// --- analysis ----------------------------------------------------------------

// analyze recomputes every node's derived state: edge states, cycles
// (strongly connected components of the folder graph), depth and
// danglingness. It returns the names whose derived state differs from
// what is saved.
func (g *Graph) analyze() map[string]bool {
	names := g.Names()
	// 1. Edge states before cycles.
	for _, name := range names {
		n := g.nodes[name]
		n.EdgeStates = make([]int, len(n.Parents))
		for i, p := range n.Parents {
			switch {
			case p.Name == "":
				n.EdgeStates[i] = EdgeInvalid
			case g.nodes[p.Name] == nil:
				n.EdgeStates[i] = EdgeDangling
			case g.nodes[p.Name].Kind != KindFolder:
				n.EdgeStates[i] = EdgeNotFolder
			default:
				n.EdgeStates[i] = EdgeValid
			}
		}
		n.Cyclic = false
	}
	// 2. Cycles: Tarjan's SCC over valid folder->folder edges (iterative).
	g.sccs = g.tarjan(names)
	for _, scc := range g.sccs {
		for _, name := range scc {
			g.nodes[name].Cyclic = true
		}
	}
	// Edges from or to a cyclic node are excluded from traversals.
	for _, name := range names {
		n := g.nodes[name]
		for i, p := range n.Parents {
			if n.EdgeStates[i] == EdgeValid && (n.Cyclic || g.nodes[p.Name].Cyclic) {
				n.EdgeStates[i] = EdgeCycle
			}
		}
	}
	// 3. Danglingness.
	for _, name := range names {
		n := g.nodes[name]
		n.State, n.Dangling = StateLive, ""
		if n.Kind != KindPlacement {
			continue
		}
		switch {
		case n.ItemNS == "":
			n.State, n.Dangling = StateDangling, "invalid"
		case !g.Trust[n.ItemNS]:
			n.State, n.Dangling = StateDangling, "untrusted"
		case n.ItemState == ItemLive:
		case n.ItemState == ItemTombstoned:
			n.State, n.Dangling = StateDangling, "tombstoned"
		case n.ItemState == ItemPurged:
			n.State, n.Dangling = StateDangling, "purged"
		default:
			n.State, n.Dangling = StateDangling, "missing"
		}
	}
	// 4. Depth: longest walkable path from a root (Kahn over the acyclic
	// walkable graph).
	indeg := map[string]int{}
	for _, name := range names {
		n := g.nodes[name]
		n.Depth, n.Deep = -1, false
		indeg[name] = len(g.WalkableParents(n))
	}
	var queue []string
	for _, name := range names {
		n := g.nodes[name]
		if !n.Cyclic && len(n.Parents) == 0 {
			n.Depth = 0
		}
		if indeg[name] == 0 {
			queue = append(queue, name)
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		n := g.nodes[name]
		for c := range g.children[name] {
			cn := g.nodes[c]
			if cn == nil || cn.Cyclic {
				continue
			}
			walk := false
			for _, p := range g.WalkableParents(cn) {
				if p == name {
					walk = true
				}
			}
			if !walk {
				continue
			}
			if n.Depth >= 0 && n.Depth+1 > cn.Depth {
				cn.Depth = n.Depth + 1
			}
			indeg[c]--
			if indeg[c] == 0 {
				queue = append(queue, c)
			}
		}
	}
	changed := map[string]bool{}
	for _, name := range names {
		n := g.nodes[name]
		n.Deep = n.Depth > MaxDepth
		if !n.derivedEqual(g.saved[name]) {
			changed[name] = true
		}
	}
	for name := range g.saved {
		if g.nodes[name] == nil {
			changed[name] = true
		}
	}
	return changed
}

func (g *Graph) tarjan(names []string) [][]string {
	index := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var out [][]string
	next := 0
	succ := func(name string) []string {
		n := g.nodes[name]
		var s []string
		for i, p := range n.Parents {
			if n.EdgeStates[i] == EdgeValid {
				s = append(s, p.Name)
			}
		}
		return s
	}
	type frame struct {
		name string
		succ []string
		i    int
	}
	for _, root := range names {
		if g.nodes[root].Kind != KindFolder {
			continue
		}
		if _, ok := index[root]; ok {
			continue
		}
		work := []*frame{{name: root, succ: succ(root)}}
		index[root], low[root] = next, next
		next++
		stack = append(stack, root)
		onStack[root] = true
		for len(work) > 0 {
			f := work[len(work)-1]
			if f.i < len(f.succ) {
				w := f.succ[f.i]
				f.i++
				if _, ok := index[w]; !ok {
					index[w], low[w] = next, next
					next++
					stack = append(stack, w)
					onStack[w] = true
					work = append(work, &frame{name: w, succ: succ(w)})
				} else if onStack[w] && index[w] < low[f.name] {
					low[f.name] = index[w]
				}
				continue
			}
			work = work[:len(work)-1]
			if len(work) > 0 {
				p := work[len(work)-1].name
				if low[f.name] < low[p] {
					low[p] = low[f.name]
				}
			}
			if low[f.name] == index[f.name] {
				var scc []string
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					scc = append(scc, w)
					if w == f.name {
						break
					}
				}
				selfLoop := false
				if len(scc) == 1 {
					for _, s := range succ(scc[0]) {
						if s == scc[0] {
							selfLoop = true
						}
					}
				}
				if len(scc) > 1 || selfLoop {
					sort.Strings(scc)
					out = append(out, scc)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}
