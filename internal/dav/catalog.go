package dav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/text/unicode/norm"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/tree"
)

// File trees (§H.2): a catalog (Addendum B) whose catalog object carries
// files: { ns, root, folder?, placement? } is served as a folder tree.
// Its top level is the children of folder node files.root; a folder is a
// folder node and a file a placement {ns}.{item}, each named by its
// node's title (a placement without one by its item's name), so a rename
// or a move is one append to the node (§H.5) and never touches the item.
// New items are created in files.ns, with opaque names. The tree is built
// from the catalog namespace's documents as the core has them
// (tree.BuildGraph), kept per token for CatalogTTL or until this server
// writes; with a tree service (Options.TreeService, treesvc.go) folders
// are listed, and paths resolved, from its listings instead (§H.3), and
// writes still read the documents where the grant reads them (a grant
// that doesn't keeps the listing's view, §H.4). The catalog's access
// ($access, §B.11) is the tree service's to apply, never this server's;
// where the tree service is a catalog service, writes and reads of
// items go under the grants it issues (catgrants.go). catalog.mode
// "tree" is assumed: a node with several parents (a DAG) shows under
// each, and is unlinked from one at a time.

const kindFolder = tree.KindFolder

// catGraph is a catalog's live nodes: their documents and heads, and the
// graph the tree service would build of them (§B.5), as one token read
// them, with the heads of their items, and the nodes' creation
// times, as read since.
type catGraph struct {
	cat   string
	g     *tree.Graph
	heads map[string]string
	at    time.Time
	gen   uint64

	mu     sync.Mutex
	items  map[string]*client.Head // by ns/name
	births map[string]time.Time    // by node
}

// tokenView is what one token read of a catalog, kept by the token's id
// for CatalogTTL, or until this server writes (views): the catalog's
// graph, or one folder as its tree service listed it. They are kept
// within CacheBytes over every token, the least recently used going
// first, since each token keeps its own (what one grant was shown is
// never shown to another, §H.7), and a catalog's graph holds every node.
type tokenView struct {
	cg *catGraph
	sd svcDir
	lk *lookupHit
}

// view returns what token tk read under k (a catalog, or catalog/folder).
func (s *Server) view(tk *token, k string) (tokenView, bool) {
	s.viewMu.Lock()
	defer s.viewMu.Unlock()
	return s.views.Get(tk.id + "\x00" + k)
}

// keepView keeps v, which tk read under k, at cost n (about what its
// nodes or entries take in memory).
func (s *Server) keepView(tk *token, k string, v tokenView, n int) {
	s.viewMu.Lock()
	defer s.viewMu.Unlock()
	s.views.Put(tk.id+"\x00"+k, v, n)
}

// graph returns catalog cat as the token read it at most CatalogTTL ago,
// and not before this server's last write.
func (st *reqState) graph(ctx context.Context, cat string) (*catGraph, error) {
	if cg := st.graphs[cat]; cg != nil {
		return cg, nil
	}
	now, gen := st.s.opt.Now(), st.s.gen.Load()
	v, _ := st.s.view(st.tk, cat)
	cg := v.cg
	if cg == nil || cg.gen != gen || now.Sub(cg.at) >= st.s.opt.CatalogTTL {
		return st.freshGraph(ctx, cat)
	}
	if st.graphs == nil {
		st.graphs, st.fresh = map[string]*catGraph{}, map[string]bool{}
	}
	st.graphs[cat] = cg
	return cg, nil
}

// freshGraph reads catalog cat again for the token, whatever it read
// within CatalogTTL, and keeps it so for the request and after.
func (st *reqState) freshGraph(ctx context.Context, cat string) (*catGraph, error) {
	now, gen := st.s.opt.Now(), st.s.gen.Load()
	cg, err := st.readGraph(ctx, cat)
	if err != nil {
		return nil, err
	}
	cg.at, cg.gen = now, gen
	st.s.keepView(st.tk, cat, tokenView{cg: cg}, 512*(len(cg.heads)+1))
	if st.graphs == nil {
		st.graphs, st.fresh = map[string]*catGraph{}, map[string]bool{}
	}
	st.graphs[cat], st.fresh[cat] = cg, true
	return cg, nil
}

// readGraph reads catalog cat's live nodes.
func (st *reqState) readGraph(ctx context.Context, cat string) (*catGraph, error) {
	hs, err := st.s.liveHeads(ctx, st.tk, cat)
	if err != nil {
		return nil, err
	}
	docs, err := st.s.fetchHeads(ctx, st.tk, hs, st.tk.c.Head, true)
	if err != nil {
		return nil, err
	}
	cg := &catGraph{cat: cat, heads: map[string]string{}, items: map[string]*client.Head{}, births: map[string]time.Time{}}
	nodes := map[string]any{}
	for _, hd := range docs {
		if hd.e.sealed {
			return nil, notOffered(cat)
		}
		cg.heads[hd.name] = hd.rev
		nodes[hd.name] = hd.e.value
	}
	cg.g = tree.BuildGraph(cat, nil, nodes)
	return cg, nil
}

// tree returns catalog cat's graph and its file tree's settings, or why
// it has none (notTree): a catalog.files its namespace document lacks, or
// a files.root that isn't a live folder.
func (st *reqState) tree(ctx context.Context, cat string) (*catGraph, *treeFiles, error) {
	c, err := st.treeConf(ctx, cat)
	if err != nil {
		return nil, nil, err
	}
	cg, err := st.graph(ctx, cat)
	if err != nil {
		return nil, nil, err
	}
	if n := cg.g.Node(c.files.root); n == nil || n.Kind != kindFolder || n.Cyclic {
		return nil, nil, fail(http.StatusNotFound, "catalog %s's files.root, %s, isn't a live folder node of it, so its file tree has no top level to show (§H.2)", cat, c.files.root)
	}
	return cg, c.files, nil
}

// writeTree is tree for a write that changes a tree's nodes (a new file
// or folder, a rename, a move, a delete), which the node documents decide
// where the grant reads them (§H.4 "Names before writes", §H.5). A grant
// that doesn't (§H.7 "Limited grants"), which lists through a tree
// service, keeps the listing's view for names (§H.4): its graph is nil,
// and what the write needs of the nodes is read from the node's own
// document where the grant reads it, or, with tree-derived access, given
// by the catalog's answer (catgrants.go); such a grant deletes no folder
// (403, noFolderDelete).
func (st *reqState) writeTree(ctx context.Context, cat string) (*catGraph, *treeFiles, error) {
	c, err := st.treeConf(ctx, cat)
	if err != nil {
		return nil, nil, err
	}
	if _, err := st.graph(ctx, cat); err != nil {
		var de *davError
		switch {
		case !errors.As(upstream(err), &de) || de.status != http.StatusUnauthorized && de.status != http.StatusForbidden && de.status != http.StatusNotFound:
			return nil, nil, err
		case st.s.viaService(cat, c):
			return nil, c.files, nil
		}
		// No listing to keep the names of, either.
		return nil, nil, fail(http.StatusForbidden, "your grant doesn't read catalog %s's node documents (%s), which a new file or folder, a rename, a move or a delete in its tree is made from without a tree service (§H.5, §H.7 \"Limited grants\")", cat, de.msg)
	}
	return st.tree(ctx, cat)
}

// noFolderDelete is the refusal of a folder's delete, a copy or a move to
// another tree, by a grant that doesn't read catalog cat's node
// documents (writeTree): a folder's emptiness is taken only from them,
// and a grant that can't read them deletes no folder (§H.4 "Names before
// writes"), nor copies one, which reads its $access and children there.
func noFolderDelete(cat, p string) error {
	return fail(http.StatusForbidden, "%s isn't deleted, copied or moved to another tree: your grant doesn't read catalog %s's node documents, which a folder's emptiness and access settings are taken from (§H.4 \"Names before writes\", §H.5); a grant that can't read them deletes no folder", p, cat)
}

// nodeDocFor is a new node's document (nodeDoc) in folder of catalog
// cat, its order after the last ordered child in graph cg, or, without
// one (writeTree), in the folder's listing (§B.2, §H.2 "Shape").
func (st *reqState) nodeDocFor(cat string, cg *catGraph, schema, title, folder string) map[string]any {
	if cg != nil {
		return cg.nodeDoc(schema, title, folder)
	}
	parent := map[string]any{"href": "/r/" + cat + "/" + folder}
	if o := st.listedOrderAfter(cat, folder); o != "" {
		parent["order"] = o
	}
	doc := map[string]any{"title": title, "parents": []any{parent}}
	if schema != "" {
		doc["$schema"] = schema
	}
	return doc
}

// listedOrderAfter is an order key after the last ordered child of folder
// in catalog cat as its listing shows them (cachedDir); "" where none
// fits or it isn't listed.
func (st *reqState) listedOrderAfter(cat, folder string) string {
	last := ""
	if d := st.cachedDir(cat, folder); d != nil {
		for _, e := range d.entries {
			if e.order != "" {
				last = e.order
			}
		}
	}
	return keyAfter(last)
}

// notTree is the answer for catalog cat, which isn't a file tree (why).
func notTree(cat, why string) error {
	if why == "" {
		why = "its namespace document, which says where its file tree is (catalog.files, §H.2), couldn't be read"
	}
	return fail(http.StatusNotFound, "catalog %s isn't served: %s", cat, why)
}

// Check refuses, at start, catalogs that aren't file trees: whose
// namespace document, read with the server's grant in local mode, or
// without a grant in a gateway, has no usable catalog.files (§H.2).
// Catalogs whose document can't be read so are left to the requests that
// open them, which answer why (404). What it reads says which flat
// namespace a tree owns (ownedBy), for tokens that can't read it.
func (s *Server) Check(ctx context.Context) error {
	tk := s.local
	if tk == nil {
		tk = s.newToken("check", s.anon, s.newScopeLocked(s.newPrincipal("check"), ""), nil)
	}
	cats := make([]string, 0, len(s.cats))
	for cat := range s.cats {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		in, err := s.nsInfoErr(ctx, tk, cat)
		switch {
		case err != nil:
			s.opt.Logf("dav: catalog %s: its namespace document couldn't be read at start (%v); it is checked when opened", cat, err)
		case in.files == nil && in.notTree != "":
			return fmt.Errorf("dav: -catalog %s: %s", cat, in.notTree)
		case in.files != nil:
			// Which flat namespace it owns (ownedBy).
			s.learn(cat, &catConf{files: in.files, trust: in.trust, trustKnown: in.trustKnown, titled: in.titled})
		}
	}
	return nil
}

// itemHead reads the head of a placement's item with tk's client, once
// per graph.
func (cg *catGraph) itemHead(tk *token) func(context.Context, string, string) (*client.Head, error) {
	return func(ctx context.Context, ns, name string) (*client.Head, error) {
		k := ns + "/" + name
		cg.mu.Lock()
		h := cg.items[k]
		cg.mu.Unlock()
		if h != nil {
			return h, nil
		}
		h, err := tk.c.Head(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		cg.mu.Lock()
		cg.items[k] = h
		cg.mu.Unlock()
		return h, nil
	}
}

// born is when node name was created, the genesis of its chain in the
// catalog's log, read once per graph; zero if unknown (pruned, refused).
func (cg *catGraph) born(ctx context.Context, tk *token, name string) time.Time {
	cg.mu.Lock()
	t, ok := cg.births[name]
	cg.mu.Unlock()
	if ok {
		return t
	}
	if head := cg.heads[name]; head != "" {
		if es, _, err := tk.c.LogPage(ctx, cg.cat, name, head, ""); err == nil && len(es) > 0 && es[0].Parent == "" {
			t, _ = time.Parse(time.RFC3339Nano, es[0].Created)
		}
	}
	cg.mu.Lock()
	cg.births[name] = t
	cg.mu.Unlock()
	return t
}

// node is node name of cg's graph, nil for none or without a graph (a
// grant that doesn't read the node documents, writeTree).
func (cg *catGraph) node(name string) *tree.Node {
	if cg == nil {
		return nil
	}
	return cg.g.Node(name)
}

// headOf is node name's head as cg read it, "" without a graph.
func (cg *catGraph) headOf(name string) string {
	if cg == nil {
		return ""
	}
	return cg.heads[name]
}

// listed reports whether a node can be in the tree: not on a cycle (§B.5)
// and, for a placement, named {ns}.{name} (§B.2).
func listed(n *tree.Node) bool {
	return n != nil && !n.Cyclic && (n.Kind == kindFolder || n.ItemNS != "")
}

// children lists the nodes in folder that can be in the tree.
func (cg *catGraph) children(folder string) []*tree.Node {
	var out []*tree.Node
	for _, c := range cg.g.Children(folder) {
		if listed(c.Node) {
			out = append(out, c.Node)
		}
	}
	return out
}

// folderName reports whether s can name a folder node: a resource name
// without a dot (§3.6, §B.2).
func folderName(s string) bool { return client.ValidResourceName(s) && !strings.Contains(s, ".") }

// treeEntry is a child of a folder as the tree shows it (§H.2): a folder
// node, or a placement whose item is live and offered, by its name there,
// with its item's head, and, listed by a tree service, its file's
// metadata and time (§H.3), if it gave them.
type treeEntry struct {
	name string
	node *tree.Node
	item *client.Head
	// escaped: its title breaks the rules, and is shown escaped (shown)
	escaped  bool
	meta     *fileMeta
	modified time.Time
	order    string // its order in the folder, as a tree service listed it (§B.2)
}

// newTreeEntry is node n's entry, with its item's head, by the name it is
// shown by before duplicates are numbered (nameDir).
func newTreeEntry(n *tree.Node, item *client.Head) treeEntry {
	return treeEntry{name: nodeName(n), node: n, item: item, escaped: n.Title != "" && shown(n.Title) != n.Title}
}

// treeDir is a folder's children as the tree shows them, by name and by
// nameKey; roots: the top level of a tree whose files.root is hidden from
// the reader, its roots (§B.11.5, §H.3), whose parents it can't see.
type treeDir struct {
	entries []treeEntry
	byName  map[string]int
	byKey   map[string]int
	roots   bool
}

// find returns the child named name, or whose name has name's nameKey
// (a client whose file system ignores case asks for it so), and whether
// name is its name, in NFC, as listed, rather than another case of it.
func (d *treeDir) find(s *Server, name string) (*treeEntry, bool) {
	if i, ok := d.byName[name]; ok {
		return &d.entries[i], true
	}
	if i, ok := d.byKey[s.nameKey(name)]; ok {
		return &d.entries[i], norm.NFC.String(name) == d.entries[i].name
	}
	return nil, false
}

// treeDir returns folder's children in catalog cat as the tree shows
// them (§H.2), once per request: listed by the catalog's tree service
// (serviceDir, §H.3), else from its node documents (nodeDir), and named
// alike whichever lists them (nameDir).
func (st *reqState) treeDir(ctx context.Context, cat, folder string) (*treeDir, error) {
	k := cat + "/" + folder
	if d := st.dirs[k]; d != nil {
		return d, nil
	}
	c, err := st.treeConf(ctx, cat)
	if err != nil {
		return nil, err
	}
	var d *treeDir
	if st.s.viaService(cat, c) {
		d, err = st.serviceDir(ctx, cat, folder, c)
	} else {
		d, err = st.nodeDir(ctx, cat, folder)
	}
	if err != nil {
		return nil, err
	}
	if st.dirs == nil {
		st.dirs = map[string]*treeDir{}
	}
	st.dirs[k] = d
	return d, nil
}

// nodeDir lists folder's children in catalog cat from its node documents
// (graph): folders, and placements whose items are live, offered (§H.7)
// and readable with the principal's grant (§B.11.5: nothing hidden from
// it shows). A placement of a namespace the catalog doesn't trust is
// left out too, as dangling (§B.5, §H.2 "Untrusted namespaces"), whether
// or not a tree service lists the catalog, as one leaves it out: either
// lists a folder alike.
func (st *reqState) nodeDir(ctx context.Context, cat, folder string) (*treeDir, error) {
	cg, _, err := st.tree(ctx, cat)
	if err != nil {
		return nil, err
	}
	c, err := st.treeConf(ctx, cat)
	if err != nil {
		return nil, err
	}
	var kids []*tree.Node
	for _, n := range cg.children(folder) {
		if n.Kind == kindFolder || slices.Contains(c.trust, n.ItemNS) {
			kids = append(kids, n)
		}
	}
	sealed := map[string]bool{}
	for _, n := range kids {
		if _, ok := sealed[n.ItemNS]; n.Kind != kindFolder && !ok {
			sealed[n.ItemNS] = st.s.nsInfo(ctx, st.tk, n.ItemNS).sealed
		}
	}
	heads := make([]*client.Head, len(kids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(st.s.opt.FetchConcurrency)
	for i, n := range kids {
		if n.Kind == kindFolder || sealed[n.ItemNS] {
			continue
		}
		g.Go(func() error {
			h, err := cg.itemHead(st.tk)(gctx, n.ItemNS, n.ItemName)
			switch {
			case hidden(err):
			case err != nil:
				return err
			case h.State == client.Live:
				heads[i] = h
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var entries []treeEntry
	for i, n := range kids {
		if n.Kind != kindFolder && heads[i] == nil {
			continue
		}
		entries = append(entries, newTreeEntry(n, heads[i]))
	}
	return st.s.nameDir(entries, func(node string) time.Time { return cg.born(ctx, st.tk, node) }), nil
}

// nameDir names a folder's children, entries (newTreeEntry), as the tree
// shows them (§H.2): each by its title, shown escaped if another tool
// wrote one that breaks the rules (shown), a placement without one by its
// item's name and a folder by its node's. Siblings whose names compare
// equal (nameKey), as a race leaves them, are shown as name (2).ext,
// name (3).ext, … in order of their nodes' creation (born, then name),
// the first keeping its name, skipping numbers whose names a sibling has;
// a title shown escaped comes after those that aren't, so it never takes
// the name of a real one.
func (s *Server) nameDir(entries []treeEntry, born func(node string) time.Time) *treeDir {
	d := &treeDir{entries: entries, byName: map[string]int{}, byKey: map[string]int{}}
	groups := map[string][]int{}
	for i, e := range d.entries {
		k := s.nameKey(e.name)
		groups[k] = append(groups[k], i)
	}
	taken := map[string]bool{}
	var dups []string
	for k, is := range groups {
		taken[k] = true
		if len(is) > 1 {
			dups = append(dups, k)
		}
	}
	sort.Strings(dups)
	for _, k := range dups {
		is := groups[k]
		at := map[int]time.Time{}
		for _, i := range is {
			at[i] = born(d.entries[i].node.Name)
		}
		sort.SliceStable(is, func(a, b int) bool {
			if ea, eb := d.entries[is[a]].escaped, d.entries[is[b]].escaped; ea != eb {
				// A title shown escaped never takes the name of one that
				// is so (§H.2 "Titles").
				return eb
			}
			ta, tb := at[is[a]], at[is[b]]
			if ta.IsZero() != tb.IsZero() {
				return !ta.IsZero()
			}
			if !ta.Equal(tb) {
				return ta.Before(tb)
			}
			return d.entries[is[a]].node.Name < d.entries[is[b]].node.Name
		})
		for _, i := range is[1:] {
			e := &d.entries[i]
			e.name = dupName(e.name, e.node.Kind == kindFolder, func(n string) bool { return taken[s.nameKey(n)] })
			taken[s.nameKey(e.name)] = true
		}
	}
	for i, e := range d.entries {
		d.byName[e.name] = i
		d.byKey[s.nameKey(e.name)] = i
	}
	return d
}

// nodeName is the name node n is shown by before duplicates are
// numbered (treeDir): its title (shown), else, a placement's, its item's
// name, a folder's its own.
func nodeName(n *tree.Node) string {
	switch name := shown(n.Title); {
	case name != "":
		return name
	case n.Kind == kindFolder:
		return n.Name
	}
	return n.ItemName
}

// childFolder returns folder's child folder named seg where that needs
// none of the folder's items read: the one child, of any kind, shown or
// not, whose name (nodeName) compares equal to seg's is a folder, which
// keeps its name; else nil, and treeDir decides.
func (st *reqState) childFolder(cg *catGraph, folder, seg string) *tree.Node {
	key := st.s.nameKey(seg)
	var found *tree.Node
	for _, n := range cg.children(folder) {
		if st.s.nameKey(nodeName(n)) == key {
			if found != nil {
				return nil
			}
			found = n
		}
	}
	if found != nil && found.Kind == kindFolder {
		return found
	}
	return nil
}

// resolveCatalog resolves the path segments after a tree's name: a chain
// of folders, each in the one before, then the last name: a folder or a
// file there, else a scratch name (§H.6; a name a node has is the node's,
// whatever it looks like), or a new node a title can name, or a name no
// file or folder can have (titleWhy).
//
// Through a tree service, a path names what its folders list (treeDir),
// which lags the core and isn't made to wait for other users' writes
// through this server: a name another user renamed, moved or deleted a
// moment ago is still listed, and one they just gave a file isn't yet. A
// write (writes) checks what the listing named against the node
// documents (agrees): every node it named still there, in that folder,
// by that name, and no node of the core's by a name it didn't list.
// Where they disagree, read again if read before the request, the path
// is resolved from the node documents, as without a tree service: a DELETE or MOVE of a name renamed since is a 404, never the
// renamed file's, and a PUT of a name a sibling has now is that
// sibling's, never a second file by its name (§H.2 "Siblings"). A folder
// over what a listing takes (tooBig) has its names found in its node
// documents (nodeChild), a few of its items read, rather than refused.
func (st *reqState) resolveCatalog(ctx context.Context, t target, segs []string) (target, error) {
	c, err := st.treeConf(ctx, t.ns)
	if err != nil {
		return t, err
	}
	if st.byNodes[t.ns] {
		cg, _, err := st.tree(ctx, t.ns)
		if err != nil {
			return t, err
		}
		return st.resolveIn(ctx, t, segs, c, func(ctx context.Context, folder, seg string, _ bool) (*treeEntry, bool, error) {
			return st.nodeChild(ctx, cg, t.ns, folder, seg)
		}, nil)
	}
	if !st.s.viaService(t.ns, c) {
		// The node documents: a path's folders above need none of their
		// items read (childFolder).
		cg, _, err := st.tree(ctx, t.ns)
		if err != nil {
			return t, err
		}
		return st.resolveIn(ctx, t, segs, c, func(ctx context.Context, folder, seg string, last bool) (*treeEntry, bool, error) {
			if !last {
				if n := st.childFolder(cg, folder, seg); n != nil {
					e := newTreeEntry(n, nil)
					return &e, true, nil
				}
			}
			d, err := st.treeDir(ctx, t.ns, folder)
			if err != nil {
				return nil, false, err
			}
			e, exact := d.find(st.s, seg)
			return e, exact, nil
		}, nil)
	}
	if !st.writes() {
		// A read: one lookup of the whole path (§B.5, §H.3), unless its
		// folders were listed already, or it doesn't resolve so.
		if r, ok, err := st.lookupPath(ctx, t, segs, c); err != nil || ok {
			return r, err
		}
	}
	var steps []pathStep
	depth := 0
	r, err := st.resolveIn(ctx, t, segs, c, func(ctx context.Context, folder, seg string, _ bool) (*treeEntry, bool, error) {
		depth++
		d, err := st.treeDir(ctx, t.ns, folder)
		var de *davError
		if errors.As(err, &de) && de.tooBig {
			// A folder too large to list: the name by lookup (§H.3), else,
			// one lookup doesn't resolve (a duplicate's number, an escaped
			// title, a node shown by its name), from the node documents.
			// Lookup doesn't wait for the user's own writes (?min): while
			// the tree service is to reach them, the node documents decide.
			mins, _ := st.p.ts.mins(append([]string{t.ns}, c.trust...), st.s.opt.Now())
			waiting := len(mins) > 0
			if !waiting {
				e, exact, found, lerr := st.lookupEntry(ctx, t.ns, segs[:depth])
				switch {
				case lerr != nil:
					return nil, false, lerr
				case found:
					return e, exact, nil
				}
			}
			cg, _, gerr := st.tree(ctx, t.ns)
			if gerr == nil {
				return st.nodeChild(ctx, cg, t.ns, folder, seg)
			}
			if _, _, dup := dupOf(seg); waiting || dup || strings.Contains(seg, "%") {
				return nil, false, err
			}
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		e, exact := d.find(st.s, seg)
		return e, exact, nil
	}, &steps)
	if err != nil || !st.writes() {
		return r, err
	}
	cg, _, err := st.tree(ctx, t.ns)
	var de *davError
	switch {
	case err != nil && errors.As(upstream(err), &de) && (de.status == http.StatusUnauthorized || de.status == http.StatusForbidden || de.status == http.StatusNotFound):
		// A grant that doesn't read the node documents (§H.7 "Limited
		// grants"), which the core answers 404 for the catalog's /heads
		// (§7), as behindDir finds, has only the listing to go by.
		return r, nil
	case err != nil || st.agrees(cg, steps):
		return r, err
	}
	if !st.fresh[t.ns] {
		// Read before the request, maybe before what the listing shows
		// (another server's write): read again.
		if cg, err = st.freshGraph(ctx, t.ns); err != nil {
			return r, err
		}
		if st.agrees(cg, steps) {
			return r, nil
		}
	}
	if st.byNodes == nil {
		st.byNodes = map[string]bool{}
	}
	st.byNodes[t.ns] = true
	return st.resolveCatalog(ctx, t, segs)
}

// pathStep is one name a path's resolution looked up (resolveCatalog):
// in folder parent ("" at the top level from roots, whose parents the
// reader can't see), the node found (none: "") and the name it was found
// by, before duplicates were numbered (nodeName), else the name asked
// for.
type pathStep struct {
	parent, node, name string
}

// finder returns folder's child named seg, the path's last name or one
// of its folders, and whether seg is its name, as listed, rather than
// another case of it.
type finder func(ctx context.Context, folder, seg string, last bool) (*treeEntry, bool, error)

// resolveIn resolves segs below t.ns's files.root with find, recording
// each name looked up in steps, if not nil.
func (st *reqState) resolveIn(ctx context.Context, t target, segs []string, c catConf, find finder, steps *[]pathStep) (target, error) {
	folder := c.files.root
	for i, seg := range segs {
		last := i == len(segs)-1
		e, exact, err := find(ctx, folder, seg, last)
		if err != nil {
			return t, err
		}
		top := i == 0 && st.rootsTop(t.ns, folder)
		if steps != nil {
			s := pathStep{parent: folder, name: seg}
			if top {
				s.parent = ""
			}
			if e != nil {
				s.node, s.name = e.node.Name, nodeName(e.node)
			}
			*steps = append(*steps, s)
		}
		if !last {
			if e == nil || e.node.Kind != kindFolder {
				t.kind = kMissing
				return t, nil
			}
			folder = e.node.Name
			continue
		}
		t.parent, t.hiddenTop = folder, top
		if e != nil {
			t.node, t.title, t.listedAs, t.otherCase = e.node.Name, e.name, nodeName(e.node), !exact
			if e.node.Kind == kindFolder {
				t.kind = kFolder
			} else {
				t.kind, t.docNS, t.docName = kPlacement, e.node.ItemNS, e.node.ItemName
			}
			return t, nil
		}
	}
	last := segs[len(segs)-1]
	if scratchName(last) || st.isScratchDir(t.path) {
		return st.scratchAt(t, false), nil
	}
	title, err := newTitle(last)
	if err != nil {
		t.kind = kBadName
		return t, nil
	}
	t.kind, t.title = kNewNode, title
	t.hiddenTop = len(segs) == 1 && st.rootsTop(t.ns, t.parent)
	return t, nil
}

// rootsTop reports whether folder is the files.root of catalog cat whose
// top level the request listed as its roots, files.root being hidden
// from the reader (serviceDir, §B.11.5).
func (st *reqState) rootsTop(cat, folder string) bool {
	d := st.dirs[cat+"/"+folder]
	return d != nil && d.roots
}

// topWrite refuses a write that changes the top level of a tree whose
// files.root is hidden from the reader, that top level its roots
// (hiddenTop, §B.11.5, §H.3): a new file or folder there would go into
// files.root, which the catalog answers as a folder not in it (404,
// §B.11.4); a node there has parents hidden from the reader, which a
// grant would name, so only catalog-admins move, rename, unplace or
// delete it (403, §B.11.4). A file's content is edited there as anywhere.
func topWrite(t target) error {
	switch {
	case !t.hiddenTop:
		return nil
	case t.kind == kNewNode:
		return fail(http.StatusNotFound, "%s can't be made: the top level of catalog %s shown to you is the folders and files you can see whose parents you can't (§B.11.5), and a new one there would go into its files.root, %s, which is hidden from you (§B.11.4)", t.path, t.ns, t.parent)
	}
	return fail(http.StatusForbidden, "%s is at the top level of catalog %s shown to you, whose parents you can't see (§B.11.5): only catalog-admins move, rename, unplace or delete it (§B.11.4)", t.path, t.ns)
}

// writes reports whether the request writes to the core where its paths
// lead (a COPY's source is read for the copy, which a stale name would
// misdirect too).
func (st *reqState) writes() bool {
	switch st.method {
	case "PUT", "DELETE", "MOVE", "COPY", "MKCOL":
		return true
	}
	return false
}

// agrees reports whether catalog graph cg holds what a path's resolution
// looked up (steps) as a tree service listed it: each node found still
// in its folder, by the name it was found by (nameKey), and, where none
// was, no node in the folder whose name compares equal to the one asked
// for (one hidden from the token, or dangling, is the node documents'
// to rule out). At a top level from roots (parent ""), whose parents
// the token can't see, a node is checked for its name only.
func (st *reqState) agrees(cg *catGraph, steps []pathStep) bool {
	for _, s := range steps {
		key := st.s.nameKey(s.name)
		if s.parent == "" {
			if n := cg.g.Node(s.node); s.node != "" && (!listed(n) || st.s.nameKey(nodeName(n)) != key) {
				return false
			}
			continue
		}
		if s.node == "" {
			for _, n := range cg.children(s.parent) {
				if st.s.nameKey(nodeName(n)) == key {
					return false
				}
			}
			continue
		}
		n := cg.g.Node(s.node)
		if !listed(n) || !slices.Contains(cg.g.WalkableParents(n), s.parent) || st.s.nameKey(nodeName(n)) != key {
			return false
		}
	}
	return true
}

// nodeChild returns folder's child named seg in catalog cat as nodeDir
// would list it, reading only the items of the children whose names
// compare equal to seg (nameKey), which a folder of thousands needs: the
// one such child shown to the token (a folder, or a placement whose item
// is live, offered and readable with its grant, in a namespace the
// catalog trusts, §H.2). With several such, or none where seg may be a
// duplicate's numbered name, the folder is listed whole (nodeDir).
func (st *reqState) nodeChild(ctx context.Context, cg *catGraph, cat, folder, seg string) (*treeEntry, bool, error) {
	c, err := st.treeConf(ctx, cat)
	if err != nil {
		return nil, false, err
	}
	key := st.s.nameKey(seg)
	var found []treeEntry
	for _, n := range cg.children(folder) {
		if st.s.nameKey(nodeName(n)) != key {
			continue
		}
		if n.Kind == kindFolder {
			found = append(found, newTreeEntry(n, nil))
			continue
		}
		if !slices.Contains(c.trust, n.ItemNS) || st.s.nsInfo(ctx, st.tk, n.ItemNS).sealed {
			continue
		}
		h, err := cg.itemHead(st.tk)(ctx, n.ItemNS, n.ItemName)
		switch {
		case hidden(err):
		case err != nil:
			return nil, false, err
		case h.State == client.Live:
			found = append(found, newTreeEntry(n, h))
		}
	}
	if _, _, dup := dupOf(seg); len(found) > 1 || len(found) == 0 && dup {
		d, err := st.nodeDir(ctx, cat, folder)
		if err != nil {
			return nil, false, err
		}
		e, exact := d.find(st.s, seg)
		return e, exact, nil
	}
	if len(found) == 0 {
		return nil, false, nil
	}
	e := found[0]
	return &e, norm.NFC.String(seg) == e.name, nil
}

// treePath reports whether p, of at most maxRefusedPath bytes, may name a
// file in a served tree, {cat}/…/{title}, whatever the tree holds.
func (st *reqState) treePath(p string) bool {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	base := segs[len(segs)-1]
	if len(segs) < 2 || len(p) > maxRefusedPath || !st.s.cats[segs[0]] || scratchName(base) {
		return false
	}
	_, err := newTitle(base)
	return err == nil
}

// orderAfter is an order key after folder's last ordered child (§B.2), so
// a node placed there lists last (§H.2 "Shape"); "" where none fits.
func (cg *catGraph) orderAfter(folder string) string {
	last := ""
	for _, c := range cg.g.Children(folder) {
		if c.HasOrder {
			last = c.Order
		}
	}
	return keyAfter(last)
}

// nodeDoc is a new node's document (§H.2): $schema (files.folder or
// files.placement, "" for none), its title, and one parent, folder, with
// an order after its last child.
func (cg *catGraph) nodeDoc(schema, title, folder string) map[string]any {
	parent := map[string]any{"href": "/r/" + cg.cat + "/" + folder}
	if o := cg.orderAfter(folder); o != "" {
		parent["order"] = o
	}
	doc := map[string]any{"title": title, "parents": []any{parent}}
	if schema != "" {
		doc["$schema"] = schema
	}
	return doc
}

// mkFolder makes folder t.title in folder t.parent (MKCOL): a new folder
// node with an opaque name (§H.2).
func (st *reqState) mkFolder(ctx context.Context, t target) error {
	_, err := st.makeFolder(ctx, t)
	return err
}

// makeFolder is mkFolder, returning the new folder node's name.
func (st *reqState) makeFolder(ctx context.Context, t target) (string, error) {
	if err := topWrite(t); err != nil {
		return "", err
	}
	cg, f, err := st.writeTree(ctx, t.ns)
	if err != nil {
		return "", err
	}
	name := newName()
	doc := st.nodeDocFor(t.ns, cg, f.folder, t.title, t.parent)
	switch d, err := st.derived(ctx, t.ns); {
	case err != nil:
		return "", err
	case d:
		// Under a Create a folder grant (§B.11.4).
		g, err := st.issue(ctx, t.ns, map[string]any{"node": name, "want": []any{"create"}, "to": []any{t.parent}})
		if err != nil {
			return "", err
		}
		return name, st.createIssued(ctx, t.ns, name, g, doc)
	}
	return name, st.createNode(ctx, t.ns, name, doc)
}

// newFile creates file t.title in folder t.parent of tree t.ns with body,
// raw or JSON value v (§H.4 "New files"), unless it restores a file of
// that path the principal deleted moments ago (restoreFile). The tree
// must trust files.ns. A new item there, with an opaque name, is created
// (If-None-Match: *; a raw file's blob uploaded first) once a dry run of
// its placement (§7.5) says the core takes it, so a placement it refuses
// (a frozen catalog, a grant that doesn't write it, the catalog's rules)
// writes nothing; then it is placed, and one refused still, the catalog
// having changed in between, deletes the new item again at once. Where
// grants come from the catalog (§B.11), the placement comes first
// (placeFirst). It never deletes unplaced items it didn't just create:
// another gateway may be in the middle of a create (§H.4, blobGrace).
func (st *reqState) newFile(ctx context.Context, t target, raw bool, v any, body []byte) (string, bool, error) {
	if rev, exact, done, err := st.restoreFile(ctx, t, raw, v, body); done {
		return rev, exact, err
	}
	if err := topWrite(t); err != nil {
		return "", false, err
	}
	// A new file's kind is its name's and content's (§H.1), whatever the
	// file deleted at its path was.
	raw, v = newKind(t.title, body)
	cg, f, err := st.writeTree(ctx, t.ns)
	if err != nil {
		return "", false, err
	}
	c, err := st.treeConf(ctx, t.ns)
	if err != nil {
		return "", false, err
	}
	if !c.trusts(f.ns) {
		return "", false, fail(http.StatusForbidden, "catalog %s doesn't trust %s, the namespace its files.ns names for new files (§H.2, §H.4): no file is created", t.ns, f.ns)
	}
	if st.s.nsInfo(ctx, st.tk, f.ns).sealed {
		return "", false, notOffered(f.ns)
	}
	item := newName()
	node := f.ns + "." + item
	doc := st.nodeDocFor(t.ns, cg, f.placement, t.title, t.parent)
	switch d, err := st.derived(ctx, t.ns); {
	case err != nil:
		return "", false, err
	case d:
		return st.placeFirst(ctx, t, f, item, doc, raw, v, body)
	}
	if err := st.probeNode(ctx, t.ns, node, doc); err != nil {
		return "", false, err
	}
	var rev string
	var exact bool
	if raw {
		rev, exact, err = st.commitRaw(ctx, f.ns, item, body, saveOpts{pre: true, fresh: true, fname: t.title})
	} else {
		rev, exact, err = st.commitDoc(ctx, f.ns, item, v, body, saveOpts{pre: true, fresh: true})
	}
	if err != nil {
		return "", false, err
	}
	st.wroteTo = f.ns + "/" + item
	if err := st.createNode(ctx, t.ns, node, doc); err != nil {
		// Deleted at once, a 429 waited out as a write's is, whether or
		// not the client waits (§H.4): nothing else removes it.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		derr := st.retrying(dctx, func() (bool, error) {
			_, err := st.tk.c.Delete(dctx, f.ns, item, rev)
			return false, err
		})
		cancel()
		if derr != nil {
			st.s.opt.Logf("dav: %s/%s: deleting the item created for a placement the core refused: %v", f.ns, item, derr)
			return "", false, err
		}
		if de, ok := upstream(err).(*davError); ok {
			out := *de
			out.msg += fmt.Sprintf(" (%s/%s, created for it, is deleted again)", f.ns, item)
			return "", false, &out
		}
		return "", false, err
	}
	return rev, exact, nil
}

// restoreFile writes body to file t as the restore of the file of that
// path the principal deleted within ownDeleteUndo (§H.6 "Delete, then
// write"), done says if it did: its placement restored as it was, then
// its item, if the DELETE deleted it, restored with body rebased on its
// last live document (§8.2), else edited. A restore the core refuses
// (403, 410), or one of a file moved away since (its item's last document
// has $successor), isn't done: the write creates a new file. If the
// item's write is refused, the DELETE is undone (undoOwnDelete).
func (st *reqState) restoreFile(ctx context.Context, t target, raw bool, v any, body []byte) (string, bool, bool, error) {
	d, ok := st.p.treeDeleted(t.path, st.s.opt.Now())
	if !ok || d.cat != t.ns || d.parent != t.parent {
		return "", false, false, nil
	}
	if derived, err := st.derived(ctx, t.ns); err != nil || derived {
		// Restored under grants the catalog issues for it, a Place grant
		// carrying restore and a Restore grant (§B.11.4), which this
		// server doesn't ask for: the write makes a new file (§H.6).
		return "", false, false, nil
	}
	in := st.s.nsInfo(ctx, st.tk, d.cat)
	h, err := st.tk.c.Head(ctx, d.cat, d.node)
	if err != nil {
		return "", false, true, err
	}
	if h.State != client.Tombstoned || h.ID != d.nodeTomb {
		return "", false, false, nil
	}
	if d.itemTomb != "" {
		ih, err := st.tk.c.Head(ctx, d.itemNS, d.itemName)
		if err != nil {
			return "", false, true, err
		}
		if ih.State != client.Tombstoned || ih.ID != d.itemTomb || ih.Successor != "" {
			return "", false, false, nil
		}
		if last, err := st.s.doc(ctx, st.tk, d.itemNS, d.itemName, ih.Last); err == nil && client.SuccessorOf(last.value) != "" {
			return "", false, false, nil
		}
	}
	if _, err := st.tk.c.Restore(ctx, d.cat, d.node, d.nodeTomb, withNonce(in, nil, []any{})); err != nil {
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == http.StatusForbidden || ae.Status == http.StatusGone || ae.Status == http.StatusPreconditionFailed) {
			return "", false, false, nil
		}
		return "", false, true, err
	}
	st.committed = true
	st.changed()
	var rev string
	var exact bool
	if raw {
		rev, exact, err = st.commitRaw(ctx, d.itemNS, d.itemName, body, saveOpts{pre: true, fname: t.title})
	} else {
		rev, exact, err = st.commitDoc(ctx, d.itemNS, d.itemName, v, body, saveOpts{pre: true})
	}
	if err == nil {
		st.p.forgetTreeDelete(t.path)
		st.wroteTo = d.itemNS + "/" + d.itemName
	}
	return rev, exact, true, err
}

// probeNode asks the core whether it takes catalog node name with doc, as
// createNode writes it, in a dry run (§7.5), which writes nothing: a
// frozen catalog, a grant that doesn't write it, or its rules refuse it
// as they would the write.
func (st *reqState) probeNode(ctx context.Context, cat, name string, doc map[string]any) error {
	in := st.s.nsInfo(ctx, st.tk, cat)
	h, err := st.tk.c.Head(ctx, cat, name)
	if err != nil {
		return upstream(err)
	}
	it := client.BatchItem{Resource: name}
	switch h.State {
	case client.Live:
		return fail(http.StatusConflict, "%s is already in catalog %s", name, cat)
	case client.Purged:
		return purgedErr(cat, name)
	case client.Tombstoned:
		it.IfMatch = h.ID
		it.Steps = []client.Step{client.PatchStep(withNonce(in, doc, []any{map[string]any{"op": "replace", "path": "", "value": doc}}))}
	default:
		it.IfNoneMatch = true
		it.Steps = []client.Step{client.PatchStep(withNonce(in, doc, client.GenesisPatches(doc)))}
	}
	res, err := st.tk.c.Batch(ctx, cat, client.BatchRequest{Items: []client.BatchItem{it}}, true)
	if err != nil {
		return upstream(batchErr(err))
	}
	for _, r := range res.Items {
		status, _ := r.Raw["status"].(float64)
		switch ie := itemError(r.Raw); {
		case status < 300:
		case ie.Status == http.StatusPreconditionFailed, goneSince(ie):
			// Made, or deleted, since its head was read: 412 or, a
			// tombstone from v0.73, 410 gone (§7.2).
			return fail(http.StatusConflict, "%s was made or deleted in catalog %s meanwhile; try again", name, cat)
		default:
			return upstream(ie)
		}
	}
	return nil
}

// batchErr is a batch's refusal (§7.5) as a single write's: its first
// failing item's own failure, else err.
func batchErr(err error) error {
	if ae, ok := client.AsAPIError(err); ok && ae.Code == "batch" && len(ae.Items()) > 0 {
		return itemError(ae.Items()[0])
	}
	return err
}

// itemError is a batch item's failure (§7.5) as a single write's error.
func itemError(m map[string]any) *client.APIError {
	status, _ := m["status"].(float64)
	code, _ := m["code"].(string)
	return &client.APIError{Status: int(status), Code: code, Body: m}
}

// writable refuses a write through a placement to an item this server
// doesn't write: one in a catalog (a node document, which takes only the
// writes of MKCOL, MOVE and DELETE here), or in a namespace neither served
// (-ns) nor trusted by the catalog (§B.3), which a local mode's grant may
// reach though the server wasn't set up to serve it. The catalog's trust
// is as the tree is listed with (treeConf): for a grant that doesn't read
// the catalog's document (§H.7 "Limited grants"), as last read with any.
func (st *reqState) writable(ctx context.Context, t target) error {
	if t.kind != kPlacement {
		return nil
	}
	if st.s.cats[t.docNS] || t.docNS == t.ns {
		return fail(http.StatusForbidden, "%s is a placement of catalog node %s/%s; its file isn't written here (folders are made, renamed, moved and deleted as directories)", t.path, t.docNS, t.docName)
	}
	if st.s.flat[t.docNS] {
		return nil
	}
	if c, err := st.treeConf(ctx, t.ns); err == nil && c.trusts(t.docNS) {
		return nil
	}
	return fail(http.StatusForbidden, "catalog %s doesn't trust namespace %s (§B.3), and it isn't served here (-ns): %s, a placement of %s/%s, isn't written through the catalog", t.ns, t.docNS, t.path, t.docNS, t.docName)
}

// createNode creates catalog node name with doc (If-None-Match: *), or
// restores it with doc if it is tombstoned (§8.2), with a fresh $nonce
// where the catalog requires one (§H.7).
func (st *reqState) createNode(ctx context.Context, cat, name string, doc map[string]any) error {
	in := st.s.nsInfo(ctx, st.tk, cat)
	defer st.changed()
	return st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, cat, name)
		if err != nil {
			return false, err
		}
		switch h.State {
		case client.Live:
			return false, fail(http.StatusConflict, "%s is already in catalog %s", name, cat)
		case client.Purged:
			return false, purgedErr(cat, name)
		case client.Tombstoned:
			_, err = st.tk.c.Restore(ctx, cat, name, h.ID, withNonce(in, doc, []any{map[string]any{"op": "replace", "path": "", "value": doc}}))
		default:
			_, err = st.tk.c.Create(ctx, cat, name, withNonce(in, doc, client.GenesisPatches(doc)))
		}
		switch {
		case goneSince(err):
			// Tombstoned since its head was read (410 from v0.73, §7.2):
			// restored, read again.
			return true, nil
		case client.IsStale(err):
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile", cat, name)
		}
		st.committed = st.committed || err == nil
		return false, err
	})
}

// deleteFile deletes file t of a tree (§H.5 "Delete a file"): its
// placement, then, where the tree owns the item's namespace (files.ns,
// §H.2) and the grant allows it, its item, with $successor first where
// successor names where it went (moveAcross); otherwise the item stays,
// unplaced. A failure between the two leaves it so too (§H.4). With
// ifMatch (a DELETE's If-Match, the revision a MOVE copied), an item
// whose head isn't that revision is a 412, before anything is written,
// or, if it changed between the check and its delete, after its
// placement is restored as it was. Without one, the item is deleted with
// If-Match on the head read here, and one changed since that read is a
// 409 (movedSinceRead), its placement restored as it was too: an edit
// made meanwhile isn't tombstoned unseen (§H.5). The placement is deleted
// only as the node documents read had it (If-Match), which resolveCatalog
// checked the path against: renamed or moved since by anyone, it is a
// 409, not deleted. A node with several parents (a DAG) is unlinked from this
// folder only, while it still has the name and parent the path named
// (unlink). A principal's DELETE is remembered a while, so its write
// of the path restores the file (§H.6).
func (st *reqState) deleteFile(ctx context.Context, t target, ifMatch, successor string) error {
	if err := topWrite(t); err != nil {
		return err
	}
	cg, f, err := st.writeTree(ctx, t.ns)
	if err != nil {
		return err
	}
	derived, err := st.derived(ctx, t.ns)
	if err != nil {
		return err
	}
	if err := st.itemAccess(ctx, t, false); err != nil {
		return err
	}
	h, err := st.head(ctx, t.docNS, t.docName)
	if err != nil {
		return err
	}
	if ifMatch != "" && (h.State != client.Live || h.ID != ifMatch) {
		return fail(http.StatusPreconditionFailed, "%s changed since %s (If-Match); reload it", t.path, ifMatch)
	}
	several, nodeHead, err := st.placedIn(ctx, t, cg, derived)
	if err != nil {
		return err
	}
	if several {
		return st.unlink(ctx, t)
	}
	var ptomb string
	if derived {
		// Under an Unplace grant (§B.11.4), with If-Match on the head the
		// node documents had, or the catalog decided, where read.
		ptomb, err = st.unplace(ctx, t.ns, t.node, nodeHead)
	} else {
		ptomb, err = st.deleteDoc(ctx, t.ns, t.node, nodeHead)
	}
	if err != nil {
		return changedSince(t, err)
	}
	d := treeDelete{cat: t.ns, node: t.node, nodeTomb: ptomb, parent: t.parent, itemNS: t.docNS, itemName: t.docName}
	if t.docNS == f.ns {
		match := ifMatch
		if match == "" && h.State == client.Live {
			match = h.ID
		}
		d.itemTomb, err = st.deleteItem(ctx, t.docNS, t.docName, match, successor)
		var de *davError
		switch {
		case err == nil, errors.Is(err, errNotExist):
		case errors.As(err, &de) && de.status == http.StatusPreconditionFailed:
			// Changed since the check: the file stays, placed, as it is.
			st.undelete(ctx, st.s.nsInfo(ctx, st.tk, t.ns), t.ns, t.node, ptomb, nil)
			if ifMatch == "" {
				return movedSinceRead(t)
			}
			return de
		case errors.As(err, &de) && (de.status == http.StatusUnauthorized || de.status == http.StatusForbidden):
			// The grant doesn't delete there (under tree-derived access the
			// catalog's key never does, §B.11.3): the item stays, unplaced.
		default:
			st.s.opt.Logf("dav: %s: the placement is deleted, and %s/%s stays, unplaced: %v", t.path, t.docNS, t.docName, err)
		}
	}
	if st.method == "DELETE" {
		st.p.noteTreeDelete(t.path, d, st.s.opt.Now())
	}
	return nil
}

// placedIn reports whether node t.node of a tree, a file or folder deleted
// from folder t.parent, is in other folders too, a node with several
// parents (a DAG), which is unlinked from this one only (§H.5), and the
// head of its node document its delete is made on ("" for none read):
// from graph cg, where the grant reads the node documents (writeTree),
// else from the node's own document where it reads that, checked to
// still have the name and parent t's path named (404 otherwise), else,
// in a tree with tree-derived access (derived), from where the catalog
// has it now (catalogParents). A grant that reads neither can't have it
// checked (403), rather than delete it from every folder.
func (st *reqState) placedIn(ctx context.Context, t target, cg *catGraph, derived bool) (bool, string, error) {
	if cg != nil {
		n := cg.node(t.node)
		return n != nil && len(cg.g.WalkableParents(n)) > 1, cg.heads[t.node], nil
	}
	head, doc, err := st.nodeAsNamed(ctx, t)
	switch {
	case err != nil:
		return false, "", err
	case doc != nil:
		return len(catalogHrefs(t.ns, parentHrefs(doc["parents"]))) > 1, head, nil
	case derived:
		ps, h, err := st.catalogParents(ctx, t)
		if err != nil {
			return false, "", err
		}
		return len(catalogHrefs(t.ns, ps)) > 1, h, nil
	}
	return false, "", fail(http.StatusForbidden, "%s isn't deleted or moved: your grant doesn't read its node's document, %s/%s, so that it is still in this folder, and whether it is in others too, which a delete from one folder leaves it in (§H.5), can't be checked", t.path, t.ns, t.node)
}

// deleteItem tombstones ns/name (§8.1), if its head is ifMatch when that
// is given, and returns the tombstone; with successor, its last revision
// first sets $successor to it, in the same batch (§7.5), unless its root
// isn't an object, which can't carry one (§H.5).
func (st *reqState) deleteItem(ctx context.Context, ns, name, ifMatch, successor string) (string, error) {
	if successor == "" {
		return st.deleteDoc(ctx, ns, name, ifMatch)
	}
	in := st.s.nsInfo(ctx, st.tk, ns)
	var tomb string
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		if ifMatch != "" && h.ID != ifMatch {
			return false, fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", ns, name, ifMatch)
		}
		cur, err := st.s.doc(ctx, st.tk, ns, name, h.ID)
		if err != nil {
			return false, err
		}
		if _, obj := cur.value.(map[string]any); !obj {
			res, err := st.tk.c.Delete(ctx, ns, name, h.ID)
			if client.IsStale(err) {
				return true, nil
			}
			if err == nil {
				tomb = res.ID
				st.s.markOwn(st.p, ns, name, tomb)
			}
			return false, err
		}
		ps := withNonce(in, cur.value, []any{map[string]any{"op": "add", "path": "/$successor", "value": successor}})
		res, err := st.tk.c.Batch(ctx, ns, client.BatchRequest{Items: []client.BatchItem{{Resource: name, IfMatch: h.ID,
			Steps: []client.Step{client.PatchStep(ps), client.DeleteStep()}}}}, false)
		err = batchErr(err)
		if client.IsStale(err) {
			return true, nil
		}
		if err == nil && len(res.Items) == 1 && len(res.Items[0].IDs) == 2 {
			tomb = res.Items[0].IDs[1]
			st.s.markOwn(st.p, ns, name, tomb)
		}
		st.committed = st.committed || err == nil
		return false, err
	})
	if errors.Is(err, errNotExist) {
		return "", errNotExist
	}
	return tomb, err
}

// deleteFolder deletes folder t of a tree (§H.5 "Delete a folder"): only
// one without visible children, which a 409 names; deleting a folder
// doesn't delete what is in it (§B.7). Its children are those of the node
// documents, read for this (freshGraph), as nodeDir lists them: never a
// tree service's listing, which lags the core (a file someone put in the
// folder a moment ago, or every file while the tree service catches up
// with a namespace), and would have the folder deleted over a file it
// orphans. Placements whose items are gone (dangling, §B.3) aren't
// contents, and are deleted first where the grant may (one it can't
// delete, 401 or 403, is orphaned, §H.5, as a hidden one is); those whose
// items the request's grant can't read are neither named nor deleted.
// The folder node is deleted as read (If-Match), and only while still
// named and placed as the path named it, which was checked against the
// token's kept graph (agrees), maybe older than this read: renamed or
// moved meanwhile, it is a 404 or a 409; a child placed while it is
// deleted is orphaned (§H.5), as one placed by another program always
// may be. A node with several parents (a DAG) is unlinked from this
// folder only (unlink). The scope's scratch files in it go with it.
func (st *reqState) deleteFolder(ctx context.Context, t target) error {
	if err := topWrite(t); err != nil {
		return err
	}
	cg, _, err := st.writeTree(ctx, t.ns)
	if err != nil {
		return err
	}
	if cg == nil {
		return noFolderDelete(t.ns, t.path)
	}
	derived, err := st.derived(ctx, t.ns)
	if err != nil {
		return err
	}
	if !st.fresh[t.ns] {
		if cg, err = st.freshGraph(ctx, t.ns); err != nil {
			return err
		}
	}
	n := cg.g.Node(t.node)
	if !listed(n) || !slices.Contains(cg.g.WalkableParents(n), t.parent) || st.s.nameKey(nodeName(n)) != st.s.nameKey(t.listedAs) {
		return fail(http.StatusNotFound, "folder %s was renamed, moved or deleted by someone else just now; reload its folder", t.path)
	}
	if len(cg.g.WalkableParents(n)) > 1 {
		return st.unlink(ctx, t)
	}
	d, err := st.nodeDir(ctx, t.ns, t.node)
	if err != nil {
		return err
	}
	if len(d.entries) > 0 {
		names := make([]string, 0, len(d.entries))
		for _, e := range d.entries {
			if e.node.Kind == kindFolder {
				names = append(names, strconv.Quote(e.name+"/"))
			} else {
				names = append(names, strconv.Quote(e.name))
			}
		}
		sort.Strings(names)
		return fail(http.StatusConflict, "folder %s isn't empty: it holds %s; deleting a folder doesn't delete what is in it (§B.7, §H.5), so delete or move those first", t.path, strings.Join(names, ", "))
	}
	for _, n := range cg.children(t.node) {
		if n.Kind == kindFolder || !st.dangling(ctx, cg, n) {
			continue
		}
		var err error
		if derived {
			_, err = st.unplace(ctx, t.ns, n.Name, "")
		} else {
			_, err = st.deleteDoc(ctx, t.ns, n.Name, "")
		}
		var de *davError
		switch {
		case err == nil, errors.Is(err, errNotExist):
		case errors.As(err, &de) && (de.status == http.StatusUnauthorized || de.status == http.StatusForbidden || derived && de.status == http.StatusNotFound):
			// Not the grant's to delete: orphaned with the folder (§B.7),
			// as a placement hidden from the caller is, never what stops
			// the folder's delete (§H.5 "Delete a folder").
			st.s.opt.Logf("dav: %s: dangling placement %s/%s isn't deleted, and is orphaned: %v", t.path, t.ns, n.Name, err)
		default:
			return err
		}
	}
	for _, name := range st.scratchUnder(t.path) {
		st.scratchRemove(name)
	}
	if derived {
		// Under a delete grant (§B.11.4), as the node documents read had
		// it.
		_, err = st.unplace(ctx, t.ns, t.node, cg.heads[t.node])
		return changedSince(t, err)
	}
	_, err = st.deleteDoc(ctx, t.ns, t.node, cg.heads[t.node])
	return changedSince(t, err)
}

// movedSinceRead is the answer for a DELETE without a tag (§H.5 "Delete
// a file") whose delete, with If-Match on the head the gateway read for
// it, found that head moved: someone else wrote the file in between,
// which isn't deleted unseen. A client's own If-Match that isn't the head
// is a 412 instead.
func movedSinceRead(t target) error {
	return fail(http.StatusConflict, "%s was changed by someone else while it was being deleted (§H.5), so it isn't deleted; reload it", t.path)
}

// changedSince is the answer for a DELETE of node t.node of a tree that
// found it changed since the node documents were read (412, If-Match on
// the head read): renamed or moved by someone else a moment ago, by
// another program than this server, which the DELETE isn't made over;
// err otherwise.
func changedSince(t target, err error) error {
	if de, ok := err.(*davError); ok && de.status == http.StatusPreconditionFailed {
		return fail(http.StatusConflict, "%s was changed by someone else just now (renamed or moved, maybe), so it isn't deleted; reload its folder", t.path)
	}
	return err
}

// stillNamed reports whether node doc, src.node's document as the core
// has it now, is still what src's path named: in folder src.parent, by
// the name it was found by (listedAs, nameKey).
func (st *reqState) stillNamed(src target, doc any) bool {
	m, _ := doc.(map[string]any)
	n := &tree.Node{Name: src.node, Kind: tree.KindPlacement, ItemNS: src.docNS, ItemName: src.docName}
	if src.kind == kFolder {
		n.Kind = kindFolder
	}
	n.Title, _ = m["title"].(string)
	if st.s.nameKey(nodeName(n)) != st.s.nameKey(src.listedAs) {
		return false
	}
	ps, _ := m["parents"].([]any)
	for _, x := range ps {
		p, _ := x.(map[string]any)
		href, _ := p["href"].(string)
		if ns, name, ok := tree.ParseHref(href); ok && ns == src.ns && name == src.parent {
			return true
		}
	}
	return false
}

// dangling reports whether placement n's item is gone (§B.3): tombstoned
// or purged, or missing from a namespace whose document the token reads
// (elsewhere a 404 may be the core hiding it, §7); or in a namespace the
// catalog doesn't trust, which no listing shows (§B.5, §H.2).
func (st *reqState) dangling(ctx context.Context, cg *catGraph, n *tree.Node) bool {
	if c, err := st.treeConf(ctx, cg.cat); err == nil && !c.trusts(n.ItemNS) {
		return true
	}
	if st.s.nsInfo(ctx, st.tk, n.ItemNS).sealed {
		return false
	}
	h, err := cg.itemHead(st.tk)(ctx, n.ItemNS, n.ItemName)
	switch {
	case err != nil:
		return false
	case h.State == client.Tombstoned, h.State == client.Purged:
		return true
	}
	if h.State != client.NotFound {
		return false
	}
	d, err := st.s.nsDoc(ctx, st.tk, n.ItemNS)
	return err == nil && d.readErr == nil
}

// moveNode renames or moves node src.node within its tree to dst (§H.5):
// one append to its title, its parents, or both, with If-Match on its
// head (again on the new head if it moved meanwhile, 412). dst is a new
// name (kNewNode), or src's own under another case, which compares equal
// (nameKey). A folder can't go into itself or a folder in it (403). In
// its new folder the node gets an order after the last child there. A
// node renamed or moved since its path was resolved, by anyone, is a
// 404 (stillNamed), never renamed or moved again over that, nor given a
// second parent. The scope's scratch files in a moved folder move with
// it.
func (st *reqState) moveNode(ctx context.Context, src, dst target) error {
	if err := topWrite(src); err != nil {
		return err
	}
	if err := topWrite(dst); err != nil && dst.kind == kNewNode {
		return err
	}
	cg, f, err := st.writeTree(ctx, src.ns)
	if err != nil {
		return err
	}
	title := dst.title
	if dst.kind != kNewNode {
		if title, err = newTitle(dst.base); err != nil {
			return err
		}
	}
	moved := dst.parent != src.parent
	d, err := st.derived(ctx, src.ns)
	if err != nil {
		return err
	}
	if moved && src.kind == kFolder {
		switch {
		case cg != nil && cg.g.Descendants([]string{src.node})[dst.parent]:
			return intoItself(src)
		case cg == nil && !d:
			// No graph, and no catalog that checks it for a Move grant
			// (§B.11.4): the folders above the new parent, as far as
			// the grant reads them.
			if err := st.notInto(ctx, f, src, dst); err != nil {
				return err
			}
		}
	}
	order := ""
	if moved {
		if cg != nil {
			order = cg.orderAfter(dst.parent)
		} else {
			order = st.listedOrderAfter(src.ns, dst.parent)
		}
	}
	if d {
		to := src.parent
		if moved {
			to = dst.parent
		}
		if err := st.moveIssued(ctx, src, title, src.parent, to, order); err != nil {
			return err
		}
		st.movedNode(src, dst)
		return nil
	}
	in := st.s.nsInfo(ctx, st.tk, src.ns)
	err = st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, src.ns, src.node)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		e, err := st.s.doc(ctx, st.tk, src.ns, src.node, h.ID)
		if err != nil {
			return false, err
		}
		if !st.stillNamed(src, e.value) {
			return false, fail(http.StatusNotFound, "%s was renamed or moved by someone else just now; reload its folder", src.path)
		}
		if src.kind == kFolder && st.srcMatch != "" && h.ID != st.srcMatch {
			return false, st.sourceMoved(src.path)
		}
		m, _ := e.value.(map[string]any)
		var ps []any
		if cur, ok := m["title"].(string); !ok || cur != title {
			ps = append(ps, map[string]any{"op": "add", "path": "/title", "value": title})
		}
		if moved {
			ps = append(ps, parentsEdit(src.ns, m["parents"], src.parent, dst.parent, order)...)
		}
		if len(ps) == 0 {
			return false, nil
		}
		_, err = st.tk.c.Append(ctx, src.ns, src.node, h.ID, withNonce(in, e.value, ps))
		if client.IsStale(err) {
			return true, nil
		}
		st.committed = st.committed || err == nil
		return false, err
	})
	st.changed()
	if err != nil {
		return err
	}
	st.movedNode(src, dst)
	return nil
}

// intoItself refuses to move folder src into itself or a folder in it
// (403, §H.5).
func intoItself(src target) error {
	return fail(http.StatusForbidden, "folder %s can't go into itself or a folder in it (§H.5)", src.path)
}

// maxAbove bounds the folders notInto reads above a new parent: past it,
// the move is refused as unchecked (§B.5's walks are bounded at depth
// 64; a DAG has more nodes than levels).
const maxAbove = 256

// notInto refuses to move folder src to dst, in a tree whose node
// documents the grant doesn't read whole (writeTree's nil graph), where
// dst's new parent is src or a folder in it (403, §H.5): a path below
// src's, or a folder whose parents, read upwards from dst.parent to
// files.root along every edge with the grant, reach src. One whose
// document the grant can't read, past which src may be, leaves it
// unchecked, and refused too (403); the race that could still make a
// cycle shows in the tree service's /problems (§B.5).
func (st *reqState) notInto(ctx context.Context, f *treeFiles, src, dst target) error {
	if dst.parent == src.node || strings.HasPrefix(dst.path, strings.TrimSuffix(src.path, "/")+"/") {
		return intoItself(src)
	}
	seen := map[string]bool{dst.parent: true}
	for queue := []string{dst.parent}; len(queue) > 0; queue = queue[1:] {
		n := queue[0]
		if n == f.root {
			continue
		}
		if len(seen) > maxAbove {
			return fail(http.StatusForbidden, "folder %s isn't moved: %s is below more than %d folders, too many to check that none of them is %s or in it (§H.5)", src.path, dst.dir, maxAbove, src.path)
		}
		h, err := st.tk.c.Head(ctx, src.ns, n)
		switch {
		case err == nil && (h.State == client.Tombstoned || h.State == client.Purged):
			// Gone: not an edge (§B.5).
			continue
		case err == nil && h.State == client.Live:
		case err == nil || hidden(err):
			return fail(http.StatusForbidden, "folder %s isn't moved: your grant doesn't read every folder above %s, so that none of them is %s or in it can't be checked (§H.5, §H.7 \"Limited grants\")", src.path, dst.dir, src.path)
		default:
			return err
		}
		e, err := st.s.doc(ctx, st.tk, src.ns, n, h.ID)
		switch {
		case hidden(err):
			return fail(http.StatusForbidden, "folder %s isn't moved: your grant doesn't read every folder above %s, so that none of them is %s or in it can't be checked (§H.5, §H.7 \"Limited grants\")", src.path, dst.dir, src.path)
		case err != nil:
			return err
		}
		m, _ := e.value.(map[string]any)
		for _, href := range parentHrefs(m["parents"]) {
			ns, name, ok := tree.ParseHref(href)
			switch {
			case !ok || ns != src.ns || seen[name]:
			case name == src.node:
				return intoItself(src)
			default:
				seen[name] = true
				queue = append(queue, name)
			}
		}
	}
	return nil
}

// movedNode moves what is kept by path for node src renamed or moved to
// dst: a folder's scratch files, a file's path records.
func (st *reqState) movedNode(src, dst target) {
	if src.kind == kFolder {
		st.scratchMoveUnder(src.path, dst.path)
	} else {
		st.s.forgetPath(st.p, src.path)
		st.s.notePath(st.p, dst.path, src.docNS, src.docName)
	}
}

// moveFolder is a MOVE of folder src: within its tree, a rename or a move
// (moveNode); to a new name in another tree, a new folder there that what
// is in src moves into (moveFolderAcross). A folder doesn't replace
// another folder or a file (§H.5), and the flat view has no folders
// (§H.2).
func (st *reqState) moveFolder(ctx context.Context, src, dst target) error {
	switch {
	case dst.kind == kFolder && dst.node == src.node && dst.ns == src.ns:
		return st.moveNode(ctx, src, dst)
	case dst.kind == kFolder, dst.kind == kCatDir:
		return fail(http.StatusForbidden, "%s is a folder already; a folder doesn't replace another (move what is in %s into it instead, §H.5)", dst.path, src.path)
	case dst.kind == kPlacement:
		return fail(http.StatusForbidden, "%s is a file: a folder doesn't replace it (§H.5)", dst.path)
	case dst.kind == kNewNode && dst.ns == src.ns:
		return st.moveNode(ctx, src, dst)
	case dst.kind == kNewNode:
		return st.moveFolderAcross(ctx, src, dst)
	case !st.s.cats[dst.ns]:
		return fail(http.StatusForbidden, "folder %s moves only to a file tree: %s isn't in one, and a namespace's directory (the flat view) has no folders (§H.2)", src.path, dst.path)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// accessRefused refuses (403) to copy folder src, or move it to another
// tree, where it carries $access or sits under a folder that does
// (§B.11.1), as the node documents of catalog graph cg have it: the copy
// is made without it (§H.5), which only catalog-admins set (§B.11.3), and
// whether a copy may so widen who reads what is copied is open (§B.12).
// Until that is settled the gateway refuses (F-H12); $access means
// something only in a tree with tree-derived access (§B.11), so a tree
// whose folders carry it is taken for one.
func (st *reqState) accessRefused(cg *catGraph, src target) error {
	seen := map[string]bool{}
	var carrier func(n *tree.Node) *tree.Node
	carrier = func(n *tree.Node) *tree.Node {
		if n == nil || seen[n.Name] {
			return nil
		}
		seen[n.Name] = true
		if n.HasAccess {
			return n
		}
		for _, p := range cg.g.WalkableParents(n) {
			if c := carrier(cg.g.Node(p)); c != nil {
				return c
			}
		}
		return nil
	}
	c := carrier(cg.g.Node(src.node))
	switch {
	case c == nil:
		return nil
	case c.Name == src.node:
		return fail(http.StatusForbidden, "folder %s carries access settings ($access, §B.11.1), which its copy wouldn't (§H.5): whether a copy may widen who reads what is in it is open (§B.12), so this server doesn't copy it, nor move it to another tree", src.path)
	}
	return fail(http.StatusForbidden, "folder %s is in a folder that carries access settings ($access, §B.11.1), which its copy wouldn't have (§H.5): whether a copy may widen who reads what is in it is open (§B.12), so this server doesn't copy it, nor move it to another tree", src.path)
}

// copyFolder makes t, the copy of a folder a COPY makes (§H.5 "Copy"),
// before x/net/webdav copies the folder's visible children (its listing,
// dirFile) into it one by one, unless Depth: 0 asks for the folder alone;
// a failure part-way leaves what was done, with no rollback, and is
// answered as that child's copy would be. The folder copied is the one
// at t's place below the COPY's source: a tree's folder, copied to a new
// name of a tree as a new folder node titled with that name and without
// the source's $access (mkFolder), not into itself or a folder in it,
// and not where it carries $access or sits under a folder that does
// (accessRefused). Onto an existing folder or file it is 403 (412 with
// Overwrite: F, x/net/webdav's), and to another case of a sibling's name
// 409 (§H.2 "Siblings"), either setting a guard (§H.6); a namespace's
// directory, a tree's top level and a scratch directory aren't copied,
// but an app's scratch directory in the folder copied, which its listing
// shows, is copied as one, with what is in it (§H.6), as a move to
// another tree carries it over (scratchMoveUnder).
func (st *reqState) copyFolder(ctx context.Context, t target) error {
	src, err := st.resolve(ctx, st.path+strings.TrimPrefix(t.path, st.dst))
	if err != nil {
		return err
	}
	if src.kind == kScratch && src.sdir && t.path != st.dst {
		switch t.kind {
		case kNewNode, kScratch, kBadName:
			// In memory, as the original: x/net/webdav copies what is in
			// it into it next, scratch there too.
			return st.scratchMkdir(t.path)
		}
	}
	if src.kind != kFolder {
		return fail(http.StatusForbidden, "%s isn't a folder of a file tree, the only folders copied (§H.5): a namespace's directory, a tree's top level and an app's temporary folder aren't", src.path)
	}
	if t.path == st.dst {
		switch t.kind {
		case kFolder, kDoc, kRaw, kPlacement:
			// Refused below: the DELETE that follows (rclone's) is
			// guarded, as after a refused PUT (saveTo).
			st.saveTo = t.path
		}
	}
	if (t.kind == kFolder || t.kind == kPlacement) && t.otherCase {
		return otherCase(t)
	}
	switch t.kind {
	case kMissing:
		return fail(http.StatusConflict, "%s can't be made: %s isn't a folder here (a file, or nothing)", t.path, t.dir)
	case kRoot, kNSDir, kCatDir, kFolder:
		return fail(http.StatusForbidden, "%s is a folder already: a folder copied there doesn't replace it, nor go into it (§H.5); copy it to a new name", t.path)
	case kDoc, kRaw, kPlacement:
		return fail(http.StatusForbidden, "%s is a file: a folder copied there doesn't replace it (§H.5)", t.path)
	case kNewNode:
	case kBadName:
		if st.s.cats[t.ns] {
			return st.badName(t)
		}
		fallthrough
	default:
		return fail(http.StatusForbidden, "folder %s is copied only into a file tree: %s isn't a new name in one, and a namespace's directory (the flat view) has no folders (§H.2)", src.path, t.path)
	}
	cg, _, err := st.writeTree(ctx, src.ns)
	if err != nil {
		return err
	}
	if cg == nil {
		return noFolderDelete(src.ns, src.path)
	}
	if t.ns == src.ns && (t.parent == src.node || cg.g.Descendants([]string{src.node})[t.parent]) {
		return fail(http.StatusForbidden, "folder %s can't be copied into itself or a folder in it (§H.5)", src.path)
	}
	if err := st.accessRefused(cg, src); err != nil {
		return err
	}
	_, err = st.makeFolder(ctx, t)
	return err
}

// moveFolderAcross moves folder src to dst, a new name in another tree
// (§H.5 "Copy": a folder moved to another tree): a new folder node there,
// titled with dst's name and without src's $access, src's visible
// children (from the node documents, nodeDir) then moved into it one by
// one, a file as a move across trees moves it (moveAcross: a copy, then a
// delete of the source, its item taking $successor where it leaves its
// namespace), a folder as this, and src deleted once empty (deleteFolder).
// A failure part-way leaves what was done, with no rollback, and is
// answered as that child's MOVE would be. Before anything is written: a
// folder that carries $access or sits under one isn't moved
// (accessRefused), nor one the grant can't delete, or unlink where it has
// several parents (allows). The MOVE's If-Match names src's node
// (srcPrecondition), not its files.
func (st *reqState) moveFolderAcross(ctx context.Context, src, dst target) error {
	cg, _, err := st.writeTree(ctx, src.ns)
	if err != nil {
		return err
	}
	if cg == nil {
		return noFolderDelete(src.ns, src.path)
	}
	if err := st.accessRefused(cg, src); err != nil {
		return err
	}
	verb := "delete"
	if n := cg.g.Node(src.node); n != nil && len(cg.g.WalkableParents(n)) > 1 {
		// Unlinked from this folder only (deleteFolder).
		verb = "append"
	}
	if err := st.allows(ctx, src, src.ns, verb); err != nil {
		return err
	}
	match, anyMatch := st.srcMatch, st.srcAny
	st.srcMatch, st.srcAny = "", false
	defer func() { st.srcMatch, st.srcAny = match, anyMatch }()
	if err := st.moveInto(ctx, src, dst); err != nil {
		return err
	}
	st.scratchMoveUnder(src.path, dst.path)
	return st.deleteFolder(ctx, src)
}

// moveInto makes folder dst and moves folder src's visible children into
// it (moveFolderAcross).
func (st *reqState) moveInto(ctx context.Context, src, dst target) error {
	node, err := st.makeFolder(ctx, dst)
	if err != nil {
		return err
	}
	cg, err := st.freshGraph(ctx, src.ns)
	if err != nil {
		return err
	}
	d, err := st.nodeDir(ctx, src.ns, src.node)
	if err != nil {
		return err
	}
	for _, e := range d.entries {
		from := target{path: src.path + "/" + e.name, dir: src.path, base: e.name, ns: src.ns, node: e.node.Name, parent: src.node,
			title: e.name, listedAs: nodeName(e.node)}
		title, err := newTitle(e.name)
		if err != nil {
			return err
		}
		to := target{kind: kNewNode, path: dst.path + "/" + e.name, dir: dst.path, base: e.name, ns: dst.ns, parent: node, title: title}
		if e.node.Kind == kindFolder {
			from.kind = kFolder
			if err := st.accessRefused(cg, from); err != nil {
				return err
			}
			if err := st.moveInto(ctx, from, to); err != nil {
				return err
			}
			st.scratchMoveUnder(from.path, to.path)
			err := st.deleteFolder(ctx, from)
			st.changed()
			if err != nil {
				return err
			}
			continue
		}
		from.kind, from.docNS, from.docName = kPlacement, e.node.ItemNS, e.node.ItemName
		err = st.moveAcross(ctx, from, to)
		// What was read before is stale now: the folder's emptiness is
		// read again from the node documents (deleteFolder).
		st.changed()
		if err != nil {
			return err
		}
	}
	return nil
}

// moveFile is a MOVE of live file src where a tree is involved (§H.5):
// within one tree, to a new name or under another case of its own, a
// rename or a move of its node (moveNode); onto an existing file, a save
// into it (moveOnto); to a new name elsewhere, a copy and a delete
// (moveAcross).
func (st *reqState) moveFile(ctx context.Context, src, dst target) error {
	switch {
	case src.kind == kPlacement && dst.ns == src.ns && (dst.kind == kNewNode || dst.kind == kPlacement && dst.node == src.node):
		return st.moveNode(ctx, src, dst)
	case dst.kind == kFolder:
		return fail(http.StatusForbidden, "%s is a folder: a file doesn't replace it", dst.path)
	case dst.kind == kPlacement:
		return st.moveOnto(ctx, src, dst)
	case dst.kind == kDoc || dst.kind == kRaw:
		if _, live, err := st.docAt(ctx, dst); err != nil {
			return err
		} else if live {
			return st.moveOnto(ctx, src, dst)
		}
		return st.moveAcross(ctx, src, dst)
	case dst.kind == kNewNode:
		return st.moveAcross(ctx, src, dst)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// copyOfFile reads live file src whole, for a copy: its content as its
// reader gets it (fileBytes), with its type and, for a raw file, its blob
// (copySrc), so the copy keeps the blob's id and copies it (§7.8).
func (st *reqState) copyOfFile(ctx context.Context, src target) (headDoc, []byte, error) {
	hd, live, err := st.docAt(ctx, src)
	switch {
	case err != nil:
		return hd, nil, err
	case !live:
		return hd, nil, errNotExist
	}
	b, err := st.fileBytes(ctx, &hd)
	if err != nil {
		return hd, nil, err
	}
	st.ctype, st.copySrc = hd.m.Type, nil
	if r := hd.m.raw; r != nil {
		st.copySrc = &blobSrc{ns: hd.ns, name: hd.name, ref: *r}
	}
	return hd, b, nil
}

// moveOnto moves live file src onto existing file dst (§H.5 "Move onto
// an existing file"): a save of src's content into dst, whose base is
// taken as a PUT's (§H.4), so dst keeps its history, then a delete of src
// as a DELETE deletes it. This is how "write a temporary file, rename it
// over" saves land. One document shown in both places isn't moved onto
// itself, and one whose source the grant can't delete (sourceDeletable)
// is refused before anything is written.
func (st *reqState) moveOnto(ctx context.Context, src, dst target) error {
	st.onto = dst.path
	if src.docNS == dst.docNS && src.docName == dst.docName {
		return fail(http.StatusForbidden, "%s and %s are one document, %s/%s, shown in two places; delete the one you don't want", src.path, dst.path, src.docNS, src.docName)
	}
	if err := st.sourceDeletable(ctx, src); err != nil {
		return err
	}
	if err := st.writable(ctx, dst); err != nil {
		return err
	}
	hd, b, err := st.copyOfFile(ctx, src)
	if err != nil {
		return err
	}
	if st.srcMatch != "" && hd.rev != st.srcMatch {
		return st.sourceMoved(src.path)
	}
	rev, _, err := st.commitRev(ctx, dst, b)
	if err != nil {
		return st.undoOwnDelete(ctx, dst, upstream(err))
	}
	if rev == "" {
		return notMoved(src, dst)
	}
	return st.deleteSource(ctx, src, dst, hd.rev, "")
}

// sourceDeletable refuses, before a MOVE writes anything, one whose
// source the grant can't delete, since a copy written before that 403
// would leave the destination replaced or made and the source there, a
// refused request with a lasting effect (§H.5 "Moves that copy"): a
// tree's file, never one at a top level whose parents the grant can't see
// (topWrite), whose delete is made from the node documents (writeTree),
// or, by a grant limited to some resources that doesn't read them (§H.7
// "Limited grants"), from its own document or the catalog's answer
// (placedIn), and is the tombstone of its placement, or for one in
// several folders an append unlinking it (deleteFile), which the grant's
// verbs in the catalog must allow; a flat namespace's file, a tombstone
// its verbs there must allow (allows).
// What only rules decide (§C.2) isn't known before the core is asked:
// such a refusal of the delete still leaves the copy.
func (st *reqState) sourceDeletable(ctx context.Context, src target) error {
	ns, verb := src.docNS, "delete"
	if src.kind == kPlacement {
		// A file at a top level whose parents the grant can't see is
		// never deleted by it (deleteFile, topWrite).
		if err := topWrite(src); err != nil {
			return err
		}
		cg, _, err := st.writeTree(ctx, src.ns)
		if err != nil {
			return err
		}
		ns = src.ns
		d, err := st.derived(ctx, src.ns)
		if err != nil {
			return err
		}
		switch several, _, err := st.placedIn(ctx, src, cg, d); {
		case err != nil:
			return err
		case several:
			verb = "append"
		}
		switch {
		case d && verb == "delete":
			// The catalog decides (§B.11.4): an Unplace grant it issues,
			// not used yet.
			if _, err := st.issue(ctx, src.ns, map[string]any{"node": src.node, "want": []any{"delete"}}); err != nil {
				if de, ok := err.(*davError); ok && de.status >= 400 && de.status < 500 {
					return fail(de.status, "%s isn't moved: %s, which deleting it takes, so it would stay where it is beside the copy; nothing was written", src.path, de.msg)
				}
				return err
			}
			return nil
		case d:
			return nil
		}
	}
	return st.allows(ctx, src, ns, verb)
}

// allows refuses a MOVE of src whose delete takes verb in ns where the
// grant's verbs there (GET /ns/{ns}/principal can, §7.4) don't include
// it; where they aren't known (that read failed, an older core), the
// core's refusal of the delete is the answer.
func (st *reqState) allows(ctx context.Context, src target, ns, verb string) error {
	if can := st.s.nsInfo(ctx, st.tk, ns).can; can != nil && !can[verb] {
		return fail(http.StatusForbidden, "%s isn't moved: the grant doesn't allow %s in %s, which deleting it takes (§C.2), so it would stay where it is beside the copy; nothing was written", src.path, verb, ns)
	}
	return nil
}

// notMoved refuses a MOVE whose copy wrote nothing to the core (an empty
// placeholder), whose source isn't deleted for it.
func notMoved(src, dst target) error {
	return fail(http.StatusConflict, "%s wasn't written to the core, so %s isn't deleted", dst.path, src.path)
}

// moveAcross moves live file src to dst, a new name in another tree or
// namespace (§H.5 "Across trees or namespaces"): a copy, a new item or
// resource with src's content (a raw file's blob copied with Blob-From
// where its rank allows, §7.8), then a delete of src; where its item is
// deleted, its last revision first takes $successor naming the copy
// (§8.1), unless its root isn't an object. One whose source the grant
// can't delete (sourceDeletable) is refused before anything is written.
func (st *reqState) moveAcross(ctx context.Context, src, dst target) error {
	if err := st.sourceDeletable(ctx, src); err != nil {
		return err
	}
	if err := st.writable(ctx, dst); err != nil {
		return err
	}
	hd, b, err := st.copyOfFile(ctx, src)
	if err != nil {
		return err
	}
	if st.srcMatch != "" && hd.rev != st.srcMatch {
		return st.sourceMoved(src.path)
	}
	if src.kind != kPlacement {
		// Its last revision takes $successor first, an append, where its
		// root is an object (deleteItem).
		e, err := st.entry(ctx, &hd)
		if err != nil {
			return err
		}
		if _, obj := e.value.(map[string]any); obj {
			if err := st.allows(ctx, src, src.docNS, "append"); err != nil {
				return err
			}
		}
	}
	st.wroteTo = ""
	st.moving = true
	rev, _, err := st.commitRev(ctx, dst, b)
	st.moving = false
	if err != nil {
		return err
	}
	if rev == "" {
		return notMoved(src, dst)
	}
	succ := ""
	if ns, name, ok := strings.Cut(st.wroteTo, "/"); ok {
		succ = "/r/" + ns + "/" + name
		if ns == hd.ns {
			succ = name
		}
	}
	return st.deleteSource(ctx, src, dst, hd.rev, succ)
}

// deleteSource deletes file src after its content, revision rev, went to
// dst (a MOVE): a tree's file as a DELETE deletes it (deleteFile), a flat
// namespace's resource; successor, if given, is where it went (§8.1).
// Only rev is deleted: an edit someone made to src meanwhile, which dst
// doesn't hold, leaves src as it is now, a 409.
func (st *reqState) deleteSource(ctx context.Context, src, dst target, rev, successor string) error {
	var err error
	if src.kind == kPlacement {
		err = st.deleteFile(ctx, src, rev, successor)
	} else {
		_, err = st.deleteItem(ctx, src.docNS, src.docName, rev, successor)
	}
	if de, ok := upstream(err).(*davError); ok && de.status == http.StatusPreconditionFailed {
		return fail(http.StatusConflict, "%s was changed by someone else while it was moved: %s holds the version moved, and %s stays as it is now; reload both", src.path, dst.path, src.path)
	}
	if err == nil {
		st.s.forgetPath(st.p, src.path)
	}
	return err
}

// unlink removes node t.node's parents entry for folder t.parent: a node
// with several parents (a DAG), deleted from one folder (§H.5). Only
// while its document as the core has it still names it as t's path did
// (stillNamed), which was checked against the token's kept graph, maybe
// older (another program's rename within CatalogTTL): one renamed or
// moved since by anyone is a 404, as for moveNode, not unlinked over that.
func (st *reqState) unlink(ctx context.Context, t target) error {
	switch d, err := st.derived(ctx, t.ns); {
	case err != nil:
		return err
	case d:
		// A move to its other parents, under a Move grant (§B.11.4).
		return st.moveIssued(ctx, t, "", t.parent, "", "")
	}
	in := st.s.nsInfo(ctx, st.tk, t.ns)
	defer st.changed()
	return st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, t.ns, t.node)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		e, err := st.s.doc(ctx, st.tk, t.ns, t.node, h.ID)
		if err != nil {
			return false, err
		}
		if !st.stillNamed(t, e.value) {
			return false, fail(http.StatusNotFound, "%s was renamed or moved by someone else just now; reload its folder", t.path)
		}
		m, _ := e.value.(map[string]any)
		ps := parentsEdit(t.ns, m["parents"], t.parent, "", "")
		if len(ps) == 0 {
			return false, nil
		}
		_, err = st.tk.c.Append(ctx, t.ns, t.node, h.ID, withNonce(in, e.value, ps))
		if client.IsStale(err) {
			return true, nil
		}
		st.committed = st.committed || err == nil
		return false, err
	})
}

// parentsEdit is the patch set replacing the parents entry for folder from
// in a parents value v with one for to, ordered order ("" for none): ""
// for to removes the entry, as does a to the node is already in; a from
// it isn't in adds one.
func parentsEdit(cat string, v any, from, to, order string) []any {
	arr, isArr := v.([]any)
	at, has := -1, false
	for i, x := range arr {
		m, _ := x.(map[string]any)
		href, _ := m["href"].(string)
		ns, name, ok := tree.ParseHref(href)
		if !ok || ns != cat {
			continue
		}
		if from != "" && name == from && at < 0 {
			at = i
		}
		if to != "" && name == to {
			has = true
		}
	}
	entry := map[string]any{"href": "/r/" + cat + "/" + to}
	if order != "" {
		entry["order"] = order
	}
	op := func(op, path string, v any) []any {
		m := map[string]any{"op": op, "path": path}
		if v != nil {
			m["value"] = v
		}
		return []any{m}
	}
	switch {
	case !isArr && to == "":
		return nil
	case !isArr:
		return op("add", "/parents", []any{entry})
	case at >= 0 && (to == "" || has):
		return op("remove", "/parents/"+strconv.Itoa(at), nil)
	case at >= 0:
		return op("replace", "/parents/"+strconv.Itoa(at), entry)
	case to == "" || has:
		return nil
	}
	return op("add", "/parents/-", entry)
}
