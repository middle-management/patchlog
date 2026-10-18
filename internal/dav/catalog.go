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
// (tree.BuildGraph), kept per principal for CatalogTTL or until this
// server writes; the catalog's access ($access, §B.11) and the tree
// service aren't consulted. catalog.mode "tree" is assumed: a node with
// several parents (a DAG) shows under each, and is unlinked from one at a
// time.

const kindFolder = tree.KindFolder

// catGraph is a catalog's live nodes: their documents and heads, and the
// graph the tree service would build of them (§B.5), as one principal
// read them, with the heads of their items, and the nodes' creation
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

// graph returns catalog cat as the principal read it at most CatalogTTL
// ago, and not before this server's last write.
func (st *reqState) graph(ctx context.Context, cat string) (*catGraph, error) {
	if cg := st.graphs[cat]; cg != nil {
		return cg, nil
	}
	now, gen := st.s.opt.Now(), st.s.gen.Load()
	st.p.mu.Lock()
	cg := st.p.cats[cat]
	st.p.mu.Unlock()
	if cg == nil || cg.gen != gen || now.Sub(cg.at) >= st.s.opt.CatalogTTL {
		var err error
		if cg, err = st.readGraph(ctx, cat); err != nil {
			return nil, err
		}
		cg.at, cg.gen = now, gen
		st.p.mu.Lock()
		st.p.cats[cat] = cg
		st.p.mu.Unlock()
	}
	if st.graphs == nil {
		st.graphs = map[string]*catGraph{}
	}
	st.graphs[cat] = cg
	return cg, nil
}

// readGraph reads catalog cat's live nodes.
func (st *reqState) readGraph(ctx context.Context, cat string) (*catGraph, error) {
	hs, err := st.s.liveHeads(ctx, st.p, cat)
	if err != nil {
		return nil, err
	}
	docs, err := st.s.fetchHeads(ctx, st.p, hs, st.p.c.Head, true)
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
	in, err := st.s.nsInfoErr(ctx, st.p, cat)
	switch {
	case err != nil:
		return nil, nil, err
	case in.files == nil && in.readErr != nil:
		return nil, nil, upstream(in.readErr)
	case in.files == nil:
		return nil, nil, notTree(cat, in.notTree)
	}
	cg, err := st.graph(ctx, cat)
	if err != nil {
		return nil, nil, err
	}
	if n := cg.g.Node(in.files.root); n == nil || n.Kind != kindFolder || n.Cyclic {
		return nil, nil, fail(http.StatusNotFound, "catalog %s's files.root, %s, isn't a live folder node of it, so its file tree has no top level to show (§H.2)", cat, in.files.root)
	}
	return cg, in.files, nil
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
// open them, which answer why (404).
func (s *Server) Check(ctx context.Context) error {
	p := s.local
	if p == nil {
		p = s.newPrincipal("check", s.anon, &account{root: "check"})
	}
	cats := make([]string, 0, len(s.cats))
	for cat := range s.cats {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		in, err := s.nsInfoErr(ctx, p, cat)
		switch {
		case err != nil:
			s.opt.Logf("dav: catalog %s: its namespace document couldn't be read at start (%v); it is checked when opened", cat, err)
		case in.files == nil && in.notTree != "":
			return fmt.Errorf("dav: -catalog %s: %s", cat, in.notTree)
		}
	}
	return nil
}

// itemHead reads the head of a placement's item with p's client, once per
// graph.
func (cg *catGraph) itemHead(p *principal) func(context.Context, string, string) (*client.Head, error) {
	return func(ctx context.Context, ns, name string) (*client.Head, error) {
		k := ns + "/" + name
		cg.mu.Lock()
		h := cg.items[k]
		cg.mu.Unlock()
		if h != nil {
			return h, nil
		}
		h, err := p.c.Head(ctx, ns, name)
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
func (cg *catGraph) born(ctx context.Context, p *principal, name string) time.Time {
	cg.mu.Lock()
	t, ok := cg.births[name]
	cg.mu.Unlock()
	if ok {
		return t
	}
	if head := cg.heads[name]; head != "" {
		if es, _, err := p.c.LogPage(ctx, cg.cat, name, head, ""); err == nil && len(es) > 0 && es[0].Parent == "" {
			t, _ = time.Parse(time.RFC3339Nano, es[0].Created)
		}
	}
	cg.mu.Lock()
	cg.births[name] = t
	cg.mu.Unlock()
	return t
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
// with its item's head.
type treeEntry struct {
	name string
	node *tree.Node
	item *client.Head
	// escaped: its title breaks the rules, and is shown escaped (shown)
	escaped bool
}

// treeDir is a folder's children as the tree shows them, by name and by
// nameKey.
type treeDir struct {
	entries []treeEntry
	byName  map[string]int
	byKey   map[string]int
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

// treeDir returns folder's children as the tree shows them (§H.2), once
// per request: folders, and placements whose items are live, offered
// (§H.7) and readable with the principal's grant (§B.11.5: nothing hidden
// from it shows), each by its title, shown escaped if another tool wrote
// one that breaks the rules (shown), a placement without one by its
// item's name and a folder by its node's. Siblings whose names compare
// equal (nameKey), as a race leaves them, are shown as name (2).ext,
// name (3).ext, … in order of their nodes' creation (born, then name),
// the first keeping its name, skipping numbers whose names a sibling has;
// a title shown escaped comes after those that aren't, so it never takes
// the name of a real one.
func (st *reqState) treeDir(ctx context.Context, cg *catGraph, folder string) (*treeDir, error) {
	k := cg.cat + "/" + folder
	if d := st.dirs[k]; d != nil {
		return d, nil
	}
	kids := cg.children(folder)
	sealed := map[string]bool{}
	for _, n := range kids {
		if _, ok := sealed[n.ItemNS]; n.Kind != kindFolder && !ok {
			sealed[n.ItemNS] = st.s.nsInfo(ctx, st.p, n.ItemNS).sealed
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
			h, err := cg.itemHead(st.p)(gctx, n.ItemNS, n.ItemName)
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
	d := &treeDir{byName: map[string]int{}, byKey: map[string]int{}}
	for i, n := range kids {
		if n.Kind != kindFolder && heads[i] == nil {
			continue
		}
		d.entries = append(d.entries, treeEntry{name: nodeName(n), node: n, item: heads[i], escaped: n.Title != "" && shown(n.Title) != n.Title})
	}
	groups := map[string][]int{}
	for i, e := range d.entries {
		k := st.s.nameKey(e.name)
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
		born := map[int]time.Time{}
		for _, i := range is {
			born[i] = cg.born(ctx, st.p, d.entries[i].node.Name)
		}
		sort.SliceStable(is, func(a, b int) bool {
			if ea, eb := d.entries[is[a]].escaped, d.entries[is[b]].escaped; ea != eb {
				// A title shown escaped never takes the name of one that
				// is so (§H.2 "Titles").
				return eb
			}
			ta, tb := born[is[a]], born[is[b]]
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
			e.name = dupName(e.name, e.node.Kind == kindFolder, func(s string) bool { return taken[st.s.nameKey(s)] })
			taken[st.s.nameKey(e.name)] = true
		}
	}
	for i, e := range d.entries {
		d.byName[e.name] = i
		d.byKey[st.s.nameKey(e.name)] = i
	}
	if st.dirs == nil {
		st.dirs = map[string]*treeDir{}
	}
	st.dirs[k] = d
	return d, nil
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
func (st *reqState) resolveCatalog(ctx context.Context, t target, segs []string) (target, error) {
	cg, f, err := st.tree(ctx, t.ns)
	if err != nil {
		return t, err
	}
	folder := f.root
	for _, seg := range segs[:len(segs)-1] {
		if n := st.childFolder(cg, folder, seg); n != nil {
			folder = n.Name
			continue
		}
		d, err := st.treeDir(ctx, cg, folder)
		if err != nil {
			return t, err
		}
		e, _ := d.find(st.s, seg)
		if e == nil || e.node.Kind != kindFolder {
			t.kind = kMissing
			return t, nil
		}
		folder = e.node.Name
	}
	last := segs[len(segs)-1]
	t.parent = folder
	d, err := st.treeDir(ctx, cg, folder)
	if err != nil {
		return t, err
	}
	if e, exact := d.find(st.s, last); e != nil {
		t.node, t.title, t.otherCase = e.node.Name, e.name, !exact
		if e.node.Kind == kindFolder {
			t.kind = kFolder
		} else {
			t.kind, t.docNS, t.docName = kPlacement, e.node.ItemNS, e.node.ItemName
		}
		return t, nil
	}
	if scratchName(last) || st.isScratchDir(t.path) {
		return st.scratchAt(t, false), nil
	}
	title, err := newTitle(last)
	if err != nil {
		t.kind = kBadName
		return t, nil
	}
	t.kind, t.title = kNewNode, title
	return t, nil
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
	cg, f, err := st.tree(ctx, t.ns)
	if err != nil {
		return err
	}
	return st.createNode(ctx, t.ns, newName(), cg.nodeDoc(f.folder, t.title, t.parent))
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
// grants come from the catalog (§B.11) the placement would come first;
// this server passes each user's grant through, so it doesn't. It never
// deletes unplaced items it didn't just create: another gateway may be in
// the middle of a create (§H.4, blobGrace).
func (st *reqState) newFile(ctx context.Context, t target, raw bool, v any, body []byte) (string, bool, error) {
	if rev, exact, done, err := st.restoreFile(ctx, t, raw, v, body); done {
		return rev, exact, err
	}
	// A new file's kind is its name's and content's (§H.1), whatever the
	// file deleted at its path was.
	raw, v = newKind(t.title, body)
	cg, f, err := st.tree(ctx, t.ns)
	if err != nil {
		return "", false, err
	}
	if !slices.Contains(st.s.nsInfo(ctx, st.p, t.ns).trust, f.ns) {
		return "", false, fail(http.StatusForbidden, "catalog %s doesn't trust %s, the namespace its files.ns names for new files (§H.2, §H.4): no file is created", t.ns, f.ns)
	}
	if st.s.nsInfo(ctx, st.p, f.ns).sealed {
		return "", false, notOffered(f.ns)
	}
	item := newName()
	node := f.ns + "." + item
	doc := cg.nodeDoc(f.placement, t.title, t.parent)
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
			_, err := st.p.c.Delete(dctx, f.ns, item, rev)
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
	in := st.s.nsInfo(ctx, st.p, d.cat)
	h, err := st.p.c.Head(ctx, d.cat, d.node)
	if err != nil {
		return "", false, true, err
	}
	if h.State != client.Tombstoned || h.ID != d.nodeTomb {
		return "", false, false, nil
	}
	if d.itemTomb != "" {
		ih, err := st.p.c.Head(ctx, d.itemNS, d.itemName)
		if err != nil {
			return "", false, true, err
		}
		if ih.State != client.Tombstoned || ih.ID != d.itemTomb || ih.Successor != "" {
			return "", false, false, nil
		}
		if last, err := st.s.doc(ctx, st.p, d.itemNS, d.itemName, ih.Last); err == nil && client.SuccessorOf(last.value) != "" {
			return "", false, false, nil
		}
	}
	if _, err := st.p.c.Restore(ctx, d.cat, d.node, d.nodeTomb, withNonce(in, nil, []any{})); err != nil {
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
	in := st.s.nsInfo(ctx, st.p, cat)
	h, err := st.p.c.Head(ctx, cat, name)
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
	res, err := st.p.c.Batch(ctx, cat, client.BatchRequest{Items: []client.BatchItem{it}}, true)
	if err != nil {
		return upstream(batchErr(err))
	}
	for _, r := range res.Items {
		if status, _ := r.Raw["status"].(float64); status >= 300 {
			return upstream(itemError(r.Raw))
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
// reach though the server wasn't set up to serve it.
func (st *reqState) writable(ctx context.Context, t target) error {
	if t.kind != kPlacement {
		return nil
	}
	if st.s.cats[t.docNS] || t.docNS == t.ns {
		return fail(http.StatusForbidden, "%s is a placement of catalog node %s/%s; its file isn't written here (folders are made, renamed, moved and deleted as directories)", t.path, t.docNS, t.docName)
	}
	if st.s.flat[t.docNS] || slices.Contains(st.s.nsInfo(ctx, st.p, t.ns).trust, t.docNS) {
		return nil
	}
	return fail(http.StatusForbidden, "catalog %s doesn't trust namespace %s (§B.3), and it isn't served here (-ns): %s, a placement of %s/%s, isn't written through the catalog", t.ns, t.docNS, t.path, t.docNS, t.docName)
}

// createNode creates catalog node name with doc (If-None-Match: *), or
// restores it with doc if it is tombstoned (§8.2), with a fresh $nonce
// where the catalog requires one (§H.7).
func (st *reqState) createNode(ctx context.Context, cat, name string, doc map[string]any) error {
	in := st.s.nsInfo(ctx, st.p, cat)
	defer st.changed()
	return st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, cat, name)
		if err != nil {
			return false, err
		}
		switch h.State {
		case client.Live:
			return false, fail(http.StatusConflict, "%s is already in catalog %s", name, cat)
		case client.Purged:
			return false, purgedErr(cat, name)
		case client.Tombstoned:
			_, err = st.p.c.Restore(ctx, cat, name, h.ID, withNonce(in, doc, []any{map[string]any{"op": "replace", "path": "", "value": doc}}))
		default:
			_, err = st.p.c.Create(ctx, cat, name, withNonce(in, doc, client.GenesisPatches(doc)))
		}
		if client.IsStale(err) || client.IsGone(err) {
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
// placement is restored as it was. A node with several parents (a DAG)
// is unlinked from this folder only. A principal's DELETE is remembered a
// while, so its write of the path restores the file (§H.6).
func (st *reqState) deleteFile(ctx context.Context, t target, ifMatch, successor string) error {
	cg, f, err := st.tree(ctx, t.ns)
	if err != nil {
		return err
	}
	h, err := st.head(ctx, t.docNS, t.docName)
	if err != nil {
		return err
	}
	if ifMatch != "" && (h.State != client.Live || h.ID != ifMatch) {
		return fail(http.StatusPreconditionFailed, "%s changed since %s (If-Match); reload it", t.path, ifMatch)
	}
	if n := cg.g.Node(t.node); n != nil && len(cg.g.WalkableParents(n)) > 1 {
		return st.editParents(ctx, t.ns, t.node, t.parent, "", "")
	}
	ptomb, err := st.deleteDoc(ctx, t.ns, t.node, "")
	if err != nil {
		return err
	}
	d := treeDelete{cat: t.ns, node: t.node, nodeTomb: ptomb, parent: t.parent, itemNS: t.docNS, itemName: t.docName}
	if t.docNS == f.ns {
		d.itemTomb, err = st.deleteItem(ctx, t.docNS, t.docName, ifMatch, successor)
		var de *davError
		switch {
		case err == nil, errors.Is(err, errNotExist):
		case errors.As(err, &de) && de.status == http.StatusPreconditionFailed:
			// Changed since the check: the file stays, placed, as it is.
			st.undelete(ctx, st.s.nsInfo(ctx, st.p, t.ns), t.ns, t.node, ptomb, nil)
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

// deleteItem tombstones ns/name (§8.1), if its head is ifMatch when that
// is given, and returns the tombstone; with successor, its last revision
// first sets $successor to it, in the same batch (§7.5), unless its root
// isn't an object, which can't carry one (§H.5).
func (st *reqState) deleteItem(ctx context.Context, ns, name, ifMatch, successor string) (string, error) {
	if successor == "" {
		return st.deleteDoc(ctx, ns, name, ifMatch)
	}
	in := st.s.nsInfo(ctx, st.p, ns)
	var tomb string
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		if ifMatch != "" && h.ID != ifMatch {
			return false, fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", ns, name, ifMatch)
		}
		cur, err := st.s.doc(ctx, st.p, ns, name, h.ID)
		if err != nil {
			return false, err
		}
		if _, obj := cur.value.(map[string]any); !obj {
			res, err := st.p.c.Delete(ctx, ns, name, h.ID)
			if client.IsStale(err) {
				return true, nil
			}
			if err == nil {
				tomb = res.ID
				st.p.markOwn(ns, name, tomb)
			}
			return false, err
		}
		ps := withNonce(in, cur.value, []any{map[string]any{"op": "add", "path": "/$successor", "value": successor}})
		res, err := st.p.c.Batch(ctx, ns, client.BatchRequest{Items: []client.BatchItem{{Resource: name, IfMatch: h.ID,
			Steps: []client.Step{client.PatchStep(ps), client.DeleteStep()}}}}, false)
		err = batchErr(err)
		if client.IsStale(err) {
			return true, nil
		}
		if err == nil && len(res.Items) == 1 && len(res.Items[0].IDs) == 2 {
			tomb = res.Items[0].IDs[1]
			st.p.markOwn(ns, name, tomb)
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
// one without visible children (treeDir), which a 409 names; deleting a
// folder doesn't delete what is in it (§B.7). Placements whose items are
// gone (dangling, §B.3) aren't contents, and are deleted first; those
// whose items the principal can't read are neither named nor deleted. A
// node with several parents (a DAG) is unlinked from this folder only.
// The principal's scratch files in it go with it.
func (st *reqState) deleteFolder(ctx context.Context, t target) error {
	cg, _, err := st.tree(ctx, t.ns)
	if err != nil {
		return err
	}
	if n := cg.g.Node(t.node); n != nil && len(cg.g.WalkableParents(n)) > 1 {
		return st.editParents(ctx, t.ns, t.node, t.parent, "", "")
	}
	d, err := st.treeDir(ctx, cg, t.node)
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
		if _, err := st.deleteDoc(ctx, t.ns, n.Name, ""); err != nil && !errors.Is(err, errNotExist) {
			return err
		}
	}
	for _, name := range st.scratchUnder(t.path) {
		st.scratchRemove(name)
	}
	_, err = st.deleteDoc(ctx, t.ns, t.node, "")
	return err
}

// dangling reports whether placement n's item is gone (§B.3): tombstoned
// or purged, or missing from a namespace whose document the principal
// reads (elsewhere a 404 may be the core hiding it, §7).
func (st *reqState) dangling(ctx context.Context, cg *catGraph, n *tree.Node) bool {
	in := st.s.nsInfo(ctx, st.p, n.ItemNS)
	if in.sealed {
		return false
	}
	h, err := cg.itemHead(st.p)(ctx, n.ItemNS, n.ItemName)
	switch {
	case err != nil:
		return false
	case h.State == client.Tombstoned, h.State == client.Purged:
		return true
	}
	return h.State == client.NotFound && in.readErr == nil
}

// moveNode renames or moves node src.node within its tree to dst (§H.5):
// one append to its title, its parents, or both, with If-Match on its
// head (again on the new head if it moved meanwhile, 412). dst is a new
// name (kNewNode), or src's own under another case, which compares equal
// (nameKey). A folder can't go into itself or a folder in it (403). In
// its new folder the node gets an order after the last child there. The
// principal's scratch files in a moved folder move with it.
func (st *reqState) moveNode(ctx context.Context, src, dst target) error {
	cg, _, err := st.tree(ctx, src.ns)
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
	if moved && src.kind == kFolder && cg.g.Descendants([]string{src.node})[dst.parent] {
		return fail(http.StatusForbidden, "folder %s can't go into itself or a folder in it (§H.5)", src.path)
	}
	order := ""
	if moved {
		order = cg.orderAfter(dst.parent)
	}
	in := st.s.nsInfo(ctx, st.p, src.ns)
	err = st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, src.ns, src.node)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		e, err := st.s.doc(ctx, st.p, src.ns, src.node, h.ID)
		if err != nil {
			return false, err
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
		_, err = st.p.c.Append(ctx, src.ns, src.node, h.ID, withNonce(in, e.value, ps))
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
	if src.kind == kFolder {
		st.scratchMoveUnder(src.path, dst.path)
	} else {
		st.s.forgetPath(st.p, src.path)
		st.s.notePath(st.p, dst.path, src.docNS, src.docName)
	}
	return nil
}

// moveFolder is a MOVE of folder src: within its tree, a rename or a move
// (moveNode); a folder isn't copied, so it doesn't leave its tree, nor
// replace another folder or a file.
func (st *reqState) moveFolder(ctx context.Context, src, dst target) error {
	switch {
	case dst.ns != src.ns:
		return fail(http.StatusForbidden, "folder %s moves only within its file tree (catalog %s); folders aren't copied: make one there, and move what is in %s into it", src.path, src.ns, src.path)
	case dst.kind == kNewNode, dst.kind == kFolder && dst.node == src.node:
		return st.moveNode(ctx, src, dst)
	case dst.kind == kFolder:
		return fail(http.StatusForbidden, "%s is a folder already; a folder doesn't replace another (move what is in %s into it instead)", dst.path, src.path)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
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
	st.ctype = hd.m.Type
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
// itself.
func (st *reqState) moveOnto(ctx context.Context, src, dst target) error {
	st.onto = dst.path
	if src.docNS == dst.docNS && src.docName == dst.docName {
		return fail(http.StatusForbidden, "%s and %s are one document, %s/%s, shown in two places; delete the one you don't want", src.path, dst.path, src.docNS, src.docName)
	}
	if err := st.writable(ctx, dst); err != nil {
		return err
	}
	hd, b, err := st.copyOfFile(ctx, src)
	if err != nil {
		return err
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
// (§8.1), unless its root isn't an object.
func (st *reqState) moveAcross(ctx context.Context, src, dst target) error {
	if err := st.writable(ctx, dst); err != nil {
		return err
	}
	hd, b, err := st.copyOfFile(ctx, src)
	if err != nil {
		return err
	}
	st.wroteTo = ""
	rev, _, err := st.commitRev(ctx, dst, b)
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

// editParents replaces node's parents entry for folder from with one for
// to, ordered order: "" for to removes the entry, as does a to the node
// is already in.
func (st *reqState) editParents(ctx context.Context, cat, node, from, to, order string) error {
	in := st.s.nsInfo(ctx, st.p, cat)
	defer st.changed()
	return st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, cat, node)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		e, err := st.s.doc(ctx, st.p, cat, node, h.ID)
		if err != nil {
			return false, err
		}
		m, _ := e.value.(map[string]any)
		ps := parentsEdit(cat, m["parents"], from, to, order)
		if len(ps) == 0 {
			return false, nil
		}
		_, err = st.p.c.Append(ctx, cat, node, h.ID, withNonce(in, e.value, ps))
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
