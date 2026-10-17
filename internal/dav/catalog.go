package dav

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/tree"
)

// Catalogs (Addendum B) as folder trees: folders are directories named by
// node name, placements files {ns}.{name}.json holding their item's
// document, and a node with several parents (a DAG) is under each. The
// tree is built from the catalog namespace's documents as the core has
// them (tree.BuildGraph), kept per principal for CatalogTTL or until this
// server writes; the catalog's access ($access, §B.11) and the tree
// service aren't consulted, and its trust list (§B.3) only bounds where
// placements write.

const kindFolder = tree.KindFolder

// catGraph is a catalog's live nodes: their documents and heads, and the
// graph the tree service would build of them (§B.5), as one principal
// read them, with the heads of their items as read since.
type catGraph struct {
	cat   string
	g     *tree.Graph
	heads map[string]string
	at    time.Time
	gen   uint64

	mu    sync.Mutex
	items map[string]*client.Head // by ns/name
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
	docs, err := st.s.fetchHeads(ctx, st.p, hs, st.p.c.Head)
	if err != nil {
		return nil, err
	}
	cg := &catGraph{cat: cat, heads: map[string]string{}, items: map[string]*client.Head{}}
	nodes := map[string]any{}
	for _, hd := range docs {
		if hd.e.sealed {
			return nil, fail(http.StatusNotImplemented, "catalog %s is sealed (Addendum E); it isn't served over WebDAV", cat)
		}
		cg.heads[hd.name] = hd.rev
		nodes[hd.name] = hd.e.value
	}
	cg.g = tree.BuildGraph(cat, nil, nodes)
	return cg, nil
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

// shown reports whether a node appears in the tree: not on a cycle (§B.5)
// and, for a placement, named {ns}.{name} (§B.2).
func shown(n *tree.Node) bool {
	return n != nil && !n.Cyclic && (n.Kind == kindFolder || n.ItemNS != "")
}

// children lists the nodes in folder, or at the catalog's root for "":
// the nodes without parents.
func (cg *catGraph) children(folder string) []*tree.Node {
	var out []*tree.Node
	if folder == "" {
		for _, name := range cg.g.Names() {
			if n := cg.g.Node(name); shown(n) && len(n.Parents) == 0 {
				out = append(out, n)
			}
		}
		return out
	}
	for _, c := range cg.g.Children(folder) {
		if shown(c.Node) {
			out = append(out, c.Node)
		}
	}
	return out
}

// under returns node name if it is in folder ("" for the root).
func (cg *catGraph) under(name, folder string) *tree.Node {
	n := cg.g.Node(name)
	if !shown(n) {
		return nil
	}
	if folder == "" {
		if len(n.Parents) == 0 {
			return n
		}
		return nil
	}
	for i, p := range n.Parents {
		if p.Name == folder && i < len(n.EdgeStates) && n.EdgeStates[i] == tree.EdgeValid {
			return n
		}
	}
	return nil
}

// folderName reports whether s can name a folder: a resource name
// without a dot (§3.6, §B.2).
func folderName(s string) bool { return client.ValidResourceName(s) && !strings.Contains(s, ".") }

// resolveCatalog resolves the path segments after a catalog's name: a
// chain of folders, each in the one before, then the last name.
func (st *reqState) resolveCatalog(ctx context.Context, t target, segs []string) (target, error) {
	cg, err := st.graph(ctx, t.ns)
	if err != nil {
		return t, err
	}
	parent := ""
	for _, seg := range segs[:len(segs)-1] {
		if n := cg.under(seg, parent); n == nil || n.Kind != kindFolder {
			t.kind = kMissing
			return t, nil
		}
		parent = seg
	}
	last := segs[len(segs)-1]
	t.parent = parent
	if n := cg.under(last, parent); n != nil && n.Kind == kindFolder {
		t.kind, t.node = kFolder, last
		return t, nil
	}
	if p, ok := strings.CutSuffix(last, ".json"); ok {
		if ns, item, ok := tree.SplitPlacement(p); ok {
			t.node, t.docNS, t.docName = p, ns, item
			if n := cg.under(p, parent); n != nil && n.Kind == tree.KindPlacement {
				t.kind = kPlacement
			} else {
				t.kind = kNewPlacement
			}
			return t, nil
		}
	}
	if folderName(last) {
		t.kind, t.node = kNewFolder, last
		return t, nil
	}
	return st.scratchAt(t, true), nil
}

// parentsOf is the parents value placing a node in folder: one live link
// to it, or none at the root (§B.2).
func parentsOf(cat, folder string) []any {
	if folder == "" {
		return []any{}
	}
	return []any{map[string]any{"href": "/r/" + cat + "/" + folder}}
}

// where lists the folders a node is in, for messages.
func (cg *catGraph) where(n *tree.Node) string {
	ps := cg.g.WalkableParents(n)
	if len(ps) == 0 {
		return "the catalog's root, or no folder"
	}
	return strings.Join(ps, ", ")
}

// mkFolder makes folder t.node in t.parent (MKCOL): a node document
// { parents } (§B.2). A folder of that name elsewhere is a 409: names are
// identity, so it is moved, not made again.
func (st *reqState) mkFolder(ctx context.Context, t target) error {
	cg, err := st.graph(ctx, t.ns)
	if err != nil {
		return err
	}
	if n := cg.g.Node(t.node); n != nil {
		return fail(http.StatusConflict, "%s is already in catalog %s (in %s); move it here instead", t.node, t.ns, cg.where(n))
	}
	return st.createNode(ctx, t.ns, t.node, map[string]any{"parents": parentsOf(t.ns, t.parent)})
}

// place writes v as the document of a placement's item, created if it
// doesn't exist (else edited), and creates the placement in t.parent
// (§B.2). An item placed elsewhere in the catalog is a 409, before
// anything is written: one placement per item per catalog, so it is moved
// instead. A new item is written first (§B.7: content first, so a
// placement never dangles); an existing one after its placement, so a
// placement the core refuses (a frozen catalog, a grant that doesn't
// write it) leaves the item as it was.
func (st *reqState) place(ctx context.Context, t target, v any, body []byte) (string, bool, error) {
	cg, err := st.graph(ctx, t.ns)
	if err != nil {
		return "", false, err
	}
	if n := cg.g.Node(t.node); n != nil {
		return "", false, fail(http.StatusConflict, "%s/%s is already placed in catalog %s (in %s); move it here instead", t.docNS, t.docName, t.ns, cg.where(n))
	}
	h, err := st.p.c.Head(ctx, t.docNS, t.docName)
	if err != nil {
		return "", false, upstream(err)
	}
	node := map[string]any{"parents": parentsOf(t.ns, t.parent)}
	if h.State == client.Live {
		if err := st.createNode(ctx, t.ns, t.node, node); err != nil {
			return "", false, err
		}
		return st.commitDoc(ctx, t.docNS, t.docName, v, body, false)
	}
	rev, exact, err := st.commitDoc(ctx, t.docNS, t.docName, v, body, false)
	if err != nil {
		return "", false, err
	}
	if err := st.createNode(ctx, t.ns, t.node, node); err != nil {
		return "", false, err
	}
	return rev, exact, nil
}

// writable refuses a write through a placement to an item this server
// doesn't write: one in a catalog (a node document, which takes only the
// writes of MKCOL, MOVE and DELETE here), or in a namespace neither served
// (-ns) nor trusted by the catalog (§B.3), which a local mode's grant may
// reach though the server wasn't set up to serve it.
func (st *reqState) writable(ctx context.Context, t target) error {
	if t.kind != kPlacement && t.kind != kNewPlacement {
		return nil
	}
	if st.s.cats[t.docNS] || t.docNS == t.ns {
		return fail(http.StatusForbidden, "%s.%s is a catalog's node; its file isn't written here (folders are made, moved and deleted as directories)", t.docNS, t.docName)
	}
	if st.s.flat[t.docNS] || slices.Contains(st.s.nsInfo(ctx, st.p, t.ns).trust, t.docNS) {
		return nil
	}
	return fail(http.StatusForbidden, "catalog %s doesn't trust namespace %s (§B.3), and it isn't served here (-ns): its documents aren't written through the catalog", t.ns, t.docNS)
}

// createNode creates catalog node name with doc (If-None-Match: *), or
// restores it with doc if it is tombstoned (§8.2).
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
			return false, fail(http.StatusForbidden, "%s/%s was purged; its name can't be used again (§8.3)", cat, name)
		case client.Tombstoned:
			_, err = st.p.c.Restore(ctx, cat, name, h.ID, withNonce(in, []any{map[string]any{"op": "replace", "path": "", "value": doc}}))
		default:
			_, err = st.p.c.Create(ctx, cat, name, withNonce(in, client.GenesisPatches(doc)))
		}
		if client.IsStale(err) || client.IsGone(err) {
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile", cat, name)
		}
		return false, err
	})
}

// unplace is a DELETE in a catalog folder. A node in several folders (a
// DAG) is unlinked from this one only, as a file with several links; a
// node in this folder only is deleted (a placement: its item stays, §B.7),
// a folder only when nothing is in it.
func (st *reqState) unplace(ctx context.Context, t target) error {
	cg, err := st.graph(ctx, t.ns)
	if err != nil {
		return err
	}
	n := cg.g.Node(t.node)
	if t.parent != "" && len(cg.g.WalkableParents(n)) > 1 {
		return st.editParents(ctx, t.ns, t.node, t.parent, "")
	}
	if n.Kind == kindFolder {
		if kids := cg.g.Children(t.node); len(kids) > 0 {
			names := make([]string, 0, len(kids))
			for _, k := range kids {
				names = append(names, k.Node.Name)
			}
			sort.Strings(names)
			return fail(http.StatusConflict, "folder %s isn't empty (%s); deleting a folder doesn't delete what is in it (§B.7)", t.node, strings.Join(names, ", "))
		}
		for _, name := range st.scratchUnder(t.path) {
			st.scratchRemove(name)
		}
	}
	return st.deleteDoc(ctx, t.ns, t.node)
}

// isCatalogMove reports whether moving src to dst moves a catalog node
// between folders: same catalog, same name.
func (st *reqState) isCatalogMove(src, dst target) bool {
	if !st.s.cats[src.ns] || src.ns != dst.ns || src.base != dst.base || src.node != dst.node {
		return false
	}
	switch dst.kind {
	case kFolder, kPlacement, kNewFolder, kNewPlacement:
		return src.kind == kFolder || src.kind == kPlacement
	}
	return false
}

// move moves a catalog node from folder src.parent to dst.parent: one
// write to the node, replacing its parents entry for the one with the
// other (§B.2 "Move"), with If-Match. A folder can't go into itself.
func (st *reqState) move(ctx context.Context, src, dst target) error {
	if src.parent == dst.parent {
		return nil
	}
	if src.kind == kFolder {
		cg, err := st.graph(ctx, src.ns)
		if err != nil {
			return err
		}
		if cg.g.Descendants([]string{src.node})[dst.parent] {
			return fail(http.StatusConflict, "folder %s can't go into itself", src.node)
		}
	}
	return st.editParents(ctx, src.ns, src.node, src.parent, dst.parent)
}

// editParents replaces node's parents entry for folder from with one for
// to: "" for from is the catalog root (an entry is added), "" for to
// removes the entry, as does a to the node is already in.
func (st *reqState) editParents(ctx context.Context, cat, node, from, to string) error {
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
		ps := parentsEdit(cat, m["parents"], from, to)
		if len(ps) == 0 {
			return false, nil
		}
		_, err = st.p.c.Append(ctx, cat, node, h.ID, withNonce(in, ps))
		if client.IsStale(err) {
			return true, nil
		}
		return false, err
	})
}

// parentsEdit is the patch set of editParents for a parents value v.
func parentsEdit(cat string, v any, from, to string) []any {
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
