package core

import (
	"sort"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/tree"
)

// fview is one subject set's view of a covered namespace at one
// checkpoint (§B.11.9 Visible): the subjects of its gs, for item 1, and
// the grant's read filter, for item 2. Every filtered read path, the
// gestures listing and the index judge names with visible. It memoises
// each name's answer, so long-poll waiters sharing an fview judge each
// entry once (§B.11.9 Cost); its methods are safe for concurrent use, but
// each call reads through the transaction it is given.
type fview struct {
	fs       *fscope
	cp       *fcp
	gs       string
	subjects []string
	filter   *grantcheck.ReadFilter
	// a is the reader: its grant's actor, or one standing for a cookie,
	// named and bucketed by the prefix as edgeReader's are.
	a *actor

	// cats are the deciding catalogs at cp, each with the subject set's
	// view of it.
	cats  []*catvis.Catalog
	views []*catvis.View

	mu   sync.Mutex
	memo map[string]bool
}

// GS is the view's subject set (§B.11.9 gs).
func (fv *fview) GS() string { return fv.gs }

// CP is the checkpoint the view judges at.
func (fv *fview) CP() *fcp { return fv.cp }

// newFview builds subjects' view at cp; filter judges item 2.
func (t *tx) newFview(fs *fscope, cp *fcp, gs string, subjects []string, filter *grantcheck.ReadFilter, a *actor) *fview {
	fv := &fview{fs: fs, cp: cp, gs: gs, subjects: subjects, filter: filter, a: a, memo: map[string]bool{}}
	for i := range cp.cats {
		c := t.catalogAt(&cp.cats[i], cp)
		fv.cats = append(fv.cats, c)
		fv.views = append(fv.views, c.View(subjects))
	}
	return fv
}

// visible reports whether name is visible to the view (§B.11.9):
//
//   - in a content namespace: some deciding catalog has a live, explicit
//     placement {ns}.{name} that its view passes as if live (item 1,
//     catvis.View.Placement: a deleted or never-created item is judged as
//     if live, a deleted or missing placement hides it), and the filter
//     allows reading it, roles counting as §B.11.5 counts them (item 2,
//     ReadFilter.AllowsItem);
//   - in a catalog: item 2 allows the node, and either it is live and the
//     catalog's node test passes (catvis.View.Node), or it is tombstoned
//     and its last live document passes as if live (catvis.View.AsIfLive,
//     Deleted resources); either way a placement's item must be live in
//     its namespace as of cp, never one that doesn't exist or is
//     tombstoned. A purged node, whose documents are gone, is hidden.
//
// Dark catalogs, e2e, purged or a branch, aren't in the view (fcp.cats):
// they make nothing visible (§B.11.9 Where).
func (fv *fview) visible(t *tx, name string) bool {
	fv.mu.Lock()
	v, ok := fv.memo[name]
	fv.mu.Unlock()
	if ok {
		return v
	}
	v = fv.judge(t, name)
	fv.mu.Lock()
	fv.memo[name] = v
	fv.mu.Unlock()
	return v
}

func (fv *fview) judge(t *tx, name string) bool {
	if !fv.filter.AllowsItem(name) {
		return false
	}
	if fv.fs.kind == fsContent {
		for _, v := range fv.views {
			if v.Placement(fv.fs.root.name, name) {
				return true
			}
		}
		return false
	}
	return fv.judgeNode(t, name)
}

// judgeNode is visible for a node of a catalog-kind namespace.
func (fv *fview) judgeNode(t *tx, name string) bool {
	if len(fv.cats) == 0 {
		return false
	}
	c, v := fv.cats[0], fv.views[0]
	if n := c.G.Node(name); n != nil && c.G.Explicit(name) {
		return v.Node(n) && fv.itemLive(t, n)
	}
	// A tombstone: its last live document, as catalogAt parsed it, judged
	// as if live, so it reaches exactly those who could see it live
	// (Deleted resources), a placement's never where its item doesn't
	// exist or is tombstoned (Catalogs).
	n := c.Deleted(name)
	return n != nil && v.AsIfLive(n) && fv.itemLive(t, n)
}

// itemLive reports, for a placement n, whether its item is live in its
// namespace as of cp: a catalog never shows a placement whose item doesn't
// exist or is tombstoned, nor so its tombstone (§B.11.9 Catalogs). It is
// true for a folder.
func (fv *fview) itemLive(t *tx, n *tree.Node) bool {
	if n.Kind != tree.KindPlacement {
		return true
	}
	seq, ok := fv.cp.seqs[n.ItemNS]
	m := t.fsLocal(n.ItemNS)
	if !ok || m == nil {
		return false
	}
	return t.resolve(m, n.ItemName, &seq).state == Live
}

// candidates calls fn, in ascending byte order, with every name after
// after (and under prefix, if not "") that may be visible, until fn
// returns false. For a content namespace they are the names
// of the root's explicit placements in the deciding catalogs, so a sparse
// reader never scans the namespace; for a catalog, every name it has or
// had. They are a superset: callers still ask visible.
func (fv *fview) candidates(t *tx, after, prefix string, fn func(name string) bool) {
	ok := func(name string) bool { return name > after && strings.HasPrefix(name, prefix) }
	if fv.fs.kind == fsCatalog {
		from := after
		if prefix > from {
			// Start at the prefix: every name under it sorts at or after it.
			from = prefix
			if ok(prefix) && !fn(prefix) {
				return
			}
		}
		for {
			names := t.namesAfter(fv.fs.n, from, 256)
			for _, name := range names {
				if !strings.HasPrefix(name, prefix) {
					if name > prefix {
						return
					}
					continue
				}
				if ok(name) && !fn(name) {
					return
				}
			}
			if len(names) < 256 {
				return
			}
			from = names[len(names)-1]
		}
	}
	set := map[string]bool{}
	for _, c := range fv.cats {
		for _, name := range placementNames(c.G, fv.fs.root.name) {
			if ok(name) {
				set[name] = true
			}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !fn(name) {
			return
		}
	}
}
