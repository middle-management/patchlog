package index

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/lru"
	"github.com/middle-management/patchlog/internal/tree"
)

// Namespaces §B.11.9 covers (§A.4 Private namespaces, Across namespaces).
//
// A followed namespace is covered, as the origin decides it, from the
// namespace documents alone (§B.11.9 Where), whether or not the origin
// implements filtered reads:
//
//   - content kind: not public, sealed or e2e, and it trusts some catalog
//     through a key whose requireAt names it (catvis.TrustedCatalogs);
//   - branch kind: a local branch, recursively, of a content-kind
//     namespace, itself neither public nor sealed; the root's trust and
//     keys are read from its document as of the baseAt the chain fixes;
//   - catalog kind: a catalog, neither public nor sealed, that some local
//     namespace of its catalog.trust trusts as content kind.
//
// A partial reader of a covered namespace (one whose grant allows read
// there without a namespace-wide edge grant, §C.5.2) reads it filtered by
// visibility (§B.11.9 Visible): its marker is reads:{ns}:g:{gs}, gs being
// the origin's (catvis.FilteredSubjects over every deciding catalog's
// Profile, its groups and grantcheck.ReadsScope's digest), and its
// answers are at the combined checkpoint (grantcheck.CombinedAt) of every
// namespace visibility reads, which they list as namespaces:
//
//   - {ns} at the index's checkpoint;
//   - for a branch, each base at the baseAt its branch reads it at;
//   - each trusted, non-e2e, unpurged catalog, and each local, unpurged
//     member of those catalogs' catalog.trust, at the index's checkpoint
//     if the index follows it, otherwise at its head as the grant checker
//     last read it (CheckerTTL).
//
// The index follows those catalogs and members without serving them: it
// reads each one's state as of the id in the checkpoint, which never
// changes, through the core's API (its namespace document, /heads and
// documents), and keeps a catalog's graph (tree.BuildGraph, with its
// tombstoned nodes' last live documents, catvis.NewCatalogDeleted) per
// checkpoint. The Client's grant must read them: a covered namespace one
// of whose catalogs or members it can't read is 502 to partial readers.
// Unrestricted readers, and every reader of a namespace that isn't
// covered, are answered as before.

// Kinds of covered namespace (fcp.kind).
const (
	fsContent = iota // trusts a catalog
	fsBranch         // a local branch, recursively, of a content namespace
	fsCatalog        // a catalog that a content namespace trusts
)

// fsBase is a base of a covered branch, read as of the ns_id at (its
// branch's baseAt).
type fsBase struct{ ns, at string }

// fsCat is a catalog a covered namespace trusts, with its document as of
// id (its ns_id in the checkpoint), whether it is e2e (it then makes
// nothing visible and stays out of at) and the kids of the root's keys
// whose requireAt names it.
type fsCat struct {
	ns, id string
	doc    map[string]any
	e2e    bool
	kids   []string
}

// fcp is a covered namespace's combined checkpoint (§B.11.9 URLs, §A.4):
// at is grantcheck.CombinedAt over ids, each member's ns_id, and cats the
// deciding catalogs' visibility there. It is immutable.
type fcp struct {
	ns    string
	kind  int
	root  string   // the content namespace whose catalogs decide; "" for catalog kind
	chain []fsBase // a branch's bases, from its own up to root
	at    string
	ids   map[string]string
	cats  []*catvis.Catalog
	// live are the names live, as of ids, in a branch's bases (Branches)
	// and in a catalog's members (whose placements a catalog shows only
	// where their items are live).
	live map[string]map[string]bool
}

// errNotReached is a namespace the index hasn't reached yet whose
// coverage can't be told until it has (503 behind, as any query of it);
// errPurgedNS one purged, whose queries are 410 (§8.5) whatever the
// reader's marker.
var (
	errNotReached = errors.New("the index has not reached the namespace yet")
	errPurgedNS   = errors.New("the namespace is purged")
)

// fstate is what the index keeps to compute checkpoints: caches only, of
// state that never changes once read (namespace documents, /heads and
// documents at an ns_id, graphs at a checkpoint).
type fstate struct {
	mu      sync.Mutex
	docs    lru.Cache[string, map[string]any]  // ns \0 ns_id → namespace document
	live    lru.Cache[string, map[string]bool] // ns \0 ns_id → names live there
	cats    lru.Cache[string, *catvis.Catalog] // catalogKey → catalog
	cps     lru.Cache[string, *fcp]            // at → checkpoint, for URLs at older ats
	nodes   map[string]map[string]catNode      // catalog → its node documents last read
	deleted lru.Cache[string, map[string]any]  // catalog \0 name \0 tombstone → last live document
	flight  singleflight.Group
}

// catNode is a catalog node's document as last read, at revision id.
type catNode struct {
	id  string
	doc any
}

const (
	fsDocsMax    = 4096
	fsLiveMax    = 64
	fsCatsMax    = 64
	fsCPsMax     = 256
	fsDeletedMax = 4096
)

func (st *fstate) init() {
	st.docs.MaxEntries, st.live.MaxEntries, st.cats.MaxEntries = fsDocsMax, fsLiveMax, fsCatsMax
	st.cps.MaxEntries, st.deleted.MaxEntries = fsCPsMax, fsDeletedMax
	st.nodes = map[string]map[string]catNode{}
}

// seedDoc keeps cfg's document as its namespace's at the ns_id the grant
// checker read it at, so docAt needn't read it again.
func (ix *Index) seedDoc(cfg *grantcheck.Config) {
	if cfg.Head == "" || cfg.Doc == nil {
		return
	}
	ix.fs.mu.Lock()
	if _, ok := ix.fs.docs.Get(cfg.NS + "\x00" + cfg.Head); !ok {
		ix.fs.docs.Put(cfg.NS+"\x00"+cfg.Head, cfg.Doc, 1)
	}
	ix.fs.mu.Unlock()
}

// docAt is ns's namespace document in force at ns_id id (immutable).
func (ix *Index) docAt(ctx context.Context, ns, id string) (map[string]any, error) {
	k := ns + "\x00" + id
	ix.fs.mu.Lock()
	d, ok := ix.fs.docs.Get(k)
	ix.fs.mu.Unlock()
	if ok {
		return d, nil
	}
	doc, err := ix.c.NSDoc(ctx, ns, id)
	if err != nil {
		return nil, fmt.Errorf("the document of %s at %s: %w", ns, id, err)
	}
	if doc.Value == nil {
		doc.Value = map[string]any{}
	}
	ix.fs.mu.Lock()
	ix.fs.docs.Put(k, doc.Value, 1)
	ix.fs.mu.Unlock()
	return doc.Value, nil
}

// liveAt are the names live in ns as of ns_id id (immutable).
func (ix *Index) liveAt(ctx context.Context, ns, id string) (map[string]bool, error) {
	k := ns + "\x00" + id
	ix.fs.mu.Lock()
	l, ok := ix.fs.live.Get(k)
	ix.fs.mu.Unlock()
	if ok {
		return l, nil
	}
	v, err, _ := ix.fs.flight.Do("live\x00"+k, func() (any, error) {
		items, err := ix.c.Heads(ctx, ns, id)
		if err != nil {
			return nil, fmt.Errorf("the heads of %s at %s: %w", ns, id, err)
		}
		l := make(map[string]bool, len(items))
		for _, it := range items {
			if it.Kind == "head" {
				l[it.Resource] = true
			}
		}
		ix.fs.mu.Lock()
		ix.fs.live.Put(k, l, 1)
		ix.fs.mu.Unlock()
		return l, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]bool), nil
}

// memberAt is the ns_id a member of a checkpoint is taken at: the index's
// checkpoint if it follows m and has reached it, otherwise m's head as
// the grant checker read it. ok is false for a namespace that is purged,
// doesn't exist or is a remote branch (§B.11.9: local, unpurged members
// only); err is a document the index can't read.
func (ix *Index) memberAt(ctx context.Context, m string) (id string, ok bool, err error) {
	if !client.ValidNSName(m) {
		return "", false, nil
	}
	if ix.known(m) {
		id, purged, err := ix.committed(ctx, m)
		switch {
		case err != nil:
			return "", false, err
		case purged:
			return "", false, nil
		case id != "":
			return id, true, nil
		}
	}
	cfg, err := ix.checker.Config(ctx, m)
	switch {
	case client.IsPurged(err), client.IsNotFound(err):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("the head of %s: %w", m, err)
	case remoteBranch(cfg.Doc):
		return "", false, nil
	}
	ix.seedDoc(cfg)
	return cfg.Head, true, nil
}

// fsOpen reports whether a namespace with document doc can be covered:
// not public, not sealed or e2e (§B.11.9 Where).
func fsOpen(doc map[string]any) bool {
	read, _ := doc["read"].(string)
	return read != "public" && !derived.Protected(derived.InfoOf(doc).Level)
}

// localBase is a local branch's base and the ns_id it was cut at, ok
// false for a root or a remote branch (whose base is in another
// deployment, §10, §G.3).
func localBase(doc map[string]any) (ns, at string, ok bool) {
	b, _ := doc["base"].(map[string]any)
	if b == nil {
		return "", "", false
	}
	if _, remote := b["origin"]; remote {
		return "", "", false
	}
	ns, _ = b["ns"].(string)
	at, _ = b["at"].(string)
	return ns, at, ns != "" && at != ""
}

func remoteBranch(doc map[string]any) bool {
	b, _ := doc["base"].(map[string]any)
	_, remote := b["origin"]
	return remote
}

func isCatalog(doc map[string]any) bool {
	_, ok := doc["catalog"]
	return ok
}

// fsTrust are the catalogs root trusts with document doc (§B.11.9 Where,
// catvis.TrustedCatalogs), each with its document as of the id it is
// taken at (memberAt): local, unpurged namespaces only.
func (ix *Index) fsTrust(ctx context.Context, root string, doc map[string]any) ([]fsCat, error) {
	var ferr error
	ids, docs := map[string]string{}, map[string]map[string]any{}
	trusts := catvis.TrustedCatalogs(root, doc, func(cat string) map[string]any {
		if ferr != nil {
			return nil
		}
		id, ok, err := ix.memberAt(ctx, cat)
		if err != nil || !ok {
			ferr = err
			return nil
		}
		d, err := ix.docAt(ctx, cat, id)
		if err != nil {
			ferr = err
			return nil
		}
		ids[cat], docs[cat] = id, d
		return d
	})
	if ferr != nil {
		return nil, ferr
	}
	out := make([]fsCat, 0, len(trusts))
	for _, tr := range trusts {
		out = append(out, fsCat{ns: tr.Catalog, id: ids[tr.Catalog], doc: docs[tr.Catalog],
			e2e: derived.InfoOf(docs[tr.Catalog]).Level == derived.LevelE2E, kids: tr.Kids})
	}
	return out, nil
}

// maxChain bounds a branch's chain of bases (the deployment's branch
// depth is 8 by default, grantcheck's bound 32).
const maxChain = 32

// coverage is ns's coverage at its checkpoint z (§B.11.9 Where): its
// kind, root, chain and trusted catalogs, nil if it isn't covered.
func (ix *Index) coverage(ctx context.Context, ns, z string) (*fcp, []fsCat, error) {
	if cfg, err := ix.checker.Config(ctx, ns); err == nil {
		ix.seedDoc(cfg) // read by the read check already, as a rule
	}
	doc, err := ix.docAt(ctx, ns, z)
	if err != nil {
		return nil, nil, err
	}
	if !fsOpen(doc) || remoteBranch(doc) {
		return nil, nil, nil
	}
	cp := &fcp{ns: ns}
	if b, at, ok := localBase(doc); ok {
		cp.kind = fsBranch
		bdoc := doc
		for ok {
			if len(cp.chain) == maxChain {
				return nil, nil, fmt.Errorf("the chain of bases of %s is too deep", ns)
			}
			cp.chain = append(cp.chain, fsBase{ns: b, at: at})
			if bdoc, err = ix.docAt(ctx, b, at); err != nil {
				return nil, nil, err
			}
			if remoteBranch(bdoc) {
				return nil, nil, nil
			}
			cp.root = b
			b, at, ok = localBase(bdoc)
		}
		// bdoc is the root's document as of the baseAt the chain fixes;
		// the root must also be open, and unpurged, now.
		id, ok, err := ix.memberAt(ctx, cp.root)
		if err != nil || !ok {
			return nil, nil, err
		}
		cur, err := ix.docAt(ctx, cp.root, id)
		if err != nil {
			return nil, nil, err
		}
		if isCatalog(bdoc) || !fsOpen(cur) || !fsOpen(bdoc) {
			return nil, nil, nil
		}
		cats, err := ix.fsTrust(ctx, cp.root, bdoc)
		if err != nil || len(cats) == 0 {
			return nil, nil, err
		}
		return cp, cats, nil
	}
	cats, err := ix.fsTrust(ctx, ns, doc)
	if err != nil {
		return nil, nil, err
	}
	if len(cats) > 0 {
		cp.kind, cp.root = fsContent, ns
		return cp, cats, nil
	}
	if !isCatalog(doc) {
		return nil, nil, nil
	}
	for _, m := range catvis.TrustList(ns, doc) {
		id, ok, err := ix.memberAt(ctx, m)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		mdoc, err := ix.docAt(ctx, m, id)
		if err != nil {
			return nil, nil, err
		}
		if _, _, branch := localBase(mdoc); branch || !fsOpen(mdoc) {
			continue
		}
		trusts, err := ix.fsTrust(ctx, m, mdoc)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range trusts {
			if c.ns == ns {
				cp.kind = fsCatalog
				return cp, []fsCat{{ns: ns, id: z, doc: doc}}, nil
			}
		}
	}
	return nil, nil, nil
}

// checkpoint is ns's combined checkpoint with ns at z, the index's
// checkpoint of it, nil if ns isn't covered (§B.11.9 URLs, §A.4). It
// reads every member's state it needs and keeps the result by at.
func (ix *Index) checkpoint(ctx context.Context, ns, z string) (*fcp, error) {
	cp, cats, err := ix.coverage(ctx, ns, z)
	if err != nil || cp == nil {
		return nil, err
	}
	cp.ids = map[string]string{}
	add := func(m, id string) {
		if _, ok := cp.ids[m]; !ok {
			cp.ids[m] = id
		}
	}
	add(ns, z)
	for _, b := range cp.chain {
		add(b.ns, b.at)
	}
	var deciding []fsCat
	for _, c := range cats {
		if c.e2e {
			continue
		}
		deciding = append(deciding, c)
		add(c.ns, c.id)
		for _, m := range catvis.TrustList(c.ns, c.doc) {
			id, ok, err := ix.memberAt(ctx, m)
			if err != nil {
				return nil, err
			}
			if ok {
				add(m, id)
			}
		}
	}
	cp.at = grantcheck.CombinedAt(cp.ids)
	for _, c := range deciding {
		cv, err := ix.catalogAt(ctx, c, cp.ids)
		if err != nil {
			return nil, err
		}
		cp.cats = append(cp.cats, cv)
	}
	cp.live = map[string]map[string]bool{}
	var lives []string
	switch cp.kind {
	case fsBranch:
		for _, b := range cp.chain {
			lives = append(lives, b.ns)
		}
	case fsCatalog:
		for m := range cp.ids {
			if m != ns {
				lives = append(lives, m)
			}
		}
	}
	for _, m := range lives {
		l, err := ix.liveAt(ctx, m, cp.ids[m])
		if err != nil {
			return nil, err
		}
		cp.live[m] = l
	}
	ix.fs.mu.Lock()
	ix.fs.cps.Put(cp.at, cp, 1)
	ix.fs.mu.Unlock()
	return cp, nil
}

// keptCP is the checkpoint at of ns computed earlier, nil if none is
// held: a reader's gs at an older at is computed there (§B.11.9: a
// grant reads at its own gs as of the URL's at).
func (ix *Index) keptCP(ns, at string) *fcp {
	ix.fs.mu.Lock()
	defer ix.fs.mu.Unlock()
	if cp, ok := ix.fs.cps.Get(at); ok && cp.ns == ns {
		return cp
	}
	return nil
}

// keptCPsIn are the checkpoints of ns the index holds that an answer
// across namespaces at ids (its namespaces, refsMerge) was read at: ns
// and each of their members at its id in ids, but a branch's bases, which
// ids may hold at their own checkpoints instead (§A.4 Across namespaces).
func (ix *Index) keptCPsIn(ns string, ids map[string]string) []*fcp {
	ix.fs.mu.Lock()
	defer ix.fs.mu.Unlock()
	var out []*fcp
	for _, at := range ix.fs.cps.Keys() {
		cp, ok := ix.fs.cps.Get(at)
		if !ok || cp.ns != ns {
			continue
		}
		in := true
		for m, id := range cp.ids {
			got, ok := ids[m]
			base := slices.ContainsFunc(cp.chain, func(b fsBase) bool { return b.ns == m })
			if !ok || (!base && got != id) {
				in = false
				break
			}
		}
		if in {
			out = append(out, cp)
		}
	}
	return out
}

// catalogAt is catalog c's visibility as of ids (§B.11.9 Visible): its
// graph from its documents at ids[c.ns], its tombstoned nodes from their
// last live documents, and its catalog.trust members in ids as its
// content namespaces, each with its document as of its id and the kids
// of its keys whose requireAt names c.
func (ix *Index) catalogAt(ctx context.Context, c fsCat, ids map[string]string) (*catvis.Catalog, error) {
	var key strings.Builder
	key.WriteString(c.ns + "\x00" + ids[c.ns])
	var inCP []string
	for _, m := range catvis.TrustList(c.ns, c.doc) {
		if id, ok := ids[m]; ok {
			inCP = append(inCP, m)
			key.WriteString("\x00" + m + "\x00" + id)
		}
	}
	k := key.String()
	ix.fs.mu.Lock()
	cv, ok := ix.fs.cats.Get(k)
	ix.fs.mu.Unlock()
	if ok {
		return cv, nil
	}
	v, err, _ := ix.fs.flight.Do("cat\x00"+k, func() (any, error) {
		g, deleted, err := ix.catalogGraph(ctx, c.ns, ids[c.ns], c.doc)
		if err != nil {
			return nil, err
		}
		contents := map[string]*catvis.Content{}
		for _, m := range inCP {
			mdoc, err := ix.docAt(ctx, m, ids[m])
			if err != nil {
				return nil, err
			}
			ct := &catvis.Content{NS: m}
			if cfg, err := grantcheck.ParseConfig(m, "", mdoc); err == nil {
				ct.Cfg = cfg // one that doesn't parse: nothing counts through it
			}
			for _, tr := range catvis.TrustedCatalogs(m, mdoc, func(name string) map[string]any {
				if name == c.ns {
					return c.doc
				}
				return nil
			}) {
				ct.Kids = tr.Kids
			}
			contents[m] = ct
		}
		cv := catvis.NewCatalogDeleted(g, contents, deleted)
		ix.fs.mu.Lock()
		ix.fs.cats.Put(k, cv, 1)
		ix.fs.mu.Unlock()
		return cv, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*catvis.Catalog), nil
}

// catalogGraph is catalog cat's graph as of ns_id id, whose document is
// doc, and its tombstoned nodes, each parsed from its last live document
// (the revision its tombstone follows), as the origin builds them. A
// document already read at the same revision is not read again; a
// tombstoned node whose last live document is gone (pruned or purged) is
// left out, as one purged is.
func (ix *Index) catalogGraph(ctx context.Context, cat, id string, doc map[string]any) (*tree.Graph, []*tree.Node, error) {
	items, err := ix.c.Heads(ctx, cat, id)
	if err != nil {
		return nil, nil, fmt.Errorf("the heads of %s at %s: %w", cat, id, err)
	}
	ix.fs.mu.Lock()
	prev := ix.fs.nodes[cat]
	ix.fs.mu.Unlock()
	var (
		mu       sync.Mutex
		nodes    = map[string]catNode{}
		docs     = map[string]any{}
		lastLive = map[string]any{}
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(ix.opt.FetchConcurrency)
	for _, it := range items {
		switch it.Kind {
		case "head":
			if n, ok := prev[it.Resource]; ok && n.id == it.Target {
				mu.Lock()
				nodes[it.Resource], docs[it.Resource] = n, n.doc
				mu.Unlock()
				continue
			}
			g.Go(func() error {
				d, err := ix.c.Doc(gctx, cat, it.Resource, it.Target)
				if err != nil {
					return fmt.Errorf("%s/%s at %s: %w", cat, it.Resource, it.Target, err)
				}
				mu.Lock()
				nodes[it.Resource], docs[it.Resource] = catNode{id: it.Target, doc: d.Value}, d.Value
				mu.Unlock()
				return nil
			})
		case "tombstone":
			g.Go(func() error {
				d, err := ix.lastLive(gctx, cat, it.Resource, it.Target)
				if err != nil {
					return err
				}
				if d != nil {
					mu.Lock()
					lastLive[it.Resource] = d
					mu.Unlock()
				}
				return nil
			})
		}
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}
	ix.fs.mu.Lock()
	ix.fs.nodes[cat] = nodes
	ix.fs.mu.Unlock()
	gr := tree.BuildGraph(cat, doc, docs)
	deleted := make([]*tree.Node, 0, len(lastLive))
	for name, d := range lastLive {
		deleted = append(deleted, tree.ParseNode(gr.Catalog, name, "", d))
	}
	return gr, deleted, nil
}

// lastLive is the document of cat's node name before its tombstone (the
// tombstone's parent), nil if it is gone or there is none.
func (ix *Index) lastLive(ctx context.Context, cat, name, tombstone string) (map[string]any, error) {
	k := cat + "\x00" + name + "\x00" + tombstone
	ix.fs.mu.Lock()
	d, ok := ix.fs.deleted.Get(k)
	ix.fs.mu.Unlock()
	if ok {
		return d, nil
	}
	gone := func(err error) bool { return client.IsGone(err) || client.IsNotFound(err) }
	entries, err := ix.c.Log(ctx, cat, name, tombstone, "")
	if err != nil && !gone(err) {
		return nil, fmt.Errorf("the log of %s/%s: %w", cat, name, err)
	}
	var parent string
	if n := len(entries); err == nil && n > 0 && entries[n-1].ID == tombstone {
		parent = entries[n-1].Parent
	}
	if parent != "" {
		doc, err := ix.c.Doc(ctx, cat, name, parent)
		switch {
		case err == nil:
			d, _ = doc.Value.(map[string]any)
		case !gone(err):
			return nil, fmt.Errorf("%s/%s at %s: %w", cat, name, parent, err)
		}
	}
	ix.fs.mu.Lock()
	ix.fs.deleted.Put(k, d, 1)
	ix.fs.mu.Unlock()
	return d, nil
}

// fview is one subject set's view of a covered namespace at a checkpoint
// (§B.11.9 Visible): its subjects decide item 1, its read filter item 2.
// It memoises each name's answer and is safe for concurrent use.
type fview struct {
	cp       *fcp
	gs       string // the §B.11.9 gs of subjects, which the marker names
	subjects []string
	filter   *grantcheck.ReadFilter
	views    []*catvis.View

	mu   sync.Mutex
	memo map[string]bool
}

func newFview(cp *fcp, subjects []string, filter *grantcheck.ReadFilter) *fview {
	fv := &fview{cp: cp, gs: grantcheck.SubjectSetID(subjects), subjects: subjects, filter: filter, memo: map[string]bool{}}
	for _, c := range cp.cats {
		fv.views = append(fv.views, c.View(subjects))
	}
	return fv
}

// visible reports whether name is visible to the view (§B.11.9), as the
// origin judges it:
//
//   - in a content namespace: some deciding catalog has a live, explicit
//     placement {ns}.{name} that its view passes as if live (item 1,
//     catvis.View.Placement), and the filter allows reading it, roles
//     counting as §B.11.5 counts them (item 2, ReadFilter.AllowsItem);
//   - in a branch: name is live in every base as of the at its branch
//     reads it at, then item 1 in the root and item 2 with the filter of
//     the grant verified in the branch: a name new in the branch is hidden
//     (Branches);
//   - in a catalog: item 2 allows the node, the catalog's node test
//     passes (catvis.View.Node; a tombstoned node's last live document
//     as if live, Deleted resources), and a placement's item is live in
//     its namespace as of the checkpoint (Catalogs).
func (fv *fview) visible(name string) bool {
	fv.mu.Lock()
	v, ok := fv.memo[name]
	fv.mu.Unlock()
	if ok {
		return v
	}
	v = fv.judge(name)
	fv.mu.Lock()
	fv.memo[name] = v
	fv.mu.Unlock()
	return v
}

func (fv *fview) judge(name string) bool {
	if !fv.filter.AllowsItem(name) {
		return false
	}
	cp := fv.cp
	switch cp.kind {
	case fsBranch:
		for _, b := range cp.chain {
			if !cp.live[b.ns][name] {
				return false
			}
		}
		fallthrough
	case fsContent:
		for _, v := range fv.views {
			if v.Placement(cp.root, name) {
				return true
			}
		}
		return false
	}
	if len(cp.cats) == 0 {
		return false
	}
	c, v := cp.cats[0], fv.views[0]
	if n := c.G.Node(name); n != nil && c.G.Explicit(name) {
		return v.Node(n) && fv.itemLive(n)
	}
	n := c.Deleted(name)
	return n != nil && v.AsIfLive(n) && fv.itemLive(n)
}

// itemLive reports, for a placement n, whether its item is live in its
// namespace as of the checkpoint; it is true for a folder.
func (fv *fview) itemLive(n *tree.Node) bool {
	if n.Kind != tree.KindPlacement {
		return true
	}
	return fv.cp.live[n.ItemNS][n.ItemName]
}

// grantFview is a partial reader's view at cp (§B.11.9 gs): its subjects
// are catvis.FilteredSubjects over the deciding subjects of every
// deciding catalog's Profile there, the grant's groups and its ReadsScope
// digest; its filter the grant's (grantcheck.FilterOf). A grant whose
// read rules refer to /now can't read this way: 403.
func grantFview(cp *fcp, v *grant.Verified) (*fview, error) {
	digest, ok := grantcheck.ReadsScope(v)
	if !ok {
		return nil, &grant.AuthError{Status: 403, Msg: "a rule limiting the grant's reads refers to /now"}
	}
	var deciding [][]string
	for _, c := range cp.cats {
		subs, _ := c.Profile().Deciding(v.Principal)
		deciding = append(deciding, subs)
	}
	subjects := catvis.FilteredSubjects(deciding, v.Principal.Groups, digest)
	return newFview(cp, subjects, grantcheck.FilterOf(v)), nil
}

// errRulesChanged and errKeepsAll refuse a cookie for a marker
// reads:{ns}:g:{gs} at a checkpoint it doesn't stand for (§B.11.9 gs,
// §B.11.5): the reader exchanges its grant again.
var (
	errRulesChanged = &grant.AuthError{Status: 403, Msg: "the rules this subject set was issued under have changed: exchange the grant again (§B.11.9)"}
	errKeepsAll     = &grant.AuthError{Status: 403, Msg: "this subject set leaves out groups that decide visibility at this checkpoint: exchange the grant again (§B.11.5, §B.11.9)"}
	errUncovered    = &grant.AuthError{Status: 403, Msg: "the namespace is no longer read filtered: exchange the grant again (§B.11.9)"}
)

// storedFview is the view of a cookie for marker reads:{ns}:g:{gs} at cp,
// judged from what the exchange recorded alone (rec), never from a grant
// the request doesn't carry: 403 where the scope digest of rec's kid's
// scope rules and its roles' definitions, read from ns's document as of
// cp (a branch's keys follow its base, §C.4), with its block rules and
// principal, differs from the one its subjects carry (a kid or role gone,
// or no longer listing read, counts as differing), and where its subjects
// leave out some of the reader's groups and some deciding catalog keeps
// all groups (§B.11.5); otherwise item 1 from rec's subjects and item 2
// from its filter.
func (ix *Index) storedFview(ctx context.Context, cp *fcp, rec *markerRec) (*fview, error) {
	doc, err := ix.docAt(ctx, cp.ns, cp.ids[cp.ns])
	if err != nil {
		return nil, err
	}
	cfg, err := grantcheck.ParseConfig(cp.ns, "", doc)
	if err != nil {
		return nil, errRulesChanged
	}
	keys := cfg.Keys
	if cp.kind == fsBranch {
		eff, err := ix.checker.Config(ctx, cp.ns)
		if err != nil {
			return nil, err
		}
		keys = eff.Keys
	}
	i := slices.IndexFunc(keys, func(k grant.Key) bool { return k.Kid == rec.kid })
	if i < 0 || !keys[i].Lists("read") {
		return nil, errRulesChanged
	}
	in := grantcheck.ScopeInput{ReadScopeResource: keys[i].ReadScopeResource, KeyRules: keys[i].Rules,
		BlockRules: rec.f.BlockRules, Roles: map[string][]any{}, Principal: rec.f.Principal}
	for _, r := range rec.roles {
		// A role that no longer lists read counts as gone, as at the
		// origin (core gsDigestHolds): a cookie never reads where its
		// grant couldn't (§2.1, §A.4).
		def, ok := cfg.Roles[r]
		if !ok || !def.Lists("read") {
			return nil, errRulesChanged
		}
		in.Roles[r] = def.Rules
	}
	d, ok := grantcheck.ScopeDigest(in)
	if !ok || !slices.Contains(rec.subjects, catvis.ScopePrefix+d) {
		return nil, errRulesChanged
	}
	if slices.Contains(rec.subjects, catvis.Partial) {
		for _, c := range cp.cats {
			if c.Profile().KeepAll {
				return nil, errKeepsAll
			}
		}
	}
	return newFview(cp, rec.subjects, rec.f), nil
}

// gMarker is the marker of a partial reader of covered ns with §B.11.9
// subject set gs (§A.4).
func gMarker(ns, gs string) string { return "reads:" + ns + ":g:" + gs }

// cover computes a's view of covered namespace ns at the checkpoint with
// ns at z ("" for the index's committed one), and with a grant (not a
// cookie) sets a's marker and gs to it (§A.4). It is errUncovered for a
// namespace not covered there (a grant's access is then that of an
// uncovered namespace, a cookie's 403), errNotReached before the index's
// first checkpoint of ns and errPurgedNS once ns is purged.
func (ix *Index) cover(ctx context.Context, a *access, ns, z string) error {
	if z == "" {
		id, purged, err := ix.committed(ctx, ns)
		switch {
		case err != nil:
			return err
		case purged:
			return errPurgedNS
		case id == "":
			return errNotReached
		}
		z = id
	}
	if a.cov != nil && a.cov.cp.ids[ns] == z {
		return nil
	}
	cp, err := ix.checkpoint(ctx, ns, z)
	if err != nil {
		return err
	}
	if cp == nil {
		return errUncovered
	}
	fv, err := a.derive(ctx, cp)
	if err != nil {
		return err
	}
	a.setView(ns, fv)
	return nil
}

// setView makes fv a's view; with a grant, a's marker and gs are fv's.
func (a *access) setView(ns string, fv *fview) {
	a.cov, a.allow, a.filter = fv, fv.visible, fv.filter
	if !a.cookie {
		a.marker = gMarker(ns, fv.gs)
		marked(a)
	}
}

// at is a copy of a with its view at cp instead, nil if it can't be
// computed there.
func (a *access) at(ctx context.Context, ns string, cp *fcp) *access {
	fv, err := a.derive(ctx, cp)
	if err != nil {
		return nil
	}
	b := *a
	b.setView(ns, fv)
	return &b
}

// mayBeCovered reports whether ns, which the index hasn't reached, may be
// covered once it has, by its current document: then its coverage, and
// so a partial reader's marker, can't be told yet.
func (ix *Index) mayBeCovered(ctx context.Context, ns string) (bool, error) {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return false, err
	}
	if !fsOpen(cfg.Doc) {
		return false, nil
	}
	_, _, branch := localBase(cfg.Doc)
	if branch || isCatalog(cfg.Doc) {
		return true, nil
	}
	cats, _ := cfg.Doc["catalogs"].(map[string]any)
	return len(cats) > 0, nil
}

// members are the namespaces cp's at covers but ns, sorted.
func (cp *fcp) members() []string {
	out := make([]string, 0, len(cp.ids))
	for m := range cp.ids {
		if m != cp.ns {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}

// coverTags are the Cache-Tags of an answer at cp besides its hits':
// idx:{m} for every namespace in at (§A.4).
func coverTags(cp *fcp) []string {
	tags := []string{"idx:" + cp.ns}
	for _, m := range cp.members() {
		tags = append(tags, "idx:"+m)
	}
	return tags
}
