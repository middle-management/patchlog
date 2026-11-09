package core

import (
	"sort"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/lru"
	"github.com/middle-management/patchlog/internal/tree"
)

// Catalog graphs as of a checkpoint (§B.11.9 Visible, D): the catalog's
// document and its live node documents at the catalog's seq in the
// checkpoint, and its tombstoned nodes' last live documents, read through
// the core's own decode paths (docAt, so compression, at-rest and sealed
// encryption are handled), and built with tree.BuildGraph, which counts
// every item as live, as judging a deleted resource as if live needs. Its
// trusted content namespaces are the catalog.trust members in the
// checkpoint, each as of its own seq, with the kids of its keys whose
// requireAt names the catalog.

// filteredCatalogs caches built catalogs. The Engine has no field for it,
// so the cache is the process's, and its key names what a catalog is
// built from by content: the catalog's ns_id at its seq and at its head
// (a purge or prune of a node after the seq appends an entry, so its head
// moves and a stale graph is never served), and each content member's
// ns_id at its seq. ns_ids are hashes over their chains (§3.5), so two
// engines share an entry only for the same histories. It is only a cache.
var filteredCatalogs struct {
	mu  sync.Mutex
	lru lru.Cache[string, *catvis.Catalog]
}

// filteredContents caches the grant-check form of namespace documents,
// keyed by the core's parsed document, which t.config keeps per row.
var filteredContents struct {
	mu  sync.Mutex
	lru lru.Cache[*Config, *grantcheck.Config]
}

const (
	filteredCatalogsMax = 64
	filteredContentsMax = 1024
)

// catalogAt is catalog c's graph and contents as of cp (cp.seqs[c]).
func (t *tx) catalogAt(c *fsCat, cp *fcp) *catvis.Catalog {
	cat := c.n
	seq := cp.seqs[cat.name]
	catCfg := t.fconfigAt(seq)
	members := catvis.TrustList(cat.name, catCfg.Doc)
	var key strings.Builder
	key.WriteString(cat.name + "\x00" + cp.ids[cat.name] + "\x00" + t.nsLogID(cat.headSeq.Int64).String())
	var inCP []string
	for _, m := range members {
		if _, ok := cp.seqs[m]; ok {
			inCP = append(inCP, m)
			key.WriteString("\x00" + m + "\x00" + cp.ids[m])
		}
	}
	k := key.String()
	filteredCatalogs.mu.Lock()
	cv, ok := filteredCatalogs.lru.Get(k)
	filteredCatalogs.mu.Unlock()
	if ok {
		return cv
	}
	docs, last := map[string]any{}, map[string]any{}
	for _, h := range t.listHeads(cat, &seq) {
		if (h.state != Live && h.state != Tombstoned) || h.row == nil {
			continue
		}
		doc, err := t.docAt(h.row)
		t.must(err)
		if h.state == Live {
			docs[h.name] = doc
		} else {
			last[h.name] = doc
		}
	}
	g := tree.BuildGraph(cat.name, catCfg.Doc, docs)
	// Tombstoned nodes, from their last live documents, are judged as if
	// live, and their own $access keeps deciding (§B.11.9 Deleted
	// resources). A purged node has no documents: it stays hidden.
	deleted := make([]*tree.Node, 0, len(last))
	for name, doc := range last {
		deleted = append(deleted, tree.ParseNode(g.Catalog, name, "", doc))
	}
	contents := map[string]*catvis.Content{}
	for _, m := range inCP {
		mcfg := t.fconfigAt(cp.seqs[m])
		ct := &catvis.Content{NS: m, Cfg: grantCheckConfig(m, mcfg)}
		for _, tr := range catvis.TrustedCatalogs(m, mcfg.Doc, func(name string) map[string]any {
			if name == cat.name {
				return catCfg.Doc
			}
			return nil
		}) {
			ct.Kids = tr.Kids
		}
		contents[m] = ct
	}
	cv = catvis.NewCatalogDeleted(g, contents, deleted)
	filteredCatalogs.mu.Lock()
	if filteredCatalogs.lru.MaxEntries == 0 {
		filteredCatalogs.lru.MaxEntries = filteredCatalogsMax
	}
	filteredCatalogs.lru.Put(k, cv, 1)
	filteredCatalogs.mu.Unlock()
	return cv
}

// grantCheckConfig is cfg as grantcheck parses it, for ns (nil if it
// doesn't parse, through which nothing then counts).
func grantCheckConfig(ns string, cfg *Config) *grantcheck.Config {
	filteredContents.mu.Lock()
	gc, ok := filteredContents.lru.Get(cfg)
	filteredContents.mu.Unlock()
	if ok {
		return gc
	}
	gc, err := grantcheck.ParseConfig(ns, "", cfg.Doc)
	if err != nil {
		gc = nil
	}
	filteredContents.mu.Lock()
	if filteredContents.lru.MaxEntries == 0 {
		filteredContents.lru.MaxEntries = filteredContentsMax
	}
	filteredContents.lru.Put(cfg, gc, 1)
	filteredContents.mu.Unlock()
	return gc
}

// placementNames are the names of the explicit placements of ns's items
// in g, with the "{ns}." prefix cut, sorted.
func placementNames(g *tree.Graph, ns string) []string {
	var out []string
	for _, name := range g.Names() {
		if item, ok := strings.CutPrefix(name, ns+"."); ok && g.Explicit(name) && ValidResourceName(item) {
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}
