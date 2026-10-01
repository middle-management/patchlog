package tree

import "sort"

// Hypothetical graphs, for tools that judge a change before it is made: the
// merge service classifying a catalog branch's changes as narrowing or
// widening access (§F.9), and the catalog service checking a merge batch
// (§F.8). Neither is followed or stored.

// BuildGraph builds the graph of catalog from its namespace document and
// its node documents (name -> document), as the tree service would after
// following them. Every placement's item counts as live, so access is
// judged structurally: as if every item existed (a release creates its
// items in another namespace, in another step).
func BuildGraph(catalog string, config map[string]any, docs map[string]any) *Graph {
	g := newGraph(catalog)
	if config != nil {
		g.setConfig(config)
	}
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if docs[name] == nil {
			continue
		}
		n := ParseNode(catalog, name, "", docs[name])
		if n.ItemNS != "" {
			n.ItemState = ItemLive
		}
		g.setExplicit(n)
	}
	g.analyze()
	return g
}

// With returns a copy of g in which changes (node name -> document, or nil
// to remove the node) replace explicit nodes. Implicit placements and
// item states are kept; a new placement's item counts as live. g itself is
// not changed, so With may be called under the service's read lock.
func (g *Graph) With(changes map[string]any) *Graph {
	h := newGraph(g.Catalog)
	h.Config, h.Trust = g.Config, map[string]bool{}
	for ns := range g.Trust {
		h.Trust[ns] = true
	}
	h.Aliases = g.Aliases
	for name, n := range g.self {
		c := *n
		h.self[name] = &c
		h.refresh(name)
	}
	for name, n := range g.explicit {
		if _, changed := changes[name]; changed {
			continue
		}
		c := *n
		h.explicit[name] = &c
		h.refresh(name)
	}
	names := make([]string, 0, len(changes))
	for n := range changes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		doc := changes[name]
		if doc == nil {
			continue
		}
		n := ParseNode(g.Catalog, name, "", doc)
		if old := g.explicit[name]; old != nil {
			n.ItemState, n.ItemHead = old.ItemState, old.ItemHead
		} else if s := g.self[name]; s != nil {
			n.ItemState, n.ItemHead = s.ItemState, s.ItemHead
		} else if n.ItemNS != "" {
			n.ItemState = ItemLive
		}
		h.explicit[name] = n
		h.refresh(name)
	}
	h.analyze()
	return h
}

// Explicit reports whether name is an explicit node (a catalog document),
// not an implicit placement.
func (g *Graph) Explicit(name string) bool { return g.explicit[name] != nil }
