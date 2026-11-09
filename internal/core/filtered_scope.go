package core

import (
	"github.com/middle-management/patchlog/internal/catvis"
)

// Filtered namespace reads (§B.11.9), an origin MAY that this one
// implements unless Options.NoFilteredReads. A partial reader, one whose
// grant verifies in a namespace and allows read there without reading it
// unrestricted (§2.1), reads a covered namespace's /heads, log ranges,
// long-poll and events filtered to what it may see, at URLs under
// /ns/{ns}/g/{gs}, where gs is its subject set: the deciding subjects of
// every catalog the namespace trusts, plus scope:{digest} of its read
// rules (§A.4).
//
// The files of this feature, each read inside one read transaction:
//
//   - filtered_scope.go: which namespaces are covered (fscope, §B.11.9
//     Where);
//   - filtered_state.go: the combined checkpoint a filtered answer is at
//     (fcp, at), and the stored subject sets (filtered_gs) and checkpoints
//     (filtered_ats);
//   - filtered_graph.go: a catalog's graph and its trusted content
//     namespaces' documents as of a checkpoint (catvis.Catalog);
//   - filtered_visible.go: whether a name is visible (fview);
//   - filtered_admit.go: a request's subject set, from a grant
//     (grantView) or a cookie (filteredAdmit);
//   - filtered_exchange.go: POST /edge-grants for a partial reader, whose
//     edge grant covers /ns/{ns}/g/{gs} alone.
//
// Uncovered namespaces behave as before v0.75: every path here is reached
// only through filteredScope.

// Kinds of covered namespace (fscope.kind).
const (
	fsContent = iota // trusts a catalog
	fsBranch         // a local branch, recursively, of a content namespace
	fsCatalog        // a catalog that a content namespace trusts
)

// fscope is a covered namespace (§B.11.9 Where), as of the read snapshot.
type fscope struct {
	n    *nsRow
	kind int
	// root is the content namespace whose catalogs decide visibility: n
	// for content kind, a branch's root, nil for catalog kind.
	root *nsRow
	// chain are a branch's bases, from its own base up to root, each with
	// the ns_log seq its branch reads it at (baseAt).
	chain []fsBase
	// cats are the catalogs root trusts, sorted by name, e2e ones
	// included (they make nothing visible); for catalog kind, n itself.
	cats []fsCat
}

// fsBase is a base of a branch, read as of at.
type fsBase struct {
	n  *nsRow
	at int64
}

// fsCat is a trusted catalog: e2e if the origin can't read it, with the
// kids of root's keys whose requireAt names it (catvis.TrustedCatalogs;
// none for catalog kind).
type fsCat struct {
	n    *nsRow
	e2e  bool
	kids []string
}

// filteredScope is n's coverage by §B.11.9, nil if it isn't covered:
//
//   - content kind: a local namespace, not a shadow or a remote branch,
//     neither public nor sealed nor e2e (nsLevel below sealed), that
//     trusts some catalog through a requireAt key (catvis.TrustedCatalogs
//     over its current document and those of its local, unpurged
//     catalogs);
//   - branch kind: a local branch of such a namespace, recursively, itself
//     neither public nor sealed; the root's trust and keys are read from
//     its document as of the seq the chain fixes (its baseAt);
//   - catalog kind: a catalog, neither public nor sealed, that some local
//     namespace of its catalog.trust trusts as content kind.
//
// A catalog's own branches, remote branches and shadows aren't covered,
// nor is anything with authentication disabled, where every reader reads
// unrestricted (§1), or with Options.NoFilteredReads.
func (t *tx) filteredScope(n *nsRow) *fscope {
	if n == nil || t.e.opt.NoFilteredReads || t.e.opt.AuthDisabled || n.isShadow() {
		return nil
	}
	if !t.fsOpen(n, t.config(n.configSeq)) {
		return nil
	}
	if n.isBranch() {
		fs := &fscope{n: n, kind: fsBranch}
		b := n
		for b.isBranch() {
			if t.remoteShadow(b) != nil {
				return nil
			}
			base := t.nsByID(b.base.Int64)
			fs.chain = append(fs.chain, fsBase{n: base, at: b.baseAt.Int64})
			b = base
		}
		root := b
		rootCfg := t.fconfigAt(fs.chain[len(fs.chain)-1].at)
		if root.purged || rootCfg.IsCatalog || !t.fsOpen(root, t.config(root.configSeq)) || !t.fsOpen(root, rootCfg) {
			return nil
		}
		fs.root, fs.cats = root, t.fsTrust(root, rootCfg.Doc)
		if len(fs.cats) == 0 {
			return nil
		}
		return fs
	}
	cfg := t.config(n.configSeq)
	if cats := t.fsTrust(n, cfg.Doc); len(cats) > 0 {
		return &fscope{n: n, kind: fsContent, root: n, cats: cats}
	}
	if !cfg.IsCatalog {
		return nil
	}
	for _, name := range cfg.CatalogTrust {
		m := t.fsLocal(name)
		if m == nil || m.isBranch() || m.purged || !t.fsOpen(m, t.config(m.configSeq)) {
			continue
		}
		for _, c := range t.fsTrust(m, t.config(m.configSeq).Doc) {
			if c.n.id == n.id {
				return &fscope{n: n, kind: fsCatalog, cats: []fsCat{{n: n}}}
			}
		}
	}
	return nil
}

// fsOpen reports whether a namespace with document cfg can be covered:
// not public, not sealed or e2e (§B.11.9 Where).
func (t *tx) fsOpen(n *nsRow, cfg *Config) bool {
	return cfg.Read != "public" && cfg.level < levelSealed && t.nsLevel(n) < levelSealed
}

// fsLocal is the local namespace named name, nil for none, a shadow or a
// remote branch (whose base is in another deployment).
func (t *tx) fsLocal(name string) *nsRow {
	m := t.nsByName(name)
	if m == nil || m.isShadow() || t.remoteShadow(m) != nil {
		return nil
	}
	return m
}

// fsTrust are the catalogs root trusts with document doc, read from their
// current documents: local, unpurged namespaces only (catvis.TrustedCatalogs).
func (t *tx) fsTrust(root *nsRow, doc map[string]any) []fsCat {
	rows := map[string]*nsRow{}
	trusts := catvis.TrustedCatalogs(root.name, doc, func(cat string) map[string]any {
		c := t.fsLocal(cat)
		if c == nil || c.purged {
			return nil
		}
		rows[cat] = c
		return t.config(c.configSeq).Doc
	})
	out := make([]fsCat, 0, len(trusts))
	for _, tr := range trusts {
		c := rows[tr.Catalog]
		out = append(out, fsCat{n: c, e2e: t.nsLevel(c) == levelE2E, kids: tr.Kids})
	}
	return out
}

// fconfigAt is the namespace document in force after the ns_log entry seq.
func (t *tx) fconfigAt(seq int64) *Config {
	var cseq int64
	t.must(t.QueryRow(`SELECT config_seq FROM ns_log WHERE seq = ?`, seq).Scan(&cseq))
	return t.config(cseq)
}
