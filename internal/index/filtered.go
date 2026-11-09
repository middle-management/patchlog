package index

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
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
//     keys are read from its document as of the baseAt the chain fixes,
//     and the branch stays covered only while the root, at its head,
//     still trusts each deciding catalog through every key counted there,
//     each unchanged (§B.11.9 Branches, §C.4; branchTrustHolds);
//   - catalog kind: a catalog, neither public nor sealed, that some local
//     namespace of its catalog.trust trusts as content kind.
//
// A partial reader of a covered namespace (one whose grant allows read
// there without a namespace-wide edge grant, §C.5.2) reads it filtered by
// visibility (§B.11.9 Visible): its marker is reads:{ns}:g:{gs}, gs being
// the origin's (catvis.FilteredSubjects over every deciding catalog's
// Profile, its groups and grantcheck.ReadsScope's digest, with
// catvis.KeySubject of its key), and its
// answers are at the combined checkpoint (grantcheck.CombinedAt) of every
// namespace visibility reads, which they list as namespaces, one ns_id per
// namespace (§B.11.9 URLs, §A.4 Answers; fcp.ids):
//
//   - {ns} at the index's checkpoint;
//   - each trusted, non-e2e, unpurged catalog, and each local, unpurged
//     member of those catalogs' catalog.trust, a branch's root among
//     them, at its head (memberAt): the index's checkpoint of it, whether
//     it serves it or follows it only for this (members.go);
//   - for a branch, each base read only as a base, at the baseAt its
//     branch reads it at, which the branch's entry fixes.
//
// Where visibility reads each namespace is kept apart from what is listed
// (fcp.reads): a branch's bases, the root among them, are read as of the
// baseAt its branch reads them at, whatever ns_id they are listed at.
//
// The index follows those catalogs, members and bases without serving them
// (members.go), so that their purges reach idx:{m} and kept results (§A.1):
// it reads each one's state as of the id in the checkpoint, which never
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
// at is grantcheck.CombinedAt over ids, and cats the deciding catalogs'
// visibility as of reads. It is immutable.
type fcp struct {
	ns    string
	kind  int
	root  string   // the content namespace whose catalogs decide; "" for catalog kind
	chain []fsBase // a branch's bases, from its own up to root
	at    string
	// ids are the namespaces the checkpoint lists, one ns_id each (§A.4
	// Answers, §B.11.9 URLs), which at, answers' namespaces, idx: tags
	// (coverTags) and min judge by: a namespace read at its head ({ns},
	// each deciding catalog, each member of their catalog.trust, a
	// branch's root among them) at that head, a base read only as a base
	// (onlyBase) at the baseAt its branch reads it at.
	ids map[string]string
	// reads are where visibility reads each namespace in ids, never what is
	// listed: ids' ns_ids, but every base of a branch's chain at the baseAt
	// its branch reads it at (its live names, and for the root its trust,
	// keys and roles, catalogAt).
	reads map[string]string
	// onlyBase are the bases ids lists at their baseAt because nothing
	// reads them at their head: an answer across namespaces lists each at
	// its own checkpoint instead where it has one (refsMerge, keptCPsIn).
	onlyBase map[string]bool
	cats     []*catvis.Catalog
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

// errGrantLacks is a namespace the index's own grant (Options.Client)
// can't read, 401 or 403, that it reads only to tell whether §B.11.9
// covers a namespace it follows, or what visibility reads there: a
// catalog that namespace's catalogs names through a requireAt key, each
// namespace a followed catalog's catalog.trust lists, a branch's bases,
// and their state at a checkpoint. Its coverage can't be told, so a
// partial reader is refused (502) rather than answered as by an
// uncovered namespace's rules, which could show what visibility hides
// (§B.11.9 Visible). Its Error names the namespace, for the operator's
// log; answers don't, as /principal doesn't name a catalog's trust to
// one who can't read the catalog whole (§7.4).
type errGrantLacks struct {
	ns  string
	err error
}

func (e *errGrantLacks) Error() string {
	return "the index's grant cannot read " + e.ns + ", which tells whether §B.11.9 covers a namespace the index follows, or what visibility reads there (widen Options.Client's grant to it): " + e.err.Error()
}

func (e *errGrantLacks) Unwrap() error { return e.err }

// msgGrantLacks answers errGrantLacks.
const msgGrantLacks = "the index's grant cannot read a namespace that decides how this one is read (§B.11.9): see the index's log"

// lacksRead is err, an upstream read of ns, as errGrantLacks where it is
// 401 or 403.
func lacksRead(ns string, err error) error {
	if ae, ok := client.AsAPIError(err); ok && (ae.Status == 401 || ae.Status == 403) {
		return &errGrantLacks{ns: ns, err: err}
	}
	return err
}

// fstate is what the index keeps to compute checkpoints: caches only, of
// state that never changes once read (namespace documents, /heads and
// documents at an ns_id, graphs at a checkpoint).
type fstate struct {
	mu      sync.Mutex
	docs    lru.Cache[string, map[string]any]  // ns \0 ns_id → namespace document
	live    lru.Cache[string, map[string]bool] // ns \0 ns_id → names live there
	cats    lru.Cache[string, *catvis.Catalog] // catalogKey → catalog
	cps     lru.Cache[string, *fcp]            // ns \0 at → checkpoint, for URLs at older ats
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
		return nil, lacksRead(ns, fmt.Errorf("the document of %s at %s: %w", ns, id, err))
	}
	if doc.Value == nil {
		doc.Value = map[string]any{}
	}
	ix.fs.mu.Lock()
	ix.fs.docs.Put(k, doc.Value, 1)
	ix.fs.mu.Unlock()
	return doc.Value, nil
}

// sharedReadTimeout bounds a read that shared serves to every request
// that joined it.
const sharedReadTimeout = 30 * time.Second

// shared runs f once for every concurrent caller with key, as the core's
// shared live reads do: f runs under a context that no caller's
// cancellation ends, bounded by sharedReadTimeout, so a request that goes
// away doesn't fail the others that joined its read; each caller stops
// waiting when its own ctx ends.
func (ix *Index) shared(ctx context.Context, key string, f func(ctx context.Context) (any, error)) (any, error) {
	ch := ix.fs.flight.DoChan(key, func() (any, error) {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sharedReadTimeout)
		defer cancel()
		return f(sctx)
	})
	select {
	case r := <-ch:
		return r.Val, r.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
	v, err := ix.shared(ctx, "live\x00"+k, func(ctx context.Context) (any, error) {
		items, err := ix.c.Heads(ctx, ns, id)
		if err != nil {
			return nil, lacksRead(ns, fmt.Errorf("the heads of %s at %s: %w", ns, id, err))
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

// memberAt is the ns_id a namespace read at its head is taken at, as a
// member of a checkpoint (a catalog, a catalog.trust member) or as a
// branch's root judged at its head (coverage): its committed position,
// the index's checkpoint if it serves m and has reached it, otherwise the
// checkpoint its follower for visibility committed (members.go, memberCP:
// "the service follows the namespaces visibility reads", §A.4), once it
// has reached the head the grant checker read, waiting for it up to
// MinWait, never a head no follower has applied; its document there is
// docAt(m, id), which never changes. ok is false for a namespace that is
// purged, doesn't exist or is a remote branch (§B.11.9: local, unpurged
// members only); err is a document the index can't read, or errNotReached
// before m's follower holds its first checkpoint (503 behind to partial
// readers). Callers depend on that contract alone, not on where the
// position comes from.
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
		return "", false, lacksRead(m, fmt.Errorf("the head of %s: %w", m, err))
	case remoteBranch(cfg.Doc):
		return "", false, nil
	}
	ix.seedDoc(cfg)
	return ix.memberCP(ctx, m, cfg.Head)
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
		// the root must also be open, and unpurged, now, at its head.
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
		if err != nil || len(cats) == 0 || !branchTrustHolds(cp.root, bdoc, cur, cats) {
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
		// Whether m trusts ns, ns's document alone deciding: the other
		// catalogs m names are none of this one's coverage, and aren't
		// read (errGrantLacks).
		if len(catvis.TrustedCatalogs(m, mdoc, func(c string) map[string]any {
			if c == ns {
				return doc
			}
			return nil
		})) > 0 {
			cp.kind = fsCatalog
			return cp, []fsCat{{ns: ns, id: z, doc: doc}}, nil
		}
	}
	return nil, nil, nil
}

// branchTrustHolds reports whether a branch whose root is root, with
// document bdoc as of the branch's baseAt and cur at its head, stays
// covered (§B.11.9 Branches: "only while the namespace that trusts the
// catalog still trusts it, at its head, through every key item 1 counts,
// each unchanged (§C.4)"): for each non-e2e catalog cats counts from
// bdoc, cur still trusts it (its catalogs names it, and its catalog.trust,
// as of the catalog's own head, lists root), and for each kid counted
// there cur holds a key whose requireAt names it, its entries under that
// kid equal, as canonical JSON, to bdoc's (the whole entry: any edit, a
// pub rotated under the same kid among them, uncovers the branch). Keys
// cur adds are not counted. An e2e catalog makes nothing visible either
// way.
func branchTrustHolds(root string, bdoc, cur map[string]any, cats []fsCat) bool {
	for _, c := range cats {
		if c.e2e {
			continue
		}
		head := catvis.TrustedCatalogs(root, cur, func(name string) map[string]any {
			if name == c.ns {
				return c.doc
			}
			return nil
		})
		i := slices.IndexFunc(head, func(tr catvis.Trust) bool { return tr.Catalog == c.ns })
		if i < 0 {
			return false
		}
		for _, kid := range c.kids {
			if !slices.Contains(head[i].Kids, kid) || !bytes.Equal(keyEntries(bdoc, kid), keyEntries(cur, kid)) {
				return false
			}
		}
	}
	return true
}

// keyEntries are the entries of doc's keys with kid, in order, as
// canonical JSON.
func keyEntries(doc map[string]any, kid string) []byte {
	keys, _ := doc["keys"].([]any)
	var out []any
	for _, k := range keys {
		if m, _ := k.(map[string]any); m != nil && m["kid"] == kid {
			out = append(out, m)
		}
	}
	return jsonv.Canonical(out)
}

// checkpoint is ns's combined checkpoint with ns at z, the index's
// checkpoint of it, nil if ns isn't covered (§B.11.9 URLs, §A.4). It
// reads every member's state it needs and keeps the result by at.
func (ix *Index) checkpoint(ctx context.Context, ns, z string) (*fcp, error) {
	cp, cats, err := ix.coverage(ctx, ns, z)
	if err != nil || cp == nil {
		return nil, err
	}
	// Listed once each (§A.4 Answers): a namespace read at its head at
	// it, a base read only as a base at its baseAt; read where visibility
	// reads it.
	cp.ids, cp.onlyBase = map[string]string{}, map[string]bool{}
	add := func(m, id string) {
		if _, ok := cp.ids[m]; !ok {
			cp.ids[m] = id
		}
	}
	add(ns, z)
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
	cp.reads = maps.Clone(cp.ids)
	for _, b := range cp.chain {
		// A base the index doesn't serve has a follower (members.go).
		if err := ix.baseFollowed(ctx, b.ns); err != nil {
			return nil, err
		}
		if _, ok := cp.ids[b.ns]; !ok {
			cp.ids[b.ns], cp.onlyBase[b.ns] = b.at, true
		}
		cp.reads[b.ns] = b.at
	}
	cp.at = grantcheck.CombinedAt(cp.ids)
	for _, c := range deciding {
		cv, err := ix.catalogAt(ctx, c, cp.reads)
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
		l, err := ix.liveAt(ctx, m, cp.reads[m])
		if err != nil {
			return nil, err
		}
		cp.live[m] = l
	}
	ix.fs.mu.Lock()
	ix.fs.cps.Put(cp.ns+"\x00"+cp.at, cp, 1)
	ix.fs.mu.Unlock()
	return cp, nil
}

// keptCP is the checkpoint at of ns computed earlier, nil if none is
// held: a reader's gs at an older at is computed there (§B.11.9: a
// grant reads at its own gs as of the URL's at).
func (ix *Index) keptCP(ns, at string) *fcp {
	ix.fs.mu.Lock()
	defer ix.fs.mu.Unlock()
	if cp, ok := ix.fs.cps.Get(ns + "\x00" + at); ok {
		return cp
	}
	return nil
}

// keptCPsIn are the checkpoints of ns the index holds that an answer
// across namespaces at ids (its namespaces, refsMerge) was read at: ns
// and each of their members at its id in ids, but a base listed only as
// a base (onlyBase), which ids may hold at its own checkpoint instead
// (§A.4 Across namespaces).
func (ix *Index) keptCPsIn(ns string, ids map[string]string) []*fcp {
	ix.fs.mu.Lock()
	defer ix.fs.mu.Unlock()
	var out []*fcp
	for _, k := range ix.fs.cps.Keys() {
		cp, ok := ix.fs.cps.Get(k)
		if !ok || cp.ns != ns {
			continue
		}
		in := true
		for m, id := range cp.ids {
			got, ok := ids[m]
			if !ok || (!cp.onlyBase[m] && got != id) {
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

// catalogAt is catalog c's visibility as of ids, where visibility reads
// each namespace (fcp.reads, §B.11.9 Visible): its graph from its
// documents at ids[c.ns], its tombstoned nodes from their last live
// documents, and its catalog.trust members in ids as its content
// namespaces, each with its document as of its id (for a branch's root,
// as of the branch's baseAt) and the kids of its keys whose requireAt
// names c.
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
	v, err := ix.shared(ctx, "cat\x00"+k, func(ctx context.Context) (any, error) {
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
		return nil, nil, lacksRead(cat, fmt.Errorf("the heads of %s at %s: %w", cat, id, err))
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
// digest, with catvis.KeySubject of its key, as the origin's; its filter
// the grant's (grantcheck.FilterOf). A grant whose
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
	pub, _ := v.Key.Raw["pub"].(string)
	subjects := append(catvis.FilteredSubjects(deciding, v.Principal.Groups, digest), catvis.KeySubject(v.Key.Kid, pub))
	slices.Sort(subjects)
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

// storedFview is the view of a cookie for marker m, reads:{ns}:g:{gs}, at
// cp, judged from what the exchanges recorded alone (rec, gsKeys), never
// from a grant the request doesn't carry: 403 where, for any key a live
// cookie of m came from (gsKeys: the cookie doesn't say which is its
// own, so each must hold), the scope digest of its kid's scope rules and
// its roles' definitions, read from ns's document as of cp (a branch's
// keys follow its base, §C.4), with rec's block rules and principal,
// differs from the one rec's subjects carry (a kid or role gone, or no
// longer listing read, counts as differing), or the key with its kid no
// longer has the pub it had (§B.11.9 gs: a key "no longer accepted" as
// §C.4 judges a base's keys, "only while the base has it with the same
// pub"; a record without one, from before migration 006, never does),
// where m has no such key recorded (from before migration 007), and where
// its subjects leave out some of the reader's groups and some deciding
// catalog keeps all groups (§B.11.5); otherwise item 1 from rec's
// subjects and item 2 from its filter. Readers with the same subjects
// and rules share m, so once a key one came from is replaced, the
// others' cookies are 403 too, until the replaced key's last cookie
// expires: never a cookie read under a key no longer accepted.
func (ix *Index) storedFview(ctx context.Context, cp *fcp, m string, rec *markerRec) (*fview, error) {
	recorded, err := ix.gsKeys(ctx, m, ix.opt.Now())
	if err != nil {
		return nil, err
	}
	if len(recorded) == 0 {
		return nil, errRulesChanged
	}
	doc, err := ix.docAt(ctx, cp.ns, cp.reads[cp.ns])
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
	for _, k := range recorded {
		if !gsKeyHolds(cfg, keys, rec, k) {
			return nil, errRulesChanged
		}
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

// gsKeyHolds reports whether k, a key a cookie of rec's marker came from,
// is still accepted with the pub it had, among keys (cfg's, or for a
// branch its effective ones, §C.4), and its scope rules and its roles'
// definitions in cfg, with rec's block rules and principal, still digest
// to the scope subject rec's subjects carry (storedFview).
func gsKeyHolds(cfg *grantcheck.Config, keys []grant.Key, rec *markerRec, k gsKey) bool {
	i := slices.IndexFunc(keys, func(key grant.Key) bool { return key.Kid == k.kid })
	if i < 0 || !keys[i].Lists("read") || k.pub == "" || keyPub(keys[i]) != k.pub {
		return false
	}
	in := grantcheck.ScopeInput{ReadScopeResource: keys[i].ReadScopeResource, KeyRules: keys[i].Rules,
		BlockRules: rec.f.BlockRules, Roles: map[string][]any{}, Principal: rec.f.Principal}
	for _, r := range k.roles {
		// A role that no longer lists read counts as gone, as at the
		// origin (core gsDigestHolds): a cookie never reads where its
		// grant couldn't (§2.1, §A.4).
		def, ok := cfg.Roles[r]
		if !ok || !def.Lists("read") {
			return false
		}
		in.Roles[r] = def.Rules
	}
	d, ok := grantcheck.ScopeDigest(in)
	return ok && slices.Contains(rec.subjects, catvis.ScopePrefix+d)
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
// idx:{m} for every namespace in at, as listed (ids, §A.4).
func coverTags(cp *fcp) []string {
	tags := []string{"idx:" + cp.ns}
	for _, m := range cp.members() {
		tags = append(tags, "idx:"+m)
	}
	return tags
}
