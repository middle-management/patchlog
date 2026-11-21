package index

import (
	"context"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/lru"
)

// Hits are filtered per revision (§A.4 Private namespaces, §7.9 Visible,
// §C.2 item 5): a hit is shown only where its head revision as of the
// checkpoint is visible to the reader, judged with that revision's read
// envelope, doc being the revision's document (a sealed one opened with
// the index's keys, v0.89), or null in an
// end-to-end namespace, where every rule on /doc fails. A filter whose
// rules don't refer to /doc decides by name. Otherwise the document is
// fetched from the origin, with the index's own grant, which reads the
// namespace unrestricted (§A.1), and each answer is kept per filter,
// name and revision id: an id determines its document (§3.3), so the
// answer never changes (§7.9 Cost, SHOULD).

// allowFunc reports whether a reader may see revision id of resource.
type allowFunc func(resource, id string) bool

// revJudged keeps answers by filter, name and revision id.
type revJudged struct {
	mu sync.Mutex
	m  lru.Cache[string, bool]
}

const revJudgedMax = 1 << 16

// revAllow is the allowFunc of filter f for namespace ns.
func (ix *Index) revAllow(ns string, f *grantcheck.ReadFilter) allowFunc {
	if !f.RefersToDoc() {
		return func(resource, _ string) bool { return f.Allows(resource) }
	}
	key := f.Encode()
	return func(resource, id string) bool {
		k := key + "\x00" + ns + "\x00" + resource + "\x00" + id
		ix.judged.mu.Lock()
		v, ok := ix.judged.m.Get(k)
		ix.judged.mu.Unlock()
		if ok {
			return v
		}
		doc, hasDoc, stable := ix.revDoc(ns, resource, id)
		v = f.AllowsDoc(resource, doc, hasDoc)
		if stable {
			ix.judged.mu.Lock()
			if ix.judged.m.MaxEntries == 0 {
				ix.judged.m.MaxEntries = revJudgedMax
			}
			ix.judged.m.Put(k, v, 1)
			ix.judged.mu.Unlock()
		}
		return v
	}
}

// revDoc is the document of revision id of ns/resource for a read
// envelope: none (null) without an id, in an end-to-end
// namespace, or where the origin doesn't serve it. stable reports an
// answer that can be kept: not one that failed for now.
func (ix *Index) revDoc(ns, resource, id string) (doc any, hasDoc, stable bool) {
	if id == "" {
		return nil, false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return nil, false, false
	}
	if derived.InfoOf(cfg.Doc).Level == derived.LevelE2E {
		// Only end-to-end: a sealed namespace's documents, which the index
		// opens with its keys, are judged (SERVICES §A.4, v0.89).
		return nil, false, true
	}
	d, err := ix.c.Doc(ctx, ns, resource, id)
	if err != nil || d == nil {
		return nil, false, false
	}
	return d.Value, true, true
}
