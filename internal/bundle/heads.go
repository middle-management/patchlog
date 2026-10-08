package bundle

import (
	"context"
	"sort"

	"github.com/middle-management/patchlog/internal/client"
)

// Target heads (§G.4.4): classifying a document starts from its head in
// the target, and a snapshot document's also from its upstream
// resource's. Where an import looks up many resources of a namespace, it
// reads them from the namespace's heads listing (§7.4), a page of up to
// the log page size per request, instead of one request per resource.
//
// The listing is the namespace as of one revision, and the lookups it
// replaces see it at other moments, all before the first batch. Either
// way an item's ifMatch or ifNoneMatch names the head it was classified
// against, so a write landing after the listing fails the batch with 412,
// as one landing after a lookup does.

// headsPerPage is how many lookups each page of a listing must replace: an
// import lists at most one page per headsPerPage resources it looks up in
// a namespace, and looks up those past where the listing stopped one by
// one. A small import into a large namespace keeps its lookups.
const headsPerPage = 10

// listing is what an import read of a namespace's heads: every resource
// up to through, in byte order (§7.4), or every resource if complete.
type listing struct {
	heads    map[string]client.HeadItem
	through  string
	complete bool
}

// head reads the head of ns/name in the target: from the namespace's
// listing when it covers name, else from GET /r/{ns}/{name}. A listing
// doesn't give a tombstone's last live revision (client.Head.Last), which
// the import doesn't use.
func (im *importer) head(ctx context.Context, ns, name string) (*client.Head, error) {
	if l := im.listing(ctx, ns); l != nil && (l.complete || name <= l.through) {
		it, ok := l.heads[name]
		switch {
		case !ok:
			return &client.Head{State: client.NotFound}, nil
		case it.Kind == "head":
			return &client.Head{State: client.Live, ID: it.Target}, nil
		case it.Kind == "tombstone":
			return &client.Head{State: client.Tombstoned, ID: it.Target}, nil
		case it.Kind == "purge":
			return &client.Head{State: client.Purged}, nil
		}
	}
	return im.c.Head(ctx, ns, name)
}

// listing lists ns's heads, once, if the import looks up at least
// headsPerPage resources there: page by page, up to the last of them or
// until its pages are used up. With authentication disabled (§1) every
// namespace is readable, so one that answers 404 doesn't exist and has no
// resources. Without a listing (nil) the lookups go to GET /r/{ns}/{name}
// as before: when the namespace doesn't list for the importer (a grant
// that may read only some of its resources, §7.6), and when it is frozen,
// as a purged namespace is, which answers 410 for every name, listed or
// not (§8.5).
func (im *importer) listing(ctx context.Context, ns string) *listing {
	if l, ok := im.listed[ns]; ok {
		return l
	}
	im.listed[ns] = nil
	want := im.lookups()[ns]
	pages := len(want) / headsPerPage
	if pages == 0 {
		return nil
	}
	h, err := im.c.NSHead(ctx, ns)
	if err != nil {
		if root, rerr := im.c.Root(ctx); rerr == nil && root.AuthDisabled() && client.IsNotFound(err) {
			im.listed[ns] = &listing{complete: true}
		}
		return im.listed[ns]
	}
	if doc, err := im.c.NSDoc(ctx, ns, h.ID); err != nil || doc.Value["frozen"] == true {
		return nil
	}
	l := &listing{heads: map[string]client.HeadItem{}}
	im.listed[ns] = l
	for last := want[len(want)-1]; pages > 0 && l.through < last; pages-- {
		items, next, err := im.c.HeadsPage(ctx, ns, h.ID, l.through)
		if err != nil {
			break // the rest are looked up one by one
		}
		for _, it := range items {
			l.heads[it.Resource] = it
		}
		if next == "" {
			l.complete = true
			break
		}
		l.through = next
	}
	return l
}

// lookups lists the resources whose heads the import looks up in each
// target namespace, in byte order: its documents, and the upstream
// resources of its snapshot documents.
func (im *importer) lookups() map[string][]string {
	if im.want != nil {
		return im.want
	}
	im.want = map[string][]string{}
	for _, k := range im.keys {
		d := im.docs[k]
		im.want[d.tns] = append(im.want[d.tns], d.name)
		if d.info.History == Snapshot {
			u := im.upstreamNS(d.ns)
			im.want[u] = append(im.want[u], d.name)
		}
	}
	for _, names := range im.want {
		sort.Strings(names)
	}
	return im.want
}
