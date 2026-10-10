package bundle

import (
	"context"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/client"
)

// Partial imports (ImportOptions.Only). An import of some of a bundle's
// namespaces leaves the others' documents out as a bundle's external
// dependencies are (§G.4.1): it writes nothing of them, and before writing
// anything checks that the target has what the documents it imports
// reference in them, as the bundle has it: by id for a full document's
// pinned revisions, by name for a live reference. A snapshot document
// that imported snapshot documents pin is rewritten to its upstream
// revision (§G.4.4), so the import plans its upstream resource as a whole
// import would, and requires that to write nothing: the target holds that
// snapshot already, from an import of its namespace. A pin of a snapshot
// document from a full document isn't rewritten, by a whole import either,
// and isn't checked.
//
// So a bundle can be imported a few namespaces at a time, by one process
// or several at once, the namespaces others depend on first; the target
// ends as one whole import leaves it.

// noteOut records, while the bundle loads, a reference r in a document the
// import brings to a bundled document it leaves out: the revision it pins
// of a full document, or "" for a live one.
func (im *importer) noteOut(r annot.Ref) {
	t := im.docs[Key(r.NS, r.Name)]
	if t == nil || im.only[t.ns] || (r.Rev != "" && t.info.History != Full) {
		return
	}
	if im.outRefs[t.key] == nil {
		im.outRefs[t.key] = map[string]bool{}
	}
	im.outRefs[t.key][r.Rev] = true
}

// leaveOut narrows a loaded bundle to the namespaces of Only: the import
// plans and writes only their documents (keys), and holds the snapshot
// documents left out that they pin (held), directly or through each
// other. It drops the others' snapshots, which nothing reads, and the
// live references to documents the bundle has deleted, which a whole
// import would delete as well.
func (im *importer) leaveOut() {
	if im.only == nil {
		return
	}
	keys := make([]string, 0, len(im.keys))
	for _, k := range im.keys {
		if im.only[im.docs[k].ns] {
			keys = append(keys, k)
		}
	}
	im.keys = keys
	var hold func(d *bdoc)
	hold = func(d *bdoc) {
		for k := range d.pinKeys {
			if t := im.docs[k]; t != nil && !im.only[t.ns] && t.info.History == Snapshot && !im.held[k] {
				im.held[k] = true
				hold(t)
			}
		}
	}
	for _, k := range im.keys {
		if d := im.docs[k]; d.info.History == Snapshot {
			hold(d)
		}
	}
	for k, d := range im.docs {
		if im.only[d.ns] {
			continue
		}
		im.left++
		deleted := false
		switch d.info.History {
		case Snapshot:
			deleted = d.snap != nil && d.snap.Deleted
			if !im.held[k] {
				d.snap, d.blobs = nil, nil
			}
		case Full:
			i, ok := d.idx[d.info.Head]
			deleted = ok && d.lines[i].Kind != "rev"
		}
		if deleted && im.outRefs[k] != nil {
			delete(im.outRefs[k], "")
			if len(im.outRefs[k]) == 0 {
				delete(im.outRefs, k)
			}
		}
	}
	for k := range im.held {
		im.heldKeys = append(im.heldKeys, k)
	}
	sort.Strings(im.heldKeys)
}

// checkOut checks the target for what the documents the import brings
// reference in those it leaves out (noteOut), and returns the problems.
func (im *importer) checkOut(ctx context.Context) ([]string, error) {
	keys := make([]string, 0, len(im.outRefs))
	for k := range im.outRefs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var problems []string
	for _, k := range keys {
		t := im.docs[k]
		at := Key(t.tns, t.name)
		th, err := im.head(ctx, t.tns, t.name)
		if err != nil {
			return nil, err
		}
		revs := make([]string, 0, len(im.outRefs[k]))
		for rev := range im.outRefs[k] {
			revs = append(revs, rev)
		}
		sort.Strings(revs)
		for _, rev := range revs {
			switch {
			case rev == "":
				if th.State != client.Live {
					problems = append(problems, fmt.Sprintf("%s, which the import leaves out, is %s in the target: imported documents name it", at, stateWord(th.State)))
				}
				continue
			case th.ID == rev:
				continue
			case th.State == client.NotFound || th.State == client.Purged:
				problems = append(problems, fmt.Sprintf("%s, which the import leaves out, is %s in the target: imported documents pin its revision %s", at, stateWord(th.State), rev))
				continue
			}
			if _, err := im.c.Doc(ctx, t.tns, t.name, rev); err != nil {
				if client.IsNotFound(err) || client.IsGone(err) || client.IsPruned(err) {
					problems = append(problems, fmt.Sprintf("revision %s of %s, which the import leaves out, is not in the target: imported documents pin it", rev, at))
					continue
				}
				return nil, err
			}
		}
	}
	return problems, nil
}

// heldProblem is the problem of a held snapshot document (leaveOut) whose
// upstream resource doesn't hold the bundle's snapshot, as planUpstream
// found it, or "".
func (im *importer) heldProblem(d *bdoc, it *item) string {
	ur := d.rep.Upstream
	what := "it is purged there"
	switch {
	case it != nil:
		what = "an import of it would " + ur.Class + " it there"
	case ur.Class != "purged":
		return ""
	}
	return fmt.Sprintf("%s, which the import leaves out, isn't in %s as the bundle has it (%s): imported snapshot documents pin it, "+
		"so import namespace %s first, or with them", d.key, ur.Target, what, d.ns)
}

func stateWord(s client.State) string {
	if s == client.NotFound {
		return "missing"
	}
	return s.String()
}
