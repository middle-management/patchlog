package client

import (
	"context"
	"fmt"

	"github.com/middle-management/patchlog/internal/patch"
)

// FoldFiltered follows a resource through a log a partial reader is
// served (§7.9 Log entries): its visible revisions, without patches
// where the parent is hidden, and {id, parent, kind: "hidden"} for a
// hidden one whose parent is visible. Such a log isn't chain-verifiable
// (§10), so a reader folds a revision's patches only onto the revision it
// holds, its parent; after a hidden entry, or on first seeing the
// resource mid-history (an entry whose parent it doesn't hold, or without
// patches), it fetches that revision's document (§7.1) instead.
//
// at and doc are the revision the reader holds and its document ("" and
// nil for none); entries are the log's, oldest first. It returns the
// revision and document it then holds: after a hidden entry with nothing
// visible after it, ("", nil), the resource having left the reader's
// view; after a tombstone, its id and nil.
func (c *Client) FoldFiltered(ctx context.Context, ns, name, at string, doc any, entries []LogEntry) (string, any, error) {
	for _, e := range entries {
		switch e.Kind {
		case "hidden":
			at, doc = "", nil
			continue
		case "tombstone":
			at, doc = e.ID, nil
			continue
		}
		if e.HasPatches && at != "" && e.Parent == at && doc != nil || e.HasPatches && e.Parent == "" {
			ops, err := patch.Parse(e.Patches)
			if err == nil {
				var base any
				exists := false
				if e.Parent != "" {
					base, exists = doc, true
				}
				if nd, _, err := patch.Apply(base, exists, ops, patch.Options{ResourceEnvelope: true}); err == nil {
					at, doc = e.ID, nd
					continue
				}
			}
		}
		d, err := c.Doc(ctx, ns, name, e.ID)
		if err != nil {
			return at, doc, fmt.Errorf("client: %s/%s at %s: %w", ns, name, e.ID, err)
		}
		at, doc = e.ID, d.Value
	}
	return at, doc, nil
}
