package verify

import (
	"bytes"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// Replay folds verified log entries onto a starting document and returns
// the document after the last entry, and whether the resource is live
// there. Start from (nil, false) with a log from genesis, or from a
// verified document at the log's trusted since. A tombstone keeps the last
// live document, which a following restore patches (§8.2); a tombstoned
// result returns that last live document with live false.
func Replay(start any, live bool, entries []client.LogEntry) (doc any, isLive bool, err error) {
	doc, isLive = start, live
	for i, e := range entries {
		switch e.Kind {
		case "tombstone":
			isLive = false
		case "rev":
			if !e.HasPatches {
				return nil, false, &PrunedError{Index: i, ID: e.ID}
			}
			ops, err := patch.Parse(e.Patches)
			if err != nil {
				return nil, false, &Error{i, e.ID, err.Error()}
			}
			// A restore applies to the last live document (exists), a
			// genesis to nothing.
			exists := isLive || (doc != nil && e.Parent != "")
			doc, _, err = patch.Apply(doc, exists, ops, patch.Options{})
			if err != nil {
				return nil, false, &Error{i, e.ID, err.Error()}
			}
			isLive = true
		default:
			return nil, false, &Error{i, e.ID, fmt.Sprintf("unknown entry kind %q", e.Kind)}
		}
	}
	return doc, isLive, nil
}

// Document checks served document bytes against a verified log from
// genesis ending at the document's revision: replaying the patch sets must
// reproduce exactly the canonical bytes served.
func Document(entries []client.LogEntry, raw []byte) error {
	doc, live, err := Replay(nil, false, entries)
	if err != nil {
		return err
	}
	if !live {
		return fmt.Errorf("verify: the log ends in a tombstone")
	}
	if want := jsonv.Canonical(doc); !bytes.Equal(want, raw) {
		return fmt.Errorf("verify: document does not match its history")
	}
	return nil
}
