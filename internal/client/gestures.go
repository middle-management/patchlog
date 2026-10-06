package client

import (
	"context"
	"fmt"
	"net/url"

	"github.com/middle-management/patchlog/internal/seal"
)

// Gestures (§7.2, §11.2).
//
// A client picks a gesture id when a user action starts (NewGesture) and
// sends it with every write the action produces: WithGesture on resource
// writes, Step.Gesture (or BatchItem.Gesture, BatchRequest.Gesture as
// defaults) in batches. An undo is written with a fresh gesture and
// WithUndoes naming the one it undoes; a redo undoes the undo. Logs serve
// them back: LogEntry.Gesture/Undoes, NSEntry.Gesture/Undoes for a single
// write and NSEntry.Gestures for a batch. Where the deployment offers it,
// Gestures lists a gesture's revisions directly (§7.4).

// NewGesture returns a fresh gesture id: 128 random bits as 26 base32
// characters (§7.2), the form of a $nonce.
func NewGesture() string { return seal.NewNonce() }

// ValidGesture reports whether s is a gesture id: ^[a-z2-7]{26}$ (§7.2).
func ValidGesture(s string) bool { return seal.ValidNonce(s) }

// GestureEntry is one entry of GET /ns/{ns}/gestures/{gesture} (§7.4): a
// revision or tombstone written with the gesture, or undoing it.
type GestureEntry struct {
	Resource string
	ID       string
	Kind     string // "rev" or "tombstone"
	Gesture  string // "" if none
	Undoes   string // "" if none
	Author   string
	NSID     string         // the namespace entry that wrote it
	Raw      map[string]any // the entry as served
}

// GesturesPage fetches one page of GET /ns/{ns}/gestures/{gesture} after
// after ("" for the first page; sent as ?after=, §7.4): its entries,
// oldest first, and next, the after of the following page, or "" on the last one. The list isn't
// immutable: a later read may find more. A deployment that doesn't offer
// the endpoint, or a sealed or e2e namespace, answers 404 (IsNotFound); a
// grant without unrestricted read 403. Clients then scan the logs they
// follow instead (§11.2).
func (c *Client) GesturesPage(ctx context.Context, ns, gesture, after string) (entries []GestureEntry, next string, err error) {
	if err := checkNS(ns); err != nil {
		return nil, "", err
	}
	if !ValidGesture(gesture) {
		return nil, "", fmt.Errorf("client: invalid gesture id %q", gesture)
	}
	var q url.Values
	if after != "" {
		q = url.Values{"after": {after}}
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/gestures/"+gesture, q, nil)
	if err != nil {
		return nil, "", err
	}
	if r.status != 200 {
		return nil, "", r.apiError()
	}
	arr, ok := r.value().([]any)
	if !ok {
		return nil, "", fmt.Errorf("client: %s: gesture listing is not an array", r.path)
	}
	entries = make([]GestureEntry, 0, len(arr))
	for _, x := range arr {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("client: %s: gesture entry is not an object", r.path)
		}
		entries = append(entries, GestureEntry{Resource: str(m, "resource"), ID: str(m, "id"), Kind: str(m, "kind"),
			Gesture: str(m, "gesture"), Undoes: str(m, "undoes"), Author: str(m, "author"), NSID: str(m, "ns_id"), Raw: m})
	}
	next = r.header.Get("X-Log-Next")
	if next != "" && (len(entries) == 0 || next != entries[len(entries)-1].Resource+"/"+entries[len(entries)-1].ID) {
		return nil, "", fmt.Errorf("client: %s: X-Log-Next %s isn't the page's last entry", r.path, next)
	}
	return entries, next, nil
}

// Gestures lists every revision and tombstone of ns written with gesture
// or undoing it, oldest first, following the pages (§7.4). See
// GesturesPage for the errors.
func (c *Client) Gestures(ctx context.Context, ns, gesture string) ([]GestureEntry, error) {
	all := []GestureEntry{}
	for since := ""; ; {
		page, next, err := c.GesturesPage(ctx, ns, gesture, since)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if next == "" {
			return all, nil
		}
		since = next
	}
}
