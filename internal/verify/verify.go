// Package verify checks the integrity of what a deployment serves by
// recomputing ids (invariant 4, §G.2): namespace chains entry by entry from a
// trusted ns_id, and resource logs back to a trusted revision or genesis.
//
// Ids travel, trust doesn't (§G.1): given a trusted starting id obtained from
// the source itself (or "" for genesis), content fetched through any cache or
// mirror can be checked without trusting the transport. What ids don't cover
// (head pointers, /heads listings, namespace documents served for an ns_id,
// authors and timestamps) is only as trustworthy as its channel.
package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Error reports an entry that fails verification.
type Error struct {
	Index  int    // index of the entry in the slice given
	ID     string // the entry's claimed id
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("verify: entry %d (%s): %s", e.Index, e.ID, e.Reason)
}

// PrunedError reports a resource log that reaches a revision whose patch set
// is absent (below a pruning horizon, §8.6). Entries before Index were
// verified; verification can resume from a revision at or after the horizon
// that is already trusted, or from an archive.
type PrunedError struct {
	Index    int
	ID       string // the first revision without a patch set
	Verified string // the last verified id before it ("" if none)
}

func (e *PrunedError) Error() string {
	return fmt.Sprintf("verify: entry %d (%s) has no patch set (pruned); verified up to %q", e.Index, e.ID, e.Verified)
}

// ErrPruned matches *PrunedError with errors.Is.
var ErrPruned = errors.New("verify: history below a pruning horizon")

func (e *PrunedError) Is(target error) bool { return target == ErrPruned }

// --- namespace chains (§3.5) ---------------------------------------------

// HashedForm rebuilds the entry exactly as hashed (§3.5) from the log
// fields, using only the fields the kind defines:
//
//	head/tombstone/purge/prune: { resource, kind, target }
//	config:                     { kind, target }
//	batch:                      { kind, entries: [sub…], source? }
//	branch (local):             { kind, name, at, target }
//	branch (remote, §G.3):      { kind, remote, at }
//	purge-ns:                   { kind }
func HashedForm(e client.NSEntry) (map[string]any, error) {
	return hashedForm(e, false)
}

func hashedForm(e client.NSEntry, sub bool) (map[string]any, error) {
	need := func(name, v string) error {
		if v == "" {
			return fmt.Errorf("%s entry without %s", e.Kind, name)
		}
		return nil
	}
	switch e.Kind {
	case "head", "tombstone", "purge", "prune":
		if sub && e.Kind != "head" && e.Kind != "tombstone" {
			return nil, fmt.Errorf("a batch cannot contain a %s entry", e.Kind)
		}
		if err := errors.Join(need("resource", e.Resource), need("target", e.Target)); err != nil {
			return nil, err
		}
		return map[string]any{"resource": e.Resource, "kind": e.Kind, "target": e.Target}, nil
	case "config":
		if err := need("target", e.Target); err != nil {
			return nil, err
		}
		return map[string]any{"kind": "config", "target": e.Target}, nil
	}
	if sub {
		return nil, fmt.Errorf("a batch cannot contain a %s entry", e.Kind)
	}
	switch e.Kind {
	case "batch":
		entries := make([]any, 0, len(e.Entries))
		for i, s := range e.Entries {
			if s.Kind == "config" && i != 0 {
				return nil, fmt.Errorf("batch config entry is not first")
			}
			h, err := hashedForm(s, true)
			if err != nil {
				return nil, err
			}
			entries = append(entries, h)
		}
		m := map[string]any{"kind": "batch", "entries": entries}
		if e.HasSource {
			if e.Source == nil {
				return nil, fmt.Errorf("batch source is not an object")
			}
			m["source"] = e.Source
		}
		return m, nil
	case "branch":
		if e.Remote != nil {
			if err := need("at", e.At); err != nil {
				return nil, err
			}
			return map[string]any{"kind": "branch", "remote": e.Remote, "at": e.At}, nil
		}
		if err := errors.Join(need("name", e.Name), need("at", e.At), need("target", e.Target)); err != nil {
			return nil, err
		}
		return map[string]any{"kind": "branch", "name": e.Name, "at": e.At, "target": e.Target}, nil
	case "purge-ns":
		return map[string]any{"kind": "purge-ns"}, nil
	}
	return nil, fmt.Errorf("unknown entry kind %q", e.Kind)
}

// NSEntryID recomputes an entry's ns_id from its predecessor ("" for the
// first entry of a chain).
func NSEntryID(prev string, e client.NSEntry) (string, error) {
	var p *ids.ID
	if prev != "" {
		id, err := ids.Parse(prev)
		if err != nil {
			return "", fmt.Errorf("malformed prev %q", prev)
		}
		p = &id
	}
	h, err := HashedForm(e)
	if err != nil {
		return "", err
	}
	return ids.Hash(p, jsonv.Canonical(h)).String(), nil
}

// VerifyNSChain checks a contiguous range of namespace entries, oldest
// first, starting right after the trusted ns_id fromID ("" = the chain's
// first entry): every entry's prev must be the previous id, and its id must
// be the hash of its hashed form. It returns the last verified id, which the
// caller can trust from then on (fromID if entries is empty).
func VerifyNSChain(entries []client.NSEntry, fromID string) (string, error) {
	prev := fromID
	for i, e := range entries {
		if e.Prev != prev {
			return prev, &Error{i, e.ID, fmt.Sprintf("prev is %q, want %q", e.Prev, prev)}
		}
		id, err := NSEntryID(prev, e)
		if err != nil {
			return prev, &Error{i, e.ID, err.Error()}
		}
		if id != e.ID {
			return prev, &Error{i, e.ID, fmt.Sprintf("id does not match its content (recomputed %s)", id)}
		}
		prev = id
	}
	return prev, nil
}

// --- resource logs (§3.3, §3.4) -------------------------------------------

// LogEntryID recomputes a resource log entry's id from its parent: the
// revision id of §3.3 over canonical(patches), or the tombstone id of §3.4.
// A revision without its patch set returns a *PrunedError (Index 0).
func LogEntryID(parent string, e client.LogEntry) (string, error) {
	var p *ids.ID
	if parent != "" {
		id, err := ids.Parse(parent)
		if err != nil {
			return "", fmt.Errorf("malformed parent %q", parent)
		}
		p = &id
	}
	switch e.Kind {
	case "rev":
		if !e.HasPatches {
			return "", &PrunedError{ID: e.ID}
		}
		return ids.Revision(p, jsonv.Canonical(e.Patches)).String(), nil
	case "tombstone":
		if p == nil {
			return "", fmt.Errorf("tombstone without parent")
		}
		return ids.Tombstone(*p).String(), nil
	}
	return "", fmt.Errorf("unknown entry kind %q", e.Kind)
}

// VerifyResourceLog checks a resource log range, oldest first, as served by
// /r/{ns}/{name}/rev/{id}/log?since={trusted}: the first entry's parent must
// be trusted ("" = genesis, no parent), every later entry's parent the
// previous id, and every id must be recomputable. It returns the last
// verified id (trusted if entries is empty). A revision whose patch set is
// absent stops verification with a *PrunedError (errors.Is ErrPruned).
func VerifyResourceLog(entries []client.LogEntry, trusted string) (string, error) {
	prev := trusted
	for i, e := range entries {
		if e.Parent != prev {
			return prev, &Error{i, e.ID, fmt.Sprintf("parent is %q, want %q", e.Parent, prev)}
		}
		id, err := LogEntryID(prev, e)
		if err != nil {
			var pe *PrunedError
			if errors.As(err, &pe) {
				return prev, &PrunedError{Index: i, ID: e.ID, Verified: prev}
			}
			return prev, &Error{i, e.ID, err.Error()}
		}
		if id != e.ID {
			return prev, &Error{i, e.ID, fmt.Sprintf("id does not match its content (recomputed %s)", id)}
		}
		prev = id
	}
	return prev, nil
}

// --- fetch and verify -----------------------------------------------------

// Namespace fetches the namespace log from the trusted ns_id fromID ("" =
// from the first entry) up to the current head and verifies it. It returns
// the verified entries and the verified head. The head pointer itself is
// untrusted, but a forged head can only name an id whose range fails
// verification or a genuine entry of the chain.
func Namespace(ctx context.Context, c *client.Client, ns, fromID string) ([]client.NSEntry, string, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return nil, "", err
	}
	if h.ID == fromID {
		return nil, fromID, nil
	}
	entries, err := c.NSLog(ctx, ns, h.ID, fromID)
	if err != nil {
		return nil, "", err
	}
	last, err := VerifyNSChain(entries, fromID)
	if err != nil {
		return nil, last, err
	}
	if last != h.ID {
		return nil, last, &Error{len(entries) - 1, last, fmt.Sprintf("log ends at %s, not at the requested head %s", last, h.ID)}
	}
	return entries, last, nil
}

// Resource fetches the log of a resource from the trusted revision trusted
// ("" = genesis) up to id ("" = the current head) and verifies it. It
// returns the verified entries and the last verified id.
func Resource(ctx context.Context, c *client.Client, ns, name, id, trusted string) ([]client.LogEntry, string, error) {
	entries, err := c.Log(ctx, ns, name, id, trusted)
	if err != nil {
		return nil, "", err
	}
	last, err := VerifyResourceLog(entries, trusted)
	if err != nil {
		return nil, last, err
	}
	if id != "" && last != id {
		return nil, last, &Error{len(entries) - 1, last, fmt.Sprintf("log ends at %s, not at the requested %s", last, id)}
	}
	return entries, last, nil
}
