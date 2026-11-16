package streams

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// Position is where a reader is in a stream: the resource it is reading,
// the stream's id or a continuation's name, and the last revision of it
// the reader saw. The zero Position is the beginning.
type Position struct {
	Resource string
	Rev      string
}

// Batch is what one revision added to a stream: a flush of the proxy's.
// The first Batch of a resource read from the beginning is its document so
// far. A reader that has handled a Batch resumes from its Position.
type Batch struct {
	Position
	Chunks []string
	// Upstream is what is known of the upstream response at this
	// revision (J.1).
	Upstream Upstream
	// Closed is set by the Batch that ends the resource; one that names
	// Next is followed by the continuation's.
	Closed *Closed
}

// ErrGone is a stream that doesn't exist for the reader: never created,
// purged once its read grants expired (J.4), or not readable with the
// reader's grant, which the core doesn't tell apart (404).
var ErrGone = errors.New("streams: the stream is gone, or not readable with this grant")

// Follow reads the stream id of namespace ns with c, a client carrying the
// read grant (J.3), and calls fn with each batch of chunks in order, until
// the revision that sets closed (J.3 The end): it returns how the stream
// closed. From the zero Position it loads the document (§11) and then
// long-polls the resource's log (§7.7); from a Position a Batch carried it
// resumes after that revision, without the chunks seen before. A stream
// closed with "size" is followed into the resource it names in next
// (J.1).
//
// An error of fn stops Follow, which returns it. A since revision whose
// history was pruned (§8.6) is the core's 410 pruned (client.IsPruned):
// such a reader starts again from the beginning.
func Follow(ctx context.Context, c *client.Client, ns, id string, from Position, fn func(Batch) error) (*Closed, error) {
	name, since := id, ""
	if from.Resource != "" {
		name, since = from.Resource, from.Rev
	}
	var up Upstream
	for {
		h, d, err := c.Load(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		if h.State != client.Live {
			return nil, fmt.Errorf("%w: %s/%s", ErrGone, ns, name)
		}
		doc, err := ParseDoc(d.Value)
		if err != nil {
			return nil, err
		}
		up = doc.Upstream
		var closed *Closed
		switch {
		case since == "":
			// From the beginning: the document so far.
			if err := fn(Batch{Position: Position{name, h.ID}, Chunks: doc.Chunks, Upstream: up, Closed: doc.Closed}); err != nil {
				return nil, err
			}
			closed = doc.Closed
		case doc.Closed != nil:
			// Resuming in a resource that has closed since: what is left
			// of its log, which no long-poll would end. The closing
			// revision may be the one the reader saw last.
			if since != h.ID {
				es, err := c.Log(ctx, ns, name, h.ID, since)
				if err != nil {
					return nil, err
				}
				if _, _, err := emit(name, es, &up, fn); err != nil {
					return nil, err
				}
			}
			closed = doc.Closed
		}
		if closed == nil {
			at := since
			if at == "" {
				at = h.ID
			}
			if closed, err = followLog(ctx, c, ns, name, at, &up, fn); err != nil {
				return nil, err
			}
		}
		if closed.Reason == ReasonSize && closed.Next != "" {
			name, since = closed.Next, ""
			continue
		}
		return closed, nil
	}
}

// emit calls fn for the entries that add to the stream, up to the one
// that sets closed, which it returns with the last entry's id.
func emit(name string, entries []client.LogEntry, up *Upstream, fn func(Batch) error) (closed *Closed, last string, err error) {
	for _, e := range entries {
		if e.Kind != "rev" {
			return nil, last, fmt.Errorf("%w: %s was deleted", ErrGone, name)
		}
		d := readPatches(e.Patches)
		if d.upstream != nil {
			*up = *d.upstream
		}
		if d.status != 0 {
			up.Status = d.status
		}
		if d.ctype != "" {
			up.ContentType = d.ctype
		}
		last = e.ID
		if len(d.chunks) == 0 && d.closed == nil && d.status == 0 {
			continue // an abort, or nothing a reader shows
		}
		if err := fn(Batch{Position: Position{name, e.ID}, Chunks: d.chunks, Upstream: *up, Closed: d.closed}); err != nil {
			return nil, last, err
		}
		if d.closed != nil {
			return d.closed, last, nil
		}
	}
	return nil, last, nil
}

// followLog long-polls one resource's log after since until an entry sets
// closed.
func followLog(ctx context.Context, c *client.Client, ns, name, since string, up *Upstream, fn func(Batch) error) (*Closed, error) {
	cursor := ""
	for {
		lp, err := c.ResourceLongPoll(ctx, ns, name, since, cursor)
		switch {
		case err == nil:
		case client.IsBadInput(err) && cursor != "":
			cursor = ""
			continue
		case client.Transient(err) && ctx.Err() == nil:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			continue
		default:
			return nil, err
		}
		cursor = lp.Cursor
		closed, last, err := emit(name, lp.Entries, up, fn)
		if err != nil || closed != nil {
			return closed, err
		}
		if last != "" {
			since = last
		}
		if lp.Since != "" {
			since = lp.Since
		}
	}
}

// Abort asks the proxy to stop stream id (J.4): it appends
// { "op": "add", "path": "/abort", "value": true } with If-Match on the
// head it last saw, and on a 412 again on the head the 412 names. It
// reports whether the abort was placed on an open stream: one that is
// closed already is left alone, as the proxy would ignore it. A stream
// that continued in another resource (closed "size", J.1) is aborted
// there.
//
// The proxy closes the stream with "aborted" once it sees the entry, which
// Follow reports.
func Abort(ctx context.Context, c *client.Client, ns, id string) (bool, error) {
	// A grant fixed to the stream can't read the namespace document, so
	// the namespace's principal answer says whether nonces are required
	// (§7.4, §C.7); unknown, one is sent, which never hurts.
	nonce := true
	if pi, err := c.NSPrincipal(ctx, ns); err == nil {
		nonce = pi.Writer.NonceRequired
	}
	name := id
	for hops := 0; hops < 1024; hops++ {
		h, d, err := c.Load(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, fmt.Errorf("%w: %s/%s", ErrGone, ns, name)
		}
		doc, err := ParseDoc(d.Value)
		if err != nil {
			return false, err
		}
		if doc.Closed != nil {
			if doc.Closed.Reason == ReasonSize && doc.Closed.Next != "" {
				name = doc.Closed.Next
				continue
			}
			return false, nil
		}
		head := h.ID
		for try := 0; ; try++ {
			ops := []any{map[string]any{"op": "add", "path": "/abort", "value": true}}
			if nonce {
				ops = append(ops, map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
			}
			_, err := c.Append(ctx, ns, name, head, ops)
			if err == nil {
				break
			}
			ae, _ := client.AsAPIError(err)
			if !client.IsStale(err) || ae.Head() == "" || try >= 32 {
				return false, err
			}
			head = ae.Head()
		}
		// Placed. If the proxy moved on to a continuation just before,
		// the abort came after this resource's close: follow it there.
		_, d, err = c.Load(ctx, ns, name)
		if err != nil || d == nil {
			return true, nil
		}
		if doc, err = ParseDoc(d.Value); err == nil && doc.Closed != nil && doc.Closed.Reason == ReasonSize && doc.Closed.Next != "" {
			name = doc.Closed.Next
			continue
		}
		return true, nil
	}
	return false, errors.New("streams: too many continuations")
}
