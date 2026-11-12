package client

import (
	"context"
	"math/rand/v2"
	"time"
)

// Backoff tunes AppendLatest. The zero value is the default.
type Backoff struct {
	// Base is the ceiling of the wait after the first lost race; it
	// doubles with each further loss in a row, up to Max. Defaults: 2 ms
	// and 16 ms. The wait itself is random between zero and the ceiling
	// (full jitter), so writers that lost together don't retry together.
	//
	// Max trades wasted requests against fairness. A writer that just won
	// holds the newest head and waits for nothing, so the longer the
	// losers wait, the more often it wins again: with writers that never
	// pause, a Max of 250 ms left one of 8 writers doing more than half the
	// appends and another none, while 16 ms gave every writer a share at about
	// half the 412s of retrying at once (docs/CAPACITY.md).
	Base, Max time.Duration
	// MaxAttempts bounds the appends tried (default 50); the last refusal
	// is returned once it is reached.
	MaxAttempts int
	// OnRetry, if set, is told each refusal that is retried: a 412 (or a
	// 429).
	OnRetry func(err error)
}

// AppendLatest appends to ns/name the patch set build returns for the
// current head, and when another writer got there first (412) tries
// again on the head the refusal names (§7.2), without reading the head
// again, after a short random wait that grows with each loss in a row.
// A 429 waits its Retry-After, reads the head again and doesn't count as
// a loss.
//
// head is the head the caller last saw; "" reads it first. build is
// called once per attempt with the head the attempt is made on: return
// the same patch set for a change that doesn't depend on the document (a
// counter's replace, an array append), or read the document at that head
// and build the change anew. An error from build ends the call.
//
// Writers contending for one document can't all succeed at once: every
// append needs the head the one before it made (§7.2: writes are never
// unconditional). Retrying at once makes it worse, since everyone who
// lost fires at the same new head; the wait spreads them out.
func (c *Client) AppendLatest(ctx context.Context, ns, name, head string, b Backoff, build func(head string) (any, error), opts ...WriteOption) (*WriteResult, error) {
	if b.Base <= 0 {
		b.Base = 2 * time.Millisecond
	}
	if b.Max <= 0 {
		b.Max = 16 * time.Millisecond
	}
	if b.MaxAttempts <= 0 {
		b.MaxAttempts = 50
	}
	if head == "" {
		h, err := c.Head(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		head = h.ID
	}
	losses := 0
	for attempt := 1; ; attempt++ {
		patches, err := build(head)
		if err != nil {
			return nil, err
		}
		res, err := c.Append(ctx, ns, name, head, patches, opts...)
		if err == nil {
			return res, nil
		}
		ae, ok := AsAPIError(err)
		if !ok || attempt >= b.MaxAttempts {
			return nil, err
		}
		var wait time.Duration
		switch ae.Status {
		case 412:
			losses++
			if h := ae.Head(); h != "" {
				head = h
			} else {
				hd, herr := c.Head(ctx, ns, name)
				if herr != nil {
					return nil, herr
				}
				head = hd.ID
			}
			ceiling := b.Base << min(losses-1, 20)
			if ceiling > b.Max || ceiling <= 0 {
				ceiling = b.Max
			}
			wait = time.Duration(rand.Int64N(int64(ceiling) + 1))
		case 429:
			wait = ae.RetryAfter
			if wait <= 0 {
				wait = 100 * time.Millisecond
			}
		default:
			return nil, err
		}
		if b.OnRetry != nil {
			b.OnRetry(err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		if ae.Status == 429 {
			// The head moved on while this writer waited for a token, and
			// a 412 would spend the token it waited for (reads draw none).
			hd, herr := c.Head(ctx, ns, name)
			if herr != nil {
				return nil, herr
			}
			head = hd.ID
		}
	}
}
