package client

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// A read-filtering grant is a view (§7.9).
//
// The plain namespace reads, NSLog, NSLogPage, Heads, HeadsPage,
// HeadsPrefix, HeadsPrefixPage and LongPoll, read a partial reader's
// filtered log and /heads wherever its grant makes it one, and say so in
// the FilteredAt they return (LongPollResult embeds it): such an answer
// holds only what the view may see and isn't chain-verifiable (§10).
//
//   - In a namespace that isn't public the origin redirects a partial
//     reader from the unfiltered URLs to its view (§7.9 URLs), and the
//     client follows that 302 once, with the same query.
//   - A public namespace's unfiltered URLs ignore the grant and never
//     redirect (§7 step 1, v0.90): there the grant filters only at its
//     view's prefix. After a granted plain read of a namespace answered as
//     a shared cache may keep it (Cache-Control without private, as a
//     public namespace's are), the client asks ViewOf once per grant and
//     namespace, which draws an exchangeRate token (§6.6), and remembers
//     the answer: a view it then reads through, discarding the
//     unfiltered answer, or "" for a grant that reads there unrestricted
//     or by fixed names, or that the exchange refuses, which keeps the
//     plain URLs. An answer marked private asks nothing. A 401 or 403 at
//     a remembered view's URLs forgets it and asks once more: a new view,
//     or "" for a grant that now reads unrestricted; a grant the exchange
//     then refuses, as one expired or revoked, gets the view's refusal,
//     then and at every later read of the namespace. A different bearer is a different entry. A request without a grant
//     never asks.
//
// WithUnfilteredOnly turns all of it off, for a caller that needs the
// verifiable log: the plain reads then answer a partial reader's
// redirect with a *FilteredError and read a public namespace at its
// unfiltered URLs.

// WithUnfilteredOnly makes the plain namespace reads read only the
// unfiltered, chain-verifiable log and /heads (§10): a partial reader's
// redirect to its view (§7.9) is a *FilteredError (AsFiltered), and in a
// public namespace the unfiltered answer stands, the grant's view never
// looked up. Verifiers, followers and tools that derive writes or exports
// from a log use it. The Filtered* calls, which ask for the filtered log,
// are unaffected.
func WithUnfilteredOnly() Option { return func(c *Client) { c.unfilteredOnly = true } }

// UnfilteredOnly reports whether the client was made WithUnfilteredOnly.
func (c *Client) UnfilteredOnly() bool { return c.unfilteredOnly }

// viewTable remembers, per grant and namespace, the view a granted read
// of a public namespace goes through ("" for the plain URLs), shared with
// With copies. An entry being asked for holds done open; a failed ask
// leaves no entry.
type viewTable struct {
	mu sync.Mutex
	m  map[string]*viewSlot
}

type viewSlot struct {
	done chan struct{}
	view string
	// refused is the refusal remembered as view "", err a failure
	// remembered by no one; ended the refusal of a grant that had a view,
	// which its reads of ns return from then on.
	refused, err, ended error
}

func (c *Client) viewKey(ns string) string { return c.bearer + "\n" + ns }

// knownView is the view remembered for ns, and whether one is, or the
// refusal its grant's view ended with.
func (c *Client) knownView(ns string) (view string, known bool, ended error) {
	c.views.mu.Lock()
	s := c.views.m[c.viewKey(ns)]
	c.views.mu.Unlock()
	if s == nil {
		return "", false, nil
	}
	select {
	case <-s.done:
		return s.view, s.err == nil, s.ended
	default:
		return "", false, nil
	}
}

// endView remembers that the grant's view of ns ended with err.
func (c *Client) endView(ns string, err error) {
	s := &viewSlot{done: make(chan struct{}), ended: err}
	close(s.done)
	c.views.mu.Lock()
	c.views.m[c.viewKey(ns)] = s
	c.views.mu.Unlock()
}

// forgetView drops the entry for ns if it still names view.
func (c *Client) forgetView(ns, view string) {
	c.views.mu.Lock()
	defer c.views.mu.Unlock()
	k := c.viewKey(ns)
	if s := c.views.m[k]; s != nil {
		select {
		case <-s.done:
			if s.view == view {
				delete(c.views.m, k)
			}
		default:
		}
	}
}

// learnView asks ViewOf for ns once, however many reads wait on it, and
// remembers the answer. A transient failure (Transient: no answer, 408,
// 429, 5xx) is returned and remembered by no one; any other refusal, as
// of a deployment without /edge-grants or a grant the exchange refuses,
// is remembered as "", the plain URLs, and returned as refused.
func (c *Client) learnView(ctx context.Context, ns string) (view string, refused, err error) {
	k := c.viewKey(ns)
	for {
		c.views.mu.Lock()
		if c.views.m == nil {
			c.views.m = map[string]*viewSlot{}
		}
		s := c.views.m[k]
		if s == nil {
			break
		}
		c.views.mu.Unlock()
		select {
		case <-s.done:
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
		if s.err == nil {
			return s.view, s.refused, nil
		}
		if ctx.Err() != nil || !errors.Is(s.err, context.Canceled) && !errors.Is(s.err, context.DeadlineExceeded) {
			return "", nil, s.err
		}
		// The read that asked was cancelled, not this one: ask again.
	}
	s := &viewSlot{done: make(chan struct{})}
	c.views.m[k] = s
	c.views.mu.Unlock()

	s.view, s.err = c.ViewOf(ctx, ns)
	if s.err != nil && !Transient(s.err) && ctx.Err() == nil {
		s.view, s.refused, s.err = "", s.err, nil
	}
	if s.err != nil {
		c.views.mu.Lock()
		if c.views.m[k] == s {
			delete(c.views.m, k)
		}
		c.views.mu.Unlock()
	}
	close(s.done)
	return s.view, s.refused, s.err
}

// shared reports whether r's Cache-Control lets a shared cache keep it,
// as a public namespace's answers do: the origin answered it whatever
// the grant, so a partial reader's view must be looked up (§7.9 Where).
func shared(r *response) bool {
	return !strings.Contains(strings.ToLower(r.header.Get("Cache-Control")), "private")
}

// autoRead reads ns as the client's grant reads it (see above): plain
// reads the unfiltered URL, following a partial reader's redirect unless
// unfilteredOnly, and reports whether its answer was shared, also when it
// then fails to read it; view reads through the view given.
func autoRead[T any](ctx context.Context, c *Client, ns string, unfilteredOnly bool,
	plain func(follow bool) (T, FilteredAt, bool, error), view func(view string) (T, FilteredAt, error)) (T, FilteredAt, error) {
	var zero T
	if unfilteredOnly || c.bearer == "" {
		t, fa, _, err := plain(!unfilteredOnly)
		return t, fa, err
	}
	v, known, ended := c.knownView(ns)
	if ended != nil {
		return zero, FilteredAt{}, ended
	}
	if known && v != "" {
		t, fa, err := view(v)
		if !IsAuth(err) {
			return t, fa, err
		}
		// The view no longer reads for the grant, as when its rules
		// changed: ask again, once. A grant the exchange now refuses, as
		// one expired or revoked, gets the view's refusal, never the
		// unfiltered answer in its place.
		c.forgetView(ns, v)
		nv, refused, lerr := c.learnView(ctx, ns)
		switch {
		case lerr != nil:
			return zero, FilteredAt{}, lerr
		case refused != nil:
			c.endView(ns, err)
			return t, fa, err
		case nv != "":
			return view(nv)
		}
	}
	// A shared answer may also be one the grant can't open, as a public
	// sealed namespace's range to a partial reader, which holds only its
	// view's key (§E.2.3): its view is looked up all the same.
	t, fa, sh, err := plain(true)
	if fa.Filtered() || known || !sh {
		return t, fa, err
	}
	v, _, lerr := c.learnView(ctx, ns)
	if lerr != nil {
		return zero, FilteredAt{}, lerr
	}
	if v == "" {
		return t, fa, err
	}
	return view(v)
}

// Unfiltered is the client WithUnfilteredOnly: c itself if it is already,
// else a copy (With) sharing its HTTP client, keys and views.
func (c *Client) Unfiltered() *Client {
	if c.unfilteredOnly {
		return c
	}
	return c.With(WithUnfilteredOnly())
}
