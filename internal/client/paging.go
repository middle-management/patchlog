package client

import (
	"context"
	"fmt"
	"net/url"
)

// Paged log ranges (§7.1 Paging).
//
// A log range longer than the deployment's log page size answers its first
// page only, oldest first, with X-Log-Next naming the page's last entry: the
// since of the next page, an immutable range up to the same id. A reader
// reads pages until the last entry it received is the range's id. A page
// that stops short of it without X-Log-Next is an error, so a truncated
// copy (a proxy that drops the header, say) can't pass for the whole range.
// Sealed pages carry their own bounds (§E.2.2): a namespace range's JWE is
// bound to [since, X-Log-Next], and a resource log's per-entry JWEs must
// chain from since to it.

// logPage fetches one page of the log range path?since=since, which ends at
// to. decode reads the answer: end is the id the page must end at
// (X-Log-Next, or to without it), and it returns the id of the page's last
// entry ("" for none). next is the since of the following page, or "" when
// the page ends at to.
func (c *Client) logPage(ctx context.Context, path, since, to string, decode func(r *response, end string) (last string, err error)) (next string, err error) {
	return c.logPageMode(ctx, path, since, to, false, decode)
}

// filteredLogPage fetches one page of a filtered range (§B.11.9 Log
// ranges), whose end the client learns from the answer's
// X-Namespace-Revision rather than the URL: a page holds only the visible
// entries among those it scanned, possibly none, and X-Log-Next names the
// last entry scanned, visible or not, on every page but the last. So the
// page's last entry needn't be X-Log-Next, an empty page may name one,
// and a page without it ends the range. decode's end is X-Log-Next, ""
// on the last page. X-Log-Next must still be an id, and must move past
// since.
func (c *Client) filteredLogPage(ctx context.Context, path, since string, decode func(r *response, end string) (last string, err error)) (next string, err error) {
	return c.logPageMode(ctx, path, since, "", true, decode)
}

func (c *Client) logPageMode(ctx context.Context, path, since, to string, filtered bool, decode func(r *response, end string) (last string, err error)) (next string, err error) {
	var q url.Values
	if since != "" {
		q = url.Values{"since": {since}}
	}
	r, err := c.do(ctx, "GET", path, q, nil)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", r.apiError()
	}
	next = r.header.Get("X-Log-Next")
	if next != "" {
		if err := checkID("X-Log-Next", next); err != nil {
			return "", fmt.Errorf("client: %s: %w", r.path, err)
		}
	}
	end := to
	if next != "" {
		end = next
	}
	last, err := decode(r, end)
	if err != nil {
		return "", err
	}
	if filtered {
		if next == since && next != "" {
			return "", fmt.Errorf("client: %s: X-Log-Next %s doesn't move past since (§B.11.9)", r.path, next)
		}
		return next, nil
	}
	if last == "" {
		last = since
	}
	switch {
	case last == to:
		return "", nil
	case next == "":
		return "", fmt.Errorf("client: %s: the log range after %q ends at %q, short of %s, without X-Log-Next (§7.1)", r.path, since, last, to)
	case last != next:
		return "", fmt.Errorf("client: %s: X-Log-Next %s isn't the page's last entry %q", r.path, next, last)
	case next == since:
		return "", fmt.Errorf("client: %s: an empty page names X-Log-Next %s", r.path, next)
	}
	return next, nil
}
