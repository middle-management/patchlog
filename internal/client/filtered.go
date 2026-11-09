package client

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Filtered namespace reads (§B.11.9).
//
// Where an origin filters a namespace by catalog visibility, a partial
// reader (one whose grant allows read there without unrestricted read,
// §2.1) is redirected from the unfiltered URLs to filtered ones under
// /ns/{ns}/g/{gs}: ranges at /ns/{ns}/g/{gs}/at/{at}/heads and …/log,
// long-poll at /ns/{ns}/g/{gs}/log and events at /ns/{ns}/g/{gs}/events.
// gs stands for the reader's subject set and grant, at for the combined
// checkpoint of every namespace visibility reads. The answers keep their
// shapes; only the set changes. A range ends at the ns_id its answers
// name in X-Namespace-Revision, pages may be empty, and X-Log-Next may
// name an entry the page doesn't hold. Filtered logs carry no branch
// entries and aren't chain-verifiable: a partial reader learns of
// branches from Branches, and of changes of visibility, which write no
// entry in the namespace, from the catalogs' logs or by listing /heads
// again (§10).

// FilteredAt names a filtered answer (§B.11.9 URLs): the namespace, the
// gs and at of its URL, and End, the ns_id of NS in at, which answers at
// an at carry as X-Namespace-Revision. GS and At are "" for an answer
// that wasn't filtered, as for an unrestricted reader, whose End is the
// ns_id of the unfiltered URL.
type FilteredAt struct {
	NS, GS, At, End string
}

// Filtered reports whether fa names a filtered answer.
func (fa FilteredAt) Filtered() bool { return fa.GS != "" }

// filteredPathRe is a path under §B.11.9's prefix /ns/{ns}/g/{gs}: with
// /at/{at} for heads and log ranges, without for long-poll and events.
var filteredPathRe = regexp.MustCompile(`^/ns/([a-z0-9][a-z0-9_-]{0,63})/g/(1[a-z2-7]{32})(?:/at/(1[a-z2-7]{32}))?/(heads|log|events)$`)

// unfilteredLogRe is an unfiltered range, /ns/{ns}/rev/{ns_id}/log.
var unfilteredLogRe = regexp.MustCompile(`^/ns/([a-z0-9][a-z0-9_-]{0,63})/rev/(1[a-z2-7]{32})/log$`)

// location is the path a redirect r names, relative to the client's base
// URL: a path-only Location, or an absolute one under the base URL. ""
// for any other.
func (c *Client) location(r *response) string {
	loc := r.header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if u.Scheme != "" || u.Host != "" {
		rest, ok := strings.CutPrefix(loc, c.base)
		if !ok {
			return ""
		}
		if u, err = url.Parse(rest); err != nil {
			return ""
		}
	}
	return u.Path
}

// filteredRedirect reads a 302 into a filtered URL of namespace ns ending
// in tail (heads, log or events): its gs, and at ("" for long-poll and
// events, which have none). withAt says whether the URL must carry an at.
func (c *Client) filteredRedirect(r *response, ns, tail string, withAt bool) (gs, at string, err error) {
	m := filteredPathRe.FindStringSubmatch(c.location(r))
	if r.status != 302 || m == nil || m[1] != ns || m[4] != tail || (m[3] != "") != withAt {
		return "", "", fmt.Errorf("client: %s redirects to %q, not a filtered %s of %s (§B.11.9)", r.path, r.header.Get("Location"), tail, ns)
	}
	return m[2], m[3], nil
}

// filteredPath is the filtered URL of fa ending in tail (§B.11.9 URLs):
// with /at/{at} when fa has one.
func filteredPath(fa FilteredAt, tail string) string {
	p := "/ns/" + fa.NS + "/g/" + fa.GS
	if fa.At != "" {
		p += "/at/" + fa.At
	}
	return p + "/" + tail
}

func checkFilteredAt(fa FilteredAt) error {
	if err := checkNS(fa.NS); err != nil {
		return err
	}
	if err := checkID("gs", fa.GS); err != nil {
		return err
	}
	return checkOptID("at", fa.At)
}

// endOf is an answer's X-Namespace-Revision, which an answer at an at
// carries (§B.11.9 Log ranges): the range's end.
func endOf(r *response) (string, error) {
	end := r.header.Get("X-Namespace-Revision")
	if err := checkID("X-Namespace-Revision", end); err != nil {
		return "", fmt.Errorf("client: %s: %w (§B.11.9)", r.path, err)
	}
	return end, nil
}

// FilteredHeadsPage fetches one page of GET /ns/{ns}/rev/{nsID}/heads, as
// HeadsPrefixPage does, for any reader. To a partial reader the origin
// answers 302 to the page's filtered form at the current at, which it
// follows once with the same prefix and after (§B.11.9 URLs): only the
// rows visible to the reader, in pages filled to the log page size, with
// next, the last row returned, on every full page, so the page after the
// last full one may be empty. fa names the answer; read further pages
// with FilteredHeadsAt(fa, …). An unrestricted reader gets the unfiltered
// page, next absent on the last, and fa without GS and At.
func (c *Client) FilteredHeadsPage(ctx context.Context, ns, nsID, prefix, after string) (items []HeadItem, next string, fa FilteredAt, err error) {
	if err := checkNS(ns); err != nil {
		return nil, "", fa, err
	}
	if err := checkID("namespace revision", nsID); err != nil {
		return nil, "", fa, err
	}
	if err := checkPrefix(ns, prefix); err != nil {
		return nil, "", fa, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/rev/"+nsID+"/heads", headsQuery(prefix, after), nil)
	if err != nil {
		return nil, "", fa, err
	}
	switch r.status {
	case 200:
		items, next, err = parseHeads(r, prefix)
		return items, next, FilteredAt{NS: ns, End: nsID}, err
	case 302:
		gs, at, err := c.filteredRedirect(r, ns, "heads", true)
		if err != nil {
			return nil, "", fa, err
		}
		return c.filteredHeads(ctx, FilteredAt{NS: ns, GS: gs, At: at}, prefix, after)
	}
	return nil, "", fa, r.apiError()
}

// FilteredHeadsAt fetches one page of the filtered /heads fa names
// (§B.11.9), as one under a cookie for /ns/{ns}/g/{gs} reads it: at fa.At,
// or, without one, at the current at, to which the origin redirects. A
// redirect from an at the origin no longer answers is followed once, to
// the current at, so the returned fa may name another at than the one
// asked: a caller that needs one checkpoint starts again from the first
// page.
func (c *Client) FilteredHeadsAt(ctx context.Context, fa FilteredAt, prefix, after string) (items []HeadItem, next string, got FilteredAt, err error) {
	if err := checkFilteredAt(fa); err != nil {
		return nil, "", got, err
	}
	if err := checkPrefix(fa.NS, prefix); err != nil {
		return nil, "", got, err
	}
	return c.filteredHeads(ctx, FilteredAt{NS: fa.NS, GS: fa.GS, At: fa.At}, prefix, after)
}

// filteredHeads reads the filtered /heads page of fa, following one
// redirect to the current at of the same gs.
func (c *Client) filteredHeads(ctx context.Context, fa FilteredAt, prefix, after string) ([]HeadItem, string, FilteredAt, error) {
	for hop := 0; ; hop++ {
		r, err := c.do(ctx, "GET", filteredPath(fa, "heads"), headsQuery(prefix, after), nil)
		if err != nil {
			return nil, "", FilteredAt{}, err
		}
		switch {
		case r.status == 200 && fa.At != "":
			if fa.End, err = endOf(r); err != nil {
				return nil, "", FilteredAt{}, err
			}
			items, next, err := parseHeads(r, prefix)
			if err != nil {
				return nil, "", FilteredAt{}, err
			}
			return items, next, fa, nil
		case r.status == 302 && hop == 0:
			gs, at, err := c.filteredRedirect(r, fa.NS, "heads", true)
			if err != nil {
				return nil, "", FilteredAt{}, err
			}
			if gs != fa.GS {
				return nil, "", FilteredAt{}, fmt.Errorf("client: %s redirects to gs %s, not %s (§B.11.9)", r.path, gs, fa.GS)
			}
			fa.At = at
			continue
		case r.status == 200 || r.status == 302:
			return nil, "", FilteredAt{}, fmt.Errorf("client: %s answers %d, not a filtered page (§B.11.9)", r.path, r.status)
		}
		return nil, "", FilteredAt{}, r.apiError()
	}
}

// FilteredHeads lists, as HeadsPrefix does, every resource whose name
// starts with prefix as of nsID, for any reader: to a partial reader the
// rows visible to it at one at (§B.11.9), which fa names. If the origin
// moves the listing to another at between pages, as when a namespace of
// the at is purged, it starts again there, at most a few times.
func (c *Client) FilteredHeads(ctx context.Context, ns, nsID, prefix string) ([]HeadItem, FilteredAt, error) {
	items, next, fa, err := c.FilteredHeadsPage(ctx, ns, nsID, prefix, "")
	if err != nil {
		return nil, FilteredAt{}, err
	}
	if !fa.Filtered() {
		if next == "" {
			return items, fa, nil
		}
		rest, err := c.headsFrom(ctx, ns, nsID, prefix, next)
		return append(items, rest...), fa, err
	}
	for restarts := 0; next != ""; {
		page, n, got, err := c.FilteredHeadsAt(ctx, fa, prefix, next)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		if got.At != fa.At {
			if restarts++; restarts > 3 {
				return nil, FilteredAt{}, fmt.Errorf("client: /ns/%s/g/%s/heads keeps moving to another at (§B.11.9)", ns, fa.GS)
			}
			if page, n, got, err = c.FilteredHeadsAt(ctx, got, prefix, ""); err != nil {
				return nil, FilteredAt{}, err
			}
			items = nil
		}
		items, next, fa = append(items, page...), n, got
	}
	return items, fa, nil
}

// headsFrom lists the unfiltered /heads pages of nsID from after on.
func (c *Client) headsFrom(ctx context.Context, ns, nsID, prefix, after string) ([]HeadItem, error) {
	var all []HeadItem
	for after != "" {
		items, next, err := c.HeadsPrefixPage(ctx, ns, nsID, prefix, after)
		if err != nil {
			return nil, err
		}
		all, after = append(all, items...), next
	}
	return all, nil
}

// FilteredLog fetches the namespace log after since ("" = from the first
// entry) as a partial reader reads it (§B.11.9): GET /ns/{ns}/log, without
// live, answers 302 to the filtered range at the current at, directly or
// by way of the unfiltered range /ns/{ns}/rev/{ns_id}/log, and FilteredLog
// follows it and reads page by page until one lacks X-Log-Next. It returns
// the visible entries, oldest first, batches with only their visible
// items, and fa, whose End is the range's end. An unrestricted reader,
// whom the unfiltered range answers, gets that range as NSLog reads it,
// and fa without GS and At.
func (c *Client) FilteredLog(ctx context.Context, ns, since string) ([]NSEntry, FilteredAt, error) {
	if err := checkNS(ns); err != nil {
		return nil, FilteredAt{}, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, FilteredAt{}, err
	}
	var q url.Values
	if since != "" {
		q = url.Values{"since": {since}}
	}
	path, end := "/ns/"+ns+"/log", ""
	for {
		r, err := c.do(ctx, "GET", path, q, nil)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		switch {
		case r.status == 200 && end != "":
			es, err := c.NSLog(ctx, ns, end, since)
			return es, FilteredAt{NS: ns, End: end}, err
		case r.status != 302:
			return nil, FilteredAt{}, r.apiError()
		}
		loc := c.location(r)
		if m := unfilteredLogRe.FindStringSubmatch(loc); m != nil && m[1] == ns && end == "" {
			path, end = loc, m[2]
			continue
		}
		gs, at, err := c.filteredRedirect(r, ns, "log", true)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		return c.FilteredLogAt(ctx, FilteredAt{NS: ns, GS: gs, At: at}, since)
	}
}

// FilteredLogAt reads the filtered range fa names after since, every page
// (§B.11.9 Log ranges), as FilteredLog does once redirected. Without
// fa.At it starts at …/g/{gs}/log, which the origin redirects to the
// current at, as under a cookie for /ns/{ns}/g/{gs}.
func (c *Client) FilteredLogAt(ctx context.Context, fa FilteredAt, since string) ([]NSEntry, FilteredAt, error) {
	if err := checkFilteredAt(fa); err != nil {
		return nil, FilteredAt{}, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, FilteredAt{}, err
	}
	fa.End = ""
	if fa.At == "" {
		var q url.Values
		if since != "" {
			q = url.Values{"since": {since}}
		}
		r, err := c.do(ctx, "GET", filteredPath(fa, "log"), q, nil)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		if r.status != 302 {
			return nil, FilteredAt{}, r.apiError()
		}
		gs, at, err := c.filteredRedirect(r, fa.NS, "log", true)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		if gs != fa.GS {
			return nil, FilteredAt{}, fmt.Errorf("client: %s redirects to gs %s, not %s (§B.11.9)", r.path, gs, fa.GS)
		}
		fa.At = at
	}
	all := []NSEntry{}
	seen := map[string]bool{}
	for {
		page, next, got, err := c.FilteredLogPage(ctx, fa, since)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		if fa.End != "" && got.End != fa.End {
			return nil, FilteredAt{}, fmt.Errorf("client: %s: the range's end moved from %s to %s (§B.11.9)", filteredPath(fa, "log"), fa.End, got.End)
		}
		fa = got
		all = append(all, page...)
		if next == "" {
			return all, fa, nil
		}
		if seen[next] {
			return nil, FilteredAt{}, fmt.Errorf("client: %s: X-Log-Next %s repeats", filteredPath(fa, "log"), next)
		}
		seen[next], since = true, next
	}
}

// FilteredLogPage fetches one page of the filtered range fa names after
// since (§B.11.9 Log ranges, §7.1): its visible entries, possibly none,
// and next, X-Log-Next, the last entry the page scanned, visible or not,
// "" on the last page. got is fa with End, the range's end, from the
// answer's X-Namespace-Revision. An at the origin no longer answers is
// redirected to the current one; that is an error here, and a reader
// starts again with FilteredLog.
func (c *Client) FilteredLogPage(ctx context.Context, fa FilteredAt, since string) (entries []NSEntry, next string, got FilteredAt, err error) {
	if err := checkFilteredAt(fa); err != nil {
		return nil, "", got, err
	}
	if fa.At == "" {
		return nil, "", got, fmt.Errorf("client: a filtered range of %s needs an at (§B.11.9)", fa.NS)
	}
	if err := checkOptID("since", since); err != nil {
		return nil, "", got, err
	}
	got = FilteredAt{NS: fa.NS, GS: fa.GS, At: fa.At}
	next, err = c.filteredLogPage(ctx, filteredPath(fa, "log"), since, func(r *response, _ string) (string, error) {
		if isJOSE(r) {
			// Only namespaces that are neither sealed nor end-to-end
			// are filtered (§B.11.9 Where).
			return "", fmt.Errorf("client: %s: a filtered page is sealed (§B.11.9)", r.path)
		}
		end, err := endOf(r)
		if err != nil {
			return "", err
		}
		got.End = end
		es, err := parseNSLog(r.value(), r.path)
		if err != nil {
			return "", err
		}
		entries = es
		return "", nil
	})
	if err != nil {
		return nil, "", FilteredAt{}, err
	}
	return entries, next, got, nil
}
