package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/middle-management/patchlog/internal/seal"
)

// Filtered namespace reads (§7.9).
//
// Where an origin filters a namespace by the grant's read rules, a partial
// reader (one whose grant allows read there without unrestricted read,
// §2.1) is redirected from the unfiltered URLs to filtered ones under
// /ns/{ns}/view/{view}: ranges at /ns/{ns}/view/{view}/at/{at}/heads and …/log,
// long-poll at /ns/{ns}/view/{view}/log and events at /ns/{ns}/view/{view}/events.
// view stands for the reader's subject set and grant, at for the ns_id of
// {ns} the answer is at. The answers keep their
// shapes; only the set changes. A range ends at the ns_id its answers
// name in X-Namespace-Revision, pages may be empty, and X-Log-Next may
// name an entry the page doesn't hold. Filtered logs carry no branch
// entries and aren't chain-verifiable: a partial reader learns of
// branches from Branches, and of changes of its rules by listing /heads
// again (§10).

// FilteredAt names a filtered answer (§7.9 URLs): the namespace, the
// view and at of its URL, and End, the ns_id of NS at at, which answers at
// an at carry as X-Namespace-Revision. View and At are "" for an answer
// that wasn't filtered, as for an unrestricted reader, whose End is the
// ns_id of the unfiltered URL.
type FilteredAt struct {
	NS, View, At, End string
}

// Filtered reports whether fa names a filtered answer.
func (fa FilteredAt) Filtered() bool { return fa.View != "" }

// filteredPathRe is a path under §7.9's prefix /ns/{ns}/view/{view}: with
// /at/{at} for heads and log ranges, without for long-poll and events.
var filteredPathRe = regexp.MustCompile(`^/ns/([a-z0-9][a-z0-9_-]{0,63})/view/(1[a-z2-7]{32})(?:/at/(1[a-z2-7]{32}))?/(heads|log|events)$`)

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
// in tail (heads, log or events): its view, and at ("" for long-poll and
// events, which have none). withAt says whether the URL must carry an at.
func (c *Client) filteredRedirect(r *response, ns, tail string, withAt bool) (view, at string, err error) {
	m := filteredPathRe.FindStringSubmatch(c.location(r))
	if r.status != 302 || m == nil || m[1] != ns || m[4] != tail || (m[3] != "") != withAt {
		return "", "", fmt.Errorf("client: %s redirects to %q, not a filtered %s of %s (§7.9)", r.path, r.header.Get("Location"), tail, ns)
	}
	return m[2], m[3], nil
}

// FilteredError is the 302 by which an origin sends a partial reader from
// a namespace's unfiltered URLs to the filtered form of View (§7.9 URLs),
// at At for heads and log ranges: the plain reads of a client made
// WithUnfilteredOnly return it, and NSEvents always does. The filtered
// log isn't chain-verifiable, and its batches hold only visible items
// (§10); a caller that accepts that reads it with a client without the
// option, or with the Filtered* calls. It unwraps to the 302's *APIError,
// so a caller that doesn't is stopped as by any other redirect.
type FilteredError struct {
	NS, View, At string
	Err          *APIError
}

func (e *FilteredError) Error() string {
	return fmt.Sprintf("%v: the log of %s is filtered for this grant, at view %s, and isn't chain-verifiable (§7.9, §10)", e.Err, e.NS, e.View)
}

func (e *FilteredError) Unwrap() error { return e.Err }

// AsFiltered returns err as a *FilteredError, if it is one.
func AsFiltered(err error) (*FilteredError, bool) {
	var fe *FilteredError
	ok := errors.As(err, &fe)
	return fe, ok
}

// filteredError is the error for a 302 r from the unfiltered long-poll or
// events of ns: a *FilteredError when it names their filtered form, tail
// being log or events, else the API error it was before v0.75.
func (c *Client) filteredError(r *response, ns, tail string) error {
	view, _, err := c.filteredRedirect(r, ns, tail, false)
	if err != nil {
		return r.apiError()
	}
	return &FilteredError{NS: ns, View: view, Err: r.apiError()}
}

// filteredPath is the filtered URL of fa ending in tail (§7.9 URLs):
// with /at/{at} when fa has one.
func filteredPath(fa FilteredAt, tail string) string {
	p := "/ns/" + fa.NS + "/view/" + fa.View
	if fa.At != "" {
		p += "/at/" + fa.At
	}
	return p + "/" + tail
}

func checkFilteredAt(fa FilteredAt) error {
	if err := checkNS(fa.NS); err != nil {
		return err
	}
	if err := checkID("view", fa.View); err != nil {
		return err
	}
	return checkOptID("at", fa.At)
}

// filteredBody is the body of a filtered 200 r of namespace ns: opened by
// open where it is sealed (application/jose, §7.9 Sealed namespaces),
// else its JSON, which a client holding sealed or e2e for ns refuses
// (ErrLevelLowered): a sealed namespace's filtered answers are JWEs.
func (c *Client) filteredBody(ctx context.Context, r *response, ns string, open func() (any, error)) (any, error) {
	if isJOSE(r) {
		body, err := open()
		if err != nil {
			return nil, fmt.Errorf("client: %s: %w", r.path, err)
		}
		return body, nil
	}
	if held := c.levels.held(ns); held == "sealed" || held == "e2e" {
		return nil, fmt.Errorf("client: %s: a filtered 200 in the clear in a namespace this client holds as %s (§7.9): %w", r.path, held, ErrLevelLowered)
	}
	return r.value(), nil
}

// endOf is an answer's X-Namespace-Revision, which an answer at an at
// carries (§7.9 Log ranges): the range's end.
func endOf(r *response) (string, error) {
	end := r.header.Get("X-Namespace-Revision")
	if err := checkID("X-Namespace-Revision", end); err != nil {
		return "", fmt.Errorf("client: %s: %w (§7.9)", r.path, err)
	}
	return end, nil
}

// FilteredHeadsAt fetches one page of the filtered /heads fa names
// (§7.9), as one under a cookie for /ns/{ns}/view/{view} reads it: at fa.At,
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
	return c.filteredHeads(ctx, FilteredAt{NS: fa.NS, View: fa.View, At: fa.At}, prefix, after)
}

// filteredHeads reads the filtered /heads page of fa, following one
// redirect to the current at of the same view.
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
			body, err := c.filteredBody(ctx, r, fa.NS, func() (any, error) {
				// Sealed: one JWE under the view's K_view, bound to
				// { ns, view, at, after } (§7.9 Sealed namespaces).
				return c.openFiltered(ctx, fa.NS, fa.View, string(r.body), fixedPL(seal.PL{"ns": fa.NS, "at": fa.At, "after": after}))
			})
			if err != nil {
				return nil, "", FilteredAt{}, err
			}
			m, _ := body.(map[string]any)
			items, next, err := parseHeadsValue(m, r.path, prefix)
			if err == nil {
				err = checkFilteredHeads(r, items, next, after)
			}
			if err != nil {
				return nil, "", FilteredAt{}, err
			}
			return items, next, fa, nil
		case r.status == 302 && hop == 0:
			view, at, err := c.filteredRedirect(r, fa.NS, "heads", true)
			if err != nil {
				return nil, "", FilteredAt{}, err
			}
			if view != fa.View {
				return nil, "", FilteredAt{}, fmt.Errorf("client: %s redirects to view %s, not %s (§7.9)", r.path, view, fa.View)
			}
			fa.At = at
			continue
		case r.status == 200 || r.status == 302:
			return nil, "", FilteredAt{}, fmt.Errorf("client: %s answers %d, not a filtered page (§7.9)", r.path, r.status)
		}
		return nil, "", FilteredAt{}, r.apiError()
	}
}

// checkFilteredHeads refuses a filtered /heads page whose rows aren't in
// ascending byte order strictly after after (§7.4), or whose next isn't
// its last row (§7.9 /heads), as on an empty page naming one: each
// next then moves past after, so a listing can't repeat a page forever.
func checkFilteredHeads(r *response, items []HeadItem, next, after string) error {
	last := after
	for _, it := range items {
		if it.Resource <= last {
			return fmt.Errorf("client: %s: row %q not after %q (§7.4)", r.path, it.Resource, last)
		}
		last = it.Resource
	}
	if next != "" && (len(items) == 0 || next != last) {
		return fmt.Errorf("client: %s: next %q is not the page's last row (§7.9)", r.path, next)
	}
	return nil
}

// filteredHeadsFrom lists the rest of the filtered /heads fa names after
// its first page, items and next, every row at one at: if the origin
// moves the listing to another at between pages, as when a namespace of
// the at is purged, it starts again there, at most a few times.
func (c *Client) filteredHeadsFrom(ctx context.Context, fa FilteredAt, prefix string, items []HeadItem, next string) ([]HeadItem, FilteredAt, error) {
	items = append([]HeadItem{}, items...)
	for restarts := 0; next != ""; {
		page, n, got, err := c.filteredHeads(ctx, fa, prefix, next)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		if got.At != fa.At {
			if restarts++; restarts > 3 {
				return nil, FilteredAt{}, fmt.Errorf("client: /ns/%s/view/%s/heads keeps moving to another at (§7.9)", fa.NS, fa.View)
			}
			if page, n, got, err = c.filteredHeads(ctx, got, prefix, ""); err != nil {
				return nil, FilteredAt{}, err
			}
			items = nil
		}
		items, next, fa = append(items, page...), n, got
	}
	return items, fa, nil
}

// FilteredLog fetches the namespace log after since ("" = from the first
// entry) up to the head, as NSLog does without knowing the head: GET
// /ns/{ns}/log, without live, answers 302 to the unfiltered range
// /ns/{ns}/rev/{ns_id}/log or, for a partial reader (§7.9), to its view's
// filtered range at the current at, directly or by way of the unfiltered
// one, which it follows, reading page by page until one lacks X-Log-Next.
// In a public namespace it reads through the grant's view as NSLog does
// (auto.go). fa is as for NSLog; WithUnfilteredOnly doesn't apply.
func (c *Client) FilteredLog(ctx context.Context, ns, since string) ([]NSEntry, FilteredAt, error) {
	if err := checkNS(ns); err != nil {
		return nil, FilteredAt{}, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, FilteredAt{}, err
	}
	return autoRead(ctx, c, ns, false, func(bool) ([]NSEntry, FilteredAt, bool, error) {
		return c.headLog(ctx, ns, since)
	}, func(view string) ([]NSEntry, FilteredAt, error) {
		return c.FilteredLogAt(ctx, FilteredAt{NS: ns, View: view}, since)
	})
}

// headLog is FilteredLog at the unfiltered URLs.
func (c *Client) headLog(ctx context.Context, ns, since string) ([]NSEntry, FilteredAt, bool, error) {
	path, end := "/ns/"+ns+"/log", ""
	for {
		r, err := c.do(ctx, "GET", path, sinceQuery(since), nil)
		if err != nil {
			return nil, FilteredAt{}, false, err
		}
		switch {
		case r.status == 200 && end != "":
			return c.nsLog(ctx, ns, end, since, true)
		case r.status != 302:
			return nil, FilteredAt{}, false, r.apiError()
		}
		loc := c.location(r)
		if m := unfilteredLogRe.FindStringSubmatch(loc); m != nil && m[1] == ns && end == "" {
			path, end = loc, m[2]
			continue
		}
		view, at, err := c.filteredRedirect(r, ns, "log", true)
		if err != nil {
			return nil, FilteredAt{}, false, err
		}
		es, fa, err := c.FilteredLogAt(ctx, FilteredAt{NS: ns, View: view, At: at}, since)
		return es, fa, false, err
	}
}

// FilteredLogAt reads the filtered range fa names after since, every page
// (§7.9 Log ranges). Without fa.At it starts at …/view/{view}/log, which
// the origin redirects to the current at, as under a cookie for
// /ns/{ns}/view/{view}.
func (c *Client) FilteredLogAt(ctx context.Context, fa FilteredAt, since string) ([]NSEntry, FilteredAt, error) {
	if err := checkFilteredAt(fa); err != nil {
		return nil, FilteredAt{}, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, FilteredAt{}, err
	}
	fa.End = ""
	if fa.At == "" {
		var err error
		if fa, err = c.currentAt(ctx, fa, "log", sinceQuery(since)); err != nil {
			return nil, FilteredAt{}, err
		}
	}
	page, next, fa, err := c.FilteredLogPage(ctx, fa, since)
	if err != nil {
		return nil, FilteredAt{}, err
	}
	return c.filteredRange(ctx, fa, next, page)
}

// currentAt is fa at the current at of its view, which a URL under
// /ns/{ns}/view/{view} without at, ending in tail, redirects to with q
// (§7.9 URLs).
func (c *Client) currentAt(ctx context.Context, fa FilteredAt, tail string, q url.Values) (FilteredAt, error) {
	r, err := c.do(ctx, "GET", filteredPath(FilteredAt{NS: fa.NS, View: fa.View}, tail), q, nil)
	if err != nil {
		return FilteredAt{}, err
	}
	if r.status != 302 {
		return FilteredAt{}, r.apiError()
	}
	view, at, err := c.filteredRedirect(r, fa.NS, tail, true)
	if err != nil {
		return FilteredAt{}, err
	}
	if view != fa.View {
		return FilteredAt{}, fmt.Errorf("client: %s redirects to view %s, not %s (§7.9)", r.path, view, fa.View)
	}
	return FilteredAt{NS: fa.NS, View: view, At: at}, nil
}

// filteredRange reads the rest of the filtered range fa names after its
// first page, first and next, every page at fa.End.
func (c *Client) filteredRange(ctx context.Context, fa FilteredAt, next string, first []NSEntry) ([]NSEntry, FilteredAt, error) {
	all := append([]NSEntry{}, first...)
	seen := map[string]bool{}
	for next != "" {
		if seen[next] {
			return nil, FilteredAt{}, fmt.Errorf("client: %s: X-Log-Next %s repeats", filteredPath(fa, "log"), next)
		}
		seen[next] = true
		page, n, got, err := c.FilteredLogPage(ctx, fa, next)
		if err != nil {
			return nil, FilteredAt{}, err
		}
		if got.End != fa.End {
			return nil, FilteredAt{}, fmt.Errorf("client: %s: the range's end moved from %s to %s (§7.9)", filteredPath(fa, "log"), fa.End, got.End)
		}
		all, next = append(all, page...), n
	}
	return all, fa, nil
}

// FilteredLogPage fetches one page of the filtered range fa names after
// since (§7.9 Log ranges, §7.1): its visible entries, possibly none,
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
		return nil, "", got, fmt.Errorf("client: a filtered range of %s needs an at (§7.9)", fa.NS)
	}
	if err := checkOptID("since", since); err != nil {
		return nil, "", got, err
	}
	got = FilteredAt{NS: fa.NS, View: fa.View, At: fa.At}
	next, err = c.filteredLogPage(ctx, filteredPath(fa, "log"), since, func(r *response, logNext string) (string, error) {
		end, err := endOf(r)
		if err != nil {
			return "", err
		}
		got.End = end
		body, err := c.filteredBody(ctx, r, fa.NS, func() (any, error) {
			// Sealed: one JWE under the view's K_view, bound to the
			// page's bounds, its last entry scanned, X-Log-Next, or on
			// the last page the range's end (§7.9 Sealed namespaces).
			last := logNext
			if last == "" {
				last = end
			}
			return c.openFiltered(ctx, fa.NS, fa.View, string(r.body), fixedPL(seal.RangePL(fa.NS, since, last)))
		})
		if err != nil {
			return "", err
		}
		es, err := parseNSLog(body, r.path)
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

// ViewOf finds the view of the client's grant in namespace ns (§7.9
// view) without a redirect: a public namespace's unfiltered URLs ignore
// the grant and never redirect a partial reader to its view, whose
// prefix alone takes the grant there, as a filter (§7 step 1, §7.9 Where,
// v0.90). In a sealed namespace POST /ns/{ns}/keys names it with the view
// key it gives a partial reader (§E.2.3); elsewhere, where /keys is 404
// not_offered, POST /edge-grants names it in the prefix
// /ns/{ns}/view/{view} it issues (§C.5.2). Either draws a token from the
// principal's exchangeRate bucket (§6.6), so the plain reads ask it once per
// grant and namespace and remember the answer (auto.go); and the exchange is all or
// nothing across the namespaces the grant names. It returns "" for a grant
// that isn't a partial reader there, one that reads ns unrestricted (K_e,
// a /ns/{ns} prefix) or fixes the names it reads (K_r, /r/{ns}/{name}
// prefixes), which reads at the unfiltered URLs, and the refusal of any
// other grant.
func (c *Client) ViewOf(ctx context.Context, ns string) (string, error) {
	if err := checkNS(ns); err != nil {
		return "", err
	}
	ka, err := c.FetchKeysAnswer(ctx, ns, nil, nil)
	switch {
	case err == nil && ka.Level == "sealed":
		// A partial reader's only key is its view's (§E.2.3).
		for _, k := range ka.Keys {
			if k.View != "" {
				return k.View, checkID("view", k.View)
			}
		}
		return "", nil
	case err != nil && !IsNotOffered(err):
		return "", err
	}
	// Not sealed, or end-to-end, which §7.9 doesn't cover: the exchange.
	r, err := c.do(ctx, "POST", "/edge-grants", nil, nil)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", r.apiError()
	}
	prefixes, _ := r.obj()["prefixes"].([]any)
	for _, p := range prefixes {
		s, _ := p.(string)
		if v, ok := strings.CutPrefix(s, "/ns/"+ns+"/view/"); ok {
			return v, checkID("view", v)
		}
	}
	return "", nil
}
