package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
)

// Filtered namespace reads (§7.9): /heads, log ranges, long-poll and
// events of a covered namespace at /ns/{ns}/view/{view}/…, filtered to
// what the view may see, a resource's immutable URLs under the same
// prefix, and the redirects of partial readers to them.
// None of it is read from or written to a cache of the origin's; every
// redirect a grant or cookie decides is private, no-store.

// privateNoStore marks a response no cache may keep, the edge included
// (§9, §7.9 URLs): a redirect decided by a grant or cookie, or an
// answer filtered for one.
func privateNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	edge.NoStore(w.Header())
}

// writeFilteredRedirect answers err if it is a *core.FilteredRedirect: 302
// to /ns/{ns}/view/{view}/at/{at}{suffix}, or without /at/{at} for
// long-poll and events, with q as its query, or to /ns/{ns}/view/{view}
// followed by a resource's immutable URL (§7.9 Content), private,
// no-store and varying by Authorization, which decided it for an
// unfiltered URL (§7.9 URLs). It returns false for any other error.
func (s *Server) writeFilteredRedirect(w http.ResponseWriter, err error, suffix string, q url.Values) bool {
	var fr *core.FilteredRedirect
	if !errors.As(err, &fr) {
		return false
	}
	loc := "/ns/" + fr.NS + "/view/" + fr.View
	switch {
	case fr.Content != "":
		loc += fr.Content
	case fr.At != "":
		loc += "/at/" + fr.At + suffix
	default:
		loc += suffix
	}
	if enc := q.Encode(); enc != "" {
		loc += "?" + enc
	}
	privateNoStore(w)
	w.Header().Add("Vary", "Authorization")
	w.Header().Set("Location", loc)
	w.WriteHeader(302)
	return true
}

// keep is the query of q's parameters names that are present.
func keep(q url.Values, names ...string) url.Values {
	out := url.Values{}
	for _, k := range names {
		if q.Has(k) {
			out.Set(k, q.Get(k))
		}
	}
	return out
}

// headsPrefix is a /heads request's prefix: "" without one, else a
// resource name (§7.4, §3.6), or 400 bad_input, a request-shape error
// answered before authorisation (§7, §12.4).
func headsPrefix(q url.Values) (string, error) {
	if !q.Has("prefix") {
		return "", nil
	}
	p := q.Get("prefix")
	if !core.ValidResourceName(p) {
		return "", badInput(fmt.Sprintf("prefix %q is not a resource name (§3.6, §7.4)", p))
	}
	return p, nil
}

// filteredHeadsTags are a filtered /heads answer's tags: the unfiltered
// /heads', heads:{ns} included (§7.9 URLs, §9).
func filteredHeadsTags(ns string) []string {
	return []string{"ns:" + ns, "heads:" + ns}
}

// filteredCache is s.cache for a filtered answer: an unrestricted
// reader's /ns/{ns} cookie reads unfiltered there, which no cache may keep
// for the view's readers (core.FilteredInfo.Private).
func (s *Server) filteredCache(w http.ResponseWriter, r *http.Request, info *core.FilteredInfo, class string, public bool, tags ...string) {
	if info != nil && info.Private {
		privateNoStore(w)
		return
	}
	s.cache(w, r, class, public, tags...)
}

// viewedKey keys a request admitted at a view's content URL (viewContent).
type viewedKey struct{}

// viewed is a request admitted at a view's content URL: the credentials
// its resource read is answered under, and whether no cache may keep it.
type viewed struct {
	cred    core.Credentials
	private bool
}

// viewContent serves GET /ns/{ns}/view/{view}/r/{name}/rev/{id}, its /raw
// and …/blob/{bid} (§7.9 Content): admitted at the view at the current
// checkpoint (core.Engine.ViewCredentials), then answered by serve, the
// resource URL's own handler, as its own form, each revision judged by
// the view. Its answers are cached and tagged as their own forms', but
// for an unrestricted reader's /ns/{ns} cookie, which no cache may keep.
func (s *Server) viewContent(serve http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, view := r.PathValue("ns"), r.PathValue("view")
		if err := validNames(ns, r.PathValue("name")); err != nil {
			writeErr(w, err)
			return
		}
		cred, err := s.e.ViewCredentials(r.Context(), ns, view, creds(r))
		if err != nil {
			privateNoStore(w)
			writeErr(w, err)
			return
		}
		v := &viewed{cred: cred, private: cred.ViewPrivate()}
		serve(w, r.WithContext(context.WithValue(r.Context(), viewedKey{}, v)))
	}
}

// viewedOf is r's admission at a view's content URL, nil for any other.
func viewedOf(r *http.Request) *viewed {
	v, _ := r.Context().Value(viewedKey{}).(*viewed)
	return v
}

// setFilteredAt sets X-Namespace-Revision, {ns}'s ns_id the answer is at
// (§7.9 Log ranges).
func setFilteredAt(w http.ResponseWriter, info *core.FilteredInfo) {
	if info != nil && info.At != "" {
		w.Header().Set("X-Namespace-Revision", info.At)
	}
}

// filteredCurrent answers a URL under /ns/{ns}/view/{view} without at:
// 302 to its form at the current at, with q (§7.9 URLs).
func (s *Server) filteredCurrent(w http.ResponseWriter, r *http.Request, suffix string, q url.Values) {
	ns, view := r.PathValue("ns"), r.PathValue("view")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	err := s.e.FilteredCurrent(r.Context(), ns, view, suffix, creds(r))
	if s.writeFilteredRedirect(w, err, suffix, q) {
		return
	}
	privateNoStore(w)
	writeErr(w, err)
}

// viewHeadsCurrent is GET /ns/{ns}/view/{view}/heads?after&prefix: 302
// to the current at.
func (s *Server) viewHeadsCurrent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, err := headsPrefix(q); err != nil {
		writeErr(w, err)
		return
	}
	s.filteredCurrent(w, r, "/heads", keep(q, "after", "prefix"))
}

// viewHeads is GET /ns/{ns}/view/{view}/at/{at}/heads?after&prefix (§7.9
// /heads): the visible rows, in pages filled to the log page size, next on
// every full page. It is cached as the unfiltered /heads, immutable, with
// its tags plus ns:{x} and heads:{x} for the rest of at, and carries
// X-Namespace-Revision.
func (s *Server) viewHeads(w http.ResponseWriter, r *http.Request) {
	ns, view, at := r.PathValue("ns"), r.PathValue("view"), r.PathValue("at")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	q := r.URL.Query()
	prefix, err := headsPrefix(q)
	if err != nil {
		writeErr(w, err)
		return
	}
	page, info, err := s.e.FilteredHeads(r.Context(), ns, view, at, q.Get("after"), prefix, creds(r))
	if err != nil {
		if s.writeFilteredRedirect(w, err, "/heads", keep(q, "after", "prefix")) {
			return
		}
		setFilteredAt(w, info)
		if info != nil && !info.Private && s.writeErrShort(w, r, err, filteredHeadsTags(ns)...) {
			return
		}
		writeErr(w, err)
		return
	}
	setFilteredAt(w, info)
	s.filteredCache(w, r, info, ccImmutable, page.Public, filteredHeadsTags(ns)...)
	if page.JWE != "" {
		// A sealed namespace's: one JWE under the view's K_view (§7.9,
		// §E.2.2).
		w.Header().Set("Content-Type", seal.ContentType)
		w.WriteHeader(200)
		io.WriteString(w, page.JWE)
		return
	}
	out := map[string]any{"heads": page.Items}
	if page.Next != "" {
		out["next"] = page.Next
	}
	writeJSON(w, 200, out)
}

// viewLog is GET /ns/{ns}/view/{view}/at/{at}/log?since= (§7.9 Log ranges): a
// page of the filtered range, possibly empty, X-Log-Next naming its last
// entry scanned on every page but the last, cached as the unfiltered range
// with X-Namespace-Revision, the range's end.
func (s *Server) viewLog(w http.ResponseWriter, r *http.Request) {
	ns, view, at := r.PathValue("ns"), r.PathValue("view"), r.PathValue("at")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	q := r.URL.Query()
	lg, info, err := s.e.FilteredLog(r.Context(), ns, view, at, q.Get("since"), s.e.Limits().LogPageSize, creds(r))
	if err != nil {
		if s.writeFilteredRedirect(w, err, "/log", keep(q, "since")) {
			return
		}
		writeErr(w, err)
		return
	}
	setFilteredAt(w, info)
	if info.Private {
		privateNoStore(w)
		writeLogBody(w, lg)
		return
	}
	s.writeLog(w, r, lg, ns, []string{"ns:" + ns})
}

// viewLive is GET /ns/{ns}/view/{view}/log: without live, 302 to the range at the
// current at; with live=long-poll, a filtered long-poll (§7.9 Long-poll).
func (s *Server) viewLive(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	live, cursor, err := liveQuery(q)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !live {
		s.filteredCurrent(w, r, "/log", keep(q, "since"))
		return
	}
	ns, view := r.PathValue("ns"), r.PathValue("view")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	s.filteredLongPoll(w, r, ns, view, cursor)
}

// filteredLongPoll is longPoll for a filtered log (§7.9 Long-poll):
// only visible entries answer 200 or end a wait. A page with none moves
// since past the entries it scanned and reads on, at once while the log
// goes on, else after the next write, until the interval ends: 204, its
// X-Namespace-Revision the newest entry scanned, else since, which the
// next poll gives as since. X-Cursor is as unfiltered (§7.7). Every fetch
// is admitted again at the current checkpoint.
func (s *Server) filteredLongPoll(w http.ResponseWriter, r *http.Request, ns, view string, reqCursor int64) {
	// One read request, one budget of validationSteps (§6.6).
	r = r.WithContext(s.e.ReadBudget(r.Context()))
	since := r.URL.Query().Get("since")
	tags := []string{"ns:" + ns}
	clock := s.clockOf(filteredLogPath(ns, view))
	interval := clock.interval
	current, err := judgeCursor(time.Now(), clock, reqCursor)
	if err != nil {
		writeErr(w, err)
		return
	}
	atOnce := reqCursor < current
	deadline := clock.end(current)
	lim := s.e.Limits().LogPageSize
	cred := creds(r)
	noChange := func(private bool) {
		cur := clock.cursor(time.Now())
		if reqCursor+1 > cur {
			cur = reqCursor + 1
		}
		s.setLive(w, r, false, "public, max-age=0, s-maxage=2", tags)
		if private {
			// An unrestricted reader's /ns/{ns} cookie: no cache's, its
			// 204 as much as its entries (§7.9 Partial reader).
			privateNoStore(w)
		}
		if since != "" {
			w.Header().Set("X-Namespace-Revision", since)
		}
		w.Header().Set("X-Cursor", strconv.FormatInt(cur, 10))
		w.WriteHeader(204)
	}
	private := false
	for {
		wait := s.e.Wait(ns)
		if testLongPollFetch != nil {
			testLongPollFetch()
		}
		lg, info, err := s.e.FilteredLiveLog(r.Context(), ns, view, since, lim, cred)
		if core.ReadBudgetRanOut(err) {
			// The wait's one budget ran out at an admission:
			// 204 naming the last entry judged whole (§6.6, §7.9
			// Long-poll, v0.90). Only that refusal: a cookie that died,
			// a revoked grant's, a purge's or any other error answers
			// as it is, whatever the budget.
			noChange(private)
			return
		}
		if err != nil {
			if s.writeErrShort(w, r, err, tags...) {
				return
			}
			writeErr(w, err)
			return
		}
		if lg.Status != 200 {
			s.writeLog(w, r, lg, ns, tags)
			return
		}
		private = info.Private
		if len(lg.Entries) == 0 && s.e.ReadBudgetSpent(r.Context()) {
			// Admitted, yet the wait's budget is spent: it has run out
			// (§6.6), 204 now, past the entries scanned.
			since = lg.Last
			noChange(private)
			return
		}
		if len(lg.Entries) > 0 {
			s.setLive(w, r, false, fmt.Sprintf("public, max-age=0, s-maxage=%d", int(interval.Seconds())), tags)
			if info.Private {
				privateNoStore(w)
			}
			w.Header().Set("X-Namespace-Revision", lg.Last)
			w.Header().Set("X-Cursor", strconv.FormatInt(clock.cursor(time.Now()), 10))
			writeLogBody(w, lg)
			return
		}
		// Past the hidden entries scanned: the next fetch, and the 204's
		// header, start after them.
		since = lg.Last
		if lg.More {
			if r.Context().Err() != nil {
				return
			}
			continue
		}
		if !atOnce {
			select {
			case <-wait:
				continue
			case <-time.After(time.Until(deadline)):
			case <-lifecycle.Stopping(r.Context()):
			case <-r.Context().Done():
				return
			}
		}
		noChange(info.Private)
		return
	}
}

// viewEvents is GET /ns/{ns}/view/{view}/events (§7.9 Events, §7.3): an event
// stream of the visible entries, each page fetched, and each keep-alive
// preceded by a fetch, admitted again and judged at the current
// checkpoint, ending when admission fails or the credential it was
// admitted under expires. since moves past every entry scanned, so
// Last-Event-ID may name a hidden one; while the log goes on it fetches
// again at once.
func (s *Server) viewEvents(w http.ResponseWriter, r *http.Request) {
	ns, view := r.PathValue("ns"), r.PathValue("view")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	since := sinceParam(r)
	cred := creds(r)
	page := s.e.Limits().LogPageSize
	wait := s.e.Wait(ns)
	lg, _, err := s.e.FilteredEventLog(r.Context(), ns, view, since, page, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	if lg.Status != 200 {
		sseLogErr(w, lg)
		return
	}
	startSSE(w)
	expired, stop := s.admissionEnds(lg.Until)
	defer stop()
	for {
		for i, e := range lg.Entries {
			sseEntry(w, e["kind"].(string), lg, i)
		}
		since = lg.Last
		if lg.Purged && !lg.More {
			// The purge-ns entry, always shown, is sent: the stream ends
			// (§7.3, §8.5).
			return
		}
		keepAlive := false
		if !lg.More {
			select {
			case <-wait:
			case <-time.After(sseKeepAlive):
				keepAlive = true
			case <-expired:
				return
			case <-lifecycle.Stopping(r.Context()):
				return
			case <-r.Context().Done():
				return
			}
		} else if r.Context().Err() != nil {
			return
		}
		wait = s.e.Wait(ns)
		lg, _, err = s.e.FilteredEventLog(r.Context(), ns, view, since, page, cred)
		if err != nil || lg.Status != 200 {
			return
		}
		if keepAlive && len(lg.Entries) == 0 {
			sseKeepAliveComment(w)
		}
	}
}
