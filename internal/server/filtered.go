package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/lifecycle"
)

// Filtered namespace reads (§B.11.9): /heads, log ranges, long-poll and
// events of a covered namespace at /ns/{ns}/g/{gs}/…, filtered to what the
// subject set gs may see, and the redirects of partial readers to them.
// None of it is read from or written to a cache of the origin's; every
// redirect a grant or cookie decides is private, no-store.

// privateNoStore marks a response no cache may keep, the edge included
// (§9, §B.11.9 URLs): a redirect decided by a grant or cookie, or an
// answer filtered for one.
func privateNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	edge.NoStore(w.Header())
}

// writeFilteredRedirect answers err if it is a *core.FilteredRedirect: 302
// to /ns/{ns}/g/{gs}/at/{at}{suffix}, or without /at/{at} for long-poll and
// events, with q as its query, private, no-store and varying by
// Authorization, which decided it for an unfiltered URL (§B.11.9 URLs).
// It returns false for any other error.
func (s *Server) writeFilteredRedirect(w http.ResponseWriter, err error, suffix string, q url.Values) bool {
	var fr *core.FilteredRedirect
	if !errors.As(err, &fr) {
		return false
	}
	loc := "/ns/" + fr.NS + "/g/" + fr.GS
	if fr.At != "" {
		loc += "/at/" + fr.At
	}
	loc += suffix
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

// filteredTags are the Cache-Tags of a filtered answer at an at: its
// unfiltered form's, then ns:{x} for every other namespace in at (§B.11.9
// URLs), which a purge or prune of any of them purges.
func filteredTags(info *core.FilteredInfo, tags ...string) []string {
	if info != nil {
		for _, x := range info.Others {
			tags = append(tags, "ns:"+x)
		}
	}
	return tags
}

// filteredHeadsTags are a filtered /heads answer's tags: filteredTags of
// the unfiltered /heads' with heads:{x} too for every other namespace in
// at, so that a resource purge in a deciding catalog, which purges its
// own /heads (heads:{x}, §8.3), reaches the pages it decided.
func filteredHeadsTags(info *core.FilteredInfo, ns string) []string {
	tags := filteredTags(info, "ns:"+ns, "heads:"+ns)
	if info != nil {
		for _, x := range info.Others {
			tags = append(tags, "heads:"+x)
		}
	}
	return tags
}

// setFilteredAt sets X-Namespace-Revision, {ns}'s ns_id in the answer's at
// (§B.11.9 Log ranges).
func setFilteredAt(w http.ResponseWriter, info *core.FilteredInfo) {
	if info != nil && info.NSID != "" {
		w.Header().Set("X-Namespace-Revision", info.NSID)
	}
}

// filteredCurrent answers a URL under /ns/{ns}/g/{gs} without at: 302 to
// its form at the current at, with q (§B.11.9 URLs).
func (s *Server) filteredCurrent(w http.ResponseWriter, r *http.Request, suffix string, q url.Values) {
	ns, gs := r.PathValue("ns"), r.PathValue("gs")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	err := s.e.FilteredCurrent(r.Context(), ns, gs, creds(r))
	if s.writeFilteredRedirect(w, err, suffix, q) {
		return
	}
	privateNoStore(w)
	writeErr(w, err)
}

// gHeadsCurrent is GET /ns/{ns}/g/{gs}/heads?after&prefix: 302 to the
// current at.
func (s *Server) gHeadsCurrent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, err := headsPrefix(q); err != nil {
		writeErr(w, err)
		return
	}
	s.filteredCurrent(w, r, "/heads", keep(q, "after", "prefix"))
}

// gHeads is GET /ns/{ns}/g/{gs}/at/{at}/heads?after&prefix (§B.11.9
// /heads): the visible rows, in pages filled to the log page size, next on
// every full page. It is cached as the unfiltered /heads, immutable, with
// its tags plus ns:{x} and heads:{x} for the rest of at, and carries
// X-Namespace-Revision.
func (s *Server) gHeads(w http.ResponseWriter, r *http.Request) {
	ns, gs, at := r.PathValue("ns"), r.PathValue("gs"), r.PathValue("at")
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
	page, info, err := s.e.FilteredHeads(r.Context(), ns, gs, at, q.Get("after"), prefix, creds(r))
	if err != nil {
		if s.writeFilteredRedirect(w, err, "/heads", keep(q, "after", "prefix")) {
			return
		}
		setFilteredAt(w, info)
		if info != nil && s.writeErrShort(w, r, err, filteredHeadsTags(info, ns)...) {
			return
		}
		writeErr(w, err)
		return
	}
	setFilteredAt(w, info)
	s.cache(w, r, ccImmutable, page.Public, filteredHeadsTags(info, ns)...)
	out := map[string]any{"heads": page.Items}
	if page.Next != "" {
		out["next"] = page.Next
	}
	writeJSON(w, 200, out)
}

// gLog is GET /ns/{ns}/g/{gs}/at/{at}/log?since= (§B.11.9 Log ranges): a
// page of the filtered range, possibly empty, X-Log-Next naming its last
// entry scanned on every page but the last, cached as the unfiltered range
// with X-Namespace-Revision, the range's end.
func (s *Server) gLog(w http.ResponseWriter, r *http.Request) {
	ns, gs, at := r.PathValue("ns"), r.PathValue("gs"), r.PathValue("at")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	q := r.URL.Query()
	lg, info, err := s.e.FilteredLog(r.Context(), ns, gs, at, q.Get("since"), s.e.Limits().LogPageSize, creds(r))
	if err != nil {
		if s.writeFilteredRedirect(w, err, "/log", keep(q, "since")) {
			return
		}
		writeErr(w, err)
		return
	}
	setFilteredAt(w, info)
	s.writeLog(w, r, lg, ns, filteredTags(info, "ns:"+ns))
}

// gLive is GET /ns/{ns}/g/{gs}/log: without live, 302 to the range at the
// current at; with live=long-poll, a filtered long-poll (§B.11.9 Long-poll).
func (s *Server) gLive(w http.ResponseWriter, r *http.Request) {
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
	ns, gs := r.PathValue("ns"), r.PathValue("gs")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	s.filteredLongPoll(w, r, ns, gs, cursor)
}

// filteredLongPoll is longPoll for a filtered log (§B.11.9 Long-poll):
// only visible entries answer 200 or end a wait. A page with none moves
// since past the entries it scanned and reads on, at once while the log
// goes on, else after the next write, until the interval ends: 204, its
// X-Namespace-Revision the newest entry scanned, else since, which the
// next poll gives as since. X-Cursor is as unfiltered (§7.7). Every fetch
// is admitted again at the current checkpoint.
func (s *Server) filteredLongPoll(w http.ResponseWriter, r *http.Request, ns, gs string, reqCursor int64) {
	since := r.URL.Query().Get("since")
	tags := []string{"ns:" + ns}
	interval := s.e.LongPollInterval()
	current, err := judgeCursor(time.Now(), interval, reqCursor)
	if err != nil {
		writeErr(w, err)
		return
	}
	atOnce := reqCursor < current
	deadline := time.Unix(0, (current+1)*int64(interval))
	lim := s.e.Limits().LogPageSize
	cred := creds(r)
	for {
		wait := s.e.Wait(ns)
		lg, _, err := s.e.FilteredLiveLog(r.Context(), ns, gs, since, lim, cred)
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
		if len(lg.Entries) > 0 {
			s.setLive(w, r, false, fmt.Sprintf("public, max-age=0, s-maxage=%d", int(interval.Seconds())), tags)
			w.Header().Set("X-Namespace-Revision", lg.Last)
			w.Header().Set("X-Cursor", strconv.FormatInt(time.Now().UnixNano()/int64(interval), 10))
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
		cur := time.Now().UnixNano() / int64(interval)
		if reqCursor+1 > cur {
			cur = reqCursor + 1
		}
		s.setLive(w, r, false, "public, max-age=0, s-maxage=2", tags)
		if since != "" {
			w.Header().Set("X-Namespace-Revision", since)
		}
		w.Header().Set("X-Cursor", strconv.FormatInt(cur, 10))
		w.WriteHeader(204)
		return
	}
}

// gEvents is GET /ns/{ns}/g/{gs}/events (§B.11.9 Events, §7.3): an event
// stream of the visible entries, each page fetched, and each keep-alive
// preceded by a fetch, admitted again and judged at the current
// checkpoint, ending when admission fails or the credential it was
// admitted under expires. since moves past every entry scanned, so
// Last-Event-ID may name a hidden one; while the log goes on it fetches
// again at once.
func (s *Server) gEvents(w http.ResponseWriter, r *http.Request) {
	ns, gs := r.PathValue("ns"), r.PathValue("gs")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	since := sinceParam(r)
	cred := creds(r)
	page := s.e.Limits().LogPageSize
	wait := s.e.Wait(ns)
	lg, _, err := s.e.FilteredLiveLog(r.Context(), ns, gs, since, page, cred)
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
		lg, _, err = s.e.FilteredLiveLog(r.Context(), ns, gs, since, page, cred)
		if err != nil || lg.Status != 200 {
			return
		}
		if keepAlive && len(lg.Entries) == 0 {
			sseKeepAliveComment(w)
		}
	}
}
