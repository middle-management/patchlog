package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/lifecycle"
)

// Live reads: event streams (§7.3) and long-poll (§7.7).

// liveQuery reads a log URL's live and cursor (§7.7): live absent, for
// the 302 to the immutable range, or long-poll; cursor, if given, a decimal
// number (^[0-9]+$), else -1. Any other live, an empty one included, and
// any other cursor, such as an empty one or +5, is 400 (§7, §12.4), before
// authorisation.
func liveQuery(q url.Values) (live bool, cursor int64, err error) {
	cursor = -1
	if q.Has("live") {
		if q.Get("live") != "long-poll" {
			return false, 0, badInput("live must be long-poll (§7.7)")
		}
		live = true
	}
	if q.Has("cursor") {
		c := q.Get("cursor")
		n, perr := strconv.ParseInt(c, 10, 64)
		if c == "" || strings.Trim(c, "0123456789") != "" || perr != nil {
			return false, 0, badInput("cursor must be a decimal number (§7.7)")
		}
		cursor = n
	}
	return live, cursor, nil
}

// longPoll implements §7.7 for a log fetched by fetch, with the request's
// cursor (liveQuery), -1 without one.
func (s *Server) longPoll(w http.ResponseWriter, r *http.Request, ns, header string, tags []string, reqCursor int64,
	fetch func(ctx context.Context, since string) (*core.Log, error)) {
	since := r.URL.Query().Get("since")
	interval := s.e.LongPollInterval()
	now := time.Now()
	current := now.UnixNano() / int64(interval)
	if reqCursor > current+int64(time.Hour/interval) {
		writeErr(w, badInput("cursor too far ahead"))
		return
	}
	deadline := time.Unix(0, (current+1)*int64(interval))
	for {
		wait := s.e.Wait(ns)
		lg, err := fetch(r.Context(), since)
		if err != nil {
			if s.writeErrShort(w, r, err) {
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
			// A page, as a range's (fetch asks for the log page size,
			// §7.1): header names its last entry, the next since. It
			// carries no X-Log-Next, which continues an immutable range
			// up to a fixed id; a live reader polls again at once anyway.
			s.setLive(w, r, lg.Public, fmt.Sprintf("public, max-age=0, s-maxage=%d", int(interval.Seconds())), tags)
			w.Header().Set(header, lg.Last)
			w.Header().Set("X-Cursor", strconv.FormatInt(time.Now().UnixNano()/int64(interval), 10))
			writeLogBody(w, lg)
			return
		}
		select {
		case <-wait:
			continue
		case <-time.After(time.Until(deadline)):
		case <-lifecycle.Stopping(r.Context()):
			// The server is shutting down: the normal "no change" answer
			// now, so the client polls again (elsewhere).
		case <-r.Context().Done():
			return
		}
		cur := time.Now().UnixNano() / int64(interval)
		if reqCursor+1 > cur {
			cur = reqCursor + 1
		}
		s.setLive(w, r, lg.Public, "public, max-age=0, s-maxage=2", tags)
		w.Header().Set(header, since)
		w.Header().Set("X-Cursor", strconv.FormatInt(cur, 10))
		w.WriteHeader(204)
		return
	}
}

// setLive sets the headers of a long-poll answer (§7.7, §9), private as
// cache sets them.
func (s *Server) setLive(w http.ResponseWriter, r *http.Request, public bool, cc string, tags []string) {
	if public {
		w.Header().Set("Cache-Control", cc)
	} else {
		w.Header().Set("Cache-Control", "private, max-age=0")
		s.edge.Private(w.Header(), r, strings.TrimPrefix(cc, "public, "))
	}
	w.Header().Set("Cache-Tag", strings.Join(tags, ","))
	w.Header().Set("Surrogate-Key", strings.Join(tags, " "))
}

func (s *Server) resourceLive(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	live, cursor, err := liveQuery(r.URL.Query())
	if err != nil {
		writeErr(w, err)
		return
	}
	lim := s.e.Limits().LogPageSize
	if !live {
		h, err := s.e.ResourceHead(r.Context(), ns, name, creds(r))
		if err != nil {
			if s.writeErrShort(w, r, err) {
				return
			}
			writeErr(w, err)
			return
		}
		if h.Head == "" {
			code := 404
			if h.State == core.Purged {
				code = 410
			}
			if code == 404 {
				// Unknown resource: §9's short class, as resourceHead does.
				s.cache(w, r, ccShort, h.Public)
			} else {
				// A purged resource is 410, "long" (§9).
				s.cache(w, r, ccLong, h.Public)
			}
			writeJSON(w, code, map[string]any{"code": map[int]string{404: "not_found", 410: "gone"}[code]})
			return
		}
		s.cache(w, r, ccHead, h.Public, resTags(ns, name)...)
		loc := "/r/" + ns + "/" + name + "/rev/" + h.Head + "/log"
		if sn := r.URL.Query().Get("since"); sn != "" {
			loc += "?since=" + sn
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(302)
		return
	}
	s.longPoll(w, r, ns, "X-Revision", resTags(ns, name), cursor, func(ctx context.Context, since string) (*core.Log, error) {
		return s.e.ResourceLog(ctx, ns, name, "", since, lim, creds(r))
	})
}

func (s *Server) nsLive(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	live, cursor, err := liveQuery(r.URL.Query())
	if err != nil {
		writeErr(w, err)
		return
	}
	lim := s.e.Limits().LogPageSize
	if !live {
		info, err := s.e.NamespaceHead(r.Context(), ns, creds(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		s.cache(w, r, ccHead, info.Public, "ns:"+ns)
		loc := "/ns/" + ns + "/rev/" + info.Head + "/log"
		if sn := r.URL.Query().Get("since"); sn != "" {
			loc += "?since=" + sn
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(302)
		return
	}
	// The request's read check, while it holds, stands for its later
	// reads, which are then shared with the other waiters (core/live.go).
	var pass *core.LivePass
	s.longPoll(w, r, ns, "X-Namespace-Revision", []string{"ns:" + ns}, cursor, func(ctx context.Context, since string) (*core.Log, error) {
		lg, p, err := s.e.NamespaceLiveLog(ctx, ns, since, lim, creds(r), pass)
		pass = p
		return lg, err
	})
}

// sse writes one server-sent event.
func sse(w http.ResponseWriter, event, id string, data any) {
	sseRaw(w, event, id, string(jsonv.Canonical(jsonv.FromGo(toModel(data)))))
}

// sseRaw writes one server-sent event whose data is one line of text (a
// JWE in sealed namespaces, Addendum E.2).
func sseRaw(w http.ResponseWriter, event, id, data string) {
	fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", event, id, data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// sseEntry writes entry i of lg: its JWE in a sealed namespace.
func sseEntry(w http.ResponseWriter, event string, lg *core.Log, i int) {
	e := lg.Entries[i]
	if lg.Sealed {
		sseRaw(w, event, e["id"].(string), lg.EntryJWEs[i])
		return
	}
	sse(w, event, e["id"].(string), e)
}

// sseLogErr answers an event stream request whose replay failed (404, 410
// or 410 pruned). Like every SSE response it is no-store (§9).
func sseLogErr(w http.ResponseWriter, lg *core.Log) {
	noStore(w)
	switch {
	case lg.Status == 404:
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case lg.Horizon != "":
		writeJSON(w, 410, prunedBody(lg.Horizon, lg.Archive))
	default:
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}

func startSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) nsEvents(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	since := sinceParam(r)
	cred := creds(r)
	// Catching up reads a log page at a time (§7.1 Paging), so a stream
	// from far back costs the server a page per fetch, not the whole
	// history (for a sealed namespace, a JWE per entry) at once.
	page := s.e.Limits().LogPageSize
	// Wait before every fetch, so no entry committed in between is missed.
	wait := s.e.Wait(ns)
	lg, err := s.e.NamespaceEvents(r.Context(), ns, since, page, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	if lg.Status != 200 {
		sseLogErr(w, lg)
		return
	}
	startSSE(w)
	for {
		for i, e := range lg.Entries {
			sseEntry(w, e["kind"].(string), lg, i)
			since = e["id"].(string)
		}
		if !lg.More {
			select {
			case <-wait:
			case <-time.After(30 * time.Second):
				fmt.Fprint(w, ": keep-alive\n\n")
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			case <-lifecycle.Stopping(r.Context()):
				// The server is shutting down: end the stream; EventSource
				// reconnects with Last-Event-ID (elsewhere).
				return
			case <-r.Context().Done():
				return
			}
		} else if r.Context().Err() != nil {
			return
		}
		wait = s.e.Wait(ns)
		lg, err = s.e.NamespaceEvents(r.Context(), ns, since, page, cred)
		if err != nil || lg.Status != 200 {
			return
		}
	}
}

func (s *Server) resourceEvents(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	cred := creds(r)
	since := sinceParam(r)
	// Wait before every fetch, so no entry committed in between is missed.
	wait := s.e.Wait(ns)
	// Catching up reads a log page at a time (§7.1 Paging), as nsEvents.
	page := s.e.Limits().LogPageSize
	// The namespace log is followed for this resource's purges and prunes
	// from its current head, with read on the resource alone (§C.5).
	head, err := s.e.ResourceEvents(r.Context(), ns, name, "", page, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	nsSince := head.Last
	lg, err := s.e.ResourceLog(r.Context(), ns, name, "", since, page, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	if lg.Status != 200 {
		sseLogErr(w, lg)
		return
	}
	startSSE(w)
	emit := func(lg *core.Log) {
		for i, e := range lg.Entries {
			ev := "revision"
			if e["kind"] == "tombstone" {
				ev = "tombstone"
			}
			sseEntry(w, ev, lg, i)
			since = e["id"].(string)
		}
	}
	// nsEntries emits this resource's purge and prune entries after
	// nsSince, a page per fetch; ok is false when a read failed, done
	// is true after a purge, which ends the stream.
	nsEntries := func() (ok, done bool) {
		for {
			nl, err := s.e.ResourceEvents(r.Context(), ns, name, nsSince, page, cred)
			if err != nil || nl.Status != 200 {
				return false, false
			}
			nsSince = nl.Last
			for i, e := range nl.Entries {
				switch e["kind"] {
				case "purge":
					sseEntry(w, "purge", nl, i)
					return true, true
				case "prune":
					sseEntry(w, "prune", nl, i)
				}
			}
			if !nl.More || r.Context().Err() != nil {
				return true, false
			}
		}
	}
	emit(lg)
	// The rest of the catch-up, a page per fetch. A read failing in
	// between (a purge, or a prune past since) ends the stream as it does
	// below.
	for lg.More && r.Context().Err() == nil {
		if lg, err = s.e.ResourceLog(r.Context(), ns, name, "", since, page, cred); err != nil || lg.Status != 200 {
			nsEntries()
			return
		}
		emit(lg)
	}
	for {
		select {
		case <-wait:
		case <-time.After(30 * time.Second):
			fmt.Fprint(w, ": keep-alive\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			continue
		case <-lifecycle.Stopping(r.Context()):
			// The server is shutting down: end the stream; EventSource
			// reconnects with Last-Event-ID (elsewhere).
			return
		case <-r.Context().Done():
			return
		}
		wait = s.e.Wait(ns)
		if ok, done := nsEntries(); !ok || done {
			return
		}
		for {
			lg, err := s.e.ResourceLog(r.Context(), ns, name, "", since, page, cred)
			if err != nil || lg.Status != 200 {
				// A purge that committed after the namespace read above:
				// send its event before ending the stream.
				nsEntries()
				return
			}
			emit(lg)
			if !lg.More || r.Context().Err() != nil {
				break
			}
		}
	}
}
