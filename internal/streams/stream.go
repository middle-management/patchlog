package streams

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// stream is one upstream response being written (J.2). Its run goroutine
// alone appends to the resource and owns head; the upstream pump and the
// log follower only send to it.
type stream struct {
	p       *Proxy
	id      string // the first resource's name: the stream's id
	seg     int    // which segment is being written
	name    string // its resource name
	head    string // the proxy's last revision of it
	size    int    // the segment's document, in canonical bytes, more or less
	created time.Time
	method  string

	status    int
	ctype     string
	metaKnown bool // upstream answered: status and contentType are known
	metaSent  bool // and recorded

	// next is the continuation created ahead of the append that names it.
	next, nextHead string
	nextSize       int
	nextCreated    time.Time

	abortSig     chan struct{} // the follower saw an abort
	followCancel context.CancelFunc
}

// event is what the upstream pump sends: the response's head first, then
// chunks.
type event struct {
	meta   bool
	status int
	ctype  string
	chunks []string
}

type piece struct {
	s   string
	enc int // its length as a JSON string
}

type outcome int

const (
	ok            outcome = iota
	rateLimited           // 429: nothing landed; try again after the wait
	aborted               // a caller's abort is in the log (J.4)
	foreignClosed         // someone else set closed: stop, append nothing
	gone                  // the resource was deleted or purged
	full                  // the core says the document would pass documentSize
	failed
)

// upstreamError is closed.error for an upstream call that failed. It says
// what kind of failure, never the error's text: Go's errors name the URL
// and host, which the document must not hold (J.1).
func upstreamError(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "the upstream request timed out"
	case errors.Is(err, errNotUTF8):
		return errNotUTF8.Error()
	}
	return "the upstream request failed"
}

// pump calls upstream and sends its response to ch, which it closes after
// setting *end to how the stream closes.
func (s *stream) pump(ctx context.Context, url string, hdr http.Header, body []byte, ch chan<- event, end *Closed) {
	defer close(ch)
	req, err := http.NewRequestWithContext(ctx, s.method, url, bytes.NewReader(body))
	if err != nil {
		*end = Closed{Reason: ReasonError, Error: "the upstream request could not be made"}
		return
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := s.p.opt.HTTPClient.Do(req)
	if err != nil {
		*end = Closed{Reason: ReasonError, Error: upstreamError(err)}
		return
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if len(ct) > 256 {
		ct = ct[:256]
	}
	select {
	case ch <- event{meta: true, status: resp.StatusCode, ctype: ct}:
	case <-ctx.Done():
		*end = Closed{Reason: ReasonError, Error: "the upstream request was cancelled"}
		return
	}
	if !textType(ct) {
		*end = Closed{Reason: ReasonError, Error: "the upstream body is not text, which a stream can't keep"}
		return
	}
	sp := newSplitter(resp.Body, s.p.maxChunk, s.p.maxEnc)
	for {
		chunks, err := sp.next()
		if len(chunks) > 0 {
			select {
			case ch <- event{chunks: chunks}:
			case <-ctx.Done():
				*end = Closed{Reason: ReasonError, Error: "the upstream request was cancelled"}
				return
			}
		}
		switch {
		case err == nil:
			continue
		case errors.Is(err, errNotUTF8):
			*end = Closed{Reason: ReasonError, Error: errNotUTF8.Error()}
		case errors.Is(err, io.EOF):
			*end = Closed{Reason: ReasonComplete}
		case errors.Is(err, context.DeadlineExceeded):
			*end = Closed{Reason: ReasonError, Error: "the upstream request timed out"}
		default:
			*end = Closed{Reason: ReasonError, Error: "the upstream response ended early"}
		}
		return
	}
}

// run carries the stream to its end: it calls upstream, appends what
// arrives at most every Flush, and closes the stream.
func (s *stream) run(url string, hdr http.Header, body []byte) {
	p := s.p
	upCtx, cancelUp := context.WithCancel(context.Background())
	defer cancelUp()
	ch := make(chan event, 8)
	var end Closed
	go s.pump(upCtx, url, hdr, body, ch, &end)
	s.startFollow()
	defer func() {
		s.followCancel()
		p.finish(s)
	}()

	// pending is what upstream sent and no append has carried yet, queued
	// bytes long as JSON. At maxPending the pump is no longer read from, so
	// upstream is held back (its channel and the connection fill) until a
	// flush makes room; aborts, the timers and shutdown are still served.
	var pending []piece
	queued := 0
	ended, forceFull := false, false
	var lastFlush, notBefore time.Time
	idle := time.NewTimer(p.opt.IdleTimeout)
	defer idle.Stop()
	events := ch
	for {
		var timer <-chan time.Time
		if (s.metaKnown && !s.metaSent) || len(pending) > 0 || ended {
			due := lastFlush.Add(p.opt.Flush)
			if notBefore.After(due) {
				due = notBefore
			}
			if wait := time.Until(due); wait > 0 {
				timer = time.After(wait)
			} else {
				var closing *Closed
				if ended {
					closing = &end
				}
				n, done, out, wait := s.flush(pending, closing, forceFull, cancelUp)
				switch out {
				case ok:
					for _, pc := range pending[:n] {
						queued -= pc.enc
					}
					pending, forceFull = pending[n:], false
					if len(pending) == 0 {
						pending = nil // let go of the flushed chunks' array
					}
					lastFlush = time.Now()
					if !idle.Stop() {
						select {
						case <-idle.C:
						default:
						}
					}
					idle.Reset(p.opt.IdleTimeout)
					if done {
						return
					}
				case rateLimited:
					notBefore = time.Now().Add(wait)
				case aborted:
					cancelUp()
					s.closeWith(&Closed{Reason: ReasonAborted})
					return
				case full:
					if forceFull {
						p.opt.Logf("streams: %s: the core refuses even the closing append for size; leaving it to the idle sweep", s.name)
						cancelUp()
						return
					}
					forceFull = true
				case foreignClosed, gone:
					cancelUp()
					return
				default:
					cancelUp()
					s.closeWith(&Closed{Reason: ReasonError, Error: "the proxy could not append to the stream"})
					return
				}
				continue
			}
		}
		recv := events
		if queued >= p.maxPending {
			recv = nil
		}
		select {
		case ev, more := <-recv:
			if !more {
				ended, events = true, nil
				continue
			}
			if ev.meta {
				s.status, s.ctype, s.metaKnown = ev.status, ev.ctype, true
			}
			for _, c := range ev.chunks {
				pc := piece{c, len(jsonv.Canonical(c))}
				pending = append(pending, pc)
				queued += pc.enc
			}
		case <-timer:
		case <-s.abortSig:
			// The follower saw an abort between chunks (J.4): read the
			// entries, as after a 412.
			switch ab, cl, err := s.catchUp(); {
			case err != nil && (client.IsGone(err) || client.IsNotFound(err)), cl:
				cancelUp()
				return
			case ab:
				cancelUp()
				s.closeWith(&Closed{Reason: ReasonAborted})
				return
			}
		case <-idle.C:
			cancelUp()
			s.closeWith(&Closed{Reason: ReasonTimeout, Error: "upstream sent nothing for " + p.opt.IdleTimeout.String()})
			return
		case <-p.ctx.Done():
			cancelUp()
			s.closeWith(&Closed{Reason: ReasonError, Error: "the proxy shut down"})
			return
		}
	}
}

// flush appends one patch set (J.2 step 3): status and contentType if not
// yet recorded, the pending chunks that fit, and closed if this ends the
// segment: with closing once everything pending fits, or with "size" and
// next when the document is about to pass documentSize (J.1). It returns
// how many chunks landed and whether the stream is done.
func (s *stream) flush(pending []piece, closing *Closed, forceFull bool, cancelUp func()) (n int, done bool, out outcome, wait time.Duration) {
	p := s.p
	var ops []any
	metaSize := 0
	if s.metaKnown && !s.metaSent {
		ops = append(ops,
			map[string]any{"op": "add", "path": "/upstream/status", "value": float64(s.status)},
			map[string]any{"op": "add", "path": "/upstream/contentType", "value": s.ctype})
		metaSize = 40 + len(jsonv.Canonical(s.ctype))
	}
	docLeft := p.docSize - reserve - s.size - metaSize
	setLeft := p.setSize - 1024
	docFull := forceFull
	for !docFull && n < len(pending) && len(ops) < p.opsPerSet-4 {
		enc := pending[n].enc
		if enc+1 > docLeft {
			docFull = true
			break
		}
		if enc+64 > setLeft {
			break
		}
		ops = append(ops, map[string]any{"op": "add", "path": "/chunks/-", "value": pending[n].s})
		docLeft -= enc + 1
		setLeft -= enc + 64
		n++
	}
	grew := p.docSize - reserve - s.size - docLeft
	var closed *Closed
	switch {
	case docFull && s.seg+1 >= p.opt.MaxSegments:
		// Out of segments: the response is cut here.
		cancelUp()
		closed = &Closed{Reason: ReasonSize, Error: "the stream filled the proxy's most resources for one response"}
		done = true
	case docFull:
		if s.next == "" {
			if !s.createNext() {
				cancelUp()
				closed = &Closed{Reason: ReasonError, Error: "the proxy could not create the stream's continuation"}
				done = true
				break
			}
		}
		closed = &Closed{Reason: ReasonSize, Next: s.next}
	case closing != nil && n == len(pending):
		closed, done = closing, true
	}
	if closed != nil {
		if len(closed.Error) > maxError {
			closed.Error = closed.Error[:maxError]
		}
		ops = append(ops, map[string]any{"op": "add", "path": "/closed", "value": closed.value()})
	}
	if len(ops) == 0 {
		return 0, false, ok, 0
	}
	out, wait = s.append(ops)
	if out != ok {
		if out != rateLimited && out != full && s.next != "" {
			// The continuation was created for nothing: don't leave it open.
			why := &Closed{Reason: ReasonError, Error: "the stream ended before it continued here"}
			if out == aborted {
				why = &Closed{Reason: ReasonAborted}
			}
			p.abandonWith(s.next, s.nextHead, why)
			s.next = ""
		}
		return 0, false, out, wait
	}
	s.size += grew
	s.metaSent = s.metaSent || s.metaKnown
	if closed != nil && closed.Next != "" {
		s.switchSegment()
	}
	return n, done, ok, 0
}

// createNext creates the resource the stream continues in: the same
// shape, with what is known of upstream, and no chunks yet.
func (s *stream) createNext() bool {
	p := s.p
	name := SegmentName(s.id, s.seg+1)
	up := map[string]any{"method": s.method}
	if s.metaKnown {
		up["status"], up["contentType"] = float64(s.status), s.ctype
	}
	gen := map[string]any{"upstream": up, "chunks": []any{}}
	if p.nonce {
		gen["$nonce"] = seal.NewNonce()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := p.create(ctx, name, gen)
	if err != nil || res.Status != 201 {
		// A 200 or 412 is a resource that was there already: not ours to
		// write.
		p.opt.Logf("streams: creating the continuation %s: status %v, %v", name, res, err)
		return false
	}
	s.next, s.nextHead = name, res.ID
	s.nextSize = len(jsonv.Canonical(jsonv.FromGo(gen)))
	s.nextCreated = entryTime(res.Entry, p.opt.Now())
	return true
}

// switchSegment moves the writer to the continuation the last append
// named.
func (s *stream) switchSegment() {
	p := s.p
	s.followCancel()
	old, oldHead, oldCreated := s.name, s.head, s.created
	s.seg++
	s.name, s.head, s.size, s.created = s.next, s.nextHead, s.nextSize, s.nextCreated
	s.next = ""
	p.mu.Lock()
	delete(p.open, old)
	p.open[s.name] = s
	p.known[old] = known{target: oldHead, closed: true, created: oldCreated}
	p.saveStateLocked()
	p.mu.Unlock()
	s.startFollow()
}

// append sends one patch set on the proxy's last revision (If-Match), with
// a fresh $nonce where the namespace requires them. A failure that leaves
// the outcome unknown is retried with the same bytes, which the core
// answers with the entry if it had landed (§7.2). A 412 is never answered
// by resending: the new entries are read first (J.4).
func (s *stream) append(ops []any) (outcome, time.Duration) {
	p := s.p
	for stale := 0; ; stale++ {
		set := ops
		if p.nonce {
			set = append(append([]any{}, ops...), map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
		}
		var err error
		for attempt := 0; ; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			var res *client.WriteResult
			res, err = p.c.Append(ctx, p.opt.NS, s.name, s.head, set)
			cancel()
			if err == nil {
				s.head = res.ID
				return ok, 0
			}
			if ae, isAPI := client.AsAPIError(err); isAPI && ae.Status == 429 {
				return rateLimited, min(max(ae.RetryAfter, 20*time.Millisecond), 30*time.Second)
			}
			if !client.Transient(err) || attempt >= 4 {
				break
			}
			time.Sleep(100 * time.Millisecond << attempt)
		}
		ae, _ := client.AsAPIError(err)
		switch {
		case client.IsStale(err) && stale < 16:
			ab, cl, err := s.catchUp()
			switch {
			case err != nil && (client.IsGone(err) || client.IsNotFound(err)):
				return gone, 0
			case err != nil:
				p.opt.Logf("streams: %s: reading the log after a 412: %v", s.name, err)
				return failed, 0
			case cl:
				return foreignClosed, 0
			case ab:
				return aborted, 0
			}
			// Something else moved the head: carry on from it.
		case client.IsGone(err), client.IsNotFound(err):
			return gone, 0
		case ae != nil && ae.Code == "limit" && ae.Body["limit"] == "documentSize":
			return full, 0
		default:
			p.opt.Logf("streams: %s: append: %v", s.name, err)
			return failed, 0
		}
	}
}

// catchUp reads the entries after the proxy's last revision and moves head
// to the newest: whether one of them asks for an abort, or sets closed.
func (s *stream) catchUp() (abort, closed bool, err error) {
	p := s.p
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := p.c.Head(ctx, p.opt.NS, s.name)
	if err != nil {
		return false, false, err
	}
	if h.State != client.Live {
		return false, false, &client.APIError{Status: 410, Code: "gone", Method: "GET", Path: "/r/" + p.opt.NS + "/" + s.name}
	}
	if h.ID == s.head {
		return false, false, nil
	}
	es, err := p.c.Log(ctx, p.opt.NS, s.name, h.ID, s.head)
	if err != nil {
		return false, false, err
	}
	for _, e := range es {
		d := readPatches(e.Patches)
		if d.abort {
			abort = true
		}
		if d.closed != nil {
			closed = true
		}
		s.size += len(jsonv.Canonical(e.Patches))
	}
	s.head = h.ID
	return abort, closed, nil
}

// closeWith ends the stream with a last append that sets closed (J.2 step
// 4), dropping what was pending.
func (s *stream) closeWith(c *Closed) {
	p := s.p
	if len(c.Error) > maxError {
		c.Error = c.Error[:maxError]
	}
	ops := []any{map[string]any{"op": "add", "path": "/closed", "value": c.value()}}
	if s.metaKnown && !s.metaSent {
		ops = append([]any{
			map[string]any{"op": "add", "path": "/upstream/status", "value": float64(s.status)},
			map[string]any{"op": "add", "path": "/upstream/contentType", "value": s.ctype}}, ops...)
	}
	for try := 0; try < 20; try++ {
		out, wait := s.append(ops)
		switch out {
		case rateLimited:
			time.Sleep(wait)
		case aborted:
			// An abort while closing: the close still stands, on the new
			// head.
		case ok, foreignClosed, gone:
			return
		default:
			p.opt.Logf("streams: %s could not be closed (%s); the idle sweep will", s.name, c.Reason)
			return
		}
	}
}

// startFollow follows the segment's log from the proxy's last revision
// (J.4): an abort appended between two chunks is seen without waiting for
// the next append's 412.
func (s *stream) startFollow() {
	p := s.p
	ctx, cancel := context.WithCancel(p.ctx)
	s.followCancel = cancel
	name, since := s.name, s.head
	go func() {
		cursor := ""
		for ctx.Err() == nil {
			lp, err := p.c.ResourceLongPoll(ctx, p.opt.NS, name, since, cursor)
			switch {
			case err == nil:
			case ctx.Err() != nil, client.IsGone(err):
				return
			case client.IsBadInput(err):
				cursor = ""
				continue
			default:
				select {
				case <-ctx.Done():
					return
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}
			since, cursor = lp.Since, lp.Cursor
			for _, e := range lp.Entries {
				d := readPatches(e.Patches)
				if d.abort {
					select {
					case s.abortSig <- struct{}{}:
					default:
					}
				}
				if d.closed != nil {
					return
				}
			}
		}
	}()
}

// finish forgets a stream whose writer ended.
func (p *Proxy) finish(s *stream) {
	p.mu.Lock()
	if p.open[s.name] == s {
		delete(p.open, s.name)
	}
	p.saveStateLocked()
	p.mu.Unlock()
}

// abandonWith closes a resource the proxy created and won't write.
func (p *Proxy) abandonWith(name, head string, c *Closed) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := p.c.Append(ctx, p.opt.NS, name, head, p.closeOps(c)); err != nil {
		p.opt.Logf("streams: closing %s: %v", name, err)
	}
}
