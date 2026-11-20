package dav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"

	"github.com/middle-management/patchlog/internal/client"
)

// davError is a failure with the status and text the WebDAV client gets.
// x/net/webdav answers every FileSystem error with a status of its own
// (a failed Close of a PUT is 405), so errWriter swaps in the status and
// text of the last davError the request's FileSystem calls returned.
type davError struct {
	status int
	msg    string
	header http.Header
	cause  error // logged, not answered
	frozen bool  // the core's 409 frozen: the namespace takes no writes (§8.4)
	// refresh: the core refused a write over a writer's setting (frozen,
	// a nonce, a limit), which the token's copy of §7.4's writer block
	// may have had out of date (record)
	refresh bool
}

func (e *davError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%d %s: %v", e.status, e.msg, e.cause)
	}
	return fmt.Sprintf("%d %s", e.status, e.msg)
}

func fail(status int, format string, args ...any) *davError {
	return &davError{status: status, msg: fmt.Sprintf(format, args...)}
}

// overLimit is the 413 of a limit exceeded (§H.4 "Answers"): the limit's
// key, what was measured and the limit in force, then why, as in "too
// large: documentSize 1048577 > 1048576 (§6.6): document too large". The
// gateway's own bounds take this shape too, named by their flags
// (--max-file-size, --max-raw-size). Where reading stopped at the bound,
// measured is a lower bound, as in the core's refusals (§6.6).
func overLimit(key string, measured, max int64, format string, args ...any) *davError {
	e := fail(http.StatusRequestEntityTooLarge, "too large: %s %d > %d", key, measured, max)
	if format != "" {
		e.msg += " " + fmt.Sprintf(format, args...)
	}
	return e
}

// limitRefusal is the core's refusal for a limit (413, or 422 with code
// limit, §6.6, §12; a batch's first item so refused, §7.5) as the 413 of
// §H.4's answers, with the limit, the sizes the core gave and its
// message, then more (merged); nil for any other error. A limit without
// sizes (a duration, a rate) is named alone; a 413 without a limit (a
// core before §6.6 named them) keeps the core's text.
func limitRefusal(ae *client.APIError, more string) *davError {
	if ae.Status != http.StatusRequestEntityTooLarge && ae.Status != http.StatusUnprocessableEntity {
		return nil
	}
	key, measured, max, sizes, ok := ae.Limit()
	var e *davError
	switch {
	case ok && sizes:
		e = overLimit(key, measured, max, "(§6.6)")
	case ok:
		e = fail(http.StatusRequestEntityTooLarge, "over a limit: %s (§6.6)", key)
	case ae.Status == http.StatusRequestEntityTooLarge:
		e = fail(http.StatusRequestEntityTooLarge, "%s", apiText(ae))
	default:
		return nil
	}
	if ok {
		if m, _ := ae.Body["message"].(string); m != "" {
			e.msg += ": " + m
		}
	}
	e.msg += more
	e.refresh = true
	return e
}

// upstream maps an error of the core (§12) to what the WebDAV client gets
// (§H.4 "Answers"): 401, 403 and 404 pass through, a 302 to a filtered
// read (§B.11.9) is 403, 409 frozen is 403 naming the successor (a frozen
// namespace takes no writes, §8.4, for good: clients retry a 423, as a
// lock that may go), 410 purged stays (§8.5) and another 410 (deleted
// meanwhile, pruned) is a 409 asking for a reload, a limit refused (413,
// or 422 code limit) is 413 with the limit and sizes the core gave
// (limitRefusal, §6.6), and the other 422s keep their errors.
//
// A request that failed for now has one rule, for every method, reads and
// writes alike (§H.4 "Answers", v0.85; FILE-18): 503 with Retry-After
// after the core's 429 or 503, or where no answer came in time; else 502,
// after its 408, any other 5xx, and where there is no connection. A 502
// and a 503 name only the upstream that failed, the core here, and carry
// nothing of its answer (§H.4 "Answers", v0.86; §C.6 Upstream failures):
// not its text, not its status, and the 503's Retry-After is this
// server's own (upBusy). The answer is logged with the core's address
// (davError.cause, record). Writes map 412 and patch failures themselves.
// Elsewhere the text is the core's code and message: the status is the
// answer's own, and the core's is named only where it differs.
func upstream(err error) error {
	if err == nil {
		return nil
	}
	var de *davError
	if errors.As(err, &de) {
		return de
	}
	for _, fe := range []error{fs.ErrNotExist, fs.ErrExist, fs.ErrPermission} {
		if errors.Is(err, fe) {
			return fe
		}
	}
	if errors.Is(err, client.ErrNoKeys) {
		return fail(http.StatusNotFound, "the content is sealed (Addendum E), and this server holds no keys, so it doesn't offer it (§H.7)")
	}
	var ne net.Error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		// 503 with Retry-After, like a 429 or 408 waited out (§H.4 Answers).
		msg := theCore + " didn't answer in time"
		if errors.Is(err, context.Canceled) {
			msg = "the request was canceled"
		}
		return &davError{status: http.StatusServiceUnavailable, msg: msg, cause: err, header: http.Header{"Retry-After": {retryLate}}}
	}
	ae, ok := client.AsAPIError(err)
	if !ok {
		return &davError{status: http.StatusBadGateway, msg: theCore + " can't be reached", cause: err}
	}
	if e := limitRefusal(ae, ""); e != nil {
		return e
	}
	msg := apiText(ae)
	switch {
	case ae.Status == 400, ae.Status == 401, ae.Status == 403, ae.Status == 404:
		return fail(ae.Status, "%s", msg)
	case ae.Status == 302:
		// A partial reader's unfiltered namespace read, redirected to its
		// filtered form (§B.11.9 URLs), which isn't read here: the grant
		// doesn't read it unrestricted, as its 403 said before v0.75.
		return fail(http.StatusForbidden, "your grant reads this namespace only filtered (§B.11.9)")
	case ae.Status == 409 && ae.Code == "frozen":
		e := fail(http.StatusForbidden, "%s: the namespace takes no writes (§8.4)", msg)
		e.frozen, e.refresh = true, true
		if s := ae.Successor(); s != "" {
			e.msg += "; its successor is " + s
		}
		return e
	case ae.Status == 409:
		return fail(http.StatusConflict, "%s", msg)
	case ae.Status == 410 && ae.Code == "purged":
		return fail(http.StatusGone, "%s: the namespace was purged (§8.5)", msg)
	case ae.Status == 410:
		return fail(http.StatusConflict, "the core answered 410: %s; reload it", msg)
	case ae.Status == 422:
		e := fail(http.StatusUnprocessableEntity, "%s", msg)
		e.refresh = ae.Code == "nonce"
		return e
	case ae.Status == 429, ae.Status == http.StatusServiceUnavailable:
		return upBusy(theCore, err)
	}
	return upFailed(theCore, err)
}

// theCore names the core in a 502 or 503.
const theCore = "the core"

// The Retry-After of this server's 503s, its own (§H.4 "Answers", v0.86):
// never the upstream's, which would say how its limits stand.
const (
	retryBusy = "1" // an upstream that is busy or behind
	retryLate = "5" // one that didn't answer in time
)

// upBusy is the 503 for an upstream (what: the core, or another
// service) that answered 429 or 503: it names the upstream and nothing of
// its answer (cause, which is logged), with this server's Retry-After.
func upBusy(what string, cause error) *davError {
	return &davError{status: http.StatusServiceUnavailable, msg: what + " is busy or behind for now; try again", cause: cause,
		header: http.Header{"Retry-After": {retryBusy}}}
}

// upFailed is the 502 for an upstream that answered 408 or another 5xx,
// or something this server can't use: it names the upstream and nothing
// of its answer (cause, which is logged).
func upFailed(what string, cause error) *davError {
	return &davError{status: http.StatusBadGateway, msg: what + " failed", cause: cause}
}

// unreached is the answer for a request to a service (what names it) that
// got no response, by §H.4's rule (v0.85): 503 with Retry-After where no
// answer came in time, else, with no connection, 502. The failure, which
// names the service's address, is logged, not answered.
func unreached(what string, err error) *davError {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return &davError{status: http.StatusServiceUnavailable, msg: what + " didn't answer in time", cause: err,
			header: http.Header{"Retry-After": {retryLate}}}
	}
	return &davError{status: http.StatusBadGateway, msg: what + " can't be reached", cause: err}
}

// apiText is an API error as text: its code and message (or, with
// neither, its status), then each validation error (§12) on a line of its
// own. The status is left to the answer's.
func apiText(ae *client.APIError) string {
	var b strings.Builder
	b.WriteString(ae.Code)
	if m, _ := ae.Body["message"].(string); m != "" {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(m)
	}
	if b.Len() == 0 {
		fmt.Fprintf(&b, "%d %s", ae.Status, http.StatusText(ae.Status))
	}
	if p, _ := ae.Body["pointer"].(string); p != "" {
		b.WriteString(" (at " + p + ")")
	}
	for _, v := range ae.ValidationErrors() {
		p := v.Pointer
		if p == "" {
			p = "(root)"
		}
		b.WriteString("\n" + p + ": " + v.Message)
	}
	return b.String()
}

// isPatchFailure reports a 422 invalid from applying a patch set (§12):
// the server names the failing op's index. A merged edit that hits it no
// longer applies to the head.
func isPatchFailure(err error) bool {
	ae, ok := client.AsAPIError(err)
	if !ok || ae.Status != 422 || ae.Code != "invalid" {
		return false
	}
	_, ok = ae.Body["index"].(float64)
	return ok
}

// errWriter passes the WebDAV handler's answer through, except an error
// status after one of the request's FileSystem calls failed with a
// davError: that one is answered instead, with its text. And where a core
// or service request made for the user's request failed for now
// (reqState.upFailure), that failure is the answer, whatever the handler
// made of the rest: a 200, a 207, a 404 or a 403 (§H.4 "Answers", v0.86:
// "whether or not the answer needed it"; CONFORMANCE Grant scope 87).
//
// A 207 is held, with its body, until the handler returns (finish): a
// PROPFIND's multistatus begins before its entries are read, and a
// failure among them could no longer change the status.
type errWriter struct {
	http.ResponseWriter
	st      *reqState
	realm   string
	wrote   bool
	swallow bool
	held    int // a 207 not sent yet
	body    bytes.Buffer
}

func (w *errWriter) WriteHeader(code int) {
	if w.wrote || w.held != 0 {
		return
	}
	if code == http.StatusMultiStatus {
		w.held = code
		return
	}
	w.writeHeader(code)
}

// finish sends a held 207, or what answers in its place.
func (w *errWriter) finish() {
	if w.held == 0 || w.wrote {
		return
	}
	w.writeHeader(w.held)
	if !w.swallow {
		w.ResponseWriter.Write(w.body.Bytes())
	}
}

func (w *errWriter) writeHeader(code int) {
	w.wrote = true
	e := w.st.err
	if up := w.st.upFailure(); up != nil && (code < 400 || e == nil || e.status != http.StatusBadGateway && e.status != http.StatusServiceUnavailable) {
		w.st.s.opt.Logf("dav: %s %s: answered %d, not %d: %v", w.st.method, w.st.path, up.status, code, up)
		if code < 400 {
			// What the request did at the core, it did: a DELETE's or
			// MOVE's locks and properties follow the file (answered),
			// though the client is told to try again. A lock its LOCK
			// made is this server's own to take back: the client gets
			// no token for it.
			w.st.answered(code)
			w.st.dropNewLock()
		} else {
			w.st.answered(up.status)
		}
		w.fail(up)
		return
	}
	if code == http.StatusOK || code == http.StatusPartialContent && wholeRange(w.Header().Get("Content-Range")) {
		w.st.served()
	}
	if w.st.pdf && code != http.StatusOK && code != http.StatusPartialContent {
		// Only a PDF's 200 or 206 goes without the sandbox (servePDF).
		w.Header().Set("Content-Security-Policy", "sandbox")
		w.Header().Del("Content-Disposition")
	}
	if w.st.noETag {
		w.Header().Del("ETag")
	}
	if code < 400 || e == nil {
		if code == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", w.realm)
		}
		w.st.answered(code)
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.st.answered(e.status)
	w.fail(e)
}

// fail answers e in place of the handler's answer.
func (w *errWriter) fail(e *davError) {
	h := w.Header()
	if w.st.pdf {
		h.Set("Content-Security-Policy", "sandbox")
		h.Del("Content-Disposition")
	}
	for _, k := range []string{"ETag", "Last-Modified", "Content-Length", "Lock-Token", "Content-Range", "Accept-Ranges"} {
		h.Del(k)
	}
	w.st.serve = nil
	for k, v := range e.header {
		h[k] = v
	}
	if e.status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", w.realm)
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.ResponseWriter.WriteHeader(e.status)
	io.WriteString(w.ResponseWriter, e.msg+"\n")
	w.swallow = true
}

// wholeRange reports whether a 206's Content-Range is the whole file
// (bytes 0-{n-1}/{n}): only a revision served in full is recorded as a
// base (§H.4), not a range a mount or a type sniffer reads.
func wholeRange(cr string) bool {
	r, ok := strings.CutPrefix(cr, "bytes 0-")
	if !ok {
		return false
	}
	last, total, ok := strings.Cut(r, "/")
	l, err1 := strconv.ParseInt(last, 10, 64)
	n, err2 := strconv.ParseInt(total, 10, 64)
	return ok && err1 == nil && err2 == nil && l == n-1
}

func (w *errWriter) Write(b []byte) (int, error) {
	if w.held != 0 && !w.wrote {
		return w.body.Write(b)
	}
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.swallow {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// saveRead is the error of a read a save decides by (§H.4 "The base":
// the head, the base and the revisions between, their log, whose entries
// they are): one that failed for now (failedRead) fails the save, as
// upstream answers a request that failed for now for every method since
// v0.85 (§H.4 "Answers"): 503 with Retry-After after the core's 429 or
// 503 or no answer in time, else 502. Any other error is returned as it
// is.
func saveRead(err error) error {
	var de *davError
	if err == nil || errors.As(err, &de) || !failedRead(err) {
		return err
	}
	// The core's 503 and 408 are answered here, as before v0.85, when
	// they were a save's alone; the rest is left to upstream as it is,
	// for the callers that look at it first (failedRead).
	if ae, ok := client.AsAPIError(err); ok && (ae.Status == http.StatusServiceUnavailable || ae.Status == http.StatusRequestTimeout) {
		return upstream(err)
	}
	return err
}

// failedRead reports a read that failed for now (§H.4 "The base", "The
// reload", §H.6): no answer from the core (a transport error, a timeout),
// or its 408, 429 or 5xx, also where fetching keys wrapped it
// (client.ErrKeyFetch). Such a read fails the save (503 or 502, upstream)
// rather than being taken as a revision the gateway can't read, which is
// 409; anything else, a refusal (403) or no keys here (client.ErrNoKeys)
// among them, is no failed read.
func failedRead(err error) bool {
	if err == nil || errors.Is(err, client.ErrNoKeys) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if ae, ok := client.AsAPIError(err); ok {
		return ae.Status == http.StatusRequestTimeout || ae.Status == http.StatusTooManyRequests || ae.Status >= 500
	}
	var ue *url.Error
	var ne net.Error
	return errors.As(err, &ue) || errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}
