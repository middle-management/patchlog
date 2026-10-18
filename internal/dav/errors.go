package dav

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"strconv"
	"strings"

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

// upstream maps an error of the core (§12) to what the WebDAV client gets:
// 401, 403 and 404 pass through, 409 frozen is 403 (a frozen namespace
// takes no writes, §8.4, for good: clients retry a 423, as a lock that
// may go), 413 stays, the other 422s keep their errors, 429 is 503 with
// Retry-After, and anything else the core failed with is 502. A failure
// to reach the core is 502 too, its details (the core's address) only
// logged. Writes map 412, 410 and patch failures themselves. The text is
// the core's code and message: the status is the answer's own, and the
// core's is named only where it differs.
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
		return fail(http.StatusNotImplemented, "the content is sealed (Addendum E); sealed and end-to-end namespaces aren't served over WebDAV")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &davError{status: http.StatusServiceUnavailable, msg: "the request was canceled or timed out", cause: err}
	}
	ae, ok := client.AsAPIError(err)
	if !ok {
		return &davError{status: http.StatusBadGateway, msg: "the core can't be reached", cause: err}
	}
	msg := apiText(ae)
	switch {
	case ae.Status == 400, ae.Status == 401, ae.Status == 403, ae.Status == 404, ae.Status == 413:
		return fail(ae.Status, "%s", msg)
	case ae.Status == 409 && ae.Code == "frozen":
		e := fail(http.StatusForbidden, "%s: the namespace takes no writes (§8.4)", msg)
		if s := ae.Successor(); s != "" {
			e.msg += "; its successor is " + s
		}
		return e
	case ae.Status == 409:
		return fail(http.StatusConflict, "%s", msg)
	case ae.Status == 410:
		return fail(http.StatusConflict, "the core answered 410: %s", msg)
	case ae.Status == 422:
		return fail(http.StatusUnprocessableEntity, "%s", msg)
	case ae.Status == 429:
		return busy(ae)
	}
	return fail(http.StatusBadGateway, "the core answered %d: %s", ae.Status, msg)
}

// busy is the 503 a 429 turns into once waiting is no longer brief (§6.6).
func busy(ae *client.APIError) *davError {
	e := fail(http.StatusServiceUnavailable, "the core answered 429: %s", apiText(ae))
	secs := int(math.Ceil(ae.RetryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	e.header = http.Header{"Retry-After": {strconv.Itoa(secs)}}
	return e
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
// davError: that one is answered instead, with its text.
type errWriter struct {
	http.ResponseWriter
	st      *reqState
	realm   string
	wrote   bool
	swallow bool
}

func (w *errWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	e := w.st.err
	if code == http.StatusOK || code == http.StatusPartialContent {
		w.st.served()
	}
	if w.st.noETag {
		w.Header().Del("ETag")
	}
	if code < 400 || e == nil {
		if code == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", w.realm)
		}
		w.ResponseWriter.WriteHeader(code)
		return
	}
	h := w.Header()
	for _, k := range []string{"ETag", "Last-Modified", "Content-Length", "Lock-Token"} {
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

func (w *errWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.swallow {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
