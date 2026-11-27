package core

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

// Storage that can't be reached (§5, §12.1, v0.91).
//
// "Storage that can't be reached for now answers 503 (unavailable)", with
// Retry-After and Cache-Control: no-store: never the 404 of an id that
// isn't there, nor a page that ends elsewhere than the same URL's did
// (§7.1 Paging, CONFORMANCE scenario 111). The reference keeps everything
// in its database (and blob files beside it), so what it can fail to
// reach is the database itself: a connection that can't be opened or is
// lost (a Postgres server restarting, a network partition). Such a
// failure, from opening a transaction to any statement in it (t.must
// panics with it), is answered unavailable instead of the 500 of an
// internal error. A storage tier the core may add (history in object
// storage) answers it by returning an *UnavailableError.

// UnavailableError is a failure to reach storage an answer needs, for now:
// answered 503 unavailable (§12.1).
type UnavailableError struct {
	Cause error
}

func (e *UnavailableError) Error() string {
	if e.Cause == nil {
		return "storage unavailable"
	}
	return "storage unavailable: " + e.Cause.Error()
}

func (e *UnavailableError) Unwrap() error { return e.Cause }

// unavailableRetry is the Retry-After of an unavailable answer.
const unavailableRetry = 5 * time.Second

// unavailable is the 503 of §12.1 for storage that can't be reached:
// Retry-After set, and Cache-Control no-store (the server's default for
// an error, which no cache keeps).
func unavailable() *Error {
	e := apiErr(503, "unavailable", "message", "storage the answer needs can't be reached for now (§5, §12.1)")
	e.Header = http.Header{
		"Retry-After":   {strconv.Itoa(int(unavailableRetry / time.Second))},
		"Cache-Control": {"no-store"},
	}
	return e
}

// storageUnreachable reports whether err is a failure to reach storage:
// an *UnavailableError, or one of the database driver's connection
// failures. A request's own cancellation isn't one.
func storageUnreachable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ue *UnavailableError
	if errors.As(err, &ue) {
		return true
	}
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var ne *net.OpError
	return errors.As(err, &ne)
}

// asUnavailable is err, or the unavailable answer where err is a failure
// to reach storage (Engine.read, Engine.update).
func asUnavailable(err error) error {
	var ae *Error
	if err == nil || errors.As(err, &ae) || !storageUnreachable(err) {
		return err
	}
	return unavailable()
}

// testStorageFault, set by tests, fails every transaction the engine opens
// with the error it returns, as storage that can't be reached would.
var testStorageFault func() error
