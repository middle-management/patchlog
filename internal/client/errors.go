package client

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// APIError is a non-success answer of the API, with the §12 error body.
type APIError struct {
	Status     int            // HTTP status
	Code       string         // §12 code, e.g. "stale", "gone", "pruned"
	Body       map[string]any // the whole error body (may be nil)
	RetryAfter time.Duration  // from Retry-After (429), zero if absent
	Method     string
	Path       string
}

func (e *APIError) Error() string {
	msg := str(e.Body, "message")
	if msg == "" {
		// Validation errors (§12): errors: [{ "pointer", "message" }].
		var parts []string
		for _, x := range e.ValidationErrors() {
			p := x.Pointer
			if p == "" {
				p = "(root)"
			}
			parts = append(parts, p+": "+x.Message)
		}
		msg = strings.Join(parts, "; ")
	}
	s := fmt.Sprintf("patchlog: %s %s: %d", e.Method, e.Path, e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if msg != "" {
		s += ": " + msg
	}
	return s
}

// ValidationError is one entry of a 422 invalid's errors (§12): where the
// document fails, as a JSON Pointer, and why.
type ValidationError struct{ Pointer, Message string }

// ValidationErrors are the errors of a 422 invalid body: a document that
// fails its schema, or a namespace document that fails the
// namespace-document schema (§7.4).
func (e *APIError) ValidationErrors() []ValidationError {
	arr, _ := e.Body["errors"].([]any)
	var out []ValidationError
	for _, x := range arr {
		m, _ := x.(map[string]any)
		out = append(out, ValidationError{Pointer: str(m, "pointer"), Message: str(m, "message")})
	}
	return out
}

// Head is the current head named by a 412 stale body ({ head }).
func (e *APIError) Head() string { return str(e.Body, "head") }

// Config is the current config id named by a 412 on a config write.
func (e *APIError) Config() string { return str(e.Body, "config") }

// Horizon is the pruning horizon of a 410 pruned (§8.6).
func (e *APIError) Horizon() string { return str(e.Body, "horizon") }

// Successor is the successor namespace of a 409 frozen (§8.4).
func (e *APIError) Successor() string { return str(e.Body, "successor") }

// Referencing lists, for a 409 in_use refusing a purge or config write that
// would leave schema references without a copy (§6.1), the referencing
// namespaces the caller can read.
func (e *APIError) Referencing() []string { return strList(e.Body["referencing"]) }

// Dependents lists the dependents of a 409 in_use (§7.4, §8.5).
func (e *APIError) Dependents() []string { return strList(e.Body["dependents"]) }

// Items are the per-item failures of a batch error (§7.5).
func (e *APIError) Items() []map[string]any {
	a, _ := e.Body["items"].([]any)
	out := make([]map[string]any, 0, len(a))
	for _, x := range a {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func (r *response) apiError() *APIError {
	e := &APIError{Status: r.status, Body: r.obj(), Method: r.method, Path: r.path}
	e.Code = str(e.Body, "code")
	if ra := r.header.Get("Retry-After"); ra != "" {
		if n, err := strconv.Atoi(ra); err == nil && n >= 0 {
			e.RetryAfter = time.Duration(n) * time.Second
		} else if t, err := time.Parse(time.RFC1123, ra); err == nil {
			e.RetryAfter = time.Until(t)
		}
	}
	return e
}

// AsAPIError returns err as an *APIError, if it is one.
func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	ok := errors.As(err, &ae)
	return ae, ok
}

func statusIs(err error, status int, codes ...string) bool {
	ae, ok := AsAPIError(err)
	if !ok || ae.Status != status {
		return false
	}
	if len(codes) == 0 {
		return true
	}
	for _, c := range codes {
		if ae.Code == c {
			return true
		}
	}
	return false
}

// IsStale reports a failed precondition (412 stale).
func IsStale(err error) bool { return statusIs(err, 412) }

// IsGone reports a 410 for a tombstoned or purged resource or namespace
// (code "gone"). A 410 pruned is not "gone"; see IsPruned.
func IsGone(err error) bool {
	ae, ok := AsAPIError(err)
	return ok && ae.Status == 410 && ae.Code != "pruned"
}

// IsPruned reports a 410 pruned (§8.6): the revision or range lies below the
// horizon. Horizon(err) names it.
func IsPruned(err error) bool { return statusIs(err, 410, "pruned") }

// IsNotFound reports a 404 (unknown, or not readable by the caller, §7).
func IsNotFound(err error) bool { return statusIs(err, 404) }

// IsInUse reports a 409 in_use: a purge of the last copy of a referenced
// schema revision, a namespace with dependents, or a config write that
// would break either (§6.1, §7.4, §8.5).
func IsInUse(err error) bool { return statusIs(err, 409, "in_use") }

// IsFrozen reports a write to a frozen namespace (409 frozen, §8.4).
func IsFrozen(err error) bool { return statusIs(err, 409, "frozen") }

// IsRateLimited reports a 429; RetryAfter says how long to wait.
func IsRateLimited(err error) bool { return statusIs(err, 429) }

// IsAuth reports a 401 or 403.
func IsAuth(err error) bool { return statusIs(err, 401) || statusIs(err, 403) }

// Horizon returns the horizon of a 410 pruned error, or "".
func Horizon(err error) string {
	if ae, ok := AsAPIError(err); ok {
		return ae.Horizon()
	}
	return ""
}

// Retryable reports whether an error is worth retrying unchanged: transport
// errors, 408, 429 and 5xx. Other API errors are permanent.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	ae, ok := AsAPIError(err)
	if !ok {
		return true
	}
	return ae.Status == 408 || ae.Status == 429 || ae.Status >= 500
}
