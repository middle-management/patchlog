package core

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// V77-01 (v0.77): 408 and 429 are transient (§A.4, §12.1), and a
// pre-raise sealing A doesn't serve B is pending with A's answer (§G.5.2
// E3 sources).

// §A.4 ("a schema or key fetch that fails transiently (transport error,
// 5xx, 408, 429) is retried"), §G.3 Creating one: a 408 or 429 from A,
// /keys included, is no answer (502 upstream at creation), never a
// refusal B can't read past (422). Before v0.77 both were refusals.
func TestV077EncNoAnswerTransient(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&client.APIError{Status: 408, Path: "/ns/m/keys"}, true},
		{&client.APIError{Status: 429, Path: "/ns/m/keys"}, true},
		{fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: 408, Path: "/ns/m/keys"}), true},
		{&client.APIError{Status: 503}, true},
		{&url.Error{Op: "POST", URL: "/ns/m/keys", Err: context.DeadlineExceeded}, true},
		{&client.APIError{Status: 403, Path: "/ns/m/keys"}, false},
		{&client.APIError{Status: 404}, false},
		{&client.APIError{Status: 410, Body: map[string]any{"code": "pruned"}}, false},
	} {
		if got := noAnswer(c.err); got != c.want {
			t.Errorf("noAnswer(%v) = %v, want %v", c.err, got, c.want)
		}
	}
	for _, st := range []int{408, 429} {
		if e := fetchErr("/ns/m/keys", &client.APIError{Status: st}); e.Status != 502 || e.Code() != "upstream" {
			t.Errorf("fetchErr of a %d: %v, want 502 upstream", st, e)
		}
	}
	if e := fetchErr("/ns/m/keys", &client.APIError{Status: 403}); e.Status != 422 {
		t.Errorf("fetchErr of a 403: %v, want 422", e)
	}
}

// §G.5.2 E3 sources: A's answers to a sealing B asks for, as recorded.
func TestV077EncPendingAnswer(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		st            int
		body          string
		err           error
		answer, horiz string
	}{
		{0, "", context.DeadlineExceeded, pendTransient, ""},
		{503, "", nil, pendTransient, ""},
		{408, "", nil, pendTransient, ""},
		{429, "", nil, pendTransient, ""},
		{403, `{"code":"forbidden"}`, nil, pendRefused, ""},
		{404, "", nil, pendRefused, ""},
		{410, `{"code":"gone"}`, nil, pendRefused, ""},
		{410, `{"code":"pruned","horizon":"1abc"}`, nil, pendPruned, "1abc"},
	} {
		a, h := pendingAnswer(c.st, []byte(c.body), c.err)
		if a != c.answer || h != c.horiz {
			t.Errorf("%d %s %v: %s %q, want %s %q", c.st, c.body, c.err, a, h, c.answer, c.horiz)
		}
	}
}
