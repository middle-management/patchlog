package dav

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type v86RT func(*http.Request) (*http.Response, error)

func (f v86RT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func v86Req(t *testing.T, st *reqState, method, url, body string) *http.Request {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequestWithContext(context.WithValue(context.Background(), stateKey{}, st), method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// §H.4 "Answers" (v0.86): once a read made for the request has failed
// for now, the request is answered with that failure, so its first write
// isn't sent: it would be made and then answered "try again". A write
// that failed blocks nothing (its own retry, or what puts things back),
// and once the request has written, what follows is sent.
func TestV086NoWriteAfterFailedRead(t *testing.T) {
	t.Parallel()
	const core = "http://core.example"
	answer := func(status int) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
	}
	type step struct {
		method, path string
		status       int  // what the core answers, if asked
		sent         bool // whether it is asked
	}
	for _, c := range []struct {
		what  string
		steps []step
	}{
		{"a write after a failed read isn't sent", []step{{"GET", "/ns/other", 500, true}, {"PATCH", "/r/docs/x", 200, false}, {"DELETE", "/r/docs/x", 200, false}}},
		{"nor after a read that got no answer in time", []step{{"GET", "/ns/other", 0, true}, {"PATCH", "/r/docs/x", 200, false}}},
		{"a read answered 404 blocks nothing", []step{{"GET", "/ns/other", 404, true}, {"PATCH", "/r/docs/x", 200, true}}},
		{"a failed read asked again and answered blocks nothing", []step{{"GET", "/ns/other", 429, true}, {"GET", "/ns/other", 200, true}, {"PATCH", "/r/docs/x", 200, true}}},
		{"a failed write blocks neither its retry nor another write", []step{{"PATCH", "/r/docs/x", 500, true}, {"PATCH", "/r/docs/x", 200, true}, {"POST", "/r/docs/y", 200, true}}},
		{"once the request has written, a failed read stops no later write", []step{{"PATCH", "/r/docs/x", 200, true}, {"GET", "/ns/other", 500, true}, {"PATCH", "/r/cat/node", 200, true}}},
	} {
		t.Run(c.what, func(t *testing.T) {
			st := &reqState{method: "PUT"}
			var next step
			asked := false
			g := writeGuard{v86RT(func(r *http.Request) (*http.Response, error) {
				asked = true
				if next.status == 0 {
					return nil, context.DeadlineExceeded
				}
				return answer(next.status), nil
			})}
			for i, s := range c.steps {
				next, asked = s, false
				body := ""
				if s.method != "GET" {
					body = `{"n":1}`
				}
				res, err := g.RoundTrip(v86Req(t, st, s.method, core+s.path, body))
				if asked != s.sent {
					t.Fatalf("step %d, %s %s: sent %v, want %v", i, s.method, s.path, asked, s.sent)
				}
				if !s.sent {
					var de *davError
					if res != nil || !errors.As(err, &de) || de.status != 502 && de.status != 503 || !strings.HasPrefix(de.msg, theCore) {
						t.Fatalf("step %d, %s %s: %v %v, want the failed read's 502 or 503", i, s.method, s.path, res, err)
					}
				}
			}
		})
	}
	// A request with no user's request behind it is sent as it is.
	asked := false
	g := writeGuard{v86RT(func(r *http.Request) (*http.Response, error) { asked = true; return answer(200), nil })}
	r, _ := http.NewRequest("PATCH", core+"/r/docs/x", strings.NewReader("{}"))
	if _, err := g.RoundTrip(r); err != nil || !asked {
		t.Fatalf("a write outside a user's request: %v, sent %v", err, asked)
	}
}

// A failure is cleared by the same request made again and answered, and
// by no other: a POST to the same URL with another body (another item's
// grant) is another request, and leaves the first one's failure the
// answer (§H.4 "Answers", v0.86).
func TestV086FailureClearedBySameRequestOnly(t *testing.T) {
	t.Parallel()
	const u = "http://core.example/ns/docs/batch"
	const what = "the core"
	res := func(status int) *http.Response { return &http.Response{StatusCode: status, Header: http.Header{}} }
	st := &reqState{method: "GET"}
	st.sawUpstream(what, v86Req(t, st, "POST", u, `{"item":"a"}`), res(503), nil)
	if e := st.upFailure(); e == nil || e.status != 503 {
		t.Fatalf("after a POST answered 503: %v", e)
	}
	st.sawUpstream(what, v86Req(t, st, "POST", u, `{"item":"b"}`), res(200), nil)
	if e := st.upFailure(); e == nil || e.status != 503 {
		t.Fatalf("a POST of another body, answered, cleared the first one's failure: %v", e)
	}
	if st.readFailure() != nil {
		t.Fatal("a failed POST counts as a failed read")
	}
	st.sawUpstream(what, v86Req(t, st, "POST", u, `{"item":"a"}`), res(200), nil)
	if e := st.upFailure(); e != nil {
		t.Fatalf("the same POST made again and answered left its failure: %v", e)
	}
	// A body that can't be read again: nothing clears its failure.
	r := v86Req(t, st, "POST", u, "")
	r.Body, r.GetBody = io.NopCloser(strings.NewReader("x")), nil
	st.sawUpstream(what, r, res(500), nil)
	r2 := v86Req(t, st, "POST", u, "")
	r2.Body, r2.GetBody = io.NopCloser(strings.NewReader("x")), nil
	st.sawUpstream(what, r2, res(200), nil)
	if e := st.upFailure(); e == nil || e.status != 502 {
		t.Fatalf("a POST whose body can't be compared: %v, want its 502 kept", e)
	}
	// A GET is the same request by its URL.
	st = &reqState{method: "GET"}
	st.sawUpstream(theCore, v86Req(t, st, "GET", "http://core.example/ns/a", ""), res(429), nil)
	st.sawUpstream(theCore, v86Req(t, st, "GET", "http://core.example/ns/b", ""), res(200), nil)
	if st.readFailure() == nil {
		t.Fatal("another GET cleared a GET's failure")
	}
	st.sawUpstream(theCore, v86Req(t, st, "GET", "http://core.example/ns/a", ""), res(200), nil)
	if st.upFailure() != nil {
		t.Fatal("the GET made again and answered left its failure")
	}
}
