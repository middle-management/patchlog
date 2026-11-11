package dav_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// Spec v0.82, the gateway (TOOLS §H.4 "The base", §H.6; BT-8): a failed
// read (408, 429, 5xx) of anything a save decides by, theirs and the
// user's own entries included, fails the save: 503 with Retry-After after
// the core's 429 or 503, else 502. Never 409, and never a save that takes
// someone else's entry for the user's own.

// v82Failed are the core's failures and what a save answers for each.
var v82Failed = []struct{ status, want int }{{408, 502}, {429, 503}, {500, 502}, {503, 503}}

// v82ExpectFailed checks a save's answer to a failed read.
func v82ExpectFailed(t *testing.T, e *env, r resp, want int, what string) {
	t.Helper()
	e.expect(r, want, what)
	if want == 503 && r.header.Get("Retry-After") == "" {
		t.Fatalf("%s: 503 without Retry-After", what)
	}
}

// BT-8, whose entry it is, with grants: alice's grant is verified under
// kid k. While k named another key, a grant of that key for the same sub
// wrote (or deleted) the file: not alice's entry, which only the
// namespace's key history tells (§H.7 "Users"). A save of alice's from
// before, over it, is a conflict (409). While a read of that history
// fails (the namespace head, its log, a config write's document), the
// save fails, 503 or 502, and nothing is written: v0.27.0 took the entry
// for alice's own and saved over it. Once the core answers, the 409.
func TestV082SaveKeyHistoryFailedRead(t *testing.T) {
	t.Parallel()
	reads := map[string]func(r *http.Request) bool{
		"the namespace head": at("GET", "/ns/docs"),
		"the namespace log": func(r *http.Request) bool {
			return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/ns/docs/rev/") && strings.HasSuffix(r.URL.Path, "/log")
		},
		"a config write's document": func(r *http.Request) bool {
			return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/ns/docs/rev/") && !strings.HasSuffix(r.URL.Path, "/log")
		},
	}
	for _, kind := range []string{"write", "delete"} {
		for what, match := range reads {
			for _, c := range v82Failed {
				t.Run(fmt.Sprintf("%s/%s/%d", kind, what, c.status), func(t *testing.T) {
					t.Parallel()
					rt := &failRT{status: c.status}
					e, k := authEnv(t, true, func(o *dav.Options) {
						o.Client = o.Client.With(client.WithHTTPClient(&http.Client{Transport: rt}))
					})
					writer := []string{"read", "create", "append", "restore", "delete"}
					alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)
					e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
					g := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET")

					// Kid k names another key for a while, whose grant for
					// the same sub writes the file.
					config := must(e.c.NSHead(e.ctx, "docs")).Config
					// setKey gives kid k to key to, in a config write under
					// a grant of the key it names now.
					setKey := func(from, to clienttest.Key) {
						admin := e.s.Client(t, client.WithBearer(from.Grant(t, e.s.Now(), "user:admin", []string{"docs"}, []string{"config"})))
						config = must(admin.PatchConfig(e.ctx, "docs", config, []any{replace("/keys", []any{to.Entry("*")})})).Config
					}
					h, _ := e.load("docs", "x")
					other := clienttest.NewKey("k")
					setKey(k, other)
					them := e.s.Client(t, client.WithBearer(other.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)))
					if kind == "write" {
						must(them.Append(e.ctx, "docs", "x", h.ID, []any{replace("/b", "theirs")}))
					} else {
						must(them.Delete(e.ctx, "docs", "x", h.ID))
					}
					setKey(other, k)
					before, _ := e.load("docs", "x")

					save := func() resp {
						return e.doAs(alice, "PUT", "/docs/x.json", edit(t, g.body, `"b": "1"`, `"b": "mine"`), "If-Match", g.header.Get("ETag"))
					}
					rt.match.Store(match)
					rt.armed.Store(true)
					v82ExpectFailed(t, e, save(), c.want, "alice's save, "+what+" failing")
					if after, _ := e.load("docs", "x"); after.ID != before.ID || after.State != before.State {
						t.Fatalf("the failed save wrote: %+v, was %+v", after, before)
					}
					// Nothing of the failed read is kept: the core answers
					// again, and the entry is someone else's.
					rt.armed.Store(false)
					r := e.expect(save(), 409, "alice's save, the core answering")
					if kind == "delete" && !strings.Contains(r.body, "deleted by someone else") {
						t.Fatalf("the 409: %s", r.body)
					}
					if after, _ := e.load("docs", "x"); after.ID != before.ID {
						t.Fatalf("the refused save wrote: %+v", after)
					}
				})
			}
		}
	}
}

// v82FailingEnv is failingEnv with a clock for the WebDAV server, which
// later advances it past what the server keeps of the core's answers.
func v82FailingEnv(t *testing.T, status int) (*env, *failRT, *atomic.Int64) {
	t.Helper()
	e := newEnv(t, []string{"docs"}, nil, nil)
	rt := &failRT{status: status}
	var later atomic.Int64
	start := time.Now()
	opt := e.opt
	opt.Client = e.s.Client(t, client.WithAuthor("dav"), client.WithHTTPClient(&http.Client{Transport: rt}))
	opt.Now = func() time.Time { return start.Add(time.Duration(later.Load())) }
	g := *e
	g.opt = opt
	g.dav = newTestServer(t, must(dav.New(opt)))
	return &g, rt, &later
}

// BT-8, who the user is, and the log between base and head (local mode,
// authentication disabled): a save over someone else's overlapping write
// reads who the user is in the namespace (GET /ns/{ns}/principal, once
// what it was told has aged) and the resource's log, to tell theirs from
// its own. A failed read of either fails the save, 503 or 502, and
// nothing is written; once the core answers, the conflict is the 409.
func TestV082SaveOverWriteFailedReads(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"the principal", "the log"} {
		for _, c := range v82Failed {
			t.Run(fmt.Sprintf("%s/%d", read, c.status), func(t *testing.T) {
				t.Parallel()
				e, rt, later := v82FailingEnv(t, c.status)
				e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
				g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
				e.theirs("docs", "x", replace("/b", "theirs"))
				head, _ := e.load("docs", "x")
				switch read {
				case "the principal":
					rt.match.Store(at("GET", "/ns/docs/principal"))
					later.Store(int64(time.Minute))
				case "the log":
					rt.match.Store(at("GET", "/r/docs/x/rev/"+head.ID+"/log"))
				}
				save := func() resp {
					return e.do("PUT", "/docs/x.json", edit(t, g.body, `"b": "1"`, `"b": "mine"`), "If-Match", g.header.Get("ETag"))
				}
				rt.armed.Store(true)
				v82ExpectFailed(t, e, save(), c.want, "PUT, "+read+" failing")
				if after, _ := e.load("docs", "x"); after.ID != head.ID {
					t.Fatalf("the failed save wrote %s", after.ID)
				}
				rt.armed.Store(false)
				e.expect(save(), 409, "PUT, the core answering")
				if after, _ := e.load("docs", "x"); after.ID != head.ID {
					t.Fatalf("the refused save wrote %s", after.ID)
				}
			})
		}
	}
}

// BT-8, §H.6's restore by a write (local mode): a save over someone
// else's delete reads the tombstone's log entry, and who the user is in
// the namespace, to tell whether the delete is its own. A failed read of either fails the
// save with the same split, and the file stays deleted; once the core
// answers, the delete is someone else's (409).
func TestV082SaveOverDeleteFailedReads(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"the principal", "the tombstone's log"} {
		for _, c := range v82Failed {
			t.Run(fmt.Sprintf("%s/%d", read, c.status), func(t *testing.T) {
				t.Parallel()
				e, rt, later := v82FailingEnv(t, c.status)
				e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
				g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
				h, _ := e.load("docs", "x")
				tomb := must(e.c.Delete(e.ctx, "docs", "x", h.ID))
				if read == "the principal" {
					rt.match.Store(at("GET", "/ns/docs/principal"))
					later.Store(int64(time.Minute))
				} else {
					rt.match.Store(func(r *http.Request) bool {
						return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/r/docs/x/rev/"+tomb.ID+"/log")
					})
				}
				save := func() resp {
					return e.do("PUT", "/docs/x.json", edit(t, g.body, `"a": "1"`, `"a": "mine"`), "If-Match", g.header.Get("ETag"))
				}
				rt.armed.Store(true)
				v82ExpectFailed(t, e, save(), c.want, "PUT, "+read+" failing")
				e.expectTombstoned("docs", "x", "after the failed read")
				rt.armed.Store(false)
				e.expect(save(), 409, "PUT, the core answering")
				e.expectTombstoned("docs", "x", "after the refused save")
			})
		}
	}
}
