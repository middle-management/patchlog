package tree_test

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/tree"
)

// v82xEvents counts the requests the tree service's client makes for
// cat's event stream and for its log ranges.
type v82xEvents struct {
	rt           http.RoundTripper
	events, logs atomic.Int64
}

func (c *v82xEvents) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, "/ns/cat/") {
		switch {
		case strings.HasSuffix(r.URL.Path, "/events"):
			c.events.Add(1)
		case strings.HasSuffix(r.URL.Path, "/log"):
			c.logs.Add(1)
		}
	}
	return c.rt.RoundTrip(r)
}

// XT-1 (4), E2E-1 through a service (§E.2.2, v0.82: a namespace event is
// sealed under K_n with pl { ns, event: id }; §7.4): a tree service that
// follows a sealed catalog over SSE reads the origin's namespace events,
// each opened by the client under the event's own pl, and applies them: a
// folder made after it caught up is in the next listing, with no log
// range read for it and no failed read of an event. A follower and an
// origin that disagreed on the event's pl would fail every event with a
// mismatch and never apply the write from the stream.
func TestV082XTreeFollowsSealedEventsOverSSE(t *testing.T) {
	t.Parallel()
	q := newV82Sealed(t)
	count := &v82xEvents{rt: http.DefaultTransport.(*http.Transport).Clone()}
	var mu sync.Mutex
	var failed []string
	x := startSvc(t, q.svc(client.WithHTTPClient(&http.Client{Transport: count})), svcOpts{now: q.s.Now, db: q.db}, func(o *tree.Options) {
		o.FollowOptions = append(o.FollowOptions, follow.WithSSE())
		logf := o.Logf
		o.Logf = func(f string, a ...any) {
			logf(f, a...)
			if strings.Contains(f, "%v") && len(a) > 0 {
				if err, ok := a[len(a)-1].(error); ok && err != nil {
					mu.Lock()
					failed = append(failed, err.Error())
					mu.Unlock()
				}
			}
		}
	})
	x.caughtUp("cat", "files")
	waitFor(t, "the tree service's event stream of cat", func() bool { return count.events.Load() > 0 })
	logs := count.logs.Load()
	createNonced(t, q.w, "cat", "late", map[string]any{"title": "Late", "parents": parents("root")})
	createNonced(t, q.w, "cat", "later", map[string]any{"title": "Later", "parents": parents("late")})
	x.caughtUp("cat")
	f := x.fetch("/cat/children?of=late", q.full)
	pt := must(derived.OpenView(string(f.body), q.keyOf, derived.View{NS: "cat", Target: f.path}))
	if es := entriesOf(t, decode(t, pt)); es["later"] == nil || len(es) != 1 {
		t.Errorf("after two events, the children of late: %s", pt)
	}
	if n := count.logs.Load() - logs; n != 0 {
		t.Errorf("the tree service read %d log ranges of cat for the two writes: they didn't come from its event stream", n)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range failed {
		if strings.Contains(l, "mismatch") || strings.Contains(l, "event") {
			t.Errorf("the follower failed: %s", l)
		}
	}
}
