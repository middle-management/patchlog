package index_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
)

// v82xCountEvents counts the requests for a namespace's event stream and
// for its log ranges that the index's client makes.
type v82xCountEvents struct {
	rt           http.RoundTripper
	events, logs atomic.Int64
}

func (c *v82xCountEvents) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, "/ns/sec/") {
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
// sealed under K_n with pl { ns, event: id }; §7.4): an index that follows
// a sealed namespace over SSE reads the origin's namespace events, each
// opened by the client under the event's own pl, and applies them: a
// write made after it caught up is found by a query, with no log range
// read for it and no failed read of an event. A follower and an origin
// that disagreed on the event's pl would fail every event with a
// mismatch and never apply the write from the stream (design: mixed
// versions).
func TestV082XIndexFollowsSealedEventsOverSSE(t *testing.T) {
	t.Parallel()
	count := &v82xCountEvents{rt: transport}
	v := newV82XWorld(t, func(o *indexOpts) {
		o.FollowOptions = append(o.FollowOptions, follow.WithSSE())
		o.Client = o.Client.With(client.WithHTTPClient(&http.Client{Transport: count}))
	})
	waitFor(t, "the index's event stream of sec", func() bool { return count.events.Load() > 0 })
	logs := count.logs.Load()
	for _, n := range []string{"c", "d"} {
		must(createNonced(v.w, "sec", n, map[string]any{"$schema": v.ref, "title": "late " + n, "tag": "t" + n}))
	}
	head := v.x.caughtUp("sec")
	f := v.x.fetch("/sec?q=late", v.rd)
	pt := must(derived.OpenView(string(f.body), epochKeys(t, v.w, "sec"), derived.View{NS: "sec", Target: f.path}))
	b := decodeJSON(t, pt)
	if got := strings.Join(resources(b), ","); got != "c,d" || b["at"] != head {
		t.Errorf("after two events: hits %s at %v, want c,d at %s", got, b["at"], head)
	}
	if n := count.logs.Load() - logs; n != 0 {
		t.Errorf("the index read %d log ranges of sec for the two writes: they didn't come from its event stream", n)
	}
	for _, l := range v.logs() {
		if strings.Contains(l, "index: sec:") {
			t.Errorf("the follower of sec failed: %s", l)
		}
	}
}
