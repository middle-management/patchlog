package streams_test

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/streams"
)

// earliestExp is the earliest exp of a grant's blocks: when it stops
// working.
func earliestExp(t *testing.T, tok string) time.Time {
	t.Helper()
	g, err := grant.Decode(tok, 0)
	if err != nil {
		t.Fatal(err)
	}
	var exp time.Time
	for _, b := range g.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	return exp
}

// §J.4 Expiry (v0.86): "A stream's read grants have the exp counted from
// its creation …, also when a repeated request hands one out again, or the
// proxy grant's own if earlier, which a narrowed grant never outlives
// (§C.2 item 1)." The proxy's grant here lasts an hour and --ttl is three:
// a read grant ends with the proxy's grant, and the one a repeated request
// hands out ends then too.
func TestV086ReadGrantCappedByProxyGrant(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{options: func(o *streams.Options) { o.TTL = 3 * time.Hour }})
	proxyExp := earliestExp(t, e.grant)
	if !proxyExp.Before(e.s.Now().Add(e.opt.TTL)) {
		t.Fatalf("the proxy grant's exp %v isn't before the TTL's end", proxyExp)
	}
	a := e.mustPost(postOpt{key: "turn-1"})
	if got := earliestExp(t, a.Grant); !got.Equal(proxyExp) {
		t.Fatalf("the read grant's exp is %v, want the proxy grant's own, %v, which is earlier than creation + ttl", got, proxyExp)
	}
	// It reads the stream.
	if got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{}); got != sseBody() || closed.Reason != streams.ReasonComplete {
		t.Fatalf("the stream read with it: %q %+v", got, closed)
	}
	status, b, body := e.post(postOpt{key: "turn-1"})
	if status != 200 || b.ID != a.ID {
		t.Fatalf("the repeated request: %d %s", status, body)
	}
	if got := earliestExp(t, b.Grant); !got.Equal(proxyExp) {
		t.Fatalf("the read grant a repeated request hands out has exp %v, want the proxy grant's own, %v", got, proxyExp)
	}
}

// Where creation + ttl is the earlier, the read grant's exp is counted
// from the stream's creation, at first and when handed out again (§J.4
// Expiry).
func TestV086ReadGrantFromCreation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	before := e.s.Now()
	a := e.mustPost(postOpt{key: "turn-1"})
	first := earliestExp(t, a.Grant)
	if first.Before(before.Add(e.opt.TTL).Add(-2*time.Second)) || first.After(e.s.Now().Add(e.opt.TTL).Add(2*time.Second)) || !first.Before(earliestExp(t, e.grant)) {
		t.Fatalf("the read grant's exp %v isn't the stream's creation + %v", first, e.opt.TTL)
	}
	e.offset.Store(int64(10 * time.Minute))
	status, b, body := e.post(postOpt{key: "turn-1"})
	if status != 200 || b.ID != a.ID {
		t.Fatalf("the repeated request: %d %s", status, body)
	}
	if again := earliestExp(t, b.Grant); !again.Equal(first) {
		t.Fatalf("handed out again ten minutes on, the exp is %v, want the first one's %v", again, first)
	}
}

// §C.4 Operator grants, §C.6 (v0.86; CONFORMANCE Access 85): an operator
// grant authorises creating namespaces and forced purges, nothing a
// service does. GET /ns/{ns}/principal describes one with its sub, so the
// proxy took it for a caller; it answers 401 and calls nothing upstream.
func TestV086OperatorGrantIsNoCaller(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	status, a, body := e.post(postOpt{bearer: e.s.OperatorGrant(t, nsApp), key: "turn-1"})
	if status != 401 || a.ID != "" || a.Grant != "" {
		t.Fatalf("an operator grant as the caller's: %d %s, want 401", status, body)
	}
	if !strings.Contains(body, "operator grant") {
		t.Errorf("the 401 doesn't say why: %s", body)
	}
	if n := e.up.hits.Load(); n != 0 {
		t.Fatalf("upstream was called %d times for an operator grant", n)
	}
	// A caller's grant still creates.
	e.mustPost(postOpt{key: "turn-1"})
}
