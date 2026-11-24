package server

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
)

// v0.90 §6.6 Validation work, §7.7 (CONFORMANCE Limits 101): a long-poll
// keeps one budget of validationSteps for its whole wait, and where it
// runs out after the wait began, having shown nothing, answers 204 naming
// the last entry judged whole: never the 403 or 404 a read check that runs
// out gives, and never a budget renewed at each wake. Until v0.90 the
// reference answered the refusal mid-wait. Not parallel: it counts fetches
// through testLongPollFetch.
func TestV090BLongPollRunOutIs204(t *testing.T) {
	const interval = 20 * time.Second
	f := newAuthFixture(t, nil, func(o *core.Options) { o.MaxValidationSteps, o.LongPollInterval = 3000, interval })
	e := f.tenv
	slow := func(levels int) string {
		g, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:r", "ns": []any{"sec"}, "can": []any{"read"},
			"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
		if err != nil {
			t.Fatal(err)
		}
		return narrowed(t, g, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/principal", "schema": doubling(levels)}}})
	}
	// The costliest rule whose one fetch's read check passes: answered at
	// once (no cursor), the empty log of a name with no entries is 204.
	// Each level doubles the steps, so two such checks run out.
	path := "/r/sec/quiet/log?live=long-poll"
	levels := 0
	for l := 4; l < 14; l++ {
		if e.get(path, slow(l)).Code != 204 {
			break
		}
		levels = l
	}
	if levels == 0 {
		t.Fatal("no rule passes a long-poll's first read check")
	}
	g := slow(levels)

	var fetches atomic.Int64
	testLongPollFetch = func() { fetches.Add(1) }
	t.Cleanup(func() { testLongPollFetch = nil })
	cur := waitCursor(t, newLiveClock(interval, resourceLogPath("sec", "quiet")), 10*time.Second)
	done := make(chan *resp, 1)
	go func() { done <- e.get(fmt.Sprintf("%s&cursor=%d", path, cur), g) }()
	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the long-poll made no first read")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A config write concerns the whole namespace: it wakes the wait,
	// whose next read check runs out of the wait's one budget.
	expect(t, e.patchNS("sec", ops(op("add", "/roles/other", map[string]any{"can": []any{"read"}})), f.adminG), 201)
	select {
	case r := <-done:
		if r.Code != 204 {
			t.Fatalf("the run-out wait: %d %s, want 204", r.Code, r.Body)
		}
		if h := r.H.Get("X-Revision"); h != "" {
			t.Fatalf("X-Revision %q, want none: since was empty", h)
		}
		if fetches.Load() < 2 {
			t.Fatalf("%d fetches: the wait wasn't woken", fetches.Load())
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the long-poll didn't answer once its budget ran out")
	}
	// The next poll has a budget of its own.
	if r := e.get(path, g); r.Code != 204 {
		t.Fatalf("the next poll: %d %s", r.Code, r.Body)
	}
}
