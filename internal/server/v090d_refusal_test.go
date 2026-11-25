package server

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/rules"
)

// v0.90 §6.6 Validation work, §7.7: a long-poll answers 204 only where its
// one budget of validationSteps ran out. A grant revoked mid-wait, after
// the wait's first read check spent most of the budget, is refused as a
// revoked grant is anywhere (401), never the 204 of a run-out. Not
// parallel: it counts fetches through testLongPollFetch.
func TestV090DLongPollRevokedMidWaitIsRefused(t *testing.T) {
	const interval = 20 * time.Second
	f := newAuthFixture(t, nil, func(o *core.Options) { o.MaxValidationSteps, o.LongPollInterval = 3000, interval })
	e := f.tenv
	slow := func(levels int) string {
		g, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:r", "ns": []any{"sec"}, "can": []any{"read"},
			"exp": e.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)}, f.issuer.priv)
		if err != nil {
			t.Fatal(err)
		}
		return narrowed(t, g, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/principal", "schema": doubling(levels)}}})
	}
	// The costliest rule whose one read check passes: a second such check
	// runs out of the wait's budget.
	e.create("sec", "probe", map[string]any{"v": 1.0}, f.adminG)
	levels := 0
	for l := 4; l < 14; l++ {
		if e.get("/r/sec/probe", slow(l)).Code != 302 {
			break
		}
		levels = l
	}
	if levels == 0 {
		t.Fatal("no rule passes a long-poll's first read check")
	}
	path := "/r/sec/quiet/log?live=long-poll"

	var fetches atomic.Int64
	testLongPollFetch = func() { fetches.Add(1) }
	t.Cleanup(func() { testLongPollFetch = nil })

	// wake starts a long-poll with g, waits for its first read, then runs
	// change (which commits to the namespace and so wakes it).
	poll := func(g string, change func()) *resp {
		t.Helper()
		fetches.Store(0)
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
		change()
		select {
		case r := <-done:
			if fetches.Load() < 2 {
				t.Fatalf("%d fetches: the wait wasn't woken", fetches.Load())
			}
			return r
		case <-time.After(8 * time.Second):
			t.Fatal("the long-poll didn't answer")
		}
		return nil
	}

	// Revoked mid-wait: the refusal of a revoked grant.
	g := slow(levels)
	r := poll(g, func() {
		expect(t, e.patchNS("sec", ops(op("add", "/revoked", []any{revocationID(t, g, 1)})), f.adminG), 201)
	})
	if r.Code != 401 {
		t.Fatalf("a wait whose grant was revoked: %d %s, want 401", r.Code, r.Body)
	}
	if r2 := e.get("/r/sec/probe", g); r2.Code != 401 {
		t.Fatalf("the revoked grant at a read: %d %s, want 401", r2.Code, r2.Body)
	}

	// Expired mid-wait: the refusal of an expired grant.
	g = slow(levels)
	r = poll(g, func() {
		e.clock.Advance(11 * time.Minute)
		expect(t, e.patchNS("sec", ops(op("add", "/roles/other", map[string]any{"can": []any{"read"}})), f.adminG), 201)
	})
	if r.Code != 401 {
		t.Fatalf("a wait whose grant expired: %d %s, want 401", r.Code, r.Body)
	}
}

// v0.90 §7.9 Long-poll, §6.6: a view's long-poll whose cookie dies
// mid-wait, its role's rules changed, answers the cookie's refusal (403),
// never the 204 of a run-out. (A cookie's admission evaluates no rule, so
// it never draws on the wait's budget.) Not parallel: it counts fetches
// through testLongPollFetch.
func TestV090DFilteredLongPollCookieDeathIsRefused(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	w.put("matches", "derby", map[string]any{"title": "derby"})
	ck, view := w.cookie(w.li())
	base := "/ns/matches/view/" + view
	const interval = 20 * time.Second // the default (§7.7)
	if r := w.do(req{method: "GET", path: base + "/log?live=long-poll", hdr: cookieHdr(ck)}); r.Code != 200 {
		t.Fatalf("the cookie's first long-poll: %d %s", r.Code, r.Body)
	}
	var fetches atomic.Int64
	testLongPollFetch = func() { fetches.Add(1) }
	t.Cleanup(func() { testLongPollFetch = nil })
	since := w.nsHead("matches", w.admin)
	cur := waitCursor(t, newLiveClock(interval, filteredLogPath("matches", view)), 10*time.Second)
	done := make(chan *resp, 1)
	go func() {
		done <- w.do(req{method: "GET", path: fmt.Sprintf("%s/log?live=long-poll&since=%s&cursor=%d", base, since, cur), hdr: cookieHdr(ck)})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the long-poll made no first fetch")
		}
		time.Sleep(5 * time.Millisecond)
	}
	expect(t, w.patchNS("matches", ops(op("replace", "/roles/reader/rules", []any{v75sNames("derby")})), w.admin), 201)
	select {
	case r := <-done:
		if r.Code != 403 {
			t.Fatalf("a wait whose cookie died: %d %s, want 403", r.Code, r.Body)
		}
		if fetches.Load() < 2 {
			t.Fatalf("%d fetches: the wait wasn't woken", fetches.Load())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the long-poll didn't answer")
	}
}

// A per-revision reader whose rule on /doc refuses v1 outright and runs
// the wait's budget out judging v2 has run out: its long-poll from
// genesis answers 204 at once, never waiting on with its budget spent
// (§6.6 Validation work: running out fails the whole request), where a
// grant revoked meanwhile would be answered 204 rather than 401.
func TestV090DLongPollSpentBudgetNeverMasksARefusal(t *testing.T) {
	const interval = 20 * time.Second
	heavy := doubling(9)
	// heavy's steps, then v must be 2: v1 refused outright.
	schema := map[string]any{"$defs": heavy["$defs"], "allOf": []any{
		map[string]any{"$ref": heavy["$ref"]},
		map[string]any{"properties": map[string]any{"v": map[string]any{"const": 2.0}}},
	}}
	rule := map[string]any{"op": "test", "path": "/doc", "schema": schema}
	r, err := rules.Compile(map[string]any{"op": "test", "path": "/doc", "schema": heavy})
	if err != nil {
		t.Fatal(err)
	}
	m := rules.Budget(1 << 30)
	r.Passes(map[string]any{"doc": map[string]any{"v": 1.0}}, m)
	steps := m.Steps

	f := newAuthFixture(t, nil, func(o *core.Options) {
		o.MaxValidationSteps, o.LongPollInterval = steps+steps/2, interval
	})
	e := f.tenv
	v1 := e.create("sec", "x", map[string]any{"v": 1.0}, f.adminG)
	e.appendRev("sec", "x", v1, ops(op("replace", "/v", 2.0)), f.adminG)
	g0, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:r", "ns": []any{"sec"}, "can": []any{"read"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	g := narrowed(t, g0, map[string]any{"rules": []any{rule}})

	path := "/r/sec/x/log?live=long-poll"
	cur := waitCursor(t, newLiveClock(interval, resourceLogPath("sec", "x")), 10*time.Second)
	done := make(chan *resp, 1)
	go func() { done <- e.get(fmt.Sprintf("%s&cursor=%d", path, cur), g) }()
	var got *resp
	select {
	case got = <-done:
	case <-time.After(3 * time.Second):
		// Still waiting with its budget spent: revoke, and the answer
		// must be the refusal, never a 204.
		expect(t, e.patchNS("sec", ops(op("add", "/revoked", []any{revocationID(t, g, 1)})), f.adminG), 201)
		select {
		case got = <-done:
			t.Fatalf("a spent wait went on, then answered a revocation %d %s; want 204 at once", got.Code, got.Body)
		case <-time.After(8 * time.Second):
			t.Fatal("the long-poll didn't answer")
		}
	}
	if got.Code != 204 || got.H.Get("X-Revision") != "" {
		t.Fatalf("a wait that ran out judging v2: %d %s, X-Revision %q; want 204 without one", got.Code, got.Body, got.H.Get("X-Revision"))
	}
}
