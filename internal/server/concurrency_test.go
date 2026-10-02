package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/verify"
)

// raceHook injects a function once, between a write's check phase and its
// write lock (core.Options.BeforeWriteLock, D.3), so races are
// deterministic. Writes the function makes pass the hook with nothing armed.
type raceHook struct {
	mu    sync.Mutex
	fn    func()
	calls atomic.Int64
}

func (h *raceHook) arm(fn func()) { h.mu.Lock(); h.fn = fn; h.mu.Unlock() }

func (h *raceHook) run() {
	h.calls.Add(1)
	h.mu.Lock()
	fn := h.fn
	h.fn = nil
	h.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func withRaceHook(h *raceHook) envOpt {
	return func(o *core.Options) { o.BeforeWriteLock, o.LockedCheckBytes = h.run, -1 }
}

// bothDBs runs a test on :memory: (one connection) and on a file database.
func bothDBs(t *testing.T, f func(t *testing.T, opts ...envOpt)) {
	t.Run("memory", func(t *testing.T) { f(t) })
	t.Run("file", func(t *testing.T) { f(t, withFileDB(t)) })
}

func (e *tenv) batchReq(ns string, body any, who string) *resp {
	e.t.Helper()
	q := req{method: "POST", path: "/ns/" + ns + "/batch", body: body}
	if e.auth {
		q.bearer = who
	} else {
		q.author = who
	}
	return e.do(q)
}

// nsEntries counts the entries of a namespace's log.
func (e *tenv) nsEntries(ns string) int {
	e.t.Helper()
	return len(e.nsKinds(ns))
}

// A concurrent append to the same resource: the write is re-checked and
// answered 412 with the new head; nothing is inserted for it.
func TestRaceConcurrentAppend(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		e := newEnv(t, append(opts, withRaceHook(h))...)
		e.mkNS("main", map[string]any{"read": "public"})
		a0 := e.create("main", "a", map[string]any{"n": 1.0})
		before := e.nsEntries("main")

		var a1 string
		h.arm(func() { a1 = e.appendRev("main", "a", a0, ops(op("replace", "/n", 2.0)), "bob") })
		r := e.write("PATCH", "main", "a", a0, ops(op("replace", "/n", 3.0)), "alice")
		expectCode(t, r, 412, "stale")
		if r.Str("head") != a1 || a1 == "" {
			t.Fatalf("412 head %q, want %q", r.Str("head"), a1)
		}
		if got := e.nsEntries("main"); got != before+1 {
			t.Fatalf("ns entries %d, want %d", got, before+1)
		}
		if d := e.doc("main", "a"); d["n"] != 2.0 {
			t.Fatalf("doc %v", d)
		}

		// A batch: one item's head moves; nothing of the batch is written.
		var a2 string
		h.arm(func() { a2 = e.appendRev("main", "a", a1, ops(op("replace", "/n", 4.0)), "bob") })
		r = e.batchReq("main", map[string]any{"items": []any{
			map[string]any{"resource": "a", "ifMatch": a1, "steps": []any{ops(op("replace", "/n", 5.0))}},
			map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		}}, "alice")
		expectCode(t, r, 412, "batch")
		items, _ := r.Obj()["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["head"] != a2 || items[0].(map[string]any)["index"] != 0.0 {
			t.Fatalf("batch 412 %s", r.Body)
		}
		expect(t, e.get("/r/main/b"), 404)

		// A delete racing an append.
		var a3 string
		h.arm(func() { a3 = e.appendRev("main", "a", a2, ops(op("replace", "/n", 6.0)), "bob") })
		r = e.write("DELETE", "main", "a", a2, nil, "alice")
		expectCode(t, r, 412, "stale")
		if r.Str("head") != a3 {
			t.Fatalf("delete 412 %s", r.Body)
		}
		// A create racing a create.
		var c0 string
		h.arm(func() { c0 = e.create("main", "c", map[string]any{"by": "bob"}, "bob") })
		r = e.write("PATCH", "main", "c", "", addRoot(map[string]any{"by": "alice"}), "alice")
		expectCode(t, r, 412, "stale")
		if r.Str("head") != c0 {
			t.Fatalf("create 412 %s", r.Body)
		}
	})
}

// An idempotent retry landing between check and insert: the redo finds
// the entry and answers 200 with it; nothing is written twice.
func TestRaceIdempotentRetry(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		e := newEnv(t, append(opts, withRaceHook(h))...)
		e.mkNS("main", map[string]any{"read": "public"})
		a0 := e.create("main", "a", map[string]any{"n": 1.0})
		before := e.nsEntries("main")
		p := ops(op("replace", "/n", 2.0))
		var first string
		h.arm(func() { first = e.appendRev("main", "a", a0, p, "alice") })
		r := e.write("PATCH", "main", "a", a0, p, "alice")
		expect(t, r, 200)
		if etagOf(r) != first || first == "" {
			t.Fatalf("replayed %q, want %q", etagOf(r), first)
		}
		if got := e.nsEntries("main"); got != before+1 {
			t.Fatalf("ns entries %d, want %d", got, before+1)
		}
		// The same for a batch.
		body := map[string]any{"items": []any{
			map[string]any{"resource": "a", "ifMatch": first, "steps": []any{ops(op("replace", "/n", 3.0))}},
			map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		}}
		var nsID string
		h.arm(func() {
			r := e.batchReq("main", body, "alice")
			expect(t, r, 201)
			nsID = r.Str("ns_id")
		})
		r = e.batchReq("main", body, "alice")
		expect(t, r, 200)
		if r.Str("ns_id") != nsID || nsID == "" {
			t.Fatalf("batch replay %s, want ns_id %s", r.Body, nsID)
		}
		if got := e.nsEntries("main"); got != before+2 {
			t.Fatalf("ns entries %d, want %d", got, before+2)
		}
		// A different principal sending the same patches gets 412.
		h.arm(func() { e.appendRev("main", "a", e.head("main", "a"), ops(op("replace", "/n", 9.0)), "alice") })
		expectCode(t, e.write("PATCH", "main", "a", e.head("main", "a"), ops(op("replace", "/n", 9.0)), "bob"), 412, "stale")
	})
}

// A config rule change, a freeze, and a removed allowance between check and
// insert: the write is re-checked against the configuration in force.
func TestRaceConfigChange(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		e := newEnv(t, append(opts, withRaceHook(h))...)
		e.mkNS("main", map[string]any{"read": "public"})
		e.mkNS("next", map[string]any{"read": "public"})
		a0 := e.create("main", "a", map[string]any{"n": 1.0, "i18n": map[string]any{}})

		h.arm(func() {
			expect(t, e.patchNS("main", ops(op("add", "/rules", []any{map[string]any{"op": "writes", "within": []any{"/i18n"}}})), ""), 201)
		})
		expectCode(t, e.write("PATCH", "main", "a", a0, ops(op("replace", "/n", 2.0))), 422, "rule")
		// Allowed by the new rules: re-checked and inserted.
		h.arm(func() { expect(t, e.patchNS("main", ops(op("add", "/x-title", "t")), ""), 201) })
		a1 := e.appendRev("main", "a", a0, ops(op("add", "/i18n/sv", "x")))
		if a1 == "" {
			t.Fatal("no id")
		}

		// A freeze: 409 frozen with the successor.
		h.arm(func() {
			expect(t, e.patchNS("main", ops(op("add", "/frozen", true), op("add", "/successor", "next")), ""), 201)
		})
		r := e.write("PATCH", "main", "a", a1, ops(op("add", "/i18n/no", "y")))
		expectCode(t, r, 409, "frozen")
		if r.Str("successor") != "next" {
			t.Fatalf("frozen %s", r.Body)
		}
	})
}

// A revocation in the namespace, and a key removed from a base, between
// check and insert: the grant is re-checked and refused.
func TestRaceRevocationAndKeys(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		f := newAuthFixture(t, nil, append(opts, withRaceHook(h))...)
		e := f.tenv
		a := e.create("sec", "a", map[string]any{}, f.issuerG)
		victim := e.grant(f.issuer, "user:v", []string{"sec", "sec-b"}, []string{"read", "append"})
		h.arm(func() {
			expect(t, e.patchNS("sec", ops(op("add", "/revoked", []any{revocationID(t, victim, 0)})), f.adminG), 201)
		})
		expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), victim), 401, "unauthenticated")
		if e.head("sec", "a", f.adminG) != a {
			t.Fatal("a refused write moved the head")
		}

		// In a branch: a revocation in the base.
		expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.adminG), 201)
		victim2 := e.grant(f.issuer, "user:w", []string{"sec", "sec-b"}, []string{"read", "append"})
		h.arm(func() {
			expect(t, e.patchNS("sec", ops(op("add", "/revoked/-", revocationID(t, victim2, 0))), f.adminG), 201)
		})
		expectCode(t, e.write("PATCH", "sec-b", "a", a, ops(op("add", "/x", 1.0)), victim2), 401, "unauthenticated")

		// Keys follow the base: the issuer key is removed from the base.
		cfg := e.get("/ns/sec/rev/"+e.nsHead("sec", f.adminG), f.adminG).Obj()
		idx := -1
		for i, k := range cfg["keys"].([]any) {
			if k.(map[string]any)["kid"] == "issuer" {
				idx = i
			}
		}
		h.arm(func() {
			expect(t, e.patchNS("sec", ops(op("remove", "/keys/"+strconv.Itoa(idx))), f.adminG), 201)
		})
		expectCode(t, e.write("PATCH", "sec-b", "a", a, ops(op("add", "/y", 1.0)), f.issuerG), 401, "unauthenticated")
		if e.head("sec-b", "a", f.adminG) != a {
			t.Fatal("a refused write moved the head")
		}
	})
}

// A schema referenced only by the pending write is purged between check and
// insert: 422 schema_unavailable.
func TestRaceSchemaPurge(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		e := newEnv(t, append(opts, withRaceHook(h))...)
		e.mkNS("schemas", map[string]any{"read": "public"})
		e.mkNS("docs", map[string]any{"read": "public"})
		s1 := e.create("schemas", "match", matchSchema())
		ref := "/r/schemas/match/rev/" + s1
		h.arm(func() { expect(t, e.purge("schemas", "match", s1, "admin"), 204) })
		r := e.write("PATCH", "docs", "x", "", addRoot(map[string]any{"$schema": ref, "score": "1-0"}))
		expectCode(t, r, 422, "schema_unavailable")
		expect(t, e.get("/r/docs/x"), 404)

		// In a batch, a schema created by an earlier item needs no re-check.
		r = e.batchReq("docs", map[string]any{"items": []any{
			map[string]any{"resource": "s", "ifNoneMatch": "*", "steps": []any{addRoot(matchSchema())}},
		}}, "alice")
		expect(t, r, 201)
	})
}

// Rate-limit tokens are drawn once per request, however often the check is
// redone.
func TestRaceRateDrawnOnce(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		e := newEnv(t, append(opts, withRaceHook(h))...)
		e.mkNS("main", map[string]any{"read": "public", "limits": map[string]any{
			"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 2.0}}})
		a0 := e.create("main", "a", map[string]any{"n": 1.0}, "alice") // one token
		// The config change forces a redo; a second draw would be 429.
		h.arm(func() { expect(t, e.patchNS("main", ops(op("add", "/x-title", "t")), ""), 201) })
		calls := h.calls.Load()
		a1 := e.appendRev("main", "a", a0, ops(op("replace", "/n", 2.0)), "alice")
		if n := h.calls.Load() - calls; n < 2 {
			t.Fatalf("hook ran %d times; expected a redo", n)
		}
		expectCode(t, e.write("PATCH", "main", "a", a1, ops(op("replace", "/n", 3.0)), "alice"), 429, "rate")
	})
}

// An allowance removed between check and insert: the batch limits are
// re-checked.
func TestRaceAllowance(t *testing.T) {
	h := &raceHook{}
	max := core.DefaultLimits()
	max.ItemsPerBatch = 50
	f := newAuthFixture(t, map[string]any{
		"limits":     map[string]any{"itemsPerBatch": 2},
		"allowances": []any{map[string]any{"sub": "user:bob", "kid": "issuer", "itemsPerBatch": 20}},
	}, func(o *core.Options) { o.Maximums = max }, withRaceHook(h))
	e := f.tenv
	h.arm(func() { expect(t, e.patchNS("sec", ops(op("remove", "/allowances")), f.adminG), 201) })
	expectCode(t, e.batchReq("sec", batchOf("b", 5), f.issuerG), 413, "limit")
	expect(t, e.batchReq("sec", batchOf("c", 2), f.issuerG), 201)
}

// Many writers on a file database, to the same and to different resources:
// every chain stays linear, every successful write has exactly one
// namespace entry, and everything verifies (§4 invariants 2 and 5).
func TestConcurrentWritersStress(t *testing.T) {
	lim := core.DefaultLimits()
	lim.RatePerResource = core.Rate{Rate: 1e6, Burst: 1e6}
	lim.RatePerPrincipal = core.Rate{Rate: 1e6, Burst: 1e6}
	lim.RatePerNamespace = core.Rate{Rate: 1e6, Burst: 1e6}
	e := newEnv(t, withFileDB(t), func(o *core.Options) { o.Limits, o.Maximums = lim, lim })
	e.mkNS("main", map[string]any{"read": "public"})
	ctx := context.Background()
	const writers, perWriter = 8, 20

	var mu sync.Mutex
	written := map[string]map[string]bool{} // resource -> ids written
	nsIDs := map[string]bool{}
	record := func(res string, id, nsID string) error {
		mu.Lock()
		defer mu.Unlock()
		if written[res] == nil {
			written[res] = map[string]bool{}
		}
		if written[res][id] {
			return fmt.Errorf("%s: id %s written twice", res, id)
		}
		if nsIDs[nsID] {
			return fmt.Errorf("ns entry %s answered twice", nsID)
		}
		written[res][id], nsIDs[nsID] = true, true
		return nil
	}
	hot, err := plclient.New(e.srv.URL, plclient.WithAuthor("setup"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"hot", "hot2"} {
		w, err := hot.CreateDoc(ctx, "main", r, map[string]any{"n": 0})
		if err != nil {
			t.Fatal(err)
		}
		if err := record(r, w.ID, w.NSID); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers*2)
	for i := 0; i < writers; i++ {
		c, err := plclient.New(e.srv.URL, plclient.WithAuthor(fmt.Sprintf("w%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		// Appends to a shared resource, retrying on 412.
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			head := ""
			for j := 0; j < perWriter; {
				if head == "" {
					h, err := c.Head(ctx, "main", "hot")
					if err != nil {
						errs <- err
						return
					}
					head = h.ID
				}
				w, err := c.Append(ctx, "main", "hot", head, []any{map[string]any{"op": "add", "path": fmt.Sprintf("/w%d_%d", i, j), "value": j}})
				var ae *plclient.APIError
				if errors.As(err, &ae) && ae.Status == 412 {
					head = ae.Head()
					continue
				}
				if err != nil {
					errs <- err
					return
				}
				if w.Status != 201 {
					errs <- fmt.Errorf("status %d", w.Status)
					return
				}
				if err := record("hot", w.ID, w.NSID); err != nil {
					errs <- err
					return
				}
				head = w.ID
				j++
			}
		}(i)
		// Its own resource, and batches that also touch a second shared one.
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			own := fmt.Sprintf("r%d", i)
			w, err := c.CreateDoc(ctx, "main", own, map[string]any{"i": i})
			if err != nil {
				errs <- err
				return
			}
			if err := record(own, w.ID, w.NSID); err != nil {
				errs <- err
				return
			}
			head := w.ID
			for j := 0; j < perWriter; j++ {
				if j%4 != 3 {
					w, err := c.Append(ctx, "main", own, head, []any{map[string]any{"op": "replace", "path": "/i", "value": j}})
					if err != nil {
						errs <- err
						return
					}
					if err := record(own, w.ID, w.NSID); err != nil {
						errs <- err
						return
					}
					head = w.ID
					continue
				}
				for {
					h2h, err := c.Head(ctx, "main", "hot2")
					if err != nil {
						errs <- err
						return
					}
					b, err := c.Batch(ctx, "main", plclient.BatchRequest{Items: []plclient.BatchItem{
						{Resource: own, IfMatch: head, Steps: []plclient.Step{plclient.PatchStep([]any{map[string]any{"op": "replace", "path": "/i", "value": -j}})}},
						{Resource: "hot2", IfMatch: h2h.ID, Steps: []plclient.Step{plclient.PatchStep([]any{map[string]any{"op": "add", "path": fmt.Sprintf("/b%d_%d", i, j), "value": j}})}},
					}}, false)
					var ae *plclient.APIError
					if errors.As(err, &ae) && ae.Status == 412 {
						continue
					}
					if err != nil {
						errs <- err
						return
					}
					if err := record(own, b.Items[0].IDs[0], b.NSID); err != nil {
						errs <- err
						return
					}
					mu.Lock()
					written["hot2"][b.Items[1].IDs[0]] = true
					mu.Unlock()
					head = b.Items[0].IDs[0]
					break
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// The namespace chain verifies, and has exactly one entry per write.
	c, _ := plclient.New(e.srv.URL)
	entries, _, err := verify.Namespace(ctx, c, "main", "")
	if err != nil {
		t.Fatal(err)
	}
	logged := map[string]map[string]int{}
	count := func(res, id string) {
		if logged[res] == nil {
			logged[res] = map[string]int{}
		}
		logged[res][id]++
	}
	for _, en := range entries {
		switch en.Kind {
		case "head":
			count(en.Resource, en.Target)
		case "batch":
			for _, s := range en.Entries {
				count(s.Resource, s.Target)
			}
		}
	}
	for res, ids := range written {
		for id := range ids {
			if logged[res][id] != 1 {
				t.Errorf("%s %s: %d namespace entries", res, id, logged[res][id])
			}
		}
		if len(logged[res]) != len(ids) {
			t.Errorf("%s: %d namespace entries for %d writes", res, len(logged[res]), len(ids))
		}
		// The resource chain is linear, verifies, and holds every write.
		log, _, err := verify.Resource(ctx, c, "main", res, "", "")
		if err != nil {
			t.Fatalf("%s: %v", res, err)
		}
		if len(log) != len(ids) {
			t.Errorf("%s: chain of %d entries for %d writes", res, len(log), len(ids))
		}
		for _, le := range log {
			if !ids[le.ID] {
				t.Errorf("%s: unexpected entry %s", res, le.ID)
			}
		}
	}
	if n := len(written["hot"]); n != writers*perWriter+1 {
		t.Errorf("hot has %d writes, want %d", n, writers*perWriter+1)
	}
}

// A write whose re-check keeps failing runs its gate inside the write lock
// after the optimistic rounds, and still draws its rate tokens once.
func TestRaceFallbackUnderLock(t *testing.T) {
	bothDBs(t, func(t *testing.T, opts ...envOpt) {
		h := &raceHook{}
		e := newEnv(t, append(opts, withRaceHook(h))...)
		e.mkNS("main", map[string]any{"read": "public", "limits": map[string]any{
			"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 2.0}}})
		a0 := e.create("main", "a", map[string]any{"n": 1.0}, "alice")
		var bump func()
		rounds := 0
		bump = func() {
			rounds++
			expect(t, e.patchNS("main", ops(op("add", "/x-title", strconv.Itoa(rounds))), ""), 201)
			h.arm(bump) // every round loses
		}
		h.arm(bump)
		calls := h.calls.Load()
		a1 := e.appendRev("main", "a", a0, ops(op("replace", "/n", 2.0)), "alice")
		h.arm(nil)
		if n := h.calls.Load() - calls; n != 3 || rounds != 3 {
			t.Fatalf("%d optimistic rounds (%d config changes), want 3", n, rounds)
		}
		if e.head("main", "a") != a1 {
			t.Fatal("head")
		}
		expectCode(t, e.write("PATCH", "main", "a", a1, ops(op("replace", "/n", 3.0)), "alice"), 429, "rate")
	})
}
