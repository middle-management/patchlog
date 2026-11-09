package core

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

// V75-03 (v0.75): the core's filtered read paths (§B.11.9): long-poll
// sharing per gs, /branches to partial readers, and the redirect of
// unfiltered reads.

// §B.11.9 Cost (SHOULD): on each wake, each new entry's visibility is
// judged at most once per gs with waiting followers, who share the answer;
// another gs judges it on its own. Not parallel: it sets testFilteredJudge.
func TestV075FilteredLiveCost(t *testing.T) {
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	var mu sync.Mutex
	judged := map[string]int{}
	testFilteredJudge = func(gs, name string) {
		mu.Lock()
		judged[gs+"/"+name]++
		mu.Unlock()
	}
	t.Cleanup(func() { testFilteredJudge = nil })
	li, bo := w.li(), w.catGrant("user:bo", []any{"chiefs"})
	lgs, bgs := v075GS(t, w, li), v075GS(t, w, bo)
	since := w.head("matches")
	w.put("matches", "derby", map[string]any{"v": 2})
	poll := func(cred Credentials, gs string) []string {
		t.Helper()
		lg, info, err := w.e.FilteredLiveLog(ctx, "matches", gs, since, 100, cred)
		if err != nil || lg.Status != 200 || info.GS != gs || lg.Last != w.head("matches") {
			t.Fatalf("FilteredLiveLog: %+v %+v %v", lg, info, err)
		}
		var names []string
		for _, e := range lg.Entries {
			names = append(names, e["resource"].(string))
		}
		return names
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := poll(li, lgs); !reflect.DeepEqual(got, []string{"derby"}) {
				t.Errorf("li: %v", got)
			}
		}()
	}
	wg.Wait()
	if got := poll(bo, bgs); len(got) != 0 {
		t.Fatalf("bo: %v", got)
	}
	if judged[lgs+"/derby"] != 1 || judged[bgs+"/derby"] != 1 {
		t.Fatalf("judgements %v", judged)
	}
	// The next wake, with a new at: judged again, once.
	w.put("matches", "derby", map[string]any{"v": 3})
	since = w.head("matches")
	w.put("matches", "derby", map[string]any{"v": 4})
	poll(li, lgs)
	poll(li, lgs)
	if judged[lgs+"/derby"] != 2 {
		t.Fatalf("judgements after the next wake %v", judged)
	}
}

// §B.11.9 Answers (scenario 91): /branches to a partial reader lists only
// local branches in which its grant verifies and allows read: no remote
// registrations, Private.
func TestV075BranchListPartial(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", At: w.head("matches"), Patches: []any{}, IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if err := w.e.update(ctx, func(t *tx) error {
		n := t.nsByName("matches")
		_, err := t.Exec(`INSERT INTO remote_branches (ns, origin, name, at_seq, ns_seq, expires) VALUES (?, ?, ?, ?, ?, ?)`,
			n.id, "https://other.example", "matches-x", n.headSeq.Int64, n.headSeq.Int64, t.now.Add(1e12).UnixMilli())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	all, err := w.e.BranchList(ctx, "matches", w.admin)
	if err != nil || all.Private || len(all.List) != 2 {
		t.Fatalf("admin: %+v %v", all, err)
	}
	bl, err := w.e.BranchList(ctx, "matches", w.li())
	if err != nil || !bl.Private || len(bl.List) != 0 {
		t.Fatalf("li: %+v %v", bl, err)
	}
	both := w.li(map[string]any{"ns": []any{"matches", "matches-r7"}})
	bl, err = w.e.BranchList(ctx, "matches", both)
	if err != nil || !bl.Private || len(bl.List) != 1 || bl.List[0]["name"] != "matches-r7" {
		t.Fatalf("li in both: %+v %v", bl, err)
	}
	// Uncovered: 403, as before v0.75.
	w2 := newV75World(t, v75Opts{engine: func(o *Options) { o.NoFilteredReads = true }})
	if _, err := w2.e.BranchList(ctx, "matches", w2.li()); v75Status(err) != 403 {
		t.Fatalf("NoFilteredReads: %v", err)
	}
}

// §B.11.9 URLs, at: a partial reader's redirect names an at recorded
// before it is answered, which filteredAt then answers.
func TestV075RedirectRecordsAt(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	_, err := w.e.NamespaceHeads(ctx, "matches", w.head("matches"), "", w.li())
	fr, ok := err.(*FilteredRedirect)
	if !ok || fr.At == "" || fr.NS != "matches" || fr.GS != v075GS(t, w, w.li()) {
		t.Fatalf("redirect %v", err)
	}
	w.inTx(func(t2 *tx) {
		var n int
		t2.must(t2.QueryRow(`SELECT COUNT(*) FROM filtered_ats WHERE at = ?`, fr.At).Scan(&n))
		if n != 1 {
			t.Fatalf("at %s not recorded", fr.At)
		}
	})
	// Events and long-poll carry no at, and record none.
	_, err = w.e.NamespaceEvents(ctx, "matches", "", 10, w.li())
	if fr, ok := err.(*FilteredRedirect); !ok || fr.At != "" || fr.CP != nil {
		t.Fatalf("events redirect %v", err)
	}
	// The filtered page at it, after a write moved the current at.
	w.put("matches", "derby", map[string]any{"v": 2})
	page, info, err := w.e.FilteredHeads(ctx, "matches", fr.GS, fr.At, "", "", w.li())
	if err != nil || info.At != fr.At || len(page.Items) != 2 {
		t.Fatalf("at the recorded at: %+v %+v %v", page, info, err)
	}
}
