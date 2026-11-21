package core

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

// V75-03 (v0.75): the core's filtered read paths (§7.9): long-poll
// sharing per view, /branches to partial readers, and the redirect of
// unfiltered reads.

// §7.9 Cost (SHOULD): on each wake, each new entry's visibility is
// judged at most once per view with waiting followers, who share the answer;
// another view judges it on its own. Not parallel: it sets testFilteredJudge.
func TestV075FilteredLiveCost(t *testing.T) {
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	var mu sync.Mutex
	judged := map[string]int{}
	testFilteredJudge = func(vid, name string) {
		mu.Lock()
		judged[vid+"/"+name]++
		mu.Unlock()
	}
	t.Cleanup(func() { testFilteredJudge = nil })
	li, bo := w.li(), w.bo()
	lvid, bvid := v075ViewID(t, w, li), v075ViewID(t, w, bo)
	var lkey, bkey string
	w.inTx(func(t2 *tx) {
		lkey, bkey = v075View(t, t2, "matches", li).j.key, v075View(t, t2, "matches", bo).j.key
	})
	since := w.head("matches")
	w.put("matches", "derby", map[string]any{"v": 2})
	poll := func(cred Credentials, vid string) []string {
		t.Helper()
		lg, info, err := w.e.FilteredLiveLog(ctx, "matches", vid, since, 100, cred)
		if err != nil || lg.Status != 200 || info.View != vid || lg.Last != w.head("matches") {
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
			if got := poll(li, lvid); !reflect.DeepEqual(got, []string{"derby"}) {
				t.Errorf("li: %v", got)
			}
		}()
	}
	wg.Wait()
	if got := poll(bo, bvid); len(got) != 0 {
		t.Fatalf("bo: %v", got)
	}
	if judged[lkey+"/derby"] != 1 || judged[bkey+"/derby"] != 1 {
		t.Fatalf("judgements %v", judged)
	}
	// The next wake, with a new at: judged again, once.
	w.put("matches", "derby", map[string]any{"v": 3})
	since = w.head("matches")
	w.put("matches", "derby", map[string]any{"v": 4})
	poll(li, lvid)
	poll(li, lvid)
	if judged[lkey+"/derby"] != 2 {
		t.Fatalf("judgements after the next wake %v", judged)
	}
}

// §7.9 Answers (TDA 68; v0.78: "a partial reader's /branches is 403"):
// /branches to a partial reader is 403, as for any reader without
// unrestricted read, a grant that also names a branch included. Before
// v0.78 it listed, Private, the local branches its grant verified in.
// It passes once ACCESS-9's reads.go change is in (V81-01).
func TestV075BranchListPartial(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", At: w.head("matches"), Patches: []any{}, IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	all, err := w.e.BranchList(ctx, "matches", "", w.admin)
	if err != nil || len(all.List) != 1 {
		t.Fatalf("admin: %+v %v", all, err)
	}
	if bl, err := w.e.BranchList(ctx, "matches", "", w.li()); v75Status(err) != 403 {
		t.Fatalf("li: %+v %v, want 403", bl, err)
	}
	both := w.li(map[string]any{"ns": []any{"matches", "matches-r7"}})
	if bl, err := w.e.BranchList(ctx, "matches", "", both); v75Status(err) != 403 {
		t.Fatalf("li in both: %+v %v, want 403", bl, err)
	}
	// Uncovered: 403, as before v0.75.
	w2 := newV75World(t, v75Opts{engine: func(o *Options) { o.NoFilteredReads = true }})
	if _, err := w2.e.BranchList(ctx, "matches", "", w2.li()); v75Status(err) != 403 {
		t.Fatalf("NoFilteredReads: %v", err)
	}
}

// §7.9 URLs, at: a partial reader's redirect names an at recorded
// before it is answered, which filteredAt then answers.
func TestV075RedirectRecordsAt(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	_, err := w.e.NamespaceHeads(ctx, "matches", w.head("matches"), "", w.li())
	fr, ok := err.(*FilteredRedirect)
	if !ok || fr.At == "" || fr.NS != "matches" || fr.View != v075ViewID(t, w, w.li()) {
		t.Fatalf("redirect %v", err)
	}
	// Events and long-poll carry no at, and record none.
	_, err = w.e.NamespaceEvents(ctx, "matches", "", 10, w.li())
	if fr, ok := err.(*FilteredRedirect); !ok || fr.At != "" {
		t.Fatalf("events redirect %v", err)
	}
	// The filtered page at it, after a write moved the current at.
	w.put("matches", "derby", map[string]any{"v": 2})
	page, info, err := w.e.FilteredHeads(ctx, "matches", fr.View, fr.At, "", "", w.li())
	if err != nil || info.At != fr.At || len(page.Items) != 2 {
		t.Fatalf("at the recorded at: %+v %+v %v", page, info, err)
	}
}

// §7.3, §8.5: a namespace stream ends after its purge-ns event. A filtered
// live read's page runs to its admission's checkpoint; a purge committed
// between the admission and the page's read is past it, so that page
// isn't marked Purged (which ends a stream without the purge-ns), and the
// next fetch gives the purge-ns entry. Not parallel: it sets
// testFilteredLiveRead.
func TestV075FilteredLivePurgeAfterAdmission(t *testing.T) {
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	vid := v075ViewID(t, w, li)
	since := w.head("matches")
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/frozen", "value": true})
	op := w.cred(w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"}})
	var once sync.Once
	testFilteredLiveRead = func() {
		once.Do(func() {
			if _, err := w.e.PurgeNamespace(ctx, Request{NS: "matches", Cred: op}, w.head("matches"), true); err != nil {
				t.Errorf("purge: %v", err)
			}
		})
	}
	t.Cleanup(func() { testFilteredLiveRead = nil })
	lg, _, err := w.e.FilteredLiveLog(ctx, "matches", vid, since, 100, li)
	if err != nil || lg.Status != 200 || len(lg.Entries) != 1 || lg.Entries[0]["kind"] != "config" {
		t.Fatalf("first page: %+v %v", lg, err)
	}
	if lg.Purged || lg.More {
		t.Fatalf("a page before the purge-ns is Purged %v, More %v", lg.Purged, lg.More)
	}
	lg, _, err = w.e.FilteredLiveLog(ctx, "matches", vid, lg.Last, 100, li)
	if err != nil || lg.Status != 200 || len(lg.Entries) != 1 || lg.Entries[0]["kind"] != "purge-ns" || !lg.Purged || lg.More {
		t.Fatalf("next page: %+v %v", lg, err)
	}
	if _, _, err = w.e.FilteredLiveLog(ctx, "matches", vid, lg.Last, 100, li); v75Status(err) != 410 {
		t.Fatalf("from the purge-ns: %v", err)
	}
}
