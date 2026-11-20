package core

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// v86viewReads checks cookie's reads of matches' filtered URLs for view at the
// current checkpoint, the later at of CONFORMANCE Access 145: /heads and
// the log range there, and the long-poll, whose read is the event
// stream's too (FilteredLiveLog). want is the status, 0 where served.
func v86viewReads(t *testing.T, w *v75World, what, vid string, cookie Credentials, want int) {
	t.Helper()
	ctx := context.Background()
	red, st := v76fRedirect(t, w, "matches", vid, cookie)
	if st != want {
		t.Errorf("%s, the redirect to the current at: status %d (0 = served), want %d", what, st, want)
	}
	at := ""
	if red != nil {
		at = red.At
	} else {
		// The cookie is refused its redirect: the at an admitted reader
		// is sent to.
		w.inTx(func(t2 *tx) { at = t2.filteredCurrent(t2.filteredScope(t2.nsByName("matches"))).at })
	}
	if _, st := v76fHeads(t, w, "matches", vid, at, cookie); st != want {
		t.Errorf("%s, /heads at the current at: status %d (0 = served), want %d", what, st, want)
	}
	if _, _, err := w.e.FilteredLog(ctx, "matches", vid, at, "", 10, cookie); v75Status(err) != want {
		t.Errorf("%s, the log range at the current at: %v, want %d (0 = served)", what, err, want)
	}
	if _, _, err := w.e.FilteredLiveLog(ctx, "matches", vid, "", 10, cookie); v75Status(err) != want {
		t.Errorf("%s, long-poll and events: %v, want %d (0 = served)", what, err, want)
	}
}

// CONFORMANCE Access 145 at the origin (SERVICES §7.9 view, v0.86): "Once
// an entry after its exchange changes one of them, the cookie is 403 from
// that entry on, even where a later entry undoes the change." li holds a
// filtered view cookie for matches; matches changes the groups scope of the
// key her grant came from, then changes it back in a later config entry,
// and nobody exchanges in between: at the later at her cookie is 403, on
// /heads, the log range, long-poll and events, until she exchanges again.
// Before v0.86 the cookie read again after the undo: the document at the
// later at gives the entry digest the exchange recorded.
func TestV086AccessGSChangeUndone(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, vid := v82accessCookie(t, w, w.li())
	v86viewReads(t, w, "li's cookie before the change", vid, cookie, 0)
	before, _ := v76fRedirect(t, w, "matches", vid, cookie)

	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	v86viewReads(t, w, "li's cookie after the key's groups scope changed", vid, cookie, 403)
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	v86viewReads(t, w, "li's cookie after the change was undone", vid, cookie, 403)
	// Other entries after the undo change nothing of that.
	w.patchConfig("matches", v82accessOp("add", "/x-note", "later"))
	w.put("matches", "later", map[string]any{"n": 1.0})
	v86viewReads(t, w, "li's cookie, later entries after the undo", vid, cookie, 403)
	// "From that entry on": at the at from before the change, which is
	// before that entry, the cookie reads as it did.
	if _, st := v76fHeads(t, w, "matches", vid, before.At, cookie); st != 0 {
		t.Errorf("li's cookie at the at from before the change: status %d, want it served", st)
	}

	// She exchanges again: the new cookie reads, the old one stays ended.
	v82accessLater(w, time.Second)
	again, gs2 := v82accessCookie(t, w, w.li())
	if gs2 != vid {
		t.Fatalf("li's vid after the undo %s, was %s", gs2, vid)
	}
	v86viewReads(t, w, "li's cookie from the exchange after the undo", vid, again, 0)
	v86viewReads(t, w, "li's old cookie after she exchanged again", vid, cookie, 403)
}

// The same where another reader of the same view, not li, exchanges after
// the undo: the row's entry digest is the one li's exchange recorded, so
// its exchange can't share the record of li's cookie's second, a
// document between the two not holding, and li's cookie from before the
// change stays ended all the same (recordFilteredView, viewShares).
func TestV086AccessGSChangeUndoneOtherExchanges(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	reader := func(sub string) Credentials { return w.catGrant(sub, []any{"editors"}) }
	bo, vid := v82accessCookie(t, w, reader("user:bo"))
	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	v82accessLater(w, time.Second)
	cy, cyView := v82accessCookie(t, w, reader("user:cy"))
	if cyView != vid {
		t.Fatalf("bo and cy have different vid: %s, %s", vid, cyView)
	}
	v86viewReads(t, w, "cy's cookie from after the undo", vid, cy, 0)
	v86viewReads(t, w, "bo's cookie from before the change, after cy's exchange", vid, bo, 403)
	// Exchanges under an unchanged document replace nothing: cy's reads
	// on after bo exchanges again.
	v82accessLater(w, time.Second)
	bo2, _ := v82accessCookie(t, w, reader("user:bo"))
	v86viewReads(t, w, "bo's cookie after bo exchanged again", vid, bo2, 0)
	v86viewReads(t, w, "cy's cookie after bo's exchange", vid, cy, 0)
	v86viewReads(t, w, "bo's old cookie", vid, bo, 403)
}

// Access 145, last sentence: "Both changes in one batch → her cookies
// hold": a config entry is judged as a whole, by the document it leaves,
// and so is a change to a member the cookie drew on nothing of.
func TestV086AccessGSChangeAndUndoInOneEntry(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, vid := v82accessCookie(t, w, w.li())
	w.patchConfig("matches",
		v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}),
		map[string]any{"op": "remove", "path": "/keys/1/groups"},
		v82accessOp("add", "/x-note", "one entry"))
	v86viewReads(t, w, "li's cookie after a change and its undo in one entry", vid, cookie, 0)
	w.patchConfig("matches", v82accessOp("add", "/x-other", true))
	v86viewReads(t, w, "li's cookie after an unrelated config entry", vid, cookie, 0)
}

// An exchange that read matches before a change and records its row
// after the change was made, and undone, is one from before the change:
// its row keeps the document it read, so its cookie is 403 at the later
// at like any from before (the race between an exchange's read and its
// record). It fails closed for the readers sharing the row, who exchange
// again.
func TestV086AccessGSExchangeAcrossChange(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	// What an exchange reads, without recording it. Its cookie ends
	// before one from a later exchange does.
	rec := v86gsRead(t, w, w.li(), w.now().Add(5*time.Minute))
	if rec.conf == 0 || rec.entry == "" {
		t.Fatalf("the exchange's record: conf %d, entry %q", rec.conf, rec.entry)
	}
	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	if err := w.e.recordFilteredView(ctx, rec); err != nil {
		t.Fatal(err)
	}
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", View: rec.view, Prefix: "/ns/matches/view/" + rec.view, Exp: time.Unix(rec.exp, 0)}}
	v86viewReads(t, w, "the cookie of an exchange that read before the change", rec.view, cookie, 403)
	// A reader exchanging now gets a cookie that reads.
	v82accessLater(w, time.Second)
	fresh, _ := v82accessCookie(t, w, w.li())
	v86viewReads(t, w, "a cookie from an exchange after the undo", rec.view, fresh, 0)
	v86viewReads(t, w, "the earlier cookie after that exchange", rec.view, cookie, 403)
}

// A cookie with no record of its own, one from before they were kept,
// is refused, and so is one where more namespace documents than viewWalk
// lie between its exchange and the checkpoint, whatever they changed.
func TestV086AccessGSFailsClosed(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, vid := v82accessCookie(t, w, w.li())
	for i := 0; i < viewWalk; i++ {
		w.patchConfig("matches", v82accessOp("add", "/x-n", float64(i)))
	}
	v86viewReads(t, w, "li's cookie, viewWalk documents later", vid, cookie, 0)
	w.patchConfig("matches", v82accessOp("add", "/x-n", "one more"))
	v86viewReads(t, w, "li's cookie, more than viewWalk documents later", vid, cookie, 403)
	v82accessLater(w, time.Second)
	again, _ := v82accessCookie(t, w, w.li())
	v86viewReads(t, w, "li's cookie after exchanging again", vid, again, 0)
	if err := w.e.update(context.Background(), func(t2 *tx) error {
		_, err := t2.Exec(`DELETE FROM filtered_view_exps`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	v86viewReads(t, w, "a cookie with no record of its own", vid, again, 403)
	// Its reader exchanges again, the grant she held included.
	li := w.li()
	c1, _ := v82accessCookie(t, w, li)
	v86viewReads(t, w, "the cookie of an exchange after that", vid, c1, 0)
}

// The sequence a grant that ends within the quarter of an hour used to
// fail (§C.5.2, SERVICES §A.4 view, CONFORMANCE Access 144; v0.86: "less
// any whole seconds a minter MAY take off so that cookies for one prefix
// that it must tell apart differ in exp"): li's grant G ends in ten
// minutes, so her cookie expires with G. A key change is made and undone,
// and she exchanges G again: the cookie expires a second earlier and
// reads, where one told apart by "expires no later than the ended ones"
// was 403 at every exchange until G expired. Each further change and
// exchange takes another second.
func TestV086AccessGSExchangeAgainSameGrant(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	g := w.li()
	first, vid := v82accessCookie(t, w, g)
	prev := first
	ended := []Credentials{}
	for i := 1; i <= 3; i++ {
		w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
		w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
		ended = append(ended, prev)
		next, _ := v82accessCookie(t, w, g)
		if want := first.Edge.Exp.Add(-time.Duration(i) * time.Second); !next.Edge.Exp.Equal(want) {
			t.Fatalf("exchange %d of the same grant: the cookie expires %v, want %v, a second before the last", i, next.Edge.Exp, want)
		}
		v86viewReads(t, w, "the cookie of the exchange after a change and its undo", vid, next, 0)
		for _, c := range ended {
			v86viewReads(t, w, "a cookie from before a change, after the re-exchange", vid, c, 403)
		}
		prev = next
	}
	// With nothing changed, an exchange shares the second it would get.
	same, _ := v82accessCookie(t, w, g)
	if !same.Edge.Exp.Equal(first.Edge.Exp.Add(-3 * time.Second)) {
		t.Errorf("an exchange with nothing changed expires %v, want the last cookie's second %v", same.Edge.Exp, prev.Edge.Exp)
	}
	v86viewReads(t, w, "the cookie of an exchange with nothing changed", vid, same, 0)
}

// Where no whole second is left before the grant's exp, the exchange is
// 503 behind with Retry-After and records nothing (Access 144, §C.5.2
// Answer, §12.1): a grant with two seconds left gives two cookies that
// must be told apart, and no third.
func TestV086AccessGSNoSecondLeft(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	g := w.li(map[string]any{"exp": w.now().Truncate(time.Second).Add(2 * time.Second).UTC().Format(time.RFC3339)})
	change := func() {
		w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
		w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	}
	c1, vid := v82accessCookie(t, w, g)
	change()
	c2, _ := v82accessCookie(t, w, g)
	v86viewReads(t, w, "the second cookie", vid, c2, 0)
	v86viewReads(t, w, "the first cookie", vid, c1, 403)
	change()
	res, err := w.e.IssueEdgeGrants(ctx, []string{g.Bearer})
	ae, _ := err.(*Error)
	if ae == nil || ae.Status != 503 || ae.Body["code"] != "behind" || ae.Header.Get("Retry-After") == "" {
		t.Fatalf("the third exchange: %+v %v, want 503 behind with Retry-After", res, err)
	}
	v86viewReads(t, w, "the second cookie after the change", vid, c2, 403)
	// A grant that lasts longer exchanges.
	c3, _ := v82accessCookie(t, w, w.li())
	v86viewReads(t, w, "the cookie of a grant that lasts longer", vid, c3, 0)
}

// v86gsRead is what an exchange of cred reads of matches, without
// recording it: the record recordFilteredView is then given.
func v86gsRead(t *testing.T, w *v75World, cred Credentials, exp time.Time) *viewRecord {
	t.Helper()
	var rec *viewRecord
	if err := w.e.read(context.Background(), func(t2 *tx) error {
		n := t2.nsByName("matches")
		a, _, _, err := t2.nsAccess(n, cred)
		if err != nil {
			return err
		}
		iss, err := t2.filteredEdgeGrant(n, t2.filteredScope(n), a, exp)
		if err != nil {
			return err
		}
		rec = iss.rec
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rec
}

// An exchange whose read predates a change and whose record lands after
// a newer exchange's moves nothing back: it can't share the newer
// cookie's record, a document between the two not holding, so it takes
// its own second and is the one that is 403, and the newer cookie reads
// on. Where every document between the two holds, they share a record,
// which keeps the later document.
func TestV086AccessGSStaleExchangeAfterNewer(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	exp := w.now().Truncate(time.Second).Add(10 * time.Minute)
	cookieOf := func(rec *viewRecord) Credentials {
		return Credentials{Edge: &EdgeGrant{NS: "matches", View: rec.view, Prefix: "/ns/matches/view/" + rec.view, Exp: time.Unix(rec.exp, 0)}}
	}
	slot := func(rec *viewRecord) (s viewSlot) {
		w.inTx(func(t2 *tx) { s, _ = t2.loadViewSlot("matches", rec.view, rec.exp) })
		return s
	}
	// Every document between holds: one record, at the later document.
	stale := v86gsRead(t, w, li, exp)
	w.patchConfig("matches", v82accessOp("add", "/x-note", "unrelated"))
	newer := v86gsRead(t, w, li, exp)
	if newer.conf <= stale.conf {
		t.Fatalf("documents: %d then %d", stale.conf, newer.conf)
	}
	for _, rec := range []*viewRecord{newer, stale} {
		if err := w.e.recordFilteredView(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	if stale.exp != newer.exp || slot(newer).conf != newer.conf {
		t.Fatalf("the stale exchange's cookie expires %d with record %+v, the newer one's %d at document %d: want one record, at the later document", stale.exp, slot(stale), newer.exp, newer.conf)
	}
	v86viewReads(t, w, "the newer cookie after the stale exchange's record", newer.view, cookieOf(newer), 0)

	// A change between them: the stale exchange takes its own second.
	// (Cookies of another minute, clear of the record above.)
	exp = exp.Add(-time.Minute)
	stale = v86gsRead(t, w, li, exp)
	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	newer = v86gsRead(t, w, li, exp)
	for _, rec := range []*viewRecord{newer, stale} {
		if err := w.e.recordFilteredView(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	if stale.exp >= newer.exp || slot(newer).conf != newer.conf || slot(stale).conf != stale.conf {
		t.Fatalf("the stale exchange's cookie expires %d (record %+v), the newer one's %d (record %+v): want a second of its own, each with its document", stale.exp, slot(stale), newer.exp, slot(newer))
	}
	v86viewReads(t, w, "the newer cookie after the stale exchange's record", newer.view, cookieOf(newer), 0)
	v86viewReads(t, w, "the stale exchange's cookie", stale.view, cookieOf(stale), 403)
}

// v86gsRows are the seconds matches has a cookie record at for view.
func v86gsRows(w *v75World, vid string) (exps []int64) {
	w.inTx(func(t2 *tx) {
		rows, err := t2.Query(`SELECT exp FROM filtered_view_exps WHERE ns = ? AND view = ? ORDER BY exp`, "matches", vid)
		t2.must(err)
		defer rows.Close()
		for rows.Next() {
			var exp int64
			t2.must(rows.Scan(&exp))
			exps = append(exps, exp)
		}
	})
	return exps
}

// §C.5.2: a prefix several grants of one exchange give gets one cookie,
// which lasts as long as the longest of them allows. Two grants of li's
// that give the same subject set of matches, one ending in two minutes
// and one in ten, in either order: one record, at the later grant's
// second, which both edge grants carry and whose cookie reads. (Each
// grant used to take a second of its own, and the cookie ended with the
// one recorded last.)
func TestV086AccessGSTwoGrantsOneCookie(t *testing.T) {
	t.Parallel()
	for _, order := range []string{"the shorter first", "the longer first"} {
		w := newV75World(t, v75Opts{})
		w.seed()
		long := w.now().Truncate(time.Second).Add(10 * time.Minute)
		grantUntil := func(exp time.Time) Credentials {
			return w.li(map[string]any{"exp": exp.UTC().Format(time.RFC3339)})
		}
		bearers := []string{grantUntil(long.Add(-8 * time.Minute)).Bearer, grantUntil(long).Bearer}
		if order == "the longer first" {
			bearers[0], bearers[1] = bearers[1], bearers[0]
		}
		res, err := w.e.IssueEdgeGrants(context.Background(), bearers)
		if err != nil || len(res.Grants) != 2 {
			t.Fatalf("%s: %+v %v", order, res, err)
		}
		vid := res.Grants[0].View
		for _, g := range res.Grants {
			if g.View != vid || !g.Exp.Equal(long) {
				t.Errorf("%s: edge grant %+v, want vid %s until %v, the longer grant's exp", order, g, vid, long)
			}
		}
		if rows := v86gsRows(w, vid); len(rows) != 1 || rows[0] != long.Unix() {
			t.Errorf("%s: cookie records at %v, want one, at %d", order, rows, long.Unix())
		}
		cookie := Credentials{Edge: &EdgeGrant{NS: "matches", View: vid, Prefix: "/ns/matches/view/" + vid, Exp: long}}
		v86viewReads(t, w, order+": the cookie", vid, cookie, 0)
	}
}

// Cookie records are swept a minute after their exp, not at it: an
// instance whose clock is ahead doesn't free a second that an exchange
// at one behind could take while an ended cookie of that exp lives.
func TestV086AccessGSSweepMargin(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	short := w.now().Truncate(time.Second).Add(2 * time.Second)
	c, vid := v82accessCookie(t, w, w.li(map[string]any{"exp": short.UTC().Format(time.RFC3339)}))
	has := func() bool { return slices.Contains(v86gsRows(w, vid), c.Edge.Exp.Unix()) }
	v82accessLater(w, 30*time.Second)
	v82accessCookie(t, w, w.li()) // an exchange sweeps
	if !has() {
		t.Fatal("the record was swept within a minute of its exp")
	}
	v82accessLater(w, viewSweepMargin)
	v82accessCookie(t, w, w.li())
	if has() {
		t.Fatal("the record was kept past the margin")
	}
}

// A read under a cookie past its exchange's document judges the
// documents between once: the verdict is kept (viewHeldSince), and later
// reads at that document read none of them again.
func TestV086AccessGSVerdictKept(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, vid := v82accessCookie(t, w, w.li())
	for i := 0; i < 20; i++ {
		w.patchConfig("matches", v82accessOp("add", "/x-n", float64(i)))
	}
	red, _ := v76fRedirect(t, w, "matches", vid, cookie)
	if red == nil {
		t.Fatal("the cookie doesn't read")
	}
	var mu sync.Mutex
	walked := 0
	w.e.onStatement = func(q string, _ []any) {
		if strings.Contains(q, "SELECT parent_seq FROM ns_config") {
			mu.Lock()
			walked++
			mu.Unlock()
		}
	}
	defer func() { w.e.onStatement = nil }()
	for i := 0; i < 3; i++ {
		if _, st := v76fHeads(t, w, "matches", vid, red.At, cookie); st != 0 {
			t.Fatalf("read %d: status %d", i, st)
		}
	}
	if walked != 0 {
		t.Errorf("reads after the first walked %d documents again", walked)
	}
	// The kept verdict is the record's: another cookie's is its own.
	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	v86viewReads(t, w, "the cookie after a change", vid, cookie, 403)
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	v86viewReads(t, w, "the cookie after the undo", vid, cookie, 403)
	fresh, _ := v82accessCookie(t, w, w.li())
	v86viewReads(t, w, "a cookie from after the undo", vid, fresh, 0)
}
