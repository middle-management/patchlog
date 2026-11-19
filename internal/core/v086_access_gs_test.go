package core

import (
	"context"
	"testing"
	"time"
)

// v86gsReads checks cookie's reads of matches' filtered URLs for gs at the
// current checkpoint, the later at of CONFORMANCE Access 145: /heads and
// the log range there, and the long-poll, whose read is the event
// stream's too (FilteredLiveLog). want is the status, 0 where served.
func v86gsReads(t *testing.T, w *v75World, what, gs string, cookie Credentials, want int) {
	t.Helper()
	ctx := context.Background()
	red, st := v76fRedirect(t, w, "matches", gs, cookie)
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
	if _, st := v76fHeads(t, w, "matches", gs, at, cookie); st != want {
		t.Errorf("%s, /heads at the current at: status %d (0 = served), want %d", what, st, want)
	}
	if _, _, err := w.e.FilteredLog(ctx, "matches", gs, at, "", 10, cookie); v75Status(err) != want {
		t.Errorf("%s, the log range at the current at: %v, want %d (0 = served)", what, err, want)
	}
	if _, _, err := w.e.FilteredLiveLog(ctx, "matches", gs, "", 10, cookie); v75Status(err) != want {
		t.Errorf("%s, long-poll and events: %v, want %d (0 = served)", what, err, want)
	}
}

// CONFORMANCE Access 145 at the origin (SERVICES §B.11.9 gs, v0.86): "Once
// an entry after its exchange changes one of them, the cookie is 403 from
// that entry on, even where a later entry undoes the change." li holds a
// filtered gs cookie for matches; matches changes the groups scope of the
// key her grant came from, then changes it back in a later config entry,
// and nobody exchanges in between: at the later at her cookie is 403, on
// /heads, the log range, long-poll and events, until she exchanges again.
// Before v0.86 the cookie read again after the undo: the document at the
// later at gives the entry digest the exchange recorded.
func TestV086AccessGSChangeUndone(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, gs := v82accessCookie(t, w, w.li())
	v86gsReads(t, w, "li's cookie before the change", gs, cookie, 0)
	before, _ := v76fRedirect(t, w, "matches", gs, cookie)

	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	v86gsReads(t, w, "li's cookie after the key's groups scope changed", gs, cookie, 403)
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	v86gsReads(t, w, "li's cookie after the change was undone", gs, cookie, 403)
	// Other entries after the undo change nothing of that.
	w.patchConfig("matches", v82accessOp("add", "/x-note", "later"))
	w.put("matches", "later", map[string]any{"n": 1.0})
	v86gsReads(t, w, "li's cookie, later entries after the undo", gs, cookie, 403)
	// "From that entry on": at the at from before the change, which is
	// before that entry, the cookie reads as it did.
	if _, st := v76fHeads(t, w, "matches", gs, before.At, cookie); st != 0 {
		t.Errorf("li's cookie at the at from before the change: status %d, want it served", st)
	}

	// She exchanges again: the new cookie reads, the old one stays ended.
	v82accessLater(w, time.Second)
	again, gs2 := v82accessCookie(t, w, w.li())
	if gs2 != gs {
		t.Fatalf("li's gs after the undo %s, was %s", gs2, gs)
	}
	v86gsReads(t, w, "li's cookie from the exchange after the undo", gs, again, 0)
	v86gsReads(t, w, "li's old cookie after she exchanged again", gs, cookie, 403)
}

// The same where another reader of the same gs, not li, exchanges after
// the undo: the row's entry digest is the one li's exchange recorded, so
// nothing replaces it, and li's cookie from before the change stays
// ended all the same (recordFilteredGS: the row's conf is below a
// document the record doesn't hold under).
func TestV086AccessGSChangeUndoneOtherExchanges(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	reader := func(sub string) Credentials { return w.catGrant(sub, []any{"editors"}) }
	bo, gs := v82accessCookie(t, w, reader("user:bo"))
	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	v82accessLater(w, time.Second)
	cy, cyGS := v82accessCookie(t, w, reader("user:cy"))
	if cyGS != gs {
		t.Fatalf("bo and cy have different gs: %s, %s", gs, cyGS)
	}
	v86gsReads(t, w, "cy's cookie from after the undo", gs, cy, 0)
	v86gsReads(t, w, "bo's cookie from before the change, after cy's exchange", gs, bo, 403)
	// Exchanges under an unchanged document replace nothing: cy's reads
	// on after bo exchanges again.
	v82accessLater(w, time.Second)
	bo2, _ := v82accessCookie(t, w, reader("user:bo"))
	v86gsReads(t, w, "bo's cookie after bo exchanged again", gs, bo2, 0)
	v86gsReads(t, w, "cy's cookie after bo's exchange", gs, cy, 0)
	v86gsReads(t, w, "bo's old cookie", gs, bo, 403)
}

// Access 145, last sentence: "Both changes in one batch → her cookies
// hold": a config entry is judged as a whole, by the document it leaves,
// and so is a change to a member the cookie drew on nothing of.
func TestV086AccessGSChangeAndUndoInOneEntry(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, gs := v82accessCookie(t, w, w.li())
	w.patchConfig("matches",
		v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}),
		map[string]any{"op": "remove", "path": "/keys/1/groups"},
		v82accessOp("add", "/x-note", "one entry"))
	v86gsReads(t, w, "li's cookie after a change and its undo in one entry", gs, cookie, 0)
	w.patchConfig("matches", v82accessOp("add", "/x-other", true))
	v86gsReads(t, w, "li's cookie after an unrelated config entry", gs, cookie, 0)
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
	// What an exchange reads, without recording it.
	var rec *gsRecord
	li := w.li()
	if err := w.e.read(ctx, func(t2 *tx) error {
		n := t2.nsByName("matches")
		a, _, _, err := t2.nsAccess(n, li)
		if err != nil {
			return err
		}
		// Its cookie ends before one from a later exchange does.
		iss, err := t2.filteredEdgeGrant(n, t2.filteredScope(n), a, w.now().Add(5*time.Minute))
		if err != nil {
			return err
		}
		rec = iss.rec
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rec.conf == 0 || rec.entry == "" {
		t.Fatalf("the exchange's record: conf %d, entry %q", rec.conf, rec.entry)
	}
	w.patchConfig("matches", v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}))
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/groups"})
	if err := w.e.recordFilteredGS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: rec.gs, Prefix: "/ns/matches/g/" + rec.gs, Exp: time.Unix(rec.exp, 0)}}
	v86gsReads(t, w, "the cookie of an exchange that read before the change", rec.gs, cookie, 403)
	// A reader exchanging now gets a cookie that reads.
	v82accessLater(w, time.Second)
	fresh, _ := v82accessCookie(t, w, w.li())
	v86gsReads(t, w, "a cookie from an exchange after the undo", rec.gs, fresh, 0)
	v86gsReads(t, w, "the earlier cookie after that exchange", rec.gs, cookie, 403)
}

// A row from before conf was kept never holds (migration: conf 0), and a
// cookie is refused where more namespace documents than gsWalk lie
// between its exchange and the checkpoint, whatever they changed.
func TestV086AccessGSFailsClosed(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, gs := v82accessCookie(t, w, w.li())
	for i := 0; i < gsWalk; i++ {
		w.patchConfig("matches", v82accessOp("add", "/x-n", float64(i)))
	}
	v86gsReads(t, w, "li's cookie, gsWalk documents later", gs, cookie, 0)
	w.patchConfig("matches", v82accessOp("add", "/x-n", "one more"))
	v86gsReads(t, w, "li's cookie, more than gsWalk documents later", gs, cookie, 403)
	v82accessLater(w, time.Second)
	again, _ := v82accessCookie(t, w, w.li())
	v86gsReads(t, w, "li's cookie after exchanging again", gs, again, 0)
	if err := w.e.update(context.Background(), func(t2 *tx) error {
		_, err := t2.Exec(`UPDATE filtered_gs SET conf = 0`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	v86gsReads(t, w, "a cookie whose row has no conf", gs, again, 403)
}
