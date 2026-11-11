package tree_test

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
)

// v82Exec runs stmts on the store at db, its service stopped.
func v82Exec(t *testing.T, db string, stmts ...string) {
	t.Helper()
	sq := must(sql.Open("sqlite", db))
	defer sq.Close()
	for _, s := range stmts {
		if _, err := sq.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// v82Meta is meta row k of the store at db, "" where there is none.
func v82Meta(t *testing.T, db, k string) string {
	t.Helper()
	sq := must(sql.Open("sqlite", db))
	defer sq.Close()
	var v string
	if err := sq.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return v
}

// SVC-07 against stored data (SERVICES §E.2.6 Per-entry sealing, §B.5
// Previews): an earlier release's preview service judged a head read
// through from the base under the base's current epoch and stored that
// number (nodes.epoch), which is no epoch of the branch whose keys seal
// the preview now. Here the base is at cat#1 and the branch at catb#2,
// with 1 stored for n: read as the branch's, n would be sealed under
// catb#1, which the branch rotated away from before n was first sealed.
// On a store that doesn't record whose epochs it holds (meta "keyns"), a
// preview drops them and judges again: meanwhile n is by name only, the
// listing stored under catb#1 isn't served, and n is then sealed under
// catb#2, as a store judged afresh has it (the control). A restart
// judges nothing again.
func TestV082PreviewStoredEpochsRejudged(t *testing.T) {
	t.Parallel()
	const path = "/cat/children?of=root"
	for _, stored := range []bool{false, true} {
		name := "judged afresh"
		if stored {
			name = "an epoch of the base stored"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := newV081Preview(t)
			must(p.x2.RotateEpoch(ctx, "catb", p.svcPriv.PublicKey())) // catb#2, cat#1
			rd := p.k.Grant(t, p.s.Now(), "user:r", []string{"cat", "catb"}, []string{"read"})
			x := p.start(t)
			if got := v82Meta(t, p.db, "keyns"); got != "catb" {
				t.Errorf("meta keyns %q, want the branch", got)
			}
			if stored {
				x.stop()
				// What the earlier release stored, and the listing a
				// store read as the branch's would give: under catb#1.
				v82Exec(t, p.db, `UPDATE nodes SET epoch = 1 WHERE name = 'n'`)
				x = p.start(t)
				if kid, _, _ := v077Sealed(t, x, path, rd, "n", p.keyOf); kid != "catb#1" {
					t.Fatalf("the fixture: n sealed under %s, want the misbound catb#1", kid)
				}
				x.stop()
				v82Exec(t, p.db, `DELETE FROM meta WHERE k = 'keyns'`)
				release := make(chan struct{})
				x = startSvc(t, p.sc(v077Blocking("/r/catb/n", release)), svcOpts{now: p.s.Now, db: p.db}, p.opts)
				done := v82Release(t, release)
				p.reach(t, x)
				if e, _ := v077Epochs(t, p.db, "n"); e != 0 || !x.s.EpochsPending() || v82Meta(t, p.db, "keyns") != "catb" {
					t.Errorf("on start: n's epoch %d, pending %v, keyns %q; want it dropped, pending and the branch recorded", e, x.s.EpochsPending(), v82Meta(t, p.db, "keyns"))
				}
				// The window: the stored listing under catb#1 is gone.
				waitFor(t, "a listing", func() bool { return x.listingAs(path, rd).status == http.StatusOK })
				f := x.fetch(path, rd)
				if f.header.Get("Content-Type") != "application/json" {
					t.Fatalf("before n is judged again: %s %s", f.header.Get("Content-Type"), f.body)
				}
				v82NameOnly(t, "n, its epoch not judged again", entriesOf(t, decode(t, f.body))["n"])
				done()
				waitFor(t, "the epochs to be read in again", func() bool { return !x.s.EpochsPending() })
			}
			kid, vals, _ := v077Sealed(t, x, path, rd, "n", p.keyOf)
			if kid != "catb#2" || vals["title"] != "N" {
				t.Errorf("n %v sealed under %s, want catb#2, the branch's epoch in force", vals, kid)
			}
			x.stop()
			x = p.start(t)
			if e, _ := v077Epochs(t, p.db, "n"); e != 2 || x.s.EpochsPending() {
				t.Errorf("after a restart: n's epoch %d, pending %v; want 2 kept", e, x.s.EpochsPending())
			}
		})
	}
}

// The other direction: the base was an epoch ahead of the branch when
// the earlier release judged n (2 stored; the branch has only catb#1).
// Read as the branch's, n would be by name only for good; judged again,
// it is sealed under catb#1.
func TestV082PreviewStoredEpochAheadRejudged(t *testing.T) {
	t.Parallel()
	p := newV081Preview(t)
	x := p.start(t)
	x.stop()
	v82Exec(t, p.db, `UPDATE nodes SET epoch = 2 WHERE name = 'n'`, `DELETE FROM meta WHERE k = 'keyns'`)
	x = p.start(t)
	waitFor(t, "the epochs to be read in again", func() bool { return !x.s.EpochsPending() })
	rd := p.k.Grant(t, p.s.Now(), "user:r", []string{"cat", "catb"}, []string{"read"})
	if kid, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "n", p.keyOf); kid != "catb#1" || vals["title"] != "N" {
		t.Errorf("n %v sealed under %s, want catb#1", vals, kid)
	}
}

// A service that is no preview judged its epochs under the catalog's own
// keys: on a store that doesn't record it they are kept, nothing is read
// in again, and the catalog is recorded.
func TestV082StoredEpochsKeptOutsidePreview(t *testing.T) {
	t.Parallel()
	q := newV82Sealed(t)
	x := startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")
	waitFor(t, "the epochs", func() bool { return !x.s.EpochsPending() })
	e, b := v077Epochs(t, q.db, "old")
	if e == 0 {
		t.Fatalf("the fixture: old's epoch isn't stored")
	}
	x.stop()
	q.exec(`DELETE FROM meta WHERE k = 'keyns'`)
	x = startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	if e2, b2 := v077Epochs(t, q.db, "old"); e2 != e || b2 != b || x.s.EpochsPending() || v82Meta(t, q.db, "keyns") != "cat" {
		t.Errorf("old's epochs %d, %d (were %d, %d), pending %v, keyns %q; want them kept and the catalog recorded",
			e2, b2, e, b, x.s.EpochsPending(), v82Meta(t, q.db, "keyns"))
	}
}
