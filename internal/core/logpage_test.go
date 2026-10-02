package core

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A page of a resource log range costs its own rows, whatever the range's
// length (§7.1 Paging): the rows of the range past the page are made
// unreadable, and the pages that don't reach them still answer, while the
// whole range (and the page that reaches them) fails. Reading the range
// from its id back to since for every page made reading a long range in
// pages quadratic.
func TestLogPageReadsItsRows(t *testing.T) {
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	ctx := context.Background()
	var revs []string
	head := ""
	for i := 0; i < 40; i++ {
		if head, err = put(e, "n", "a", head, i); err != nil {
			t.Fatal(err)
		}
		revs = append(revs, head)
	}
	// Every row after revs[5] but the head (which the read resolves) can't
	// be scanned any more: created isn't a number.
	if err := e.update(ctx, func(t *tx) error {
		var lo int64
		id := mustID(revs[5])
		if err := t.QueryRow(`SELECT r.seq FROM revisions r JOIN resources o ON o.res = r.res WHERE o.name = 'a' AND r.id = ?`, id[:]).Scan(&lo); err != nil {
			return err
		}
		set := `created = 'unreadable'`
		if t.e.pg {
			if _, err := t.Exec(`ALTER TABLE revisions ALTER COLUMN created DROP NOT NULL`); err != nil {
				return err
			}
			set = `created = NULL`
		}
		_, err := t.Exec(`UPDATE revisions SET `+set+` WHERE seq > ? AND res = (SELECT res FROM revisions WHERE seq = ?) AND seq < (SELECT head_seq FROM resources WHERE name = 'a')`, lo, lo)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	page := func(since string, limit int) (*Log, error) {
		return e.ResourceLog(ctx, "n", "a", head, since, limit, Credentials{})
	}
	for _, c := range []struct {
		since string
		want  []string
	}{
		{"", revs[0:3]},
		{revs[0], revs[1:4]},
		{revs[2], revs[3:6]},
	} {
		lg, err := page(c.since, 3)
		if err != nil {
			t.Fatalf("page after %q: %v", c.since, err)
		}
		if lg.Status != 200 || !lg.More || len(lg.Entries) != 3 || lg.Last != c.want[2] {
			t.Fatalf("page after %q: %d, more %v, %d entries, last %s", c.since, lg.Status, lg.More, len(lg.Entries), lg.Last)
		}
		prev := ""
		if c.since != "" {
			prev = c.since
		}
		for i, m := range lg.Entries {
			if m["id"] != c.want[i] || (prev != "" && m["parent"] != prev) {
				t.Fatalf("page after %q: entry %d is %v", c.since, i, m)
			}
			prev = c.want[i]
		}
	}
	// The rows are really unreadable: a page reaching them fails, and so
	// does the whole range.
	if _, err := page(revs[3], 3); err == nil {
		t.Fatal("a page over unreadable rows answered")
	}
	if _, err := page("", 0); err == nil {
		t.Fatal("the whole range answered over unreadable rows")
	}
	// The empty range at the head reads no other row.
	if lg, err := page(head, 3); err != nil || lg.Status != 200 || len(lg.Entries) != 0 || lg.More {
		t.Fatalf("empty range: %v %+v", err, lg)
	}
}

// A page reads a resource's rows in seq order, which is its chain only
// while every row's parent is the row before it. The schema allows one
// first row and one child per parent in a resource, but not that a later
// row's parent is in the same resource, so a broken chain is an error, not
// a range answering rows that aren't ancestors of its id.
func TestLogPageBrokenChain(t *testing.T) {
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	ctx := context.Background()
	var revs []string
	head := ""
	for i := 0; i < 4; i++ {
		if head, err = put(e, "n", "a", head, i); err != nil {
			t.Fatal(err)
		}
		revs = append(revs, head)
	}
	other, err := put(e, "n", "b", "", 99)
	if err != nil {
		t.Fatal(err)
	}
	for _, since := range []string{"", revs[0]} {
		if lg, err := e.ResourceLog(ctx, "n", "a", head, since, 2, Credentials{}); err != nil || lg.Status != 200 {
			t.Fatalf("before, after %q: %v %+v", since, err, lg)
		}
	}
	// revs[2]'s parent is now b's revision: revs[0] and revs[1] are no
	// ancestors of the head by the parent links, though still before it
	// in a's seq order.
	seqOf := func(t *tx, id string) (seq int64) {
		b := mustID(id)
		t.must(t.QueryRow(`SELECT seq FROM revisions WHERE id = ?`, b[:]).Scan(&seq))
		return seq
	}
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE revisions SET parent_seq = ? WHERE seq = ?`, seqOf(t, other), seqOf(t, revs[2]))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		since string
		limit int
	}{{"", 0}, {"", 3}, {revs[0], 2}, {revs[1], 1}} {
		if lg, err := e.ResourceLog(ctx, "n", "a", head, c.since, c.limit, Credentials{}); err == nil {
			t.Errorf("broken chain after %q, limit %d: answered %d entries", c.since, c.limit, len(lg.Entries))
		}
	}
	// A page that doesn't reach the break still answers.
	if lg, err := e.ResourceLog(ctx, "n", "a", head, "", 2, Credentials{}); err != nil || lg.Status != 200 || len(lg.Entries) != 2 {
		t.Fatalf("page before the break: %v %+v", err, lg)
	}
}
