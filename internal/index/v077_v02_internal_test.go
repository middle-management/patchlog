package index

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// V77-02 (v0.77): unit tests of the index's own predicates and mappings.

// TestV077LacksKey408 (FSVC-11 / ENC-3; §A.4: "a 4xx other than 408 and
// 429" lacks keys; §A.1: "a schema or key fetch that fails transiently
// (transport error, 5xx, 408, 429) is retried"): a /keys 408 is for now,
// never lacking the key, and a schema revision answering 408 isn't final.
func TestV077LacksKey408(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, st := range []int{408, 429, 500, 503} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: st, Path: "/ns/x/keys"})
		if lacksKey(ctx, err) {
			t.Errorf("lacksKey of a /keys %d: true, want false (transient)", st)
		}
		if unavailable(&client.APIError{Status: st, Path: "/r/schemas/s/rev/x"}) {
			t.Errorf("a schema %d is final, want retried", st)
		}
	}
	for _, st := range []int{400, 401, 403, 404, 410} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: st, Path: "/ns/x/keys"})
		if !lacksKey(ctx, err) {
			t.Errorf("lacksKey of a /keys %d: false, want true", st)
		}
		if !unavailable(&client.APIError{Status: st, Path: "/r/schemas/s/rev/x"}) {
			t.Errorf("a schema %d isn't final", st)
		}
	}
}

// TestV077JudgeEpochs (ENC-5; §E.2.6: the epoch of a revision a hit
// derives from is "judged once, when the service first seals a value
// derived from it"): a pending docs.epoch is judged by the first answer,
// and a later one under another epoch reads that back; a row that holds
// another head now isn't judged; rewriting the row with the same head and
// a pending epoch (an apply again) keeps the judgement, and a new head
// is pending again.
func TestV077JudgeEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
	res := must(ix.db.Exec(`INSERT INTO docs (ns, resource, head, schema, epoch) VALUES ('n', 'r', 'h1', NULL, NULL)`))
	id := must(res.LastInsertId())
	if got := must(ix.judgeEpochs(ctx, []docHead{{id, "h1"}}, 5)); got[id] != 5 {
		t.Fatalf("first judgement: %v", got)
	}
	if got := must(ix.judgeEpochs(ctx, []docHead{{id, "h1"}}, 6)); got[id] != 5 {
		t.Errorf("second judgement: %v, want the first's 5", got)
	}
	if got := must(ix.judgeEpochs(ctx, []docHead{{id, "h0"}}, 6)); len(got) != 0 {
		t.Errorf("a head the row no longer holds: %v", got)
	}
	epoch := func() int {
		var e sql.NullInt64
		if err := ix.db.QueryRow(`SELECT epoch FROM docs WHERE docid = ?`, id).Scan(&e); err != nil {
			t.Fatal(err)
		}
		return int(e.Int64)
	}
	write := func(head string) {
		tx := must(ix.db.Begin())
		defer tx.Rollback()
		if err := ix.write(ctx, tx, "n", prepared{resource: "r", head: head, typed: true}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	write("h1")
	if e := epoch(); e != 5 {
		t.Errorf("after the same head is written again: epoch %d, want 5", e)
	}
	write("h2")
	if e := epoch(); e != 0 {
		t.Errorf("after a new head: epoch %d, want pending", e)
	}
}
