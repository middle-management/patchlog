package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
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

// fakeChain is grantcheck's chain error as the index sees it, by its
// ChainUnreadable method alone; its Error names the catalog, which no
// answer may.
type fakeChain struct{ transient bool }

func (e fakeChain) Error() string         { return "namespace cat-season: cannot read its chain" }
func (e fakeChain) ChainUnreadable() bool { return e.transient }

// TestV077ChainUnreadable (FSVC-10 / FCORE-3; §C.4 requireAt: "A verifier
// that can't read the chain answers 503 (behind) while the cause is
// transient (§A.1), and 502 (upstream) otherwise, naming no namespace,
// never 403"): a read check failing so is 503 behind with Retry-After, or
// 502 upstream, its body naming no namespace, even where the error is also
// a 403 (a grant check that wrapped it), at a query, at /_refs and at a
// view (writeAccessErr, writeCoverErr, writeUpstreamErr).
func TestV077ChainUnreadable(t *testing.T) {
	t.Parallel()
	ix := &Index{opt: Options{Logf: func(string, ...any) {}}}
	for _, c := range []struct {
		name   string
		err    error
		status int
	}{
		{"transient", fakeChain{true}, 503},
		{"lasting", fakeChain{false}, 502},
		{"transient, also a 403", errors.Join(&grant.AuthError{Status: 403, Msg: "at rejected: namespace cat-season"}, fakeChain{true}), 503},
		{"lasting, also a 403", fmt.Errorf("%w: %w", &grant.AuthError{Status: 403, Msg: "at rejected"}, fakeChain{false}), 502},
	} {
		for what, write := range map[string]func(http.ResponseWriter){
			"access": func(w http.ResponseWriter) {
				ix.writeAccessErr(w, "access check for matches", c.err, "cannot read the namespace configuration")
			},
			"cover": func(w http.ResponseWriter) { ix.writeCoverErr(w, "matches", c.err) },
			"upstream": func(w http.ResponseWriter) {
				ix.writeUpstreamErr(w, "exchange", c.err, "cannot read a namespace configuration")
			},
		} {
			rec := httptest.NewRecorder()
			write(rec)
			code := map[int]string{503: "behind", 502: "upstream"}[c.status]
			body := rec.Body.String()
			if rec.Code != c.status || !strings.Contains(body, `"code":"`+code+`"`) || strings.Contains(body, "cat-season") {
				t.Errorf("%s, %s: %d %s, want %d %s naming no namespace", c.name, what, rec.Code, body, c.status, code)
			}
			if c.status == 503 && rec.Header().Get("Retry-After") == "" {
				t.Errorf("%s, %s: 503 without Retry-After", c.name, what)
			}
		}
	}
}

// TestV077MemberBehindNamesNone (FSVC-12; §A.4 Private namespaces: "503
// (behind, §B.5) until it has reached each"; /principal hides
// catalog.trust, §7.4): a namespace visibility reads whose follower holds
// no checkpoint yet is 503 behind with a fixed body; only the log names
// it.
func TestV077MemberBehindNamesNone(t *testing.T) {
	t.Parallel()
	var logged []string
	ix := &Index{opt: Options{Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}}
	rec := httptest.NewRecorder()
	ix.writeCoverErr(rec, "matches", fmt.Errorf("%w: %s (§A.4)", errMemberBehind, "cat-season"))
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "cat-season") || rec.Header().Get("Retry-After") == "" {
		t.Errorf("member behind: %d %s", rec.Code, rec.Body)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "cat-season") {
		t.Errorf("the log %q doesn't name cat-season", logged)
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
