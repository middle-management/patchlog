package index

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/ids"
)

// TestV073StrictMins (IX-12, §A.5, F-I1): until F-I1 is answered, a min
// naming another namespace on a query of one keeps the v0.51 behaviour
// (strictMins off); the strict reading refuses it, listing it, before any
// read check, as a min naming a namespace the current checkpoint doesn't
// cover. A bare min, or one naming the queried namespace, is never refused.
func TestV073StrictMins(t *testing.T) {
	if strictMins {
		t.Fatal("strictMins is on before F-I1 is answered")
	}
	id := ids.FromBytes(bytes.Repeat([]byte{7}, ids.Size)).String()
	ix := &Index{roots: map[string]bool{"pa": true, "pb": true}}
	mins := []MinRef{{ID: id}, {NS: "pa", ID: id}, {NS: "pb", ID: id}, {NS: "zz", ID: id}}
	refused, behind, err := ix.judgeMins(context.Background(), httptest.NewRequest("GET", "/pa", nil), "pa", mins, true)
	if err != nil || behind || fmt.Sprint(refused) != fmt.Sprint([]string{"pb:" + id, "zz:" + id}) {
		t.Fatalf("strict: refused %v, behind %v, err %v", refused, behind, err)
	}
	if mins[0].NS != "pa" {
		t.Errorf("a bare min names the queried namespace: %+v", mins[0])
	}
}

// TestV073DropWholePublic (ENC-33, §E.2.6): opening the index drops the
// stored results sealed whole at a public URL, as before v0.73, with their
// tags, and keeps every other: a whole JWE at a private one (/g/{gs}, a
// namespace named g included), a public URL's JSON, /_refs answers.
func TestV073DropWholePublic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	ix := openBare(t, path)
	ctx := context.Background()
	id := ids.FromBytes(bytes.Repeat([]byte{7}, ids.Size)).String()
	rows := []struct {
		view, scope string
		json, kept  bool
	}{
		{"/ps/at/" + id + "?q=x", "ps", false, false},
		{"/g/at/" + id + "?q=x", "g", false, false},
		{"/ps/at/" + id + "?q=y", "ps", true, true},
		{"/ps/g/" + id + "/at/" + id + "?q=x", "ps", false, true},
		{"/g/g/" + id + "/at/" + id + "?q=x", "g", false, true},
		{"/_refs/g/" + id + "/at/" + id + "?to=x", "/_refs/g/" + id, true, true},
	}
	for _, r := range rows {
		if _, err := ix.sealed.Put(ctx, r.view, r.scope, id, derived.Stored{Body: []byte("b"), JSON: r.json, Tags: "idx:" + r.scope}); err != nil {
			t.Fatal(err)
		}
	}
	ix.db.Close()
	ix = openBare(t, path)
	for _, r := range rows {
		var views, tags int
		if err := ix.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sealed_views WHERE view = ?1), (SELECT count(*) FROM sealed_view_tags WHERE view = ?1)`, r.view).Scan(&views, &tags); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 0}[r.kept]; views != want || tags != want {
			t.Errorf("%s (json %v): %d views, %d tags, want %d", r.view, r.json, views, tags, want)
		}
	}
}

// fillText writes n text rows of about 3 KB, each with goal keeper once,
// a 20th of them in ns small and the rest in big, as candidateSQL reads
// them.
func fillText(t *testing.T, ix *Index, n int) {
	t.Helper()
	ctx := context.Background()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	filler := strings.Repeat("lorem ipsum dolor sit amet consectetur ", 40)
	for i := range n {
		ns := "big"
		if i%20 == 0 {
			ns = "small"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO "text" (rowid, ns, resource, schema, path, body) VALUES (?, ?, ?, '', '/title', ?)`,
			int64(i+1)<<textShift, ns, fmt.Sprintf("r%d", i), filler+" goal keeper "+filler); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO docs (docid, ns, resource, head, schema) VALUES (?, ?, ?, '', '')`, i+1, ns, fmt.Sprintf("r%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestV073TextMatchCost (IX-19, §A.4): scores per document don't make a
// text match re-tokenize every matching row of every namespace. A word of
// one token is read from its instances, at about the cost of the FTS5
// rank of v0.55 (here within 5 times, from 13 times with highlight()); a
// word of several tokens (a phrase) is counted with highlight() in rows of
// the queried namespace only.
func TestV073TextMatchCost(t *testing.T) {
	ix := openBare(t, filepath.Join(t.TempDir(), "s.db"))
	if !ix.fts {
		t.Skip("no FTS5")
	}
	const n = 5000 // about 30 MB: the timings scale with n, their ratios don't
	fillText(t, ix, n)
	ctx := context.Background()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	run := func(want int, q string, args ...any) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			var c int
			if err := tx.QueryRowContext(ctx, q, args...).Scan(&c); err != nil {
				t.Fatalf("%v\n%s", err, q)
			}
			if c != want {
				t.Fatalf("count %d, want %d\n%s", c, want, q)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	match := func(ns, w string) (string, []any) {
		q := &Query{words: []string{w}}
		if err := ix.ftsTokens(ctx, tx, q); err != nil {
			t.Fatal(err)
		}
		m, args := textMatchSQL(true, ns, q.words, q.toks)
		return `SELECT count(*) FROM ` + m, args
	}
	rank := fmt.Sprintf(`SELECT count(*) FROM (SELECT docid, sum(s) AS score FROM (SELECT rowid >> %d AS docid, 0 AS k, -rank AS s FROM "text" WHERE "text" MATCH ?) GROUP BY docid HAVING count(DISTINCT k) = 1)`, textShift)
	old := run(n, rank, `"goal"`)
	m, args := match("small", "goal")
	cur := run(n, m, args...)
	t.Logf("one token: v0.55 rank %s, now %s (x%.1f)", old, cur, float64(cur)/float64(old))
	if cur > 5*old {
		t.Errorf("a word of one token costs x%.1f what it did", float64(cur)/float64(old))
	}
	// sum(c): SQLite computes no column a count(*) doesn't read.
	everywhere := fmt.Sprintf(`SELECT sum(c) FROM (SELECT * FROM (SELECT rowid >> %d AS docid, max(1, length(highlight("text", 4, char(1), '')) - length(body)) AS c FROM "text" WHERE "text" MATCH ? LIMIT -1))`, textShift)
	all := run(n, everywhere, `"goal-keeper"`)
	m, args = match("small", "goal-keeper")
	small := run(n/20, m, args...)
	t.Logf("a phrase: highlight() everywhere %s, in small %s", all, small)
	if small > all/5 {
		t.Errorf("a phrase in small, a 20th of the rows, costs %s, highlight() everywhere %s", small, all)
	}
}

// TestV073TokensAsFTS5 (IX-19, §A.4): a word read from its instances
// matches the documents, and counts the occurrences, that MATCH and
// highlight() do, whatever its case, diacritics or script, and as a
// prefix; a phrase still matches as one.
func TestV073TokensAsFTS5(t *testing.T) {
	ix := openBare(t, filepath.Join(t.TempDir(), "s.db"))
	if !ix.fts {
		t.Skip("no FTS5")
	}
	ctx := context.Background()
	for i, b := range []string{"goal goalie", "Goa trip", "GOAL! goal; goal", "ago goa", "café crème", "Café-Crème brûlée, crème",
		"ÉTÉ été", "日本語 日本", "Straße strasse", "goa\U0010FFFFx", "e-mail email e mail", "x"} {
		if _, err := ix.db.ExecContext(ctx, `INSERT INTO "text" (rowid, ns, resource, schema, path, body) VALUES (?, 'n', ?, '', '/t', ?)`, int64(i+1)<<textShift, fmt.Sprint(i), b); err != nil {
			t.Fatal(err)
		}
		if _, err := ix.db.ExecContext(ctx, `INSERT INTO docs (docid, ns, resource, head, schema) VALUES (?, 'n', ?, '', '')`, i+1, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	scores := func(words []string, toks [][]string) string {
		m, args := textMatchSQL(true, "n", words, toks)
		rows, err := tx.QueryContext(ctx, `SELECT docid, score FROM `+m+` ORDER BY docid`, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var d int64
			var s float64
			if err := rows.Scan(&d, &s); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%d:%.6f", d, s))
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct {
		q     string
		toks  string
		match bool // some document matches
	}{
		{"goal", "[[goal]]", true}, {"GOA*", "[[goa]]", true}, {"ete", "[[ete]]", true}, {"crè*", "[[cre]]", true},
		{"Café crème", "[[cafe] [creme]]", true}, {"café-crème", "[[cafe creme]]", true}, {"日本*", "[[日本]]", true},
		{"straße", "[[straße]]", true}, {"e-mail", "[[e mail]]", true}, {"nothing", "[[nothing]]", false},
	} {
		q := &Query{words: words(c.q)}
		if err := ix.ftsTokens(ctx, tx, q); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(q.toks) != c.toks {
			t.Errorf("%q: tokens %v, want %s", c.q, q.toks, c.toks)
		}
		got, want := scores(q.words, q.toks), scores(q.words, nil)
		if got != want || (got != "") != c.match {
			t.Errorf("%q: from instances %q, from MATCH and highlight() %q", c.q, got, want)
		}
	}
}
