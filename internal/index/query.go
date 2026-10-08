package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
)

// Query is a parsed query (§A.4). Parameters:
//
//	q=words             full text over x-index "text" fields; every word must occur in the
//	                    document (in any text field); a trailing * makes a word a prefix
//	schema=ref          exact $schema, or a prefix ending at a path segment
//	                    (/r/schemas/match matches /r/schemas/match/rev/…)
//	ref=/r/ns/name      documents that reference a resource (§A.4): any form; with
//	                    /rev/{id} only those pinned to that revision; with #entry (sent as
//	                    %23entry) only those naming that entry
//	facet[/path]=v      exact match on an x-index "facet" field; repeated values of one
//	                    path are ORed, different paths ANDed
//	gt|ge|lt|le[/path]=v range filter on an x-index "sort" field: a number compares with
//	                    numbers, anything else with strings (RFC 3339 date-times normalised)
//	sort=/path | -/path order by a "sort" field (repeatable; missing values last); default:
//	                    score (with q), then resource name
//	counts=/path        facet counts over all hits (repeatable)
//	fields=/a,/b        also show those indexed fields in hits, "text" ones included; a path
//	                    no schema marks with x-index in the namespace is 400 (§A.4)
//	limit=n             page size, 1–100 (default 20)
//	after=n             continue after the first n hits (from "next")
//	min=ns_id           read-your-writes (§A.5): an ns_id of the queried namespace, or
//	min=ns:ns_id        ns:ns_id for any namespace the service follows; repeatable, and
//	                    every one must be reached
type Query struct {
	Q      string
	words  []string
	Schema string
	Ref    *RefFilter
	Facets map[string][]string // path -> values (ORed)
	Ranges []rangeFilter
	Sorts  []sortKey
	Counts []string
	Fields []string
	Limit  int
	After  int
	// Mins are the ?min= values; NS is "" for a bare ns_id (the queried
	// namespace).
	Mins []MinRef
}

// RefFilter is a parsed ?ref= (§A.4). Rev and Entry are "" when the form
// has none.
type RefFilter struct{ NS, Name, Rev, Entry string }

// ParseRefFilter parses /r/{ns}/{name}[/rev/{id}][#{entry}]. The entry is
// percent-decoded, as it is stored.
func ParseRefFilter(s string) (*RefFilter, error) {
	r, ok := annot.ParseRefString(s)
	if !ok {
		return nil, fmt.Errorf("ref must be /r/{ns}/{name}, /r/{ns}/{name}/rev/{id} or /r/{ns}/{name}%%23{entry}")
	}
	return &RefFilter{NS: r.NS, Name: r.Name, Rev: r.Rev, Entry: r.Entry}, nil
}

// MinRef is one ?min= value (§A.5).
type MinRef struct{ NS, ID string }

// ParseMin parses "{ns_id}" or "{ns}:{ns_id}" (§A.5, §B.5).
func ParseMin(s string) (MinRef, error) {
	var m MinRef
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		m.NS, s = s[:i], s[i+1:]
		if !validNS(m.NS) {
			return m, fmt.Errorf("min: %q is not a namespace name", m.NS)
		}
	}
	if _, err := ids.Parse(s); err != nil {
		return m, fmt.Errorf("min is not an ns_id or {ns}:{ns_id}")
	}
	m.ID = s
	return m, nil
}

type rangeFilter struct {
	op, path string
	num      bool
	f        float64
	s        string
}

type sortKey struct {
	path string
	desc bool
}

var rangeOps = map[string]string{"gt": ">", "ge": ">=", "lt": "<", "le": "<="}

// bracket splits "facet[/a/b]" into ("facet", "/a/b").
func bracket(k string) (string, string, bool) {
	i := strings.IndexByte(k, '[')
	if i < 0 || !strings.HasSuffix(k, "]") {
		return "", "", false
	}
	return k[:i], k[i+1 : len(k)-1], true
}

func validPath(p string) error {
	if p == "" || p[0] != '/' {
		return fmt.Errorf("path %q must be a JSON pointer starting with /", p)
	}
	_, err := pointer.Parse(p)
	return err
}

// ParseQuery parses and validates query parameters. Unknown parameters are
// rejected, so cache keys stay meaningful.
func ParseQuery(v url.Values) (*Query, error) {
	q := &Query{Facets: map[string][]string{}, Limit: 20}
	one := func(k string) (string, error) {
		if len(v[k]) > 1 {
			return "", fmt.Errorf("%s given more than once", k)
		}
		return v.Get(k), nil
	}
	for k, vals := range v {
		switch k {
		case "q", "schema", "ref", "limit", "after":
			if _, err := one(k); err != nil {
				return nil, err
			}
		case "min":
			for _, s := range vals {
				m, err := ParseMin(s)
				if err != nil {
					return nil, err
				}
				q.Mins = append(q.Mins, m)
			}
		case "sort":
			for _, s := range vals {
				sk := sortKey{path: s}
				if strings.HasPrefix(s, "-") {
					sk = sortKey{path: s[1:], desc: true}
				}
				if err := validPath(sk.path); err != nil {
					return nil, fmt.Errorf("sort: %v", err)
				}
				q.Sorts = append(q.Sorts, sk)
			}
		case "fields":
			if _, err := one(k); err != nil {
				return nil, err
			}
			seen := map[string]bool{}
			for _, p := range strings.Split(vals[0], ",") {
				if err := validPath(p); err != nil {
					return nil, fmt.Errorf("fields: %v", err)
				}
				if !seen[p] {
					seen[p] = true
					q.Fields = append(q.Fields, p)
				}
			}
		case "counts":
			for _, s := range vals {
				if err := validPath(s); err != nil {
					return nil, fmt.Errorf("counts: %v", err)
				}
				q.Counts = append(q.Counts, s)
			}
		default:
			name, path, ok := bracket(k)
			if !ok {
				return nil, fmt.Errorf("unknown parameter %q", k)
			}
			if err := validPath(path); err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			switch {
			case name == "facet":
				q.Facets[path] = append(q.Facets[path], vals...)
			case rangeOps[name] != "":
				for _, s := range vals {
					rf := rangeFilter{op: rangeOps[name], path: path}
					if f, err := strconv.ParseFloat(s, 64); err == nil {
						rf.num, rf.f = true, f
					} else if t, ok := normTime(s); ok {
						rf.s = t
					} else {
						rf.s = s
					}
					q.Ranges = append(q.Ranges, rf)
				}
			default:
				return nil, fmt.Errorf("unknown parameter %q", k)
			}
		}
	}
	sort.Strings(q.Counts)
	sort.Slice(q.Ranges, func(i, j int) bool {
		a, b := q.Ranges[i], q.Ranges[j]
		if a.path != b.path {
			return a.path < b.path
		}
		return a.op < b.op
	})
	q.Q = v.Get("q")
	q.words = words(q.Q)
	if strings.TrimSpace(q.Q) != "" && len(q.words) == 0 {
		return nil, fmt.Errorf("q has no searchable words")
	}
	q.Schema = v.Get("schema")
	if _, ok := v["ref"]; ok {
		rf, err := ParseRefFilter(v.Get("ref"))
		if err != nil {
			return nil, err
		}
		q.Ref = rf
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 100 {
			return nil, fmt.Errorf("limit must be 1–100")
		}
		q.Limit = n
	}
	if s := v.Get("after"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("after must be a non-negative integer")
		}
		q.After = n
	}
	return q, nil
}

// words splits q into search words: whitespace-separated, keeping only
// words with a letter or digit; a trailing * marks a prefix.
func words(q string) []string {
	var out []string
	for _, w := range strings.Fields(q) {
		if strings.IndexFunc(w, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) >= 0 {
			out = append(out, w)
		}
	}
	return out
}

func ftsPhrase(w string) string {
	prefix := strings.HasSuffix(w, "*")
	w = strings.TrimRight(w, "*")
	p := `"` + strings.ReplaceAll(w, `"`, `""`) + `"`
	if prefix {
		p += "*"
	}
	return p
}

func likePattern(w string) string {
	w = strings.TrimRight(w, "*")
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(w) + "%"
}

// Hit is one result.
type Hit struct {
	Resource string
	ID       string
	Schema   string
	Score    float64
	Facets   map[string][]any
	Sorts    map[string][]any // sort values as written, for paths with no facet value
	Text     map[string][]any // with ?fields=: the requested text fields
	Refs     []RefHit         // with ?ref=: the matching references (§A.4)
	Self     bool             // with ?ref=: the document references itself
	docid    int64
}

// RefHit is one reference of a hit: where it sits and the string as written.
type RefHit struct {
	Path string `json:"path"`
	Ref  string `json:"ref"`
}

// Result is a page of hits.
type Result struct {
	Hits   []Hit
	More   bool
	Counts map[string][]FacetCount
}

// FacetCount is one value of a facet count.
type FacetCount struct {
	Value any `json:"value"`
	Count int `json:"count"`
}

// filter is the ?ref= filter, a ?facet= path or a range: a condition on
// rows of table (as alias a), each of one resource. A query tests it per
// document on the table's primary key, or reads the candidates from it on
// its query index (see driver).
type filter struct {
	table, a string
	idx, pk  string // the query index, the primary key's index
	cond     string
	args     []any
}

// filters lists q's filters: the ref, the facets by path, the ranges.
func (q *Query) filters() []filter {
	var fs []filter
	if rf := q.Ref; rf != nil {
		cond, args := refCond(rf)
		fs = append(fs, filter{`refs`, "x", "refs_q", "sqlite_autoindex_refs_1", cond, args})
	}
	paths := make([]string, 0, len(q.Facets))
	for p := range q.Facets {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		var cond strings.Builder
		cond.WriteString(`f.path = ? AND f.value IN (`)
		args := []any{p}
		for i, v := range q.Facets[p] {
			if i > 0 {
				cond.WriteString(`, `)
			}
			cond.WriteString(`?`)
			args = append(args, v)
		}
		cond.WriteString(`)`)
		fs = append(fs, filter{`facet`, "f", "facet_q", "sqlite_autoindex_facet_1", cond.String(), args})
	}
	for _, r := range q.Ranges {
		f := filter{table: `"sort"`, a: "r", idx: "sort_q", pk: "sqlite_autoindex_sort_1"}
		if r.num {
			f.cond, f.args = `r.path = ? AND typeof(r.value) IN ('integer', 'real') AND r.value `+r.op+` ?`, []any{r.path, r.f}
		} else {
			f.cond, f.args = `r.path = ? AND typeof(r.value) = 'text' AND r.value `+r.op+` ?`, []any{r.path, r.s}
		}
		fs = append(fs, f)
	}
	return fs
}

// A query reads its candidates either from one filter's matches (its rows
// on the filter's query index, each looked up in docs, then sorted) or by
// scanning the namespace's documents in resource order, testing each. A
// match costs about four times what a tested document does, so a filter
// drives if it matches under a quarter of the namespace's documents. That
// is the rule when the query reads every candidate anyway (a sort, counts,
// or a page past the matches); otherwise the scan stops at the page, and
// the filter must also match fewer than maxDrive rows, which bounds what
// driving can cost over the scan. Matches are counted on the filter's
// index up to maxDriveAll, documents up to four times the matches, so the
// counting costs little next to either plan.
const (
	maxDrive    = 1000
	maxDriveAll = 1 << 14
)

// driver returns the index in fs of the filter that drives the query (the
// one with the fewest matches, if it is selective), or -1 to scan. A q=
// query is driven by its text matches (see candidateSQL).
func (ix *Index) driver(ctx context.Context, tx *sql.Tx, ns string, q *Query, fs []filter) (int, error) {
	if len(q.words) > 0 || len(fs) == 0 {
		return -1, nil
	}
	best, m := -1, min(max(maxDrive, q.After+q.Limit), maxDriveAll)
	if len(q.Sorts) > 0 || len(q.Counts) > 0 {
		m = maxDriveAll
	}
	for i, f := range fs {
		var n int
		args := append(append([]any{ns}, f.args...), m)
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM `+f.table+` `+f.a+` INDEXED BY `+f.idx+` WHERE `+f.a+`.ns = ? AND `+f.cond+` LIMIT ?)`, args...).Scan(&n)
		if err != nil {
			return -1, err
		}
		if n < m {
			best, m = i, n
		}
	}
	if best < 0 {
		return -1, nil
	}
	var docs int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM docs WHERE ns = ? LIMIT ?)`, ns, 4*m+1).Scan(&docs); err != nil {
		return -1, err
	}
	if docs <= 4*m {
		return -1, nil
	}
	return best, nil
}

// candidateSQL builds the query for all candidates in order, read from
// the text matches (with q=), from fs[drive] (drive >= 0), or from the
// namespace's documents. The table that drives comes first in a CROSS
// JOIN, so that SQLite keeps it the outer loop whatever its estimates,
// and each filter reads the index named for it.
func (ix *Index) candidateSQL(ns string, q *Query, fs []filter, drive int) (string, []any) {
	var sb strings.Builder
	var args []any
	if len(q.words) > 0 {
		drive = -1
	}
	sb.WriteString(`SELECT d.docid, d.resource, d.head, COALESCE(d.schema, ''), `)
	if len(q.words) > 0 {
		sb.WriteString(`t.score`)
	} else {
		sb.WriteString(`0.0`)
	}
	sb.WriteString(` FROM `)
	switch {
	case len(q.words) > 0:
		sb.WriteString(`(SELECT docid, sum(s) AS score FROM (`)
		for i, w := range q.words {
			if i > 0 {
				sb.WriteString(` UNION ALL `)
			}
			if ix.fts {
				fmt.Fprintf(&sb, `SELECT rowid >> %d AS docid, %d AS k, -rank AS s FROM "text" WHERE "text" MATCH ?`, textShift, i)
				args = append(args, ftsPhrase(w))
			} else {
				fmt.Fprintf(&sb, `SELECT docid, %d AS k, 1.0 AS s FROM "text" WHERE body LIKE ? ESCAPE '\'`, i)
				args = append(args, likePattern(w))
			}
		}
		fmt.Fprintf(&sb, `) GROUP BY docid HAVING count(DISTINCT k) = %d) t CROSS JOIN docs d`, len(q.words))
	case drive >= 0:
		f := fs[drive]
		sb.WriteString(`(SELECT DISTINCT ` + f.a + `.resource FROM ` + f.table + ` ` + f.a + ` INDEXED BY ` + f.idx + ` WHERE ` + f.a + `.ns = ? AND ` + f.cond + `) m CROSS JOIN docs d`)
		args = append(append(args, ns), f.args...)
	default:
		sb.WriteString(`docs d`)
	}
	for i, s := range q.Sorts {
		fmt.Fprintf(&sb, ` LEFT JOIN "sort" s%d ON s%d.ns = d.ns AND s%d.resource = d.resource AND s%d.path = ?`, i, i, i, i)
		args = append(args, s.path)
	}
	sb.WriteString(` WHERE d.ns = ?`)
	args = append(args, ns)
	switch {
	case len(q.words) > 0:
		sb.WriteString(` AND d.docid = t.docid`)
	case drive >= 0:
		sb.WriteString(` AND d.resource = m.resource`)
	}
	if q.Schema != "" {
		pre := strings.TrimRight(q.Schema, "/") + "/"
		sb.WriteString(` AND (d.schema = ? OR substr(d.schema, 1, ?) = ?)`)
		args = append(args, q.Schema, len(pre), pre)
	}
	for i, f := range fs {
		if i != drive {
			sb.WriteString(` AND EXISTS (SELECT 1 FROM ` + f.table + ` ` + f.a + ` INDEXED BY ` + f.pk + ` WHERE ` + f.a + `.ns = d.ns AND ` + f.a + `.resource = d.resource AND ` + f.cond + `)`)
			args = append(args, f.args...)
		}
	}
	sb.WriteString(` ORDER BY `)
	for i, s := range q.Sorts {
		dir := "ASC"
		if s.desc {
			dir = "DESC"
		}
		fmt.Fprintf(&sb, `s%d.value IS NULL, s%d.value %s, `, i, i, dir)
	}
	if len(q.words) > 0 {
		sb.WriteString(`t.score DESC, `)
	}
	sb.WriteString(`d.resource`)
	return sb.String(), args
}

// refCond is the condition on a refs row x that matches the filter.
func refCond(rf *RefFilter) (string, []any) {
	cond := `x.target_ns = ? AND x.target = ?`
	args := []any{rf.NS, rf.Name}
	if rf.Rev != "" {
		cond += ` AND x.rev = ?`
		args = append(args, rf.Rev)
	}
	if rf.Entry != "" {
		cond += ` AND x.entry = ?`
		args = append(args, rf.Entry)
	}
	return cond, args
}

// attachRefs gives each hit the references that matched the filter.
func (ix *Index) attachRefs(ctx context.Context, tx *sql.Tx, ns string, rf *RefFilter, hits []Hit) error {
	if rf == nil || len(hits) == 0 {
		return nil
	}
	idx := map[string]int{}
	ph := make([]string, len(hits))
	cond, args := refCond(rf)
	args = append([]any{ns}, args...)
	for i, h := range hits {
		idx[h.Resource] = i
		ph[i] = "?"
		args = append(args, h.Resource)
	}
	rows, err := tx.QueryContext(ctx, `SELECT x.resource, x.path, x.ref FROM refs x WHERE x.ns = ? AND `+cond+` AND x.resource IN (`+strings.Join(ph, ",")+`) ORDER BY x.resource, x.path`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		var rh RefHit
		if err := rows.Scan(&r, &rh.Path, &rh.Ref); err != nil {
			return err
		}
		h := &hits[idx[r]]
		h.Refs = append(h.Refs, rh)
		h.Self = rf.NS == ns && rf.Name == r
	}
	return rows.Err()
}

// run executes q against ns inside tx. allow filters hits (nil = all).
func (ix *Index) run(ctx context.Context, tx *sql.Tx, ns string, q *Query, allow func(resource string) bool) (*Result, error) {
	for _, f := range q.Fields {
		ok, err := ix.indexedField(ctx, tx, ns, f)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, &FieldError{Path: f}
		}
	}
	fs := q.filters()
	drive, err := ix.driver(ctx, tx, ns, q, fs)
	if err != nil {
		return nil, err
	}
	stmt, args := ix.candidateSQL(ns, q, fs, drive)
	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	var all []string // allowed resources, when counting
	n := 0
	for rows.Next() {
		var h Hit
		if err := rows.Scan(&h.docid, &h.Resource, &h.ID, &h.Schema, &h.Score); err != nil {
			rows.Close()
			return nil, err
		}
		if allow != nil && !allow(h.Resource) {
			continue
		}
		if len(q.Counts) > 0 {
			all = append(all, h.Resource)
		}
		n++
		switch {
		case n <= q.After:
		case len(res.Hits) < q.Limit:
			res.Hits = append(res.Hits, h)
		default:
			res.More = true
		}
		if res.More && len(q.Counts) == 0 {
			break
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ix.attachFacets(ctx, tx, ns, res.Hits); err != nil {
		return nil, err
	}
	if err := ix.attachSorts(ctx, tx, ns, res.Hits); err != nil {
		return nil, err
	}
	if err := ix.attachText(ctx, tx, q.Fields, res.Hits); err != nil {
		return nil, err
	}
	if err := ix.attachRefs(ctx, tx, ns, q.Ref, res.Hits); err != nil {
		return nil, err
	}
	if len(q.Counts) > 0 {
		if res.Counts, err = ix.counts(ctx, tx, ns, q.Counts, all); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// FieldError is a ?fields= path that no schema indexed in the namespace
// marks with x-index (§A.4): 400.
type FieldError struct{ Path string }

func (e *FieldError) Error() string {
	return "fields: " + e.Path + " is not a field any schema indexed in the namespace marks with x-index"
}

// indexedField reports whether some document of ns has indexed rows at path.
func (ix *Index) indexedField(ctx context.Context, tx *sql.Tx, ns, path string) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 WHERE EXISTS (SELECT 1 FROM facet WHERE ns = ? AND path = ?)
		OR EXISTS (SELECT 1 FROM "sort" WHERE ns = ? AND path = ?)
		OR EXISTS (SELECT 1 FROM "text" WHERE ns = ? AND path = ?)`, ns, path, ns, path, ns, path).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// attachSorts gives each hit its sort values as written, for the paths
// that have no facet value (a field that is both shows its facet values).
func (ix *Index) attachSorts(ctx context.Context, tx *sql.Tx, ns string, hits []Hit) error {
	if len(hits) == 0 {
		return nil
	}
	idx := map[string]int{}
	ph := make([]string, len(hits))
	args := []any{ns}
	for i, h := range hits {
		idx[h.Resource] = i
		ph[i] = "?"
		args = append(args, h.Resource)
	}
	rows, err := tx.QueryContext(ctx, `SELECT resource, path, raw FROM "sort" WHERE ns = ? AND resource IN (`+strings.Join(ph, ",")+`) ORDER BY resource, path`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r, p string
		var raw sql.NullString
		if err := rows.Scan(&r, &p, &raw); err != nil {
			return err
		}
		h := &hits[idx[r]]
		if _, ok := h.Facets[p]; ok || !raw.Valid {
			continue
		}
		v, err := jsonv.Parse([]byte(raw.String))
		if err != nil {
			return err
		}
		if h.Sorts == nil {
			h.Sorts = map[string][]any{}
		}
		h.Sorts[p] = []any{v}
	}
	return rows.Err()
}

// attachText gives each hit the strings of its requested text fields.
func (ix *Index) attachText(ctx context.Context, tx *sql.Tx, fields []string, hits []Hit) error {
	if len(fields) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, f := range fields {
		want[f] = true
	}
	for i := range hits {
		h := &hits[i]
		var rows *sql.Rows
		var err error
		if ix.fts {
			rows, err = tx.QueryContext(ctx, `SELECT path, body FROM "text" WHERE rowid BETWEEN ? AND ? ORDER BY rowid`, h.docid<<textShift, h.docid<<textShift|(1<<textShift-1))
		} else {
			rows, err = tx.QueryContext(ctx, `SELECT path, body FROM "text" WHERE docid = ? ORDER BY rowid`, h.docid)
		}
		if err != nil {
			return err
		}
		for rows.Next() {
			var p, body string
			if err := rows.Scan(&p, &body); err != nil {
				rows.Close()
				return err
			}
			if !want[p] {
				continue
			}
			if _, ok := h.Facets[p]; ok {
				continue // shown with the facet values already
			}
			if h.Text == nil {
				h.Text = map[string][]any{}
			}
			h.Text[p] = append(h.Text[p], body)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return nil
}

func (ix *Index) attachFacets(ctx context.Context, tx *sql.Tx, ns string, hits []Hit) error {
	if len(hits) == 0 {
		return nil
	}
	idx := map[string]int{}
	ph := make([]string, len(hits))
	args := []any{ns}
	for i, h := range hits {
		idx[h.Resource] = i
		ph[i] = "?"
		args = append(args, h.Resource)
	}
	rows, err := tx.QueryContext(ctx, `SELECT resource, path, raw FROM facet WHERE ns = ? AND resource IN (`+strings.Join(ph, ",")+`) ORDER BY resource, path, raw`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r, p, raw string
		if err := rows.Scan(&r, &p, &raw); err != nil {
			return err
		}
		h := &hits[idx[r]]
		if h.Facets == nil {
			h.Facets = map[string][]any{}
		}
		v, err := jsonv.Parse([]byte(raw))
		if err != nil {
			return err
		}
		h.Facets[p] = append(h.Facets[p], v)
	}
	return rows.Err()
}

// counts tallies the facet values at paths of resources. When they are
// few (at most maxDriveAll, and under half the path's rows, counted up to
// that), it looks their rows up; else it reads all of the path's rows.
func (ix *Index) counts(ctx context.Context, tx *sql.Tx, ns string, paths, resources []string) (map[string][]FacetCount, error) {
	in := make(map[string]bool, len(resources))
	for _, r := range resources {
		in[r] = true
	}
	var list []byte // resources as a JSON array, for json_each
	out := map[string][]FacetCount{}
	for _, p := range paths {
		n := 0
		if len(resources) <= maxDriveAll {
			err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM facet INDEXED BY facet_q WHERE ns = ? AND path = ? LIMIT ?)`, ns, p, 2*len(resources)+1).Scan(&n)
			if err != nil {
				return nil, err
			}
		}
		var rows *sql.Rows
		var err error
		if n > 2*len(resources) {
			if list == nil {
				list, _ = json.Marshal(resources)
			}
			rows, err = tx.QueryContext(ctx, `SELECT f.resource, f.raw FROM json_each(?) j CROSS JOIN facet f INDEXED BY sqlite_autoindex_facet_1 WHERE f.ns = ? AND f.resource = j.value AND f.path = ?`, string(list), ns, p)
		} else {
			rows, err = tx.QueryContext(ctx, `SELECT resource, raw FROM facet WHERE ns = ? AND path = ?`, ns, p)
		}
		if err != nil {
			return nil, err
		}
		c := map[string]int{}
		for rows.Next() {
			var r, raw string
			if err := rows.Scan(&r, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			if in[r] {
				c[raw]++
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		list := []FacetCount{}
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if c[keys[i]] != c[keys[j]] {
				return c[keys[i]] > c[keys[j]]
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			v, _ := jsonv.Parse([]byte(k))
			list = append(list, FacetCount{Value: v, Count: c[k]})
		}
		out[p] = list
	}
	return out, nil
}
