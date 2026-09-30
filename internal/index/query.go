package index

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

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
//	facet[/path]=v      exact match on an x-index "facet" field; repeated values of one
//	                    path are ORed, different paths ANDed
//	gt|ge|lt|le[/path]=v range filter on an x-index "sort" field: a number compares with
//	                    numbers, anything else with strings (RFC 3339 date-times normalised)
//	sort=/path | -/path order by a "sort" field (repeatable; missing values last); default:
//	                    score (with q), then resource name
//	counts=/path        facet counts over all hits (repeatable)
//	limit=n             page size, 1–100 (default 20)
//	after=n             continue after the first n hits (from "next")
//	min=ns_id           read-your-writes (§A.5): an ns_id of the queried namespace, or
//	min=ns:ns_id        ns:ns_id for any namespace the service follows; repeatable, and
//	                    every one must be reached
type Query struct {
	Q      string
	words  []string
	Schema string
	Facets map[string][]string // path -> values (ORed)
	Ranges []rangeFilter
	Sorts  []sortKey
	Counts []string
	Limit  int
	After  int
	// Mins are the ?min= values; NS is "" for a bare ns_id (the queried
	// namespace).
	Mins []MinRef
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
		case "q", "schema", "limit", "after":
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

// candidateSQL builds the query for all candidates in order.
func (ix *Index) candidateSQL(ns string, q *Query) (string, []any) {
	var sb strings.Builder
	var args []any
	sb.WriteString(`SELECT d.docid, d.resource, d.head, COALESCE(d.schema, ''), `)
	if len(q.words) > 0 {
		sb.WriteString(`t.score`)
	} else {
		sb.WriteString(`0.0`)
	}
	sb.WriteString(` FROM docs d`)
	if len(q.words) > 0 {
		sb.WriteString(` JOIN (SELECT docid, sum(s) AS score FROM (`)
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
		fmt.Fprintf(&sb, `) GROUP BY docid HAVING count(DISTINCT k) = %d) t ON t.docid = d.docid`, len(q.words))
	}
	for i, s := range q.Sorts {
		fmt.Fprintf(&sb, ` LEFT JOIN "sort" s%d ON s%d.ns = d.ns AND s%d.resource = d.resource AND s%d.path = ?`, i, i, i, i)
		args = append(args, s.path)
	}
	sb.WriteString(` WHERE d.ns = ?`)
	args = append(args, ns)
	if q.Schema != "" {
		pre := strings.TrimRight(q.Schema, "/") + "/"
		sb.WriteString(` AND (d.schema = ? OR substr(d.schema, 1, ?) = ?)`)
		args = append(args, q.Schema, len(pre), pre)
	}
	paths := make([]string, 0, len(q.Facets))
	for p := range q.Facets {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		vals := q.Facets[p]
		sb.WriteString(` AND EXISTS (SELECT 1 FROM facet f WHERE f.ns = d.ns AND f.resource = d.resource AND f.path = ? AND f.value IN (`)
		args = append(args, p)
		for i, v := range vals {
			if i > 0 {
				sb.WriteString(`, `)
			}
			sb.WriteString(`?`)
			args = append(args, v)
		}
		sb.WriteString(`))`)
	}
	for _, r := range q.Ranges {
		sb.WriteString(` AND EXISTS (SELECT 1 FROM "sort" r WHERE r.ns = d.ns AND r.resource = d.resource AND r.path = ? AND `)
		args = append(args, r.path)
		if r.num {
			fmt.Fprintf(&sb, `typeof(r.value) IN ('integer', 'real') AND r.value %s ?)`, r.op)
			args = append(args, r.f)
		} else {
			fmt.Fprintf(&sb, `typeof(r.value) = 'text' AND r.value %s ?)`, r.op)
			args = append(args, r.s)
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

// run executes q against ns inside tx. allow filters hits (nil = all).
func (ix *Index) run(ctx context.Context, tx *sql.Tx, ns string, q *Query, allow func(resource string) bool) (*Result, error) {
	stmt, args := ix.candidateSQL(ns, q)
	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	var all []string // allowed resources, when counting
	n := 0
	for rows.Next() {
		var h Hit
		var docid int64
		if err := rows.Scan(&docid, &h.Resource, &h.ID, &h.Schema, &h.Score); err != nil {
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
	if len(q.Counts) > 0 {
		if res.Counts, err = ix.counts(ctx, tx, ns, q.Counts, all); err != nil {
			return nil, err
		}
	}
	return res, nil
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

func (ix *Index) counts(ctx context.Context, tx *sql.Tx, ns string, paths, resources []string) (map[string][]FacetCount, error) {
	in := make(map[string]bool, len(resources))
	for _, r := range resources {
		in[r] = true
	}
	out := map[string][]FacetCount{}
	for _, p := range paths {
		rows, err := tx.QueryContext(ctx, `SELECT resource, raw FROM facet WHERE ns = ? AND path = ?`, ns, p)
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
