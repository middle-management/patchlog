package core

import (
	"database/sql"
	"fmt"
	"strings"
)

// Multi-row statements (batches, step 7 of §6.2).
//
// A batch of n items would cost n statements per table, each a round trip
// on Postgres. A bulk statement runs once there, over one array per column
// (unnest), whatever the number of rows, so its text is constant and needs
// no placeholders per row. SQLite runs the same statement once per row,
// which costs no round trip. Rows are given as SQLite takes them: one
// value per placeholder of lite, in order; pg names its arrays $1…$k in
// that order, with types the Postgres element types of the columns.

//
// Spanner (spanner.go) has no unnest of several arrays: its form of a
// bulk insert (sp) subscripts each column's array by the elements of one
// more, of ordinals 1…n (spOrdinals). A statement without one runs as
// SQLite's, once per row, its rows sent together as one batch of DML in a
// write transaction (spDMLBatch).

// bulkStmt is one statement in both forms, and Spanner's.
type bulkStmt struct {
	pg, lite, sp string
	types        []string
	// table and cols are a bulkInsert's, for its rows as mutations on
	// Spanner (spMutate).
	table string
	cols  []string
}

// bulkInsert builds an INSERT of cols ("name type", the Postgres element
// type) into table, followed by suffix (ON CONFLICT …, RETURNING …).
func bulkInsert(table, cols, suffix string) bulkStmt {
	var names, arrays, marks, subs []string
	var types []string
	cs := strings.Split(cols, ",")
	for i, c := range cs {
		name, typ, _ := strings.Cut(strings.TrimSpace(c), " ")
		names, types = append(names, name), append(types, typ)
		arrays = append(arrays, fmt.Sprintf("$%d::%s[]", i+1, typ))
		marks = append(marks, "?")
		spTyp := typ
		if typ == "smallint" {
			spTyp = "bigint" // Spanner has no smallint
		}
		subs = append(subs, fmt.Sprintf("($%d::%s[])[u.i]", i+1, spTyp))
	}
	list := strings.Join(names, ", ")
	return bulkStmt{
		pg:    `INSERT INTO ` + table + ` (` + list + `) SELECT * FROM unnest(` + strings.Join(arrays, ", ") + `) ` + suffix,
		lite:  `INSERT INTO ` + table + ` (` + list + `) VALUES (` + strings.Join(marks, ",") + `) ` + suffix,
		sp:    `INSERT INTO ` + table + ` (` + list + `) SELECT ` + strings.Join(subs, ", ") + fmt.Sprintf(` FROM unnest($%d::bigint[]) AS u(i) `, len(cs)+1) + suffix,
		types: types,
		table: table,
		cols:  names,
	}
}

// spOrdinals is the last argument of a Spanner bulk insert of n rows.
func spOrdinals(n int) []int64 {
	o := make([]int64, n)
	for i := range o {
		o[i] = int64(i + 1)
	}
	return o
}

// spArgs are the arguments of s's Spanner form over rows: its columns'
// arrays, then the ordinals, unless the form is Postgres's.
func (s bulkStmt) spArgs(rows [][]any) []any {
	args := s.arrays(rows)
	if s.sp != s.pg {
		args = append(args, spOrdinals(len(rows)))
	}
	return args
}

// bulkExec runs s over rows and returns the number of rows affected.
func (t *tx) bulkExec(s bulkStmt, rows [][]any) int64 {
	if len(rows) == 0 {
		return 0
	}
	t.wrote()
	if t.e.spanner && s.sp != "" {
		t.counted(s.sp)
		r, err := t.Tx.Exec(s.sp, pgArgs(s.spArgs(rows), true)...)
		t.must(err)
		n, err := r.RowsAffected()
		t.must(err)
		return n
	}
	if t.e.pg && !t.e.spanner {
		t.counted(s.pg)
		r, err := t.Tx.Exec(s.pg, s.arrays(rows)...)
		t.must(err)
		n, err := r.RowsAffected()
		t.must(err)
		return n
	}
	if t.e.spanner && t.sp != nil && len(rows) > 1 {
		// One batch of DML, one round trip (spDMLBatch).
		return t.spDMLBatch(s.lite, rows)
	}
	var n int64
	for _, row := range rows {
		r, err := t.Exec(s.lite, row...)
		t.must(err)
		k, err := r.RowsAffected()
		t.must(err)
		n += k
	}
	return n
}

// bulkQuery runs s, a statement returning rows, over rows, calling scan
// for every row returned.
func (t *tx) bulkQuery(s bulkStmt, rows [][]any, scan func(*sql.Rows)) {
	if len(rows) == 0 {
		return
	}
	t.wrote()
	each := func(rs *sql.Rows, err error) {
		t.must(err)
		for rs.Next() {
			scan(rs)
		}
		t.must(rs.Err())
		rs.Close()
	}
	if t.e.spanner && s.sp != "" {
		t.counted(s.sp)
		each(t.Tx.Query(s.sp, pgArgs(s.spArgs(rows), true)...))
		return
	}
	if t.e.pg && !t.e.spanner {
		t.counted(s.pg)
		each(t.Tx.Query(s.pg, s.arrays(rows)...))
		return
	}
	for _, row := range rows {
		each(t.Query(s.lite, row...))
	}
}

// mutationValue is a column's value of a row of s as a Spanner mutation
// takes it, converted as arrays converts it: NULL as nil.
func (s bulkStmt) mutationValue(c int, v any) any {
	switch typ := s.types[c]; typ {
	case "bigint", "smallint":
		switch x := v.(type) {
		case int64, nil:
			return x
		case int:
			return int64(x)
		case bool:
			if x {
				return int64(1)
			}
			return int64(0)
		}
	case "bytea":
		switch x := v.(type) {
		case []byte, nil:
			return x
		case string:
			return []byte(x)
		}
	case "text":
		switch x := v.(type) {
		case string, nil:
			return x
		}
	}
	panic(fmt.Sprintf("bulk: %T in a %s column", v, s.types[c]))
}

// arrays transposes rows into one Postgres array per column.
func (s bulkStmt) arrays(rows [][]any) []any {
	out := make([]any, len(s.types))
	for c, typ := range s.types {
		switch typ {
		case "bigint", "smallint":
			a := make([]*int64, len(rows))
			for i, row := range rows {
				switch v := row[c].(type) {
				case int64:
					a[i] = &v
				case int:
					x := int64(v)
					a[i] = &x
				case bool:
					var x int64
					if v {
						x = 1
					}
					a[i] = &x
				case nil:
				default:
					panic(fmt.Sprintf("bulk: %T in a %s column", v, typ))
				}
			}
			out[c] = a
		case "bytea":
			a := make([][]byte, len(rows))
			for i, row := range rows {
				switch v := row[c].(type) {
				case []byte:
					a[i] = v
				case string:
					a[i] = []byte(v)
				case nil:
				default:
					panic(fmt.Sprintf("bulk: %T in a %s column", v, typ))
				}
			}
			out[c] = a
		case "text":
			a := make([]*string, len(rows))
			for i, row := range rows {
				switch v := row[c].(type) {
				case string:
					a[i] = &v
				case nil:
				default:
					panic(fmt.Sprintf("bulk: %T in a %s column", v, typ))
				}
			}
			out[c] = a
		default:
			panic("bulk: column type " + typ)
		}
	}
	return out
}
