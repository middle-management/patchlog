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

// bulkStmt is one statement in both forms.
type bulkStmt struct {
	pg, lite string
	types    []string
}

// bulkInsert builds an INSERT of cols ("name type", the Postgres element
// type) into table, followed by suffix (ON CONFLICT …, RETURNING …).
func bulkInsert(table, cols, suffix string) bulkStmt {
	var names, arrays, marks []string
	var types []string
	for i, c := range strings.Split(cols, ",") {
		name, typ, _ := strings.Cut(strings.TrimSpace(c), " ")
		names, types = append(names, name), append(types, typ)
		arrays = append(arrays, fmt.Sprintf("$%d::%s[]", i+1, typ))
		marks = append(marks, "?")
	}
	list := strings.Join(names, ", ")
	return bulkStmt{
		pg:    `INSERT INTO ` + table + ` (` + list + `) SELECT * FROM unnest(` + strings.Join(arrays, ", ") + `) ` + suffix,
		lite:  `INSERT INTO ` + table + ` (` + list + `) VALUES (` + strings.Join(marks, ",") + `) ` + suffix,
		types: types,
	}
}

// bulkExec runs s over rows and returns the number of rows affected.
func (t *tx) bulkExec(s bulkStmt, rows [][]any) int64 {
	if len(rows) == 0 {
		return 0
	}
	t.wrote()
	if t.e.pg {
		r, err := t.Tx.Exec(s.pg, s.arrays(rows)...)
		t.must(err)
		n, err := r.RowsAffected()
		t.must(err)
		return n
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
	if t.e.pg {
		each(t.Tx.Query(s.pg, s.arrays(rows)...))
		return
	}
	for _, row := range rows {
		each(t.Query(s.lite, row...))
	}
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
