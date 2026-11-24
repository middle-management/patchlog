// Package spannerurl reads the URLs that name a Spanner database of the
// PostgreSQL dialect (docs/SPANNER.md):
//
//	spanner://projects/P/instances/I/databases/D[?param=value&…]
//
// The engine opens it with the database/sql driver of
// github.com/googleapis/go-sql-spanner ("spanner"), whose connection
// string DSN builds. With SPANNER_EMULATOR_HOST set, the driver connects
// to the emulator there and creates the instance and the database, of the
// PostgreSQL dialect, if they don't exist.
package spannerurl

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Scheme prefixes a Spanner URL.
const Scheme = "spanner://"

// Is reports whether path is a Spanner URL.
func Is(path string) bool { return strings.HasPrefix(path, Scheme) }

// Parse splits a Spanner URL into its database's name
// (projects/P/instances/I/databases/D) and its query parameters.
func Parse(raw string) (db string, q url.Values, err error) {
	rest, ok := strings.CutPrefix(raw, Scheme)
	if !ok {
		return "", nil, fmt.Errorf("not a Spanner URL: %q", raw)
	}
	db, query, _ := strings.Cut(rest, "?")
	db = strings.Trim(db, "/")
	p := strings.Split(db, "/")
	if len(p) != 6 || p[0] != "projects" || p[2] != "instances" || p[4] != "databases" || p[1] == "" || p[3] == "" || p[5] == "" {
		return "", nil, fmt.Errorf("a Spanner URL is %sprojects/P/instances/I/databases/D: %q", Scheme, raw)
	}
	if q, err = url.ParseQuery(query); err != nil {
		return "", nil, fmt.Errorf("%q: %w", raw, err)
	}
	return db, q, nil
}

// Emulator reports whether the driver connects to the emulator
// (SPANNER_EMULATOR_HOST).
func Emulator() bool { return os.Getenv("SPANNER_EMULATOR_HOST") != "" }

// DSN is the driver's connection string for a Spanner URL, whose query
// parameters are passed to the driver, but for those named in drop (the
// engine's own). The driver's retries of aborted transactions are off: the
// engine runs them again itself (update1), with what it read anew, where
// the driver would replay the statements and give up if any read
// differently.
func DSN(raw string, drop ...string) (string, error) {
	db, q, err := Parse(raw)
	if err != nil {
		return "", err
	}
	for _, k := range drop {
		q.Del(k)
	}
	params := map[string]string{}
	if Emulator() {
		params["autoConfigEmulator"] = "true"
		params["dialect"] = "postgresql"
	}
	for k, v := range q {
		params[k] = v[len(v)-1]
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(db)
	for i, k := range keys {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte(';')
		}
		b.WriteString(k + "=" + params[k])
	}
	return b.String(), nil
}
