// Package sqlitedsn builds the data source names the SQLite driver
// (modernc.org/sqlite) opens a database file with.
//
// The driver takes the query after the DSN's first '?' as its parameters
// (_pragma, _txlock) and passes a name that starts with "file:" to
// sqlite3_open_v2 whole as a URI, which SQLite cuts at '?' and '#' and
// whose %HH escapes it decodes. "file:" + path + "?…" thus opens another
// file when the path holds a '?' or '#' (t.TempDir of an unnamed subtest
// holds "#00"), or decodes a '%' in it, and a '?' in the path also turns
// the first parameter into part of a key the driver ignores. DSN escapes
// those characters, so SQLite opens exactly the path given, with the
// parameters applied.
package sqlitedsn

import "strings"

// DSN returns the DSN of the SQLite database at path (a file name, or
// ":memory:") with query, '&'-separated driver parameters such as
// "_pragma=busy_timeout(10000)", or "" for none.
//
// A relative path stays relative (to the working directory), and a Windows
// one (C:\…) is left as it is. An absolute one gets the empty authority
// ("file:///…"), so one starting with "//" isn't read as a host.
// Every other character, spaces, ':' and non-ASCII ones among them, goes
// through as it is: SQLite decodes only %HH escapes in the path and ends
// it only at '?' or '#'.
func DSN(path, query string) string {
	var b strings.Builder
	b.WriteString("file:")
	if strings.HasPrefix(path, "/") {
		b.WriteString("//")
	}
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '%':
			b.WriteString("%25")
		case '?':
			b.WriteString("%3F")
		case '#':
			b.WriteString("%23")
		default:
			b.WriteByte(c)
		}
	}
	if query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	return b.String()
}
