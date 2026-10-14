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
// parameters applied. CheckLegacy refuses a path whose database an
// earlier release kept in that other file, until it is moved.
package sqlitedsn

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

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

// Legacy returns the file that "file:" + path + "?" + parameters, the DSN
// of releases before DSN, opened for the database at path, if that is
// another file; it returns "" when it is path itself, or a directory, or
// when that DSN failed to open. It reads the DSN as the driver and SQLite did:
//   - the driver took its parameters from after the path's first '?', and
//     failed when url.ParseQuery did (a bad %-escape, a ';');
//   - SQLite read a name starting with "//" as an authority up to the next
//     '/', failing unless it was empty or "localhost";
//   - it ended the path at its first '?' or '#', and decoded each %HH in
//     it, ending the path at a %00 (a bad escape stays as it is).
func Legacy(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		if _, err := url.ParseQuery(path[i+1:]); err != nil {
			return ""
		}
	}
	name := path
	if rest, ok := strings.CutPrefix(name, "//"); ok {
		host := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			host = rest[:i]
		}
		if host != "" && host != "localhost" {
			return ""
		}
		name = rest[len(host):]
	}
	if i := strings.IndexAny(name, "?#"); i >= 0 {
		name = name[:i]
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '%' && i+2 < len(name) && isHex(name[i+1]) && isHex(name[i+2]) {
			c = unhex(name[i+1])<<4 | unhex(name[i+2])
			i += 2
			if c == 0 {
				break
			}
		}
		b.WriteByte(c)
	}
	if b.Len() == 0 || strings.HasSuffix(b.String(), "/") || filepath.Clean(b.String()) == filepath.Clean(path) {
		return ""
	}
	return b.String()
}

// CheckLegacy returns an error when there is no file at path but there is
// one at Legacy(path): a database that releases before DSN kept there.
// Opening path would start an empty database beside it (and the core's
// blob sweep would then delete its blob files, which no row of the empty
// one names), so its owner must move it first.
func CheckLegacy(path string) error {
	old := Legacy(path)
	if old == "" {
		return nil
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if fi, err := os.Stat(old); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	return fmt.Errorf("database %s does not exist, but %s does: before this release, a '#', '?' or %%XX in the path opened that file instead; stop every process using it, move it, with its -wal and -shm files, to %s, then start again", path, old, path)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}
