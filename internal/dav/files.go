package dav

import (
	"mime"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Files (Addendum H): a file other than a JSON file is a raw document,
// whose root is a blob reference (§7.8) to its bytes, kept exactly; a JSON
// file is a document, read as its rendering (§H.1), which internal/files
// makes, as for every tool (files.Rendering, files.Bare).

// extTypes is §H.1's table: a raw file's type by its name's extension, in
// any letter case, so two tools store the same file alike.
var extTypes = map[string]string{
	"md": "text/markdown", "markdown": "text/markdown",
	"txt": "text/plain", "text": "text/plain",
	"html": "text/html", "htm": "text/html",
	"css": "text/css",
	"js":  "text/javascript", "mjs": "text/javascript",
	"csv":  "text/csv",
	"xml":  "application/xml",
	"yaml": "application/yaml", "yml": "application/yaml",
	"json": "application/json",
	"png":  "image/png",
	"jpg":  "image/jpeg", "jpeg": "image/jpeg",
	"gif":  "image/gif",
	"webp": "image/webp",
	"svg":  "image/svg+xml",
	"pdf":  "application/pdf",
	"zip":  "application/zip",
	"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

// blobTypeRe is a type a blob id takes (§3.7), as the core checks it.
var blobTypeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)

// fileType is the type a raw file named name, holding body, is stored
// with, as every tool takes it (§H.1): by the name's extension
// (extTypes); else the upload's Content-Type ctype ("" for none) without
// its parameters, unless it says nothing of the bytes (an octet stream, a
// form); else, for an existing file, had, the type it has ("" for a new
// one); else application/octet-stream. A text/ type needs body in UTF-8,
// a leading BOM allowed (§3.7): any other body is
// application/octet-stream, whatever the name or upload says. The type is
// part of the blob id (§3.7), so it is taken once the head is read.
func fileType(name, ctype, had string, body []byte) string {
	typ := declaredType(name, ctype)
	if typ == "" {
		typ = had
	}
	if typ == "" || !textOK(typ, body) {
		return octetStream
	}
	return typ
}

// octetStream is the type of bytes nothing says more of (§H.1).
const octetStream = "application/octet-stream"

// declaredType is the type a raw file's name or upload says (fileType),
// "" where neither says one.
func declaredType(name, ctype string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		if t, ok := extTypes[strings.ToLower(name[i+1:])]; ok {
			return t
		}
	}
	if mt, _, err := mime.ParseMediaType(ctype); err == nil {
		mt = strings.ToLower(mt)
		switch {
		case mt == octetStream, mt == "binary/octet-stream", mt == "application/x-www-form-urlencoded",
			strings.HasPrefix(mt, "multipart/"):
		case blobTypeRe.MatchString(mt):
			return mt
		}
	}
	return ""
}

// textOK reports whether body may be stored as type typ (§H.1, §3.7): a
// text/ type needs UTF-8, a leading BOM allowed.
func textOK(typ string, body []byte) bool {
	return !strings.HasPrefix(typ, "text/") || utf8.Valid(trimBOM(body))
}

// rawRef is a raw document's blob reference (§7.8): the file's bytes, as
// blob bid of type typ and size bytes, under nonce ("" for none).
type rawRef struct {
	bid, typ, nonce string
	size            int64
}

// rawRefOf is doc's blob reference if doc is raw (§7.8 Files), else nil.
func rawRefOf(doc any, bid string) *rawRef {
	if bid == "" {
		return nil
	}
	m := doc.(map[string]any)
	r := &rawRef{bid: bid}
	r.typ, _ = m["type"].(string)
	r.nonce, _ = m["nonce"].(string)
	n, _ := m["size"].(float64)
	r.size = int64(n)
	return r
}

// refOf is a raw document's blob reference alone, what a raw file's save
// compares and sets member by member (§H.4), the root's other members
// ($schema, $nonce, $successor) left as they are; {} for any other value.
func refOf(doc any) any {
	m, _ := doc.(map[string]any)
	out := map[string]any{}
	for _, k := range []string{"$blob", "type", "size", "nonce"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// scratchName reports the names of editors' and systems' own files, kept
// by the gateway as scratch files (§H.6): .DS_Store, ._*, Thumbs.db, ~$*,
// .~lock.*# (LibreOffice's lock files), *.swp, *.swo and *.swx (vim's
// swap files), 4913, *~, #*#, *___jb_tmp___ and .goutputstream-*;
// *___jb_old___, where JetBrains' safe write moves the original aside
// before moving its *___jb_tmp___ in; sed followed by six letters or
// digits, the temporary file sed -i writes beside the file it edits; and
// "Icon\r", where macOS keeps a folder's custom icon, a name no title can
// be (a CR), which a Finder copy of such a folder writes. A name a real
// file has is that file's, whatever it looks like (resolveFlat,
// resolveIn): an existing name always wins over a pattern.
func scratchName(base string) bool {
	switch {
	case base == ".DS_Store", base == "Thumbs.db", base == "4913", base == "Icon\r",
		strings.HasPrefix(base, "._"), strings.HasPrefix(base, "~$"), strings.HasPrefix(base, ".goutputstream-"),
		len(base) > len(".~lock.") && strings.HasPrefix(base, ".~lock.") && strings.HasSuffix(base, "#"),
		strings.HasSuffix(base, ".swp"), strings.HasSuffix(base, ".swo"), strings.HasSuffix(base, ".swx"),
		strings.HasSuffix(base, "~"),
		len(base) > 1 && base[0] == '#' && base[len(base)-1] == '#',
		strings.HasSuffix(base, "___jb_tmp___"), strings.HasSuffix(base, "___jb_old___"),
		sedTemp.MatchString(base):
		return true
	}
	return false
}

// sedTemp is the name of sed -i's temporary file (§H.6): sed and six
// letters or digits, as mkstemp draws them.
var sedTemp = regexp.MustCompile(`^sed[A-Za-z0-9]{6}$`)

// dupName is the name a file whose name another has is shown by (§H.2
// "Siblings"): name (2).ext, name (3).ext, …, the number before the
// extension (a folder's at the end), skipping one taken reports taken;
// within maxTitle bytes, the stem cut short (at a character) to fit.
func dupName(name string, dir bool, taken func(string) bool) string {
	stem, ext := name, ""
	if i := strings.LastIndexByte(name, '.'); i > 0 && !dir {
		stem, ext = name[:i], name[i:]
	}
	for n := 2; ; n++ {
		num := " (" + strconv.Itoa(n) + ")"
		s, e := stem, ext
		if len(s)+len(num)+len(e) > maxTitle && len(num)+len(e) >= maxTitle {
			s, e = stem+ext, ""
		}
		for len(s)+len(num)+len(e) > maxTitle {
			_, size := utf8.DecodeLastRuneInString(s)
			s = s[:len(s)-size]
		}
		if d := s + num + e; !taken(d) {
			return d
		}
	}
}

// dupOf is the name a duplicate's name (dupName) stands for, and its
// number; false for a name that isn't one.
func dupOf(base string) (string, int, bool) {
	m := dupNames.FindStringSubmatch(base)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	return m[1] + m[3], n, err == nil && n >= 2
}

var dupNames = regexp.MustCompile(`^(.+) \(([0-9]+)\)(\.[^.]*)?$`)
