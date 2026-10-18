package dav

import (
	"bytes"
	"encoding/json"
	"mime"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// Files (Addendum H): a file other than a JSON file is a raw document,
// whose root is a blob reference (§7.8) to its bytes, kept exactly; a JSON
// file is a document, read as its rendering (§H.1).

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

// fileType is the type of a raw file named name, uploaded with
// Content-Type ctype ("" for none), as every tool stores it (§H.1): by the
// name's extension (extTypes), else ctype without its parameters unless it
// says nothing of the bytes (an octet stream, a form), else
// application/octet-stream.
func fileType(name, ctype string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		if t, ok := extTypes[strings.ToLower(name[i+1:])]; ok {
			return t
		}
	}
	if mt, _, err := mime.ParseMediaType(ctype); err == nil {
		mt = strings.ToLower(mt)
		switch {
		case mt == "application/octet-stream", mt == "binary/octet-stream", mt == "application/x-www-form-urlencoded",
			strings.HasPrefix(mt, "multipart/"):
		case blobTypeRe.MatchString(mt):
			return mt
		}
	}
	return "application/octet-stream"
}

// bare is a document as a file shows it (§H.1): without a top-level $nonce
// of the fresh form (§6.4.1) and a $successor of §8.1's, which are the
// writers' mechanics, not content. Any other value is returned as it is.
func bare(doc any) any {
	m, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	left := func(k string) bool {
		v, has := m[k]
		return has && (k == "$nonce" || k == "$successor") && schema.LeftOut(k, v)
	}
	if !left("$nonce") && !left("$successor") {
		return doc
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if !left(k) {
			out[k] = v
		}
	}
	return out
}

// render is a JSON file's rendering (§H.1): the canonical text (§3.1) of
// the document as bare shows it, laid out as JSON.stringify(v, null, 2)
// lays it out, with one final LF. The canonical text is laid out, never a
// parsed object serialised again, so members keep JCS's order (keys that
// look like array indices too), and a revision always reads as the same
// bytes.
func render(v any) []byte {
	var b bytes.Buffer
	if err := json.Indent(&b, jsonv.Canonical(bare(v)), "", "  "); err != nil {
		panic("dav: canonical JSON doesn't indent: " + err.Error())
	}
	b.WriteByte('\n')
	return b.Bytes()
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
// *.swp, 4913, *~, #*#, *___jb_tmp___ and .goutputstream-*; *___jb_old___,
// where JetBrains' safe write moves the original aside before moving its
// *___jb_tmp___ in; and "Icon\r", where macOS keeps a folder's custom
// icon, a name no title can be (a CR), which a Finder copy of such a folder
// writes. A name a real file has is that file's, whatever it looks like
// (resolveFlat).
func scratchName(base string) bool {
	switch {
	case base == ".DS_Store", base == "Thumbs.db", base == "4913", base == "Icon\r",
		strings.HasPrefix(base, "._"), strings.HasPrefix(base, "~$"), strings.HasPrefix(base, ".goutputstream-"),
		strings.HasSuffix(base, ".swp"), strings.HasSuffix(base, "~"),
		len(base) > 1 && base[0] == '#' && base[len(base)-1] == '#',
		strings.HasSuffix(base, "___jb_tmp___"), strings.HasSuffix(base, "___jb_old___"):
		return true
	}
	return false
}

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
