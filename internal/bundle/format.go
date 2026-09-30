// Package bundle implements the bundles of Addendum G.4: the newline-
// delimited JSON format (§G.4.1) with a streaming Reader and Writer, export
// with a dependency closure (§G.4.2, §G.4.3) and import classified by
// ancestry (§G.4.4). Export and import are clients of the public API
// (internal/client); nothing here is a server operation.
//
// The Writer is also meant for pruning archives (§8.6), which use the
// full-history form of the same format.
//
// # Format decisions (where §G.4.1 leaves room)
//
//   - Every line, header included, is written as canonical JSON (JCS, §3.1)
//     followed by "\n". Readers accept any I-JSON line and ignore blank
//     lines.
//   - The bundle digest used in source.bundle (§3.5, §G.4.4) is
//     text(trunc160(sha256(L₁ ‖ 0x0A ‖ L₂ ‖ 0x0A ‖ … ‖ Lₙ ‖ 0x0A))), where Lᵢ is
//     canonical(line i), header first. For a bundle written by Writer that
//     is the truncated SHA-256 of the file's bytes. The spec only says
//     text(digest); the text form of §3.2 is defined for 160-bit values, so
//     the digest is truncated like an id, and hashing canonical lines makes
//     it independent of whitespace.
//   - Keys of docs and requires are "{ns}/{name}". external entries are
//     "{ns}/{name}" for a live dependency (checked by name in the target)
//     or "{ns}/{name}/rev/{id}" for a pinned one (checked by id).
//   - History lines always carry "parent" ("" for genesis). "author",
//     "created" and "signature" appear only with "authors": true; a line that
//     carries them in a bundle without authors is rejected. Author
//     signatures are carried but not verified (the server does not verify
//     them either, see README).
//   - A deleted snapshot line carries no "doc".
//   - Unknown members in the header or a line are rejected: this is bundle
//     version 1, and strictness catches tampering and truncation early.
//
// # Encryption (§G.5)
//
//   - The header's "access" gives each exporting namespace's protection:
//     "public", "private" (read-restricted, with or without E1), "sealed"
//     (E2) or "e2e" (E3). Its keys must be namespaces of "at"; the exporter
//     writes every one. A namespace missing from it is "private".
//   - E2: the exporter holds keys (a read grant, and an identity when the
//     source wraps them), so lines hold plaintext. Private and sealed
//     content is written as a sealed bundle (sealed.go) unless the exporter
//     is told to write plaintext.
//   - E3: lines carry the ciphertext verbatim, the keyring resource
//     included, and ids verify over it as usual. Only full history: a
//     snapshot needs a client with keys (§G.5.1), which this exporter
//     isn't, so it refuses. Nothing is folded, so an e2e document brings
//     no dependencies.
//   - The importer enforces what the source can't: a private or sealed
//     source goes only into a private or sealed target, an e2e source only
//     into an e2e target of the same name (sealed patch sets bind pl.ns,
//     §E.3.1; importing under another name is a merge by a client holding
//     both sets of keys, §F.8), unless ImportOptions.AllowLessProtected.
//     Missing targets are created as protected as their source.
package bundle

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/verify"
)

// MediaType is the bundle media type (§G.4.1).
const MediaType = "application/vnd.patchlog.bundle+jsonl"

// Version is the bundle format version written in the header.
const Version = 1

// History modes of a document (§G.4.3).
const (
	Full     = "full"
	Snapshot = "snapshot"
)

// Access levels of a namespace in the header's access (§G.5.1).
const (
	AccessPublic  = "public"
	AccessPrivate = "private"
	AccessSealed  = "sealed"
	AccessE2E     = "e2e"
)

func validAccess(s string) bool {
	return s == AccessPublic || s == AccessPrivate || s == AccessSealed || s == AccessE2E
}

// DocInfo is a header docs entry.
type DocInfo struct {
	History string // Full or Snapshot
	Head    string // the last history line's id, or the snapshot's source id
}

// Header is the first line of a bundle.
type Header struct {
	Origin   string
	Created  string
	At       map[string]string  // namespace → ns_id the export was taken at
	Docs     map[string]DocInfo // "ns/name" → mode and head
	External []string           // dependencies deliberately left out
	Requires map[string]string  // "ns/name" → id that must be in the target's chain
	Authors  bool
	Access   map[string]string // namespace → its access level (§G.5.1)
}

// AccessOf is a namespace's access level; one the header doesn't give is
// private (§G.5.1).
func (h *Header) AccessOf(ns string) string {
	if a, ok := h.Access[ns]; ok {
		return a
	}
	return AccessPrivate
}

// Key is the docs key of a resource.
func Key(ns, name string) string { return ns + "/" + name }

// SplitKey splits a docs key.
func SplitKey(k string) (ns, name string, ok bool) {
	i := strings.IndexByte(k, '/')
	if i < 0 {
		return "", "", false
	}
	ns, name = k[:i], k[i+1:]
	return ns, name, client.ValidNSName(ns) && client.ValidResourceName(name)
}

// External is a parsed external entry.
type External struct {
	NS, Name string
	Rev      string // "" for a live dependency
}

func (e External) String() string {
	if e.Rev != "" {
		return e.NS + "/" + e.Name + "/rev/" + e.Rev
	}
	return e.NS + "/" + e.Name
}

var externalRE = regexp.MustCompile(`^([a-z0-9][a-z0-9_-]{0,63})/([a-z0-9][a-z0-9._-]{0,127})(?:/rev/(1[a-z2-7]{32}))?$`)

// ParseExternal parses an external entry.
func ParseExternal(s string) (External, bool) {
	m := externalRE.FindStringSubmatch(s)
	if m == nil {
		return External{}, false
	}
	return External{NS: m[1], Name: m[2], Rev: m[3]}, true
}

// Line is one entry line: a history line (Snapshot == "") or a snapshot line.
type Line struct {
	NS, Resource string

	// History lines (§3.3, §3.4).
	ID, Parent, Kind string // Kind "rev" or "tombstone"
	Patches          any    // canonical patch set (jsonv model), revisions only
	// Attribution, only with Header.Authors.
	Author, Created, Signature string

	// Snapshot lines.
	Snapshot string // the source id: head revision, or tombstone if Deleted
	Doc      any
	Deleted  bool
}

// IsSnapshot reports a snapshot line.
func (l *Line) IsSnapshot() bool { return l.Snapshot != "" }

// Key is the line's docs key.
func (l *Line) Key() string { return Key(l.NS, l.Resource) }

// LogEntry returns a history line as a resource log entry.
func (l *Line) LogEntry() client.LogEntry {
	return client.LogEntry{ID: l.ID, Parent: l.Parent, Kind: l.Kind, Patches: l.Patches,
		HasPatches: l.Kind == "rev" && l.Patches != nil, Author: l.Author, Created: l.Created, Signature: l.Signature}
}

// HistoryLine converts a verified log entry of ns/name into a line. The
// attribution fields are kept only if authors is set.
func HistoryLine(ns, name string, e client.LogEntry, authors bool) Line {
	l := Line{NS: ns, Resource: name, ID: e.ID, Parent: e.Parent, Kind: e.Kind}
	if e.Kind == "rev" {
		l.Patches = e.Patches
	}
	if authors {
		l.Author, l.Created, l.Signature = e.Author, e.Created, e.Signature
	}
	return l
}

func (l *Line) value() map[string]any {
	m := map[string]any{"ns": l.NS, "resource": l.Resource}
	if l.IsSnapshot() {
		m["snapshot"] = l.Snapshot
		if l.Deleted {
			m["deleted"] = true
		} else {
			m["doc"] = l.Doc
		}
		return m
	}
	m["id"], m["parent"], m["kind"] = l.ID, l.Parent, l.Kind
	if l.Kind == "rev" {
		m["patches"] = l.Patches
	}
	for k, v := range map[string]string{"author": l.Author, "created": l.Created, "signature": l.Signature} {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

func (h *Header) value() map[string]any {
	at := map[string]any{}
	for k, v := range h.At {
		at[k] = v
	}
	docs := map[string]any{}
	for k, d := range h.Docs {
		docs[k] = map[string]any{"history": d.History, "head": d.Head}
	}
	m := map[string]any{"bundle": float64(Version), "origin": h.Origin, "created": h.Created,
		"at": at, "docs": docs, "authors": h.Authors}
	if len(h.External) > 0 {
		ext := append([]string(nil), h.External...)
		sort.Strings(ext)
		a := make([]any, len(ext))
		for i, e := range ext {
			a[i] = e
		}
		m["external"] = a
	}
	if len(h.Requires) > 0 {
		r := map[string]any{}
		for k, v := range h.Requires {
			r[k] = v
		}
		m["requires"] = r
	}
	if len(h.Access) > 0 {
		a := map[string]any{}
		for k, v := range h.Access {
			a[k] = v
		}
		m["access"] = a
	}
	return m
}

// --- errors ------------------------------------------------------------

// Error reports a bundle that fails a check of §G.4.1. Line is 1-based (the
// header is line 1); 0 means a whole-bundle check at the end.
type Error struct {
	Line int
	Key  string // the document concerned, if any
	Msg  string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("bundle: ")
	if e.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", e.Line)
	}
	if e.Key != "" {
		b.WriteString(e.Key + ": ")
	}
	b.WriteString(e.Msg)
	return b.String()
}

// ErrInvalid matches every *Error with errors.Is.
var ErrInvalid = errors.New("bundle: invalid")

func (e *Error) Is(target error) bool { return target == ErrInvalid }

// --- header parsing and checks -------------------------------------------

var idRE = regexp.MustCompile(`^1[a-z2-7]{32}$`)

func validID(s string) bool { return idRE.MatchString(s) }

func parseHeader(v any) (*Header, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the header is not an object")
	}
	for k := range m {
		switch k {
		case "bundle", "origin", "created", "at", "docs", "external", "requires", "authors", "access":
		default:
			return nil, fmt.Errorf("unknown header member %q", k)
		}
	}
	if n, _ := m["bundle"].(float64); n != Version {
		return nil, fmt.Errorf("not a version %d bundle (bundle: %v)", Version, m["bundle"])
	}
	h := &Header{At: map[string]string{}, Docs: map[string]DocInfo{}, Requires: map[string]string{}, Access: map[string]string{}}
	h.Origin, _ = m["origin"].(string)
	if h.Origin == "" {
		return nil, fmt.Errorf("header needs an origin")
	}
	h.Created, _ = m["created"].(string)
	if h.Created == "" {
		return nil, fmt.Errorf("header needs created")
	}
	if a, has := m["authors"]; has {
		b, ok := a.(bool)
		if !ok {
			return nil, fmt.Errorf("authors must be a boolean")
		}
		h.Authors = b
	}
	at, ok := m["at"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("header needs at")
	}
	for ns, v := range at {
		id, _ := v.(string)
		if !client.ValidNSName(ns) || !validID(id) {
			return nil, fmt.Errorf("at: invalid entry %q", ns)
		}
		h.At[ns] = id
	}
	if a, has := m["access"]; has {
		am, ok := a.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("access must be an object")
		}
		for ns, v := range am {
			s, _ := v.(string)
			if _, ok := h.At[ns]; !ok {
				return nil, fmt.Errorf("access: namespace %s has no at", ns)
			}
			if !validAccess(s) {
				return nil, fmt.Errorf("access: %s: must be %q, %q, %q or %q", ns, AccessPublic, AccessPrivate, AccessSealed, AccessE2E)
			}
			h.Access[ns] = s
		}
	}
	docs, ok := m["docs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("header needs docs")
	}
	for k, v := range docs {
		ns, _, ok := SplitKey(k)
		if !ok {
			return nil, fmt.Errorf("docs: invalid key %q", k)
		}
		if _, ok := h.At[ns]; !ok {
			return nil, fmt.Errorf("docs: %s: namespace %s has no at", k, ns)
		}
		d, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("docs: %s is not an object", k)
		}
		for dk := range d {
			if dk != "history" && dk != "head" {
				return nil, fmt.Errorf("docs: %s: unknown member %q", k, dk)
			}
		}
		info := DocInfo{}
		info.History, _ = d["history"].(string)
		info.Head, _ = d["head"].(string)
		if info.History != Full && info.History != Snapshot {
			return nil, fmt.Errorf("docs: %s: history must be %q or %q", k, Full, Snapshot)
		}
		if !validID(info.Head) {
			return nil, fmt.Errorf("docs: %s: invalid head", k)
		}
		h.Docs[k] = info
	}
	if r, has := m["requires"]; has {
		rm, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requires must be an object")
		}
		for k, v := range rm {
			id, _ := v.(string)
			if !validID(id) {
				return nil, fmt.Errorf("requires: %s: invalid id", k)
			}
			d, ok := h.Docs[k]
			if !ok {
				return nil, fmt.Errorf("requires: %s is not in docs", k)
			}
			if d.History != Full {
				return nil, fmt.Errorf("requires: %s: requires applies only to full documents", k)
			}
			if id == d.Head {
				return nil, fmt.Errorf("requires: %s: the required id is the head, so the document has no lines", k)
			}
			h.Requires[k] = id
		}
	}
	if e, has := m["external"]; has {
		arr, ok := e.([]any)
		if !ok {
			return nil, fmt.Errorf("external must be an array")
		}
		for _, x := range arr {
			s, _ := x.(string)
			ext, ok := ParseExternal(s)
			if !ok {
				return nil, fmt.Errorf("external: invalid entry %q", s)
			}
			if ext.Rev == "" {
				if _, in := h.Docs[Key(ext.NS, ext.Name)]; in {
					return nil, fmt.Errorf("external: %s is also in docs", s)
				}
			}
			h.External = append(h.External, s)
		}
	}
	return h, nil
}

// checkHeader validates a header built in memory (for Writer).
func checkHeader(h *Header) error {
	_, err := parseHeader(jsonv.FromGo(h.value()))
	return err
}

// --- line parsing ----------------------------------------------------------

func parseLine(v any, authors bool) (*Line, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("line is not an object")
	}
	l := &Line{}
	l.NS, _ = m["ns"].(string)
	l.Resource, _ = m["resource"].(string)
	if !client.ValidNSName(l.NS) || !client.ValidResourceName(l.Resource) {
		return nil, fmt.Errorf("line needs a valid ns and resource")
	}
	if snap, has := m["snapshot"]; has {
		for k := range m {
			switch k {
			case "ns", "resource", "snapshot", "doc", "deleted":
			default:
				return nil, fmt.Errorf("snapshot line: unknown member %q", k)
			}
		}
		l.Snapshot, _ = snap.(string)
		if !validID(l.Snapshot) {
			return nil, fmt.Errorf("snapshot line: invalid snapshot id")
		}
		if d, has := m["deleted"]; has {
			if d != true {
				return nil, fmt.Errorf("snapshot line: deleted must be true if present")
			}
			l.Deleted = true
			if _, hasDoc := m["doc"]; hasDoc {
				return nil, fmt.Errorf("snapshot line: a deleted document carries no doc")
			}
			return l, nil
		}
		doc, hasDoc := m["doc"]
		if !hasDoc {
			return nil, fmt.Errorf("snapshot line: missing doc")
		}
		l.Doc = doc
		return l, nil
	}
	for k := range m {
		switch k {
		case "ns", "resource", "id", "parent", "kind", "patches":
		case "author", "created", "signature":
			if !authors {
				return nil, fmt.Errorf("history line carries %q in a bundle without authors", k)
			}
		default:
			return nil, fmt.Errorf("history line: unknown member %q", k)
		}
	}
	l.ID, _ = m["id"].(string)
	l.Parent, _ = m["parent"].(string)
	l.Kind, _ = m["kind"].(string)
	l.Author, _ = m["author"].(string)
	l.Created, _ = m["created"].(string)
	l.Signature, _ = m["signature"].(string)
	if !validID(l.ID) {
		return nil, fmt.Errorf("history line: invalid id")
	}
	if l.Parent != "" && !validID(l.Parent) {
		return nil, fmt.Errorf("history line: invalid parent")
	}
	switch l.Kind {
	case "rev":
		p, has := m["patches"]
		if !has {
			return nil, fmt.Errorf("history line %s: a revision without patches (pruned history can't be bundled without its archive)", l.ID)
		}
		if _, ok := p.([]any); !ok {
			return nil, fmt.Errorf("history line %s: patches must be an array", l.ID)
		}
		l.Patches = p
	case "tombstone":
		if _, has := m["patches"]; has {
			return nil, fmt.Errorf("history line %s: a tombstone carries no patches", l.ID)
		}
	default:
		return nil, fmt.Errorf("history line: kind must be rev or tombstone")
	}
	return l, nil
}

// --- the checker shared by Reader and Writer ---------------------------------

type docState struct {
	lines int
	last  string // last id (full) or the snapshot id
}

type checker struct {
	h    *Header
	docs map[string]*docState
	n    int // lines checked, header included
	hash hash.Hash
}

func newChecker(h *Header) *checker {
	return &checker{h: h, docs: map[string]*docState{}, n: 1, hash: sha256.New()}
}

func (c *checker) digestLine(canon []byte) {
	c.hash.Write(canon)
	c.hash.Write([]byte{0x0A})
}

// line checks one entry line (§G.4.1), recomputing history ids.
func (c *checker) line(l *Line) error {
	c.n++
	k := l.Key()
	fail := func(format string, args ...any) error {
		return &Error{Line: c.n, Key: k, Msg: fmt.Sprintf(format, args...)}
	}
	if _, ok := c.h.At[l.NS]; !ok {
		return fail("namespace %s has no at in the header", l.NS)
	}
	info, ok := c.h.Docs[k]
	if !ok {
		return fail("not listed in the header's docs")
	}
	st := c.docs[k]
	if st == nil {
		st = &docState{}
		c.docs[k] = st
	}
	if l.IsSnapshot() {
		if info.History != Snapshot {
			return fail("a snapshot line for a %s document", info.History)
		}
		if st.lines > 0 {
			return fail("more than one snapshot line")
		}
		if l.Snapshot != info.Head {
			return fail("snapshot %s is not the header's head %s", l.Snapshot, info.Head)
		}
		st.lines, st.last = 1, l.Snapshot
		return nil
	}
	if info.History != Full {
		return fail("a history line for a %s document", info.History)
	}
	want := c.h.Requires[k] // "" = genesis
	if st.lines > 0 {
		want = st.last
	}
	if l.Parent != want {
		if st.lines == 0 {
			if want == "" {
				return fail("the chain must start at genesis (parent %q) or name its parent in requires", l.Parent)
			}
			return fail("the chain must start right after requires %s, not after %q", want, l.Parent)
		}
		return fail("line %s out of chain order: parent %q, want %q", l.ID, l.Parent, want)
	}
	id, err := verify.LogEntryID(l.Parent, l.LogEntry())
	if err != nil {
		return fail("%s: %v", l.ID, err)
	}
	if id != l.ID {
		return fail("id %s does not match its content (recomputed %s)", l.ID, id)
	}
	st.lines++
	st.last = id
	return nil
}

// finish runs the whole-bundle checks and returns the digest.
func (c *checker) finish() (string, error) {
	keys := make([]string, 0, len(c.h.Docs))
	for k := range c.h.Docs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		info := c.h.Docs[k]
		st := c.docs[k]
		if st == nil || st.lines == 0 {
			return "", &Error{Key: k, Msg: "listed in docs but has no lines (truncated bundle?)"}
		}
		if st.last != info.Head {
			return "", &Error{Key: k, Msg: fmt.Sprintf("the last line is %s, not the header's head %s (truncated bundle?)", st.last, info.Head)}
		}
	}
	return digestText(c.hash), nil
}

func digestText(h hash.Hash) string {
	var id ids.ID
	copy(id[:], h.Sum(nil))
	return id.String()
}

// --- Reader --------------------------------------------------------------

// Reader reads a bundle line by line, checking every line as it goes and
// the whole bundle at the end (§G.4.1). It holds only per-document chain
// state, never the bundle's content.
type Reader struct {
	br     *bufio.Reader
	h      *Header
	c      *checker
	lineNo int
	digest string
	done   bool
}

// NewReader reads and checks the header.
func NewReader(r io.Reader) (*Reader, error) {
	rd := &Reader{br: bufio.NewReaderSize(r, 1<<16)}
	v, canon, err := rd.next()
	if err != nil {
		if err == io.EOF {
			return nil, &Error{Line: 1, Msg: "empty bundle"}
		}
		return nil, err
	}
	h, err := parseHeader(v)
	if err != nil {
		return nil, &Error{Line: rd.lineNo, Msg: err.Error()}
	}
	rd.h = h
	rd.c = newChecker(h)
	rd.c.digestLine(canon)
	return rd, nil
}

// Header is the bundle's header.
func (r *Reader) Header() *Header { return r.h }

func (r *Reader) next() (any, []byte, error) {
	for {
		b, err := r.br.ReadBytes('\n')
		if len(b) == 0 && err != nil {
			if err == io.EOF {
				return nil, nil, io.EOF
			}
			return nil, nil, err
		}
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		r.lineNo++
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		v, perr := jsonv.Parse(b)
		if perr != nil {
			return nil, nil, &Error{Line: r.lineNo, Msg: "not I-JSON: " + perr.Error()}
		}
		return v, jsonv.Canonical(v), nil
	}
}

// Next returns the next line, checked. At the end it runs the whole-bundle
// checks and returns io.EOF if they pass, or an *Error.
func (r *Reader) Next() (*Line, error) {
	if r.done {
		return nil, io.EOF
	}
	v, canon, err := r.next()
	if err == io.EOF {
		d, ferr := r.c.finish()
		if ferr != nil {
			return nil, ferr
		}
		r.digest, r.done = d, true
		return nil, io.EOF
	}
	if err != nil {
		return nil, err
	}
	l, err := parseLine(v, r.h.Authors)
	if err != nil {
		return nil, &Error{Line: r.lineNo, Msg: err.Error()}
	}
	r.c.n = r.lineNo - 1
	if err := r.c.line(l); err != nil {
		return nil, err
	}
	r.c.digestLine(canon)
	return l, nil
}

// Digest is the bundle digest; it is set once Next has returned io.EOF.
func (r *Reader) Digest() string { return r.digest }

// Summary describes a verified bundle.
type Summary struct {
	Header *Header
	Digest string
	Lines  int // entry lines, header excluded
}

// Verify reads a whole bundle, checking every line and the whole bundle.
func Verify(r io.Reader) (*Summary, error) {
	rd, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	n := 0
	for {
		_, err := rd.Next()
		if err == io.EOF {
			return &Summary{Header: rd.Header(), Digest: rd.Digest(), Lines: n}, nil
		}
		if err != nil {
			return nil, err
		}
		n++
	}
}

// --- Writer ----------------------------------------------------------------

// Writer writes a bundle. The header must be complete up front (every docs
// entry with its head); lines are checked against it as they are written,
// with the same checks a Reader applies, so a Writer never produces a
// bundle a Reader rejects. Close runs the whole-bundle checks.
type Writer struct {
	bw     *bufio.Writer
	h      *Header
	c      *checker
	digest string
	closed bool
}

// NewWriter checks the header and writes it.
func NewWriter(w io.Writer, h Header) (*Writer, error) {
	if h.At == nil {
		h.At = map[string]string{}
	}
	if h.Docs == nil {
		h.Docs = map[string]DocInfo{}
	}
	if err := checkHeader(&h); err != nil {
		return nil, &Error{Line: 1, Msg: err.Error()}
	}
	// Re-read the header in its parsed form so Requires is never nil.
	hp, _ := parseHeader(jsonv.FromGo(h.value()))
	wr := &Writer{bw: bufio.NewWriterSize(w, 1<<16), h: hp, c: newChecker(hp)}
	if err := wr.emit(h.value()); err != nil {
		return nil, err
	}
	return wr, nil
}

// Header is the header written.
func (w *Writer) Header() *Header { return w.h }

func (w *Writer) emit(v map[string]any) error {
	canon := jsonv.Canonical(jsonv.FromGo(v))
	w.c.digestLine(canon)
	if _, err := w.bw.Write(canon); err != nil {
		return err
	}
	return w.bw.WriteByte('\n')
}

// Line writes one line after checking it.
func (w *Writer) Line(l Line) error {
	if w.closed {
		return errors.New("bundle: write after Close")
	}
	if !w.h.Authors {
		l.Author, l.Created, l.Signature = "", "", ""
	}
	if l.IsSnapshot() && !l.Deleted {
		v, err := client.ToValue(docJSON(l.Doc))
		if err != nil {
			return &Error{Line: w.c.n + 1, Key: l.Key(), Msg: "doc: " + err.Error()}
		}
		l.Doc = v
	}
	if !l.IsSnapshot() && l.Kind == "rev" {
		v, err := client.ToValue(docJSON(l.Patches))
		if err != nil {
			return &Error{Line: w.c.n + 1, Key: l.Key(), Msg: "patches: " + err.Error()}
		}
		l.Patches = v
	}
	if err := w.c.line(&l); err != nil {
		return err
	}
	return w.emit(l.value())
}

// docJSON lets nil documents through as JSON null.
func docJSON(v any) any {
	if v == nil {
		return []byte("null")
	}
	return v
}

// History writes a log entry of ns/name as a history line.
func (w *Writer) History(ns, name string, e client.LogEntry) error {
	return w.Line(HistoryLine(ns, name, e, w.h.Authors))
}

// SnapshotDoc writes a snapshot line; with deleted, id is the tombstone and
// doc is ignored.
func (w *Writer) SnapshotDoc(ns, name, id string, doc any, deleted bool) error {
	l := Line{NS: ns, Resource: name, Snapshot: id, Deleted: deleted}
	if !deleted {
		l.Doc = doc
	}
	return w.Line(l)
}

// Close runs the whole-bundle checks, flushes, and returns the digest. The
// underlying writer is not closed.
func (w *Writer) Close() (string, error) {
	if w.closed {
		return w.digest, nil
	}
	w.closed = true
	d, err := w.c.finish()
	if err != nil {
		w.bw.Flush()
		return "", err
	}
	w.digest = d
	return d, w.bw.Flush()
}

// Digest is the bundle digest, set by Close.
func (w *Writer) Digest() string { return w.digest }
