package dav

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// File trees (§H.2): a namespace whose documents carry their place as
// data. A file is a document { $schema, folder, name, content } under an
// opaque resource name, its file content (a blob reference for a raw
// file, any value for a JSON file); a folder is one without content, the
// folder {folder}/{name}, or /{name} at the top. A document is in the tree
// only when its folder is / or has a folder document: folders are listed
// one at a time from the top, through the index (§H.3: GET
// /{ns}?facet[/folder]={path}&schema=/r/schemas/file&sort=/name, paged),
// so one whose folder has no folder document is never reached. A rename
// or a move is one append replacing /name or /folder (§H.5), a folder's
// one batch over it and every visible document under it.
//
// The index lags the core (§A.5), so before any write the documents a
// listing resolved are read again, and each must still have the folder
// and name the path named; where one doesn't, the folder is listed again
// with ?min at the namespace's head, which an index behind answers 503
// (§H.4 "Names before writes"). Every listing sends the ns_ids of this
// server's last writes in the namespace as ?min (§H.3 "Read-your-writes"),
// so a folder is empty only when a listing at or past them has nothing
// in it.
//
// What the rest of the package says of a file's document holds of a tree
// file's content (§H.2 "content"): the save engine (write.go, raw.go)
// sees the content as the document (treeEntry), and its patch sets are
// sent under /content (appendFile), with the $nonce at the document's
// top level; others' writes are content's (contentWrites), so a rename
// never conflicts with a save.

// treeEnt is a name in a tree folder's listing: a file, its document, or
// a folder, its folder documents (two for one path, left by a race, are
// one folder, §H.2).
type treeEnt struct {
	title string // the title the documents have (shown escaped if it breaks the rules)
	dir   bool
	hds   []headDoc
}

// appendFile appends ps, a patch set of tree file ns/name's content (or
// a flat namespace's document's), on head: in a tree each operation goes
// under /content, but the $nonce withNonce added, which is the
// document's.
func (st *reqState) appendFile(ctx context.Context, in nsInfo, ns, name, head string, ps []any) (*client.WriteResult, error) {
	if in.tree {
		ps = underContent(ps)
	}
	return st.tk.c.Append(ctx, ns, name, head, ps)
}

// underContent is patch set ps of a file's content as one of its
// document: paths (and from) under /content, but a $nonce's (nonceOp).
func underContent(ps []any) []any {
	out := make([]any, len(ps))
	for i, op := range ps {
		m, ok := op.(map[string]any)
		if !ok || nonceOp(op) {
			out[i] = op
			continue
		}
		c := make(map[string]any, len(m))
		for k, v := range m {
			c[k] = v
		}
		for _, k := range []string{"path", "from"} {
			if p, ok := m[k].(string); ok {
				c[k] = "/content" + p
			}
		}
		out[i] = c
	}
	return out
}

// nonceOp reports the fresh $nonce withNonce adds (§C.7), which is a
// tree document's own, never its content's.
func nonceOp(op any) bool {
	m, _ := op.(map[string]any)
	p, _ := m["path"].(string)
	o, _ := m["op"].(string)
	return p == seal.NoncePath && o == "add"
}

// contentWrites is the writes of a tree document's log entries (spans,
// logWrites) as writes of its content: a write under /content is the
// content's at the rest of its path, one of the whole document the whole
// content's, and others (its folder or name: a move, a rename) none of
// the file's.
func contentWrites(ws [][]pointer.Pointer) [][]pointer.Pointer {
	out := make([][]pointer.Pointer, len(ws))
	for i, w := range ws {
		for _, p := range w {
			switch {
			case len(p) == 0:
				out[i] = append(out[i], pointer.Pointer{})
			case p[0] == "content":
				out[i] = append(out[i], append(pointer.Pointer{}, p[1:]...))
			}
		}
	}
	return out
}

// treeGone is a save's answer for a tree file whose document was deleted
// after the listing named it: a 409 asking for a reload (§H.4 "Answers").
func treeGone(p string) error {
	return fail(http.StatusConflict, "%s was deleted meanwhile; reload the folder", p)
}

// Titles (§H.2): a file's or folder's name is its document's title,
// Unicode a person gave it, compared with its siblings' after NFC and,
// unless the server is case-sensitive (Options.CaseSensitive), after case
// folding (files.TitleKey).

// titleWhy says why name can't be given to a file or folder in a tree
// (§H.2 "Titles"), "" if it can: it must be UTF-8 (NFC is the caller's,
// which normalises), 1 to 255 bytes of it, not . or .., without /, \,
// NUL, characters of Cc, Zl and Zp, or the bidirectional controls
// U+202A–U+202E and U+2066–U+2069 (other Cf characters, joiners, soft
// hyphens, LRM and RLM, are allowed); and, since Windows drops them,
// without a trailing space or dot.
func titleWhy(name string) string {
	switch {
	case !utf8.ValidString(name):
		return "it isn't UTF-8"
	case name == "":
		return "it is empty"
	case len(name) > maxTitle:
		return fmt.Sprintf("it is %d bytes of UTF-8, over %d", len(name), maxTitle)
	case name == "." || name == "..":
		return "it is . or .."
	case strings.HasSuffix(name, " ") || strings.HasSuffix(name, "."):
		return "it ends in a space or a dot, which Windows drops"
	}
	for _, r := range name {
		if badTitleRune(r) {
			return fmt.Sprintf("it holds %U, and titles hold no /, \\, NUL, control characters, bidirectional controls (U+202A–U+202E, U+2066–U+2069), nor line or paragraph separators", r)
		}
	}
	return ""
}

// badTitleRune reports a character no title holds (§H.2 "Titles").
func badTitleRune(r rune) bool {
	return r == '/' || r == '\\' || r == 0 || unicode.In(r, unicode.Cc, unicode.Zl, unicode.Zp) ||
		r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069
}

// newTitle is the title a new file or folder named name is given, or a
// renamed one: name in NFC, refused (403) if it breaks the rules
// (titleWhy), for every client (§H.2).
func newTitle(name string) (string, error) {
	t := norm.NFC.String(name)
	if why := titleWhy(t); why != "" {
		return "", fail(http.StatusForbidden, "%q can't name a file or folder here: %s; a name in a file tree is 1 to 255 bytes of UTF-8, not . or .., without /, \\, NUL, control characters or bidirectional controls, and doesn't end in a space or a dot (§H.2)", name, why)
	}
	return t, nil
}

// shown is a title as a file name (§H.2 "Titles"): as it is if it keeps
// the rules, else escaped, so a title another tool wrote never corrupts a
// listing: in NFC, its invalid bytes and the characters titles can't hold
// as %XX of their UTF-8, as are a lone . or .. and a trailing space or
// dot, within 255 bytes. The bool says it was escaped.
func shown(title string) (string, bool) {
	if title != "" && titleWhy(title) == "" && norm.NFC.IsNormalString(title) {
		return title, false
	}
	var valid strings.Builder
	for i := 0; i < len(title); {
		r, n := utf8.DecodeRuneInString(title[i:])
		if r == utf8.RuneError && n == 1 {
			fmt.Fprintf(&valid, "%%%02X", title[i])
		} else {
			valid.WriteString(title[i : i+n])
		}
		i += n
	}
	var toks []string
	for _, r := range norm.NFC.String(valid.String()) {
		if badTitleRune(r) {
			toks = append(toks, pct(string(r)))
		} else {
			toks = append(toks, string(r))
		}
	}
	for n := len(toks); ; {
		out, taken := "", 0
		for _, t := range toks[:n] {
			if len(out)+len(t) > maxTitle {
				break
			}
			out += t
			taken++
		}
		switch {
		case out == "":
			return "%00", true
		case out == "." || out == "..":
			return pct(out), true
		case strings.HasSuffix(out, " ") || strings.HasSuffix(out, "."):
			esc := out[:len(out)-1] + pct(out[len(out)-1:])
			if len(esc) <= maxTitle {
				return esc, true
			}
			n = taken - 1
			continue
		}
		return out, true
	}
}

// pct is s as %XX of its bytes.
func pct(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// nameKey is what sibling names are compared by (§H.2 "Siblings").
func (s *Server) nameKey(name string) string { return files.TitleKey(name, s.opt.CaseSensitive) }

// newName is an opaque resource name for a new file or folder (§H.2):
// 13 random base32 characters, lowercase.
func newName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("dav: random: " + err.Error())
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// joinFolder is the path of folder title in folder parent (§H.2).
func joinFolder(parent, title string) string {
	if parent == "/" {
		return "/" + title
	}
	return parent + "/" + title
}

// noteWrite keeps the ns_id of a write this server made at the core's
// path p (/r/{ns}/…, /ns/{ns}/…), for the trees' listings (?min).
func (s *Server) noteWrite(p, nsid string) {
	if nsid == "" || len(s.trees) == 0 {
		return
	}
	var ns string
	switch {
	case strings.HasPrefix(p, "/r/"):
		ns, _, _ = strings.Cut(p[len("/r/"):], "/")
	case strings.HasPrefix(p, "/ns/"):
		ns, _, _ = strings.Cut(p[len("/ns/"):], "/")
	}
	if !s.trees[ns] {
		return
	}
	s.nsWriteMu.Lock()
	defer s.nsWriteMu.Unlock()
	ws := s.nsWrites[ns]
	if !slices.Contains(ws, nsid) {
		// The last few, in the order answered: ns_ids don't order, and
		// writes may answer out of order, so each is waited for.
		ws = append(ws, nsid)
		if len(ws) > maxMins {
			ws = ws[len(ws)-maxMins:]
		}
		s.nsWrites[ns] = ws
	}
}

// maxMins bounds the ns_ids of its own writes this server sends as ?min.
const maxMins = 4

// mins is the ?min values a listing of tree ns sends: the server's last
// writes there, and the namespace heads the request caught up to
// (catchUp).
func (st *reqState) mins(ns string) []string {
	st.s.nsWriteMu.Lock()
	out := slices.Clone(st.s.nsWrites[ns])
	st.s.nsWriteMu.Unlock()
	if id := st.caught[ns]; id != "" && !slices.Contains(out, id) {
		out = append(out, id)
	}
	return out
}

// theIndex names the index service in a 502 or 503.
const theIndex = "the index"

// ixHit is a hit of a folder's listing: a document and the revision the
// index holds.
type ixHit struct {
	Resource string `json:"resource"`
	ID       string `json:"id"`
}

// indexFolder lists folder fpath of tree ns through the index (§H.3), with
// the request's token, every page of it: at most MaxListing documents, a
// larger folder refused (403), never listed cut short. An index that has
// no document of the file schema the reader may see yet, which refuses the
// facet as marked by no schema (400), lists an empty folder.
func (st *reqState) indexFolder(ctx context.Context, ns, fpath string) ([]ixHit, error) {
	q := url.Values{}
	q.Set("facet[/folder]", fpath)
	q.Set("schema", st.s.opt.FileSchema)
	q.Set("sort", "/name")
	q.Set("limit", "100")
	for _, m := range st.mins(ns) {
		q.Add("min", ns+":"+m)
	}
	u := strings.TrimRight(st.s.opt.Index, "/") + "/" + ns + "?" + q.Encode()
	var out []ixHit
	for u != "" {
		var page struct {
			Hits []ixHit `json:"hits"`
			Next string  `json:"next"`
		}
		final, err := st.indexGet(ctx, u, &page)
		if err != nil {
			if errors.Is(err, errUnmarked) {
				return nil, nil
			}
			return nil, err
		}
		out = append(out, page.Hits...)
		if len(out) > st.s.opt.MaxListing {
			return nil, fail(http.StatusForbidden, "folder %s of %s holds more than %d files and folders, more than this gateway lists (§H.3); it isn't listed cut short", fpath, ns, st.s.opt.MaxListing)
		}
		u = ""
		if page.Next != "" {
			// The next page is asked of the result the first was, its at:
			// an opaque position means nothing at another.
			v := final.Query()
			v.Set("after", page.Next)
			v.Del("min")
			final.RawQuery = v.Encode()
			u = final.String()
		}
	}
	return out, nil
}

// errUnmarked is the index's 400 for a facet no schema it indexed for a
// document the reader may see marks (§A.4): no file of the tree yet.
var errUnmarked = errors.New("no document of the file schema indexed yet")

// indexGet reads u from the index with the request's grant into v, and
// returns the URL that answered (after redirects). A failure for now is
// the request's (sawUpstream, §H.4 "Answers"): 503 behind or busy, with
// Retry-After, 502 otherwise; the index's refusal of the grant (401, 403)
// is answered as it says.
func (st *reqState) indexGet(ctx context.Context, u string, v any) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if b := st.tk.c.Bearer(); b != "" {
		req.Header.Set("Authorization", "Bearer "+b)
	}
	res, err := st.s.ixc.Do(req)
	st.sawUpstream(theIndex, req, res, err)
	if err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, unreached(theIndex, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return nil, unreached(theIndex, err)
	}
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	json.Unmarshal(b, &e)
	cause := fmt.Errorf("GET %s: %d %s", u, res.StatusCode, b)
	switch {
	case res.StatusCode == http.StatusOK:
		if err := json.Unmarshal(b, v); err != nil {
			return nil, upFailed(theIndex, err)
		}
		return res.Request.URL, nil
	case res.StatusCode == http.StatusBadRequest && strings.Contains(e.Message, "is not a path any schema indexed"):
		return nil, errUnmarked
	case res.StatusCode == http.StatusUnauthorized, res.StatusCode == http.StatusForbidden:
		return nil, fail(res.StatusCode, "the index refused the grant: %s", e.Message)
	case res.StatusCode == http.StatusGone:
		return nil, fail(http.StatusGone, "the namespace was purged (§8.5)")
	case res.StatusCode == http.StatusTooManyRequests, res.StatusCode == http.StatusServiceUnavailable:
		return nil, upBusy(theIndex, cause)
	}
	return nil, upFailed(theIndex, cause)
}

// treeList lists folder t (a tree's directory, or one of its folders):
// the index's hits, each read at the revision the index holds with the
// request's token (a document it can't read is left out), placed in the
// folder by that revision; named by their titles, escaped where they
// break the rules, duplicates numbered in order of resource name, a real
// title first (§H.2 "Siblings"). Folder documents of one title are one
// folder.
func (st *reqState) treeList(ctx context.Context, t target, l *listing) error {
	hits, err := st.indexFolder(ctx, t.ns, t.fpath)
	if err != nil {
		return err
	}
	items := make([]headDoc, 0, len(hits))
	for _, h := range hits {
		if client.ValidResourceName(h.Resource) && h.ID != "" {
			items = append(items, headDoc{ns: t.ns, name: h.Resource, rev: h.ID})
		}
	}
	hds, err := st.s.fetchHeads(ctx, st.tk, items, st.tk.c.Head, true)
	if err != nil {
		return err
	}
	type cand struct {
		hd       headDoc
		name     string
		escaped  bool
		dir      bool
		title    string
		resource string
	}
	var cs []cand
	real := map[string]bool{}
	for _, hd := range hds {
		e := hd.e
		if e == nil || e.sealed || !e.tree || !e.placed || e.folder != t.fpath {
			continue
		}
		name, esc := shown(e.name)
		hd.listed = true
		cs = append(cs, cand{hd: hd, name: name, escaped: esc, dir: e.isFolder, title: e.name, resource: hd.name})
		if !esc {
			real[st.s.nameKey(name)] = true
		}
	}
	// Real titles first, then by resource name: the first keeps its name.
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].escaped != cs[j].escaped {
			return !cs[i].escaped
		}
		return cs[i].resource < cs[j].resource
	})
	l.tree = map[string]*treeEnt{}
	taken := map[string]bool{}
	folders := map[string]*treeEnt{} // by exact title
	for _, c := range cs {
		if c.dir {
			if f := folders[c.title]; f != nil {
				f.hds = append(f.hds, c.hd)
				continue
			}
		}
		name := c.name
		if k := st.s.nameKey(name); taken[k] || c.escaped && real[k] {
			name = dupName(name, c.dir, func(n string) bool { k := st.s.nameKey(n); return taken[k] || real[k] })
		}
		taken[st.s.nameKey(name)] = true
		ent := &treeEnt{title: c.title, dir: c.dir, hds: []headDoc{c.hd}}
		l.tree[name] = ent
		if c.dir {
			folders[c.title] = ent
			fi := st.dirInfo(name)
			if !c.hd.m.modified.IsZero() {
				fi.mod = c.hd.m.modified
			}
			l.byName[name] = fi
			l.infos = append(l.infos, fi)
			continue
		}
		l.docs[name] = c.hd
		fi := st.docInfo(name, c.hd)
		l.byName[name] = fi
		l.infos = append(l.infos, fi)
	}
	return nil
}

// treeListing is the listing of folder fpath of tree ns, at dir path
// dirPath, read once per request.
func (st *reqState) treeListing(ctx context.Context, ns, fpath, dirPath string) (*listing, error) {
	k := kFolder
	if fpath == "/" {
		k = kNSDir
	}
	return st.list(ctx, target{kind: k, path: dirPath, ns: ns, tree: true, fpath: fpath, dir: pathDir(dirPath), base: pathBase(dirPath)})
}

// resolveTree resolves t, a path in tree t.ns (segs its segments, the
// namespace first): one folder at a time from the top, a folder in the
// middle of the path matching whatever its case (§H.2 "Siblings"), the
// last name a file (kDoc, kRaw by its content), a folder (kFolder), or
// else a new name (kNew) or a scratch file (§H.6). A path through no
// folder is kMissing.
func (st *reqState) resolveTree(ctx context.Context, t target, segs []string) (target, error) {
	t.tree = true
	if len(segs) == 1 {
		t.kind, t.fpath = kNSDir, "/"
		return t, nil
	}
	fpath, dirPath := "/", "/"+t.ns
	for i := 1; i < len(segs)-1; i++ {
		l, err := st.treeListing(ctx, t.ns, fpath, dirPath)
		if err != nil {
			return t, err
		}
		ent := l.tree[norm.NFC.String(segs[i])]
		if ent == nil {
			k := st.s.nameKey(segs[i])
			for n, e := range l.tree {
				if e.dir && st.s.nameKey(n) == k {
					ent = e
					break
				}
			}
		}
		if ent == nil || !ent.dir {
			t.kind = kMissing
			return t, nil
		}
		fpath = joinFolder(fpath, ent.title)
		dirPath += "/" + segs[i]
	}
	l, err := st.treeListing(ctx, t.ns, fpath, dirPath)
	if err != nil {
		return t, err
	}
	t.folder = fpath
	base := norm.NFC.String(t.base)
	if ent := l.tree[t.base]; ent != nil || l.tree[base] != nil {
		if ent == nil {
			ent = l.tree[base]
		}
		t.title = ent.title
		if ent.dir {
			t.kind, t.fpath = kFolder, joinFolder(fpath, ent.title)
			return t, nil
		}
		hd := ent.hds[0]
		t.docNS, t.docName, t.kind = t.ns, hd.name, kDoc
		if hd.m.raw != nil {
			t.kind = kRaw
		}
		return t, nil
	}
	if _, ok := st.scratchPeek(t.path); ok || scratchName(t.base) || appDir(t.base) && st.isScratchDir(t.path) {
		return st.scratchAt(t, false), nil
	}
	t.kind, t.title = kNew, base
	k := st.s.nameKey(base)
	for n := range l.tree {
		if st.s.nameKey(n) == k {
			t.variant = n
			break
		}
	}
	return t, nil
}

func pathDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "/"
}

func pathBase(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

// entAt is the listing entry of resolved tree path t.
func (st *reqState) entAt(t target) *treeEnt {
	if l := st.lists[t.dir]; l != nil && l.tree != nil {
		if e := l.tree[t.base]; e != nil {
			return e
		}
		return l.tree[norm.NFC.String(t.base)]
	}
	return nil
}

// catchUp has the request's next listings of tree ns wait for the index
// to reach the namespace's head as the request's token reads it now
// (§H.4 "Names before writes": listed again with ?min where a document
// no longer has the folder and name the listing said): an index that
// doesn't, in the time it waits, is 503 behind.
func (st *reqState) catchUp(ctx context.Context, ns string) error {
	h, err := st.tk.c.NSHead(ctx, ns)
	if err != nil {
		return err
	}
	if st.caught == nil {
		st.caught = map[string]string{}
	}
	st.caught[ns] = h.ID
	st.lists = nil
	return nil
}

// placedAt reads ns/name's head with the request's token and returns it
// where it is live and still placed as folder/title, a file or a folder
// as dir says (§H.4 "Names before writes"); false otherwise.
func (st *reqState) placedAt(ctx context.Context, ns, name, folder, title string, dir bool) (headDoc, bool, error) {
	h, err := st.head(ctx, ns, name)
	if hidden(err) {
		return headDoc{}, false, nil
	}
	if err != nil || h.State != client.Live {
		return headDoc{}, false, err
	}
	e, err := st.s.doc(ctx, st.tk, ns, name, h.ID)
	if hidden(err) {
		return headDoc{}, false, nil
	}
	if err != nil {
		return headDoc{}, false, err
	}
	if e.sealed || !e.tree || !e.placed || e.folder != folder || e.name != title || e.isFolder != dir {
		return headDoc{}, false, nil
	}
	return headDoc{ns: ns, name: name, rev: h.ID, m: e.meta(), e: e}, true, nil
}

// treeDocAt is docAt of a tree file: the document the folder's listing
// names, read again at its head, which must still be that file, placed
// where the path says. One that isn't (moved, renamed, deleted since the
// index listed it) is looked up again with the folder listed at the
// namespace's head (catchUp): it may be another document now, or none.
func (st *reqState) treeDocAt(ctx context.Context, t target) (headDoc, bool, error) {
	_, hd, ok, err := st.treeFresh(ctx, t)
	return hd, ok, err
}

// treeFresh is treeDocAt, with what the path names once looked up again:
// the same file, another, a new name (kNew), or nothing.
func (st *reqState) treeFresh(ctx context.Context, t target) (target, headDoc, bool, error) {
	for round := 0; ; round++ {
		ent := st.entAt(t)
		if ent == nil || ent.dir {
			return t, headDoc{}, false, nil
		}
		hd, ok, err := st.placedAt(ctx, t.ns, ent.hds[0].name, t.folder, ent.title, false)
		if err != nil || ok || round > 0 {
			return t, hd, ok, err
		}
		if err := st.catchUp(ctx, t.ns); err != nil {
			return t, headDoc{}, false, err
		}
		if t, err = st.resolveName(ctx, t.path); err != nil {
			return t, headDoc{}, false, err
		}
		if !t.isDoc() {
			return t, headDoc{}, false, nil
		}
	}
}

// folderDocs are the folder documents of tree folder t, each read again
// at its head and still placed so (placedAt); none left (moved, renamed,
// deleted since the index listed them) looks the folder up again at the
// namespace's head (catchUp), and is the folder's absence if it is gone.
func (st *reqState) folderDocs(ctx context.Context, t target) ([]headDoc, error) {
	for round := 0; ; round++ {
		ent := st.entAt(t)
		if ent == nil || !ent.dir {
			return nil, errNotExist
		}
		var out []headDoc
		for _, hd := range ent.hds {
			h, ok, err := st.placedAt(ctx, t.ns, hd.name, t.folder, ent.title, true)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, h)
			}
		}
		if len(out) > 0 || round > 0 {
			if len(out) == 0 {
				return nil, errNotExist
			}
			return out, nil
		}
		if err := st.catchUp(ctx, t.ns); err != nil {
			return nil, err
		}
		var err error
		if t, err = st.resolveName(ctx, t.path); err != nil {
			return nil, err
		}
		if t.kind != kFolder {
			return nil, errNotExist
		}
	}
}

// parentFolder checks that the folder a new name t is made in (§H.4 "New
// files": "its folder a folder the user can see") still is: the top, or a
// folder whose documents are still placed so; 409 otherwise.
func (st *reqState) parentFolder(ctx context.Context, t target) error {
	if t.folder == "/" {
		return nil
	}
	p, err := st.resolveName(ctx, t.dir)
	if err != nil {
		return err
	}
	if p.kind == kFolder {
		if _, err := st.folderDocs(ctx, p); err == nil {
			return nil
		} else if !errors.Is(err, errNotExist) {
			return err
		}
	}
	return fail(http.StatusConflict, "folder %s isn't there any more (moved, renamed or deleted), so %s can't be made in it; reload it", t.dir, t.base)
}

// fileSchemaRef is the file schema's head revision, which new files and
// folders are pinned to (§H.2), read with the request's token.
func (st *reqState) fileSchemaRef(ctx context.Context) (string, error) {
	if st.schemaRef != "" {
		return st.schemaRef, nil
	}
	h, err := st.tk.c.Head(ctx, st.s.schemaNS, st.s.schemaName)
	if err != nil {
		return "", err
	}
	if h.State != client.Live {
		return "", fail(http.StatusBadGateway, "the file schema %s doesn't exist: the deployment must create it (patchlog files schema) before files are made", st.s.opt.FileSchema)
	}
	st.schemaRef = st.s.opt.FileSchema + "/rev/" + h.ID
	return st.schemaRef, nil
}

// newPlaced checks a new name t for a file or folder in a tree (§H.2):
// its title (403 for one that breaks the rules), and a sibling whose name
// matches only under another case, which is a 409 naming it (or, for a
// folder, 405), but where it is except (a MOVE's source, which a
// case-only rename makes again). It returns the title.
func (st *reqState) newPlaced(t target, folder bool, except string) (string, error) {
	title, err := newTitle(t.base)
	if err != nil {
		return "", err
	}
	if t.variant != "" && t.variant != except {
		if folder {
			return "", fail(http.StatusMethodNotAllowed, "%s exists under another case, as %s (§H.2 \"Siblings\")", t.path, t.variant)
		}
		return "", fail(http.StatusConflict, "%s names %s, which exists in that folder under another case (§H.2 \"Siblings\"); use that name, or another", t.base, t.variant)
	}
	return title, nil
}

// treeCreate writes body as a new file at tree name t (§H.4 "New files"):
// a raw file's blob uploaded first (copied with Blob-From from a COPY's
// or MOVE's source, §7.8), then the document created under a fresh
// opaque name with If-None-Match: *, pinned to the file schema, its
// folder one the user can see (409 otherwise). A JSON file is one whose
// name ends in .json and whose body is I-JSON (§H.1).
func (st *reqState) treeCreate(ctx context.Context, t target, body []byte) (string, bool, error) {
	title, err := st.newPlaced(t, false, st.srcVariant())
	if err != nil {
		return "", false, err
	}
	in, err := st.saveInfo(ctx, t.ns)
	if err != nil {
		return "", false, err
	}
	if in.sealed {
		return "", false, notOffered(t.ns)
	}
	if err := st.parentFolder(ctx, t); err != nil {
		return "", false, err
	}
	ref, err := st.fileSchemaRef(ctx)
	if err != nil {
		return "", false, err
	}
	raw, v := newKind(title, body)
	var content any = v
	var b rawBlob
	if raw {
		if in.blobSize > 0 && len(body) > in.blobSize {
			return "", false, overLimit("blobSize", int64(len(body)), int64(in.blobSize), "(§6.6, §7.8): the file is larger than namespace %s's blobs may be; nothing was uploaded", t.ns)
		}
		nonce := ""
		if in.nonce {
			nonce = seal.NewNonce()
		}
		b = st.rawBlobOf(title, "", nonce, body)
		content = b.ref
	}
	var rev string
	exact := false
	sent := false
	err = st.retrying(ctx, func() (bool, error) {
		name := newName()
		if raw && !sent {
			// The blob goes to the first name tried; a retry under another
			// name copies it there.
			if err := st.uploadTo(ctx, t.ns, name, b, body); err != nil {
				return false, err
			}
			sent = true
			st.blobAt = name
		} else if raw && st.blobAt != name {
			if err := st.tk.c.CopyBlob(ctx, t.ns, name, b.bid, t.ns, st.blobAt, ""); err != nil {
				return false, err
			}
		}
		doc := map[string]any{"$schema": ref, "folder": t.folder, "name": title, "content": content}
		ps := withNonce(in, doc, client.GenesisPatches(doc))
		res, err := st.tk.c.Create(ctx, t.ns, name, ps)
		err = tooLarge(err, true)
		switch {
		case client.IsStale(err), goneSince(err):
			// The name drawn exists or existed: draw another.
			return true, nil
		case err != nil:
			return false, err
		}
		rev = res.ID
		same := rendersAs(v)
		var wbody []byte = body
		if raw {
			same, wbody = b.holds(body), nil
		}
		exact = st.wrote(t.ns, name, map[string]any{}, []any{map[string]any{"op": "replace", "path": "", "value": content}},
			[]pointer.Pointer{{}}, res, content, wbody, same)
		st.wroteTo = t.ns + "/" + name
		return false, nil
	})
	return rev, err == nil && exact, err
}

// uploadTo sends raw file b's blob, body, to ns/name: copied from its
// source where it is a copy's (Blob-From, §7.8), else, or where the core
// refuses that, uploaded.
func (st *reqState) uploadTo(ctx context.Context, ns, name string, b rawBlob, body []byte) error {
	if b.from != nil {
		err := st.tk.c.CopyBlob(ctx, ns, name, b.bid, b.from.ns, b.from.name, "")
		ae, isAPI := client.AsAPIError(err)
		switch {
		case err == nil:
			return nil
		case !isAPI || ae.Status != http.StatusNotFound && ae.Status != http.StatusUnprocessableEntity:
			return err
		}
	}
	_, err := st.tk.c.UploadBlob(ctx, ns, name, b.typ, b.nonce, body)
	return err
}

// srcVariant is the name a MOVE's source has in the folder of its
// destination, if the source is there: a case-only rename isn't refused
// as a case variant of a sibling (§H.2 "Siblings").
func (st *reqState) srcVariant() string {
	if st.method != "MOVE" || pathDir(st.path) != pathDir(st.dst) {
		return ""
	}
	return pathBase(st.path)
}

// treeMkdir makes folder t, a new name in a tree (MKCOL, §H.8): a folder
// document { $schema, folder, name } under a fresh opaque name, with
// If-None-Match: *, in a folder the user can see (409 otherwise).
func (st *reqState) treeMkdir(ctx context.Context, t target) error {
	title, err := st.newPlaced(t, true, st.srcVariant())
	if err != nil {
		return err
	}
	in, err := st.saveInfo(ctx, t.ns)
	if err != nil {
		return err
	}
	if in.sealed {
		return notOffered(t.ns)
	}
	if err := st.parentFolder(ctx, t); err != nil {
		return err
	}
	ref, err := st.fileSchemaRef(ctx)
	if err != nil {
		return err
	}
	defer st.changed()
	return st.retrying(ctx, func() (bool, error) {
		doc := map[string]any{"$schema": ref, "folder": t.folder, "name": title}
		_, err := st.tk.c.Create(ctx, t.ns, newName(), withNonce(in, doc, client.GenesisPatches(doc)))
		if client.IsStale(err) || goneSince(err) {
			return true, nil
		}
		st.committed = st.committed || err == nil
		return false, err
	})
}

// treeRmdir deletes folder t (§H.5 "Delete a folder"): only one without
// visible children, as a listing at or past this server's last write in
// the namespace shows them (409 naming them otherwise); then each of its
// folder documents, with If-Match on the head read. Children the user
// can't see don't stop it, and fall out of the tree.
func (st *reqState) treeRmdir(ctx context.Context, t target) error {
	l, err := st.treeListing(ctx, t.ns, t.fpath, t.path)
	if err != nil {
		return err
	}
	if len(l.tree) > 0 {
		var names []string
		for n := range l.tree {
			names = append(names, n)
		}
		sort.Strings(names)
		if len(names) > 10 {
			names = append(names[:10], "…")
		}
		return fail(http.StatusConflict, "%s isn't empty: it holds %s; delete what is in it first (§H.5)", t.path, strings.Join(names, ", "))
	}
	hds, err := st.folderDocs(ctx, t)
	if err != nil {
		return err
	}
	defer st.changed()
	for _, hd := range hds {
		match := hd.rev
		if st.ifMatch != "" {
			match = st.ifMatch
		}
		if _, err := st.deleteDoc(ctx, t.ns, hd.name, match); err != nil {
			if de, ok := err.(*davError); ok && de.status == http.StatusPreconditionFailed && st.ifMatch == "" {
				return movedSinceRead(t)
			}
			if !errors.Is(err, errNotExist) {
				return err
			}
		}
	}
	for _, p := range st.scratchUnder(t.path) {
		st.scratchRemove(p)
	}
	st.s.forgetPath(st.p, t.path)
	return nil
}

// treeMove moves live file src (§H.5): onto an existing file, a save of
// its content into it (moveOnto); to a new name in its own tree, one
// append replacing /name and /folder, with If-Match on the head read
// (treeRename); anywhere else, a copy and a delete (moveAcross).
func (st *reqState) treeMove(ctx context.Context, src, dst target) error {
	switch {
	case dst.isDoc():
		if _, live, err := st.docAt(ctx, dst); err != nil {
			return err
		} else if live {
			return st.moveOnto(ctx, src, dst)
		}
		if dst.tree {
			return treeGone(dst.path)
		}
		return st.moveAcross(ctx, src, dst)
	case dst.kind == kNew && src.tree && dst.ns == src.ns:
		return st.treeRename(ctx, src, dst)
	case dst.kind == kNew:
		return st.moveAcross(ctx, src, dst)
	case dst.isDir():
		return fail(http.StatusForbidden, "%s is a folder: a file moved there doesn't replace it (§H.5)", dst.path)
	}
	return fail(http.StatusForbidden, "%s can't be moved to %s", src.path, dst.path)
}

// treeRename renames or moves live tree file src to dst, a new name in its
// tree (§H.5 "Rename or move a file"): one append replacing /name and
// /folder, with If-Match on the head read again (treeDocAt, 404 if it no
// longer has the name and folder the path named), into a folder that
// exists (409 otherwise).
func (st *reqState) treeRename(ctx context.Context, src, dst target) error {
	title, err := st.newPlaced(dst, false, st.srcVariant())
	if err != nil {
		return err
	}
	hd, live, err := st.treeDocAt(ctx, src)
	if err != nil {
		return err
	}
	if !live {
		return errNotExist
	}
	if st.srcMatch != "" && hd.rev != st.srcMatch {
		return st.sourceMoved(src.path)
	}
	if err := st.parentFolder(ctx, dst); err != nil {
		return err
	}
	in, err := st.saveInfo(ctx, src.ns)
	if err != nil {
		return err
	}
	var ps []any
	if hd.e.name != title {
		ps = append(ps, map[string]any{"op": "replace", "path": "/name", "value": title})
	}
	if hd.e.folder != dst.folder {
		ps = append(ps, map[string]any{"op": "replace", "path": "/folder", "value": dst.folder})
	}
	if len(ps) == 0 {
		return nil
	}
	res, err := st.tk.c.Append(ctx, src.ns, hd.name, hd.rev, withNonce(in, hd.e.whole, ps))
	switch {
	case client.IsStale(err):
		return fail(http.StatusConflict, "%s was changed by someone else while it was being moved, so it isn't moved; reload it", src.path)
	case err != nil:
		return err
	}
	st.committed = true
	st.s.markOwn(st.p, src.ns, hd.name, res.ID)
	st.s.forgetPath(st.p, src.path)
	st.s.notePath(st.p, dst.path, src.ns, hd.name)
	st.changed()
	return nil
}

// treeMoveFolder renames or moves folder src to dst, a new name in its
// tree (§H.5 "Rename or move a folder"): one batch (§7.5) rewriting its
// folder documents' name and folder and the folder of every visible
// document under it, each item with If-Match on the head read. One into
// itself or a descendant is 403; one too large for a batch is refused as
// a limit (§6.6, 413). Documents under it the user can't see fall out of
// the tree.
func (st *reqState) treeMoveFolder(ctx context.Context, src, dst target) error {
	switch {
	case dst.kind != kNew || !dst.tree || dst.ns != src.ns:
		if dst.isDir() {
			return fail(http.StatusForbidden, "%s is a folder: a folder moved there doesn't replace it (§H.5)", dst.path)
		}
		if dst.isDoc() {
			return fail(http.StatusForbidden, "%s is a file: a folder moved there doesn't replace it (§H.5)", dst.path)
		}
		return fail(http.StatusForbidden, "%s can't be moved to %s: a folder moves within its tree (copy it to another namespace, then delete it)", src.path, dst.path)
	case dst.path == src.path || strings.HasPrefix(dst.path+"/", src.path+"/"):
		return fail(http.StatusForbidden, "%s can't be moved into itself (§H.5)", src.path)
	}
	title, err := st.newPlaced(dst, true, st.srcVariant())
	if err != nil {
		return err
	}
	if err := st.parentFolder(ctx, dst); err != nil {
		return err
	}
	in, err := st.saveInfo(ctx, src.ns)
	if err != nil {
		return err
	}
	fds, err := st.folderDocs(ctx, src)
	if err != nil {
		return err
	}
	newPath := joinFolder(dst.folder, title)
	var items []client.BatchItem
	for _, hd := range fds {
		if st.srcMatch != "" && hd.rev != st.srcMatch && len(fds) == 1 {
			return st.sourceMoved(src.path)
		}
		ps := []any{map[string]any{"op": "replace", "path": "/name", "value": title}}
		if hd.e.folder != dst.folder {
			ps = append(ps, map[string]any{"op": "replace", "path": "/folder", "value": dst.folder})
		}
		items = append(items, client.BatchItem{Resource: hd.name, IfMatch: hd.rev, Steps: []client.Step{client.PatchStep(withNonce(in, hd.e.whole, ps))}})
	}
	// Every visible document under it, folder by folder.
	var walk func(fpath, dirPath string) error
	walk = func(fpath, dirPath string) error {
		l, err := st.treeListing(ctx, src.ns, fpath, dirPath)
		if err != nil {
			return err
		}
		for name, ent := range l.tree {
			for _, hd := range ent.hds {
				cur, ok, err := st.placedAt(ctx, src.ns, hd.name, fpath, ent.title, ent.dir)
				if err != nil {
					return err
				}
				if !ok {
					return fail(http.StatusConflict, "%s/%s was changed by someone else while %s was being moved, so nothing was moved; reload it", dirPath, name, src.path)
				}
				nf := newPath + strings.TrimPrefix(fpath, src.fpath)
				ps := []any{map[string]any{"op": "replace", "path": "/folder", "value": nf}}
				items = append(items, client.BatchItem{Resource: hd.name, IfMatch: cur.rev, Steps: []client.Step{client.PatchStep(withNonce(in, cur.e.whole, ps))}})
			}
			if ent.dir {
				if err := walk(joinFolder(fpath, ent.title), dirPath+"/"+name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(src.fpath, src.path); err != nil {
		return err
	}
	_, err = st.tk.c.Batch(ctx, src.ns, client.BatchRequest{Items: items}, false)
	err = batchErr(err)
	switch {
	case client.IsStale(err), goneSince(err):
		return fail(http.StatusConflict, "something in %s was changed by someone else while it was being moved, so nothing was moved; reload it", src.path)
	case err != nil:
		return tooLarge(err, true)
	}
	st.committed = true
	st.scratchMoveUnder(src.path, dst.path)
	st.changed()
	return nil
}

// treeCopyDir makes folder t, a COPY's destination or one under it, as
// MKCOL makes one (§H.5 "Copy"): a copy into the folder copied itself or
// a descendant of it is 403, before anything is written.
func (st *reqState) treeCopyDir(ctx context.Context, src, t target) error {
	if t.path == st.dst && (st.dst == st.path || strings.HasPrefix(st.dst, st.path+"/")) {
		return fail(http.StatusForbidden, "%s can't be copied into itself (§H.5)", st.path)
	}
	switch t.kind {
	case kNew:
		return st.treeMkdir(ctx, t)
	case kFolder:
		return fail(http.StatusForbidden, "%s is a folder: a folder copied there doesn't replace it (§H.5)", t.path)
	case kDoc, kRaw:
		return fail(http.StatusForbidden, "%s is a file: a folder copied there doesn't replace it (§H.5)", t.path)
	}
	return fail(http.StatusForbidden, "%s can't be copied to %s", src.path, t.path)
}
