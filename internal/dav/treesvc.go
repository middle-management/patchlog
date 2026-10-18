package dav

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/telemetry"
	"github.com/middle-management/patchlog/internal/tree"
)

// Listings from the tree service (§H.3, §H.7). With Options.TreeService,
// a tree's folder is listed from the tree service's children listing
// (§B.5), read with the request's grant, its token's, passed through as
// the bearer: the tree service checks it, and shows the reader only the
// nodes and items it may read (§B.11.5), so a grant limited to some
// resources, which can't read the catalog's /heads, lists a tree. A tree
// service following a file tree adds to each placement its item's file:
// { size, type, modified } (§H.3), which give a file's size, type and
// time, and the entry's head its ETag: a folder lists in one request,
// every page of it (treePage entries each, at most maxTreePages: a folder
// larger is refused, never cut short), and no item is read for it. A
// placement whose file is sealed ({"sealed": JWE}, a sealed namespace's
// item) isn't offered (§H.7); one without file, or without its time (an
// end-to-end namespace's item, a head the service hasn't read yet, a row
// older than created), is offered as the node path offers it: read from
// the core, sealed ones left out. Names are given as the node path gives
// them (treeDir, nameDir), so either source names a folder's files alike
// and paths resolve to what was listed. A catalog whose catalog.title is
// set is listed from its node documents: the tree service gives its
// items' titles to placements without one (§B.5), which the gateway shows
// by their items' names (§H.2).
//
// The tree service lags the core. A listing by a user who wrote through
// this server, with any of their tokens, asks for every namespace entry
// their writes produced in the catalog and the namespaces it trusts, the
// writes' X-Namespace-Revision (watchWrites), with ?min= (§B.5 "Fresh
// listings after a write"), which the tree service waits for, until a
// listing that asked for them came back: however long the tree service
// lags, a user's own new file stays listed and a file they renamed
// doesn't come back by its old name. Past TreeWait the folder is listed
// from the node documents instead, as without a tree service, for slowFor
// (a 503 if the token's grant can't read them either); entries the tree
// service refuses to wait for (400) aren't asked for again. Other users'
// listings don't wait, and writes check what such a listing named
// against the node documents (resolveCatalog). A listing is kept per
// token for CatalogTTL, as a catalog's graph is: what one grant was shown
// is never shown to another, which may read less (§H.7). The tree service
// unreachable, failing, or not caught up with a namespace the catalog
// trusts is a 502 or 503, never an empty folder.

const (
	// treePage is the entries a listing page asks for, the tree
	// service's most, and maxTreePages the pages one folder lists.
	treePage, maxTreePages = 1000, 10
	// slowFor is how long a catalog whose tree service didn't reach the
	// user's writes in time is listed from its node documents.
	slowFor = 5 * time.Second
	// maxWroteNS bounds the namespaces a user's writes are kept for, and
	// maxWroteIDs the entries of one.
	maxWroteNS, maxWroteIDs = 64, 4
)

// errBehind: the tree service hasn't reached a user's writes in time;
// errMinsRefused: it refuses to wait for them (400).
var (
	errBehind      = errors.New("dav: the tree service is behind the user's writes")
	errMinsRefused = errors.New("dav: the tree service refuses to wait for the user's writes")
)

// treeShared is what the server keeps of the tree service: its client,
// and the catalogs' settings as last read with any grant (learn).
type treeShared struct {
	hc   *http.Client
	page int // entries a page asks for (treePage)

	mu    sync.Mutex
	confs map[string]catConf // by catalog
}

// init checks opt's tree services and, with any, watches the writes of
// opt's client (watchWrites).
func (ts *treeShared) init(opt *Options) error {
	check := func(what, u string) (string, error) {
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "http" && p.Scheme != "https" || p.Host == "" || p.RawQuery != "" {
			return "", fmt.Errorf("dav: %s %q isn't a tree service's base URL (http://host[:port][/path])", what, u)
		}
		return strings.TrimRight(u, "/"), nil
	}
	var err error
	if opt.TreeService != "" {
		if opt.TreeService, err = check("TreeService", opt.TreeService); err != nil {
			return err
		}
	}
	urls := map[string]string{}
	for cat, u := range opt.TreeServices {
		if !slices.Contains(opt.Catalogs, cat) {
			return fmt.Errorf("dav: a tree service for %s, which isn't a catalog served", cat)
		}
		if urls[cat], err = check("the tree service of "+cat, u); err != nil {
			return err
		}
	}
	opt.TreeServices = urls
	ts.confs, ts.page = map[string]catConf{}, treePage
	if opt.TreeService == "" && len(urls) == 0 {
		return nil
	}
	ts.hc = &http.Client{Transport: telemetry.Transport(nil), Timeout: time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	now := opt.Now
	opt.Client = opt.Client.With(client.WithTransport(func(next http.RoundTripper) http.RoundTripper { return watchWrites(next, now) }))
	return nil
}

// treeURL is catalog cat's tree service, "" for none.
func (s *Server) treeURL(cat string) string {
	if u, ok := s.opt.TreeServices[cat]; ok {
		return u
	}
	return s.opt.TreeService
}

// catConf is what listing a tree takes from its catalog's namespace
// document (§B.6, §H.2): catalog.files, catalog.trust, and whether
// catalog.title is set (§B.5).
type catConf struct {
	files  *treeFiles
	trust  []string
	titled bool
}

// viaService reports whether catalog cat's folders are listed from its
// tree service.
func (s *Server) viaService(cat string, c catConf) bool { return s.treeURL(cat) != "" && !c.titled }

// treeConf returns catalog cat's settings as the request's token reads
// them (nsInfo), or why it isn't a file tree (notTree). A token whose
// grant doesn't read the document, which takes unrestricted read (§7.4),
// as one limited to some resources (§H.7), lists through a tree service
// with the settings last read with any grant (learn), the server's own at
// start included: only files.root is needed to ask for the top level, and
// the tree service and the core check the token's grant for everything
// listed and read.
func (st *reqState) treeConf(ctx context.Context, cat string) (catConf, error) {
	in, err := st.s.nsInfoErr(ctx, st.tk, cat)
	switch {
	case err != nil:
		return catConf{}, err
	case in.files != nil:
		c := catConf{files: in.files, trust: in.trust, titled: in.titled}
		st.s.learn(cat, &c)
		return c, nil
	case in.readErr == nil:
		st.s.learn(cat, nil)
		return catConf{}, notTree(cat, in.notTree)
	}
	if c, ok := st.s.learned(cat); ok && st.s.treeURL(cat) != "" {
		return c, nil
	}
	return catConf{}, upstream(in.readErr)
}

// learn keeps catalog cat's settings as read, nil if it isn't a file tree.
func (s *Server) learn(cat string, c *catConf) {
	s.ts.mu.Lock()
	defer s.ts.mu.Unlock()
	if c == nil {
		delete(s.ts.confs, cat)
	} else {
		s.ts.confs[cat] = *c
	}
}

func (s *Server) learned(cat string) (catConf, bool) {
	s.ts.mu.Lock()
	defer s.ts.mu.Unlock()
	c, ok := s.ts.confs[cat]
	return c, ok
}

// treeSvc is what a user (principal) keeps for listing through a tree
// service: the namespace entries their writes through this server
// produced, with any of their tokens, which their listings wait for
// until one that did came back (reached), and the catalogs whose tree
// service didn't reach them in time.
type treeSvc struct {
	mu    sync.Mutex
	wrote map[string][]wroteID // by namespace, oldest first
	slow  map[string]time.Time // by catalog: listed from node documents until then
}

// wroteID is a namespace entry a write produced, and when.
type wroteID struct {
	id string
	at time.Time
}

// svcDir is a folder as the tree service listed it, and when (at, and
// the server's write count, gen).
type svcDir struct {
	d   *treeDir
	at  time.Time
	gen uint64
}

// noteWrite keeps id, the entry of namespace ns a write produced at now.
func (ts *treeSvc) noteWrite(ns, id string, now time.Time) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.wrote == nil {
		ts.wrote = map[string][]wroteID{}
	}
	ids := ts.wrote[ns]
	for _, w := range ids {
		if w.id == id {
			return
		}
	}
	if _, ok := ts.wrote[ns]; !ok && len(ts.wrote) >= maxWroteNS {
		old := ""
		for k, ws := range ts.wrote {
			if old == "" || ws[len(ws)-1].at.Before(ts.wrote[old][len(ts.wrote[old])-1].at) {
				old = k
			}
		}
		delete(ts.wrote, old)
	}
	ids = append(ids, wroteID{id: id, at: now})
	if len(ids) > maxWroteIDs {
		ids = ids[len(ids)-maxWroteIDs:]
	}
	ts.wrote[ns] = ids
}

// mins are the ?min= values of the entries the user's writes to the
// namespaces nss produced, not yet reached (§B.5).
func (ts *treeSvc) mins(nss []string) []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var out []string
	for ns, ws := range ts.wrote {
		if slices.Contains(nss, ns) {
			for _, w := range ws {
				out = append(out, ns+":"+w.id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// reached drops mins, the ?min= values of entries a listing of the tree
// service included (or that it refuses to wait for): it never goes back
// before them, so later listings show those writes without asking.
func (ts *treeSvc) reached(mins []string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, m := range mins {
		ns, id, _ := strings.Cut(m, ":")
		ws := slices.DeleteFunc(ts.wrote[ns], func(w wroteID) bool { return w.id == id })
		if len(ws) == 0 {
			delete(ts.wrote, ns)
		} else {
			ts.wrote[ns] = ws
		}
	}
}

// isSlow reports whether catalog cat is listed from its node documents
// for now (slowFor).
func (ts *treeSvc) isSlow(cat string, now time.Time) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return now.Before(ts.slow[cat])
}

func (ts *treeSvc) setSlow(cat string, until time.Time) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.slow == nil {
		ts.slow = map[string]time.Time{}
	}
	for k, t := range ts.slow {
		if !until.Before(t.Add(slowFor)) {
			delete(ts.slow, k)
		}
	}
	ts.slow[cat] = until
}

// fresh returns sd's listing if it was listed less than ttl before now
// and since this server's last write (gen).
func (sd svcDir) fresh(now time.Time, ttl time.Duration, gen uint64) *treeDir {
	if sd.d == nil || sd.gen != gen || now.Sub(sd.at) >= ttl {
		return nil
	}
	return sd.d
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// watchWrites is the transport of the core's client where a tree service
// lists: it keeps, for the user whose request makes a write (its token's
// principal), the namespace entry it produced (X-Namespace-Revision,
// §7.2), wherever in this server the write is made, for their listings to
// wait for (mins).
func watchWrites(next http.RoundTripper, now func() time.Time) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		res, err := next.RoundTrip(r)
		if err != nil || r.Method == http.MethodGet || r.Method == http.MethodHead || res.StatusCode >= 300 {
			return res, err
		}
		if id, ns := res.Header.Get("X-Namespace-Revision"), writtenNS(r.URL.Path); id != "" && ns != "" {
			if st := state(r.Context()); st != nil {
				st.p.ts.noteWrite(ns, id, now())
			}
		}
		return res, err
	})
}

// writtenNS is the namespace a write's URL path names, /r/{ns}/… or
// /ns/{ns}…, after any prefix of the core's base URL; "" for none.
func writtenNS(p string) string {
	segs := strings.Split(p, "/")
	for i := 0; i+1 < len(segs); i++ {
		if (segs[i] == "r" || segs[i] == "ns") && client.ValidNSName(segs[i+1]) {
			return segs[i+1]
		}
	}
	return ""
}

// serviceDir lists folder of catalog cat from its tree service (above),
// or from its node documents while the tree service is behind the user's
// writes (behindDir).
func (st *reqState) serviceDir(ctx context.Context, cat, folder string, c catConf) (*treeDir, error) {
	now, gen := st.s.opt.Now(), st.s.gen.Load()
	k := cat + "/" + folder
	v, _ := st.s.view(st.tk, k)
	if d := v.sd.fresh(now, st.s.opt.CatalogTTL, gen); d != nil {
		// Listed since this server's last write, so with every write of
		// the user's it was to wait for (a write notes its entry before
		// it counts, changed).
		return d, nil
	}
	mins := st.p.ts.mins(append([]string{cat}, c.trust...))
	if len(mins) > 0 && st.p.ts.isSlow(cat, now) {
		return st.behindDir(ctx, cat, folder)
	}
	ents, err := st.svcList(ctx, cat, folder, mins)
	switch {
	case errors.Is(err, errBehind):
		st.s.opt.Logf("dav: %s: the tree service hasn't reached %s within %v; folder %s is listed from the catalog's node documents", cat, strings.Join(mins, " "), st.s.opt.TreeWait, folder)
		st.p.ts.setSlow(cat, now.Add(slowFor))
		return st.behindDir(ctx, cat, folder)
	case errors.Is(err, errMinsRefused):
		st.s.opt.Logf("dav: %s: the tree service refuses to wait for %s; folder %s is listed from the catalog's node documents", cat, strings.Join(mins, " "), folder)
		st.p.ts.reached(mins)
		return st.behindDir(ctx, cat, folder)
	case err == nil:
		st.p.ts.reached(mins)
	}
	if err != nil {
		if de := (*davError)(nil); errors.As(err, &de) && de.status == http.StatusNotFound && folder == c.files.root {
			return nil, fail(http.StatusNotFound, "catalog %s's tree service shows no live folder node as its files.root to you, so its file tree has no top level to show (§H.2, §B.11.5)", cat)
		}
		return nil, err
	}
	var kids []treeEntry
	for _, e := range ents {
		te, ok, err := st.svcEntry(ctx, cat, e)
		if err != nil {
			return nil, err
		}
		if ok {
			kids = append(kids, te)
		}
	}
	d := st.s.nameDir(kids, func(node string) time.Time { return st.nodeBorn(ctx, cat, node) })
	st.s.keepView(st.tk, k, tokenView{sd: svcDir{d: d, at: now, gen: gen}}, 256*(len(d.entries)+1))
	return d, nil
}

// behindDir lists folder of catalog cat from its node documents, while
// the tree service is behind the user's writes; a grant that can't read
// them (§H.7) waits for the tree service (503).
func (st *reqState) behindDir(ctx context.Context, cat, folder string) (*treeDir, error) {
	d, err := st.nodeDir(ctx, cat, folder)
	var de *davError
	if err != nil && errors.As(upstream(err), &de) && (de.status == http.StatusUnauthorized || de.status == http.StatusForbidden || de.status == http.StatusNotFound) {
		e := fail(http.StatusServiceUnavailable, "catalog %s's tree service hasn't caught up with your latest writes yet, and your grant doesn't read the catalog's nodes otherwise (%s); try again in a moment", cat, de.msg)
		e.header = http.Header{"Retry-After": {"1"}}
		return nil, e
	}
	return d, err
}

// svcItem is an entry of a children listing (§B.5, §H.3).
type svcItem struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Title  string   `json:"title"`
	Sealed *string  `json:"sealed"` // a title sealed (§E.2.6)
	Item   string   `json:"item"`
	Head   string   `json:"head"`
	Self   bool     `json:"self"`
	File   *svcFile `json:"file"`
}

// svcFile is a placement's file metadata (§H.3).
type svcFile struct {
	Size     *json.Number `json:"size"`
	Type     string       `json:"type"`
	Modified string       `json:"modified"`
	Sealed   *string      `json:"sealed"`
}

// svcEntry is listing entry e as a child of a folder (treeEntry), and
// whether it is one: a folder; a placement whose item the tree service
// shows the reader (a head), with its file metadata where given, and not
// in a sealed or end-to-end namespace (§H.7: its file sealed, or without
// file in a namespace sealed). An implicit placement (§B.9), which no
// catalog node holds and the gateway can't rename or move, isn't one; a
// title sealed is a sealed catalog, which isn't offered (§H.3).
func (st *reqState) svcEntry(ctx context.Context, cat string, e svcItem) (treeEntry, bool, error) {
	if e.Sealed != nil {
		return treeEntry{}, false, notOffered(cat)
	}
	switch {
	case e.Kind == "folder" && folderName(e.Name):
		return newTreeEntry(&tree.Node{Name: e.Name, Kind: kindFolder, Title: e.Title}, nil), true, nil
	case e.Kind != "item" || e.Self || e.Head == "":
		return treeEntry{}, false, nil
	}
	ns, name, ok := tree.ParseHref(e.Item)
	if !ok || e.Name != ns+"."+name {
		return treeEntry{}, false, nil
	}
	n := &tree.Node{Name: e.Name, Kind: tree.KindPlacement, Title: e.Title, ItemNS: ns, ItemName: name}
	te := newTreeEntry(n, &client.Head{State: client.Live, ID: e.Head})
	f := e.File
	switch {
	case f != nil && f.Sealed != nil:
		return treeEntry{}, false, nil
	case f != nil && f.Size != nil && f.Type != "":
		size, err := f.Size.Int64()
		mod, terr := time.Parse(time.RFC3339Nano, f.Modified)
		if err != nil || size < 0 || terr != nil {
			break
		}
		m := fileMeta{Meta: files.Meta{Size: size, Type: f.Type}}
		if f.Type != "application/json" {
			m.raw = &rawRef{typ: f.Type, size: size}
		}
		te.meta, te.modified = &m, mod
		return te, true, nil
	}
	// No file, or no time: read from the core as the node path reads it
	// (list), and its time with it (§H.3 "Where times are absent"), but
	// for a sealed or end-to-end namespace's item.
	return te, !st.s.nsInfo(ctx, st.tk, ns).sealed, nil
}

// nodeBorn is when catalog node name was created, the genesis of its
// chain, read with the token's grant; zero if unknown.
func (st *reqState) nodeBorn(ctx context.Context, cat, name string) time.Time {
	h, err := st.tk.c.Head(ctx, cat, name)
	if err != nil || h.State != client.Live {
		return time.Time{}
	}
	es, _, err := st.tk.c.LogPage(ctx, cat, name, h.ID, "")
	if err != nil || len(es) == 0 || es[0].Parent != "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, es[0].Created)
	return t
}

// svcAnswer is a listing page, or the tree service's error (§12).
type svcAnswer struct {
	Children []svcItem `json:"children"`
	Next     string    `json:"next"`
	Code     string    `json:"code"`
	Message  string    `json:"message"`
}

// svcList reads the children of folder in catalog cat from its tree
// service, every page, with the token's grant (§B.5): the head
// pointer's redirect to the listing at the current checkpoint, then the
// pages there. With mins, the listing includes those entries, which the
// tree service waits for, and the whole read is bounded by TreeWait:
// errBehind if it isn't done by then, or the tree service refuses them.
func (st *reqState) svcList(ctx context.Context, cat, folder string, mins []string) ([]svcItem, error) {
	q := url.Values{"of": {folder}, "limit": {strconv.Itoa(st.s.ts.page)}}
	parent := ctx
	if len(mins) > 0 {
		q["min"] = mins
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, st.s.opt.TreeWait)
		defer cancel()
	}
	u, err := url.Parse(st.s.treeURL(cat) + "/" + cat + "/children?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var out []svcItem
	for hops, pages := 0, 0; ; {
		a, loc, err := st.svcGet(ctx, cat, u, len(mins) > 0)
		switch {
		case err != nil && len(mins) > 0 && ctx.Err() != nil && parent.Err() == nil:
			return nil, errBehind
		case err != nil:
			return nil, err
		case loc != nil:
			if hops++; hops > 4 {
				return nil, fail(http.StatusBadGateway, "catalog %s's tree service redirected the listing of %s more than 4 times", cat, folder)
			}
			u = loc
			continue
		}
		out = append(out, a.Children...)
		if a.Next == "" {
			return out, nil
		}
		if pages++; pages >= maxTreePages {
			e := fail(http.StatusForbidden, "a folder of catalog %s holds more than %d files and folders, more than this server lists in one folder: split it into folders through another tool (its files are opened, written and moved by name all the same)", cat, maxTreePages*st.s.ts.page)
			e.tooBig = true
			return nil, e
		}
		// The next page, at the checkpoint of this one (§B.5): its query
		// is in canonical form, without min.
		nu := *u
		nu.RawQuery = strings.TrimPrefix(a.Next, "?")
		u, hops = &nu, 0
	}
}

// svcGet reads one URL of catalog cat's tree service: a page, or a
// redirect's target. withMins: a 503 behind, or a 400 refusing them, is
// errBehind.
func (st *reqState) svcGet(ctx context.Context, cat string, u *url.URL, withMins bool) (*svcAnswer, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if b := st.tk.c.Bearer(); b != "" {
		req.Header.Set("Authorization", "Bearer "+b)
	}
	res, err := st.s.ts.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's tree service can't be reached", cat), cause: err}
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's tree service's answer was cut short", cat), cause: err}
	}
	switch res.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		loc, err := u.Parse(res.Header.Get("Location"))
		if err != nil || res.Header.Get("Location") == "" {
			return nil, nil, fail(http.StatusBadGateway, "catalog %s's tree service redirected to %q", cat, res.Header.Get("Location"))
		}
		return nil, loc, nil
	}
	var a svcAnswer
	jsonErr := json.Unmarshal(b, &a)
	msg := strings.TrimPrefix(a.Code+": "+a.Message, ": ")
	if msg == "" {
		msg = http.StatusText(res.StatusCode)
	}
	switch ct, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type")); {
	case res.StatusCode == http.StatusOK && ct == "application/jose":
		// A sealed catalog's listing, sealed whole (§E.2.6): its titles
		// are sealed too, and it isn't offered (§H.3).
		return nil, nil, notOffered(cat)
	case res.StatusCode == http.StatusOK && jsonErr != nil:
		return nil, nil, &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's tree service answered with a listing that isn't JSON", cat), cause: jsonErr}
	case res.StatusCode == http.StatusOK:
		return &a, nil, nil
	case withMins && res.StatusCode == http.StatusServiceUnavailable && a.Code == "behind":
		return nil, nil, errBehind
	case withMins && res.StatusCode == http.StatusBadRequest:
		return nil, nil, errMinsRefused
	case res.StatusCode == http.StatusNotFound:
		return nil, nil, fail(http.StatusNotFound, "catalog %s's tree service: %s", cat, msg)
	case res.StatusCode == http.StatusGone:
		return nil, nil, fail(http.StatusGone, "catalog %s's tree service: %s: the catalog was purged (§8.5)", cat, msg)
	case res.StatusCode == http.StatusUnauthorized && !st.s.opt.Gateway:
		// Local mode's grant is the server's own (-bearer): a 502, named
		// as the tree service's refusal, where record would name a 401
		// the core's.
		return nil, nil, fail(http.StatusBadGateway, "catalog %s's tree service refused this server's grant (-bearer): %s", cat, msg)
	case res.StatusCode == http.StatusUnauthorized, res.StatusCode == http.StatusForbidden:
		// A gateway's 401 is the user's grant refused: the challenge
		// again, and the token verified again at its next request
		// (record).
		return nil, nil, fail(res.StatusCode, "catalog %s's tree service refused the listing: %s", cat, msg)
	case res.StatusCode == http.StatusServiceUnavailable, res.StatusCode == http.StatusTooManyRequests:
		e := fail(http.StatusServiceUnavailable, "catalog %s's tree service answered %d: %s", cat, res.StatusCode, msg)
		ra := res.Header.Get("Retry-After")
		if ra == "" {
			ra = "1"
		}
		e.header = http.Header{"Retry-After": {ra}}
		return nil, nil, e
	}
	return nil, nil, fail(http.StatusBadGateway, "catalog %s's tree service answered %d: %s", cat, res.StatusCode, msg)
}
