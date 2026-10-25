package dav

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/tree"
)

// Tree-derived access (§B.11, §H.2 "Access"). A tree whose tree service
// is a catalog service (derived: it issues grants, POST /grants, as a
// tree service without §B.11 doesn't) gives its users their rights to
// read, place and move from the catalog's grants, not from a grant of
// theirs on the content namespace (§H.2): the gateway asks the catalog
// service for them with the user's grant, its proof of identity
// (§B.11.6), and sends the core's requests for the resource a grant
// fixes with that grant (route):
//
//   - a new file is placed first, under a Place grant, then its item
//     created, its blob uploaded first, with If-None-Match: * under the
//     Create grant the catalog resolves from the placement; the
//     placement is deleted if that fails (§H.4 "New files", placeFirst);
//   - a rename or a move is one append under a Move grant, whose patch
//     set begins with the test of /parents the answer gives (§H.5,
//     §B.11.4), a stale test (422) answered 409, asking for a reload;
//   - a file's placement is deleted under an Unplace grant, a folder
//     under a delete grant, and a folder made under a Create a folder
//     grant (§B.11.4); the item stays, since the catalog's key never
//     deletes there (§B.11.3);
//   - a file's item is read, and edited, under a grant for its content
//     verbs (§B.11.4), or a read grant of POST /read-grants for a listing
//     (§B.11.5); one the catalog refuses is the user's own grant's to
//     read or edit, if it can.
//
// Organising grants (Place, Move, Unplace, delete, Create a folder) are
// sent with writes only: reads of the node documents, which decide
// names and a folder's emptiness (§H.4), stay the user's grant's.

// kindFor is how long what a tree service is, a catalog service or not,
// is kept.
const kindFor = 5 * time.Minute

// svcKind is what catalog cat's tree service was found to be, and when.
type svcKind struct {
	catalog bool
	at      time.Time
}

// derived reports whether catalog cat's tree service is a catalog service
// (§B.11): one that answers POST /grants, which a tree service without
// §B.11 refuses (405, GET and HEAD only). A tree service that can't be
// asked for now is the error.
func (st *reqState) derived(ctx context.Context, cat string) (bool, error) {
	base := st.s.treeURL(cat)
	if base == "" {
		return false, nil
	}
	now := st.s.opt.Now()
	st.s.ts.mu.Lock()
	k, ok := st.s.ts.kinds[cat]
	st.s.ts.mu.Unlock()
	if ok && now.Sub(k.at) < kindFor {
		return k.catalog, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/grants", strings.NewReader("{}"))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := st.s.ts.hc.Do(req)
	if err != nil {
		return false, &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's tree service can't be reached", cat), cause: err}
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusMethodNotAllowed, http.StatusNotFound:
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusUnsupportedMediaType:
		k.catalog = true
	default:
		return false, fail(http.StatusBadGateway, "catalog %s's tree service answered POST /grants %d", cat, res.StatusCode)
	}
	k.at = now
	st.s.ts.mu.Lock()
	st.s.ts.kinds[cat] = k
	st.s.ts.mu.Unlock()
	return k.catalog, nil
}

// issued is a catalog service's answer to POST /grants (§B.11.4): the
// grant, the node's parents and head as decided, for a Move (parents),
// an Unplace or a delete (head).
type issued struct {
	Grant   string `json:"grant"`
	Parents any    `json:"parents"`
	Head    string `json:"head"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// issue asks catalog cat's catalog service for a grant (POST /grants,
// §B.11.4) with the token's grant, its request req ({ item | node, want,
// to? }), and ?min for the user's writes there it is to decide past
// (§B.11.4 "Read-your-writes"): a placement's before its item's Create
// grant. A 503 (behind, or the mins not reached yet) is asked again
// within TreeWait. The catalog's refusals (403, 404, 409, 410) are the
// answer, with its message; a 401 refuses the user's grant.
func (st *reqState) issue(ctx context.Context, cat string, req map[string]any) (*issued, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var a issued
	if err := st.catalogPost(ctx, cat, "/grants", body, &a); err != nil {
		return nil, err
	}
	if a.Grant == "" {
		return nil, fail(http.StatusBadGateway, "catalog %s's catalog service answered POST /grants without a grant", cat)
	}
	return &a, nil
}

// catalogPost posts body to path of catalog cat's catalog service, as
// issue does, decoding its 200 answer into out.
func (st *reqState) catalogPost(ctx context.Context, cat, path string, body []byte, out any) error {
	c, err := st.treeConf(ctx, cat)
	if err != nil {
		return err
	}
	nss := append([]string{cat}, c.trust...)
	mins, _ := st.p.ts.mins(nss, st.s.opt.Now())
	q := ""
	if len(mins) > 0 {
		q = "?" + url.Values{"min": mins}.Encode()
	}
	// Waited out in real time, as a listing's TreeWait is (svcListing).
	deadline := time.Now().Add(st.s.opt.TreeWait)
	for wait := 50 * time.Millisecond; ; wait = min(2*wait, time.Second) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, st.s.treeURL(cat)+path+q, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if b := st.tk.c.Bearer(); b != "" {
			req.Header.Set("Authorization", "Bearer "+b)
		}
		res, err := st.s.ts.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's catalog service can't be reached", cat), cause: err}
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		res.Body.Close()
		if err != nil {
			return &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's catalog service's answer was cut short", cat), cause: err}
		}
		if res.StatusCode == http.StatusOK {
			if err := json.Unmarshal(b, out); err != nil {
				return &davError{status: http.StatusBadGateway, msg: fmt.Sprintf("catalog %s's catalog service answered %s with what isn't JSON", cat, path), cause: err}
			}
			return nil
		}
		var e struct{ Code, Message string }
		json.Unmarshal(b, &e)
		msg := strings.TrimPrefix(e.Code+": "+e.Message, ": ")
		if msg == "" {
			msg = http.StatusText(res.StatusCode)
		}
		switch res.StatusCode {
		case http.StatusServiceUnavailable, http.StatusTooManyRequests:
			if time.Now().Add(wait).Before(deadline) {
				select {
				case <-time.After(wait):
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			de := fail(http.StatusServiceUnavailable, "catalog %s's catalog service answered %d: %s", cat, res.StatusCode, msg)
			ra := res.Header.Get("Retry-After")
			if ra == "" {
				ra = "1"
			}
			de.header = http.Header{"Retry-After": {ra}}
			return de
		case http.StatusUnauthorized:
			if !st.s.opt.Gateway {
				return fail(http.StatusBadGateway, "catalog %s's catalog service refused this server's grant (-bearer): %s", cat, msg)
			}
			return fail(http.StatusUnauthorized, "catalog %s's catalog service refused your grant: %s", cat, msg)
		case http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusGone:
			return fail(res.StatusCode, "catalog %s's catalog service: %s (§B.11.4)", cat, msg)
		}
		return fail(http.StatusBadGateway, "catalog %s's catalog service answered %s %d: %s", cat, path, res.StatusCode, msg)
	}
}

// issuedGrant is a grant a catalog service issued a token (§B.11.4,
// §B.11.5), for one resource (route): what it can do there, until when,
// and whether it serves writes only (an organising grant: reads stay the
// user's grant's).
type issuedGrant struct {
	grant  string
	can    []string
	exp    time.Time
	writes bool
}

// issuedSlack is how long before its expiry an issued grant is no longer
// sent, and asked for again.
const issuedSlack = 30 * time.Second

// maxIssued bounds the issued grants a token keeps.
const maxIssued = 1 << 10

// install has the token's core requests for ns/name sent with grant g,
// which catalog cat's catalog service issued it (route), for writes only
// where writes (an organising grant). It notes the catalog's kid in ns
// for the user's sub (§H.7 "Users": its entries there are the user's),
// and, for a content grant, drops what the token was told of ns, which
// the issued grant asks for again (§7.4 writer, can).
func (st *reqState) install(ns, name, g string, writes bool) error {
	dg, err := grant.Decode(g, 64<<10)
	if err != nil || len(dg.Blocks) == 0 {
		return fail(http.StatusBadGateway, "the catalog service issued a grant that doesn't decode: %v", err)
	}
	root := dg.Blocks[0]
	ig := issuedGrant{grant: g, can: append([]string(nil), root.Can...), writes: writes}
	if root.Exp != nil {
		ig.exp = *root.Exp
	}
	for _, b := range dg.Blocks[1:] {
		if b.Exp != nil && (ig.exp.IsZero() || b.Exp.Before(ig.exp)) {
			ig.exp = *b.Exp
		}
	}
	st.p.issuedTo(ns, root.Sub, root.Kid)
	tk := st.tk
	tk.mu.Lock()
	if len(tk.issued) >= maxIssued {
		now := st.s.opt.Now()
		for k, v := range tk.issued {
			if !now.Before(v.exp.Add(-issuedSlack)) {
				delete(tk.issued, k)
			}
		}
		for k := range tk.issued {
			if len(tk.issued) < maxIssued {
				break
			}
			delete(tk.issued, k)
		}
	}
	tk.issued[ns+"/"+name] = ig
	if !writes {
		delete(tk.writers, ns)
	}
	tk.mu.Unlock()
	return nil
}

// issuedFor returns the grant issued for ns/name that can do every verb
// of verbs now, "" if none.
func (tk *token) issuedFor(ns, name string, now time.Time, verbs ...string) string {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	ig, ok := tk.issued[ns+"/"+name]
	if !ok || !now.Before(ig.exp.Add(-issuedSlack)) {
		return ""
	}
	for _, v := range verbs {
		if !slices.Contains(ig.can, v) {
			return ""
		}
	}
	return ig.grant
}

// route is the transport of a token's client: a request for a resource
// (/r/{ns}/{name}…) the token holds an issued grant for (install) goes
// with that grant, where the grant can do what the request takes (read
// for GET and HEAD, delete for DELETE, create, append or restore for
// any other), and not for reads where it serves writes only; and GET
// /ns/{ns}/principal with a content grant issued in ns, which tells what
// writes there need (§7.4).
func (tk *token) route(now func() time.Time) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if g := tk.routed(r, now()); g != "" {
				r = r.Clone(r.Context())
				r.Header.Set("Authorization", "Bearer "+g)
			}
			return next.RoundTrip(r)
		})
	}
}

// routed is the issued grant request r goes with (route), "" for the
// token's own.
func (tk *token) routed(r *http.Request, now time.Time) string {
	tk.mu.Lock()
	n := len(tk.issued)
	tk.mu.Unlock()
	if n == 0 {
		return ""
	}
	segs := strings.Split(r.URL.Path, "/")
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	for i := 0; i+2 < len(segs); i++ {
		switch {
		case segs[i] == "r" && client.ValidNSName(segs[i+1]):
			ns, name := segs[i+1], segs[i+2]
			tk.mu.Lock()
			ig, ok := tk.issued[ns+"/"+name]
			tk.mu.Unlock()
			if !ok || !now.Before(ig.exp.Add(-issuedSlack)) || read && ig.writes {
				return ""
			}
			switch {
			case read && slices.Contains(ig.can, "read"):
			case r.Method == http.MethodDelete && slices.Contains(ig.can, "delete"):
			case !read && r.Method != http.MethodDelete && (slices.Contains(ig.can, "create") || slices.Contains(ig.can, "append") || slices.Contains(ig.can, "restore")):
			default:
				return ""
			}
			return ig.grant
		case segs[i] == "ns" && client.ValidNSName(segs[i+1]) && segs[i+2] == "principal" && i+3 == len(segs) && read:
			ns := segs[i+1]
			tk.mu.Lock()
			defer tk.mu.Unlock()
			for k, ig := range tk.issued {
				if strings.HasPrefix(k, ns+"/") && !ig.writes && now.Before(ig.exp.Add(-issuedSlack)) {
					return ig.grant
				}
			}
			return ""
		}
	}
	return ""
}

// itemAccess has the token's requests for t's item, a file of a tree with
// tree-derived access, go with a grant the catalog issues for it (§H.2
// "Access", §B.11.4): read, and append where write. One the catalog
// refuses (a role that doesn't count, an item it doesn't see) leaves them
// to the user's own grant, which may read or edit it all the same.
func (st *reqState) itemAccess(ctx context.Context, t target, write bool) error {
	if t.kind != kPlacement || !st.s.cats[t.ns] {
		return nil
	}
	if d, err := st.derived(ctx, t.ns); err != nil || !d {
		return err
	}
	want := []string{"read"}
	if write {
		want = append(want, "append")
	}
	if st.tk.issuedFor(t.docNS, t.docName, st.s.opt.Now(), want...) != "" {
		return nil
	}
	a, err := st.issue(ctx, t.ns, map[string]any{"item": "/r/" + t.docNS + "/" + t.docName, "want": toAny(want)})
	var de *davError
	switch {
	case errors.As(err, &de) && de.status >= 400 && de.status < 500 && de.status != http.StatusUnauthorized:
		return nil
	case err != nil:
		return err
	}
	return st.install(t.docNS, t.docName, a.Grant, false)
}

// readGrants has the token's reads of items, files of catalog cat's
// tree with tree-derived access that a listing shows without their file
// metadata, go with the grants POST /read-grants issues for them
// (§B.11.4, §B.11.5: its answer's items, each with its grant), those it
// holds no read grant for yet; items it refuses (an item's status and
// code, no grant) are left to the user's own grant.
func (st *reqState) readGrants(ctx context.Context, cat string, items []headDoc) error {
	if len(items) == 0 {
		return nil
	}
	if d, err := st.derived(ctx, cat); err != nil || !d {
		return err
	}
	now := st.s.opt.Now()
	var want []any
	for _, hd := range items {
		if st.tk.issuedFor(hd.ns, hd.name, now, "read") == "" && len(want) < 100 {
			want = append(want, "/r/"+hd.ns+"/"+hd.name)
		}
	}
	if len(want) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"items": want})
	if err != nil {
		return err
	}
	type entry struct {
		Item  string `json:"item"`
		Grant string `json:"grant"`
	}
	var a struct {
		Items []entry `json:"items"`
		// Grants is the list as catalog services before v0.73 named it,
		// whose entries are the same.
		Grants []entry `json:"grants"`
	}
	if err := st.catalogPost(ctx, cat, "/read-grants", body, &a); err != nil {
		var de *davError
		if errors.As(err, &de) && de.status >= 400 && de.status < 500 && de.status != http.StatusUnauthorized {
			return nil
		}
		return err
	}
	if a.Items == nil {
		a.Items = a.Grants
	}
	for _, it := range a.Items {
		ns, name, ok := strings.Cut(strings.TrimPrefix(it.Item, "/r/"), "/")
		if ok && it.Grant != "" {
			if err := st.install(ns, name, it.Grant, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// toAny is ss as a JSON array.
func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// createIssued creates catalog node name with doc (If-None-Match: *)
// under grant g the catalog issued for it (§B.11.4: Place, or Create a
// folder), with a fresh $nonce where the catalog requires one (§H.7).
// Its name is new, so it isn't looked up first: one that exists or
// existed is a 409.
func (st *reqState) createIssued(ctx context.Context, cat, name string, g *issued, doc map[string]any) error {
	if err := st.install(cat, name, g.Grant, true); err != nil {
		return err
	}
	in := st.s.nsInfo(ctx, st.tk, cat)
	defer st.changed()
	return st.retrying(ctx, func() (bool, error) {
		_, err := st.tk.c.Create(ctx, cat, name, withNonce(in, doc, client.GenesisPatches(doc)))
		if client.IsStale(err) || goneSince(err) {
			return false, fail(http.StatusConflict, "%s/%s exists or existed already", cat, name)
		}
		st.committed = st.committed || err == nil
		return false, err
	})
}

// placeFirst creates new file t (newFile), item item of files.ns, in a
// tree with tree-derived access (§H.4 "New files"): its placement node
// first, doc, under a Place grant (§B.11.4), dangling until its item
// exists (§B.7); then the item, its blob uploaded first for a raw file,
// with If-None-Match: * under the Create grant the catalog resolves from
// the placement, asked for past the placement's write (?min). If that
// fails, the placement is deleted again under an Unplace grant; one the
// catalog doesn't grant dangles.
func (st *reqState) placeFirst(ctx context.Context, t target, f *treeFiles, item string, doc map[string]any, raw bool, v any, body []byte) (string, bool, error) {
	href, node := "/r/"+f.ns+"/"+item, f.ns+"."+item
	place, err := st.issue(ctx, t.ns, map[string]any{"item": href, "want": []any{"place"}, "to": []any{t.parent}})
	if err != nil {
		return "", false, err
	}
	if err := st.createIssued(ctx, t.ns, node, place, doc); err != nil {
		return "", false, err
	}
	var rev string
	var exact bool
	create, err := st.issue(ctx, t.ns, map[string]any{"item": href, "want": []any{"create"}})
	if err == nil {
		err = st.install(f.ns, item, create.Grant, false)
	}
	if err == nil {
		// Created blind: the Create grant can't read its head (§B.11.4).
		if raw {
			rev, exact, err = st.commitRaw(ctx, f.ns, item, body, saveOpts{pre: true, fresh: true, fname: t.title, blind: true})
		} else {
			rev, exact, err = st.commitDoc(ctx, f.ns, item, v, body, saveOpts{pre: true, fresh: true, blind: true})
		}
	}
	if err == nil {
		st.wroteTo = f.ns + "/" + item
		return rev, exact, nil
	}
	// The placement, dangling, goes again, a 429 waited out as a write's
	// is, whether or not the client waits (§H.4).
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	_, uerr := st.unplace(dctx, t.ns, node, "")
	cancel()
	if uerr != nil {
		st.s.opt.Logf("dav: %s/%s: deleting the placement made for an item whose create failed: %v; it dangles (§B.7)", t.ns, node, uerr)
		return "", false, err
	}
	if de, ok := upstream(err).(*davError); ok {
		out := *de
		out.msg += fmt.Sprintf(" (its placement, %s/%s, made for it first, is deleted again)", t.ns, node)
		return "", false, &out
	}
	return "", false, err
}

// unplace deletes node of catalog cat, a placement or a folder, under an
// Unplace or delete grant the catalog issues (§B.11.4), with If-Match on
// the head it decided, where that is head, if given, which the node
// documents read had (412 otherwise: changed since); a head moved before
// the delete is asked for again. It returns the tombstone.
func (st *reqState) unplace(ctx context.Context, cat, node, head string) (string, error) {
	var tomb string
	err := st.retrying(ctx, func() (bool, error) {
		g, err := st.issue(ctx, cat, map[string]any{"node": node, "want": []any{"delete"}})
		if err != nil {
			return false, err
		}
		match := g.Head
		if match == "" {
			h, err := st.tk.c.Head(ctx, cat, node)
			if err != nil {
				return false, err
			}
			match = h.ID
		}
		if head != "" && match != head {
			return false, fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", cat, node, head)
		}
		if err := st.install(cat, node, g.Grant, true); err != nil {
			return false, err
		}
		res, err := st.tk.c.Delete(ctx, cat, node, match)
		if client.IsStale(err) {
			return true, nil
		}
		if err == nil {
			tomb = res.ID
			st.s.markOwn(st.p, cat, node, res.ID)
			st.committed = true
		}
		return false, err
	})
	st.changed()
	return tomb, err
}

// nodeAsNamed returns the head of node t.node, a file or folder a write
// changes, and its document, where the user's grant reads them, checked
// to still have the name and parent t's path named (stillNamed, 404
// otherwise, §H.5); no document where it can't read it (the head alone
// where only the document is hidden from it), which keeps the listing's
// view for names (§H.4 "Names before writes").
func (st *reqState) nodeAsNamed(ctx context.Context, t target) (string, map[string]any, error) {
	h, err := st.tk.c.Head(ctx, t.ns, t.node)
	switch {
	case hidden(err), err == nil && h.State == client.NotFound:
		// Not the grant's to read: the core hides it (404, §7).
		return "", nil, nil
	case err != nil:
		return "", nil, err
	case h.State != client.Live:
		return "", nil, errNotExist
	}
	e, err := st.s.doc(ctx, st.tk, t.ns, t.node, h.ID)
	switch {
	case hidden(err):
		return h.ID, nil, nil
	case err != nil:
		return "", nil, err
	case !st.stillNamed(t, e.value):
		return "", nil, fail(http.StatusNotFound, "%s was renamed or moved by someone else just now; reload its folder", t.path)
	}
	m, _ := e.value.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return h.ID, m, nil
}

// parentHrefs is the hrefs of a node's parents value v (§B.2), each once.
func parentHrefs(v any) []string {
	var out []string
	arr, _ := v.([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		if h, ok := m["href"].(string); ok && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// moveIssued renames node src.node to title ("" keeps its title), or
// moves it from folder from to folder to ("" leaves from only: a node
// with several parents unlinked from one, §H.5), ordered order there, in
// a tree with tree-derived access: one append under a Move grant the
// catalog issues for the node's parents after it (§B.11.4: to its
// current ones for a rename), its patch set beginning with the test of
// /parents against the parents the catalog decided (the answer's
// parents), so it moves the node only from where it was judged; a stale
// test is a 422, answered 409 (reload). It is moved only from where
// src's path put it (§H.5): where the user's grant reads the node's own
// document, that is checked to still have the name and parent the path
// named (404 otherwise, nodeAsNamed), and its parents are those asked
// for; else the listing's view is kept for its name, and the parents the
// catalog decided must still hold from (404 otherwise: moved since by
// someone else), and are asked for again where they aren't from alone.
// Each attempt, after a stale If-Match too, reads and decides all again.
func (st *reqState) moveIssued(ctx context.Context, src target, title, from, to, order string) error {
	cat := src.ns
	in := st.s.nsInfo(ctx, st.tk, cat)
	href := func(n string) string { return "/r/" + cat + "/" + n }
	// after is the node's parents after the write, ps before it: the
	// same for a rename (to is from), from replaced by to for a move,
	// from left out to unlink (to "").
	after := func(ps []string) []string {
		if to == from {
			return ps
		}
		var out []string
		for _, p := range ps {
			if p != href(from) && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		if to != "" && !slices.Contains(out, href(to)) {
			out = append(out, href(to))
		}
		return out
	}
	ask := func(ps []string) (*issued, error) {
		return st.issue(ctx, cat, map[string]any{"node": src.node, "want": []any{"move"}, "to": toAny(ps)})
	}
	err := st.retrying(ctx, func() (bool, error) {
		_, doc, err := st.nodeAsNamed(ctx, src)
		if err != nil {
			return false, err
		}
		// parents are the node's before the write: its document's where
		// read, else, until the catalog decides them, from alone (the
		// listing's view).
		parents, read := []string{href(from)}, doc != nil
		var curTitle *string
		if read {
			parents = parentHrefs(doc["parents"])
			if t, ok := doc["title"].(string); ok {
				curTitle = &t
			}
		}
		target := after(parents)
		if len(target) == 0 && !read {
			// An unlink whose other parents aren't known: asked for as a
			// move to where it is, to learn them from the answer.
			target = parents
		}
		g, err := ask(target)
		if err != nil {
			return false, err
		}
		decided := parentHrefs(g.Parents)
		switch {
		case g.Parents == nil && !read:
			return false, fail(http.StatusForbidden, "%s isn't renamed or moved: your grant doesn't read its document, and catalog %s's answer doesn't say where it is now (§B.11.4), so that it is still where the path names it can't be checked (§H.5)", src.path, cat)
		case g.Parents == nil:
		case !slices.Contains(decided, href(from)) && !read:
			// Not in the folder src's path names, as the catalog decided:
			// moved since by someone else, whatever the listing showed.
			return false, fail(http.StatusNotFound, "%s was renamed or moved by someone else just now; reload its folder", src.path)
		case !slices.Contains(decided, href(from)):
			return false, fail(http.StatusConflict, "%s was moved by someone else, and catalog %s hasn't decided its move from where it is now yet (§B.11.4); reload its folder", src.path, cat)
		case !sameSet(decided, parents) || !sameSet(after(decided), target):
			// Its parents, as the catalog decided them, aren't those
			// assumed (another's of a node with several, not read): asked
			// for again, for those.
			parents = decided
			if target = after(parents); len(target) == 0 {
				return false, fail(http.StatusConflict, "%s is in no other folder now, so it isn't unlinked from this one (§H.5); reload its folder", src.path)
			}
			if g, err = ask(target); err != nil {
				return false, err
			}
			if g.Parents == nil || !sameSet(parentHrefs(g.Parents), parents) {
				// Moved again while the catalog decided: all again.
				return true, nil
			}
		}
		if src.kind == kFolder && st.srcMatch != "" && g.Head != "" && g.Head != st.srcMatch {
			return false, st.sourceMoved(src.path)
		}
		var ps []any
		if g.Parents != nil {
			ps = append(ps, map[string]any{"op": "test", "path": "/parents", "value": g.Parents})
		}
		changes := 0
		if title != "" && (curTitle == nil || *curTitle != title) {
			ps = append(ps, map[string]any{"op": "add", "path": "/title", "value": title})
			changes++
		}
		if to != from {
			var entries []any
			arr, _ := g.Parents.([]any)
			if arr == nil {
				for _, p := range parents {
					arr = append(arr, map[string]any{"href": p})
				}
			}
			for _, x := range arr {
				m, _ := x.(map[string]any)
				if h, _ := m["href"].(string); h != href(from) && h != href(to) {
					entries = append(entries, x)
				}
			}
			if to != "" {
				e := map[string]any{"href": href(to)}
				if order != "" {
					e["order"] = order
				}
				entries = append(entries, e)
			}
			if entries == nil {
				entries = []any{}
			}
			ps = append(ps, map[string]any{"op": "replace", "path": "/parents", "value": entries})
			changes++
		}
		if changes == 0 {
			return false, nil
		}
		head := g.Head
		if head == "" {
			h, err := st.tk.c.Head(ctx, cat, src.node)
			if err != nil {
				return false, err
			}
			head = h.ID
		}
		if err := st.install(cat, src.node, g.Grant, true); err != nil {
			return false, err
		}
		_, err = st.tk.c.Append(ctx, cat, src.node, head, withNonce(in, map[string]any{}, ps))
		switch {
		case client.IsStale(err), goneSince(err):
			return true, nil
		case isPatchFailure(err):
			return false, fail(http.StatusConflict, "%s was moved by someone else since the catalog decided its move (the test of its parents failed, §B.11.4); reload its folder", src.path)
		}
		st.committed = st.committed || err == nil
		return false, err
	})
	st.changed()
	return err
}

// catalogHrefs is those of hrefs that name a node of catalog cat.
func catalogHrefs(cat string, hrefs []string) []string {
	var out []string
	for _, h := range hrefs {
		if ns, _, ok := tree.ParseHref(h); ok && ns == cat {
			out = append(out, h)
		}
	}
	return out
}

// catalogParents is where catalog cat's catalog service has node t.node
// now, for a write by a grant that doesn't read its document (§H.7
// "Limited grants"): the parents it decides for a Move of it to its
// folder t.parent, which a delete of it from there needs the powers of
// too (§B.11.4), and its head as decided. A node no longer in t.parent
// is a 404 (renamed or moved since, §H.5); one whose parents the answer
// doesn't give (a catalog-admin's) can't be checked, and is a 403.
func (st *reqState) catalogParents(ctx context.Context, t target) ([]string, string, error) {
	in := "/r/" + t.ns + "/" + t.parent
	g, err := st.issue(ctx, t.ns, map[string]any{"node": t.node, "want": []any{"move"}, "to": []any{in}})
	if err != nil {
		return nil, "", err
	}
	ps := parentHrefs(g.Parents)
	switch {
	case g.Parents == nil:
		return nil, "", fail(http.StatusForbidden, "%s isn't deleted or moved: your grant doesn't read its document, and catalog %s's answer doesn't say which folders it is in now (§B.11.4), so whether it is still in this one, and in others too, which a delete from one folder leaves it in (§H.5), can't be checked", t.path, t.ns)
	case !slices.Contains(ps, in):
		return nil, "", fail(http.StatusNotFound, "%s was renamed or moved by someone else just now; reload its folder", t.path)
	}
	return ps, g.Head, nil
}

// sameSet reports whether a and b hold the same strings.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
