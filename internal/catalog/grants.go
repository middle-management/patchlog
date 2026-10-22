package catalog

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// Request is the body of POST /grants (§B.11.4):
//
//	{ "item": "/r/matches/derby", "want": ["read", "append"] }        content verbs, from effective roles
//	{ "item": "/r/matches/final", "want": ["create"] }                 genesis of a placed, never-existing item
//	{ "item": "/r/matches/final", "want": ["restore"] }                a deleted item, by the roles it had when deleted
//	{ "item": "/r/matches/derby", "want": ["place"], "to": [folders] } create the placement
//	{ "node": "matches.derby",    "want": ["move"],  "to": [folders] } replace the node's parents
//	{ "node": "matches.derby",    "want": ["delete"] }                  unplace
//	{ "node": "season-2026",      "want": ["delete"] }                  delete a folder
//	{ "node": "highlights",       "want": ["create"], "to": [folders] } create a folder
//
// Folders and nodes may be given as /r/{catalog}/{name} or bare names.
// Place, Move and Create a folder take to; HasTo says it was given, so
// that to: [], a root, which only catalog admins may ask for, is told
// apart from a request without one (§B.11.4).
type Request struct {
	Item  string   `json:"item,omitempty"`
	Node  string   `json:"node,omitempty"`
	Want  []string `json:"want"`
	To    []string `json:"to,omitempty"`
	HasTo bool     `json:"-"`
}

// UnmarshalJSON decodes a request, noting whether it gives to.
func (r *Request) UnmarshalJSON(b []byte) error {
	type plain Request
	var aux struct {
		plain
		To *[]string `json:"to"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*r = Request(aux.plain)
	r.To, r.HasTo = nil, aux.To != nil
	if aux.To != nil {
		r.To = *aux.To
	}
	return nil
}

// Issued is an issued grant, the answer of POST /grants (§B.11.4):
// { grant, checkpoint, parents?, head? }. At is the grant's own at, the
// catalog's ns_id; Checkpoint, beside the grant and never in it, is what
// it was decided at (checkpointAt), by which a client that caches
// decisions keys them. Parents, for a Move grant that pins them, is the
// node's parents member as decided, which the write's leading test of
// /parents must name (planMove); Head, for a Move or an Unplace or
// delete, is the node's head revision as decided, for the write's
// If-Match. The other members (ns, resource, can, roles, exp, at) stay,
// for clients that read them (F-B8).
type Issued struct {
	Grant      string            `json:"grant"`
	NS         string            `json:"ns"`
	Resource   string            `json:"resource"`
	Can        []string          `json:"can"`
	Roles      []string          `json:"roles,omitempty"`
	Exp        string            `json:"exp"`
	At         map[string]any    `json:"at"`
	Checkpoint map[string]string `json:"checkpoint"`
	Parents    any               `json:"parents,omitempty"`
	Head       string            `json:"head,omitempty"`
}

// Error is a refusal with an HTTP status. A refusal that is a decision
// carries the checkpoint it was decided at (decidedAt).
type Error struct {
	Status     int
	Code       string
	Msg        string
	Checkpoint map[string]string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Msg) }

func errf(status int, code, format string, a ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

func badInput(format string, a ...any) error  { return errf(400, "bad_input", format, a...) }
func forbidden(format string, a ...any) error { return errf(403, "forbidden", format, a...) }
func conflict(format string, a ...any) error  { return errf(409, "conflict", format, a...) }

func upstream(err error) error {
	return &Error{Status: 502, Code: "upstream", Msg: err.Error()}
}

// configErr answers a namespace document the checker couldn't read: 410
// gone for a purged sealed namespace, whose documents are 410 purged once
// the purge destroys their epoch keys (§8.5), as for a purged item, since
// nothing in it can be granted any more; 502 otherwise.
func configErr(ns string, err error) error {
	if client.IsPurged(err) {
		return errf(410, "gone", "namespace %s is purged", ns)
	}
	return upstream(err)
}

// decidedAt marks a refusal that is a decision (403, 404, 409, 410) with
// the checkpoint it was decided at (checkpointAt), so a client that
// caches refusals keys them as it keys grants (§B.11.4). Plans defer it
// once their View has run; other errors pass unchanged. A refusal decided
// from state the checkpoint doesn't pin, such as the core's head of a
// name (a 409 for a name the service hasn't seen yet) or the signing key
// at the head, isn't decided at it: the plan clears its checkpoint before
// it returns one, so it carries none, as before its View ran.
func decidedAt(err error, checkpoint map[string]string) error {
	var ce *Error
	if len(checkpoint) == 0 || !errors.As(err, &ce) || ce.Checkpoint != nil {
		return err
	}
	switch ce.Status {
	case 403, 404, 409, 410:
		ce.Checkpoint = checkpoint
	}
	return err
}

// checkpointAt is the checkpoint a decision reports (§B.11.4),
// { ns: ns_id }: the ns_ids, as of the checkpoint g reflects, of the
// catalog and of nss, the namespaces of the items the request names and
// of those whose roles or includes it read (a folder's visibility, a
// move's no widening: every trusted namespace; organising.checkpoint),
// which are all a decision on them depends on. So a write elsewhere, in
// a content namespace the decision didn't read, doesn't move it, as the
// combined checkpoint of listings (§B.5) would. A namespace the service
// doesn't follow has no entry. Call it under View.
func checkpointAt(g *tree.Graph, cur map[string]string, nss ...string) map[string]string {
	cp := map[string]string{}
	for _, ns := range append([]string{g.Catalog}, nss...) {
		if id := cur[ns]; id != "" {
			cp[g.Actual(ns)] = id
		}
	}
	return cp
}

// itemNS is the namespace of the item a catalog node names, for a
// placement {ns}.{name} (checkpointAt); a folder names none.
func itemNS(node string) []string {
	if ns, _, ok := tree.SplitPlacement(node); ok {
		return []string{ns}
	}
	return nil
}

// folderName reports whether a catalog node named name would be a folder:
// a name without a dot (tree.ParseNode), whether or not the catalog has
// such a node.
func folderName(name string) bool {
	return !strings.Contains(name, ".")
}

// plan is a decision, made under the graph lock at a checkpoint: cp is
// the catalog's ns_id there (the grant's at), checkpoint what the answer
// reports (checkpointAt). key is the signing key's entry as of the head,
// which the core checks the grant against (maxTtl, requireAt, groups;
// §C.4); the decision itself uses the entry as of the checkpoint
// (configAt). parents and head go in the answer beside the grant
// (Issued); expBy, if set, bounds the grant's exp (a Move grant's, within
// the catalog's maxLag of its decision, §B.11.8).
type plan struct {
	ns, resource string
	can, roles   []string
	rules        []any
	cp           string
	checkpoint   map[string]string
	key          *grant.Key
	parents      any
	head         string
	expBy        time.Time
}

// Authenticate verifies a caller's grant for the catalog namespace.
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (*grant.Verified, error) {
	return s.t.Checker().Verify(ctx, s.t.Catalog(), tree.Bearer(r))
}

func (s *Service) serveGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, err := s.Authenticate(r.Context(), r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	if status, code, msg := s.t.AwaitMins(r.Context(), r.URL.Query()["min"]); status != 0 {
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		tree.WriteError(w, status, code, msg)
		return
	}
	var req Request
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.Issue(r.Context(), v, req)
	if err != nil {
		writeErr(w, err)
		return
	}
	tree.WriteJSON(w, http.StatusOK, res)
}

// ReadGrantsRequest is the body of POST /read-grants (§B.11.5).
type ReadGrantsRequest struct {
	Items []string `json:"items"`
}

// maxReadGrants is the most items one POST /read-grants may list (400
// bad_input above it): the service's limit, since every item is decided
// at one checkpoint and a longer list is likelier to need a retry.
const maxReadGrants = 100

// readGrantRetries is how often POST /read-grants decides its items again
// when the checkpoint moved while it decided them, before it answers 503
// behind.
const readGrantRetries = 3

// serveReadGrants issues one read grant per item, fixed to that resource
// (§B.11.5). Items of public namespaces need none; refusals are reported
// per item:
//
//	{ "grants": [
//	  { "item", "grant", "exp", "keys"?, "keysWithheld"?, "checkpoint" },
//	  { "item", "public": true, "keys"?, "checkpoint"? },
//	  { "item", "keys"? | "keysWithheld"?, "checkpoint" },                 a catalog node
//	  { "item", "error": { "status", "code", "message" }, "checkpoint"? } ] }
//
// with one entry per item, in request order, and at most maxReadGrants
// items (400 above). It answers for every item at once, all decided at one
// combined checkpoint (§B.5): it notes it before and after deciding, and
// decides again if it moved, up to readGrantRetries times, then answers
// 503 behind with Retry-After.
//
// Each entry carries the checkpoint its decision was made at, beside its
// grant as POST /grants carries it (§B.11.4, checkpointAt): the catalog's
// ns_id and that of the item's own namespace (for a catalog node, of the
// item a placement names, and for a folder, of every trusted namespace,
// whose roles decide its visibility), which are all that one item's
// decision depends on. So a client caches each item's decision on its
// own, and a write to one item's namespace leaves the others' standing. One map for
// the whole answer would key every item by every named namespace, and
// couldn't leave out the entries §B.11.4 gives none: a refusal decided
// from state the checkpoint doesn't pin (decidedAt), a 5xx, or a public
// item of a namespace the service doesn't follow, whose exposure is read
// at the head.
//
// So "may this reader read all of these?" is one call (§B.11.5): it may
// if every entry comes back with a grant, or "public": true (an item in a
// public namespace that isn't sealed, which gets no grant), or, for a
// sealed item or a catalog node, with its keys; that is, if no entry has
// an error. It may not if an entry's error is a refusal (a 4xx status);
// an entry whose error is a 5xx (503 behind from checkLag, 503 keys, 502
// upstream) is undecided, and the client asks again. Whether a namespace
// is public, and its encryption, are read as of the checkpoint too
// (exposureAt).
//
// Keys (§B.11.5, §E.2.6). For an item of a sealed content namespace the
// answer also carries the item's per-resource keys K_r, which open its
// revisions; for a sealed or e2e catalog, the keys of its placement node
// {ns}.{name}, which open the placement's per-entry listing entries, if
// the placement is visible to the caller. An item may also be a catalog
// node /r/{catalog}/{name} visible to the caller: it gets that node's
// keys only (no grant). Visible is the one test listings use (§B.11.5,
// visibility.Node). Keys are
// derived from the epoch keys the service holds as a consumer, for the
// epochs a reader gets (derived.Keys.ResourceKeys), and wrapped (HPKE) to
// the enc key of the caller's grant in the §E.2.3 format:
//
//	"keys": [{ "kid": "{ns}#{e}", "name": name, "wrapped" }, …]
//
// A caller whose grant has no enc gets "keysWithheld" instead. Keys of an
// e2e content namespace are not given: its revisions are sealed by clients
// under the epoch key, which only the keyring distributes (§E.3.2).
func (s *Service) serveReadGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	v, err := s.Authenticate(ctx, r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	if status, code, msg := s.t.AwaitMins(r.Context(), r.URL.Query()["min"]); status != 0 {
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		tree.WriteError(w, status, code, msg)
		return
	}
	var req ReadGrantsRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if len(req.Items) == 0 || len(req.Items) > maxReadGrants {
		writeErr(w, badInput("items must list 1 to %d items", maxReadGrants))
		return
	}
	for try := 0; try <= readGrantRetries; try++ {
		before := s.t.At()
		out := s.decideReads(ctx, v, req.Items)
		if f := s.afterDecide.Load(); f != nil {
			(*f)(try)
		}
		if s.t.At() == before {
			tree.WriteJSON(w, http.StatusOK, map[string]any{"grants": out})
			return
		}
	}
	writeErr(w, errf(503, "behind", "the catalog service's checkpoint kept moving while it decided the items"))
}

// decideReads decides POST /read-grants' items (serveReadGrants), one
// entry per item, in order.
func (s *Service) decideReads(ctx context.Context, v *grant.Verified, items []string) []any {
	lagOK := map[string]bool{}
	cat := s.t.Catalog()
	var enc *ecdh.PublicKey
	if len(v.Grant.Blocks) > 0 {
		enc = v.Grant.Blocks[0].Enc
	}
	// pin is the checkpoint a decision on items of nss reports
	// (checkpointAt).
	pin := func(nss ...string) (cp map[string]string) {
		s.t.View(func(g *tree.Graph, cur map[string]string) { cp = checkpointAt(g, cur, nss...) })
		return cp
	}
	// pinNode is the checkpoint a decision on the visibility of catalog
	// node name reports: a folder's reads every trusted namespace's
	// roles, a placement's its item's namespace's (§B.11.4 checkpoint).
	// Which is judged from the name, not the graph, so a hidden folder's
	// refusal carries the checkpoint a missing one's does (§B.11.5).
	pinNode := func(name string) (cp map[string]string) {
		s.t.View(func(g *tree.Graph, cur map[string]string) {
			nss := itemNS(name)
			if folderName(name) {
				for ns := range g.Trust {
					nss = append(nss, ns)
				}
			}
			cp = checkpointAt(g, cur, nss...)
		})
		return cp
	}
	// visible is the visibility test listings use (§B.11.5), for catalog
	// nodes and their keys.
	var vis tree.Visibility
	visible := func(name string) (bool, error) {
		if vis == nil {
			var err error
			if _, vis, err = s.Resolve(ctx, v); err != nil {
				return false, upstream(err)
			}
		}
		ok := false
		s.t.View(func(g *tree.Graph, _ map[string]string) {
			if n := g.Node(name); n != nil {
				ok = vis.Node(g, n)
			}
		})
		return ok, nil
	}
	out := []any{}
	for _, item := range items {
		e := map[string]any{"item": item}
		ns, name, ok := tree.ParseHref(item)
		var err error
		var want []keyOf         // the keys the item's answer carries
		var cp map[string]string // the checkpoint it was decided at
		switch {
		case ok && ns == cat:
			// A catalog node: its keys, if the caller sees it.
			cp = pinNode(name)
			var seen bool
			if seen, err = visible(name); err == nil && !seen {
				err = decidedAt(forbidden("%s is not a catalog node you can see", item), cp)
			}
			want = []keyOf{{cat, name}}
		default:
			var public, pinned bool
			var in derived.Info
			if ok {
				public, in, pinned = s.exposureAt(ctx, ns)
			}
			if public && !in.Protected() {
				e["public"] = true
				if pinned {
					e["checkpoint"] = pin(ns)
				}
				out = append(out, e)
				continue
			}
			var p *plan
			p, err = s.planContent(ctx, v, item, []string{"read"})
			if err == nil {
				cp = p.checkpoint
			}
			if err == nil && public {
				// Ciphertext is public; the keys decide (§E.2.5).
				e["public"] = true
			} else if err == nil {
				var is *Issued
				if is, err = s.mint(ctx, v, p, lagOK); err == nil {
					e["grant"], e["exp"] = is.Grant, is.Exp
				}
			}
			if in.Level == derived.LevelSealed {
				want = append(want, keyOf{ns, name})
			}
			// The placement's keys open its listing entry, so they go only
			// to callers the entry is listed for (§B.11.5).
			if err == nil {
				var seen bool
				if seen, err = visible(ns + "." + name); seen {
					want = append(want, keyOf{cat, ns + "." + name})
				}
			}
		}
		if err == nil {
			err = s.addKeys(ctx, e, enc, want)
		}
		if err != nil {
			delete(e, "grant")
			delete(e, "exp")
			delete(e, "public")
			var ce *Error
			if !errors.As(err, &ce) {
				ce = &Error{Status: 500, Code: "internal", Msg: err.Error()}
			}
			e["error"] = map[string]any{"status": ce.Status, "code": ce.Code, "message": ce.Msg}
			// Only a refusal decided at the checkpoint carries it
			// (decidedAt).
			cp = ce.Checkpoint
		}
		if len(cp) > 0 {
			e["checkpoint"] = cp
		}
		out = append(out, e)
	}
	return out
}

// exposureAt is whether ns is public and its encryption, as of the
// checkpoint the service is at (Graph.Content, configAt), so that one
// checkpoint gives one answer for an item (§B.11.4); the grant checker's
// and the key tracker's copies at the head stand in for a namespace the
// service doesn't follow, which has no state at a checkpoint (pinned
// false).
func (s *Service) exposureAt(ctx context.Context, ns string) (public bool, in derived.Info, pinned bool) {
	held := false
	s.t.View(func(g *tree.Graph, _ map[string]string) {
		c := g.Content[ns]
		if c == nil {
			return
		}
		held, in = true, derived.InfoOf(c.Doc)
		if cfg := s.parsed(c).cfg; cfg != nil {
			public = cfg.Read == "public"
		}
	})
	if held {
		return public, in, true
	}
	cfg, err := s.t.Checker().Config(ctx, ns)
	in, _ = s.t.Keys().Info(ctx, ns)
	return err == nil && cfg.Read == "public", in, false
}

// keyOf names a resource whose per-resource keys an answer carries.
type keyOf struct{ ns, name string }

// addKeys sets e["keys"] to the per-resource keys of want (those of
// namespaces that are sealed or e2e), wrapped to enc, or e["keysWithheld"]
// if there are keys and no enc to wrap them to.
func (s *Service) addKeys(ctx context.Context, e map[string]any, enc *ecdh.PublicKey, want []keyOf) error {
	var got []derived.ResourceKey
	for _, k := range want {
		ks, err := s.t.Keys().ResourceKeys(ctx, k.ns, k.name)
		if err != nil {
			logf(s)("catalog: keys of %s/%s: %v", k.ns, k.name, err)
			return errf(503, "keys", "the catalog service cannot obtain the keys of %s", k.ns)
		}
		got = append(got, ks...)
	}
	if len(got) == 0 {
		return nil
	}
	if enc == nil {
		e["keysWithheld"] = "the caller's grant has no enc key to wrap per-resource keys to (§E.2.3)"
		return nil
	}
	arr := make([]any, 0, len(got))
	for _, k := range got {
		wk, err := seal.WrapKey(enc, k.Kid, k.Resource, k.Key)
		if err != nil {
			return err
		}
		arr = append(arr, wk.Value())
	}
	e["keys"] = arr
	return nil
}

func logf(s *Service) func(string, ...any) {
	if s.opt.Tree.Logf != nil {
		return s.opt.Tree.Logf
	}
	return func(string, ...any) {}
}

func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return badInput("cannot read the body")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return badInput("malformed body: %v", err)
	}
	return nil
}

func writeErr(w http.ResponseWriter, err error) {
	var ce *Error
	if errors.As(err, &ce) {
		if ce.Status == 503 {
			w.Header().Set("Retry-After", "1")
		}
		if ce.Checkpoint != nil {
			tree.WriteJSON(w, ce.Status, map[string]any{"code": ce.Code, "message": ce.Msg, "checkpoint": ce.Checkpoint})
			return
		}
		tree.WriteError(w, ce.Status, ce.Code, ce.Msg)
		return
	}
	tree.WriteError(w, 500, "internal", err.Error())
}

// Issue decides a grant request for the verified caller v and signs the
// grant (§B.11.4).
func (s *Service) Issue(ctx context.Context, v *grant.Verified, req Request) (*Issued, error) {
	want := dedupe(req.Want)
	var p *plan
	var err error
	switch {
	case len(want) == 0:
		return nil, badInput("want is required")
	case contains(want, "place"):
		if len(want) != 1 || req.Item == "" {
			return nil, badInput(`place takes an item and want ["place"]`)
		}
		p, err = s.planPlace(ctx, v, req.Item, req)
	case contains(want, "move"):
		if len(want) != 1 || req.Node == "" {
			return nil, badInput(`move takes a node and want ["move"]`)
		}
		p, err = s.planMove(ctx, v, req.Node, req)
	case req.Node != "" && contains(want, "create"):
		if len(want) != 1 {
			return nil, badInput(`creating a folder takes a node and want ["create"]`)
		}
		p, err = s.planCreateFolder(ctx, v, req.Node, req)
	case req.Node != "" && len(want) == 1 && want[0] == "restore":
		p, err = s.planRestoreNode(ctx, v, req.Node)
	case req.Node != "":
		if len(want) != 1 || want[0] != "delete" {
			return nil, badInput(`a node request wants ["move"], ["create"] or ["delete"]`)
		}
		p, err = s.planUnplace(ctx, v, req.Node)
	case req.Item != "" && len(want) == 1 && want[0] == "restore" && s.inCatalog(req.Item):
		p, err = s.planRestoreNode(ctx, v, req.Item)
	case req.Item != "":
		p, err = s.planContent(ctx, v, req.Item, want)
	default:
		return nil, badInput("item or node is required")
	}
	if err != nil {
		return nil, err
	}
	return s.mint(ctx, v, p, map[string]bool{})
}

// inCatalog reports whether item names a document of the catalog
// namespace, /r/{catalog}/{name}.
func (s *Service) inCatalog(item string) bool {
	ns, _, ok := tree.ParseHref(item)
	return ok && ns == s.t.Catalog()
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func resourceRule(name string) any {
	return map[string]any{"op": "test", "path": "/resource", "value": name}
}

// parentsRule fixes /doc/parents to exactly the given folders (any order,
// any order keys).
func parentsRule(catalog string, folders []string) any {
	hrefs := make([]string, len(folders))
	for i, f := range folders {
		hrefs[i] = "/r/" + catalog + "/" + f
	}
	return parentHrefsRule(hrefs)
}

// parentHrefsRule fixes /doc/parents to exactly the given hrefs. None is
// a root: parents absent or [] (§B.2).
func parentHrefsRule(list []string) any {
	if len(list) == 0 {
		return map[string]any{"any": []any{
			map[string]any{"op": "test", "path": "/doc/parents", "exists": false},
			map[string]any{"op": "test", "path": "/doc/parents", "schema": map[string]any{"type": "array", "maxItems": 0}}}}
	}
	hrefs := make([]any, len(list))
	var all []any
	for i, h := range list {
		hrefs[i] = h
		all = append(all, map[string]any{"contains": map[string]any{
			"type": "object", "required": []any{"href"},
			"properties": map[string]any{"href": map[string]any{"const": h}}}})
	}
	sch := map[string]any{
		"type": "array", "minItems": len(list), "maxItems": len(list),
		"items": map[string]any{"type": "object", "required": []any{"href"},
			"properties": map[string]any{"href": map[string]any{"enum": hrefs}}},
	}
	if len(all) > 0 {
		sch["allOf"] = all
	}
	return map[string]any{"op": "test", "path": "/doc/parents", "schema": sch}
}

// planContent decides content verbs (read, append, create, …) on an item
// from the caller's roles at its placement, collected only through
// subjects the catalog's key in the content namespace may grant through
// (who.through: its sub and groups scopes, §B.11.2, §B.11.4); restore is
// planRestore's. The roles, their definitions and
// the catalog's key are those as of the checkpoint the decision reports
// (configAt), as for visibility.
func (s *Service) planContent(ctx context.Context, v *grant.Verified, item string, want []string) (_ *plan, err error) {
	for _, w := range want {
		if !grant.IsVerb(w) {
			return nil, badInput("unknown verb %q", w)
		}
	}
	cat := s.t.Catalog()
	ns, name, ok := tree.ParseHref(item)
	if !ok {
		return nil, badInput("item must be /r/{ns}/{name}")
	}
	if ns == cat {
		return nil, badInput("catalog documents are organised with place, move and delete")
	}
	create := contains(want, "create")
	if create && len(want) != 1 {
		return nil, badInput("create can't be combined with other verbs")
	}
	if contains(want, "restore") {
		if len(want) != 1 {
			return nil, badInput("restore can't be combined with other verbs")
		}
		return s.planRestore(ctx, v, ns, name, item)
	}
	latest, err := s.t.Checker().Config(ctx, ns)
	if err != nil {
		return nil, configErr(ns, err)
	}
	signer := findKey(latest.Keys, s.opt.Kid)
	if signer == nil {
		return nil, forbidden("namespace %s does not list the catalog's key %q", ns, s.opt.Kid)
	}
	pl := ns + "." + name
	var (
		cfg             *grantcheck.Config
		key             *grant.Key
		trusted, placed bool
		state, itemSt   int
		roles           map[string]bool
		cp              string
		checkpoint      map[string]string
	)
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		checkpoint = checkpointAt(g, cur, ns)
		cfg = s.configAt(g, ns, latest)
		if key = findKey(cfg.Keys, s.opt.Kid); key == nil {
			return
		}
		trusted = g.Trust[ns]
		if n := g.Node(pl); n != nil && !n.Self {
			placed, state, itemSt = true, n.State, n.ItemState
		}
		// Roles count only through subjects the catalog's key in the
		// content namespace may grant through: its sub and groups scopes
		// (§B.11.2 Through the key, §B.11.4 Resolve).
		roles = s.rolesFor(pl, callerOf(v).through(key))
	})
	switch {
	case key == nil:
		return nil, forbidden("namespace %s does not list the catalog's key %q", ns, s.opt.Kid)
	case !trusted:
		return nil, forbidden("namespace %s is not trusted by catalog %s", ns, cat)
	case !placed:
		return nil, forbidden("%s is not placed in catalog %s", item, cat)
	case create:
		// A create grant can only ever produce the genesis: refuse names that
		// exist or existed (§B.11.4).
		if itemSt != tree.ItemUnknown {
			return nil, conflict("%s exists or existed", item)
		}
		h, err := s.t.Client().Head(ctx, ns, name)
		if err != nil {
			return nil, upstream(err)
		}
		if h.State != client.NotFound {
			// The core is ahead of the checkpoint (decidedAt).
			checkpoint = nil
			return nil, conflict("%s exists or existed", item)
		}
	case state != tree.StateLive:
		// A dangling placement grants nothing (§B.11.2).
		return nil, forbidden("the placement of %s is dangling", item)
	}
	var kept, can []string
	for r := range roles {
		def, ok := cfg.Roles[r]
		if !ok || !roleAllowed(key, r) {
			continue
		}
		for _, c := range def.Can {
			if contains(want, c) {
				kept = append(kept, r)
				break
			}
		}
	}
	for _, w := range want {
		if !key.IsStar() && !contains(key.Can, w) {
			continue
		}
		for _, r := range kept {
			if contains(cfg.Roles[r].Can, w) {
				can = append(can, w)
				break
			}
		}
	}
	if len(can) == 0 {
		return nil, forbidden("no role of yours allows %s on %s", strings.Join(want, ", "), item)
	}
	var final []string
	for _, r := range kept {
		for _, c := range can {
			if contains(cfg.Roles[r].Can, c) {
				final = append(final, r)
				break
			}
		}
	}
	sort.Strings(final)
	return &plan{ns: ns, resource: name, can: can, roles: final, rules: []any{resourceRule(name)}, cp: cp, checkpoint: checkpoint, key: signer}, nil
}

// planRestore decides a restore (§B.11.4): it brings back a deleted item
// where it is placed, for the roles its placement had when the tombstone
// was seen (§B.11.7), collected through subjects the catalog's key may
// assert. The frozen rows stay those of the deletion even if the item was
// unplaced and placed again, but the item must still have a placement in
// this catalog. The grant can only restore: if the item is live by the
// time it is used, the write is an append and the core refuses it.
//
// The answers come in this order, so they reveal nothing to callers
// without read beyond what names and purges already do (§E.4):
//
//   - 404 for a name that never existed, 410 for a purged item: any name
//     of a namespace the service holds as purged, which is 410 at the
//     core too, even one it never saw, as when it started after the purge
//     (tree.ItemState, §8.5);
//   - 403 for a caller without a role granting read on the item (in its
//     frozen rows if deleted, its current ones if live), without a role
//     granting restore, whose item has no placement, or whose restore
//     would widen: the roles the item would have after it, from its
//     current placement, exceed its frozen rows for some subject, judged
//     with includes as for moves (§B.11.7). Such an item is restored by
//     a catalog admin, who skips that check as for moves;
//   - then 409 for a live item.
//
// Each refusal carries the checkpoint it holds at (decidedAt). The item's
// state is read from the database, which changes with the checkpoint
// under the graph lock, so what is read held at some checkpoint between
// the ones before and after the read: a name the service has seen is
// never unknown again, so 404 holds at the one before, and a purge is
// permanent, so 410 holds at the one after.
func (s *Service) planRestore(ctx context.Context, v *grant.Verified, ns, name, item string) (_ *plan, err error) {
	cat := s.t.Catalog()
	pl := ns + "." + name
	trusted := false
	var cp string
	var checkpoint map[string]string
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		trusted = g.Trust[ns]
		checkpoint = checkpointAt(g, cur, ns)
	})
	if !trusted {
		// The service follows only trusted namespaces: it knows nothing of
		// this one's items.
		return nil, forbidden("namespace %s is not trusted by catalog %s", ns, cat)
	}
	itemSt, _, err := s.t.ItemState(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	switch itemSt {
	case tree.ItemUnknown:
		return nil, errf(404, "not_found", "%s has never existed", item)
	case tree.ItemPurged:
		s.t.View(func(g *tree.Graph, cur map[string]string) { checkpoint = checkpointAt(g, cur, ns) })
		return nil, errf(410, "gone", "%s was purged: there is nothing to restore", item)
	}
	latest, err := s.t.Checker().Config(ctx, ns)
	if err != nil {
		return nil, configErr(ns, err)
	}
	signer := findKey(latest.Keys, s.opt.Kid)
	if signer == nil {
		// Decided at the head, as in planContent (decidedAt).
		checkpoint = nil
		return nil, forbidden("namespace %s does not list the catalog's key %q", ns, s.opt.Kid)
	}
	admin := s.isAdmin(v)
	var (
		cfg         *grantcheck.Config
		key         *grant.Key
		placed      bool
		roles       map[string]bool
		wSubj, wRol string
		widens      bool
	)
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		checkpoint = checkpointAt(g, cur, ns)
		cfg = s.configAt(g, ns, latest)
		if key = findKey(cfg.Keys, s.opt.Kid); key == nil {
			return
		}
		subs := callerOf(v).through(key)
		incs := map[string]Includes{ns: ParseIncludes(cfg.Doc)}
		n := g.Node(pl)
		placed = n != nil && !n.Self
		if placed {
			itemSt = n.ItemState
		}
		if itemSt == tree.ItemLive {
			roles = s.rolesFor(pl, subs)
			return
		}
		roles = s.frozenRolesFor(pl, subs)
		if !placed || admin {
			return
		}
		wSubj, wRol, widens = widening(pl, Effective(g, pl, nil), s.frozen[pl], incs)
	})
	if key == nil {
		return nil, forbidden("namespace %s does not list the catalog's key %q", ns, s.opt.Kid)
	}
	if itemSt == tree.ItemPurged {
		return nil, errf(410, "gone", "%s was purged: there is nothing to restore", item)
	}
	// Roles the content namespace defines with a verb, within the key's
	// roles scope.
	with := func(verb string) []string {
		var out []string
		for r := range roles {
			if def, ok := cfg.Roles[r]; ok && roleAllowed(key, r) && contains(def.Can, verb) {
				out = append(out, r)
			}
		}
		sort.Strings(out)
		return out
	}
	kept := with("restore")
	switch {
	case len(with("read")) == 0:
		return nil, forbidden("no role of yours allows read on %s", item)
	case len(kept) == 0 || !key.IsStar() && !contains(key.Can, "restore"):
		return nil, forbidden("no role of yours allows restore on %s", item)
	case !placed:
		return nil, forbidden("%s is not placed in catalog %s", item, cat)
	case widens:
		return nil, forbidden("restoring %s would give %s the role %s, which it didn't have when the item was deleted; a catalog admin can restore it", item, wSubj, wRol)
	case itemSt == tree.ItemLive:
		return nil, conflict("%s is not deleted", item)
	}
	return &plan{ns: ns, resource: name, can: []string{"restore"}, roles: kept, rules: []any{resourceRule(name)}, cp: cp, checkpoint: checkpoint, key: signer}, nil
}

// folders resolves a request's to list to distinct node names (400 for a
// malformed entry, or for a request without to). An empty list asks for
// a root, which only catalog admins may (organising.nonEmpty); whether
// each entry is a live folder is the decision's (organising.targets).
func (s *Service) folders(req Request) ([]string, error) {
	if !req.HasTo {
		return nil, badInput("to is required: the folders to place the node in, or [] for a root")
	}
	out := []string{}
	for _, f := range req.To {
		name, ok := tree.Resolve(s.t.Catalog(), f)
		if !ok {
			return nil, badInput("malformed folder %q", f)
		}
		if !contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

func liveFolder(g *tree.Graph, name string) bool {
	n := g.Node(name)
	return n != nil && n.Kind == tree.KindFolder && !n.Cyclic
}

// parentLabel names a parents entry in a refusal: its node name, or its
// href if that isn't a live link to a node of the catalog.
func parentLabel(p tree.Parent) string {
	if p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("%q", p.Href)
}

// powers decides one caller's tree powers (move, place, §B.11.1) at the
// checkpoint g reflects (§B.11.2 Tree powers):
//
//   - they count only at a live folder that isn't cyclic, and only through
//     the caller's subjects the catalog's key in the catalog may grant
//     through (who.through: its sub and groups scopes);
//   - at a folder with $access, a subject's roles have them where they are
//     assigned there, and with inheritPowers also where they are collected
//     on the walk up from it;
//   - at a folder without $access but with parents, a subject's role has
//     them when the same subject's role has them at every parents entry,
//     a tombstoned, purged, dangling (missing), cyclic or non-folder parent,
//     or an entry that isn't a live link to a node of the catalog, giving
//     none; a root without $access gives none.
//
// The walk through parents is recursive, bounded by tree.MaxDepth, and
// safe on cycles (cyclic nodes give nothing). Callers in the admin group
// need no tree power (§B.11.4) and don't ask. Use it under View.
type powers struct {
	g    *tree.Graph
	subs map[string]bool
	defs map[string]any // the catalog's roles, as of the checkpoint
	memo map[string]map[string]map[string]bool
}

// powersAt is the caller w's tree powers at the checkpoint g reflects, key
// the catalog's key in the catalog namespace there (keyAt; nil gives none).
func powersAt(g *tree.Graph, key *grant.Key, w who) *powers {
	defs, _ := g.Config["roles"].(map[string]any)
	return &powers{g: g, subs: w.through(key), defs: defs, memo: map[string]map[string]map[string]bool{}}
}

// has reports whether the caller holds power p at folder.
func (pw *powers) has(folder, p string) bool {
	for _, roles := range pw.rolesAt(folder, 0) {
		for r := range roles {
			if def, _ := pw.defs[r].(map[string]any); def[p] == true {
				return true
			}
		}
	}
	return false
}

// rolesAt is, per subject of the caller's, its roles that hold for tree
// powers at folder (powers).
func (pw *powers) rolesAt(folder string, depth int) map[string]map[string]bool {
	if m, ok := pw.memo[folder]; ok {
		return m
	}
	pw.memo[folder] = nil // a cycle back here gives nothing
	out := map[string]map[string]bool{}
	n := pw.g.Node(folder)
	switch {
	case n == nil || n.Self || n.Kind != tree.KindFolder || n.Cyclic || depth > tree.MaxDepth:
	case n.HasAccess:
		access := n.Access
		if n.InheritPowers {
			access = Effective(pw.g, folder, nil)
		}
		for subj, roles := range access {
			if pw.subs[subj] {
				for _, r := range roles {
					addRole(out, subj, r)
				}
			}
		}
	case len(n.Parents) > 0:
		// Per subject and role: held at every parents entry.
		for i, p := range n.Parents {
			if i >= len(n.EdgeStates) || n.EdgeStates[i] != tree.EdgeValid {
				out = map[string]map[string]bool{}
				break
			}
			at := pw.rolesAt(p.Name, depth+1)
			if i == 0 {
				for subj, roles := range at {
					for r := range roles {
						addRole(out, subj, r)
					}
				}
				continue
			}
			for subj, roles := range out {
				for r := range roles {
					if !at[subj][r] {
						delete(roles, r)
					}
				}
				if len(roles) == 0 {
					delete(out, subj)
				}
			}
		}
	}
	pw.memo[folder] = out
	return out
}

func addRole(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

// organising is what the organising decisions share (§B.11.4), made
// under View at one checkpoint: whether the caller is in catalog-admins,
// its view of the catalog, and the namespaces the decision read, which
// its checkpoint names beside the catalog and the named item's
// namespace (checkpointAt).
//
// The answers come in the order §B.11.4 gives them: 400 for a malformed
// request, before any of these; 404 for a node that isn't an
// untombstoned node of the catalog, a to entry that isn't a live folder
// of it, or, to a caller not in catalog-admins, either one hidden from it
// (§B.11.5), a new folder's name excepted (node, targets); 403 for a
// requirement that fails; then 409, and Place's 410. A hidden node is so
// answered as a missing one, with the same message and checkpoint, except
// to admins organising and where the answer is 409 (names are not
// secrets); no refusal names a hidden node (planMove's widening).
type organising struct {
	g     *tree.Graph
	admin bool
	vis   *visibility // nil for an admin
	read  map[string]bool
}

// organisingAt is the caller v's organising view at the checkpoint g
// reflects: for a caller not in catalog-admins, that of the subject set
// its listings are keyed by (keyedAt), as §B.11.5 judges visibility.
// Call it under View.
func (s *Service) organisingAt(g *tree.Graph, v *grant.Verified, admin bool) *organising {
	o := &organising{g: g, admin: admin, read: map[string]bool{}}
	if !admin {
		w, groups := whoOf(s.keyedAt(g, v))
		o.vis = &visibility{s: s, who: w, groups: groups}
	}
	return o
}

// checkpoint is the checkpoint the decision reports (§B.11.4): the
// catalog's, nss' (the namespace of the item the request names) and
// those of the namespaces it read.
func (o *organising) checkpoint(cur map[string]string, nss ...string) map[string]string {
	for ns := range o.read {
		nss = append(nss, ns)
	}
	return checkpointAt(o.g, cur, nss...)
}

// readTrusted notes that the decision read every trusted content
// namespace's document: roles to judge a folder's visibility, includes
// to judge no widening (§B.11.4 checkpoint).
func (o *organising) readTrusted() {
	for ns := range o.g.Trust {
		o.read[ns] = true
	}
}

// offered refuses organising requests in an end-to-end catalog, whose
// writes fail rules on /doc (§6.2, §B.11.4): 404 not_offered, as of the
// checkpoint.
func (o *organising) offered() error {
	if derived.InfoOf(o.g.Config).Level == derived.LevelE2E {
		return notOffered(o.g.Catalog)
	}
	return nil
}

func notOffered(cat string) error {
	return errf(404, "not_offered", "%s is an end-to-end catalog: the catalog service issues no organising grants for it", cat)
}

// sees reports whether the caller sees node n as organising requests
// judge it (visibility.Organising): an admin sees every node. A folder's
// visibility reads every trusted namespace's roles, a placement's its
// item's namespace's.
func (o *organising) sees(n *tree.Node) bool {
	if o.admin {
		return true
	}
	if n.Kind == tree.KindFolder {
		o.readTrusted()
	} else if o.g.Trust[n.ItemNS] {
		o.read[n.ItemNS] = true
	}
	return o.vis.Organising(o.g, n)
}

// node is the node name a request names: 404 unless it is an
// untombstoned node of the catalog, an explicit one, that the caller
// sees. A tombstoned folder is answered so too: folders are restored only
// by catalog admins, under grants of their own (§B.11.4).
//
// A hidden node is answered as a missing one, checkpoint included
// (§B.11, §B.11.5): for a caller not in catalog-admins, a folder's name
// reads every trusted namespace whether or not a folder has it, as a
// placement's name reads its item's namespace (itemNS).
func (o *organising) node(name string) (*tree.Node, error) {
	if !o.admin && folderName(name) {
		o.readTrusted()
	}
	n := o.g.Node(name)
	if n == nil || n.Self || !o.sees(n) {
		return nil, errf(404, "not_found", "no node %s in %s", name, o.g.Catalog)
	}
	return n, nil
}

// targets checks a request's to list: 404 for an entry that isn't a live
// folder of the catalog, or that the caller doesn't see. For a caller not
// in catalog-admins, any to reads every trusted namespace, so the 404 for
// a hidden folder carries the checkpoint one for any other entry does
// (node).
func (o *organising) targets(tos []string) error {
	if !o.admin && len(tos) > 0 {
		o.readTrusted()
	}
	for _, f := range tos {
		if !liveFolder(o.g, f) || !o.sees(o.g.Node(f)) {
			return errf(404, "not_found", "no folder %s in %s", f, o.g.Catalog)
		}
	}
	return nil
}

// nonEmpty refuses an empty to, a root, to a caller not in
// catalog-admins (403, §B.11.4).
func (o *organising) nonEmpty(tos []string) error {
	if !o.admin && len(tos) == 0 {
		return forbidden("only catalog admins may make a root: to must name a folder")
	}
	return nil
}

// leaves refuses a caller not in catalog-admins a move, unplace or delete
// of n where n has no parents (a root), or a parent hidden from it, which
// its grant would name (403, §B.11.4). The refusal names no hidden
// parent; a parents entry naming no node is no node to hide, and gives
// no power (powers).
func (o *organising) leaves(n *tree.Node, verb string) error {
	if o.admin {
		return nil
	}
	if len(n.Parents) == 0 {
		return forbidden("only catalog admins may %s a root node such as %s", verb, n.Name)
	}
	for _, p := range n.Parents {
		if pn := o.g.Node(p.Name); p.Name != "" && pn != nil && !o.sees(pn) {
			return forbidden("you may not %s %s: a parent of it is hidden from you", verb, n.Name)
		}
	}
	return nil
}

// planCreateFolder decides creating a folder (§B.11.4): a role with move
// on every folder in to, unless the caller is an admin, who may also
// give to: [] for a root folder. Items in it get their parents' roles
// through the walk-up, and until an admin gives it $access (the grant
// refuses a document with $access unless the caller is an admin), each
// subject's role has the powers there that it has at all its parents
// (powers). The new name is exempt from the 404s (organising), and is
// 409, after the 403s, where it is taken, hidden or not (names are not
// secrets): a node has it, or a parents entry or an accepted $parents
// names it (Graph.DeclaredChildren), which the checkpoint decides, since
// creating it would re-attach that dangling edge and widen access below
// it (scenario 41); or a node had it, which the core's head decides.
func (s *Service) planCreateFolder(ctx context.Context, v *grant.Verified, node string, req Request) (_ *plan, err error) {
	cat := s.t.Catalog()
	name, ok := tree.Resolve(cat, node)
	if !ok || strings.Contains(name, ".") || !client.ValidResourceName(name) {
		return nil, badInput("a folder name is a resource name without a dot")
	}
	tos, err := s.folders(req)
	if err != nil {
		return nil, err
	}
	latest, err := s.catalogConfig(ctx)
	if err != nil {
		return nil, err
	}
	admin := s.isAdmin(v)
	var cp string
	var checkpoint map[string]string
	var taken bool
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		o := s.organisingAt(g, v, admin)
		defer func() { checkpoint = o.checkpoint(cur) }()
		taken = g.Node(name) != nil || len(g.DeclaredChildren(name)) > 0
		if err = o.offered(); err != nil {
			return
		}
		if err = o.targets(tos); err != nil {
			return
		}
		key := s.keyAt(g, cat, latest)
		switch {
		case key == nil:
			err = s.noCatalogKey()
			return
		case !key.IsStar() && !contains(key.Can, "create"):
			err = forbidden("the catalog's key may not create in %s", cat)
			return
		}
		if err = o.nonEmpty(tos); err != nil {
			return
		}
		pw := powersAt(g, key, callerOf(v))
		for _, f := range tos {
			if !admin && !pw.has(f, "move") {
				err = forbidden("no role of yours with move is assigned on %s", f)
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	signer, err := s.signer(latest, &checkpoint)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, conflict("%s is taken in %s: a node has it, or a parents entry names it", name, cat)
	}
	h, herr := s.t.Client().Head(ctx, cat, name)
	if herr != nil {
		return nil, upstream(herr)
	}
	if h.State != client.NotFound {
		// The core is ahead of the checkpoint, or a node had the name,
		// which the service doesn't keep (decidedAt).
		checkpoint = nil
		return nil, conflict("%s exists or existed in %s", name, cat)
	}
	rules := []any{resourceRule(name), parentsRule(cat, tos)}
	if !admin {
		rules = append(rules, map[string]any{"op": "test", "path": "/doc/$access", "exists": false})
	}
	return &plan{ns: cat, resource: name, can: []string{"create"}, rules: rules, cp: cp, checkpoint: checkpoint, key: signer}, nil
}

// isAdmin reports whether the caller is in the admin group: its grant's
// groups list it, as the catalog's rule tests /principal/groups (§B.11.3).
// A group written "group:catalog-admins" is another group (groupSubjects).
func (s *Service) isAdmin(v *grant.Verified) bool {
	return contains(v.Principal.Groups, s.opt.AdminGroup)
}

// catalogConfig is the catalog namespace's document at the head, whose
// entry for the catalog's key signs organising grants (signer). An end-
// to-end catalog gets none (404 not_offered, §B.11.4), as of its head
// too: levels only rise (Addendum E, Levels).
func (s *Service) catalogConfig(ctx context.Context) (*grantcheck.Config, error) {
	cfg, err := s.t.Checker().Config(ctx, s.t.Catalog())
	if err != nil {
		return nil, configErr(s.t.Catalog(), err)
	}
	if derived.InfoOf(cfg.Doc).Level == derived.LevelE2E {
		return nil, notOffered(s.t.Catalog())
	}
	return cfg, nil
}

// signer is the catalog's key in latest, the catalog's document at the
// head, which signs a plan (plan.key). A head without it is a 403
// decided at the head, not at the checkpoint, so it clears the
// checkpoint (decidedAt); it comes after the decision's own 404s and
// 403s.
func (s *Service) signer(latest *grantcheck.Config, checkpoint *map[string]string) (*grant.Key, error) {
	key := findKey(latest.Keys, s.opt.Kid)
	if key == nil {
		*checkpoint = nil
		return nil, s.noCatalogKey()
	}
	return key, nil
}

func (s *Service) noCatalogKey() error {
	return forbidden("the catalog namespace does not list the catalog's key %q", s.opt.Kid)
}

// keyAt is the catalog's key in ns as of the checkpoint g reflects
// (configAt), which decides; nil if ns doesn't list it there. Call it
// under View.
func (s *Service) keyAt(g *tree.Graph, ns string, latest *grantcheck.Config) *grant.Key {
	return findKey(s.configAt(g, ns, latest).Keys, s.opt.Kid)
}

// planPlace decides a placement (§B.11.4): the caller is in the content
// namespace's catalogs.{catalog}.place list, and has a role with place
// assigned on every target folder, unless it is an admin, who may also
// give to: [] for a root. Re-placing a deleted placement (a restore) must
// also not widen, unless the caller is an admin: the item's roles from
// its placement after the write, under to, are compared with the deleted
// placement's rows (§B.11.4 No widening, §B.11.7).
//
// The answers, in order (organising): 400; 404 for a to entry that isn't
// a live folder, or is hidden from a non-admin; 403 for the place list,
// the powers, an empty to from a non-admin, an item namespace the catalog
// doesn't trust, or a re-place that widens; then 409 for an item whose
// placement is live, hidden or not (names are not secrets), and 410 for
// one whose placement was purged. The core's head is the service's only
// record of a purged placement (the graph keeps it apart from a deleted
// one only as gone), so that 410 carries no checkpoint (decidedAt).
//
// The catalog only issues the grant; the client writes the placement
// document. Clients should give every placement (create or restore) a
// fresh random $nonce (§C.7, §B.11.4), so its revision ids can't be used to
// confirm guesses of its content; the grant's rules fix only /resource and
// /doc/parents, and refuse a non-admin's $access, so a $nonce is always
// allowed.
func (s *Service) planPlace(ctx context.Context, v *grant.Verified, item string, req Request) (_ *plan, err error) {
	cat := s.t.Catalog()
	ns, name, ok := tree.ParseHref(item)
	if !ok || ns == cat {
		return nil, badInput("item must be /r/{ns}/{name} of a content namespace")
	}
	pl := ns + "." + name
	if !client.ValidResourceName(pl) {
		return nil, badInput("the placement name %s is not a valid resource name", pl)
	}
	tos, err := s.folders(req)
	if err != nil {
		return nil, err
	}
	latest, err := s.catalogConfig(ctx)
	if err != nil {
		return nil, err
	}
	// The content namespace's document at the head stands in for the one
	// at the checkpoint where the graph has none (configAt); a failure
	// to read it matters only once the namespace is trusted.
	ccfg, cerr := s.t.Checker().Config(ctx, ns)
	subs := Subjects(v)
	admin := s.isAdmin(v)
	var (
		key           *grant.Key
		cp            string
		checkpoint    map[string]string
		wSubj, wRole  string
		widens, seenD bool
		placed, noCfg bool
	)
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		o := s.organisingAt(g, v, admin)
		defer func() { checkpoint = o.checkpoint(cur, ns) }()
		if err = o.offered(); err != nil {
			return
		}
		if err = o.targets(tos); err != nil {
			return
		}
		if key = s.keyAt(g, cat, latest); key == nil {
			err = s.noCatalogKey()
			return
		}
		if err = o.nonEmpty(tos); err != nil {
			return
		}
		if !g.Trust[ns] {
			err = forbidden("namespace %s is not trusted by catalog %s", ns, cat)
			return
		}
		// The place list, and includes, as of the checkpoint (configAt).
		var ccur *grantcheck.Config
		if cerr == nil {
			ccur = s.configAt(g, ns, ccfg)
		} else if c := g.Content[ns]; c != nil {
			ccur = s.parsed(c).cfg
		}
		if ccur == nil {
			noCfg = true
			return
		}
		if !inPlaceList(ccur.Doc, cat, subs) {
			err = forbidden("namespace %s does not let you place its items in %s (catalogs.%s.place)", ns, cat, cat)
			return
		}
		pw := powersAt(g, key, callerOf(v))
		for _, f := range tos {
			if !admin && !pw.has(f, "place") {
				err = forbidden("no role of yours with place is assigned on %s", f)
				return
			}
		}
		if n := g.Node(pl); n != nil && !n.Self {
			placed = true
			return
		}
		if !admin {
			// Judged here, at the checkpoint, for a re-place below: the
			// rows the placement had when it was deleted, against the
			// roles it would have under to, with no $access (§B.11.3).
			var kept map[string][]string
			kept, seenD = s.unplacedRows(pl)
			incs := map[string]Includes{ns: ParseIncludes(ccur.Doc)}
			wSubj, wRole, widens = widening(pl, rolesUnder(g, tos), kept, incs)
		}
	})
	if noCfg {
		// Not decided at the checkpoint (decidedAt).
		checkpoint = nil
		return nil, configErr(ns, cerr)
	}
	if err != nil {
		return nil, err
	}
	signer, err := s.signer(latest, &checkpoint)
	if err != nil {
		return nil, err
	}
	if placed {
		return nil, conflict("%s is already placed in %s; move it instead", item, cat)
	}
	verb := "create"
	h, herr := s.t.Client().Head(ctx, cat, pl)
	// The answers below are decided from the core's head of the placement,
	// which may be ahead of the checkpoint (decidedAt); the service's own
	// view of it is the 409 above.
	ahead := func(err error) error { checkpoint = nil; return err }
	switch {
	case herr != nil:
		return nil, upstream(herr)
	case h.State == client.Live:
		return nil, ahead(conflict("%s is already placed in %s; move it instead", item, cat))
	case h.State == client.Purged:
		return nil, ahead(errf(410, "gone", "the placement %s was purged", pl))
	case h.State == client.Tombstoned && widens && !seenD:
		// The service holds no rows of the placement's deletion (it never
		// saw it, or it is from before deleted placements' rows were
		// kept): compared with none, and not decided at the checkpoint.
		return nil, ahead(forbidden("re-placing %s would give %s the role %s, and the catalog keeps no rows of its deleted placement to compare with; a catalog admin can place it", item, wSubj, wRole))
	case h.State == client.Tombstoned && widens:
		// A re-place that widens the deleted placement's rows (§B.11.4
		// No widening, §B.11.7).
		return nil, forbidden("re-placing %s would give %s the role %s, which it didn't have when its placement was deleted; a catalog admin can place it", item, wSubj, wRole)
	case h.State == client.Tombstoned:
		// Re-placing restores the old placement (§B.11.4): the grant carries
		// only restore, never create or append, and the client restores
		// with a root replace. What stops a restore-only grant from acting
		// as a move is the core's gate (§6.2 v0.21 candidate verbs): if the
		// placement is live again by the time the grant is used, the PATCH
		// settles as an append, which isn't a candidate verb, and is refused
		// at step 2 before the If-Match comparison, so nothing about the
		// live document is checked or revealed. On a still-deleted
		// placement the restore sees the last live document at step 3, as
		// any restore does.
		if !key.IsStar() && !contains(key.Can, "restore") {
			return nil, ahead(conflict("the placement %s was deleted and the catalog's key may not restore it", pl))
		}
		verb = "restore"
	}
	rules := []any{resourceRule(pl), parentsRule(cat, tos)}
	if !admin {
		// Only an admin creates or restores a placement with $access
		// (§B.11.3), as Create a folder's grant says too.
		rules = append(rules, map[string]any{"op": "test", "path": "/doc/$access", "exists": false})
	}
	return &plan{ns: cat, resource: pl, can: []string{verb}, rules: rules, cp: cp, checkpoint: checkpoint, key: signer}, nil
}

func inPlaceList(doc map[string]any, cat string, subs map[string]bool) bool {
	cs, _ := doc["catalogs"].(map[string]any)
	c, _ := cs[cat].(map[string]any)
	list, _ := c["place"].([]any)
	for _, x := range list {
		if s, ok := x.(string); ok && subs[s] {
			return true
		}
	}
	return false
}

// planMove decides a move (§B.11.4): a role with move on every current
// parent the node leaves and on every target folder, and no widening of
// anyone's roles in the moved subtree, unless the caller is a catalog
// admin, who needs neither and may give to: [] for a root. A parents
// entry left that gives no power, a broken one included (powers), is
// refused, and so is a to entry that is the node or below it, for
// admins too.
//
// The answers, in order (organising): 400; 404 for a node that isn't an
// untombstoned node of the catalog, a to entry that isn't a live folder,
// or either one hidden from a non-admin; 403 for the requirements, a
// non-admin's empty to, root or hidden parent (organising.leaves)
// included.
//
// A Move grant may also change the node's other members, $access
// excepted, which the catalog's key's rules refuse (§B.11.3) and, unless
// the caller is an admin, the grant's own rules too: a rename is a move
// to the node's current parents. Unless the caller is an admin,
// its patch set must begin with a test of /parents against the node's
// parents as decided, which the answer gives as parents (a rule on
// /patches/0), so it moves the node only from where it was judged: a
// stale test fails at step 3, a missing or different one the rule. The
// answer gives the node's head as decided too, and the grant expires
// within the catalog's maxLag of the decision (§B.11.8).
func (s *Service) planMove(ctx context.Context, v *grant.Verified, node string, req Request) (_ *plan, err error) {
	cat := s.t.Catalog()
	name, ok := tree.Resolve(cat, node)
	if !ok {
		return nil, badInput("malformed node")
	}
	tos, err := s.folders(req)
	if err != nil {
		return nil, err
	}
	latest, err := s.catalogConfig(ctx)
	if err != nil {
		return nil, err
	}
	admin := s.isAdmin(v)
	var incs map[string]Includes
	if !admin {
		if incs, err = s.includesOfTrusted(ctx); err != nil {
			return nil, err
		}
	}
	var (
		cp         string
		checkpoint map[string]string
		parents    any
		head       string
		expBy      time.Time
	)
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		o := s.organisingAt(g, v, admin)
		defer func() { checkpoint = o.checkpoint(cur, itemNS(name)...) }()
		if err = o.offered(); err != nil {
			return
		}
		var n *tree.Node
		if n, err = o.node(name); err != nil {
			return
		}
		if err = o.targets(tos); err != nil {
			return
		}
		key := s.keyAt(g, cat, latest)
		if key == nil {
			err = s.noCatalogKey()
			return
		}
		if err = o.nonEmpty(tos); err != nil {
			return
		}
		if err = o.leaves(n, "move"); err != nil {
			return
		}
		below := g.Descendants([]string{name})
		pw := powersAt(g, key, callerOf(v))
		for _, f := range tos {
			if below[f] {
				err = forbidden("%s can't move under %s, which is itself or below it", name, f)
				return
			}
			if !admin && !pw.has(f, "move") {
				err = forbidden("no role of yours with move is assigned on %s", f)
				return
			}
		}
		for _, p := range n.Parents {
			if admin || p.Name != "" && contains(tos, p.Name) {
				continue
			}
			if !pw.has(p.Name, "move") {
				err = forbidden("no role of yours with move is assigned on %s, which the node leaves", parentLabel(p))
				return
			}
		}
		if !admin {
			incs = s.includesAt(g, incs)
			o.readTrusted()
			if subj, at, role, bad := s.widens(g, name, tos, incs); bad {
				// Nothing about a node hidden from the caller appears, not
				// its name nor its roles (§B.11, §B.11.5): the refusal then
				// names only the moved node, which the caller sees (node).
				if an := g.Node(at); an == nil || !o.sees(an) {
					err = forbidden("the move would widen access below %s", name)
				} else {
					err = forbidden("the move would give %s the role %s on %s", subj, role, g.Href(at))
				}
				return
			}
			parents = n.RawParents()
		}
		head = n.Head
		// Decided now, at this checkpoint: the grant lives at most the
		// catalog's maxLag, as of the checkpoint, from here (§B.11.8, §7.4).
		expBy = s.now().Add(grant.EffectiveMaxLag(s.configAt(g, cat, latest).MaxLag, nil))
	})
	if err != nil {
		return nil, err
	}
	signer, err := s.signer(latest, &checkpoint)
	if err != nil {
		return nil, err
	}
	rules := []any{resourceRule(name), parentsRule(cat, tos)}
	if !admin {
		// $access excepted in the grant itself, as Create a folder's and
		// Place's are, not only by the catalog's key's rules (§B.11.3).
		rules = append(rules, map[string]any{"op": "test", "path": "/patches/0",
			"value": map[string]any{"op": "test", "path": "/parents", "value": parents}},
			map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/$access"}})
	}
	return &plan{ns: cat, resource: name, can: []string{"append"}, cp: cp, checkpoint: checkpoint, key: signer, rules: rules,
		parents: parents, head: head, expBy: expBy}, nil
}

// Includes is one content namespace's declared role inclusions (§B.11.4):
// role -> the roles it names in "includes".
type Includes map[string][]string

// ParseIncludes reads "includes" from a namespace document's roles. Other
// role fields are the core's business; a malformed includes counts as none.
func ParseIncludes(doc map[string]any) Includes {
	out := Includes{}
	roles, _ := doc["roles"].(map[string]any)
	for r, def := range roles {
		d, _ := def.(map[string]any)
		list, _ := d["includes"].([]any)
		for _, x := range list {
			if name, ok := x.(string); ok {
				out[r] = append(out[r], name)
			}
		}
	}
	return out
}

// closure is every role present given roles: the roles themselves and,
// transitively, every role they include. Cycles in includes are harmless:
// each role is visited once.
func (inc Includes) closure(roles []string) map[string]bool {
	out := map[string]bool{}
	stack := append([]string(nil), roles...)
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[r] {
			continue
		}
		out[r] = true
		stack = append(stack, inc[r]...)
	}
	return out
}

// includesOfTrusted reads the includes of every trusted content namespace.
// The declarations are trusted as written: changing /roles needs a * key
// in that namespace (§B.11.4, §C.1.1).
func (s *Service) includesOfTrusted(ctx context.Context) (map[string]Includes, error) {
	var trust []string
	s.t.View(func(g *tree.Graph, _ map[string]string) {
		for ns := range g.Trust {
			trust = append(trust, ns)
		}
	})
	out := map[string]Includes{}
	for _, ns := range trust {
		cfg, err := s.t.Checker().Config(ctx, ns)
		if client.IsPurged(err) {
			// A purged sealed namespace's document is 410 (§8.5): its
			// items are purged, and it declares no includes any more.
			out[ns] = ParseIncludes(nil)
			continue
		}
		if err != nil {
			return nil, upstream(err)
		}
		out[ns] = ParseIncludes(cfg.Doc)
	}
	return out, nil
}

// includesAt is the includes of every content namespace g trusts, as of
// the checkpoint it reflects (Graph.Content), so a decision reflects the
// checkpoint it reports; latest (includesOfTrusted) stands in where the
// graph has no document. Call it under View.
func (s *Service) includesAt(g *tree.Graph, latest map[string]Includes) map[string]Includes {
	out := map[string]Includes{}
	for ns := range g.Trust {
		if c := g.Content[ns]; c != nil {
			out[ns] = ParseIncludes(c.Doc)
		} else if inc, ok := latest[ns]; ok {
			out[ns] = inc
		}
	}
	return out
}

// present reports whether role r counts as present before at node d,
// given the roles before (§B.11.4: it, or a role that includes it, was
// present). Includes apply only to an item's roles, read from its own
// content namespace: for a placement {ns}.{name}, incs[ns]. A folder's
// roles compare by name (§B.11.4 No widening).
func present(d, r string, before []string, incs map[string]Includes) bool {
	if contains(before, r) {
		return true
	}
	if ns, _, ok := tree.SplitPlacement(d); ok {
		return incs[ns].closure(before)[r]
	}
	return false
}

// widening reports the first subject and role, in byte order, of after
// (roles per subject at node d after a write) that isn't present in
// before (§B.11.4 No widening, present).
func widening(d string, after, before map[string][]string, incs map[string]Includes) (subject, role string, bad bool) {
	subjects := make([]string, 0, len(after))
	for subj := range after {
		subjects = append(subjects, subj)
	}
	sort.Strings(subjects)
	for _, subj := range subjects {
		for _, r := range after[subj] {
			if !present(d, r, before[subj], incs) {
				return subj, r, true
			}
		}
	}
	return "", "", false
}

// rolesUnder is the roles a node without $access would have under the
// live folders tos (§B.11.2 Walk up): the union of theirs.
func rolesUnder(g *tree.Graph, tos []string) map[string][]string {
	acc := map[string]map[string]bool{}
	for _, f := range tos {
		for subj, roles := range Effective(g, f, nil) {
			for _, r := range roles {
				addRole(acc, subj, r)
			}
		}
	}
	out := map[string][]string{}
	for subj, m := range acc {
		for r := range m {
			out[subj] = append(out[subj], r)
		}
		sort.Strings(out[subj])
	}
	return out
}

// widens reports a subject, node and role that a move of name to tos
// would add to the effective roles of the moved subtree (§B.11.4). Roles
// are compared by name, with the content namespace's declared includes.
// Deleted items' placements are no exception (§B.11.7).
func (s *Service) widens(g *tree.Graph, name string, tos []string, incs map[string]Includes) (subject, node, role string, bad bool) {
	override := map[string][]string{name: tos}
	below := g.Descendants([]string{name})
	nodes := make([]string, 0, len(below))
	for d := range below {
		nodes = append(nodes, d)
	}
	sort.Strings(nodes)
	for _, d := range nodes {
		// Before is what the node has now, computed from the graph, for a
		// deleted item's placement too: its move is checked like any other,
		// against the roles the item would have now, not against its frozen
		// rows (§B.11.7). Who may restore it still doesn't change with a
		// move, and a restore that would widen is refused (planRestore).
		if subj, r, bad := widening(d, Effective(g, d, override), Effective(g, d, nil), incs); bad {
			return subj, d, r, true
		}
	}
	return "", "", "", false
}

// planUnplace decides deleting a node, a placement (unplace) or a folder
// (§B.11.4 Unplace or delete a folder): a role with move on every
// current parent, a broken one giving none (powers), unless the caller is
// a catalog admin. The answers, in order (organising): 400; 404 for a
// node that isn't an untombstoned node of the catalog, or is hidden from
// a non-admin, a tombstoned folder included; 403 for the powers, or a
// non-admin's root or hidden parent (organising.leaves). The grant fixes
// /doc/parents, the document being deleted, to exactly the parents
// checked, by href, so the node can't be moved first; the answer gives
// the node's head as decided.
func (s *Service) planUnplace(ctx context.Context, v *grant.Verified, node string) (_ *plan, err error) {
	cat := s.t.Catalog()
	name, ok := tree.Resolve(cat, node)
	if !ok {
		return nil, badInput("malformed node")
	}
	latest, err := s.catalogConfig(ctx)
	if err != nil {
		return nil, err
	}
	admin := s.isAdmin(v)
	var (
		cp         string
		checkpoint map[string]string
		hrefs      []string
		head       string
	)
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		o := s.organisingAt(g, v, admin)
		defer func() { checkpoint = o.checkpoint(cur, itemNS(name)...) }()
		if err = o.offered(); err != nil {
			return
		}
		var n *tree.Node
		if n, err = o.node(name); err != nil {
			return
		}
		key := s.keyAt(g, cat, latest)
		if key == nil {
			err = s.noCatalogKey()
			return
		}
		if err = o.leaves(n, "delete"); err != nil {
			return
		}
		pw := powersAt(g, key, callerOf(v))
		for _, p := range n.Parents {
			hrefs = append(hrefs, p.Href)
			if !admin && !pw.has(p.Name, "move") {
				err = forbidden("no role of yours with move is assigned on %s", parentLabel(p))
				return
			}
		}
		head = n.Head
	})
	if err != nil {
		return nil, err
	}
	signer, err := s.signer(latest, &checkpoint)
	if err != nil {
		return nil, err
	}
	return &plan{ns: cat, resource: name, can: []string{"delete"}, rules: []any{resourceRule(name), parentHrefsRule(hrefs)},
		cp: cp, checkpoint: checkpoint, key: signer, head: head}, nil
}

// planRestoreNode answers a request to restore a catalog node, as
// { node, want: ["restore"] } or { item: "/r/{catalog}/{name}", want:
// ["restore"] }: the service restores no catalog node. Folders are
// restored only by catalog admins under grants of their own, and a
// deleted placement by a Place, whose grant restores it (§B.11.4). So a
// node that isn't an untombstoned node of the catalog, or that is hidden
// from a non-admin, is 404, as in every organising request, and any
// other 409, as Restore answers a live item.
func (s *Service) planRestoreNode(ctx context.Context, v *grant.Verified, node string) (_ *plan, err error) {
	cat := s.t.Catalog()
	name, ok := tree.Resolve(cat, node)
	if !ok {
		return nil, badInput("malformed node")
	}
	if _, err := s.catalogConfig(ctx); err != nil {
		return nil, err
	}
	admin := s.isAdmin(v)
	var checkpoint map[string]string
	defer func() { err = decidedAt(err, checkpoint) }()
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		o := s.organisingAt(g, v, admin)
		defer func() { checkpoint = o.checkpoint(cur, itemNS(name)...) }()
		if err = o.offered(); err != nil {
			return
		}
		if _, err = o.node(name); err == nil {
			err = conflict("%s is not deleted", name)
		}
	})
	return nil, err
}

// checkLag refuses to issue from a checkpoint older than the catalog's
// maxLag (or the key's), since the core would reject the grant's at
// anyway (§B.11.8, §C.4 requireAt).
func (s *Service) checkLag(ctx context.Context, cp string, key *grant.Key) error {
	cat := s.t.Catalog()
	if cp == "" {
		return errf(503, "behind", "the catalog service has not reached the catalog yet")
	}
	if key.RequireAt == nil {
		return nil // the core doesn't check at for this key
	}
	h, err := s.t.Client().NSHead(ctx, cat)
	if err != nil {
		return upstream(err)
	}
	if h.ID == cp {
		return nil
	}
	var nsLag *time.Duration
	if cfg, err := s.t.Checker().Config(ctx, cat); err == nil {
		nsLag = cfg.MaxLag
	}
	limit := grant.EffectiveMaxLag(nsLag, key.MaxLag) // default 60 s (§C.4)
	entries, err := s.t.Client().NSLog(ctx, cat, h.ID, cp)
	if err != nil || len(entries) == 0 {
		return errf(503, "behind", "the catalog service's checkpoint is not in the catalog's chain")
	}
	t, err := time.Parse(time.RFC3339Nano, entries[0].Created)
	if err == nil && s.now().Sub(t) > limit {
		return errf(503, "behind", "the catalog service lags the catalog by more than maxLag")
	}
	return nil
}

// mint signs a plan as a root grant for the caller (§B.11.4).
func (s *Service) mint(ctx context.Context, v *grant.Verified, p *plan, lagOK map[string]bool) (*Issued, error) {
	if !lagOK[p.cp] {
		if err := s.checkLag(ctx, p.cp, p.key); err != nil {
			return nil, err
		}
		lagOK[p.cp] = true
	}
	now := s.now()
	ttl := s.opt.TTL
	if p.key.MaxTTL != nil && *p.key.MaxTTL < ttl {
		ttl = *p.key.MaxTTL
	}
	exp := now.Add(ttl).UTC().Truncate(time.Second)
	// Never outlive the caller's own grant.
	for _, b := range v.Grant.Blocks {
		if b.Exp != nil && b.Exp.Before(exp) {
			exp = b.Exp.UTC()
		}
	}
	if !exp.After(now) {
		return nil, forbidden("the caller's grant expires too soon")
	}
	// A Move grant expires within the catalog's maxLag of its decision,
	// which bounds how long an overtaken decision can be used (§B.11.8).
	if !p.expBy.IsZero() && p.expBy.Before(exp) {
		if exp = p.expBy.UTC(); !exp.After(now) {
			return nil, forbidden("the grant would expire, within the catalog's maxLag of its decision, before it is issued")
		}
	}
	var groups []any
	for _, g := range v.Principal.Groups {
		if ok, _ := p.key.Groups.Permits([]string{g}); ok {
			groups = append(groups, g)
		}
	}
	at := map[string]any{"ns": s.t.Catalog(), "id": p.cp}
	root := map[string]any{
		"kid": s.opt.Kid, "sub": v.Principal.ID, "ns": []any{p.ns}, "can": toAny(p.can),
		"exp": exp.Format(time.RFC3339Nano), "at": at, "rules": p.rules,
	}
	if len(groups) > 0 {
		root["groups"] = groups
	}
	if len(p.roles) > 0 {
		root["roles"] = toAny(p.roles)
	}
	g, err := grant.Mint(root, s.opt.Key)
	if err != nil {
		return nil, err
	}
	return &Issued{Grant: g.Encode(), NS: p.ns, Resource: p.resource, Can: p.can, Roles: p.roles,
		Exp: exp.Format(time.RFC3339Nano), At: at, Checkpoint: p.checkpoint, Parents: p.parents, Head: p.head}, nil
}

func toAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
