package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/verify"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// This file is the branch side of remote branches (§G.3): a namespace of
// this deployment whose base is a namespace in another deployment.
//
// A remote branch is created with the deployment operator key (§C.4) by a
// genesis that sets base: { origin, ns, at }. Before the write transaction
// opens, the base's namespace log up to at, its heads as of at and every
// resource's log are fetched from the base and verified by recomputing ids
// (§G.2). Everything is then inserted in one transaction into a hidden
// shadow namespace, "~" + the branch's name, which mirrors the base's chain
// up to at with identical ids. The remote branch is an ordinary local
// branch of its shadow, so read-through, foreign parents, history and logs
// work unchanged.
//
// If the base is itself a branch, its read-through heads aren't in its own
// log: each is verified against the log of the base that wrote it, following
// base and at from the verified configuration genesis, recursively. Each
// level of that chain gets a shadow of its own, "~{branch}~{i}" for the
// base's i-th base, holding only what the levels above read through or use
// as foreign parents, and each shadow is a local branch of the next at the
// right at. The branch-depth limit counts every level.
//
// The rules that rely on one operator stop at the shadows: keys and
// revocations are the branch's own, purges in the base (including those
// that propagated to it from its bases) arrive as notices from its log, and
// nothing on this side blocks the base (§7.6).
//
// Encryption (§G.5). A base that isn't public, or is sealed or e2e, binds
// the branch: it must be private or sealed (a sealed branch of a sealed
// base may be public, as for local branches), never below the base's
// encryption level, and e2e only if the base is. That is what A's export
// grant entrusts to B, and B enforces it at creation. The shadows follow
// the branch's level (at rest, and for sealing and e2e).
//
//   - E2. B fetches with keys: the endpoint's grant gets them from the
//     base's POST /ns/{ns}/keys, unwrapped with the endpoint's Identity
//     when the base wraps them (§E.2.3). The shadows hold plaintext, ids
//     over it as usual, and the branch has its own epoch keys: read-through
//     content is sealed under them like any other (§E.2.5).
//   - E3. B mirrors the base's ciphertext verbatim, ids over it verified as
//     usual, without folding anything (no documents, and no $schema
//     closure: validation is the clients', §E.3.2). The keyring resource is
//     mirrored like any other, so POST /ns/{branch}/keys relays the base's
//     wrapped keys (kid "{base ns}#{e}") until the branch writes a keyring
//     of its own; each shadow records its level's epochs and when they
//     began, from its configuration history. History the base pruned can't
//     be mirrored: its horizon is a sealed snapshot.

// RemoteAuthor is the author of entries this deployment writes on behalf of
// a remote base: purges followed from its log, and mirrored horizons whose
// author isn't served.
const RemoteAuthor = "system:remote"

func shadowName(branch string) string { return "~" + branch }

// remoteShadow returns the shadow n reads through, if n is a remote branch.
func (t *tx) remoteShadow(n *nsRow) *nsRow {
	if !n.isBranch() {
		return nil
	}
	if b := t.nsByID(n.base.Int64); b.isShadow() {
		return b
	}
	return nil
}

// baseIdentity names a branch's base namespace, across deployments: the
// local base's id, or the remote base's origin and name (§7.4 successor).
func (t *tx) baseIdentity(n *nsRow) string {
	if !n.isBranch() {
		return ""
	}
	if sh := t.remoteShadow(n); sh != nil {
		var origin, ns string
		t.must(t.QueryRow(`SELECT origin, ns FROM remote_bases WHERE shadow = ?`, sh.id).Scan(&origin, &ns))
		return origin + " " + ns
	}
	return fmt.Sprint(n.base.Int64)
}

// remoteBaseIn reports whether a genesis patch set produces a document whose
// base names an origin.
func remoteBaseIn(patches any) bool {
	ops, err := patch.Parse(patches)
	if err != nil {
		return false
	}
	doc, _, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return false
	}
	m, _ := doc.(map[string]any)
	b, _ := m["base"].(map[string]any)
	_, has := b["origin"]
	return has
}

func remoteErr(format string, a ...any) *Error {
	return apiErr(502, "remote", "message", fmt.Sprintf(format, a...))
}

// unverified reports source data that fails verification.
func unverified(format string, a ...any) *Error {
	return apiErr(502, "remote", "message", "the base's data failed verification: "+fmt.Sprintf(format, a...))
}

// endpoint resolves how an origin is reached.
func (e *Engine) endpoint(origin string) (RemoteEndpoint, error) {
	ep := RemoteEndpoint{BaseURL: origin}
	if e.opt.Remote.Resolve != nil {
		r, err := e.opt.Remote.Resolve(origin)
		if err != nil {
			return ep, err
		}
		ep = r
		if ep.BaseURL == "" {
			ep.BaseURL = origin
		}
	}
	if ep.HTTPClient == nil {
		ep.HTTPClient = telemetry.DefaultClient
	}
	return ep, nil
}

func (e *Engine) remoteClient(origin string) (*client.Client, RemoteEndpoint, error) {
	ep, err := e.endpoint(origin)
	if err != nil {
		return nil, ep, err
	}
	// Keys of sealed bases come with the endpoint's grant (§G.5).
	opts := []client.Option{client.WithHTTPClient(ep.HTTPClient), client.WithKeys(client.NewKeys(ep.Identity))}
	if ep.Bearer != "" {
		opts = append(opts, client.WithBearer(ep.Bearer))
	}
	c, err := client.New(ep.BaseURL, opts...)
	return c, ep, err
}

// fetchErr maps a failed fetch from the base.
func fetchErr(what string, err error) *Error {
	if ae, ok := client.AsAPIError(err); ok {
		switch {
		case ae.Status == 404:
			return invalid(fmt.Sprintf("%s: not found at the base (at not in its chain, or not readable)", what))
		case ae.Status == 401 || ae.Status == 403:
			return remoteErr("%s: the base refused access (%d)", what, ae.Status)
		case ae.Status == 410 && ae.Code == "pruned":
			return apiErr(410, "pruned", "message", what+": history needed at at was pruned at the base", "horizon", ae.Horizon())
		case ae.Status == 410:
			return gone("message", what+": gone at the base")
		}
		return remoteErr("%s: %d from the base", what, ae.Status)
	}
	if errors.Is(err, client.ErrNoKeys) {
		return remoteErr("%s: the base is sealed (Addendum E.2) and its keys aren't available to this deployment; "+
			"the endpoint's grant must get them from the base's POST /ns/{ns}/keys (§G.5)", what)
	}
	return remoteErr("%s: %v", what, err)
}

// schemaFetchErr maps a failed fetch of a referenced schema revision from
// its namespace at the base (§G.3): a revision that doesn't resolve there,
// as with a draft in a branch (§6.1), can't be mirrored, and creation fails
// with 422.
func schemaFetchErr(ref schema.Ref) func(string, error) *Error {
	return func(what string, err error) *Error {
		if ae, ok := client.AsAPIError(err); ok && ae.Status == 404 {
			return apiErr(422, "schema_unavailable", "ref", ref.Path(), "message",
				ref.Path()+" doesn't resolve in "+ref.NS+" at the base (a draft in a branch there, §6.1, or unreadable); "+
					"a remote branch mirrors schema revisions only from their own namespace (§G.3)")
		}
		return fetchErr(what, err)
	}
}

// --- fetching and verifying the base -------------------------------------

// remoteChain is a verified resource chain from the base, oldest first. If
// the base had pruned it, entries[0] is the horizon, without its patch set
// and with the horizon's document as horizonDoc (§8.6): ids from the horizon
// on are verified; the horizon's document is only as trustworthy as the
// channel.
type remoteChain struct {
	entries    []client.LogEntry
	horizonDoc []byte
	index      map[string]int
	// opaque marks e2e content (§E.3): patch sets are ciphertext, never
	// applied, and the chain has no documents.
	opaque bool
	// blobs are the blobs its documents reference, fetched from the base
	// and verified (remote_blobs.go).
	blobs map[ids.ID]*remoteBlob
}

func newChain(entries []client.LogEntry, horizonDoc []byte) *remoteChain {
	c := &remoteChain{entries: entries, horizonDoc: horizonDoc, index: map[string]int{}}
	for i, e := range entries {
		c.index[e.ID] = i
	}
	return c
}

func (c *remoteChain) last() client.LogEntry { return c.entries[len(c.entries)-1] }

// prefix is the chain's entries up to index k.
func (c *remoteChain) prefix(k int) *remoteChain {
	p := newChain(c.entries[:k+1], c.horizonDoc)
	p.opaque, p.blobs = c.opaque, c.blobs
	return p
}

// fold walks the chain, calling f with each entry and the document after it
// (for a tombstone, the last live document). An opaque chain has no
// documents: f gets nil.
func (c *remoteChain) fold(f func(i int, e client.LogEntry, doc any) error) error {
	var doc any
	exists := false
	for i, e := range c.entries {
		switch {
		case c.opaque && (e.Kind == "rev" || e.Kind == "tombstone"):
			// Ciphertext: readers verify and fold it (§E.3.2).
		case i == 0 && c.horizonDoc != nil:
			doc, exists = jsonv.MustParse(c.horizonDoc), true
		case e.Kind == "tombstone":
			if !exists {
				return fmt.Errorf("tombstone %s without a document", e.ID)
			}
		case e.Kind == "rev":
			ops, err := patch.Parse(e.Patches)
			if err != nil {
				return fmt.Errorf("revision %s: %v", e.ID, err)
			}
			doc, _, err = patch.Apply(doc, exists, ops, patch.Options{})
			if err != nil {
				return fmt.Errorf("revision %s: %v", e.ID, err)
			}
			exists = true
		default:
			return fmt.Errorf("entry %s of kind %q", e.ID, e.Kind)
		}
		if err := f(i, e, doc); err != nil {
			return err
		}
	}
	return nil
}

// docAt is the document after entry i.
func (c *remoteChain) docAt(i int) (any, error) {
	var out any
	err := c.fold(func(j int, _ client.LogEntry, doc any) error {
		if j == i {
			out = doc
			return errStop
		}
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return out, err
}

var errStop = errors.New("stop")

// fetchChain fetches and verifies a resource's chain up to target. mapErr
// maps a failed fetch (fetchErr, or unreadableBase for a base's base).
// opaque fetches e2e content (§E.3), verified over its ciphertext.
func fetchChain(ctx context.Context, c *client.Client, ns, name, target string, opaque bool, mapErr func(string, error) *Error) (*remoteChain, *Error) {
	what := "/r/" + ns + "/" + name
	entries, err := c.Log(ctx, ns, name, target, "")
	if err == nil {
		last, verr := verify.VerifyResourceLog(entries, "")
		if verr != nil {
			return nil, unverified("%s: %v", what, verr)
		}
		if last != target || len(entries) == 0 {
			return nil, unverified("%s: the log ends at %s, not at %s", what, last, target)
		}
		ch := newChain(entries, nil)
		ch.opaque = opaque
		return ch, nil
	}
	if !client.IsPruned(err) {
		return nil, mapErr(what, err)
	}
	if opaque {
		// The horizon's document is a sealed snapshot (§8.6, §E.3), which
		// this deployment can neither verify nor fold.
		return nil, apiErr(410, "pruned", "message", what+": the e2e base pruned history needed at at; its horizon is a sealed snapshot, which can't be mirrored (§G.5)",
			"horizon", client.Horizon(err))
	}
	// Pruned at the base (§8.6): mirror from the horizon, with its
	// document as a snapshot, verifying ids from there on.
	h := client.Horizon(err)
	if _, perr := ids.Parse(h); perr != nil {
		return nil, mapErr(what, err)
	}
	d, err := c.Doc(ctx, ns, name, h)
	if err != nil {
		if client.IsGone(err) && !client.IsPruned(err) {
			return nil, apiErr(410, "pruned", "message", what+": the base's horizon is a tombstone, whose document can't be fetched", "horizon", h)
		}
		return nil, mapErr(what, err)
	}
	var rest []client.LogEntry
	if h != target {
		rest, err = c.Log(ctx, ns, name, target, h)
		if err != nil {
			if client.IsNotFound(err) {
				return nil, apiErr(410, "pruned", "message", what+": history needed at at was pruned at the base", "horizon", h)
			}
			return nil, mapErr(what, err)
		}
		last, verr := verify.VerifyResourceLog(rest, h)
		if verr != nil {
			return nil, unverified("%s: %v", what, verr)
		}
		if last != target {
			return nil, unverified("%s: the log ends at %s, not at %s", what, last, target)
		}
	}
	entries = append([]client.LogEntry{{ID: h, Kind: "rev", Author: RemoteAuthor}}, rest...)
	ch := newChain(entries, jsonv.Canonical(d.Value))
	if err := ch.fold(func(int, client.LogEntry, any) error { return nil }); err != nil {
		return nil, unverified("%s: %v", what, err)
	}
	return ch, nil
}

// unreadableBase maps a failed fetch from a base of the remote base (§G.3):
// if this deployment can't read it, it can't create the remote branch.
func unreadableBase(ns string) func(string, error) *Error {
	return func(what string, err error) *Error {
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == 401 || ae.Status == 403 || ae.Status == 404) {
			return invalid(fmt.Sprintf("%s: the remote base is a branch of %s, which this deployment can't read there (%d); "+
				"a remote branch of a branch needs read access to every base in its chain", what, ns, ae.Status))
		}
		return fetchErr(what, err)
	}
}

// remoteRes is one resource of a namespace of the base's chain as of its at.
type remoteRes struct {
	name    string
	kind    string // head, tombstone or purge
	target  string
	lastIdx int // the namespace entry that set it; -1 for none
	// chain is the resource's verified chain up to target; nil for a
	// purged resource. Entries before from belong to lower levels.
	chain *remoteChain
	from  int
	// parent is the lower level's resource whose head is the foreign
	// parent of this level's first entry (§3.3, §7.6), or nil.
	parent *remoteRes
	// purgedKind is the kind of a purged resource's head, rev or tombstone.
	purgedKind int
}

// remoteSchema is a schema resource mirrored into a namespace of this
// deployment that isn't a branch.
type remoteSchema struct {
	ns, name string
	chain    *remoteChain
}

func (s *remoteSchema) chainIndex(id string) (int, bool) {
	if s == nil {
		return 0, false
	}
	i, ok := s.chain.index[id]
	return i, ok
}

// remoteLevel is one namespace of the base's chain as of its at: the base
// itself (level 0) and, if it is a branch, its base as of the branch's at
// (level 1), and so on (§G.3). Each level is mirrored into a shadow of its
// own, and each shadow is a local branch of the next, so read-through and
// foreign parents work as for local branches.
type remoteLevel struct {
	ns, at string
	log    []client.NSEntry
	byName map[string]*remoteRes // every resource of the level's log
	res    []*remoteRes          // the ones mirrored: read through from above, or foreign parents
	// An e2e level's encryption member as of at, and its epochs with when
	// they began (§E.3.2), for the shadow's keyring relay.
	enc    map[string]any
	epochs []epochStart
	// nonce: the base itself (level 0) requires nonces as of at (§C.7).
	nonce bool
}

// remoteMirror is the base as of at, verified.
type remoteMirror struct {
	base    *BaseRef
	read    string // the base's read mode at at (as served; §G.5)
	level   int    // the base's encryption level at at (as served)
	levels  []*remoteLevel
	schemas []*remoteSchema
	// schemaNonce: the schemas' source namespaces that require nonces
	// (§C.7), as far as they can be read.
	schemaNonce map[string]bool
}

// fetchLevel fetches and verifies a namespace's log up to at, and its
// configuration genesis. next is its base, if it is a branch. Members of
// the base's namespace documents this deployment doesn't define are
// ignored (§7.4, §G.3): nothing of them is copied.
func fetchLevel(ctx context.Context, c *client.Client, ns, at string, mapErr func(string, error) *Error) (*remoteLevel, *BaseRef, *Error) {
	// The namespace log up to at, verified from its first entry: at is the
	// trusted starting point (§G.1).
	log, err := c.NSLog(ctx, ns, at, "")
	if err != nil {
		return nil, nil, mapErr("/ns/"+ns+"/rev/"+at+"/log", err)
	}
	last, verr := verify.VerifyNSChain(log, "")
	if verr != nil {
		return nil, nil, unverified("/ns/%s: namespace log: %v", ns, verr)
	}
	if last != at {
		return nil, nil, unverified("/ns/%s: the namespace log ends at %s, not at %s", ns, last, at)
	}
	lv := &remoteLevel{ns: ns, at: at, log: log, byName: map[string]*remoteRes{}}
	set := func(name, kind, target string, i int) {
		r := &remoteRes{name: name, kind: kind, target: target, lastIdx: i}
		if prev := lv.byName[name]; kind == "purge" && prev != nil && prev.kind == "tombstone" {
			r.purgedKind = kindTombstone
		}
		lv.byName[name] = r
	}
	for i, en := range log {
		switch en.Kind {
		case "head", "tombstone", "purge":
			set(en.Resource, en.Kind, en.Target, i)
		case "batch":
			for _, s := range en.Entries {
				if s.Kind == "head" || s.Kind == "tombstone" {
					set(s.Resource, s.Kind, s.Target, i)
				}
			}
		case "purge-ns":
			return nil, nil, gone("message", "the remote base (or a base of it) is purged: /ns/"+ns)
		}
	}
	// A branch's base and at are in its configuration genesis, which a
	// local branch writes as one add of the whole document (§7.6): its id,
	// the target of the chain's first entry, proves the base and at.
	if len(log) == 0 || log[0].Kind != "config" {
		return lv, nil, nil
	}
	d, err := c.NSDoc(ctx, ns, log[0].ID)
	if err != nil {
		if _, ok := client.AsAPIError(err); ok {
			return nil, nil, mapErr("/ns/"+ns+"/rev/"+log[0].ID, err)
		}
		// Not readable as plain JSON (sealed): not a branch this server
		// follows. If it is one after all, /heads won't agree.
		return lv, nil, nil
	}
	bv, isBranch := d.Value["base"]
	if !isBranch {
		return lv, nil, nil
	}
	doc, perr := jsonv.Parse(d.Raw)
	if perr != nil {
		return nil, nil, unverified("/ns/%s: configuration genesis: %v", ns, perr)
	}
	genesis := []any{map[string]any{"op": "add", "path": "", "value": doc}}
	if ids.Revision(nil, jsonv.Canonical(genesis)).String() != log[0].Target {
		return nil, nil, unverified("/ns/%s: the configuration genesis doesn't match the namespace log", ns)
	}
	bm, _ := bv.(map[string]any)
	if _, remote := bm["origin"]; remote {
		return nil, nil, invalid(fmt.Sprintf("/ns/%s is itself a remote branch; this server mirrors only bases whose chain is in one deployment", ns))
	}
	bns, _ := bm["ns"].(string)
	bat, _ := bm["at"].(string)
	if _, err := ids.Parse(bat); err != nil || !ValidNSName(bns) {
		return nil, nil, unverified("/ns/%s: the configuration's base is malformed", ns)
	}
	return lv, &BaseRef{NS: bns, At: bat}, nil
}

// unknownLevel refuses a remote branch whose base's namespace document
// can't be read at at: without it, B can't tell how protected the base is
// (§G.5.2). A transport failure stays a 502; anything the base answered,
// or a document B can't open, is 422.
func unknownLevel(base *BaseRef, err error) *Error {
	what := "/ns/" + base.NS + "/rev/" + base.At
	msg := fmt.Sprintf("%s: this deployment can't read the base's namespace document (%v), so it can't tell how protected the base is; "+
		"a remote branch is refused then (§G.5.2): the endpoint's grant needs read on it, and keys if it is sealed", what, err)
	var ue *url.Error
	if errors.As(err, &ue) {
		return remoteErr("%s", msg)
	}
	return invalid(msg)
}

// fetchEpochs reads an e2e level's encryption member as of its at, and its
// epochs with when each began: the created time of the first entry of its
// log whose configuration names it (§E.3.2). Configuration documents are
// only as trustworthy as the channel; they only decide which epochs a grant
// on this side gets relayed (§E.2.3).
func (e *Engine) fetchEpochs(ctx context.Context, c *client.Client, lv *remoteLevel, mapErr func(string, error) *Error) *Error {
	epochOf := func(nsID string) (map[string]any, int, *Error) {
		d, err := c.NSDoc(ctx, lv.ns, nsID)
		if err != nil {
			return nil, 0, mapErr("/ns/"+lv.ns+"/rev/"+nsID, err)
		}
		enc, _ := d.Value["encryption"].(map[string]any)
		if lvl, _ := enc["level"].(string); lvl != "e2e" {
			return nil, 0, unverified("/ns/%s: an e2e base's chain holds a namespace that isn't e2e", lv.ns)
		}
		ep := 1
		if f, ok := enc["epoch"].(float64); ok {
			ep = int(f)
		}
		return enc, ep, nil
	}
	enc, cur, ferr := epochOf(lv.at)
	if ferr != nil {
		return ferr
	}
	if lv.enc, ferr = e.shadowEncryption(lv.ns, enc); ferr != nil {
		return ferr
	}
	seen := map[int]bool{}
	for _, en := range lv.log {
		isConfig := en.Kind == "config"
		for _, s := range en.Entries {
			isConfig = isConfig || s.Kind == "config"
		}
		if !isConfig {
			continue
		}
		_, ep, ferr := epochOf(en.ID)
		if ferr != nil {
			return ferr
		}
		if !seen[ep] && ep <= cur {
			seen[ep] = true
			lv.epochs = append(lv.epochs, epochStart{e: ep, created: time.UnixMilli(parseCreated(en.Created, time.Now()))})
		}
	}
	return nil
}

// shadowEncryption is what a shadow keeps of an e2e level's encryption
// member (§G.3): the members this version defines, which its keyring relay
// reads. The shadow's document is stored here and read under this
// deployment's schema and limits (§7.4), so members a base of a newer
// version may carry are left out rather than stored, and the ones kept
// must be valid as tx.config will read them.
func (e *Engine) shadowEncryption(ns string, enc map[string]any) (map[string]any, *Error) {
	out := map[string]any{}
	for _, k := range []string{"level", "epoch", "historyEpochs", "pad"} {
		if v, ok := enc[k]; ok {
			out[k] = v
		}
	}
	if _, err := e.parseConfig(map[string]any{"encryption": out}); err != nil {
		return nil, unverified("/ns/%s: the base's encryption member: %v", ns, err)
	}
	return out, nil
}

// fetchRemote fetches and verifies the base of a remote branch as of at
// (§G.3), outside any transaction. If the base is a branch, its bases are
// fetched and verified too, each as of the at of the branch above it, and
// every read-through head is verified against the log of the base that
// wrote it.
func (e *Engine) fetchRemote(ctx context.Context, base *BaseRef) (*remoteMirror, *Error) {
	c, _, err := e.remoteClient(base.Origin)
	if err != nil {
		return nil, remoteErr("%s: %v", base.Origin, err)
	}
	root, err := c.Root(ctx)
	if err != nil {
		return nil, fetchErr("GET /", err)
	}
	if root.Origin != base.Origin {
		return nil, remoteErr("the deployment reached for %s publishes the origin %q", base.Origin, root.Origin)
	}
	m := &remoteMirror{base: base, read: "grant"}
	mapErrs := []func(string, error) *Error{fetchErr}
	ns, at := base.NS, base.At
	for {
		mapErr := mapErrs[len(mapErrs)-1]
		lv, next, ferr := fetchLevel(ctx, c, ns, at, mapErr)
		if ferr != nil {
			return nil, ferr
		}
		m.levels = append(m.levels, lv)
		if len(m.levels) == 1 {
			// The base's protection comes from its namespace document
			// (sealed ones are decrypted with the endpoint's keys). One B
			// can't read is refused: its level can't be told (§G.5.2).
			d, err := c.NSDoc(ctx, base.NS, base.At)
			if err != nil {
				return nil, unknownLevel(base, err)
			}
			// Only read, encryption, nonce and base are read here, and
			// members this deployment doesn't define are ignored, so a
			// base whose deployment upgrades first, or holds x- or older
			// members, is still followed (§7.4, §G.3). The spec version
			// GET / publishes is never a reason to refuse.
			if d.Value["read"] == "public" {
				m.read = "public"
			}
			if enc, ok := d.Value["encryption"].(map[string]any); ok {
				lv, _ := enc["level"].(string)
				if m.level = levelOf(lv); m.level == levelNone {
					m.level = levelE2E // unknown: the strictest
				}
			}
			lv.nonce = d.Value["nonce"] == "required" && m.level != levelE2E
		}
		if next == nil {
			break
		}
		// The remote branch is a branch of every namespace of the chain:
		// the branch-depth limit counts them all (§6.6).
		if len(m.levels)+1 > e.opt.Maximums.BranchDepth {
			return nil, limitErr(422, fmt.Sprintf("branch depth exceeded: the remote base's chain has more than %d namespaces", e.opt.Maximums.BranchDepth))
		}
		ns, at = next.NS, next.At
		mapErrs = append(mapErrs, unreadableBase(ns))
	}
	opaque := m.level == levelE2E
	if opaque {
		for i, lv := range m.levels {
			if ferr := e.fetchEpochs(ctx, c, lv, mapErrs[i]); ferr != nil {
				return nil, ferr
			}
		}
	}
	// Every resource as the base sees it at at: the topmost level with
	// entries for it (§7.6).
	visible := map[string]int{}
	for i := len(m.levels) - 1; i >= 0; i-- {
		for name := range m.levels[i].byName {
			visible[name] = i
		}
	}
	// The listing the spec reads must agree with the logs (§G.3).
	heads, err := c.Heads(ctx, base.NS, base.At)
	if err != nil {
		return nil, fetchErr("/ns/"+base.NS+"/rev/"+base.At+"/heads", err)
	}
	if len(heads) != len(visible) {
		return nil, unverified("/heads lists %d resources, the namespace logs %d", len(heads), len(visible))
	}
	purgedAfter := map[string]*remoteRes{}
	for _, h := range heads {
		i, ok := visible[h.Resource]
		if !ok {
			return nil, unverified("/heads lists %s, which no namespace log does", h.Resource)
		}
		r := m.levels[i].byName[h.Resource]
		switch {
		case r.kind == h.Kind && r.target == h.Target:
		case h.Kind == "purge" && r.kind != "purge":
			// Purged at the base after at (§8.3): its content is gone
			// there, and the purge entry follows at or after at.
			p := &remoteRes{name: r.name, kind: "purge", target: h.Target, lastIdx: -1}
			if h.Target == r.target && r.kind == "tombstone" {
				p.purgedKind = kindTombstone
			}
			purgedAfter[h.Resource] = p
		default:
			return nil, unverified("/heads lists %s as %s %s, which the namespace logs don't", h.Resource, h.Kind, h.Target)
		}
	}
	var queue []schema.Ref
	for _, name := range sortedKeys(visible) {
		i := visible[name]
		lv := m.levels[i]
		if p := purgedAfter[name]; p != nil {
			lv.res = append(lv.res, p)
			continue
		}
		r := lv.byName[name]
		lv.res = append(lv.res, r)
		if r.kind == "purge" {
			continue
		}
		ch, ferr := fetchChain(ctx, c, lv.ns, name, r.target, opaque && name != KeyringName, mapErrs[i])
		if ferr != nil {
			return nil, ferr
		}
		r.chain = ch
		// The blobs its documents reference, mirrored with it (§G.3).
		if ferr := fetchBlobs(ctx, c, lv.ns, name, ch, mapErrs[i]); ferr != nil {
			return nil, ferr
		}
		if !ch.opaque {
			doc, err := ch.docAt(len(ch.entries) - 1)
			if err != nil {
				return nil, unverified("/r/%s/%s: %v", lv.ns, name, err)
			}
			if dm, ok := doc.(map[string]any); ok {
				if s, ok := dm["$schema"].(string); ok {
					if ref, ok := schema.ParseRef(s); ok {
						queue = append(queue, ref)
					}
				}
			}
		}
		// The chain crosses foreign parents into lower levels (§7.6): the
		// entries up to each lower level's head as of its at are that
		// level's, and verified by it.
		for cur, j := r, i+1; j < len(m.levels); j++ {
			q := m.levels[j].byName[name]
			if q == nil {
				continue
			}
			if q.kind == "purge" {
				break
			}
			k, ok := ch.index[q.target]
			if !ok || k >= len(cur.chain.entries)-1 {
				break // not a foreign parent: an ordinary create above
			}
			cur.from, cur.parent = k+1, q
			q.chain = ch.prefix(k)
			m.levels[j].res = append(m.levels[j].res, q)
			cur = q
		}
	}
	// The $schema and $ref closure (§G.3), each schema resource's history
	// up to the referenced revisions.
	schemas := map[string]*remoteSchema{}
	seen := map[string]bool{}
	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		if seen[ref.Path()] {
			continue
		}
		seen[ref.Path()] = true
		key := ref.NS + "/" + ref.Name
		s := schemas[key]
		if _, have := s.chainIndex(ref.Rev); !have {
			ch, ferr := fetchChain(ctx, c, ref.NS, ref.Name, ref.Rev, false, schemaFetchErr(ref))
			if ferr != nil {
				return nil, ferr
			}
			if s == nil {
				s = &remoteSchema{ns: ref.NS, name: ref.Name, chain: ch}
				schemas[key] = s
			} else if _, ok := ch.index[s.chain.last().ID]; ok {
				s.chain = ch // the new chain extends the one fetched before
			} else {
				return nil, unverified("%s: revisions on diverging chains", ref.Path())
			}
		}
		i := s.chain.index[ref.Rev]
		if s.chain.entries[i].Kind != "rev" {
			return nil, unverified("%s is a tombstone", ref.Path())
		}
		doc, err := s.chain.docAt(i)
		if err != nil {
			return nil, unverified("%s: %v", ref.Path(), err)
		}
		queue = append(queue, schema.Refs(doc)...)
	}
	for _, k := range sortedKeys(schemas) {
		m.schemas = append(m.schemas, schemas[k])
	}
	m.schemaNonce = fetchSchemaNonces(ctx, c, m.schemas)
	return m, nil
}

// --- creating a remote branch ----------------------------------------------

// checkRemoteGenesis authenticates the operator grant and checks the
// genesis of a remote branch (§C.4, §G.3).
func (t *tx) checkRemoteGenesis(req Request, cc ConfigChange) (*Config, map[string]any, *actor, *Error) {
	if !ValidNSName(req.NS) {
		return nil, nil, nil, badInput("invalid namespace name")
	}
	keys := t.operatorKeys()
	if keys == nil {
		keys = []grant.Key{}
	}
	a, aerr := t.authenticate(req.NS, nil, nil, req.Cred, keys)
	if aerr != nil {
		return nil, nil, nil, aerr
	}
	if a.verified != nil && !a.star {
		return nil, nil, nil, forbidden("creating a remote branch needs a deployment operator key")
	}
	ops, err := patch.Parse(cc.Patches)
	if err != nil {
		return nil, nil, nil, patchErr(err)
	}
	doc, _, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return nil, nil, nil, patchErr(err)
	}
	cfg, perr := t.e.newConfig(doc, nil, nil)
	if perr != nil {
		return nil, nil, nil, perr
	}
	if aerr := t.e.checkArchives(cfg); aerr != nil {
		return nil, nil, nil, aerr
	}
	if !cfg.Base.Remote() {
		return nil, nil, nil, invalid("/base must be { origin, ns, at }")
	}
	if cfg.Base.Origin == t.e.opt.Origin {
		return nil, nil, nil, invalid("the base is in this deployment; create a local branch with POST /ns/{base}/branches")
	}
	if cfg.Successor != "" {
		return nil, nil, nil, invalid("a new namespace cannot have a successor")
	}
	if err := t.checkEncryption(nil, cfg, -1); err != nil {
		return nil, nil, nil, err
	}
	return cfg, doc.(map[string]any), a, nil
}

func (e *Engine) createRemoteBranch(ctx context.Context, req Request, cc ConfigChange) (*WriteResult, error) {
	// Nothing is fetched before the name, the operator grant and the
	// document have been checked.
	var cfg *Config
	taken := false
	err := e.read(ctx, func(t *tx) error {
		if t.nsByName(req.NS) != nil {
			taken = true
			return nil
		}
		c, _, _, err := t.checkRemoteGenesis(req, cc)
		cfg = c
		return asErr(err)
	})
	if err != nil {
		return nil, err
	}
	var m *remoteMirror
	if !taken {
		var ferr *Error
		if m, ferr = e.fetchRemote(ctx, cfg.Base); ferr != nil {
			return nil, ferr
		}
	}
	var res *WriteResult
	err = e.update(ctx, func(t *tx) error {
		if t.nsForWrite(req.NS) != nil || m == nil {
			r, err := t.writeConfig(req, cc) // 412 for a taken name
			res = r
			return err
		}
		cfg, doc, a, err := t.checkRemoteGenesis(req, cc)
		if err != nil {
			return err
		}
		r, err := t.insertRemoteBranch(req, cc, cfg, doc, m, t.actorID(a))
		res = r
		return asErr(err)
	})
	if err != nil {
		return nil, err
	}
	if res.Status == 201 && cfg != nil && e.opt.Remote.Register {
		if err := e.RegisterRemote(ctx, req.NS); err != nil {
			log.Printf("remote branch %s: registering with %s: %v", req.NS, cfg.Base.Origin, err)
		}
	}
	return res, nil
}

// insertRemoteBranch inserts the shadow, the mirrored schemas and the
// branch, all verified before the transaction opened.
func (t *tx) insertRemoteBranch(req Request, cc ConfigChange, cfg *Config, doc map[string]any, m *remoteMirror, author int64) (*WriteResult, *Error) {
	// The obligations of §G.5, which the base can't enforce.
	if cfg.Read == "public" && m.read != "public" {
		return nil, invalid("a branch of a non-public namespace cannot be public (§G.5): make it private (read: grant) or sealed")
	}
	if cfg.level < m.level {
		return nil, invalid(fmt.Sprintf("/encryption: a branch cannot have a lower encryption level than its base, which is %s (§G.5)", levelNames[m.level]))
	}
	if cfg.level == levelE2E && m.level != levelE2E {
		return nil, invalid("/encryption: a branch can be e2e only if its base is")
	}
	if m.levels[0].nonce && !cfg.NonceRequired {
		return nil, invalid(`/nonce: the base requires nonces, so a remote branch of it must be created with "nonce": "required" too, or merging it back would fail (§C.7, §G.3)`)
	}
	// base.chain records the namespaces followed while verifying (§G.3):
	// readers of an e2e branch accept read-through ciphertext bound to any
	// of them. A genesis may give it, and must then give it right;
	// otherwise it is added, and the genesis becomes one add of the whole
	// document, as stored.
	chain := make([]any, len(m.levels))
	for i, lv := range m.levels {
		chain[i] = lv.ns
	}
	if cfg.Base.Chain != nil {
		if !jsonv.Equal(anyStrings(cfg.Base.Chain), chain) {
			return nil, invalid(fmt.Sprintf("/base/chain must be %v: the base's namespace and its bases as of at", chain))
		}
	} else {
		doc = jsonv.Clone(doc).(map[string]any)
		doc["base"].(map[string]any)["chain"] = chain
		cc.Patches = []any{map[string]any{"op": "add", "path": "", "value": doc}}
	}
	// The shadows' mirrored rows follow the branch's level.
	if t.shadowLevels == nil {
		t.shadowLevels = map[string]int{}
	}
	for i := range m.levels {
		t.shadowLevels[shadowLevelName(req.NS, i)] = cfg.level
	}
	if err := t.mirrorSchemas(m, req.NS, cfg, author); err != nil {
		return nil, err
	}
	shadow, atSeq := t.insertShadows(req.NS, m)
	canon := jsonv.Canonical(cc.Patches)
	cfgID := ids.Revision(nil, canon)
	bid := t.mustInsert(`INSERT INTO namespaces (name, base, base_at, base_config_seq, frozen) VALUES (?,?,?,?,?) RETURNING ns`,
		req.NS, shadow.id, atSeq, shadow.configSeq, cfg.Frozen)
	cseq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?) RETURNING seq`,
		bid, cfgID[:], string(canon), string(jsonv.Canonical(doc)), author, t.now.UnixMilli())
	bn := t.nsByID(bid)
	// A sealed branch's first epoch key, an e2e branch's first epoch.
	t.sealedConfigWritten(bn, nil, cfg)
	// No entry is written to any other local chain: the base's is remote.
	_, nsID := t.appendNS(bn, map[string]any{"kind": "config", "target": cfgID.String()}, nil, &cseq, cseq, author)
	_, err := t.Exec(`INSERT INTO remote_bases (shadow, branch, origin, ns, at, checkpoint) VALUES (?,?,?,?,?,?)`,
		shadow.id, bid, m.base.Origin, m.base.NS, m.base.At, m.base.At)
	t.must(err)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: cfgID.String()}, nil
}

// insertShadows mirrors every level of the base's chain into a shadow of
// its own, the bottom one first, each a local branch of the one below at
// that level's at. It returns the top shadow, which the remote branch reads
// through, and the seq of at in it.
func (t *tx) insertShadows(branch string, m *remoteMirror) (*nsRow, int64) {
	var sh *nsRow
	var at int64
	heads := map[*remoteRes]int64{}
	for i := len(m.levels) - 1; i >= 0; i-- {
		sh, at = t.insertShadow(shadowLevelName(branch, i), m.read, m.levels[i], sh, at, heads)
		for _, x := range m.levels[i].epochs {
			_, err := t.Exec(`INSERT INTO e2e_epochs (ns, epoch, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`, sh.id, x.e, x.created.UnixMilli())
			t.must(err)
		}
	}
	return sh, at
}

// shadowLevelName is the shadow of level i of a remote branch's base chain:
// "~{branch}" for the base itself, "~{branch}~{i}" for its bases. Neither is
// in the §3.6 grammar.
func shadowLevelName(branch string, i int) string {
	if i == 0 {
		return shadowName(branch)
	}
	return shadowName(branch) + "~" + strconv.Itoa(i)
}

// insertShadow mirrors one level's chain up to its at and its mirrored
// resources into a new shadow namespace, with identical ids, as a branch of
// base at baseAt (nil: not a branch). heads records the head row of each
// mirrored resource, for the foreign parents of the levels above. It
// returns the shadow and the seq of at in it.
func (t *tx) insertShadow(name, read string, lv *remoteLevel, base *nsRow, baseAt int64, heads map[*remoteRes]int64) (*nsRow, int64) {
	remote := t.authorID(RemoteAuthor)
	cdoc := map[string]any{"read": read}
	if lv.enc != nil {
		// An e2e level: its epochs, for the keyring relay (§E.3.2).
		cdoc["encryption"] = lv.enc
	}
	if lv.nonce {
		// The branch can't turn it off (checkNonceBase).
		cdoc["nonce"] = "required"
	}
	genesis := []any{map[string]any{"op": "add", "path": "", "value": cdoc}}
	gcanon := jsonv.Canonical(genesis)
	cid := ids.Revision(nil, gcanon)
	var bid, bat, bcfg any
	if base != nil {
		bid, bat, bcfg = base.id, baseAt, base.configSeq
	}
	sid := t.mustInsert(`INSERT INTO namespaces (name, base, base_at, base_config_seq) VALUES (?,?,?,?) RETURNING ns`, name, bid, bat, bcfg)
	cseq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?) RETURNING seq`,
		sid, cid[:], string(gcanon), string(jsonv.Canonical(cdoc)), remote, t.now.UnixMilli())
	// Resources first, so the log rows can name them.
	resIDs := map[string]int64{}
	for _, rr := range lv.res {
		if rr.chain == nil {
			// Purged at the base: only the head's id is known (its
			// content and parents are gone there too).
			res := t.mustInsert(`INSERT INTO resources (ns, name, state) VALUES (?,?,?) RETURNING res`, sid, rr.name, statePurged)
			resIDs[rr.name] = res
			id := mustID(rr.target)
			head := t.mustInsert(`INSERT INTO revisions (res, id, parent_seq, first, kind, author, created) VALUES (?,?,NULL,1,?,?,?) RETURNING seq`,
				res, id[:], rr.purgedKind, remote, t.now.UnixMilli())
			_, err := t.Exec(`UPDATE resources SET head_seq = ? WHERE res = ?`, head, res)
			t.must(err)
			continue
		}
		res := t.mustInsert(`INSERT INTO resources (ns, name) VALUES (?,?) RETURNING res`, sid, rr.name)
		resIDs[rr.name] = res
		var parent *revRow
		if rr.parent != nil {
			parent = t.rev(heads[rr.parent])
		}
		heads[rr] = t.insertChain(res, rr.chain, rr.from, parent, parent != nil)
	}
	settles := map[int][]*remoteRes{} // log index → resources whose head it set
	for _, rr := range lv.res {
		if rr.chain != nil && rr.lastIdx >= 0 {
			settles[rr.lastIdx] = append(settles[rr.lastIdx], rr)
		}
	}
	var prev any
	var atSeq int64
	for i, en := range lv.log {
		hf, err := verify.HashedForm(en)
		t.must(err)
		body := jsonv.Canonical(hf)
		var p *ids.ID
		if i > 0 {
			x := mustID(lv.log[i-1].ID)
			p = &x
		}
		id := ids.Hash(p, body)
		if id.String() != en.ID {
			panic(fmt.Errorf("mirrored entry %s does not verify", en.ID))
		}
		var res any
		if en.IsResource() {
			if x, ok := resIDs[en.Resource]; ok {
				res = x // unmirrored resources of lower levels have no row
			}
		}
		author := remote
		if en.Author != "" {
			author = t.authorID(en.Author)
		}
		atSeq = t.mustInsert(`INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created) VALUES (?,?,?,?,?,NULL,?,?,?,?) RETURNING seq`,
			sid, id[:], prev, nsKindCode(en.Kind), res, string(body), cseq, author, parseCreated(en.Created, t.now))
		prev = atSeq
		for _, rr := range settles[i] {
			_, err := t.Exec(`INSERT INTO head_history (res, ns_seq, target_seq) VALUES (?,?,?)`, resIDs[rr.name], atSeq, heads[rr])
			t.must(err)
		}
	}
	t.metaChanged = true
	_, err := t.Exec(`UPDATE namespaces SET head_seq = ?, head_id = NULL, config_seq = ? WHERE ns = ?`, atSeq, cseq, sid)
	t.must(err)
	return t.nsByID(sid), atSeq
}

// remoteShadows returns the shadows a remote branch reads through, its
// base's first, then its bases'; nil if n isn't a remote branch. All of
// them are the remote side (§7.6).
func (t *tx) remoteShadows(n *nsRow) []*nsRow {
	var out []*nsRow
	for s := t.remoteShadow(n); s != nil; {
		out = append(out, s)
		if !s.isBranch() {
			break
		}
		s = t.nsByID(s.base.Int64)
	}
	return out
}

func parseCreated(s string, now time.Time) int64 {
	if tm, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return tm.UnixMilli()
	}
	return now.UnixMilli()
}

// insertChain inserts the chain's entries from index from on into res, the
// first chained on parent (nil: a new resource), and updates the resource's
// head, state, horizon and cached documents. With foreign, parent is in a
// base's resource, and the first entry is res's first, with a foreign
// parent (§3.3). It returns the head row's seq.
func (t *tx) insertChain(res int64, ch *remoteChain, from int, parent *revRow, foreign bool) int64 {
	remote := t.authorID(RemoteAuthor)
	var parentSeq any
	if parent != nil {
		parentSeq = parent.seq
	}
	var last, lastLive int64 = 0, 0
	var lastLiveDoc []byte
	var horizon any
	if parent != nil && !ch.opaque {
		ll := t.lastLive(parent)
		lastLive = ll.seq
	}
	state := stateLive
	var declared [][]ids.ID
	if ch.opaque {
		var err error
		declared, err = ch.declaredLists()
		t.must(err) // verified before the transaction (fetchBlobs)
	}
	err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		if i < from {
			return nil
		}
		id := mustID(e.ID)
		first := 0
		if (parent == nil || foreign) && i == from {
			first = 1
		}
		kind := kindRev
		var patches, typed, sig any
		var canonDoc []byte
		if !ch.opaque {
			canonDoc = jsonv.Canonical(doc)
		}
		switch {
		case e.Kind == "tombstone":
			kind = kindTombstone
		case e.HasPatches:
			patches = t.putPatches(res, id, jsonv.Canonical(e.Patches))
		}
		if kind == kindRev && !ch.opaque {
			if dm, ok := doc.(map[string]any); ok {
				if s, ok := dm["$schema"].(string); ok {
					typed = s
				}
			}
		}
		if e.Signature != "" {
			sig = e.Signature
		}
		author := remote
		if e.Author != "" {
			author = t.authorID(e.Author)
		}
		// The base's gestures are mirrored with its entries (§7.2, §G.3);
		// one that isn't a gesture id is dropped, never stored.
		var gesture, undoes any
		if ValidGesture(e.Gesture) {
			gesture = e.Gesture
		}
		if ValidGesture(e.Undoes) {
			undoes = e.Undoes
		}
		last = t.mustInsert(`INSERT INTO revisions (res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes) VALUES (?,?,?,?,?,?,?,NULL,NULL,?,?,?,?,?) RETURNING seq`,
			res, id[:], parentSeq, first, kind, patches, author, sig, typed, parseCreated(e.Created, t.now), gesture, undoes)
		parentSeq = last
		if kind == kindTombstone {
			state = stateTombstoned
			return nil
		}
		state = stateLive
		if ch.opaque {
			// e2e content has no documents on the server (§E.3); its blobs
			// are those the sealed op declares (§E.3.1).
			t.attachFetched(res, ch, declared[i], last)
			return nil
		}
		lastLive, lastLiveDoc = last, canonDoc
		t.attachMirrored(res, ch, doc, last)
		if patches == nil {
			// The horizon: its document is kept as a snapshot (§8.6).
			_, err := t.Exec(`INSERT INTO snapshots (seq, res, doc) VALUES (?,?,?)`, last, res, t.putDoc("snapshots", res, last, canonDoc))
			t.must(err)
			horizon = last
			return nil
		}
		t.cacheDoc(id, canonDoc)
		t.maybeSnapshot(res, last, canonDoc)
		return nil
	})
	t.must(err) // verified before the transaction
	if last == 0 {
		return parent.seq
	}
	// Its revisions were counted for snapshots by maybeSnapshot, not in the
	// row (insertItems): counted again from the table next time.
	_, err = t.Exec(`UPDATE resources SET head_seq = ?, state = ?, horizon_seq = COALESCE(?, horizon_seq), snap_revs = NULL, snap_bytes = NULL WHERE res = ?`, last, state, horizon, res)
	t.must(err)
	if ch.opaque {
		_, err = t.Exec(`DELETE FROM heads WHERE res = ?`, res)
		t.must(err)
		return last
	}
	if lastLiveDoc == nil {
		b, derr := t.docBytesAt(t.rev(lastLive))
		t.must(derr)
		lastLiveDoc = b
	}
	if len(lastLiveDoc) <= t.e.opt.HeadSnapshotMax {
		_, err = t.Exec(`INSERT INTO heads (res, seq, doc) VALUES (?,?,?) ON CONFLICT (res) DO UPDATE SET seq = excluded.seq, doc = excluded.doc`, res, lastLive, t.putDoc("heads", res, lastLive, lastLiveDoc))
	} else {
		_, err = t.Exec(`DELETE FROM heads WHERE res = ?`, res)
	}
	t.must(err)
	return last
}

// mirrorSchemas mirrors the schema closure into namespaces of this
// deployment that aren't branches, under the same paths, so $schema
// resolves here (§G.3). A namespace that doesn't exist is created with the
// branch's read mode, keys and roles, and its source's nonce setting
// (§C.7). A path whose chain neither contains the base's nor is a prefix of
// it is 409 name_conflict. The entries it writes record the creating
// operator as author and its grant (§7.4).
func (t *tx) mirrorSchemas(m *remoteMirror, branch string, cfg *Config, author int64) *Error {
	type change struct {
		name string
		kind string
		head int64
		res  int64
	}
	byNS := map[string][]*remoteSchema{}
	for _, s := range m.schemas {
		byNS[s.ns] = append(byNS[s.ns], s)
	}
	for _, nsName := range sortedKeys(byNS) {
		n := t.nsForWrite(nsName)
		conflict := func(s *remoteSchema, why string) *Error {
			return apiErr(409, "name_conflict", "path", "/r/"+s.ns+"/"+s.name+"/rev/"+s.chain.last().ID, "message", why)
		}
		if nsName == branch || n != nil && (n.isBranch() || n.purged) {
			return conflict(byNS[nsName][0], "the schema namespace here is a branch or purged")
		}
		if n == nil {
			doc := map[string]any{"read": cfg.Read}
			for _, k := range []string{"keys", "roles", "encryption"} {
				if v, ok := cfg.Doc[k]; ok {
					doc[k] = jsonv.Clone(v)
				}
			}
			if m.schemaNonce[nsName] {
				// Its source's setting, not the branch's (§C.7).
				doc["nonce"] = "required"
			}
			n, _, _ = t.insertNamespace(nsName, []any{map[string]any{"op": "add", "path": "", "value": doc}}, doc, false, author)
		}
		var changes []change
		for _, s := range byNS[nsName] {
			own := t.resource(n.id, s.name)
			if own == nil {
				res := t.mustInsert(`INSERT INTO resources (ns, name) VALUES (?,?) RETURNING res`, n.id, s.name)
				head := t.insertChain(res, s.chain, 0, nil, false)
				changes = append(changes, change{s.name, s.chain.last().Kind, head, res})
				continue
			}
			if own.state == statePurged || !own.headSeq.Valid {
				return conflict(s, "the resource here is purged")
			}
			h := t.rev(own.headSeq.Int64)
			if i, ok := s.chain.index[h.id.String()]; ok {
				if i == len(s.chain.entries)-1 {
					continue // same head
				}
				head := t.insertChain(own.id, s.chain, i+1, h, false) // a prefix: extend it
				changes = append(changes, change{s.name, s.chain.last().Kind, head, own.id})
				continue
			}
			if t.findInAncestry(h, mustID(s.chain.last().ID)) != nil {
				continue // already contains the base's chain
			}
			return conflict(s, "the resource here holds a different history")
		}
		if len(changes) == 0 {
			continue
		}
		var entries []any
		for _, c := range changes {
			kind := "head"
			if c.kind == "tombstone" {
				kind = "tombstone"
			}
			entries = append(entries, map[string]any{"resource": c.name, "kind": kind, "target": t.rev(c.head).id.String()})
		}
		seq, _ := t.appendNS(n, map[string]any{"kind": "batch", "entries": entries}, nil, nil, n.configSeq, author)
		for _, c := range changes {
			_, err := t.Exec(`INSERT INTO head_history (res, ns_seq, target_seq) VALUES (?,?,?)`, c.res, seq, c.head)
			t.must(err)
		}
		t.tags = append(t.tags, "ns:"+n.name)
	}
	return nil
}

// purgeShadow removes the content of name from a shadow, without an entry
// (the shadow's chain mirrors the base's). It runs whenever the remote
// branch purges the name, so the copy never outlives the branch's purge.
func (t *tx) purgeShadow(sh *nsRow, name string) {
	t.lockNS(sh.id, lockExclusive)
	r := t.resource(sh.id, name)
	if r == nil || r.state == statePurged {
		return
	}
	t.deleteDEKs(`res = ?`, r.id)
	_, err := t.Exec(`UPDATE revisions SET patches = NULL WHERE res = ?`, r.id)
	t.must(err)
	_, err = t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE res = ?`, statePurged, r.id)
	t.must(err)
	_, err = t.Exec(`DELETE FROM heads WHERE res = ?`, r.id)
	t.must(err)
	_, err = t.Exec(`DELETE FROM snapshots WHERE res = ?`, r.id)
	t.must(err)
	t.purgeBlobs(`res = ?`, r.id)
	t.flushDocs = true
}

// purgeShadowNS removes all of a shadow's content (the remote branch's
// namespace purge, §8.5).
func (t *tx) purgeShadowNS(sh *nsRow) {
	t.lockNS(sh.id, lockExclusive)
	t.deleteDEKs(`ns = ?`, sh.id)
	q := `res IN (SELECT res FROM resources WHERE ns = ?)`
	for _, s := range []string{
		`UPDATE revisions SET patches = NULL WHERE ` + q,
		`DELETE FROM heads WHERE ` + q,
		`DELETE FROM snapshots WHERE ` + q,
	} {
		_, err := t.Exec(s, sh.id)
		t.must(err)
	}
	t.purgeBlobs(q, sh.id)
	_, err := t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE ns = ?`, statePurged, sh.id)
	t.must(err)
	t.metaChanged = true
	_, err = t.Exec(`UPDATE namespaces SET purged = 1 WHERE ns = ?`, sh.id)
	t.must(err)
	t.flushDocs = true
}

// --- following the base, and registering with it ----------------------------

// remoteBase is a remote_bases row.
type remoteBase struct {
	shadow, branch int64
	origin, ns, at string
	checkpoint     string
	regNSID        sql.NullString
	regExpires     sql.NullInt64
	branchName     string
}

func (t *tx) remoteBases(where string, args ...any) []*remoteBase {
	rows, err := t.Query(`SELECT r.shadow, r.branch, r.origin, r.ns, r.at, r.checkpoint, r.reg_ns_id, r.reg_expires, n.name
		FROM remote_bases r JOIN namespaces n ON n.ns = r.branch WHERE `+where+` ORDER BY n.name`, args...)
	t.must(err)
	defer rows.Close()
	var out []*remoteBase
	for rows.Next() {
		b := &remoteBase{}
		t.must(rows.Scan(&b.shadow, &b.branch, &b.origin, &b.ns, &b.at, &b.checkpoint, &b.regNSID, &b.regExpires, &b.branchName))
		out = append(out, b)
	}
	return out
}

// RemoteNotice is a purge seen in a remote base's log (§G.3).
type RemoteNotice struct {
	Branch   string // the remote branch
	ID       string // the base's ns_id of the entry
	Kind     string // purge or purge-ns
	Resource string // purge: the resource name
	Applied  bool   // applied locally (§8.3), or only recorded
	Created  string
}

// RemoteNotices lists the purge notices of a remote branch ("" = all), oldest
// first.
func (e *Engine) RemoteNotices(ctx context.Context, ns string) ([]RemoteNotice, error) {
	var out []RemoteNotice
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT n.name, x.id, x.kind, x.resource, x.applied, x.created FROM remote_notices x JOIN namespaces n ON n.ns = x.branch
			WHERE ? = '' OR n.name = ? ORDER BY x.seq`, ns, ns)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var rn RemoteNotice
			var res sql.NullString
			var created int64
			t.must(rows.Scan(&rn.Branch, &rn.ID, &rn.Kind, &res, &rn.Applied, &created))
			rn.Resource, rn.Created = res.String, formatTime(created)
			out = append(out, rn)
		}
		return nil
	})
	return out, err
}

// SyncRemotes follows every live remote branch's base once: purges in its
// log since the last check are applied (or recorded as notices, with
// IgnorePurges), and with Register, registrations are made or renewed.
func (e *Engine) SyncRemotes(ctx context.Context) error {
	var bases []*remoteBase
	if err := e.read(ctx, func(t *tx) error {
		bases = t.remoteBases(`n.purged = 0`)
		return nil
	}); err != nil {
		return err
	}
	var errs []error
	for _, b := range bases {
		if err := e.jobStep(ctx); err != nil {
			errs = append(errs, err)
			break
		}
		if err := e.followRemote(ctx, b); err != nil {
			errs = append(errs, fmt.Errorf("remote branch %s: following %s/ns/%s: %w", b.branchName, b.origin, b.ns, err))
		}
		if !e.opt.Remote.Register {
			continue
		}
		if b.regNSID.Valid && e.now().Before(time.UnixMilli(b.regExpires.Int64).Add(-e.opt.Remote.RenewBefore)) {
			continue
		}
		if err := e.RegisterRemote(ctx, b.branchName); err != nil {
			errs = append(errs, fmt.Errorf("remote branch %s: registering with %s: %w", b.branchName, b.origin, err))
		}
	}
	return errors.Join(errs...)
}

// followRemote applies the purges in a base's log after the checkpoint
// (§G.3: on purge or purge-ns, §8.3 applies locally to the branch's own
// chains for that name, its own branches and its cache tags).
func (e *Engine) followRemote(ctx context.Context, b *remoteBase) error {
	c, _, err := e.remoteClient(b.origin)
	if err != nil {
		return err
	}
	entries, head, err := verify.Namespace(ctx, c, b.ns, b.checkpoint)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	follow := !e.opt.Remote.IgnorePurges
	return e.update(ctx, func(t *tx) error {
		// The branch's lock first: the checkpoint is read as of it.
		bn := t.nsByIDLocked(b.branch, lockExclusive)
		var cp string
		t.must(t.QueryRow(`SELECT checkpoint FROM remote_bases WHERE shadow = ?`, b.shadow).Scan(&cp))
		if cp != b.checkpoint {
			return nil // followed concurrently
		}
		author := t.authorID(RemoteAuthor)
		for _, en := range entries {
			var names []string
			switch en.Kind {
			case "purge":
				names = []string{en.Resource}
			case "purge-ns":
				// Every name the base had, including those it read
				// through from its own bases.
				set := map[string]bool{}
				for _, sh := range t.remoteShadows(bn) {
					rows, err := t.Query(`SELECT name FROM resources WHERE ns = ?`, sh.id)
					t.must(err)
					for rows.Next() {
						var s string
						t.must(rows.Scan(&s))
						set[s] = true
					}
					rows.Close()
				}
				names = sortedKeys(set)
			default:
				continue
			}
			var res any
			if en.Kind == "purge" {
				res = en.Resource
			}
			applied := follow && !bn.purged
			_, err := t.Exec(`INSERT INTO remote_notices (branch, id, kind, resource, applied, created) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
				bn.id, en.ID, en.Kind, res, applied, t.now.UnixMilli())
			t.must(err)
			if !applied {
				log.Printf("remote branch %s: %s %v in %s/ns/%s recorded as a notice, not applied", bn.name, en.Kind, names, b.origin, b.ns)
				continue
			}
			for _, name := range names {
				t.purgeResource(bn, name, author, false)
			}
		}
		_, err := t.Exec(`UPDATE remote_bases SET checkpoint = ? WHERE shadow = ?`, head, b.shadow)
		t.must(err)
		return nil
	})
}

// RegisterRemote registers a remote branch with its base, or renews its
// registration (§G.3). It needs read and export at the base, through the
// endpoint's bearer grant.
func (e *Engine) RegisterRemote(ctx context.Context, ns string) error {
	var b *remoteBase
	if err := e.read(ctx, func(t *tx) error {
		bs := t.remoteBases(`n.name = ?`, ns)
		if len(bs) == 0 {
			return notFound()
		}
		b = bs[0]
		return nil
	}); err != nil {
		return err
	}
	if !ValidRemoteOrigin(e.opt.Origin) {
		return fmt.Errorf("this deployment's origin %q is not an https origin (or http on a loopback host)", e.opt.Origin)
	}
	c, ep, err := e.remoteClient(b.origin)
	if err != nil {
		return err
	}
	body := map[string]any{"remote": map[string]any{"origin": e.opt.Origin, "ns": ns}, "at": b.at}
	precond := map[string]string{"If-None-Match": "*"}
	if b.regNSID.Valid {
		precond = map[string]string{"If-Match": `"` + b.regNSID.String + `"`}
	}
	res, err := postRegistration(ctx, ep, c.BaseURL(), b.ns, body, precond)
	if ae, ok := client.AsAPIError(err); ok && ae.Status == 412 && ae.Head() != "" {
		// A registration of ours whose answer was lost, or one that is
		// still unexpired: renew it.
		res, err = postRegistration(ctx, ep, c.BaseURL(), b.ns, body, map[string]string{"If-Match": `"` + ae.Head() + `"`})
	}
	if err != nil {
		return err
	}
	nsID, _ := res["ns_id"].(string)
	exp, _ := res["expires"].(string)
	expT, perr := time.Parse(time.RFC3339Nano, exp)
	if nsID == "" || perr != nil {
		return fmt.Errorf("unexpected registration response %v", res)
	}
	return e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE remote_bases SET reg_ns_id = ?, reg_expires = ? WHERE shadow = ?`, nsID, expT.UnixMilli(), b.shadow)
		t.must(err)
		return nil
	})
}

// remoteLoop follows remote bases every interval until Close.
func (e *Engine) remoteLoop(interval time.Duration) {
	defer e.bg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-e.stop:
				case <-ctx.Done():
				}
				cancel()
			}()
			if !e.leader(ctx) {
				cancel()
				continue // another instance follows them (pglock.go)
			}
			if err := e.SyncRemotes(leaderJob(ctx)); err != nil {
				log.Printf("remote: %v", err)
			}
			cancel()
		}
	}
}

func mustID(s string) ids.ID {
	id, err := ids.Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

// postRegistration sends a registration to the base (§G.3) and returns the
// answer's body; a failure is a *client.APIError.
func postRegistration(ctx context.Context, ep RemoteEndpoint, baseURL, ns string, body map[string]any, precond map[string]string) (map[string]any, error) {
	path := "/ns/" + ns + "/branches"
	hr, err := http.NewRequestWithContext(ctx, "POST", baseURL+path, strings.NewReader(string(jsonv.Canonical(jsonv.FromGo(body)))))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	for k, v := range precond {
		hr.Header.Set(k, v)
	}
	if ep.Bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+ep.Bearer)
	}
	res, err := ep.HTTPClient.Do(hr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if v, perr := jsonv.Parse(b); perr == nil {
		m, _ = v.(map[string]any)
	}
	if res.StatusCode != 200 && res.StatusCode != 201 {
		code, _ := m["code"].(string)
		return nil, &client.APIError{Status: res.StatusCode, Code: code, Body: m, Method: "POST", Path: path}
	}
	return m, nil
}
