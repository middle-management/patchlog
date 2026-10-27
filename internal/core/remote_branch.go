package core

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
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
// nothing on this side blocks the base (§7.6). So do raises of the base's
// level and its read made non-public, which the branch follows (§G.5.2,
// followConfig).
//
// Encryption (§G.5). A base that isn't public, or is sealed or e2e, binds
// the branch: it must be private or sealed (a sealed branch of a sealed
// base may be public, as for local branches), never below the base's
// encryption level, and e2e only if the base is. That is what A's export
// grant entrusts to B, and B enforces it at creation, in the config writes
// its base's current document judges (checkRemoteSource), and by raising
// its level when the base's rises (followLevel), or, on a server that
// lacks the level, answering 502 upstream for what it mirrored (§1,
// upstream.go). The shadows follow the branch's level (at rest, and for
// sealing and e2e).
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
func (t *gate) remoteShadow(n *nsRow) *nsRow {
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

// localIdentity is local namespace n's baseIdentity as a base of its
// branches.
func (t *tx) localIdentity(n *nsRow) string { return fmt.Sprint(n.id) }

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

// upstreamErr is the 502 of a remote branch's creation that failed at its
// base's deployment (§G.3, §12.1): it didn't answer, answered 5xx, or served
// data that fails verification. fetchRemote adds origin, naming that
// deployment, to every such 502 it returns.
func upstreamErr(format string, a ...any) *Error {
	return apiErr(502, "upstream", "message", fmt.Sprintf(format, a...))
}

// unverified reports source data that fails verification.
func unverified(format string, a ...any) *Error {
	return upstreamErr("%s", "the base's data failed verification: "+fmt.Sprintf(format, a...))
}

// noAnswer reports a failed fetch where the base's deployment didn't
// answer, or answered 5xx: only that is 502 upstream at creation (§G.3).
func noAnswer(err error) bool {
	if ae, ok := client.AsAPIError(err); ok {
		return ae.Status >= 500
	}
	var ue *url.Error
	var ne net.Error
	return errors.As(err, &ue) || errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded)
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

// fetchErr maps a failed fetch from the base (§G.3, §G.5.2). What the base
// answers is a base this deployment can't read, 422, but for its 410s
// (pruned, gone or purged, levelErr); only no answer, or a 5xx, is 502
// upstream. Keys this deployment can't get leave the base unreadable too.
func fetchErr(what string, err error) *Error {
	if ae, ok := client.AsAPIError(err); ok {
		switch {
		case ae.Status == 404:
			return invalid(fmt.Sprintf("%s: not found at the base (at not in its chain, or not readable)", what))
		case ae.Status == 401 || ae.Status == 403:
			return invalid(fmt.Sprintf("%s: the base refused access (%d), so this deployment can't read it; "+
				"the endpoint's grant needs unrestricted read there (§G.3, §G.5.2)", what, ae.Status))
		case ae.Status == 410 && ae.Code == "pruned":
			return apiErr(410, "pruned", "message", what+": history needed at at was pruned at the base", "horizon", ae.Horizon())
		case ae.Status == 410:
			return gone("message", what+": gone at the base")
		case ae.Status >= 500:
			return upstreamErr("%s: %d from the base", what, ae.Status)
		}
		return invalid(fmt.Sprintf("%s: the base answered %d, so this deployment can't read it (§G.3)", what, ae.Status))
	}
	if errors.Is(err, client.ErrNoKeys) {
		return invalid(fmt.Sprintf("%s: the base is sealed (Addendum E.2) and its keys aren't available to this deployment, so it can't read it; "+
			"the endpoint's grant must get them from the base's POST /ns/{ns}/keys (§G.5.2)", what))
	}
	return upstreamErr("%s: %v", what, err)
}

// schemaFetchErr maps a failed fetch of a referenced schema revision from
// its namespace at the base (§G.3): a revision that doesn't resolve there,
// as with a draft in a branch (§6.1), or that is purged there, can't be
// mirrored, and creation fails with 422 (§12: unknown, purged or
// unreadable, as a 401 or 403 is). A schema namespace isn't in the base's
// chain, so its purge is no purged base (purgedBase).
func schemaFetchErr(ref schema.Ref) func(string, error) *Error {
	return func(what string, err error) *Error {
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == 404 || ae.Status == 401 || ae.Status == 403 || ae.Status == 410 && ae.Code != "pruned") {
			return schemaUnavailable(ref.Path(), "message",
				ref.Path()+" doesn't resolve in "+ref.NS+" at the base (a draft in a branch there, §6.1, purged, or unreadable); "+
					"a remote branch mirrors schema revisions only from their own namespace (§G.3)")
		}
		return fetchErr(what, err)
	}
}

// purgedBase is the 410 of a remote branch whose base, or a base in its
// chain, is purged (§G.3, §8.5): origin, ns and head name the purged
// namespace and its purge-ns entry there (§12).
func purgedBase(origin, ns, head string) *Error {
	return apiErr(410, "purged", "origin", origin, "ns", ns, "head", head, "message",
		"the remote base, or a base in its chain, is purged: "+origin+"/ns/"+ns+" (§G.3, §8.5)")
}

// purgedAt reports the head of a 410 purged the base answered for one of a
// namespace's URLs (§8.5).
func purgedAt(err error) (string, bool) {
	if ae, ok := client.AsAPIError(err); ok && ae.Status == 410 && ae.Code == "purged" {
		return ae.Head(), true
	}
	return "", false
}

// levelErr is mapErr for the URLs of ns, a namespace of the base's chain:
// the base's 410 purged for one of them names ns as the purged base
// (§G.3), which mapErr would answer as a purged resource.
func levelErr(origin, ns string, mapErr func(string, error) *Error) func(string, error) *Error {
	return func(what string, err error) *Error {
		if head, ok := purgedAt(err); ok {
			return purgedBase(origin, ns, head)
		}
		return mapErr(what, err)
	}
}

// --- fetching and verifying the base -------------------------------------

// remoteChain is a verified resource chain from the base, oldest first. If
// the base had pruned it, entries[0] is the horizon, without its patch set
// and with the horizon's document as horizonDoc (§8.6): ids from the horizon
// on are verified; the horizon's document is only as trustworthy as the
// channel.
type remoteChain struct {
	ns         string // the namespace it was fetched from
	entries    []client.LogEntry
	horizonDoc []byte
	index      map[string]int
	// opaque marks e2e content (§E.3): patch sets are ciphertext, never
	// applied, and the chain has no documents. In a level raised to e2e,
	// the first plain entries are from before the raise (plainPrefix): in
	// the clear, as the base serves them (Addendum E Levels), with
	// documents as in a chain that isn't opaque.
	opaque bool
	plain  int
	// blobs are the blobs its documents reference, fetched from the base
	// and verified (remote_blobs.go).
	blobs map[ids.ID]*remoteBlob
	// rules are the schema rules markers the base serves for the
	// chain's schema documents, by entry id (fetchRules): the rows that
	// mirror them keep them, so a revision compiles here as it does there
	// (§6.1, F-S1). An entry the base sends none for is stored without one
	// (NULL, read as Legacy).
	rules map[string]schema.Rules
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
	p.ns, p.opaque, p.blobs, p.rules = c.ns, c.opaque, c.blobs, c.rules
	p.plain = min(c.plain, len(p.entries))
	return p
}

// plainPrefix is the number of an opaque chain's first entries that come
// before its first sealed op (§E.3.1): in a level raised to e2e, content
// from before the raise, which the base serves at the level before it, in
// the clear or sealed, which the client opens (Addendum E Levels). A
// restore with [] there keeps the last live document, before the raise or
// after it alike.
func (c *remoteChain) plainPrefix() int {
	for i, e := range c.entries {
		if e.Kind == "rev" && e.HasPatches {
			if _, _, ok := seal.SealedOp(e.Patches); ok {
				return i
			}
		}
	}
	return len(c.entries)
}

// fetchRules reads, for each schema document of ch, the rules marker the
// base serves its revision with (schema.RulesHeader, a HEAD of the
// revision): one request per schema revision, none for other documents
// or an opaque chain. mapErr maps a failed request, as for fetchChain.
func fetchRules(ctx context.Context, c *client.Client, ns, name string, ch *remoteChain, mapErr func(string, error) *Error) *Error {
	if ch.opaque || !ch.mentionsDialect() {
		return nil
	}
	var ferr *Error
	err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		if e.Kind != "rev" || !schema.IsSchemaDoc(doc) {
			return nil
		}
		if _, done := ch.rules[e.ID]; done {
			return nil
		}
		r, known, err := c.SchemaRules(ctx, ns, name, e.ID)
		if err != nil {
			ferr = mapErr("/r/"+ns+"/"+name+"/rev/"+e.ID, err)
			return errStop
		}
		if known {
			if ch.rules == nil {
				ch.rules = map[string]schema.Rules{}
			}
			ch.rules[e.ID] = r
		}
		return nil
	})
	if ferr != nil {
		return ferr
	}
	if err != nil {
		return unverified("/r/%s/%s: %v", ns, name, err)
	}
	return nil
}

// mentionsDialect reports whether any document of the chain may be a
// schema document: its horizon's document or a patch set names the
// dialect URL, which every schema
// document's $schema does. A chain without it needn't be folded for
// markers.
func (c *remoteChain) mentionsDialect() bool {
	dialect := []byte(schema.Dialect2020)
	if bytes.Contains(c.horizonDoc, dialect) {
		return true
	}
	for _, e := range c.entries {
		if e.HasPatches && bytes.Contains(jsonv.Canonical(e.Patches), dialect) {
			return true
		}
	}
	return false
}

// fold walks the chain, calling f with each entry and the document after it
// (for a tombstone, the last live document). An opaque chain has no
// documents: f gets nil.
func (c *remoteChain) fold(f func(i int, e client.LogEntry, doc any) error) error {
	var doc any
	exists := false
	for i, e := range c.entries {
		switch {
		case c.opaque && i >= c.plain && (e.Kind == "rev" || e.Kind == "tombstone"):
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
			// A genesis applies to the document null (§6.2 step 3).
			doc, _, err = patch.Apply(doc, true, ops, patch.Options{})
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
// maps a failed fetch (the level's levelErr over fetchErr, or over
// unreadableBase for a base's base, or schemaFetchErr).
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
		ch.ns, ch.opaque = ns, opaque
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
	ch.ns = ns
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
	// raise is the index in log of the entry that raised an e2e level to
	// e2e before at, -1 if it was e2e from its creation (Addendum E
	// Levels); preEnc is its encryption member before (nil for none), and
	// from sealed, preEpochs are the epochs before the raise with when each
	// began, which only the source's own log gives (§G.5.2), and preKeys
	// the keys of those its source's /keys gave this deployment's grant
	// (fetchPreRaiseKeys), which the branch's /keys gives as at E2.
	raise     int
	preEnc    map[string]any
	preEpochs []epochStart
	preKeys   map[int][]byte
	// nonce: the base itself (level 0) requires nonces as of at (§C.7).
	nonce bool
}

// remoteMirror is the base as of at, verified.
type remoteMirror struct {
	base    *BaseRef
	read    string // the base's current read mode (as served; §G.5.2)
	level   int    // the base's current encryption level (as served)
	levels  []*remoteLevel
	schemas []*remoteSchema
	// schemaSources: the schemas' source namespaces at the base, as their
	// current namespace documents give them (fetchSchemaSources).
	schemaSources map[string]schemaSource
}

// Protection ranks (§2.1): public < private = sealed < e2e.
const (
	rankPublic = iota
	rankPrivate
	rankE2E
)

// schemaSource is what a remote branch's schema mirror takes from its
// source namespace at the base (§G.3): its protection as a source (§2.1),
// and whether it requires nonces (§C.7).
type schemaSource struct {
	rank  int
	nonce bool
}

// sourceRank is the protection of a namespace document as a source
// (§2.1): e2e at E3, sealed (ranked as private) at E2 whatever its read,
// and otherwise public or private by its read. A level this deployment
// doesn't know counts as the strictest.
func sourceRank(doc map[string]any) int {
	if enc, ok := doc["encryption"].(map[string]any); ok {
		lv, _ := enc["level"].(string)
		switch levelOf(lv) {
		case levelE2E, levelNone:
			return rankE2E
		case levelSealed:
			return rankPrivate
		}
	}
	if doc["read"] == "public" {
		return rankPublic
	}
	return rankPrivate
}

// targetRank is the protection of a namespace of this deployment as a
// target (§2.1): as a source, except that a sealed one whose read is
// public is public.
func targetRank(cfg *Config) int {
	switch {
	case cfg.level == levelE2E:
		return rankE2E
	case cfg.Read == "public":
		return rankPublic
	}
	return rankPrivate
}

// fetchSchemaSources reads the current namespace document of each source
// namespace of a remote branch's schema closure at the base (§G.3). One
// this deployment can't read counts as private (§2.1) and leaves the
// nonce setting optional (§C.7): mirroring writes nothing through the
// gate, so only later writes here would be checked. Only no answer, or a
// 5xx, fails creation (502).
func fetchSchemaSources(ctx context.Context, c *client.Client, schemas []*remoteSchema) (map[string]schemaSource, *Error) {
	out := map[string]schemaSource{}
	for _, s := range schemas {
		if _, done := out[s.ns]; done {
			continue
		}
		src := schemaSource{rank: rankPrivate}
		d, err := currentNSDoc(ctx, c, s.ns)
		switch {
		case err == nil:
			src = schemaSource{rank: sourceRank(d.Value), nonce: d.Value["nonce"] == "required"}
		case noAnswer(err):
			return nil, upstreamErr("/ns/%s: %v", s.ns, err)
		}
		out[s.ns] = src
	}
	return out, nil
}

// fetchLevel fetches and verifies a namespace's log up to at, and its
// configuration genesis. next is its base, if it is a branch. Members of
// the base's namespace documents this deployment doesn't define are
// ignored (§7.4, §G.3): nothing of them is copied. A log that ends at a
// purge-ns entry is a purged base at origin (§G.3).
func fetchLevel(ctx context.Context, c *client.Client, origin, ns, at string, mapErr func(string, error) *Error) (*remoteLevel, *BaseRef, *Error) {
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
	lv := &remoteLevel{ns: ns, at: at, log: log, byName: map[string]*remoteRes{}, raise: -1}
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
			// The log's last entry (§8.5): at is the purge itself. A's
			// /heads answers that first, so this is a backstop.
			return nil, nil, purgedBase(origin, ns, en.ID)
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

// unknownLevel refuses a remote branch whose base's current namespace
// document can't be read: without it, B can't tell how protected the base
// is (§G.5.2). No answer, or a 5xx, stays a 502; anything else the base
// answered, or a document B can't open, is 422.
func unknownLevel(base *BaseRef, err error) *Error {
	what := "/ns/" + base.NS
	msg := fmt.Sprintf("%s: this deployment can't read the base's namespace document (%v), so it can't tell how protected the base is; "+
		"a remote branch is refused then (§G.5.2): the endpoint's grant needs read on it, and keys if it is sealed", what, err)
	if noAnswer(err) {
		return upstreamErr("%s", msg)
	}
	return invalid(msg)
}

// currentNSDoc fetches a namespace's current document at the base: the
// one at its head.
func currentNSDoc(ctx context.Context, c *client.Client, ns string) (*client.NSDoc, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	return c.NSDoc(ctx, ns, h.ID)
}

// docLevel is the encryption level a namespace document of the base
// declares; one this deployment doesn't know counts as the strictest.
func docLevel(doc map[string]any) int {
	enc, ok := doc["encryption"].(map[string]any)
	if !ok {
		return levelNone
	}
	lv, _ := enc["level"].(string)
	if l := levelOf(lv); l != levelNone {
		return l
	}
	return levelE2E
}

// fetchEpochs reads an e2e level's encryption member as of its at, and its
// epochs with when each began: the created time of the first entry of its
// log whose configuration names it (§E.3.2). Configuration documents are
// only as trustworthy as the channel; they only decide which epochs a grant
// on this side gets relayed (§E.2.3). A level raised to e2e before at
// (Addendum E Levels) has configurations below e2e before the raise: the
// raise, what was in force before it and, from sealed, the epochs before it
// are recorded too (remoteLevel.raise), whose keys fetchPreRaiseKeys gets.
// Levels never go down, so a level below e2e after an e2e one fails
// verification.
func (e *Engine) fetchEpochs(ctx context.Context, c *client.Client, lv *remoteLevel, mapErr func(string, error) *Error) *Error {
	docOf := func(nsID string) (map[string]any, *Error) {
		d, err := c.NSDoc(ctx, lv.ns, nsID)
		if err != nil {
			return nil, mapErr("/ns/"+lv.ns+"/rev/"+nsID, err)
		}
		return d.Value, nil
	}
	epochOf := func(enc map[string]any) int {
		ep := 1
		if f, ok := enc["epoch"].(float64); ok {
			ep = int(f)
		}
		return ep
	}
	atDoc, ferr := docOf(lv.at)
	if ferr != nil {
		return ferr
	}
	enc, _ := atDoc["encryption"].(map[string]any)
	if docLevel(atDoc) != levelE2E {
		return unverified("/ns/%s: an e2e base's chain holds a namespace that isn't e2e at at", lv.ns)
	}
	cur := epochOf(enc)
	if lv.enc, ferr = e.shadowEncryption(lv.ns, enc); ferr != nil {
		return ferr
	}
	lv.raise = -1
	seen, preSeen := map[int]bool{}, map[int]bool{}
	prev := -1 // the level of the last configuration read
	var prevEnc map[string]any
	for i, en := range lv.log {
		if !configChanged(en) {
			continue
		}
		d, ferr := docOf(en.ID)
		if ferr != nil {
			return ferr
		}
		enc, _ := d["encryption"].(map[string]any)
		level, ep := docLevel(d), epochOf(enc)
		created := time.UnixMilli(parseCreated(en.Created, time.Now()))
		switch {
		case level == levelE2E:
			if prev >= 0 && prev < levelE2E {
				lv.raise = i
				if prevEnc != nil {
					if lv.preEnc, ferr = e.shadowEncryption(lv.ns, prevEnc); ferr != nil {
						return ferr
					}
				}
			}
			if !seen[ep] && ep <= cur {
				seen[ep] = true
				lv.epochs = append(lv.epochs, epochStart{e: ep, created: created})
			}
		case prev == levelE2E:
			return unverified("/ns/%s: its encryption level went down from e2e (Addendum E Levels)", lv.ns)
		case level == levelSealed && !preSeen[ep]:
			preSeen[ep] = true
			lv.preEpochs = append(lv.preEpochs, epochStart{e: ep, created: created})
		}
		prev, prevEnc = level, enc
	}
	return nil
}

// fetchPreRaiseKeys gets, for a level raised to e2e from sealed before at,
// the keys of its epochs before the raise from the source's POST
// /ns/{ns}/keys with this deployment's grant (Addendum E Levels, §G.3
// Reading through): they are the origin's, given as at E2, raw or wrapped
// to the grant's enc in base mode, which the endpoint's Identity unwraps.
// The branch's /keys gives them to its own grants as at E2 (preRaiseKeys),
// with start times only from the source's own log (§G.5.2). Keys the source
// gives this grant none of, it relays none of; keyring entries (from) are
// the mirrored keyring's. Only no answer, or a 5xx, fails creation.
func fetchPreRaiseKeys(ctx context.Context, c *client.Client, ep RemoteEndpoint, lv *remoteLevel) *Error {
	if lv.raise < 0 || len(lv.preEpochs) == 0 {
		return nil
	}
	epochs := make([]int, len(lv.preEpochs))
	for i, x := range lv.preEpochs {
		epochs[i] = x.e
	}
	got, err := c.FetchKeys(ctx, lv.ns, epochs, nil)
	if err != nil {
		if noAnswer(err) {
			return upstreamErr("/ns/%s/keys: %v", lv.ns, err)
		}
		log.Printf("remote base %s: its keys of the epochs before its raise to e2e: %v; the branch gives none of them", lv.ns, err)
		return nil
	}
	lv.preKeys = map[int][]byte{}
	for _, k := range got {
		kns, e, err := seal.ParseKid(k.Kid)
		if err != nil || kns != lv.ns || k.From != "" || k.Resource != "" || !slices.Contains(epochs, e) {
			continue
		}
		key := k.Key
		if key == nil {
			if ep.Identity == nil {
				continue
			}
			if key, err = seal.UnwrapKey(ep.Identity, k.Wrapped); err != nil {
				continue
			}
		}
		if len(key) == seal.KeySize {
			lv.preKeys[e] = key
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
func (e *Engine) fetchRemote(ctx context.Context, base *BaseRef) (_ *remoteMirror, failed *Error) {
	defer func() {
		// A 502 names the remote base's deployment (§12.1).
		if failed != nil && failed.Code() == "upstream" {
			failed.Body["origin"] = base.Origin
		}
	}()
	c, ep, err := e.remoteClient(base.Origin)
	if err != nil {
		return nil, upstreamErr("%s: %v", base.Origin, err)
	}
	root, err := c.Root(ctx)
	if err != nil {
		return nil, fetchErr("GET /", err)
	}
	if root.Origin != base.Origin {
		return nil, upstreamErr("the deployment reached for %s publishes the origin %q", base.Origin, root.Origin)
	}
	m := &remoteMirror{base: base, read: "grant"}
	// A 410 purged for a namespace's URLs names it (levelErr). A's own
	// purge is found before any base's: a base can't be purged while A,
	// its dependent, lives (§8.5), so the first one found is named.
	mapErrs := []func(string, error) *Error{levelErr(base.Origin, base.NS, fetchErr)}
	// The listing the spec reads (§G.3), checked against the logs below.
	// It comes first: for a purged A it is 410 purged at any revision,
	// once A's read check passes and before any other answer (§8.5), so a
	// purged base is 410 as for a local branch (§7.6) even with an at A
	// doesn't know, or a log A can't deliver.
	heads, err := c.Heads(ctx, base.NS, base.At)
	if err != nil {
		return nil, mapErrs[0]("/ns/"+base.NS+"/rev/"+base.At+"/heads", err)
	}
	ns, at := base.NS, base.At
	for {
		mapErr := mapErrs[len(mapErrs)-1]
		lv, next, ferr := fetchLevel(ctx, c, base.Origin, ns, at, mapErr)
		if ferr != nil {
			return nil, ferr
		}
		m.levels = append(m.levels, lv)
		if len(m.levels) == 1 {
			// The base's protection comes from its current namespace
			// document, as a local branch's creation is judged by its
			// base's (§G.5.2, §7.4): its read, level and nonce setting,
			// which merging back must pass there now (§C.7). Sealed ones
			// are decrypted with the endpoint's keys. One B can't read is
			// refused: its protection can't be told (§G.5.2).
			d, err := currentNSDoc(ctx, c, base.NS)
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
			m.level = docLevel(d.Value)
			lv.nonce = d.Value["nonce"] == "required" && m.level != levelE2E
			if m.level == levelE2E {
				// A branch of a raised base can't be created with an at
				// before its e2e raise (Addendum E, Levels): the epoch
				// key in force at an earlier at also opens what the base
				// sealed after it. The base's document as of at says
				// whether the raise lies after at.
				ad, err := c.NSDoc(ctx, base.NS, base.At)
				if err != nil && noAnswer(err) {
					return nil, upstreamErr("/ns/%s/rev/%s: %v", base.NS, base.At, err)
				}
				if err != nil || docLevel(ad.Value) != levelE2E {
					return nil, docInvalid("/base/at", "/base/at is before the base's raise to e2e: a branch of a raised base "+
						"can't be created with an at before its e2e raise (Addendum E, Levels, §G.5.2); create it at a later at, such as the base's head")
				}
			}
		}
		if next == nil {
			break
		}
		// The remote branch is a branch of every namespace of the chain:
		// the branch-depth limit counts them all (§6.6).
		if len(m.levels)+1 > e.opt.Maximums.BranchDepth {
			return nil, limitErr(422, "branchDepth", int64(len(m.levels)+1), int64(e.opt.Maximums.BranchDepth), fmt.Sprintf("branch depth exceeded: the remote base's chain has more than %d namespaces", e.opt.Maximums.BranchDepth))
		}
		ns, at = next.NS, next.At
		mapErrs = append(mapErrs, levelErr(base.Origin, ns, unreadableBase(ns)))
	}
	opaque, raised := m.level == levelE2E, false
	if opaque {
		for i, lv := range m.levels {
			if ferr := e.fetchEpochs(ctx, c, lv, mapErrs[i]); ferr != nil {
				return nil, ferr
			}
			if ferr := fetchPreRaiseKeys(ctx, c, ep, lv); ferr != nil {
				return nil, ferr
			}
			raised = raised || lv.raise >= 0
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
		if ch.opaque && raised {
			// History from before a raise to e2e (MF-37).
			ch.plain = ch.plainPrefix()
		}
		if ferr := fetchRules(ctx, c, lv.ns, name, ch, mapErrs[i]); ferr != nil {
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
		s := schemas[k]
		ref := schema.Ref{NS: s.ns, Name: s.name, Rev: s.chain.last().ID}
		if ferr := fetchRules(ctx, c, s.ns, s.name, s.chain, schemaFetchErr(ref)); ferr != nil {
			return nil, ferr
		}
		m.schemas = append(m.schemas, s)
	}
	sources, ferr := fetchSchemaSources(ctx, c, m.schemas)
	if ferr != nil {
		return nil, ferr
	}
	m.schemaSources = sources
	return m, nil
}

// --- creating a remote branch ----------------------------------------------

// checkRemoteGenesis authenticates the operator grant, checks it for
// config, and checks the genesis of a remote branch (§C.4, §G.3).
func (t *gate) checkRemoteGenesis(req Request, cc ConfigChange) (*Config, map[string]any, *actor, *Error) {
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
	// The operator grant is checked for config, which covers the schema
	// histories the creation mirrors and the namespaces it creates for
	// them (§C.2, §C.4).
	if aerr := t.authorize(a, "config", ""); aerr != nil {
		return nil, nil, nil, aerr
	}
	ops, err := patch.Parse(cc.Patches)
	if err != nil {
		return nil, nil, nil, patchErr(err)
	}
	doc, _, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return nil, nil, nil, patchErr(err)
	}
	// Step 4: a creation counts as a create, held to the deployment's
	// defaults, as createNamespace's (§6.6).
	if err := checkConfigLimits(t.e.opt.Limits, cc.Patches, jsonv.Canonical(cc.Patches), true, jsonv.Canonical(doc), func() bool { return true }); err != nil {
		return nil, nil, nil, err
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
	if cfg.Base.Chain == nil {
		// The creator gives chain, checked once the base is verified
		// (insertRemoteBranch); the genesis is never rewritten (§G.3).
		return nil, nil, nil, docInvalid("/base/chain", `/base/chain is missing: a remote branch's genesis gives the base's namespace, then its base, and so on, as of at, e.g. "chain": [`+
			strconv.Quote(cfg.Base.NS)+`] for a base that isn't a branch (§G.3)`)
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
		r, err := t.insertRemoteBranch(req, cc, cfg, doc, m, a)
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
// branch, all verified before the transaction opened. It first finishes
// the genesis checks that need the base (§G.3, §G.5), then runs step 6
// for a, the operator grant that creates it (checkCreationRules).
func (t *tx) insertRemoteBranch(req Request, cc ConfigChange, cfg *Config, doc map[string]any, m *remoteMirror, a *actor) (*WriteResult, *Error) {
	if oerr := remoteObligations(req.NS, cfg, m); oerr != nil {
		return nil, oerr
	}
	// Step 6, after the genesis is validated: the creating operator
	// grant's own rules, as for a namespace's creation (§6.4.3, §C.2).
	if err := t.checkCreationRules(a, cc.Patches); err != nil {
		return nil, err
	}
	author := t.actorID(a)
	// The shadows' mirrored rows follow the branch's level.
	if t.shadowLevels == nil {
		t.shadowLevels = map[string]int{}
	}
	for i := range m.levels {
		t.shadowLevels[shadowLevelName(req.NS, i)] = cfg.level
	}
	if err := t.mirrorSchemas(m, req.NS, author); err != nil {
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

// remoteObligations checks the obligations of §G.5 that the base can't
// enforce, of a remote branch ns with configuration cfg over m, and its
// base.chain (§G.3).
func remoteObligations(ns string, cfg *Config, m *remoteMirror) *Error {
	if cfg.Read == "public" && m.read != "public" {
		return invalid("a branch of a non-public namespace cannot be public (§G.5): make it private (read: grant) or sealed")
	}
	if cfg.level < m.level {
		return invalid(fmt.Sprintf("/encryption: a branch cannot have a lower encryption level than its base, which is %s (§G.5)", levelNames[m.level]))
	}
	if cfg.level == levelE2E && m.level != levelE2E {
		return invalid("/encryption: a branch can be e2e only if its base is")
	}
	if m.levels[0].nonce && !cfg.NonceRequired {
		return invalid(`/nonce: the base requires nonces, so a remote branch of it must be created with "nonce": "required" too, or merging it back would fail (§C.7, §G.3)`)
	}
	// base.chain records the namespaces followed while verifying (§G.3):
	// readers of an e2e branch accept read-through ciphertext bound to any
	// of them. The genesis gives it (checkRemoteGenesis), and must give it
	// right; its config id is over the genesis as sent.
	chain := make([]any, len(m.levels))
	for i, lv := range m.levels {
		chain[i] = lv.ns
	}
	if !jsonv.Equal(anyStrings(cfg.Base.Chain), chain) {
		return docInvalid("/base/chain", fmt.Sprintf("/base/chain must be %s: the base's namespace, then its base, and so on, as of at (§G.3)", jsonv.Canonical(chain)))
	}
	if m.level == levelE2E && slices.Contains(cfg.Base.Chain, ns) {
		// A kid {ns}#{e} names one keyring (§F.8.1).
		return docInvalid("/base/chain", "/base/chain names "+ns+": a remote branch of an e2e base can't have the name of a namespace in its base.chain, "+
			"since read-through ciphertext keeps their names in pl.ns and kid (§G.5.2, §F.8.1)")
	}
	return nil
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
		lv := m.levels[i]
		sh, at = t.insertShadow(shadowLevelName(branch, i), m.read, lv, sh, at, heads)
		for _, x := range lv.epochs {
			_, err := t.Exec(`INSERT INTO e2e_epochs (ns, epoch, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`, sh.id, x.e, x.created.UnixMilli())
			t.must(err)
		}
		// The keys of the epochs before a raise from sealed, with the start
		// times the source's log gives them (preRaiseKeys).
		for _, x := range lv.preEpochs {
			if k := lv.preKeys[x.e]; k != nil {
				t.storeEpochKey(sh.id, x.e, k, x.created)
			}
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
	// A level raised to e2e before at (Addendum E Levels) has two
	// configurations: the one before the raise, in force at the entries
	// before it, and the e2e one from the raising entry on, so the shadow's
	// raise lies where the source's does (e2eRaiseOf).
	first := cdoc
	if lv.raise >= 0 {
		first = map[string]any{"read": read}
		if lv.preEnc != nil {
			first["encryption"] = lv.preEnc
		}
	}
	genesis := []any{map[string]any{"op": "add", "path": "", "value": first}}
	gcanon := jsonv.Canonical(genesis)
	cid := ids.Revision(nil, gcanon)
	var bid, bat, bcfg any
	if base != nil {
		bid, bat, bcfg = base.id, baseAt, base.configSeq
	}
	sid := t.mustInsert(`INSERT INTO namespaces (name, base, base_at, base_config_seq) VALUES (?,?,?,?) RETURNING ns`, name, bid, bat, bcfg)
	cseq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?) RETURNING seq`,
		sid, cid[:], string(gcanon), string(jsonv.Canonical(first)), remote, t.now.UnixMilli())
	preSeq := cseq
	if lv.raise >= 0 {
		raised := []any{map[string]any{"op": "replace", "path": "", "value": cdoc}}
		rcanon := jsonv.Canonical(raised)
		rid := ids.Revision(&cid, rcanon)
		cseq = t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,?,?,?,?,?) RETURNING seq`,
			sid, rid[:], preSeq, string(rcanon), string(jsonv.Canonical(cdoc)), remote, parseCreated(lv.log[lv.raise].Created, t.now))
		level, epoch, pad := levelNone, 0, 0
		if pre, perr := t.e.parseConfig(first); perr == nil {
			level = pre.level
			if level == levelSealed {
				epoch = pre.Epoch
				if pre.Pad {
					pad = 1
				}
			}
		}
		_, err := t.Exec(`INSERT INTO e2e_raises (ns, config_seq, level, epoch, pad, created) VALUES (?,?,?,?,?,?)`,
			sid, cseq, level, epoch, pad, parseCreated(lv.log[lv.raise].Created, t.now))
		t.must(err)
	}
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
		entryCfg := cseq
		if i < lv.raise {
			entryCfg = preSeq
		}
		atSeq = t.mustInsert(`INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created) VALUES (?,?,?,?,?,NULL,?,?,?,?) RETURNING seq`,
			sid, id[:], prev, nsKindCode(en.Kind), res, string(body), entryCfg, author, parseCreated(en.Created, t.now))
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
func (t *gate) remoteShadows(n *nsRow) []*nsRow {
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
			patches = t.putPatches(res, id, jsonv.Canonical(e.Patches), nil)
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
		// So is its via (§7.1): the delegatees of the grant the base's
		// entry was written under, which the mirror's log serves as the
		// base's does.
		var via any
		if len(e.Via) > 0 {
			via = string(jsonv.Canonical(anyStrings(e.Via)))
		}
		// The marker the base serves a schema revision with (fetchRules),
		// or none, read as Legacy (schemaload.go).
		var rules any
		if r, ok := ch.rules[e.ID]; ok && kind == kindRev {
			rules = int(r)
		}
		var size, digest any
		if kind == kindRev && !ch.opaque && i == len(ch.entries)-1 && t.resLevel(res) < levelAtRest {
			// The head the chain leaves (headMeta), but not in a shadow
			// or namespace encrypted at all: a sealed one never lists
			// them, and at rest they would sit in plaintext (§E.1).
			sz, sum := headMeta(canonDoc)
			size, digest = sz, sum
		}
		last = t.mustInsert(`INSERT INTO revisions (res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules) VALUES (?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,?) RETURNING seq`,
			res, id[:], parentSeq, first, kind, patches, author, via, sig, typed, parseCreated(e.Created, t.now), gesture, undoes, size, digest, rules)
		parentSeq = last
		if e.Kid != "" {
			// Served sealed by its source, which serves it under the epoch
			// the kid names: a revision from before a raise from sealed
			// keeps that epoch (Addendum E Levels), which a prune snapshot
			// of it names (§E.3.1, preRaiseEpoch).
			if kns, ep, err := seal.ParseKid(e.Kid); err == nil && kns == ch.ns {
				_, err := t.Exec(`INSERT INTO rev_epochs (seq, epoch) VALUES (?,?)`, last, ep)
				t.must(err)
			}
		}
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
// genesis document { "read": "public" } if its source at the base is
// public (§2.1), and { "read": "grant" } otherwise, and takes its source's
// nonce setting once its history is in (requireNonces, §C.7). A mirror,
// created or existing, that ranks below its source is 422 (§2.1). A path
// whose chain neither contains the base's nor is a prefix of it, or a
// namespace that is a branch, is 409 name_conflict. A namespace that
// refuses the history answers as it refuses it: 410 purged, 410 gone for a
// purged resource, and, where history would be written, 409 frozen, or 422
// at e2e, where only a key holder seals content (§2.1, §E.3.1). Every
// resource of a namespace is judged before anything is written to it. The
// entries it writes record the creating operator as author and its grant
// (§7.4).
func (t *tx) mirrorSchemas(m *remoteMirror, branch string, author int64) *Error {
	type change struct {
		name string
		kind string
		head int64
		res  int64
	}
	// write is history to write: s.chain from from on, onto parent, into
	// res (0 for a new resource row).
	type write struct {
		s      *remoteSchema
		res    int64
		from   int
		parent *revRow
	}
	byNS := map[string][]*remoteSchema{}
	for _, s := range m.schemas {
		byNS[s.ns] = append(byNS[s.ns], s)
	}
	for _, nsName := range sortedKeys(byNS) {
		n := t.nsForWrite(nsName)
		path := func(s *remoteSchema) string { return "/r/" + s.ns + "/" + s.name + "/rev/" + s.chain.last().ID }
		conflict := func(s *remoteSchema, why string) *Error {
			return apiErr(409, "name_conflict", "path", path(s), "message", why)
		}
		if nsName == branch || n != nil && n.isBranch() {
			return conflict(byNS[nsName][0], "the schema namespace here is a branch")
		}
		if n != nil && n.purged {
			// It refuses the history as any write to it (§8.5).
			e := t.purgedNS(n)
			e.Body["ns"] = nsName
			e.Body["message"] = "the schema namespace " + nsName + " here is purged, so the schemas can't be mirrored into it (§G.3, §8.5)"
			return e
		}
		src := m.schemaSources[nsName]
		created := n == nil
		if created {
			read := "grant"
			if src.rank == rankPublic {
				read = "public"
			}
			doc := map[string]any{"read": read}
			n, _, _ = t.insertNamespace(nsName, []any{map[string]any{"op": "add", "path": "", "value": doc}}, doc, false, author)
		}
		cur := t.config(n.configSeq)
		if rank := targetRank(cur); rank < src.rank {
			return invalid(fmt.Sprintf("the schema namespace %s here is less protected than its source at the base (§2.1): "+
				"a remote branch's schema mirror never ranks below its source (§G.3)", nsName))
		}
		var writes []write
		for _, s := range byNS[nsName] {
			own := t.resource(n.id, s.name)
			if own == nil {
				writes = append(writes, write{s: s})
				continue
			}
			if !own.headSeq.Valid && own.state != statePurged {
				// A row without entries, as a pending blob's (§7.8), holds
				// no resource: the history goes in as for a missing one.
				writes = append(writes, write{s: s, res: own.id})
				continue
			}
			// A purged resource that holds the base's history refuses it as
			// any write to it does (410 gone, §7.2, §8.3), before the
			// frozen check (§6.2 step 2).
			purged := gone("path", path(s), "message", "the resource here is purged, so its schema history can't be mirrored into it (§G.3, §8.3)")
			if !own.headSeq.Valid {
				return purged
			}
			h := t.rev(own.headSeq.Int64)
			i, prefix := s.chain.index[h.id.String()]
			if !prefix && t.findInAncestry(h, mustID(s.chain.last().ID)) == nil {
				return conflict(s, "the resource here holds a different history")
			}
			switch {
			case own.state == statePurged:
				return purged
			case !prefix || i == len(s.chain.entries)-1:
				continue // already contains the base's chain, or the same head
			}
			writes = append(writes, write{s: s, res: own.id, from: i + 1, parent: h}) // a prefix: extend it
		}
		if len(writes) == 0 {
			continue
		}
		if cur.Frozen {
			// A frozen one refuses the history as any write to it (§8.4).
			e := apiErr(409, "frozen", "message", "the schema namespace "+nsName+" here is frozen, so the schemas can't be mirrored into it (§G.3, §8.4)")
			if cur.Successor != "" {
				e.Body["successor"] = cur.Successor
			}
			return e
		}
		if cur.level == levelE2E {
			// Only a key holder seals content into e2e (§2.1): this
			// deployment writes the history as it is, which an e2e
			// namespace refuses (§E.3.1).
			return invalid("the schema namespace " + nsName + " here is end-to-end, so the schemas can't be mirrored into it: " +
				"only a key holder seals content into e2e (§2.1, §G.3)")
		}
		var changes []change
		for _, w := range writes {
			res := w.res
			if res == 0 {
				res = t.mustInsert(`INSERT INTO resources (ns, name) VALUES (?,?) RETURNING res`, n.id, w.s.name)
			}
			head := t.insertChain(res, w.s.chain, w.from, w.parent, false)
			changes = append(changes, change{w.s.name, w.s.chain.last().Kind, head, res})
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
		if created && src.nonce {
			t.requireNonces(n, author)
		}
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
	_, err := t.Exec(`UPDATE revisions SET patches = NULL, size = NULL, digest = NULL WHERE res = ?`, r.id)
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
// namespace purge, §8.5), and the epoch keys of its source's epochs from
// before a raise from sealed it fetched (MF-37): a purge destroys a
// namespace's epoch keys (§8.5, §E.2.4).
func (t *tx) purgeShadowNS(sh *nsRow) {
	t.lockNS(sh.id, lockExclusive)
	t.deleteDEKs(`ns = ?`, sh.id)
	t.deleteSealed(`ns = ?`, sh.id)
	t.deleteBlobEpochs(`ns = ?`, sh.id)
	t.deleteEpochKeys(sh.id)
	q := `res IN (SELECT res FROM resources WHERE ns = ?)`
	for _, s := range []string{
		`UPDATE revisions SET patches = NULL, size = NULL, digest = NULL WHERE ` + q,
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

// --- config writes judged by the base's current document ---------------------

// A config write that makes a remote branch public, raises it to e2e or
// turns off a nonce requirement its base has is judged by the base's
// current namespace document, read for that write, and refused as creation
// is where it can't be read (§G.5.2): the shadow holds only what the base
// was when the branch was created. The read happens outside the write
// lock: the first run of the write finds that it needs the document
// (remoteSourceFor) and rolls back (errNeedSource), and withRemoteSource
// reads it from the base and runs the write again with it.

// remoteSourcesKey is the context key of a write's remoteSources.
type remoteSourcesKey struct{}

// remoteSources are the base documents read for one write, by the remote
// branch's ns.
type remoteSources struct {
	docs map[int64]*remoteSourceDoc
}

// remoteSourceDoc is a remote branch's base's current namespace document,
// read for a write: doc, or err with down set where the base didn't
// answer, or answered 5xx. origin and ns name the base. withAt marks a
// read for a raise to e2e, which also reads the base's document as of at:
// atE2E reports it e2e.
type remoteSourceDoc struct {
	origin string
	ns     string
	doc    map[string]any
	withAt bool
	atE2E  bool
	err    error
	down   bool
}

// errNeedSource rolls back a write that needs the current namespace
// document of the base of remote branch branch (remoteSourceFor).
type errNeedSource struct {
	branch         int64
	origin, ns, at string
	withAt         bool
}

func (e *errNeedSource) Error() string {
	return "the write needs the current namespace document of " + e.origin + "/ns/" + e.ns
}

// withRemoteSource runs f, a config write or a batch with a config change,
// with ctx carrying the base documents it needs (§G.5.2): each that a run
// of f finds missing is read from the base, outside any transaction, and f
// runs again.
func (e *Engine) withRemoteSource(ctx context.Context, f func(context.Context) error) error {
	h := &remoteSources{docs: map[int64]*remoteSourceDoc{}}
	ctx = context.WithValue(ctx, remoteSourcesKey{}, h)
	for tries := 0; ; tries++ {
		err := f(ctx)
		var need *errNeedSource
		if !errors.As(err, &need) {
			return err
		}
		if tries == 3 {
			// A safety net: a write runs again with the same request, and
			// a configuration that changed since gives it a 412 at step 2,
			// before it needs the document again.
			return apiErr(502, "upstream", "origin", need.origin, "message", "the base's namespace document read for this write kept being needed again")
		}
		h.docs[need.branch] = e.readRemoteSource(ctx, need)
	}
}

// readRemoteSource reads the base's current namespace document, and for a
// raise to e2e the one as of at, as creation does (fetchRemote).
func (e *Engine) readRemoteSource(ctx context.Context, need *errNeedSource) *remoteSourceDoc {
	out := &remoteSourceDoc{origin: need.origin, ns: need.ns, withAt: need.withAt}
	c, _, err := e.remoteClient(need.origin)
	if err != nil {
		out.err, out.down = err, true
		return out
	}
	d, err := currentNSDoc(ctx, c, need.ns)
	if err != nil {
		out.err, out.down = err, noAnswer(err)
		return out
	}
	out.doc = d.Value
	if need.withAt && docLevel(d.Value) == levelE2E {
		ad, err := c.NSDoc(ctx, need.ns, need.at)
		if err != nil && noAnswer(err) {
			out.err, out.down = err, true
			return out
		}
		out.atE2E = err == nil && docLevel(ad.Value) == levelE2E
	}
	return out
}

// remoteSourceFor returns the current namespace document of remote branch
// n's base as read for this write; withAt asks for the document as of at
// too. A write that hasn't read it yet rolls back to read it
// (errNeedSource, withRemoteSource); one run without withRemoteSource,
// which can't, gets it as unread.
func (t *tx) remoteSourceFor(n *nsRow, withAt bool) *remoteSourceDoc {
	var origin, ns, at string
	t.must(t.QueryRow(`SELECT origin, ns, at FROM remote_bases WHERE branch = ?`, n.id).Scan(&origin, &ns, &at))
	h, _ := t.ctx.Value(remoteSourcesKey{}).(*remoteSources)
	if h == nil {
		return &remoteSourceDoc{origin: origin, ns: ns, err: errors.New("not read for this write"), down: true}
	}
	if d := h.docs[n.id]; d != nil && (d.withAt || !withAt) {
		return d
	}
	panic(&errNeedSource{branch: n.id, origin: origin, ns: ns, at: at, withAt: withAt})
}

// checkRemoteSource is the §7.4 validation of remote branch n's namespace
// document cfg that depends on its base (§G.5.2): a write that makes it
// public, raises it to e2e or turns off a nonce requirement is judged by
// the base's current namespace document as a local branch's is by its
// base's. One this deployment can't read refuses the write as it refuses
// creation (§G.3): 410 purged, naming the base, where the base answers
// that its namespace is purged, as a sealed one's documents are once it is
// (§8.5, purgedBase); 502 upstream, naming the base's deployment, where
// the base didn't answer or answered 5xx; and 422 otherwise (unknownLevel).
// Refusals are 422 invalid with errors pointing at the member, as for the
// other branch fields; nothing is applied.
func (t *gate) checkRemoteSource(n *nsRow, cur, cfg *Config) *Error {
	toE2E := cfg.level == levelE2E && cur.level < levelE2E
	toPublic := cur.Read != "public" && cfg.Read == "public"
	nonceOff := cur.NonceRequired && !cfg.NonceRequired
	var ptr string
	switch {
	case toE2E:
		ptr = "/encryption"
	case toPublic:
		ptr = "/read"
	case nonceOff:
		ptr = "/nonce"
	default:
		return nil
	}
	src := t.remoteSourceFor(n, toE2E)
	if src.err != nil {
		if head, ok := purgedAt(src.err); ok {
			return purgedBase(src.origin, src.ns, head)
		}
		msg := fmt.Sprintf("this deployment can't read its base's current namespace document (%v), by which a config write that makes a remote branch public, "+
			"raises it to e2e or turns off a nonce requirement is judged (§G.5.2); nothing was applied", src.err)
		if src.down {
			e := upstreamErr("%s", msg)
			e.Body["origin"] = src.origin
			return e
		}
		return docInvalid(ptr, ptr+": "+msg)
	}
	level := docLevel(src.doc)
	switch {
	case toE2E && level != levelE2E:
		return docInvalid("/encryption", "/encryption: a branch can be e2e only if its base is, and the base's current namespace document isn't (§G.5.2, Addendum E Levels)")
	case toE2E && !src.atE2E:
		return docInvalid("/encryption", "/encryption: at is before the base's raise to e2e, and a branch can't be raised to e2e with an at before its base's e2e raise "+
			"(Addendum E Levels, §G.5.2); rebase it onto the base's current head (§F.5)")
	case toPublic && src.doc["read"] != "public":
		return docInvalid("/read", "a branch of a non-public namespace cannot be public: the base's current namespace document isn't public (§G.5.2, §7.4)")
	case nonceOff && src.doc["nonce"] == "required" && level != levelE2E:
		return docInvalid("/nonce", `/nonce: a branch can't turn off the nonce requirement its base has, and the base's current namespace document requires nonces (§G.5.2, §7.6, §C.7)`)
	}
	return nil
}

// --- following the base, and registering with it ----------------------------

// remoteBase is a remote_bases row. catchUp: the follower reads the base's
// namespace document as of the checkpoint once more (remote_catchup).
type remoteBase struct {
	shadow, branch int64 // SQL's rows
	origin, ns, at string
	checkpoint     string
	regNSID        sql.NullString
	regExpires     sql.NullInt64
	branchName     string
	purged         bool // the branch is
	catchUp        bool
}

// sqlRemoteBases lists the remote branches' bases, by branch name, or the
// one of branch name.
func (e *Engine) sqlRemoteBases(ctx context.Context, name string) ([]*remoteBase, error) {
	var out []*remoteBase
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT r.shadow, r.branch, r.origin, r.ns, r.at, r.checkpoint, r.reg_ns_id, r.reg_expires, n.name, n.purged,
		EXISTS (SELECT 1 FROM remote_catchup c WHERE c.branch = r.branch)
		FROM remote_bases r JOIN namespaces n ON n.ns = r.branch WHERE ? = '' OR n.name = ? ORDER BY n.name`, name, name)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			b := &remoteBase{}
			t.must(rows.Scan(&b.shadow, &b.branch, &b.origin, &b.ns, &b.at, &b.checkpoint, &b.regNSID, &b.regExpires, &b.branchName, &b.purged, &b.catchUp))
			out = append(out, b)
		}
		return nil
	})
	return out, err
}

// RemoteNotice is a purge seen in a remote base's log (§G.3), or a config
// change there that raised the base's level above the branch's or made its
// read non-public (§G.5.2).
type RemoteNotice struct {
	Branch   string // the remote branch
	ID       string // the base's ns_id of the entry
	Kind     string // purge, purge-ns, or config
	Resource string // purge: the resource name
	// Applied: applied locally (§8.3), or, for config, followed: the
	// branch raised its level, and restricted its read, as its base did
	// (followConfig). A config change not followed is in RemoteLevels.
	Applied bool
	Created string
}

// RemoteNotices lists the notices of a remote branch ("" = all), oldest
// first.
func (e *Engine) RemoteNotices(ctx context.Context, ns string) ([]RemoteNotice, error) {
	return e.be.remoteNotices(ctx, ns)
}

// sqlRemoteNotices is RemoteNotices on SQL.
func (e *Engine) sqlRemoteNotices(ctx context.Context, ns string) ([]RemoteNotice, error) {
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

// RemoteLevel is a remote branch whose base's level, as last seen in the
// log it follows, is above its own, because it couldn't follow the raise
// (§G.5.2, followLevel).
type RemoteLevel struct {
	Branch string // the remote branch
	Level  string // the base's level: at-rest, sealed or e2e
	// Lacks: this server can't hold that level, so every resource the base
	// had at at, read through or written on since and not purged since,
	// answers 502 upstream here, and in the branches reading through the
	// remote branch (§1, upstreamRefusal).
	Lacks bool
	// Rebase: Levels refuse the raise, as they refuse e2e to a branch whose
	// at is before its base's e2e raise, so the branch needs a rebase onto
	// the base's current head (§G.5.2, §F.5).
	Rebase  bool
	ID      string // the base's ns_id of the entry that raised it
	Created string
}

// RemoteLevels lists the remote branches ("" = all) whose base's level is
// above their own.
func (e *Engine) RemoteLevels(ctx context.Context, ns string) ([]RemoteLevel, error) {
	return e.be.remoteLevels(ctx, ns)
}

// sqlRemoteLevels is RemoteLevels on SQL.
func (e *Engine) sqlRemoteLevels(ctx context.Context, ns string) ([]RemoteLevel, error) {
	var out []RemoteLevel
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT n.name, l.level, l.lacks, l.rebase, l.id, l.created FROM remote_levels l JOIN namespaces n ON n.ns = l.branch
			WHERE ? = '' OR n.name = ? ORDER BY n.name`, ns, ns)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var rl RemoteLevel
			var level int
			var created int64
			t.must(rows.Scan(&rl.Branch, &level, &rl.Lacks, &rl.Rebase, &rl.ID, &created))
			rl.Level, rl.Created = levelNames[level], formatTime(created)
			out = append(out, rl)
		}
		return nil
	})
	return out, err
}

// SyncRemotes follows every live remote branch's base once: purges in its
// log since the last check are applied, and raises of its level and
// restrictions of its read followed (§G.3, §G.5.2); with Register,
// registrations are made or renewed.
func (e *Engine) SyncRemotes(ctx context.Context) error {
	bases, err := e.be.remoteBases(ctx, "")
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range bases {
		if b.purged {
			continue
		}
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

// followRemote follows a base's log after the checkpoint. On purge or
// purge-ns, §8.3 applies locally to the branch's own chains for that name,
// its own branches and its cache tags (§G.3); a deployment that sees a
// purge always applies it. A sealed base's purge arrives as the 410 purged
// of its log, whose head is the purge-ns entry (§8.5). On a config entry,
// or a batch with a config change, the base's namespace document after it
// is read, before the write transaction, and a raise of its level, or a
// read made non-public, is followed (followConfig, §G.5.2). A remote
// branch from before this follower (catchUp, migration 010_remote_catch_up) first
// follows the base's document as of the checkpoint, once, whether or not
// the log has moved since: the entries before it were followed only for
// their purges. The epochs the e2e bases below the base have in force now
// are followed too (followChainEpochs).
func (e *Engine) followRemote(ctx context.Context, b *remoteBase) error {
	c, ep, err := e.remoteClient(b.origin)
	if err != nil {
		return err
	}
	return errors.Join(e.followLog(ctx, c, ep, b), e.followChainEpochs(ctx, c, ep, b))
}

// followChainEpochs follows, for a remote branch of a branch, the epoch
// each e2e namespace of its base.chain below the base has in force now,
// read from its current namespace document at the origin (§G.5.2), into
// the shadow mirroring it (followEpoch): a branch's /keys relays a base's
// keyring entries to a grant without nbf only while that base's epoch now
// is its epoch at at (§E.2.3, epochNow), and the follower of the base's
// own log sees only the base's. An epoch later than the one at at is read
// by epochNow alone, so its start time is when it was seen. A base that
// can't be read keeps the epoch last seen, as the base itself does when
// its log can't be followed; the error is reported.
func (e *Engine) followChainEpochs(ctx context.Context, c *client.Client, ep RemoteEndpoint, b *remoteBase) error {
	type level struct {
		shadow string
		ns     string
	}
	var levels []level
	if err := e.gateRead(ctx, func(t *gate) error {
		bn := t.nsByName(b.branchName)
		if bn == nil || bn.purged {
			return nil
		}
		for i, sh := range t.remoteShadows(bn) {
			if i > 0 && t.config(sh.configSeq).level == levelE2E {
				levels = append(levels, level{sh.name, t.kidName(sh)})
			}
		}
		return nil
	}); err != nil || len(levels) == 0 {
		return err
	}
	docs := map[string]sourceDoc{}
	var errs []error
	for _, lv := range levels {
		h, err := c.NSHead(ctx, lv.ns)
		if err != nil {
			errs = append(errs, fmt.Errorf("/ns/%s: %w", lv.ns, err))
			continue
		}
		d, err := fetchSourceDoc(ctx, c, ep, lv.ns, h.ID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		docs[lv.shadow] = d
	}
	if len(docs) > 0 {
		errs = append(errs, e.be.followEpochs(ctx, docs))
	}
	return errors.Join(errs...)
}

// sqlFollowEpochs records the epochs in force at the bases of a chain's
// levels, in the shadows mirroring them, by shadow name (followEpoch).
func (e *Engine) sqlFollowEpochs(ctx context.Context, docs map[string]sourceDoc) error {
	return e.update(ctx, func(t *tx) error {
		for name, d := range docs {
			// A shadow, which nsByName never names.
			var sh int64
			if t.QueryRow(`SELECT ns FROM namespaces WHERE name = ?`, name).Scan(&sh) == nil {
				t.followEpoch(sh, d, "")
			}
		}
		return nil
	})
}

// followLog follows the base's log after the checkpoint (followRemote).
func (e *Engine) followLog(ctx context.Context, c *client.Client, ep RemoteEndpoint, b *remoteBase) error {
	entries, head, err := verify.Namespace(ctx, c, b.ns, b.checkpoint)
	if h, ok := purgedAt(err); ok && h != "" {
		// A sealed base's log is 410 once it is purged, with head its
		// purge-ns entry, which stands in for the entries (§8.5, §10),
		// unless the checkpoint is there already: every later sync gets
		// the same 410.
		if h == b.checkpoint {
			return nil
		}
		entries, head, err = []client.NSEntry{{ID: h, Kind: "purge-ns"}}, h, nil
	}
	if err != nil {
		if !noAnswer(err) {
			// A log this deployment can't open because the base is sealed
			// now still says that much (sealedAt): its level is followed as
			// a raise to sealed, though nothing else of the log can be.
			if h, herr := c.NSHead(ctx, b.ns); herr == nil && sealedAt(ctx, ep, c.BaseURL(), "/ns/"+b.ns+"/rev/"+h.ID) {
				if ferr := e.followSealed(ctx, b, h.ID); ferr != nil {
					return errors.Join(err, ferr)
				}
			}
		}
		return err
	}
	// The catch-up: the base's document as of the checkpoint. One the base
	// answers 410 purged for is a purged base, whose purge-ns this follows:
	// nothing is left to raise. One it answers otherwise but B can't read
	// keeps the mark, and the log is followed without it, so its purges
	// still apply; the error is reported after.
	var catchUp *sourceDoc
	var catchErr error
	if b.catchUp {
		d, err := fetchSourceDoc(ctx, c, ep, b.ns, b.checkpoint)
		switch _, purged := purgedAt(err); {
		case err == nil:
			catchUp = &d
		case noAnswer(err):
			return err
		case !purged:
			catchErr = fmt.Errorf("reading the base's namespace document once more, as the follower before v0.73 skipped it: %w", err)
		}
	}
	if len(entries) == 0 && (!b.catchUp || catchErr != nil) {
		return catchErr
	}
	// The base's namespace document after each config change, which this
	// deployment reads only from the base itself (§G.5.2).
	docs := map[string]sourceDoc{}
	e2eSeen := catchUp != nil && catchUp.level == levelE2E
	for _, en := range entries {
		if !configChanged(en) {
			continue
		}
		d, err := fetchSourceDoc(ctx, c, ep, b.ns, en.ID)
		if err != nil {
			return err
		}
		docs[en.ID] = d
		e2eSeen = e2eSeen || d.level == levelE2E
	}
	// A raise to e2e is followed as far as Levels allow (followLevel): to
	// the level the base had before it, once, while the branch is below
	// e2e and hasn't recorded it.
	if e2eSeen {
		var below bool
		if err := e.gateRead(ctx, func(t *gate) error {
			bn := t.nsByName(b.branchName)
			below = bn != nil && t.config(bn.configSeq).level < levelE2E && t.recordedLevel(bn) < levelE2E
			return nil
		}); err != nil {
			return err
		}
		if below {
			pre, err := preRaiseLevel(ctx, c, ep, b)
			if err != nil && noAnswer(err) {
				return err
			}
			for id, d := range docs {
				if d.level == levelE2E {
					d.pre = pre
					docs[id] = d
				}
			}
			if catchUp != nil && catchUp.level == levelE2E {
				catchUp.pre = pre
			}
		}
	}
	return e.be.followed(ctx, b, entries, head, docs, catchUp, catchErr)
}

// sqlFollowed records what following a base found (followLog): the
// catch-up, each config change's level and epoch, each purge in entries
// as a notice, applied, and head as the new checkpoint.
func (e *Engine) sqlFollowed(ctx context.Context, b *remoteBase, entries []client.NSEntry, head string, docs map[string]sourceDoc, catchUp *sourceDoc, catchErr error) error {
	return errors.Join(e.update(ctx, func(t *tx) error {
		// The branch's lock first: the checkpoint is read as of it.
		bn := t.nsByIDLocked(b.branch, lockExclusive)
		var cp string
		t.must(t.QueryRow(`SELECT checkpoint FROM remote_bases WHERE shadow = ?`, b.shadow).Scan(&cp))
		if cp != b.checkpoint {
			return nil // followed concurrently
		}
		if b.catchUp && catchErr == nil {
			res, err := t.Exec(`DELETE FROM remote_catchup WHERE branch = ?`, bn.id)
			t.must(err)
			if k, err := res.RowsAffected(); err == nil && k > 0 && catchUp != nil && !bn.purged {
				t.followConfig(bn, b.checkpoint, *catchUp)
				bn = t.nsByIDLocked(bn.id, lockExclusive)
			}
		}
		author := t.authorID(RemoteAuthor)
		for _, en := range entries {
			if d, ok := docs[en.ID]; ok {
				t.followEpoch(b.shadow, d, en.Created)
				if !bn.purged {
					t.followConfig(bn, en.ID, d)
					bn = t.nsByIDLocked(bn.id, lockExclusive)
				}
				continue
			}
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
			// A purged branch has nothing left to purge: only recorded.
			applied := !bn.purged
			_, err := t.Exec(`INSERT INTO remote_notices (branch, id, kind, resource, applied, created) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
				bn.id, en.ID, en.Kind, res, applied, t.now.UnixMilli())
			t.must(err)
			if !applied {
				continue
			}
			for _, name := range names {
				t.purgeResource(bn, name, author, false)
			}
		}
		_, err := t.Exec(`UPDATE remote_bases SET checkpoint = ? WHERE shadow = ?`, head, b.shadow)
		t.must(err)
		return nil
	}), catchErr)
}

// recordedLevel is the level a remote branch recorded following its
// base's raise to e2e (remote_levels), levelNone for none.
func (t *tx) recordedLevel(bn *nsRow) int {
	var recorded int
	if err := t.QueryRow(`SELECT level FROM remote_levels WHERE branch = ?`, bn.id).Scan(&recorded); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	return recorded
}

// configChanged reports whether a namespace entry changes the namespace
// document: a config entry, or a batch with a config change (§7.4, §7.5).
func configChanged(en client.NSEntry) bool {
	if en.Kind == "config" {
		return true
	}
	if en.Kind == "batch" {
		for _, s := range en.Entries {
			if s.Kind == "config" {
				return true
			}
		}
	}
	return false
}

// sourceDoc is what a remote branch follows of its base's namespace
// document after a config change (§G.5.2): its level, and its read, ""
// where the document is sealed and this deployment can't open it. At e2e,
// epoch is its encryption.epoch, and pre the level the base had before its
// raise to e2e, where the follower read it (preRaiseLevel).
type sourceDoc struct {
	level int
	read  string
	epoch int
	pre   int
}

// fetchSourceDoc reads the base's namespace document as of nsID. One the
// base serves sealed but this deployment can't open is at least sealed
// (sealedAt), its read unknown.
func fetchSourceDoc(ctx context.Context, c *client.Client, ep RemoteEndpoint, ns, nsID string) (sourceDoc, error) {
	d, err := c.NSDoc(ctx, ns, nsID)
	if err == nil {
		read, _ := d.Value["read"].(string)
		sd := sourceDoc{level: docLevel(d.Value), read: read}
		if enc, ok := d.Value["encryption"].(map[string]any); ok {
			if f, ok := enc["epoch"].(float64); ok {
				sd.epoch = int(f)
			}
		}
		return sd, nil
	}
	if !noAnswer(err) && sealedAt(ctx, ep, c.BaseURL(), "/ns/"+ns+"/rev/"+nsID) {
		return sourceDoc{level: levelSealed}, nil
	}
	return sourceDoc{}, fmt.Errorf("/ns/%s/rev/%s: %w", ns, nsID, err)
}

// preRaiseLevel is the level b's base had before its raise to e2e, from
// its namespace documents from the branch's at on: the branch was created
// below e2e, so the raise lies after at (Addendum E Levels). This
// deployment reads them only from the base itself (§G.5.2).
func preRaiseLevel(ctx context.Context, c *client.Client, ep RemoteEndpoint, b *remoteBase) (int, error) {
	d, err := fetchSourceDoc(ctx, c, ep, b.ns, b.at)
	if err != nil {
		return levelNone, err
	}
	level := d.level
	entries, _, err := verify.Namespace(ctx, c, b.ns, b.at)
	if err != nil {
		return levelNone, err
	}
	for _, en := range entries {
		if !configChanged(en) {
			continue
		}
		d, err := fetchSourceDoc(ctx, c, ep, b.ns, en.ID)
		if err != nil {
			return levelNone, err
		}
		if d.level == levelE2E {
			break
		}
		level = d.level
	}
	return level, nil
}

// followEpoch records an epoch of an e2e base seen at a config change in
// the shadow mirroring it, sh, with the entry's created time ("": now, for
// an epoch read from a base's current document, followChainEpochs): the
// shadow's document stays the base's as of at, and a branch's /keys relays
// the base's keyring entries by the epoch the base has in force now
// (epochNow, §E.2.3), so none once it has moved past its epoch at at.
func (t *tx) followEpoch(sh int64, d sourceDoc, created string) {
	if d.level != levelE2E || d.epoch < 1 {
		return
	}
	if t.config(t.nsByID(sh).configSeq).level != levelE2E {
		return
	}
	_, err := t.Exec(`INSERT INTO e2e_epochs (ns, epoch, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`, sh, d.epoch, parseCreated(created, t.now))
	t.must(err)
}

// sealedAt reports whether the base answers path, one of its namespace
// document URLs, sealed (§E.2.2): only a namespace at sealed or above
// serves its documents so, so this deployment learns that much of its
// base's level even where it can't open them.
func sealedAt(ctx context.Context, ep RemoteEndpoint, baseURL, path string) bool {
	hr, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
	if err != nil {
		return false
	}
	if ep.Bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+ep.Bearer)
	}
	res, err := ep.HTTPClient.Do(hr)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	ct, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	return res.StatusCode == 200 && strings.EqualFold(ct, seal.ContentType)
}

// followSealed follows a base whose log this deployment can't open because
// it is sealed: as a raise to sealed (followConfig), recorded at the head
// the base names, which isn't verified. The checkpoint stays: nothing else
// of the log is followed.
func (e *Engine) followSealed(ctx context.Context, b *remoteBase, head string) error {
	return e.be.followSealed(ctx, b, head)
}

// sqlFollowSealed is followSealed on SQL.
func (e *Engine) sqlFollowSealed(ctx context.Context, b *remoteBase, head string) error {
	return e.update(ctx, func(t *tx) error {
		bn := t.nsByIDLocked(b.branch, lockExclusive)
		if !bn.purged {
			t.followConfig(bn, head, sourceDoc{level: levelSealed})
		}
		return nil
	})
}

// followConfig follows a config change seen at the base's entry id
// (§G.5.2). A raise of the base's level above the branch's is followed as
// far as Levels allow (followLevel), unless it was recorded already as one
// the branch can't follow. A read the base made non-public restricts a
// public branch's, its public dependents first, leaves first (SHOULD).
// Either is recorded as a config notice, applied if the branch followed
// all of it.
func (t *tx) followConfig(bn *nsRow, id string, d sourceDoc) {
	cur := t.config(bn.configSeq)
	var recorded int
	if err := t.QueryRow(`SELECT level FROM remote_levels WHERE branch = ?`, bn.id).Scan(&recorded); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	raise := d.level > cur.level && d.level > recorded
	restrict := d.read != "" && d.read != "public" && cur.Read == "public"
	if !raise && !restrict {
		return
	}
	applied := true
	if raise {
		applied = t.followLevel(bn, id, d.level, d.pre)
	}
	if restrict {
		applied = t.restrictRead(bn) && applied
	}
	_, err := t.Exec(`INSERT INTO remote_notices (branch, id, kind, resource, applied, created) VALUES (?,?,?,NULL,?,?) ON CONFLICT DO NOTHING`,
		bn.id, id, "config", applied, t.now.UnixMilli())
	t.must(err)
}

// followLevel follows a raise of the base's level to level, above the
// branch's own, seen at the base's entry id (§G.5.2): the branch raises
// its local dependents, leaves first, then itself, by config writes of
// this deployment (RemoteAuthor, serverConfig), which seal what they read
// through as a local raise does (insertConfig, encryptNamespace). It
// reports whether it raised. Otherwise it records in remote_levels why it
// couldn't:
//
//   - a level this server lacks: without a key store it holds none
//     (checkEncryption), and the resources the base had at at then answer
//     502 upstream (§1, upstreamRefusal); or a raise that failed, so they
//     do too rather than be served below the base's level (Levels);
//   - e2e, which Levels refuse a branch whose at is before its base's e2e
//     raise, as the raise seen after at is: the branch needs a rebase. It
//     follows as far as Levels allow: to pre, the level the base had
//     before the raise, at which the base goes on serving what the branch
//     reads through (Addendum E Levels, After a raise), where the branch
//     missed it, as a follower that skipped config entries did.
func (t *tx) followLevel(bn *nsRow, id string, level, pre int) bool {
	lacks, rebase := false, false
	switch {
	case t.e.opt.KeyStore == nil:
		lacks = true
	case level == levelE2E:
		rebase = true
		if pre > t.config(bn.configSeq).level {
			if err := t.raiseLeavesFirst(bn, pre); err != nil {
				log.Printf("remote branch %s: following its base's level before its raise to e2e, %s: %v", bn.name, levelNames[pre], err)
				lacks = true
			}
		}
	default:
		if err := t.raiseLeavesFirst(bn, level); err != nil {
			log.Printf("remote branch %s: following its base's raise to %s: %v", bn.name, levelNames[level], err)
			lacks, rebase = true, true
		}
	}
	if !lacks && !rebase {
		return true
	}
	var wasLacks, wasRebase bool
	if err := t.QueryRow(`SELECT lacks, rebase FROM remote_levels WHERE branch = ?`, bn.id).Scan(&wasLacks, &wasRebase); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	_, err := t.Exec(`DELETE FROM remote_levels WHERE branch = ?`, bn.id)
	t.must(err)
	_, err = t.Exec(`INSERT INTO remote_levels (branch, level, lacks, rebase, id, created) VALUES (?,?,?,?,?,?)`,
		bn.id, level, lacks || wasLacks, rebase || wasRebase, id, t.now.UnixMilli())
	t.must(err)
	if lacks {
		// Copies of its resources, at the edge and in the read cache, go:
		// they answer 502 now (§9).
		t.metaChanged = true
		for _, n := range t.leavesFirst(bn) {
			t.tags = append(t.tags, "ns:"+n.name)
		}
		log.Printf("remote branch %s: its base was raised to %s, which this server lacks: what it had at at answers 502 upstream (§1)", bn.name, levelNames[level])
	} else {
		log.Printf("remote branch %s: its base was raised to %s, which Levels refuse a branch whose at is before the raise: rebase it (§G.5.2)", bn.name, levelNames[level])
	}
	return false
}

// leavesFirst lists n and the branches of it that aren't purged, at any
// depth, each after its own branches: the order levels are raised and
// reads restricted in (§7.4).
func (t *tx) leavesFirst(n *nsRow) []*nsRow {
	var out []*nsRow
	for _, b := range t.branchesOf(n) {
		if !b.purged {
			out = append(out, t.leavesFirst(b)...)
		}
	}
	return append(out, n)
}

// raiseLeavesFirst raises bn and its dependents to level, leaves first,
// each that is below it (§7.4, Addendum E Levels).
func (t *tx) raiseLeavesFirst(bn *nsRow, level int) error {
	for _, n := range t.leavesFirst(bn) {
		n = t.nsByIDLocked(n.id, lockExclusive)
		cur := t.config(n.configSeq)
		if cur.level >= level {
			continue
		}
		ps := []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": levelNames[level]}}}
		if _, ok := cur.Doc["schemaReads"]; ok && level >= levelSealed {
			// A member the new level refuses goes in the same write
			// (§6.1, Addendum E Levels).
			ps = append(ps, map[string]any{"op": "remove", "path": "/schemaReads"})
		}
		if err := t.serverConfig(n, ps); err != nil {
			return fmt.Errorf("raising %s: %w", n.name, err)
		}
	}
	return nil
}

// restrictRead makes a public remote branch, and its public dependents
// first, leaves first, readable by grant only, as its base now is (§G.5.2
// SHOULD, §7.4). It reports whether it did.
func (t *tx) restrictRead(bn *nsRow) bool {
	for _, n := range t.leavesFirst(bn) {
		n = t.nsByIDLocked(n.id, lockExclusive)
		if t.config(n.configSeq).Read != "public" {
			continue
		}
		if err := t.serverConfig(n, []any{map[string]any{"op": "add", "path": "/read", "value": "grant"}}); err != nil {
			log.Printf("remote branch %s: restricting the read of %s as its base's: %v", bn.name, n.name, err)
			return false
		}
	}
	return true
}

// serverConfig is a config write of this deployment's own to n, made for a
// remote base it follows (§G.5.2): by RemoteAuthor, under no grant, and
// checked as one under a * key is (§7.4), its entry recording no grant.
func (t *tx) serverConfig(n *nsRow, patches []any) error {
	cur := t.config(n.configSeq)
	cc := &ConfigChange{IfMatch: t.configID(n.configSeq).String(), Patches: patches}
	a := &actor{principal: grant.Principal{ID: RemoteAuthor}, star: true, bucketKey: RemoteAuthor}
	p, err := t.planConfig(n, cur, a, cc, false)
	if err != nil {
		return err
	}
	if p.replay != nil {
		return nil
	}
	author := t.authorID(RemoteAuthor)
	t.asServer(func() {
		seq := t.insertConfig(n, p, author)
		t.appendNS(n, map[string]any{"kind": "config", "target": p.id.String()}, nil, &seq, seq, author)
	})
	return nil
}

// RegisterRemote registers a remote branch with its base, or renews its
// registration (§G.3). It needs unrestricted read and export at the base,
// through the endpoint's bearer grant.
func (e *Engine) RegisterRemote(ctx context.Context, ns string) error {
	bs, err := e.be.remoteBases(ctx, ns)
	if err != nil {
		return err
	}
	if len(bs) == 0 {
		return notFound()
	}
	b := bs[0]
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
	return e.be.registered(ctx, b, nsID, expT)
}

// sqlRegistered records a branch's registration with its base.
func (e *Engine) sqlRegistered(ctx context.Context, b *remoteBase, nsID string, expires time.Time) error {
	return e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE remote_bases SET reg_ns_id = ?, reg_expires = ? WHERE shadow = ?`, nsID, expires.UnixMilli(), b.shadow)
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
	} else if rm, ok := body["remote"].(map[string]any); ok {
		// A base with authentication disabled needs an author for the
		// write (§7.2): this deployment, by its origin.
		hr.Header.Set("X-Author", fmt.Sprint(rm["origin"]))
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
