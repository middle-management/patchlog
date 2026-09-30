package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/verify"
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
// work unchanged. The rules that rely on one operator stop at the shadow:
// keys and revocations are the branch's own, purges in the base arrive as
// notices from its log, and nothing on this side blocks the base (§7.6).

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
		ep.HTTPClient = http.DefaultClient
	}
	return ep, nil
}

func (e *Engine) remoteClient(origin string) (*client.Client, RemoteEndpoint, error) {
	ep, err := e.endpoint(origin)
	if err != nil {
		return nil, ep, err
	}
	opts := []client.Option{client.WithHTTPClient(ep.HTTPClient)}
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
	return remoteErr("%s: %v", what, err)
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
}

func newChain(entries []client.LogEntry, horizonDoc []byte) *remoteChain {
	c := &remoteChain{entries: entries, horizonDoc: horizonDoc, index: map[string]int{}}
	for i, e := range entries {
		c.index[e.ID] = i
	}
	return c
}

func (c *remoteChain) last() client.LogEntry { return c.entries[len(c.entries)-1] }

// fold walks the chain, calling f with each entry and the document after it
// (for a tombstone, the last live document).
func (c *remoteChain) fold(f func(i int, e client.LogEntry, doc any) error) error {
	var doc any
	exists := false
	for i, e := range c.entries {
		switch {
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

// fetchChain fetches and verifies a resource's chain up to target.
func fetchChain(ctx context.Context, c *client.Client, ns, name, target string) (*remoteChain, *Error) {
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
		return newChain(entries, nil), nil
	}
	if !client.IsPruned(err) {
		return nil, fetchErr(what, err)
	}
	// Pruned at the base (§8.6): mirror from the horizon, with its
	// document as a snapshot, verifying ids from there on.
	h := client.Horizon(err)
	if _, perr := ids.Parse(h); perr != nil {
		return nil, fetchErr(what, err)
	}
	d, err := c.Doc(ctx, ns, name, h)
	if err != nil {
		if client.IsGone(err) && !client.IsPruned(err) {
			return nil, apiErr(410, "pruned", "message", what+": the base's horizon is a tombstone, whose document can't be fetched", "horizon", h)
		}
		return nil, fetchErr(what, err)
	}
	var rest []client.LogEntry
	if h != target {
		rest, err = c.Log(ctx, ns, name, target, h)
		if err != nil {
			if client.IsNotFound(err) {
				return nil, apiErr(410, "pruned", "message", what+": history needed at at was pruned at the base", "horizon", h)
			}
			return nil, fetchErr(what, err)
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

// remoteRes is one resource of the base as of at.
type remoteRes struct {
	name    string
	kind    string // head, tombstone or purge
	target  string
	lastIdx int // the namespace entry that set it
	chain   *remoteChain
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

// remoteMirror is the base as of at, verified.
type remoteMirror struct {
	base    *BaseRef
	read    string // the base's read mode at at (as served; §G.5)
	level   int    // the base's encryption level at at (as served)
	log     []client.NSEntry
	res     []*remoteRes
	schemas []*remoteSchema
}

// fetchRemote fetches and verifies the base of a remote branch as of at
// (§G.3), outside any transaction.
func (e *Engine) fetchRemote(ctx context.Context, base *BaseRef) (*remoteMirror, *Error) {
	c, _, err := e.remoteClient(base.Origin)
	if err != nil {
		return nil, remoteErr("%s: %v", base.Origin, err)
	}
	if o, err := c.Origin(ctx); err != nil {
		return nil, fetchErr("GET /", err)
	} else if o != base.Origin {
		return nil, remoteErr("the deployment reached for %s publishes the origin %s", base.Origin, o)
	}
	m := &remoteMirror{base: base, read: "grant"}
	// The namespace log up to at, verified from its first entry: at is the
	// trusted starting point (§G.1).
	log, err := c.NSLog(ctx, base.NS, base.At, "")
	if err != nil {
		return nil, fetchErr("/ns/"+base.NS+"/rev/"+base.At+"/log", err)
	}
	last, verr := verify.VerifyNSChain(log, "")
	if verr != nil {
		return nil, unverified("namespace log: %v", verr)
	}
	if last != base.At {
		return nil, unverified("the namespace log ends at %s, not at %s", last, base.At)
	}
	m.log = log
	if d, err := c.NSDoc(ctx, base.NS, base.At); err == nil {
		if _, isBranch := d.Value["base"]; isBranch {
			return nil, invalid("the remote base is itself a branch; this server mirrors only bases whose chain lists every resource")
		}
		if d.Value["read"] == "public" {
			m.read = "public"
		}
		if enc, ok := d.Value["encryption"].(map[string]any); ok {
			lv, _ := enc["level"].(string)
			if m.level = levelOf(lv); m.level == levelNone {
				m.level = levelE2E // unknown: the strictest
			}
		}
	}
	// Heads as of at, from the verified log.
	byName := map[string]*remoteRes{}
	set := func(name, kind, target string, i int) {
		r := &remoteRes{name: name, kind: kind, target: target, lastIdx: i}
		if prev := byName[name]; kind == "purge" && prev != nil && prev.kind == "tombstone" {
			r.purgedKind = kindTombstone
		}
		byName[name] = r
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
			return nil, gone("message", "the remote base is purged")
		}
	}
	// The listing the spec reads must agree with the log (§G.3).
	heads, err := c.Heads(ctx, base.NS, base.At)
	if err != nil {
		return nil, fetchErr("/ns/"+base.NS+"/rev/"+base.At+"/heads", err)
	}
	if len(heads) != len(byName) {
		return nil, unverified("/heads lists %d resources, the namespace log %d", len(heads), len(byName))
	}
	for _, h := range heads {
		r := byName[h.Resource]
		if r == nil || r.kind != h.Kind || r.target != h.Target {
			return nil, unverified("/heads lists %s as %s %s, which the namespace log doesn't", h.Resource, h.Kind, h.Target)
		}
	}
	names := sortedKeys(byName)
	var queue []schema.Ref
	for _, name := range names {
		r := byName[name]
		m.res = append(m.res, r)
		if r.kind == "purge" {
			continue
		}
		ch, ferr := fetchChain(ctx, c, base.NS, name, r.target)
		if ferr != nil {
			return nil, ferr
		}
		r.chain = ch
		doc, err := ch.docAt(len(ch.entries) - 1)
		if err != nil {
			return nil, unverified("/r/%s/%s: %v", base.NS, name, err)
		}
		if dm, ok := doc.(map[string]any); ok {
			if s, ok := dm["$schema"].(string); ok {
				if ref, ok := schema.ParseRef(s); ok {
					queue = append(queue, ref)
				}
			}
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
			ch, ferr := fetchChain(ctx, c, ref.NS, ref.Name, ref.Rev)
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
	return m, nil
}

// --- creating a remote branch ----------------------------------------------

// checkRemoteGenesis authenticates the operator grant and checks the
// genesis of a remote branch (§C.4, §G.3).
func (t *tx) checkRemoteGenesis(req Request, cc ConfigChange) (*Config, map[string]any, *actor, *Error) {
	if !ValidNSName(req.NS) {
		return nil, nil, nil, badInput("invalid namespace name")
	}
	keys := t.e.opt.OperatorKeys
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
	cfg, perr := t.e.parseConfig(doc)
	if perr != nil {
		var le *limitError
		if errors.As(perr, &le) {
			return nil, nil, nil, limitErr(422, le.msg)
		}
		return nil, nil, nil, invalid(perr.Error())
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
	if cfg.level >= levelSealed {
		return nil, nil, nil, invalid("/encryption: remote branches cannot be sealed on this server (§G.5)")
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
		if t.nsByName(req.NS) != nil || m == nil {
			r, err := t.writeConfig(req, cc) // 412 for a taken name
			res = r
			return err
		}
		cfg, doc, a, err := t.checkRemoteGenesis(req, cc)
		if err != nil {
			return err
		}
		r, err := t.insertRemoteBranch(req, cc, cfg, doc, m, t.authorID(a.id()))
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
	if cfg.Read == "public" && m.read != "public" {
		return nil, invalid("a branch of a non-public namespace cannot be public")
	}
	if cfg.level < m.level {
		return nil, invalid("/encryption: a branch cannot have a lower encryption level than its base")
	}
	// The shadow's mirrored rows follow the branch's level.
	if t.shadowLevels == nil {
		t.shadowLevels = map[string]int{}
	}
	t.shadowLevels[shadowName(req.NS)] = cfg.level
	if err := t.mirrorSchemas(m, req.NS, cfg, author); err != nil {
		return nil, err
	}
	shadow, atSeq := t.insertShadow(req.NS, m)
	canon := jsonv.Canonical(cc.Patches)
	cfgID := ids.Revision(nil, canon)
	r, err := t.Exec(`INSERT INTO namespaces (name, base, base_at, base_config_seq, frozen) VALUES (?,?,?,?,?)`,
		req.NS, shadow.id, atSeq, shadow.configSeq, cfg.Frozen)
	t.must(err)
	bid, _ := r.LastInsertId()
	r, err = t.Exec(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?)`,
		bid, cfgID[:], string(canon), string(jsonv.Canonical(doc)), author, t.now.UnixMilli())
	t.must(err)
	cseq, _ := r.LastInsertId()
	bn := t.nsByID(bid)
	// No entry is written to any other local chain: the base's is remote.
	_, nsID := t.appendNS(bn, map[string]any{"kind": "config", "target": cfgID.String()}, nil, &cseq, cseq, author)
	_, err = t.Exec(`INSERT INTO remote_bases (shadow, branch, origin, ns, at, checkpoint) VALUES (?,?,?,?,?,?)`,
		shadow.id, bid, m.base.Origin, m.base.NS, m.base.At, m.base.At)
	t.must(err)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: cfgID.String()}, nil
}

// insertShadow mirrors the base's chain up to at and its resources as of
// at into the shadow namespace, with identical ids. It returns the shadow
// and the seq of at in it.
func (t *tx) insertShadow(branch string, m *remoteMirror) (*nsRow, int64) {
	remote := t.authorID(RemoteAuthor)
	cdoc := map[string]any{"read": m.read}
	genesis := []any{map[string]any{"op": "add", "path": "", "value": cdoc}}
	gcanon := jsonv.Canonical(genesis)
	cid := ids.Revision(nil, gcanon)
	r, err := t.Exec(`INSERT INTO namespaces (name) VALUES (?)`, shadowName(branch))
	t.must(err)
	sid, _ := r.LastInsertId()
	r, err = t.Exec(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?)`,
		sid, cid[:], string(gcanon), string(jsonv.Canonical(cdoc)), remote, t.now.UnixMilli())
	t.must(err)
	cseq, _ := r.LastInsertId()
	// Resources first, so the log rows can name them.
	resIDs := map[string]int64{}
	heads := map[string]int64{}
	for _, rr := range m.res {
		if rr.chain == nil {
			// Purged at the base as of at: only the head's id is known
			// (its content and parents are gone there too).
			r, err := t.Exec(`INSERT INTO resources (ns, name, state) VALUES (?,?,?)`, sid, rr.name, statePurged)
			t.must(err)
			res, _ := r.LastInsertId()
			resIDs[rr.name] = res
			id := mustID(rr.target)
			r, err = t.Exec(`INSERT INTO revisions (res, id, parent_seq, first, kind, author, created) VALUES (?,?,NULL,1,?,?,?)`,
				res, id[:], rr.purgedKind, remote, t.now.UnixMilli())
			t.must(err)
			head, _ := r.LastInsertId()
			_, err = t.Exec(`UPDATE resources SET head_seq = ? WHERE res = ?`, head, res)
			t.must(err)
			continue
		}
		r, err := t.Exec(`INSERT INTO resources (ns, name) VALUES (?,?)`, sid, rr.name)
		t.must(err)
		res, _ := r.LastInsertId()
		resIDs[rr.name] = res
		heads[rr.name] = t.insertChain(res, rr.chain, 0, nil)
	}
	settles := map[int][]*remoteRes{} // log index → resources whose head it set
	for _, rr := range m.res {
		if rr.chain != nil {
			settles[rr.lastIdx] = append(settles[rr.lastIdx], rr)
		}
	}
	var prev any
	var atSeq int64
	for i, en := range m.log {
		hf, err := verify.HashedForm(en)
		t.must(err)
		body := jsonv.Canonical(hf)
		var p *ids.ID
		if i > 0 {
			x := mustID(m.log[i-1].ID)
			p = &x
		}
		id := ids.Hash(p, body)
		if id.String() != en.ID {
			panic(fmt.Errorf("mirrored entry %s does not verify", en.ID))
		}
		var res any
		if en.IsResource() {
			res = resIDs[en.Resource]
		}
		author := remote
		if en.Author != "" {
			author = t.authorID(en.Author)
		}
		r, err := t.Exec(`INSERT INTO ns_log (ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created) VALUES (?,?,?,?,?,NULL,?,?,?,?)`,
			sid, id[:], prev, nsKindCode(en.Kind), res, string(body), cseq, author, parseCreated(en.Created, t.now))
		t.must(err)
		atSeq, _ = r.LastInsertId()
		prev = atSeq
		for _, rr := range settles[i] {
			_, err := t.Exec(`INSERT INTO head_history (res, ns_seq, target_seq) VALUES (?,?,?)`, resIDs[rr.name], atSeq, heads[rr.name])
			t.must(err)
		}
	}
	_, err = t.Exec(`UPDATE namespaces SET head_seq = ?, config_seq = ? WHERE ns = ?`, atSeq, cseq, sid)
	t.must(err)
	return t.nsByID(sid), atSeq
}

func parseCreated(s string, now time.Time) int64 {
	if tm, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return tm.UnixMilli()
	}
	return now.UnixMilli()
}

// insertChain inserts the chain's entries from index from on into res, the
// first chained on parent (nil: a new resource), and updates the resource's
// head, state, horizon and cached documents. It returns the head row's seq.
func (t *tx) insertChain(res int64, ch *remoteChain, from int, parent *revRow) int64 {
	remote := t.authorID(RemoteAuthor)
	var parentSeq any
	if parent != nil {
		parentSeq = parent.seq
	}
	var last, lastLive int64 = 0, 0
	var lastLiveDoc []byte
	var horizon any
	if parent != nil {
		ll := t.lastLive(parent)
		lastLive = ll.seq
	}
	state := stateLive
	err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		if i < from {
			return nil
		}
		id := mustID(e.ID)
		first := 0
		if parent == nil && i == from {
			first = 1
		}
		kind := kindRev
		var patches, typed, sig any
		canonDoc := jsonv.Canonical(doc)
		switch {
		case e.Kind == "tombstone":
			kind = kindTombstone
		case e.HasPatches:
			patches = t.putPatches(res, id, jsonv.Canonical(e.Patches))
		}
		if kind == kindRev {
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
		r, err := t.Exec(`INSERT INTO revisions (res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created) VALUES (?,?,?,?,?,?,?,NULL,NULL,?,?,?)`,
			res, id[:], parentSeq, first, kind, patches, author, sig, typed, parseCreated(e.Created, t.now))
		t.must(err)
		last, _ = r.LastInsertId()
		parentSeq = last
		if kind == kindTombstone {
			state = stateTombstoned
			return nil
		}
		state = stateLive
		lastLive, lastLiveDoc = last, canonDoc
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
	_, err = t.Exec(`UPDATE resources SET head_seq = ?, state = ?, horizon_seq = COALESCE(?, horizon_seq) WHERE res = ?`, last, state, horizon, res)
	t.must(err)
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
// branch's read mode, keys and roles. A path whose chain neither contains
// the base's nor is a prefix of it is 409 name_conflict.
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
		n := t.nsByName(nsName)
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
			n, _, _ = t.insertNamespace(nsName, []any{map[string]any{"op": "add", "path": "", "value": doc}}, doc, false, author)
		}
		var changes []change
		for _, s := range byNS[nsName] {
			own := t.resource(n.id, s.name)
			if own == nil {
				r, err := t.Exec(`INSERT INTO resources (ns, name) VALUES (?,?)`, n.id, s.name)
				t.must(err)
				res, _ := r.LastInsertId()
				head := t.insertChain(res, s.chain, 0, nil)
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
				head := t.insertChain(own.id, s.chain, i+1, h) // a prefix: extend it
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
	t.flushDocs = true
}

// purgeShadowNS removes all of a shadow's content (the remote branch's
// namespace purge, §8.5).
func (t *tx) purgeShadowNS(sh *nsRow) {
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
	_, err := t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE ns = ?`, statePurged, sh.id)
	t.must(err)
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
		var cp string
		t.must(t.QueryRow(`SELECT checkpoint FROM remote_bases WHERE shadow = ?`, b.shadow).Scan(&cp))
		if cp != b.checkpoint {
			return nil // followed concurrently
		}
		bn, sh := t.nsByID(b.branch), t.nsByID(b.shadow)
		author := t.authorID(RemoteAuthor)
		for _, en := range entries {
			var names []string
			switch en.Kind {
			case "purge":
				names = []string{en.Resource}
			case "purge-ns":
				rows, err := t.Query(`SELECT name FROM resources WHERE ns = ? ORDER BY name`, sh.id)
				t.must(err)
				for rows.Next() {
					var s string
					t.must(rows.Scan(&s))
					names = append(names, s)
				}
				rows.Close()
			default:
				continue
			}
			var res any
			if en.Kind == "purge" {
				res = en.Resource
			}
			applied := follow && !bn.purged
			_, err := t.Exec(`INSERT OR IGNORE INTO remote_notices (branch, id, kind, resource, applied, created) VALUES (?,?,?,?,?,?)`,
				bn.id, en.ID, en.Kind, res, applied, t.now.UnixMilli())
			t.must(err)
			if !applied {
				log.Printf("remote branch %s: %s %v in %s/ns/%s recorded as a notice, not applied", bn.name, en.Kind, names, b.origin, b.ns)
				continue
			}
			for _, name := range names {
				t.purgeResource(bn, name, author)
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
			if err := e.SyncRemotes(ctx); err != nil {
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
