package core

import (
	"context"
	"fmt"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// authorizeTaken authorises a create of an existing namespace, before its
// 412: an operator grant may create namespaces (§C.4), and otherwise the
// caller needs config on the namespace itself.
func (t *gate) authorizeTaken(n *nsRow, req Request) *Error {
	if keys := t.operatorKeys(); len(keys) > 0 {
		if a, err := t.authenticate(n.name, nil, nil, req.Cred, keys); err == nil && (a.verified == nil || a.star) {
			return nil
		}
	}
	a, err := t.authenticate(n.name, n, t.config(n.configSeq), req.Cred, nil)
	if err != nil {
		return err
	}
	return t.authorize(a, "config", "")
}

// createNamespace bootstraps a namespace with an operator key (§C.4).
func (t *tx) createNamespace(req Request, cc ConfigChange) (*WriteResult, *Error) {
	a, doc, cfg, err := t.planCreate(req, cc)
	if err != nil {
		return nil, err
	}
	nn, id, nsID := t.insertNamespace(req.NS, cc.Patches, doc, cfg.Frozen, t.actorID(a))
	t.sealedConfigWritten(nn, nil, cfg)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: id.String()}, nil
}

// planCreate checks a namespace's creation: the name, an operator's
// credentials, the document. It returns the creating actor and the
// namespace's document and configuration.
func (t *gate) planCreate(req Request, cc ConfigChange) (*actor, any, *Config, *Error) {
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
		return nil, nil, nil, forbidden("creating a namespace needs a deployment operator key")
	}
	ops, err := patch.Parse(cc.Patches)
	if err != nil {
		return nil, nil, nil, patchErr(err)
	}
	doc, _, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return nil, nil, nil, patchErr(err)
	}
	// Step 4: a creation counts as a create (§6.6), held to the
	// deployment's defaults, which no document has lowered yet.
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
	if cfg.Base != nil {
		return nil, nil, nil, invalid("branches are created with POST /ns/{base}/branches")
	}
	if err := t.checkEncryption(nil, cfg, -1); err != nil {
		return nil, nil, nil, err
	}
	if cfg.Successor != "" {
		return nil, nil, nil, invalid("a new namespace cannot have a successor")
	}
	return a, doc, cfg, nil
}

// insertNamespace inserts a new non-branch namespace with its config genesis
// and first config entry.
func (t *tx) insertNamespace(name string, patches, doc any, frozen bool, author int64) (*nsRow, ids.ID, ids.ID) {
	canon := jsonv.Canonical(patches)
	id := ids.Revision(nil, canon)
	nsid := t.mustInsert(`INSERT INTO namespaces (name, frozen) VALUES (?, ?) RETURNING ns`, name, frozen)
	cseq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?) RETURNING seq`,
		nsid, id[:], string(canon), string(jsonv.Canonical(doc)), author, t.now.UnixMilli())
	n := t.nsByID(nsid)
	_, nsID := t.appendNS(n, map[string]any{"kind": "config", "target": id.String()}, nil, &cseq, cseq, author)
	return n, id, nsID
}

// BranchRequest is POST /ns/{base}/branches (§7.6).
type BranchRequest struct {
	Name        string
	At          string
	Patches     any
	IfNoneMatch bool
}

// CreateBranch creates a branch of a local base.
func (e *Engine) CreateBranch(ctx context.Context, req Request, br BranchRequest) (*WriteResult, error) {
	return e.be.createBranch(ctx, req, br)
}

// sqlCreateBranch is CreateBranch on SQL.
func (e *Engine) sqlCreateBranch(ctx context.Context, req Request, br BranchRequest) (*WriteResult, error) {
	var res *WriteResult
	err := e.update(ctx, func(t *tx) error {
		r, err := t.createBranch(req, br)
		res = r
		return asErr(err)
	})
	return res, err
}

func (t *tx) createBranch(req Request, br BranchRequest) (*WriteResult, *Error) {
	p, replay, err := t.planBranch(req, br)
	if err != nil || replay != nil {
		return replay, err
	}
	base, a, nd, gcanon, cfgID, atSeq, atID, cfg := p.base, p.a, p.doc, p.canon, p.cfgID, p.atSeq, p.atID, p.cfg
	// Step 7.
	author := t.actorID(a)
	bid := t.mustInsert(`INSERT INTO namespaces (name, base, base_at, base_config_seq) VALUES (?,?,?,?) RETURNING ns`, p.name, base.id, atSeq, base.configSeq)
	cseq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?) RETURNING seq`,
		bid, cfgID[:], string(gcanon), string(jsonv.Canonical(nd)), author, t.now.UnixMilli())
	bn := t.nsByIDLocked(bid, lockExclusive)
	// Both logs, in ascending key order, after every other lock (D.8).
	t.lockLogs(base.id, bid)
	t.appendNS(bn, map[string]any{"kind": "config", "target": cfgID.String()}, nil, &cseq, cseq, author)
	// A sealed branch has its own epoch keys (§E.2.5).
	t.sealedConfigWritten(bn, nil, cfg)
	_, nsID := t.appendNS(base, map[string]any{"kind": "branch", "name": p.name, "at": atID.String(), "target": cfgID.String()}, nil, &cseq, base.configSeq, author)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: cfgID.String()}, nil
}

// branchPlan is a branch the gate allowed (§7.6): its base, the entry it
// branches at, its namespace document as a genesis patch set.
type branchPlan struct {
	name   string
	base   *nsRow
	a      *actor
	atSeq  int64
	atID   ids.ID
	doc    any
	canon  []byte // the genesis patch set, canonical
	cfgID  ids.ID
	cfg    *Config
	writes []string
}

// planBranch checks a branch's creation (§7.6, §6.2 steps 1–6), or
// answers an idempotent retry of one (replay).
func (t *gate) planBranch(req Request, br BranchRequest) (p *branchPlan, replay *WriteResult, perr *Error) {
	base := t.nsForWrite(req.NS)
	if base == nil {
		return nil, nil, t.absentNS(req.NS, req.Cred)
	}
	bcfg := t.config(base.configSeq)
	a, aerr := t.authenticate(base.name, base, bcfg, req.Cred, nil)
	if aerr != nil {
		return nil, nil, aerr
	}
	// Step 1.
	if !ValidNSName(br.Name) {
		return nil, nil, badInput("invalid branch name")
	}
	if err := t.authorize(a, "branch", br.Name); err != nil {
		return nil, nil, err
	}
	if !t.readsNS(base, bcfg, a, true) {
		return nil, nil, forbidden("branching needs unrestricted read on the base (§2.1)")
	}
	if err := t.rateLimit(base, bcfg, a, nil, 1); err != nil {
		return nil, nil, err
	}
	// 410 after authorisation and the rate limits, like every write to a
	// purged namespace (§6.2, §8.5).
	if base.purged {
		return nil, nil, t.purgedNS(base)
	}
	// Step 2: the precondition. A branch requires If-None-Match: * (§7.6);
	// 428 comes after authorisation (§6.2).
	if !br.IfNoneMatch {
		return nil, nil, apiErr(428, "precondition_required")
	}
	if br.Patches == nil {
		br.Patches = []any{}
	}
	// Step 2.
	atSeq := base.headSeq.Int64
	if br.At != "" {
		id, err := ids.Parse(br.At)
		if err != nil {
			return nil, nil, invalid("at is not in the base's chain")
		}
		s, ok := t.nsLogSeq(base.id, id)
		if !ok {
			return nil, nil, invalid("at is not in the base's chain")
		}
		atSeq = s
	}
	atID := t.nsLogID(atSeq)
	// Build the branch's namespace document (step 3).
	doc := cloneDoc(bcfg.Doc)
	for _, k := range []string{"frozen", "successor", "merged", "abandoned", "drafts", "schemaReads"} {
		delete(doc, k) // §7.6: none of them is inherited
	}
	doc["base"] = map[string]any{"ns": base.name, "at": atID.String()}
	ops, err := patch.Parse(br.Patches)
	if err != nil {
		return nil, nil, patchErr(err)
	}
	nd, w, err := patch.Apply(doc, true, ops, patch.Options{})
	if err != nil {
		return nil, nil, patchErr(err)
	}
	writes := patch.WritesStrings(w)
	genesis := []any{map[string]any{"op": "add", "path": "", "value": nd}}
	gcanon := jsonv.Canonical(genesis)
	cfgID := ids.Revision(nil, gcanon)
	if ex := t.nsByName(br.Name); ex != nil {
		// Idempotent retry: same principal, same at and patches, until
		// the branch is purged; after that it is 412 too: its name stays
		// reserved, for its creator too (§7.6, §8.5).
		gseq, author, gid, ok := t.configGenesis(ex)
		if ok && !ex.purged && ex.base.Valid && ex.base.Int64 == base.id && ex.baseAt.Int64 == atSeq &&
			author == t.actorID(a) && gid == cfgID {
			r := &WriteResult{Status: 200, Replayed: true, ConfigID: cfgID.String()}
			// The base's branch entry targets the branch's config genesis.
			if seq, ok := t.branchEntry(base, gseq); ok {
				r.NSID = t.nsLogID(seq).String()
			}
			return nil, r, nil
		}
		return nil, nil, apiErr(412, "stale", "message", "the name is taken")
	}
	// Limits (step 4).
	depth := 1
	for b := base; b.isBranch(); b = t.nsByID(b.base.Int64) {
		depth++
	}
	if depth > t.e.opt.Maximums.BranchDepth {
		return nil, nil, limitErr(422, "branchDepth", int64(depth), int64(t.e.opt.Maximums.BranchDepth), "branch depth exceeded")
	}
	// Live branches only (§6.6): merged or superseded branches are frozen,
	// not live (§F.6), and don't count, so branches kept for review after
	// their merge don't block new ones.
	if live := t.liveBranches(base, nil); live >= bcfg.Limits.BranchesPerNamespace {
		return nil, nil, limitErr(422, "branchesPerNamespace", int64(live+1), int64(bcfg.Limits.BranchesPerNamespace), "too many live branches")
	}
	// The patches and the document, a creation counting as a create, held
	// to the base's limits (§6.6). Step 1 needed unrestricted read.
	if err := checkConfigLimits(bcfg.Limits, br.Patches, jsonv.Canonical(br.Patches), true, jsonv.Canonical(nd), func() bool { return true }); err != nil {
		return nil, nil, err
	}
	// Step 5. The document starts as the base's, so the members this
	// version defines that it holds unchanged are judged as there; any
	// other member is refused, since a branch is a new namespace
	// (checkMembers).
	cfg, perr := t.e.newConfig(nd, definedMembers(bcfg.Doc), bcfg.Doc)
	if perr != nil {
		return nil, nil, perr
	}
	if !jsonv.Equal(bcfg.Doc["retention"], cfg.Doc["retention"]) {
		if aerr := t.e.checkArchives(cfg); aerr != nil {
			return nil, nil, aerr
		}
	}
	if cfg.Base == nil || cfg.Base.NS != base.name || cfg.Base.At != atID.String() {
		return nil, nil, invalid("/base cannot be changed")
	}
	if cfg.DraftsFor != nil && base.isBranch() && t.draftRoot(base) == "" {
		return nil, nil, invalid("/drafts is only for local branches that aren't end-to-end encrypted (§7.4)")
	}
	if touchesGuarded(writes) && !a.star {
		return nil, nil, forbidden("these patches need a grant chained to a * key of the base")
	}
	for b := base; ; b = t.nsByID(b.base.Int64) {
		for kid, k := range t.config(b.configSeq).starKeys() {
			nk, ok := findKey(cfg.Keys, kid)
			if !ok || string(nk.Pub) != string(k.Pub) || !nk.IsStar() {
				return nil, nil, invalid(fmt.Sprintf("key %q of %s must be kept", kid, b.name))
			}
		}
		if !b.isBranch() {
			break
		}
	}
	if cfg.Read == "public" && bcfg.Read != "public" {
		return nil, nil, invalid("a branch of a non-public namespace cannot be public")
	}
	if err := t.checkEncryption(nil, cfg, t.nsLevel(base)); err != nil {
		return nil, nil, err
	}
	if err := t.checkNonceBase(nil, cfg, base); err != nil {
		return nil, nil, err
	}
	// Step 6: the base's rules evaluate a branch envelope.
	env := t.basicEnvelope("branch", br.Name, a)
	env["writes"] = anyStrings(writes)
	env["doc"] = nd
	env["patches"] = jsonv.MustParse(jsonv.Canonical(br.Patches))
	if err := t.checkRules(bcfg, a, env, false); err != nil {
		return nil, nil, err
	}
	return &branchPlan{name: br.Name, base: base, a: a, atSeq: atSeq, atID: atID, doc: nd, canon: gcanon, cfgID: cfgID, cfg: cfg, writes: writes}, nil, nil
}
