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
// 412: an operator grant may create namespaces with config (§C.2 item 2,
// §C.4), and otherwise the caller needs config on the namespace itself.
func (t *tx) authorizeTaken(n *nsRow, req Request) *Error {
	if keys := t.operatorKeys(); len(keys) > 0 {
		if a, err := t.authenticate(n.name, nil, nil, req.Cred, keys); err == nil {
			return t.authorize(a, "config", "")
		}
	}
	a, err := t.authenticate(n.name, n, t.config(n.configSeq), req.Cred, nil)
	if err != nil {
		return err
	}
	return t.authorize(a, "config", "")
}

// createNamespace bootstraps a namespace with an operator grant (§C.4),
// which checks config (§C.2 item 2) and, as the grant that creates it,
// passes the *-key guard (§C.2).
func (t *tx) createNamespace(req Request, cc ConfigChange) (*WriteResult, *Error) {
	if !ValidNSName(req.NS) {
		return nil, badInput("invalid namespace name")
	}
	keys := t.operatorKeys()
	if keys == nil {
		keys = []grant.Key{}
	}
	a, aerr := t.authenticate(req.NS, nil, nil, req.Cred, keys)
	if aerr != nil {
		return nil, aerr
	}
	if err := t.authorize(a, "config", ""); err != nil {
		return nil, err
	}
	ops, err := patch.Parse(cc.Patches)
	if err != nil {
		return nil, patchErr(err)
	}
	doc, _, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return nil, patchErr(err)
	}
	// Step 4: the document, validated as §7.4 says, then the limits: a
	// creation counts as a create (§6.6), held to the deployment's
	// defaults, which no document has lowered yet.
	cfg, perr := t.e.newConfig(doc, nil, nil)
	if perr != nil {
		return nil, perr
	}
	if aerr := t.e.checkArchives(cfg); aerr != nil {
		return nil, withPointer(aerr)
	}
	if cfg.Base != nil {
		return nil, docInvalid("/base", "branches are created with POST /ns/{base}/branches")
	}
	if err := t.checkEncryption(nil, cfg, -1); err != nil {
		return nil, err
	}
	if cfg.Successor != "" {
		// A creation names no successor (default, F-B9).
		return nil, docInvalid("/successor", "a new namespace cannot have a successor")
	}
	if err := checkConfigLimits(t.e.opt.Limits, cc.Patches, jsonv.Canonical(cc.Patches), true, jsonv.Canonical(doc), func() bool { return true }); err != nil {
		return nil, err
	}
	nn, id, nsID := t.insertNamespace(req.NS, cc.Patches, doc, cfg.Frozen, t.actorID(a))
	t.sealedConfigWritten(nn, nil, cfg)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: id.String()}, nil
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
	var res *WriteResult
	err := e.update(ctx, func(t *tx) error {
		r, err := t.createBranch(req, br)
		res = r
		return asErr(err)
	})
	return res, err
}

func (t *tx) createBranch(req Request, br BranchRequest) (*WriteResult, *Error) {
	base := t.nsForWrite(req.NS)
	if base == nil {
		return nil, t.absentNS(req.NS, req.Cred)
	}
	bcfg := t.config(base.configSeq)
	a, aerr := t.authenticate(base.name, base, bcfg, req.Cred, nil)
	if aerr != nil {
		return nil, aerr
	}
	// Step 1.
	if !ValidNSName(br.Name) {
		return nil, badInput("invalid branch name")
	}
	if err := t.authorize(a, "branch", br.Name); err != nil {
		return nil, err
	}
	if !t.readsNS(base, bcfg, a, true) {
		return nil, forbidden("branching needs unrestricted read on the base (§2.1)")
	}
	if err := t.rateLimit(base, bcfg, a, nil, 1); err != nil {
		return nil, err
	}
	// 410 after authorisation and the rate limits, like every write to a
	// purged namespace (§6.2, §8.5).
	if base.purged {
		return nil, t.purgedNS(base)
	}
	// Step 2: the precondition. A branch requires If-None-Match: * (§7.6);
	// 428 comes after authorisation (§6.2).
	if !br.IfNoneMatch {
		return nil, apiErr(428, "precondition_required")
	}
	if br.Patches == nil {
		br.Patches = []any{}
	}
	// Step 2.5: a taken name is 412, with no head or config, before an at
	// outside the base's chain is refused at step 4 (§6.2, §7.6), unless
	// the request retries the branch's creation.
	if ex := t.nsByName(br.Name); ex != nil {
		if r := t.branchRetry(base, ex, br, a); r != nil {
			return r, nil
		}
		return nil, apiErr(412, "stale", "message", "the name is taken")
	}
	// at defaults to the base's head, the latest ns_id of its chain as
	// the branch entry is inserted (§7.6).
	atSeq, atOK := base.headSeq.Int64, true
	if br.At != "" {
		atSeq, atOK = t.branchAt(base, br.At)
	}
	atText := br.At
	if atOK {
		atText = t.nsLogID(atSeq).String()
	}
	// Step 3: the branch's namespace document.
	nd, writes, gcanon, cfgID, perr := branchGenesis(bcfg.Doc, base.name, atText, br.Patches, branchDropped)
	if perr != nil {
		return nil, patchErr(perr)
	}
	// Step 4: the document, validated as §7.4 says, then the limits
	// (§6.2). Every refusal of a branch field is 422 invalid with errors
	// pointing at the member, before the *-key guard (§7.4, §C.2).
	if !atOK {
		return nil, docInvalid("/base/at", "at is not in the base's chain (§7.6)")
	}
	// The document starts as the base's, so the members this version
	// defines that it holds unchanged are judged as there; any other
	// member is refused, since a branch is a new namespace (checkMembers).
	cfg, verr := t.e.newConfig(nd, definedMembers(bcfg.Doc), bcfg.Doc)
	if verr != nil {
		return nil, verr
	}
	if !jsonv.Equal(bcfg.Doc["retention"], cfg.Doc["retention"]) {
		if aerr := t.e.checkArchives(cfg); aerr != nil {
			return nil, withPointer(aerr)
		}
	}
	if cfg.Base == nil || cfg.Base.NS != base.name || cfg.Base.At != atText || cfg.Base.Remote() {
		return nil, docInvalid("/base", "/base cannot be changed (§7.4)")
	}
	if cfg.DraftsFor != nil && base.isBranch() && t.draftRoot(base) == "" {
		return nil, docInvalid("/drafts", "/drafts is only for local branches that aren't end-to-end encrypted (§7.4)")
	}
	// Every * key of the base is kept (§7.6), and every * key of its local
	// bases that the base's document holds (keepsStarKeys).
	for b := base; ; b = t.nsByID(b.base.Int64) {
		if err := keepsStarKeys(bcfg, cfg, b, t.config(b.configSeq)); err != nil {
			return nil, err
		}
		if !b.isBranch() || t.remoteShadow(b) != nil {
			break
		}
	}
	if cfg.Read == "public" && bcfg.Read != "public" {
		return nil, docInvalid("/read", "a branch of a non-public namespace cannot be public (§7.4)")
	}
	if err := t.checkEncryption(nil, cfg, t.nsLevel(base)); err != nil {
		return nil, err
	}
	if err := t.checkNonceBase(nil, cfg, base); err != nil {
		return nil, err
	}
	if cfg.Successor != "" {
		// A branch of base, or of a namespace further up its chain, as
		// for a config write that sets it (§7.4).
		bases := t.successorBases(base)
		bases[fmt.Sprint(base.id)] = true
		if err := t.successorOK(cfg.Successor, 0, bases); err != nil {
			return nil, err
		}
	}
	depth := 1
	for b := base; b.isBranch(); b = t.nsByID(b.base.Int64) {
		depth++
	}
	if depth > t.e.opt.Maximums.BranchDepth {
		return nil, limitErr(422, "branchDepth", int64(depth), int64(t.e.opt.Maximums.BranchDepth), "branch depth exceeded")
	}
	// Live branches only (§6.6): merged or superseded branches are frozen,
	// not live (§F.6), and don't count, so branches kept for review after
	// their merge don't block new ones.
	if live := t.liveBranches(base, nil); live >= bcfg.Limits.BranchesPerNamespace {
		return nil, limitErr(422, "branchesPerNamespace", int64(live+1), int64(bcfg.Limits.BranchesPerNamespace), "too many live branches")
	}
	// The patches and the document, a creation counting as a create, held
	// to the base's limits (§6.6). Step 1 needed unrestricted read.
	if err := checkConfigLimits(bcfg.Limits, br.Patches, jsonv.Canonical(br.Patches), true, jsonv.Canonical(nd), func() bool { return true }); err != nil {
		return nil, err
	}
	// Step 6: the *-key guard, with a * key of the base (§7.6, §C.2), then
	// the base's rules, which evaluate a branch envelope.
	if touchesGuarded(writes) && !a.star {
		return nil, forbidden("these patches need a grant chained to a * key of the base")
	}
	env := t.basicEnvelope("branch", br.Name, a)
	env["writes"] = anyStrings(writes)
	env["doc"] = nd
	env["patches"] = jsonv.MustParse(jsonv.Canonical(br.Patches))
	if err := t.checkRules(bcfg, a, env, false); err != nil {
		return nil, err
	}
	// Step 7.
	author := t.actorID(a)
	bid := t.mustInsert(`INSERT INTO namespaces (name, base, base_at, base_config_seq) VALUES (?,?,?,?) RETURNING ns`, br.Name, base.id, atSeq, base.configSeq)
	cseq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,NULL,?,?,?,?) RETURNING seq`,
		bid, cfgID[:], string(gcanon), string(jsonv.Canonical(nd)), author, t.now.UnixMilli())
	bn := t.nsByIDLocked(bid, lockExclusive)
	// Both logs, in ascending key order, after every other lock (D.8).
	t.lockLogs(base.id, bid)
	t.appendNS(bn, map[string]any{"kind": "config", "target": cfgID.String()}, nil, &cseq, cseq, author)
	// A sealed branch has its own epoch keys (§E.2.5).
	t.sealedConfigWritten(bn, nil, cfg)
	_, nsID := t.appendNS(base, map[string]any{"kind": "branch", "name": br.Name, "at": atText, "target": cfgID.String()}, nil, &cseq, base.configSeq, author)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: cfgID.String()}, nil
}

// branchDropped are the members of the base's current document a local
// branch's starting document leaves out (§7.6): none of them is
// inherited. legacyBranchDropped is the list before v0.73, which kept
// cleanup, so that a creation made then still retries (branchRetry).
var (
	branchDropped       = []string{"frozen", "successor", "merged", "abandoned", "cleanup", "drafts", "schemaReads"}
	legacyBranchDropped = []string{"frozen", "successor", "merged", "abandoned", "drafts", "schemaReads"}
)

// branchGenesis builds a local branch's namespace document from its base's
// document bdoc (§7.6): the members dropped removed, base: { ns, at }
// added, then patches applied. It returns the document, the patches'
// writes, and the canonical genesis patch set and its config id.
func branchGenesis(bdoc map[string]any, baseName, at string, patches any, dropped []string) (doc any, writes []string, canon []byte, id ids.ID, err error) {
	d := cloneDoc(bdoc)
	for _, k := range dropped {
		delete(d, k)
	}
	d["base"] = map[string]any{"ns": baseName, "at": at}
	ops, err := patch.Parse(patches)
	if err != nil {
		return nil, nil, nil, ids.ID{}, err
	}
	nd, w, err := patch.Apply(d, true, ops, patch.Options{})
	if err != nil {
		return nil, nil, nil, ids.ID{}, err
	}
	canon = jsonv.Canonical([]any{map[string]any{"op": "add", "path": "", "value": nd}})
	return nd, patch.WritesStrings(w), canon, ids.Revision(nil, canon), nil
}

// branchAt resolves a branch's at in base's chain (§7.6).
func (t *tx) branchAt(base *nsRow, at string) (int64, bool) {
	id, err := ids.Parse(at)
	if err != nil {
		return 0, false
	}
	return t.nsLogSeq(base.id, id)
}

// branchRetry answers an idempotent retry of the creation of ex, a taken
// name, or nil (§7.6, §7.2): until ex is purged, a local branch of base
// whose creation was by the same principal (the same root sub and kid),
// with the same at, where an omitted at names the one recorded for the
// branch and one outside the base's chain matches nothing, and the same
// patches. The patches are judged by the genesis they give from the base's
// document in force at the creation, so later config writes to the base
// don't turn a retry into a 412.
func (t *tx) branchRetry(base, ex *nsRow, br BranchRequest, a *actor) *WriteResult {
	if ex.purged || !ex.base.Valid || ex.base.Int64 != base.id {
		return nil
	}
	atSeq := ex.baseAt.Int64
	if br.At != "" {
		if s, ok := t.branchAt(base, br.At); !ok || s != atSeq {
			return nil
		}
	}
	var gseq int64
	var gid []byte
	if t.QueryRow(`SELECT seq, id FROM ns_config WHERE ns = ? AND parent_seq IS NULL`, ex.id).Scan(&gseq, &gid) != nil {
		return nil
	}
	// The base's branch entry targets the branch's config genesis.
	var seq int64
	if t.QueryRow(`SELECT seq FROM ns_log WHERE ns = ? AND kind = ? AND target_seq = ?`, base.id, nsKindCode("branch"), gseq).Scan(&seq) != nil ||
		!t.samePrincipal(seq, a, t.actorID(a)) {
		return nil
	}
	bdoc := t.config(base.configSeq).Doc
	if ex.baseConfigSeq.Valid {
		bdoc = t.config(ex.baseConfigSeq.Int64).Doc
	}
	at := t.nsLogID(atSeq).String()
	match := false
	for _, dropped := range [][]string{branchDropped, legacyBranchDropped} {
		if _, _, _, id, err := branchGenesis(bdoc, base.name, at, br.Patches, dropped); err == nil && id == ids.FromBytes(gid) {
			match = true
			break
		}
	}
	if !match {
		return nil
	}
	return &WriteResult{Status: 200, Replayed: true, ConfigID: ids.FromBytes(gid).String(), NSID: t.nsLogID(seq).String()}
}
