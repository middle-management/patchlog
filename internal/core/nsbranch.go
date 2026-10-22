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
	// Step 2.
	atSeq := base.headSeq.Int64
	if br.At != "" {
		id, err := ids.Parse(br.At)
		if err != nil {
			return nil, invalid("at is not in the base's chain")
		}
		s, ok := t.nsLogSeq(base.id, id)
		if !ok {
			return nil, invalid("at is not in the base's chain")
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
		return nil, patchErr(err)
	}
	nd, w, err := patch.Apply(doc, true, ops, patch.Options{})
	if err != nil {
		return nil, patchErr(err)
	}
	writes := patch.WritesStrings(w)
	genesis := []any{map[string]any{"op": "add", "path": "", "value": nd}}
	gcanon := jsonv.Canonical(genesis)
	cfgID := ids.Revision(nil, gcanon)
	if ex := t.nsByName(br.Name); ex != nil {
		// Idempotent retry: same principal, same at and patches, until
		// the branch is purged; after that it is 412 too: its name stays
		// reserved, for its creator too (§7.6, §8.5).
		var author, gseq int64
		var gid []byte
		qerr := t.QueryRow(`SELECT seq, author, id FROM ns_config WHERE ns = ? AND parent_seq IS NULL`, ex.id).Scan(&gseq, &author, &gid)
		if qerr == nil && !ex.purged && ex.base.Valid && ex.base.Int64 == base.id && ex.baseAt.Int64 == atSeq &&
			author == t.actorID(a) && ids.FromBytes(gid) == cfgID {
			var seq int64
			// The base's branch entry targets the branch's config genesis.
			t.QueryRow(`SELECT seq FROM ns_log WHERE ns = ? AND kind = ? AND target_seq = ?`, base.id, nsKindCode("branch"), gseq).Scan(&seq)
			r := &WriteResult{Status: 200, Replayed: true, ConfigID: cfgID.String()}
			if seq != 0 {
				r.NSID = t.nsLogID(seq).String()
			}
			return r, nil
		}
		return nil, apiErr(412, "stale", "message", "the name is taken")
	}
	// Limits (step 4).
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
	// Step 5. The document starts as the base's, so the members this
	// version defines that it holds unchanged are judged as there; any
	// other member is refused, since a branch is a new namespace
	// (checkMembers).
	cfg, perr := t.e.newConfig(nd, definedMembers(bcfg.Doc), bcfg.Doc)
	if perr != nil {
		return nil, perr
	}
	if !jsonv.Equal(bcfg.Doc["retention"], cfg.Doc["retention"]) {
		if aerr := t.e.checkArchives(cfg); aerr != nil {
			return nil, aerr
		}
	}
	if cfg.Base == nil || cfg.Base.NS != base.name || cfg.Base.At != atID.String() {
		return nil, invalid("/base cannot be changed")
	}
	if cfg.DraftsFor != nil && base.isBranch() && t.draftRoot(base) == "" {
		return nil, invalid("/drafts is only for local branches that aren't end-to-end encrypted (§7.4)")
	}
	if touchesGuarded(writes) && !a.star {
		return nil, forbidden("these patches need a grant chained to a * key of the base")
	}
	for b := base; ; b = t.nsByID(b.base.Int64) {
		for kid, k := range t.config(b.configSeq).starKeys() {
			nk, ok := findKey(cfg.Keys, kid)
			if !ok || string(nk.Pub) != string(k.Pub) || !nk.IsStar() {
				return nil, invalid(fmt.Sprintf("key %q of %s must be kept", kid, b.name))
			}
		}
		if !b.isBranch() {
			break
		}
	}
	if cfg.Read == "public" && bcfg.Read != "public" {
		return nil, invalid("a branch of a non-public namespace cannot be public")
	}
	if err := t.checkEncryption(nil, cfg, t.nsLevel(base)); err != nil {
		return nil, err
	}
	if err := t.checkNonceBase(nil, cfg, base); err != nil {
		return nil, err
	}
	// Step 6: the base's rules evaluate a branch envelope.
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
	_, nsID := t.appendNS(base, map[string]any{"kind": "branch", "name": br.Name, "at": atID.String(), "target": cfgID.String()}, nil, &cseq, base.configSeq, author)
	return &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: cfgID.String()}, nil
}
