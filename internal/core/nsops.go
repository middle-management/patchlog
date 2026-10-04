package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
)

// configPlan is a config change that passed steps 1–6.
type configPlan struct {
	cfg      *Config
	doc      map[string]any
	canon    []byte
	id       ids.ID
	expected *ids.ID
	replay   *WriteResult
}

// planConfig runs steps 1–6 of a config write on an existing namespace.
func (t *tx) planConfig(n *nsRow, cur *Config, a *actor, cc *ConfigChange, inBatch bool) (*configPlan, error) {
	// Step 1.
	if err := t.authorize(a, "config", ""); err != nil {
		return nil, err
	}
	p := &configPlan{}
	curID := t.configID(n.configSeq)
	if cc.IfMatch != "" {
		if pid, err := ids.Parse(cc.IfMatch); err == nil {
			e := ids.Revision(&pid, jsonv.Canonical(cc.Patches))
			p.expected = &e
		}
	}
	// Speculative apply, to decide the rate-limit exemption (§6.6).
	ops, perr := patch.Parse(cc.Patches)
	var newDoc any
	var writes []string
	if perr == nil {
		d, w, err := patch.Apply(cur.Doc, true, ops, patch.Options{})
		if err == nil {
			newDoc, writes = d, patch.WritesStrings(w)
		}
	}
	if !inBatch && !a.star && !freezeOnly(writes, newDoc) {
		if err := t.rateLimit(n, cur, a, nil, 1); err != nil {
			return nil, err
		}
	}
	// A purged namespace is 410 after authorisation (§6.2 step 2, §7.8's
	// order), before the retry lookup and the precondition.
	if n.purged {
		return nil, gone()
	}
	// Step 2: idempotent retry, then the precondition. Config writes are
	// allowed in frozen namespaces.
	if !inBatch && p.expected != nil {
		var seq int64
		var author int64
		err := t.QueryRow(`SELECT seq, author FROM ns_config WHERE ns = ? AND id = ?`, n.id, p.expected[:]).Scan(&seq, &author)
		if err == nil && author == t.actorID(a) {
			// The entry that wrote it: the first in force with it, a
			// config entry or a batch with a config change (§7.4).
			var nsSeq int64
			t.QueryRow(`SELECT MIN(seq) FROM ns_log WHERE ns = ? AND config_seq = ?`, n.id, seq).Scan(&nsSeq)
			r := &WriteResult{Status: 200, Replayed: true, ConfigID: p.expected.String()}
			if nsSeq != 0 {
				r.NSID = t.nsLogID(nsSeq).String()
			}
			p.replay = r
			return p, nil
		}
	}
	switch {
	case cc.IfNoneMatch:
		return nil, apiErr(412, "stale", "config", curID.String())
	case cc.IfMatch == "":
		return nil, apiErr(428, "precondition_required")
	case cc.IfMatch != curID.String():
		return nil, apiErr(412, "stale", "config", curID.String())
	}
	// Step 3.
	if perr != nil {
		return nil, patchErr(perr)
	}
	d, w, err := patch.Apply(cur.Doc, true, ops, patch.Options{})
	if err != nil {
		return nil, patchErr(err)
	}
	newDoc, writes = d, patch.WritesStrings(w)
	p.canon = jsonv.Canonical(cc.Patches)
	p.id = ids.Revision(&curID, p.canon)
	// Step 4.
	if len(p.canon) > cur.Limits.PatchSetSize {
		return nil, limitErr(413, "patch set too large")
	}
	if len(jsonv.Canonical(newDoc)) > cur.Limits.DocumentSize {
		return nil, limitErr(413, "document too large")
	}
	// Step 5: the built-in namespace-document schema and branch fields.
	cfg, verr := t.validateConfig(n, cur, newDoc, writes, a)
	if verr != nil {
		return nil, verr
	}
	p.cfg, p.doc = cfg, newDoc.(map[string]any)
	// Step 6.
	env := t.basicEnvelope("config", "", a)
	env["writes"] = anyStrings(writes)
	env["doc"] = newDoc
	env["patches"] = jsonv.MustParse(p.canon)
	if err := t.checkRules(cur, a, env, true); err != nil {
		return nil, err
	}
	return p, nil
}

func anyStrings(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// freezeOnly: writes all at /frozen, /successor or /merged, resulting in
// frozen: true (§6.6 exemption).
func freezeOnly(writes []string, doc any) bool {
	if len(writes) == 0 {
		return false
	}
	for _, w := range writes {
		if !(w == "/frozen" || w == "/successor" || w == "/merged") {
			return false
		}
	}
	m, _ := doc.(map[string]any)
	return m != nil && m["frozen"] == true
}

// newConfig is the schema check of step 5 for a namespace document a write
// produces (§7.4): parseConfig, then checkMembers against prev, what the
// write keeps (nil for a new namespace). base is a new branch's base's
// document, so a member refused because the branch inherits it says so.
func (e *Engine) newConfig(doc any, prev, base map[string]any) (*Config, *Error) {
	cfg, err := e.parseConfig(doc)
	if err == nil {
		err = checkMembers(cfg.Doc, prev)
	}
	var me *memberError
	if errors.As(err, &me) && me.member != "" {
		if _, ok := base[me.member]; ok {
			me.inherited = true
		}
	}
	if err != nil {
		return nil, configErr(err)
	}
	return cfg, nil
}

// configErr is the 422 for a namespace document that fails its schema: a
// limit has code "limit"; anything else is code "invalid" with
// errors: [{ "pointer", "message" }], as for schema validation (§7.4,
// §12), and the message alone too, for clients that show only that.
func configErr(err error) *Error {
	var le *limitError
	var me *memberError
	switch {
	case errors.As(err, &le):
		return limitErr(422, le.msg)
	case errors.As(err, &me):
		return docInvalid(me.pointer, me.Error())
	}
	return docInvalid(messagePointer(err.Error()), err.Error())
}

// docInvalid is a 422 invalid with one error at ptr.
func docInvalid(ptr, msg string) *Error {
	return apiErr(422, "invalid", "message", msg, "errors", []any{map[string]any{"pointer": ptr, "message": msg}})
}

// messagePointer is the JSON Pointer a parseConfig message starts with,
// such as "/read" of "/read must be …" or "/keys" of "/keys: …", or ""
// for the whole document.
func messagePointer(msg string) string {
	if !strings.HasPrefix(msg, "/") {
		return ""
	}
	if i := strings.IndexAny(msg, " :"); i > 0 {
		msg = msg[:i]
	}
	if _, err := pointer.Parse(msg); err != nil {
		return ""
	}
	return msg
}

// validateConfig is step 5 for a config write.
func (t *tx) validateConfig(n *nsRow, cur *Config, newDoc any, writes []string, a *actor) (*Config, *Error) {
	cfg, err := t.e.newConfig(newDoc, cur.Doc, nil)
	if err != nil {
		return nil, err
	}
	if !jsonv.Equal(cur.Doc["retention"], cfg.Doc["retention"]) {
		if aerr := t.e.checkArchives(cfg); aerr != nil {
			return nil, aerr
		}
	}
	if (touchesGuarded(writes) || (cur.Read != "public" && cfg.Read == "public")) && !a.star {
		return nil, forbidden("this change needs a grant chained to a * key")
	}
	if !jsonv.Equal(cur.Doc["base"], cfg.Doc["base"]) {
		return nil, invalid("/base cannot change")
	}
	if cfg.DraftsFor != nil && t.draftRoot(n) == "" {
		return nil, invalid("/drafts is only for local branches that aren't end-to-end encrypted (§7.4)")
	}
	baseLevel := -1
	if n.isBranch() {
		// A remote branch's shadow follows the branch itself; its
		// base's level was checked when it was created.
		if b := t.nsByID(n.base.Int64); !b.isShadow() {
			baseLevel = t.nsLevel(b)
		}
	}
	if err := t.checkEncryption(cur, cfg, baseLevel); err != nil {
		return nil, err
	}
	if cfg.level >= levelSealed && cur.level < levelSealed {
		// A remote branch becoming sealed seals its read-through content
		// under its own keys (§E.2.5). Registered remote branches of n are
		// bound by §G.5, which only their deployments can enforce. Local
		// public dependents that aren't sealed block it (§7.4): its content
		// would stay public through them.
		var deps []string
		for _, d := range t.publicDependents(n) {
			if b := t.nsByName(d); b != nil && t.nsLevel(b) < levelSealed {
				deps = append(deps, d)
			}
		}
		if len(deps) > 0 {
			return nil, apiErr(409, "in_use", "dependents", anyStrings(deps), "message", "a namespace with public dependents cannot become sealed")
		}
	}
	if cfg.level > cur.level {
		if deps := t.lowerDependents(n, cfg.level); len(deps) > 0 {
			return nil, apiErr(409, "in_use", "dependents", anyStrings(deps), "message", "raise the encryption level of these branches first")
		}
	}
	if n.isBranch() {
		// A remote base's keys don't reach across (§7.6): the loop stops
		// at the shadow, which has none.
		for b := n; b.isBranch() && t.remoteShadow(b) == nil; {
			b = t.nsByID(b.base.Int64)
			for kid, k := range t.config(b.configSeq).starKeys() {
				nk, ok := findKey(cfg.Keys, kid)
				if !ok || string(nk.Pub) != string(k.Pub) || !nk.IsStar() {
					return nil, invalid(fmt.Sprintf("key %q is a * key of base %s and cannot be removed or changed", kid, b.name))
				}
			}
		}
		base := t.nsByID(n.base.Int64)
		if cfg.Read == "public" && t.config(base.configSeq).Read != "public" && !sealedPair(cfg.level, t.nsLevel(base)) {
			return nil, invalid("a branch of a non-public namespace cannot be public")
		}
	}
	if cfg.Successor != "" {
		s := t.nsByName(cfg.Successor)
		if s == nil || s.isShadow() || t.baseIdentity(s) != t.baseIdentity(n) {
			return nil, invalid("successor must be an existing namespace with the same base")
		}
	}
	if cur.Read == "public" && cfg.Read != "public" {
		var deps []string
		for _, d := range t.publicDependents(n) {
			// A sealed branch of a sealed base may stay public.
			if b := t.nsByName(d); b == nil || !sealedPair(t.nsLevel(b), cfg.level) {
				deps = append(deps, d)
			}
		}
		if len(deps) > 0 {
			return nil, apiErr(409, "in_use", "dependents", anyStrings(deps))
		}
	}
	if n.isBranch() && (!sameStrings(cur.DraftsFor, cfg.DraftsFor) || cfg.level == levelE2E && cur.level != levelE2E) {
		// Narrowing drafts.for, or raising a branch to e2e, may leave a
		// reference to its drafts without a copy (§6.1, §7.4).
		if broken := t.brokenReferences(refChange{cfg: map[int64]*Config{n.id: cfg}}); len(broken) > 0 {
			return nil, t.inUse(broken, "the change would leave references to this branch's draft schema revisions without a copy (§6.1)")
		}
	}
	return cfg, nil
}

// sealedPair reports a sealed branch of a sealed base. Such a branch may be
// public even if its base isn't (a relaxation of §7.4): it only ever serves
// ciphertext under its own keys (§E.2.5).
func sealedPair(branchLevel, baseLevel int) bool {
	return branchLevel >= levelSealed && baseLevel >= levelSealed
}

func (t *tx) publicDependents(n *nsRow) []string {
	var out []string
	for _, b := range t.branchesOf(n) {
		if !b.purged && t.config(b.configSeq).Read == "public" {
			out = append(out, b.name)
		}
	}
	return out
}

func (t *tx) branchesOf(n *nsRow) []*nsRow {
	rows, err := t.Query(`SELECT `+nsCols+` FROM namespaces WHERE base = ? ORDER BY name`, n.id)
	t.must(err)
	defer rows.Close()
	var out []*nsRow
	for rows.Next() {
		b, err := scanNS(rows)
		t.must(err)
		out = append(out, b)
	}
	return out
}

// insertConfig inserts a planned config revision and returns its seq.
func (t *tx) insertConfig(n *nsRow, p *configPlan, author int64) int64 {
	seq := t.mustInsert(`INSERT INTO ns_config (ns, id, parent_seq, patches, doc, author, created) VALUES (?,?,?,?,?,?,?) RETURNING seq`,
		n.id, p.id[:], n.configSeq, string(p.canon), string(jsonv.Canonical(p.doc)), author, t.now.UnixMilli())
	old := t.config(n.configSeq)
	raised := p.cfg.level > old.level
	t.metaChanged = true
	_, err := t.Exec(`UPDATE namespaces SET frozen = ?, config_seq = ? WHERE ns = ?`, p.cfg.Frozen, seq, n.id)
	t.must(err)
	n.frozen = p.cfg.Frozen
	n.configSeq = seq
	if raised {
		// Turning encryption at rest on encrypts what is stored (§E.1).
		t.encryptNamespace(n)
	}
	// A sealed namespace's epoch key starts with the config write that
	// begins its epoch (§E.2.1).
	t.sealedConfigWritten(n, old, p.cfg)
	if old.cachePublic() && !p.cfg.cachePublic() {
		// Public copies at the edge must go (§9); every response of the
		// namespace carries ns:{ns}. Its branches can't be public now
		// (planConfig refuses while they are, sealed pairs aside, which
		// keep serving ciphertext under their own tags).
		t.tags = append(t.tags, "ns:"+n.name)
	}
	return seq
}

// WriteConfig creates a namespace (IfNoneMatch) or changes its document.
// A genesis whose base is in another deployment creates a remote branch
// (§G.3), fetching and verifying the base before the write transaction.
func (e *Engine) WriteConfig(ctx context.Context, req Request, cc ConfigChange) (*WriteResult, error) {
	if cc.IfNoneMatch && remoteBaseIn(cc.Patches) {
		return e.createRemoteBranch(ctx, req, cc)
	}
	var res *WriteResult
	err := e.update(ctx, func(t *tx) error {
		r, err := t.writeConfig(req, cc)
		res = r
		return err
	})
	return res, err
}

func (t *tx) writeConfig(req Request, cc ConfigChange) (*WriteResult, error) {
	var res *WriteResult
	err := func() error {
		n := t.nsForWrite(req.NS)
		if cc.IfNoneMatch && n == nil {
			r, err := t.createNamespace(req, cc)
			res = r
			return asErr(err)
		}
		if n == nil {
			return t.absentNS(req.NS, req.Cred)
		}
		if cc.IfNoneMatch {
			// The name is taken, also by a purged namespace, whose name
			// stays reserved (§8.5).
			if err := t.authorizeTaken(n, req); err != nil {
				return err
			}
			return apiErr(412, "stale", "config", t.configID(n.configSeq).String())
		}
		cur := t.config(n.configSeq)
		a, aerr := t.authenticate(n.name, n, cur, req.Cred, nil)
		if aerr != nil {
			return aerr
		}
		t.reqCreds = req.anyCreds()
		p, err := t.planConfig(n, cur, a, &cc, false)
		if err != nil {
			return err
		}
		if p.replay != nil {
			res = p.replay
			return nil
		}
		author := t.actorID(a)
		seq := t.insertConfig(n, p, author)
		_, nsID := t.appendNS(n, map[string]any{"kind": "config", "target": p.id.String()}, nil, &seq, seq, author)
		res = &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: p.id.String()}
		return nil
	}()
	return res, err
}

// authorizeTaken authorises a create of an existing namespace, before its
// 412: an operator grant may create namespaces (§C.4), and otherwise the
// caller needs config on the namespace itself.
func (t *tx) authorizeTaken(n *nsRow, req Request) *Error {
	if keys := t.e.opt.OperatorKeys; len(keys) > 0 {
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
	if !ValidNSName(req.NS) {
		return nil, badInput("invalid namespace name")
	}
	keys := t.e.opt.OperatorKeys
	if keys == nil {
		keys = []grant.Key{}
	}
	a, aerr := t.authenticate(req.NS, nil, nil, req.Cred, keys)
	if aerr != nil {
		return nil, aerr
	}
	if a.verified != nil && !a.star {
		return nil, forbidden("creating a namespace needs a deployment operator key")
	}
	ops, err := patch.Parse(cc.Patches)
	if err != nil {
		return nil, patchErr(err)
	}
	doc, _, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return nil, patchErr(err)
	}
	cfg, perr := t.e.newConfig(doc, nil, nil)
	if perr != nil {
		return nil, perr
	}
	if aerr := t.e.checkArchives(cfg); aerr != nil {
		return nil, aerr
	}
	if cfg.Base != nil {
		return nil, invalid("branches are created with POST /ns/{base}/branches")
	}
	if err := t.checkEncryption(nil, cfg, -1); err != nil {
		return nil, err
	}
	if cfg.Successor != "" {
		return nil, invalid("a new namespace cannot have a successor")
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
	if !t.canRead(base, bcfg, a, "") || !a.unrestrictedRead() {
		return nil, forbidden("branching needs unrestricted read on the base")
	}
	if err := t.rateLimit(base, bcfg, a, nil, 1); err != nil {
		return nil, err
	}
	// 410 after authorisation, like every write (§6.2).
	if base.purged {
		return nil, gone()
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
	for _, k := range []string{"frozen", "successor", "merged", "abandoned", "drafts"} {
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
		// Idempotent retry: same principal, same at and patches.
		var author, gseq int64
		var gid []byte
		qerr := t.QueryRow(`SELECT seq, author, id FROM ns_config WHERE ns = ? AND parent_seq IS NULL`, ex.id).Scan(&gseq, &author, &gid)
		if qerr == nil && ex.base.Valid && ex.base.Int64 == base.id && ex.baseAt.Int64 == atSeq &&
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
		return nil, limitErr(422, "branch depth exceeded")
	}
	live := 0
	for _, b := range t.branchesOf(base) {
		if !b.purged {
			live++
		}
	}
	if live >= bcfg.Limits.BranchesPerNamespace {
		return nil, limitErr(422, "too many live branches")
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
	if cfg.Read == "public" && bcfg.Read != "public" && !sealedPair(cfg.level, t.nsLevel(base)) {
		return nil, invalid("a branch of a non-public namespace cannot be public")
	}
	if err := t.checkEncryption(nil, cfg, t.nsLevel(base)); err != nil {
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

// Purge purges a resource (§8.3). It returns the purge entry's ns_id.
func (e *Engine) Purge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error) {
	var out string
	err := e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(req.NS)
		if n == nil {
			return t.absentNS(req.NS, req.Cred)
		}
		cfg := t.config(n.configSeq)
		a, operator, aerr := t.purger(n, cfg, req, force)
		if aerr != nil {
			return aerr
		}
		if err := t.authorize(a, "purge", name); err != nil {
			return err
		}
		// 410 after authorisation, like every write (§6.2).
		if n.purged {
			return gone()
		}
		if ifMatch == "" {
			return apiErr(428, "precondition_required")
		}
		v := t.resolve(n, name, nil)
		switch v.state {
		case NotFound:
			return notFound()
		case Purged:
			return gone()
		}
		if ifMatch != v.head.id.String() {
			return apiErr(412, "stale", "head", v.head.id.String())
		}
		// The purge reaches n and every branch it propagates to (§8.3),
		// each locked exclusively before it is read.
		reached := t.purgeReach(n)
		gone := func(ns *nsRow, res string) bool { return res == name && reached[ns.id] }
		forced := false
		if broken := t.brokenReferences(refChange{exclude: gone, removed: gone}); len(broken) > 0 {
			if !force {
				return t.inUse(broken, "the purge would remove the last available copy of a referenced schema revision (§6.1)")
			}
			if err := t.mayForce(n, a, operator); err != nil {
				return err
			}
			forced = true
		}
		if !operator {
			env := t.basicEnvelope("purge", name, a)
			env["writes"], env["doc"], env["patches"] = []any{}, nil, []any{}
			if err := t.checkRules(cfg, a, env, false); err != nil {
				return err
			}
		}
		// Every log the purge appends to, in ascending key order, after
		// every other lock (D.8).
		logs := make([]int64, 0, len(reached))
		for id := range reached {
			logs = append(logs, id)
		}
		t.lockLogs(logs...)
		out = t.purgeResource(n, name, t.actorID(a), forced).String()
		return nil
	})
	return out, err
}

// purgeReach locks n and every unpurged branch a resource purge in n
// propagates to (§8.3) exclusively, in the order purgeResource does, and
// returns their ids.
func (t *tx) purgeReach(n *nsRow) map[int64]bool {
	reached := map[int64]bool{n.id: true}
	var walk func(x *nsRow)
	walk = func(x *nsRow) {
		for _, b := range t.branchesOf(x) {
			if !b.purged && !reached[b.id] {
				t.lockNS(b.id, lockExclusive)
				reached[b.id] = true
				walk(b)
			}
		}
	}
	walk(n)
	return reached
}

// purger authenticates a purge (§8.3, §8.5). A forced one (§6.1) may come
// with a grant chained to a deployment operator key instead of one of the
// namespace's: then operator is true, and the namespace's rules don't
// apply to it.
func (t *tx) purger(n *nsRow, cfg *Config, req Request, force bool) (a *actor, operator bool, err *Error) {
	t.reqCreds = req.anyCreds()
	a, err = t.authenticate(n.name, n, cfg, req.Cred, nil)
	if err == nil || !force || len(t.e.opt.OperatorKeys) == 0 {
		return a, false, err
	}
	if oa, oerr := t.authenticate(n.name, nil, nil, req.Cred, t.e.opt.OperatorKeys); oerr == nil {
		return oa, true, nil
	}
	return nil, false, err
}

// mayForce decides whether a purge refused as in_use may be forced (§6.1):
// with ?force=1 and a grant chained to a deployment operator key, or, for
// a purge of a branch or of a resource in one, to a * key of that branch,
// inherited or its own. A * key of a namespace that isn't a branch
// doesn't force. With authentication disabled everyone is the operator.
func (t *tx) mayForce(n *nsRow, a *actor, operator bool) *Error {
	if operator || t.e.opt.AuthDisabled || (n.isBranch() && a.star) {
		return nil
	}
	return forbidden("forcing a purge refused as in_use needs a grant chained to a deployment operator key, or, in a branch, to a * key of the branch (§6.1)")
}

// purgeResource purges name in n and propagates to every branch (§8.3). It
// returns the id of n's purge entry. forced marks every entry it writes,
// propagated ones included, as overriding an in_use refusal (§3.5, §6.1).
// Propagated entries are the server's own: they keep the purger as author
// but record no grant (§7.4).
func (t *tx) purgeResource(n *nsRow, name string, author int64, forced bool) ids.ID {
	if t.locking() {
		// Every namespace a purge reaches is locked exclusively, and read
		// as of its lock (D.8 purge propagation).
		n = t.nsByIDLocked(n.id, lockExclusive)
	}
	// Branches first: a branch reading the resource through must still see
	// it, so that it records its own purge entry.
	for _, b := range t.branchesOf(n) {
		if !b.purged {
			t.asServer(func() { t.purgeResource(b, name, author, forced) })
		}
	}
	v := t.resolve(n, name, nil)
	var nsID ids.ID
	if v.state != NotFound && v.state != Purged {
		own := v.own
		var res int64
		if own == nil {
			res = t.mustInsert(`INSERT INTO resources (ns, name, head_seq, state) VALUES (?,?,?,?) RETURNING res`, n.id, name, v.head.seq, statePurged)
		} else {
			res = own.id
			t.deleteArchives(`res = ?`, res)
			// Destroying the data key makes whatever survives of the
			// rows and archives unreadable (§8.3, §E.1).
			t.deleteDEKs(`res = ?`, res)
			_, err := t.Exec(`UPDATE revisions SET patches = NULL WHERE res = ?`, res)
			t.must(err)
			_, err = t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE res = ?`, statePurged, res)
			t.must(err)
			// Purge ends every attachment, and pending entries go too
			// (§7.8, §8.3).
			t.purgeBlobs(`res = ?`, res)
		}
		_, err := t.Exec(`DELETE FROM heads WHERE res = ?`, res)
		t.must(err)
		_, err = t.Exec(`DELETE FROM snapshots WHERE res = ?`, res)
		t.must(err)
		_, err = t.Exec(`DELETE FROM e2e_snapshots WHERE res = ?`, res)
		t.must(err)
		target := v.head.seq
		entry := map[string]any{"resource": name, "kind": "purge", "target": v.head.id.String()}
		if forced {
			entry["forced"] = true
		}
		_, nsID = t.appendNS(n, entry, &res, &target, n.configSeq, author)
		t.tags = append(t.tags, "r:"+n.name+"/"+name)
		t.flushDocs = true
	}
	// Sealed copies of its content go too (§E.2.2).
	t.deleteSealed(`ns = ? AND name = ?`, n.id, name)
	t.deleteBlobEpochs(`ns = ? AND name = ?`, n.id, name)
	// A remote branch's mirrored copy is its own: it goes too, in every
	// shadow of its base's chain (§G.3).
	for _, sh := range t.remoteShadows(n) {
		t.purgeShadow(sh, name)
	}
	return nsID
}

// PurgeNamespace purges a frozen namespace (§8.5). It returns the purge-ns
// entry's ns_id.
//
// With force it purges even if that removes the last copy of a referenced
// schema revision (§6.1, §8.5): with a grant chained to a deployment
// operator key, or, for a branch, to a * key of the branch. The purge-ns
// entry then says forced: true (§3.5). Dependents can't be forced.
func (e *Engine) PurgeNamespace(ctx context.Context, req Request, ifMatch string, force bool) (string, error) {
	var out string
	err := e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(req.NS)
		if n == nil {
			return t.absentNS(req.NS, req.Cred)
		}
		cfg := t.config(n.configSeq)
		a, operator, aerr := t.purger(n, cfg, req, force)
		if aerr != nil {
			return aerr
		}
		if err := t.authorize(a, "purge-ns", ""); err != nil {
			return err
		}
		// 410 after authorisation, like every write (§6.2).
		if n.purged {
			return gone()
		}
		if ifMatch == "" {
			return apiErr(428, "precondition_required")
		}
		head := t.nsLogID(n.headSeq.Int64)
		if ifMatch != head.String() {
			return apiErr(412, "stale", "head", head.String())
		}
		if !cfg.Frozen {
			return apiErr(409, "not_frozen")
		}
		var deps []string
		for _, b := range t.branchesOf(n) {
			if !b.purged {
				deps = append(deps, b.name)
			}
		}
		if len(deps) > 0 {
			return apiErr(409, "in_use", "dependents", anyStrings(deps))
		}
		gone := func(ns *nsRow, _ string) bool { return ns.id == n.id }
		forced := false
		if broken := t.brokenReferences(refChange{exclude: gone, removed: gone}); len(broken) > 0 {
			if !force {
				return t.inUse(broken, "the namespace holds the last available copy of a schema revision referenced from another namespace (§6.1)")
			}
			if err := t.mayForce(n, a, operator); err != nil {
				return err
			}
			forced = true
		}
		if !operator {
			env := t.basicEnvelope("purge-ns", "", a)
			env["writes"], env["doc"], env["patches"] = []any{}, nil, []any{}
			if err := t.checkRules(cfg, a, env, false); err != nil {
				return err
			}
		}
		t.deleteArchives(`res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		t.deleteDEKs(`ns = ?`, n.id)
		// Sealed bytes and epoch keys go too (§E.2, §8.5).
		t.deleteSealed(`ns = ?`, n.id)
		t.deleteBlobEpochs(`ns = ?`, n.id)
		t.deleteEpochKeys(n.id)
		_, err := t.Exec(`UPDATE revisions SET patches = NULL WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		t.must(err)
		_, err = t.Exec(`DELETE FROM heads WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		t.must(err)
		_, err = t.Exec(`DELETE FROM snapshots WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		t.must(err)
		_, err = t.Exec(`DELETE FROM e2e_snapshots WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		t.must(err)
		t.purgeBlobs(`res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		_, err = t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE ns = ?`, statePurged, n.id)
		t.must(err)
		t.metaChanged = true
		_, err = t.Exec(`UPDATE namespaces SET purged = 1 WHERE ns = ?`, n.id)
		t.must(err)
		// A remote branch's mirrored copy of its base goes too; nothing
		// reaches the base (§G.3).
		for _, sh := range t.remoteShadows(n) {
			t.purgeShadowNS(sh)
		}
		entry := map[string]any{"kind": "purge-ns"}
		if forced {
			entry["forced"] = true
		}
		_, nsID := t.appendNS(n, entry, nil, nil, n.configSeq, t.actorID(a))
		out = nsID.String()
		t.tags = append(t.tags, "ns:"+n.name)
		t.flushDocs = true
		return nil
	})
	return out, err
}

// PruneRequest is POST /r/{ns}/{name}/prune (§8.6).
type PruneRequest struct {
	Horizon string
	Keep    []string
	// Snapshot is the horizon's document sealed by a key-holding client
	// (seal.SealSnapshot), required for e2e resources and refused
	// elsewhere (§8.6).
	Snapshot string
}

// PruneResult is the answer to a prune.
type PruneResult struct {
	Horizon string // the effective horizon
	NSID    string // the prune entry's ns_id, if the horizon moved
	Archive string // the URL of the archive written, if any
}

// Prune prunes a resource's history below a horizon (§8.6), archiving the
// pruned range first when an archive destination is configured.
//
// The prune verb suffices when the archive exists and the horizon doesn't go
// below what the resource's retention rule keeps; otherwise the grant must
// be chained to a * key.
func (e *Engine) Prune(ctx context.Context, req Request, name string, pr PruneRequest) (*PruneResult, error) {
	var out *PruneResult
	err := e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(req.NS)
		if n == nil {
			return t.absentNS(req.NS, req.Cred)
		}
		cfg := t.config(n.configSeq)
		a, aerr := t.authenticate(n.name, n, cfg, req.Cred, nil)
		if aerr != nil {
			return aerr
		}
		if err := t.authorize(a, "prune", name); err != nil {
			return err
		}
		// 410 after authorisation, like every write (§6.2).
		if n.purged {
			return gone()
		}
		if n.isBranch() {
			return invalid("branches don't prune (§8.6)")
		}
		v := t.resolve(n, name, nil)
		if v.state == NotFound {
			return notFound()
		}
		if v.state == Purged {
			return gone()
		}
		hid, err := ids.Parse(pr.Horizon)
		if err != nil {
			return invalid("horizon must be an ancestor of the head")
		}
		h := t.findInAncestry(v.head, hid)
		if h == nil {
			return invalid("horizon must be an ancestor of the head")
		}
		if len(pr.Keep) > cfg.Limits.KeepPerResource {
			return limitErr(422, "too many kept revisions")
		}
		e2e := t.e2eContent(n, name)
		switch {
		case !e2e && pr.Snapshot != "":
			return invalid("snapshot is only for e2e resources, whose documents the server can't compute (§8.6)")
		case e2e && len(pr.Keep) > 0:
			return invalid("keep is not supported for e2e resources: the server can't keep documents it can't compute (protect revisions with retention or a lower horizon)")
		case e2e && pr.Snapshot == "":
			return invalid("pruning an e2e resource needs the horizon's document as a sealed snapshot (§8.6)")
		}
		var keep []*revRow
		for _, k := range pr.Keep {
			kid, err := ids.Parse(k)
			var row *revRow
			if err == nil {
				row = t.findInAncestry(v.head, kid)
			}
			if row == nil || row.kind != kindRev {
				return invalid("keep lists a revision that is not in the resource's history")
			}
			keep = append(keep, row)
		}
		h = t.protect(n, cfg, v.own.id, h)
		rule := cfg.retentionRule(name)
		dest, hasArchive := t.archiveDest(rule)
		noArchive := rule != nil && rule.NoArchive
		if noArchive {
			// The rule prunes without an archive (§8.6).
			dest, hasArchive = "", false
		}
		if e2e && !hasArchive {
			return invalid("pruning an e2e resource needs an archive destination (§8.6)")
		}
		if !a.star {
			// Applying a rule that says "archive": false, within what it
			// keeps, needs only prune: the * key was needed to write it.
			if !hasArchive && !noArchive {
				return forbidden("pruning where no archive is configured needs a grant chained to a * key")
			}
			if rule != nil && h.seq > t.retentionBoundary(rule, v.own) {
				return forbidden("going below what retention keeps needs a grant chained to a * key")
			}
		}
		env := t.basicEnvelope("prune", name, a)
		env["writes"], env["patches"] = []any{}, []any{}
		env["doc"] = map[string]any{"horizon": pr.Horizon, "keep": anyStrings(pr.Keep)}
		if err := t.checkRules(cfg, a, env, false); err != nil {
			return err
		}
		var res *PruneResult
		var perr error
		if e2e {
			res, perr = t.pruneToE2E(n, cfg, name, v.own, h, hid, pr, dest, t.actorID(a))
		} else {
			res, perr = t.pruneTo(n, name, v.own, h, keep, pr.Keep, dest, hasArchive, t.actorID(a))
		}
		if perr != nil {
			return perr
		}
		out = res
		return nil
	})
	return out, err
}

// protect moves a horizon down past the protected revisions of §8.6: the
// retry window and the heads as of the at of every live local branch and
// every unexpired remote branch registration.
func (t *tx) protect(n *nsRow, cfg *Config, res int64, h *revRow) *revRow {
	var minSeq sql.NullInt64
	cutoff := t.now.Add(-cfg.Limits.RetryWindow).UnixMilli()
	t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ? AND created >= ?`, res, cutoff).Scan(&minSeq))
	if minSeq.Valid && minSeq.Int64 < h.seq {
		h = t.rev(minSeq.Int64)
	}
	var ats []int64
	for _, b := range t.allBranchesOf(n) {
		ats = append(ats, b.baseAt.Int64)
	}
	// Remote branches whose registration hasn't expired (§G.3).
	ats = append(ats, t.registeredAts(n)...)
	for _, at := range ats {
		var p int64
		if err := t.QueryRow(`SELECT target_seq FROM head_history WHERE res = ? AND ns_seq <= ? ORDER BY ns_seq DESC LIMIT 1`, res, at).Scan(&p); err == nil && p < h.seq {
			h = t.rev(p)
		}
	}
	return h
}

// pruneTo prunes own below h, which protect has already moved down. With
// archive set, the pruned range is written to dest first, and nothing is
// dropped unless that succeeds.
func (t *tx) pruneTo(n *nsRow, name string, own *resRow, h *revRow, keep []*revRow, keepStrs []string, dest string, archive bool, author int64) (*PruneResult, error) {
	cur := own.horizonSeq
	if cur.Valid && h.seq <= cur.Int64 {
		return &PruneResult{Horizon: t.rev(cur.Int64).id.String()}, nil
	}
	// A horizon with nothing of its resource's chain below it (a first
	// entry) prunes nothing, and a prune that changes nothing writes
	// nothing (§8.6).
	var below bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM revisions WHERE res = ? AND seq < ?)`, own.id, h.seq).Scan(&below))
	if !below {
		return &PruneResult{Horizon: h.id.String()}, nil
	}
	// Documents that stay available: the horizon (and for a tombstone the
	// last live document), kept revisions and referenced schemas.
	refs := t.referencedPaths()
	keepSeqs := map[int64]*revRow{}
	keepSeqs[t.lastLive(h).seq] = t.lastLive(h)
	for _, k := range keep {
		keepSeqs[k.seq] = k
	}
	// Referenced schema revisions keep their documents; one already below
	// an earlier horizon keeps the snapshot it has.
	preserve := map[int64]bool{}
	rrows, qerr := t.Query(`SELECT seq, id, patches IS NOT NULL FROM revisions WHERE res = ? AND seq < ? AND kind = 0`, own.id, h.seq)
	t.must(qerr)
	for rrows.Next() {
		var seq int64
		var id []byte
		var hasPatches bool
		t.must(rrows.Scan(&seq, &id, &hasPatches))
		if refs["/r/"+n.name+"/"+name+"/rev/"+ids.FromBytes(id).String()] {
			if hasPatches {
				keepSeqs[seq] = nil
			} else {
				preserve[seq] = true
			}
		}
	}
	rrows.Close()
	docs := map[int64][]byte{}
	for seq, row := range keepSeqs {
		if row == nil {
			row = t.rev(seq)
		}
		doc, err := t.docBytesAt(row)
		if err != nil {
			return nil, invalid("a kept revision was already pruned")
		}
		docs[seq] = doc
	}
	// Archive before dropping anything (§8.6).
	res := &PruneResult{Horizon: h.id.String()}
	if archive {
		from := own.horizonSeq.Int64
		if !cur.Valid {
			t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ?`, own.id).Scan(&from))
		}
		u, err := t.writeArchive(n, name, own.id, from, h, dest)
		if err != nil {
			return nil, err
		}
		res.Archive = u
	}
	for seq, doc := range docs {
		_, err := t.Exec(`INSERT INTO snapshots (seq, res, doc) VALUES (?,?,?) ON CONFLICT (seq) DO UPDATE SET res = excluded.res, doc = excluded.doc`, seq, own.id, t.putDoc("snapshots", own.id, seq, doc))
		t.must(err)
	}
	// Attachments no kept document references end (§7.8); the archive
	// written above carries their blobs.
	kept := make([]int64, 0, len(keepSeqs)+len(preserve))
	for seq := range keepSeqs {
		kept = append(kept, seq)
	}
	for seq := range preserve {
		kept = append(kept, seq)
	}
	var epochs map[ids.ID]map[int]bool
	if t.isSealedNS(n) {
		// The epochs each blob is served under, before (§E.2.2).
		epochs = t.resourceBlobEpochs(n, own)
	}
	t.pruneBlobs(own.id, h.seq, kept)
	_, err := t.Exec(`UPDATE revisions SET patches = NULL WHERE res = ? AND seq < ? AND kind = 0`, own.id, h.seq)
	t.must(err)
	// Below the horizon only the documents kept above survive:
	// intermediate snapshots (D.4) and an earlier prune's keep set go,
	// or pruned revisions would still be served.
	srows, qerr := t.Query(`SELECT seq FROM snapshots WHERE res = ? AND seq < ?`, own.id, h.seq)
	t.must(qerr)
	var drop []int64
	for srows.Next() {
		var seq int64
		t.must(srows.Scan(&seq))
		if _, kept := keepSeqs[seq]; !kept && !preserve[seq] {
			drop = append(drop, seq)
		}
	}
	srows.Close()
	for _, seq := range drop {
		_, err = t.Exec(`DELETE FROM snapshots WHERE seq = ?`, seq)
		t.must(err)
	}
	t.flushDocs = true
	// Sealed copies of what was pruned go too, wherever they are served
	// (a branch reads through); kept documents keep their bytes.
	t.deletePrunedSealed(own.id, h.seq, keepSeqs)
	keepJSON := string(jsonv.Canonical(anyStrings(keepStrs)))
	_, err = t.Exec(`UPDATE resources SET horizon_seq = ?, keep = ? WHERE res = ?`, h.seq, keepJSON, own.id)
	t.must(err)
	if epochs != nil {
		t.pruneBlobEpochs(n, name, own.id, epochs)
	}
	target := h.seq
	_, nsID := t.appendNS(n, map[string]any{"resource": name, "kind": "prune", "target": h.id.String()}, &own.id, &target, n.configSeq, author)
	res.NSID = nsID.String()
	return res, nil
}

// allBranchesOf lists the direct branches of n that aren't purged.
func (t *tx) allBranchesOf(n *nsRow) []*nsRow {
	var out []*nsRow
	for _, b := range t.branchesOf(n) {
		if !b.purged {
			out = append(out, b)
		}
	}
	return out
}
