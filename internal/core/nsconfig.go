package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

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
	// exempt: the change draws no rate tokens, being by a * key or only a
	// freeze (§6.6). A batch's config change otherwise costs one token
	// from the principal and namespace buckets, as a config write does.
	exempt bool
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
	p.exempt = a.star || freezeOnly(writes, newDoc)
	if !inBatch && !p.exempt {
		if err := t.rateLimit(n, cur, a, nil, 1); err != nil {
			return nil, err
		}
	}
	// A purged namespace is 410 after authorisation and the rate limits
	// (§6.2 step 2, §8.5), before the retry lookup and the precondition. A
	// batch answers it itself, once its items are authorised too
	// (checkItems), so its plan keeps the configuration in force.
	if n.purged {
		if inBatch {
			p.cfg = cur
			return p, nil
		}
		return nil, t.purgedNS(n)
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
				// The retry carries what was recorded, gestures included
				// (§7.2); only a config entry has them (§7.4).
				var gjson sql.NullString
				if t.QueryRow(`SELECT gestures FROM ns_log WHERE seq = ? AND kind = ?`, nsSeq, nsKindCode("config")).Scan(&gjson) == nil && gjson.Valid {
					if g, ok := jsonv.Parse([]byte(gjson.String)); ok == nil {
						if m, ok := g.(map[string]any); ok {
							r.Entry = &LogEntry{}
							if s, ok := m["gesture"].(string); ok {
								r.Entry.Gesture = s
							}
							if s, ok := m["undoes"].(string); ok {
								r.Entry.Undoes = s
							}
						}
					}
				}
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
	// Step 4: the namespace document the write produces, validated as
	// §7.4 says, then the limits (§6.2): the patch-set and document limits
	// in force, as for a resource write, and an unfrozen branch against
	// its base's branchesPerNamespace (§6.6). Only a caller with
	// unrestricted read may read the namespace document.
	cfg, verr := t.validateConfig(n, cur, newDoc)
	if verr != nil {
		return nil, verr
	}
	readable := func() bool { return t.readsNS(n, cur, a, false) }
	if err := checkConfigLimits(cur.Limits, cc.Patches, p.canon, false, jsonv.Canonical(newDoc), readable); err != nil {
		return nil, err
	}
	if err := t.unfreezeLimit(n, cur, cfg); err != nil {
		return nil, err
	}
	p.cfg, p.doc = cfg, newDoc.(map[string]any)
	// Step 6: the *-key guard, then the in_use refusals, then the rules
	// (§6.2, §C.2).
	if (touchesGuarded(writes) || (cur.Read != "public" && cfg.Read == "public")) && !a.star {
		return nil, forbidden("this change needs a grant chained to a * key")
	}
	if err := t.configInUse(n, cur, cfg); err != nil {
		return nil, err
	}
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
// A limit or allowance prev holds unchanged is held to the deployment's
// maximums rather than refused (configMode, §6.6).
func (e *Engine) newConfig(doc any, prev, base map[string]any) (*Config, *Error) {
	cfg, err := parseConfigIn(doc, e.opt.Limits, e.opt.Maximums, configMode{prev: prev})
	if err == nil {
		// rulesPerNamespace, the document's own or the default, within the
		// deployment's maximum, counts every rule form of rules, roles and
		// key scopes (§12.2). It holds a creation, a branch's included,
		// and the writes that change what it bounds, not a document
		// stored over it (§6.6).
		if bound := min(cfg.Limits.RulesPerNS, e.opt.Maximums.RulesPerNS); cfg.ruleForms > bound && (base != nil || rulesOrBoundChanged(cfg.Doc, prev)) {
			err = sizeLimit("rulesPerNamespace", cfg.ruleForms, bound, fmt.Sprintf("more than %d rule forms in rules, roles and key scopes (§12.2)", bound))
		}
	}
	if err == nil && (prev == nil || base != nil || valuesChanged(cfg.Doc, prev)) {
		// A creation, a branch's included, or a write that changes limits
		// or encryption (§6.6 Values); never a stored document, nor an
		// epoch's rotation.
		err = cfg.checkValues()
	}
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

// valuesChanged reports whether doc changes from prev what the §6.6 Values
// inequality holds a config write to: limits, or encryption other than its
// epoch. An epoch moves on every rotation, the server's on a schedule and
// whenever read access is revoked (§E.2.1), and an E3 client's bump; it
// changes no term of the inequality, and refusing it would leave a
// namespace stored under an earlier bound, or a since lowered default,
// sealed under the key a revoked reader holds.
func valuesChanged(doc, prev map[string]any) bool {
	return !jsonv.Equal(doc["limits"], prev["limits"]) || !jsonv.Equal(withoutEpoch(doc["encryption"]), withoutEpoch(prev["encryption"]))
}

// withoutEpoch is an encryption member without its epoch.
func withoutEpoch(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(m))
	for k, x := range m {
		if k != "epoch" {
			out[k] = x
		}
	}
	return out
}

// rulesOrBoundChanged reports whether doc changes its rule forms, in
// rules, roles or key scopes, or its own rulesPerNamespace from prev (nil
// for a new namespace): the writes that bound holds (§6.6, §12.2). A
// document an earlier release stored over it, which checked only the
// deployment's maximum, or counted only rules, takes any other write, a
// freeze among them, as members stored under an earlier version are kept
// until they are changed (§7.4).
func rulesOrBoundChanged(doc, prev map[string]any) bool {
	if prev == nil {
		return true
	}
	dl, _ := doc["limits"].(map[string]any)
	pl, _ := prev["limits"].(map[string]any)
	return !jsonv.Equal(ruleLists(doc), ruleLists(prev)) || !jsonv.Equal(dl["rulesPerNamespace"], pl["rulesPerNamespace"])
}

// ruleLists gathers the rule lists of a namespace document that
// rulesPerNamespace counts: rules, each role's and each key scope's, by
// role name and kid, leaving out roles and keys without rules.
func ruleLists(doc map[string]any) map[string]any {
	out := map[string]any{}
	if v, ok := doc["rules"]; ok {
		out["rules"] = v
	}
	roles, _ := doc["roles"].(map[string]any)
	for name, r := range roles {
		if m, _ := r.(map[string]any); m != nil && m["rules"] != nil {
			out["roles/"+name] = m["rules"]
		}
	}
	keys, _ := doc["keys"].([]any)
	for _, k := range keys {
		if m, _ := k.(map[string]any); m != nil && m["rules"] != nil {
			kid, _ := m["kid"].(string) // unique (grant.ParseKeys)
			out["keys/"+kid] = m["rules"]
		}
	}
	return out
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
		return le.err()
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

// validateConfig validates the namespace document a config write produces
// as §7.4 says, at step 4 before the limits (§6.2): its members, then the
// branch fields and the level rules (Addendum E, Levels). Every refusal is
// 422, invalid with errors pointing at the member, or a limit of newConfig,
// so it comes before the *-key guard (§7.4, §C.2).
func (t *tx) validateConfig(n *nsRow, cur *Config, newDoc any) (*Config, *Error) {
	cfg, err := t.e.newConfig(newDoc, cur.Doc, nil)
	if err != nil {
		return nil, err
	}
	if !jsonv.Equal(cur.Doc["retention"], cfg.Doc["retention"]) {
		if aerr := t.e.checkArchives(cfg); aerr != nil {
			return nil, withPointer(aerr)
		}
	}
	if !jsonv.Equal(cur.Doc["base"], cfg.Doc["base"]) {
		return nil, docInvalid("/base", "/base cannot change (§7.4)")
	}
	if cfg.DraftsFor != nil && t.draftRoot(n) == "" {
		return nil, docInvalid("/drafts", "/drafts is only for local branches that aren't end-to-end encrypted (§7.4)")
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
	if n.isBranch() {
		// A remote base's keys don't reach across (§7.6): the loop stops
		// at the shadow, which has none.
		for b := n; b.isBranch() && t.remoteShadow(b) == nil; {
			b = t.nsByID(b.base.Int64)
			if err := keepsStarKeys(cfg, b, t.config(b.configSeq)); err != nil {
				return nil, err
			}
		}
		base := t.nsByID(n.base.Int64)
		if cfg.Read == "public" && t.config(base.configSeq).Read != "public" {
			return nil, docInvalid("/read", "a branch of a non-public namespace cannot be public (§7.4)")
		}
		if err := t.checkNonceBase(cur, cfg, base); err != nil {
			return nil, err
		}
	}
	if err := t.checkSuccessor(n, cur, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// keepsStarKeys refuses a branch's namespace document that removes or
// changes a key entry that is a * key of b, one of its bases, whose
// configuration in force is bcfg (§7.4, §7.6): 422 at /keys.
func keepsStarKeys(cfg *Config, b *nsRow, bcfg *Config) *Error {
	for kid, k := range bcfg.starKeys() {
		nk, ok := findKey(cfg.Keys, kid)
		if !ok || string(nk.Pub) != string(k.Pub) || !nk.IsStar() {
			return docInvalid("/keys", fmt.Sprintf("key %q is a * key of base %s and must be kept unchanged (§7.4, §7.6)", kid, b.name))
		}
	}
	return nil
}

// checkSuccessor is the successor rule of §7.4 for a config write to n:
// only a write that sets or changes successor is checked (successorOK),
// so a successor purged since it was named blocks no other write.
func (t *tx) checkSuccessor(n *nsRow, cur, cfg *Config) *Error {
	if cfg.Successor == "" || cfg.Successor == cur.Successor {
		return nil
	}
	var bases map[string]bool
	if n.isBranch() {
		bases = t.successorBases(n)
	}
	return t.successorOK(cfg.Successor, n.id, bases)
}

// successorOK checks a successor that a write sets or changes (§7.4): it
// must name another namespace than self (0 for one being created) that
// exists and isn't purged; for a branch, whose successorBases are bases, a
// branch of the same base or of a namespace further up its base chain,
// whose at may differ, as after a rebase (§F.4, §F.5); for a namespace
// that isn't a branch (bases nil), another namespace that isn't a branch.
func (t *tx) successorOK(name string, self int64, bases map[string]bool) *Error {
	s := t.nsByName(name)
	switch {
	case s == nil || s.isShadow():
		return docInvalid("/successor", "successor must name a namespace that exists (§7.4)")
	case s.id == self:
		return docInvalid("/successor", "successor must name another namespace (§7.4)")
	case s.purged:
		return docInvalid("/successor", "successor must name a namespace that isn't purged (§7.4)")
	case bases == nil && s.isBranch():
		return docInvalid("/successor", "the successor of a namespace that isn't a branch must not be a branch (§7.4)")
	case bases != nil && (!s.isBranch() || !bases[t.baseIdentity(s)]):
		return docInvalid("/successor", "the successor of a branch must be a branch of the same base or of a namespace further up its base chain (§7.4)")
	}
	return nil
}

// successorBases are the baseIdentity values a branch's successor may
// have (§7.4): n's base and every namespace further up its base chain. A
// remote base in the chain contributes itself and its own bases as the
// branch's base.chain names them, by origin and name, and ends the walk.
func (t *tx) successorBases(n *nsRow) map[string]bool {
	out := map[string]bool{}
	for b := n; b.isBranch(); {
		if sh := t.remoteShadow(b); sh != nil {
			var origin, ns string
			t.must(t.QueryRow(`SELECT origin, ns FROM remote_bases WHERE shadow = ?`, sh.id).Scan(&origin, &ns))
			out[origin+" "+ns] = true
			if ref := t.config(b.configSeq).Base; ref != nil {
				for _, c := range ref.Chain {
					out[origin+" "+c] = true
				}
			}
			break
		}
		b = t.nsByID(b.base.Int64)
		out[fmt.Sprint(b.id)] = true
	}
	return out
}

// unfreezeLimit refuses unfreezing a local branch whose base already has
// branchesPerNamespace live branches: unfreezing makes the branch live
// again, which counts against its base's limit as creating one does
// (§6.6, §8.4).
func (t *tx) unfreezeLimit(n *nsRow, cur, cfg *Config) *Error {
	if !n.isBranch() || !cur.Frozen || cfg.Frozen {
		return nil
	}
	base := t.nsByID(n.base.Int64)
	if base.isShadow() {
		return nil
	}
	if live, max := t.liveBranches(base, n), t.config(base.configSeq).Limits.BranchesPerNamespace; live >= max {
		return limitErr(422, "branchesPerNamespace", int64(live+1), int64(max), "too many live branches: the base already has branchesPerNamespace live branches (§6.6, §8.4)")
	}
	return nil
}

// configInUse is a config write's in_use refusals (409), at step 6 after
// the *-key guard (§6.2, §6.1, §7.4).
func (t *tx) configInUse(n *nsRow, cur, cfg *Config) *Error {
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
			return apiErr(409, "in_use", "dependents", anyStrings(deps), "message", "a namespace with public dependents cannot become sealed")
		}
	}
	if cfg.level > cur.level {
		if deps := t.lowerDependents(n, cfg.level); len(deps) > 0 {
			return apiErr(409, "in_use", "dependents", anyStrings(deps), "message", "raise the encryption level of these branches first")
		}
	}
	if err := t.checkNonceDependents(n, cur, cfg); err != nil {
		return err
	}
	if cur.Read == "public" && cfg.Read != "public" {
		deps := t.publicDependents(n)
		if len(deps) > 0 {
			return apiErr(409, "in_use", "dependents", anyStrings(deps))
		}
	}
	if n.isBranch() && (!sameStrings(cur.DraftsFor, cfg.DraftsFor) || cfg.level == levelE2E && cur.level != levelE2E) {
		// Narrowing drafts.for, or raising a branch to e2e, may leave a
		// reference to its drafts without a copy (§6.1, §7.4).
		if broken := t.brokenReferences(refChange{cfg: map[int64]*Config{n.id: cfg}}); len(broken) > 0 {
			return t.inUse(broken, "the change would leave references to this branch's draft schema revisions without a copy (§6.1)")
		}
	}
	return nil
}

// withPointer gives a 422 invalid that has only a message the errors
// member §7.4 asks for, its pointer the one the message starts with
// (messagePointer).
func withPointer(err *Error) *Error {
	if err == nil || err.Status != 422 || err.Body["code"] != "invalid" || err.Body["errors"] != nil {
		return err
	}
	msg, _ := err.Body["message"].(string)
	return docInvalid(messagePointer(msg), msg)
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

// liveBranches counts n's direct branches that are live (§6.6): neither
// frozen nor purged, leaving out except.
func (t *tx) liveBranches(n, except *nsRow) int {
	live := 0
	for _, b := range t.branchesOf(n) {
		if except != nil && b.id == except.id {
			continue
		}
		if !b.purged && !t.config(b.configSeq).Frozen {
			live++
		}
	}
	return live
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
	if old.cachePublic() && !p.cfg.cachePublic() || old.level < levelSealed && p.cfg.level >= levelSealed {
		// Public copies at the edge must go (§9); every response of the
		// namespace carries ns:{ns}. Its branches can't be public now
		// (planConfig refuses while they are, sealed pairs aside, which
		// keep serving ciphertext under their own tags). So must, on a
		// raise to sealed, whatever the read setting, the /heads pages
		// listing created, size and digest and the revisions sent with
		// Last-Modified and Repr-Digest (§7.1, §7.4), which the level now
		// hides. A level is never lowered, and e2e only at creation.
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
		if err := checkConfigGestures(&cc); err != nil {
			return err
		}
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
		meta := gestureMeta(cc.Gesture, cc.Undoes)
		_, nsID := t.appendNSMeta(n, map[string]any{"kind": "config", "target": p.id.String()}, meta, nil, &seq, seq, author)
		res = &WriteResult{Status: 201, NSID: nsID.String(), ConfigID: p.id.String(), Entry: &LogEntry{Gesture: cc.Gesture, Undoes: cc.Undoes}}
		return nil
	}()
	return res, err
}
