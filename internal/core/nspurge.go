package core

import (
	"context"

	"github.com/middle-management/patchlog/internal/ids"
)

// Purge purges a resource (§8.3). It returns the purge entry's ns_id.
func (e *Engine) Purge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error) {
	return e.be.purge(ctx, req, name, ifMatch, force)
}

// sqlPurge is Purge on SQL.
func (e *Engine) sqlPurge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error) {
	var out string
	err := e.update(ctx, func(t *tx) error {
		p, err := t.planPurge(req, name, ifMatch, force)
		if err != nil {
			return err
		}
		// Every log the purge appends to, in ascending key order, after
		// every other lock (D.8).
		logs := make([]int64, 0, len(p.reached))
		for id := range p.reached {
			logs = append(logs, id)
		}
		t.lockLogs(logs...)
		out = t.purgeResource(p.n, name, t.actorID(p.a), p.forced).String()
		return nil
	})
	return out, err
}

// purgePlan is a purge the gate allowed (§8.3, §8.5): of a resource, the
// head it purges and every namespace it reaches.
type purgePlan struct {
	n       *nsRow
	a       *actor
	forced  bool
	head    *revRow
	reached map[int64]bool
}

// planPurge checks a resource purge (§8.3, §6.2): authentication, the
// verb, the precondition on the head, schema copies (§6.1), the rules.
func (t *gate) planPurge(req Request, name, ifMatch string, force bool) (*purgePlan, *Error) {
	n := t.nsForWrite(req.NS)
	if n == nil {
		return nil, t.absentNSOp(req.NS, req.Cred, force)
	}
	cfg := t.config(n.configSeq)
	a, operator, aerr := t.purger(n, cfg, req, force)
	if aerr != nil {
		return nil, aerr
	}
	if err := t.authorize(a, "purge", name); err != nil {
		return nil, err
	}
	// 410 after authorisation, like every write (§6.2).
	if n.purged {
		return nil, t.purgedNS(n)
	}
	if ifMatch == "" {
		return nil, apiErr(428, "precondition_required")
	}
	v := t.resolve(n, name, nil)
	switch v.state {
	case NotFound:
		return nil, notFound()
	case Purged:
		return nil, gone()
	}
	if ifMatch != v.head.id.String() {
		return nil, apiErr(412, "stale", "head", v.head.id.String())
	}
	// The purge reaches n and every branch it propagates to (§8.3),
	// each locked exclusively before it is read.
	reached := t.purgeReach(n)
	gone := func(ns *nsRow, res string) bool { return res == name && reached[ns.id] }
	forced := false
	if broken := t.brokenReferences(refChange{exclude: gone, removed: gone}); len(broken) > 0 {
		if !force {
			return nil, t.inUse(broken, "the purge would remove the last available copy of a referenced schema revision (§6.1)")
		}
		if err := t.mayForce(n, a, operator); err != nil {
			return nil, err
		}
		forced = true
	}
	if !operator {
		env := t.basicEnvelope("purge", name, a)
		env["writes"], env["doc"], env["patches"] = []any{}, nil, []any{}
		if err := t.checkRules(cfg, a, env, false); err != nil {
			return nil, err
		}
	}
	return &purgePlan{n: n, a: a, forced: forced, head: v.head, reached: reached}, nil
}

// purgeReach locks n and every unpurged branch a resource purge in n
// propagates to (§8.3) exclusively, in the order purgeResource does, and
// returns their ids.
func (t *gate) purgeReach(n *nsRow) map[int64]bool {
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
func (t *gate) purger(n *nsRow, cfg *Config, req Request, force bool) (a *actor, operator bool, err *Error) {
	t.reqCreds = req.anyCreds()
	a, err = t.authenticate(n.name, n, cfg, req.Cred, nil)
	if err == nil || !force || len(t.operatorKeys()) == 0 {
		return a, false, err
	}
	if oa, oerr := t.authenticate(n.name, nil, nil, req.Cred, t.operatorKeys()); oerr == nil {
		return oa, true, nil
	}
	return nil, false, err
}

// mayForce decides whether a purge refused as in_use may be forced (§6.1):
// with ?force=1 and a grant chained to a deployment operator key, or, for
// a purge of a branch or of a resource in one, to a * key of that branch,
// inherited or its own. A * key of a namespace that isn't a branch
// doesn't force. With authentication disabled everyone is the operator.
func (t *gate) mayForce(n *nsRow, a *actor, operator bool) *Error {
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
	// A branch purged since its base listed it is skipped (§8.5).
	if n.purged {
		return ids.ID{}
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
			// The documents' sizes and digests go with them (headMeta).
			_, err := t.Exec(`UPDATE revisions SET patches = NULL, size = NULL, digest = NULL WHERE res = ?`, res)
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
		// And the /heads pages, which list a head's document's size and
		// digest (NamespaceHeads): every branch the purge reaches purges
		// its own.
		t.tags = append(t.tags, "r:"+n.name+"/"+name, "heads:"+n.name)
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
	return e.be.purgeNamespace(ctx, req, ifMatch, force)
}

// planPurgeNS checks a namespace purge (§8.5): authentication, the verb,
// the precondition on the log's head, frozen, no dependents, schema
// copies (§6.1), the rules.
func (t *gate) planPurgeNS(req Request, ifMatch string, force bool) (*purgePlan, *Error) {
	n := t.nsForWrite(req.NS)
	if n == nil {
		return nil, t.absentNSOp(req.NS, req.Cred, force)
	}
	cfg := t.config(n.configSeq)
	a, operator, aerr := t.purger(n, cfg, req, force)
	if aerr != nil {
		return nil, aerr
	}
	if err := t.authorize(a, "purge-ns", ""); err != nil {
		return nil, err
	}
	// 410 after authorisation, like every write (§6.2).
	if n.purged {
		return nil, t.purgedNS(n)
	}
	if ifMatch == "" {
		return nil, apiErr(428, "precondition_required")
	}
	head := t.nsLogID(n.headSeq.Int64)
	if ifMatch != head.String() {
		return nil, apiErr(412, "stale", "head", head.String())
	}
	if !cfg.Frozen {
		return nil, apiErr(409, "not_frozen")
	}
	var deps []string
	for _, b := range t.branchesOf(n) {
		if !b.purged {
			deps = append(deps, b.name)
		}
	}
	if len(deps) > 0 {
		return nil, apiErr(409, "in_use", "dependents", anyStrings(deps))
	}
	gone := func(ns *nsRow, _ string) bool { return ns.id == n.id }
	forced := false
	if broken := t.brokenReferences(refChange{exclude: gone, removed: gone}); len(broken) > 0 {
		if !force {
			return nil, t.inUse(broken, "the namespace holds the last available copy of a schema revision referenced from another namespace (§6.1)")
		}
		if err := t.mayForce(n, a, operator); err != nil {
			return nil, err
		}
		forced = true
	}
	if !operator {
		env := t.basicEnvelope("purge-ns", "", a)
		env["writes"], env["doc"], env["patches"] = []any{}, nil, []any{}
		if err := t.checkRules(cfg, a, env, false); err != nil {
			return nil, err
		}
	}
	return &purgePlan{n: n, a: a, forced: forced}, nil
}

// sqlPurgeNamespace is PurgeNamespace on SQL.
func (e *Engine) sqlPurgeNamespace(ctx context.Context, req Request, ifMatch string, force bool) (string, error) {
	var out string
	err := e.update(ctx, func(t *tx) error {
		p, perr := t.planPurgeNS(req, ifMatch, force)
		if perr != nil {
			return perr
		}
		n, a, forced := p.n, p.a, p.forced
		t.deleteArchives(`res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
		t.deleteDEKs(`ns = ?`, n.id)
		// Sealed bytes and epoch keys go too (§E.2, §8.5).
		t.deleteSealed(`ns = ?`, n.id)
		t.deleteBlobEpochs(`ns = ?`, n.id)
		t.deleteEpochKeys(n.id)
		_, err := t.Exec(`UPDATE revisions SET patches = NULL, size = NULL, digest = NULL WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
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
