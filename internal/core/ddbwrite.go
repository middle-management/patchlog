package core

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Writes on DynamoDB run the SQL path's gate (gate.go) over the table's
// reads (ddbreads.go), then commit its decision (ddb.Commit): steps 1–6
// of §6.2 are the same code on every backend, and the store contributes
// only its reads and the commit. The commit pins what the checks relied
// on; one that finds it moved (ddb.ErrStale) is checked again from the
// start, D.3's recheck, as a SQL write whose re-check fails is.

// ddbAttempts bounds how often a write is checked again because its
// commit found the state moved.
const ddbAttempts = 8

// ddbWriteItems is writeItems on DynamoDB: a resource write or a batch.
func (e *Engine) ddbWriteItems(ctx context.Context, req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun bool) (res *WriteResult, err error) {
	if req.Signature != "" {
		return nil, ddbUnsupported("author signatures")
	}
	for _, it := range items {
		if it.Resource == KeyringName {
			return nil, ddbUnsupported("e2e keyrings")
		}
		for _, st := range it.Steps {
			if st.Signature != "" {
				// The gate would verify one, but the commit stores none.
				return nil, ddbUnsupported("author signatures")
			}
		}
	}
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	drawn := false
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(e, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true, rateDrawn: &drawn}}
		type checked struct {
			p   *writePlan
			res *WriteResult
			err error
		}
		out, perr := ddbCheck(func() checked {
			p, res, err := g.checkItems(req, items, cc, source, isBatch, dryRun, drawn)
			return checked{p, res, err}
		})
		switch {
		case perr != nil:
			return nil, perr
		case out.err != nil:
			return nil, out.err
		case out.res != nil:
			return out.res, nil
		}
		p := out.p
		if p.cplan != nil {
			if err := ddbRefusals(p.cplan.cfg); err != nil {
				return nil, err
			}
		}
		c, cerr := ddbCheck(func() *ddb.Commit { return r.commitOf(g, p) })
		if cerr != nil {
			return nil, cerr
		}
		if c.Grant, err = e.ddbStoreGrant(ctx, p.a); err != nil {
			return nil, err
		}
		c.NoAuth = p.a.noAuth
		cres, err := e.ddb.store.Commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return nil, ddbAsErr(err)
		}
		res := p.result
		res.NSID = cres.NSID
		var tags []string
		if p.cplan != nil {
			res.ConfigID = p.cplan.id.String()
			e.ddbForgetConfig(req.NS)
			if old := r.config(p.n.configSeq); old.cachePublic() && !p.cplan.cfg.cachePublic() {
				tags = append(tags, "ns:"+req.NS)
			}
		}
		if !p.isBatch {
			res.Entry = ddbStepEntry(c, &c.Items[0], len(c.Items[0].Steps)-1)
			res.Entry.Grant = grantRefOf(p.a.grant)
		}
		e.ddbCommitted(req.NS, tags...)
		return res, nil
	}
	return nil, apiErr(409, "conflict", "detail", "the write's state kept moving")
}

// commitOf renders a checked plan as the store's commit (insertPlan and
// planEntry of write.go, as data): every item's steps on the head its
// checks read, the config change, the namespace entry.
func (r *ddbReads) commitOf(g *gate, p *writePlan) *ddb.Commit {
	ns := r.nsName(p.n.id)
	cfgRef := r.cfgs[p.n.configSeq]
	c := &ddb.Commit{
		NS: ns, Author: p.a.id(), Created: g.now.UnixMilli(),
		CfgPos: cfgRef.pos, CfgID: r.cfgRow(p.n.configSeq).ID,
	}
	var entries []any
	if cp := p.cplan; cp != nil {
		c.Config = &ddb.CommitConfig{ID: cp.id.String(), Patches: string(cp.canon), Doc: string(jsonv.Canonical(cp.doc)), Frozen: cp.cfg.Frozen}
		entries = append(entries, map[string]any{"kind": "config", "target": cp.id.String()})
	}
	for _, s := range p.st {
		it := ddb.CommitItem{Name: s.Resource}
		if h := s.view.head; h != nil {
			it.HeadPos, it.HeadID = r.revs[h.seq].key.pos, h.id.String()
			if h.kind == kindTombstone {
				it.HeadTombstoned = true
				if rr := r.resRows[s.view.own.id]; rr != nil {
					it.LastID, it.LastPos = rr.LastID, rr.LastPos
				}
			}
		}
		for j, step := range s.steps {
			cs := ddb.CommitStep{ID: step.id.String(), Tombstone: step.del, Gesture: s.Steps[j].Gesture, Undoes: s.Steps[j].Undoes}
			if step.parentID != nil {
				cs.ParentID = step.parentID.String()
			}
			if !step.del {
				cs.Patches = string(step.canon)
				if step.docCanon != nil {
					cs.Doc = string(step.docCanon)
				} else {
					cs.Doc = string(jsonv.Canonical(step.doc))
				}
			}
			it.Steps = append(it.Steps, cs)
		}
		it.Attach, it.EndPending = r.attachOf(s)
		c.Items = append(c.Items, it)
		final := s.steps[len(s.steps)-1]
		kind := "head"
		if final.del {
			kind = "tombstone"
		}
		entries = append(entries, map[string]any{"resource": s.Resource, "kind": kind, "target": final.id.String()})
	}
	if p.isBatch {
		c.Entry, c.Kind = map[string]any{"kind": "batch", "entries": entries}, "batch"
		if p.src != nil {
			c.Entry["source"] = p.src
		}
		if bg := batchGestures(p.st); bg != nil {
			c.Gestures = bg["gestures"]
		}
		return c
	}
	c.Entry = entries[0].(map[string]any)
	c.Kind = c.Entry["kind"].(string)
	c.Gesture, c.Undoes = p.st[0].Steps[0].Gesture, p.st[0].Steps[0].Undoes
	return c
}

// attachOf lists the blobs an item's steps reference that its resource
// hasn't attached (attachStep of blobs.go), each with the first step that
// references it, and the pending entries of every blob they reference,
// which the write ends.
func (r *ddbReads) attachOf(s *itemState) ([]ddb.BlobAttach, []ddb.BlobPending) {
	own := s.view.own.id
	var out []ddb.BlobAttach
	refs := map[string]bool{}
	for j, step := range s.steps {
		bids := make([]ids.ID, 0, len(step.blobs))
		for bid := range step.blobs {
			bids = append(bids, bid)
		}
		slices.SortFunc(bids, func(a, b ids.ID) int { return bytes.Compare(a[:], b[:]) })
		for _, bid := range bids {
			src := step.blobs[bid]
			if refs[bid.String()] {
				continue
			}
			refs[bid.String()] = true
			if !src.pending && src.res == own {
				continue // attached already
			}
			out = append(out, ddb.BlobAttach{Bid: bid.String(), Type: src.typ, Nonce: src.nonce, Size: src.size, Hash: src.hash, Step: j})
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	ps, err := r.s.PendingOf(r.ctx, r.res[own].ns)
	r.must(err)
	var end []ddb.BlobPending
	for _, p := range ps {
		if p.Name == s.Resource && refs[p.Bid] {
			end = append(end, ddb.BlobPending{Bid: p.Bid, Uploader: p.Uploader})
		}
	}
	return out, end
}

// ddbStepEntry is a committed step's resource log entry, as a write
// answers it (logEntry of resolve.go), less its grant (grantRefOf).
func ddbStepEntry(c *ddb.Commit, it *ddb.CommitItem, j int) *LogEntry {
	st := it.Steps[j]
	le := &LogEntry{ID: st.ID, Parent: st.ParentID, Kind: "rev", Author: c.Author, Created: formatTime(c.Created), Gesture: st.Gesture, Undoes: st.Undoes}
	if st.Tombstone {
		le.Kind = "tombstone"
	} else {
		le.Patches, le.size = jsonv.MustParse([]byte(st.Patches)), len(st.Patches)
	}
	return le
}

// ddbWriteConfig is WriteConfig on DynamoDB: a namespace's creation (the
// store's own, CreateNamespace), or a config change through the gate's
// planConfig (writeConfig of nsops.go).
func (e *Engine) ddbWriteConfig(ctx context.Context, req Request, cc ConfigChange) (res *WriteResult, err error) {
	if cc.IfNoneMatch {
		if remoteBaseIn(cc.Patches) {
			return nil, ddbUnsupported("branches")
		}
		return e.ddbCreateNamespace(ctx, req, cc)
	}
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(e, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true}}
		type planned struct {
			n   *nsRow
			cur *Config
			a   *actor
			p   *configPlan
			err error
		}
		out, perr := ddbCheck(func() planned {
			n := g.nsForWrite(req.NS)
			if n == nil {
				return planned{err: g.absentNS(req.NS, req.Cred)}
			}
			cur := g.config(n.configSeq)
			a, aerr := g.authenticate(n.name, n, cur, req.Cred, nil)
			if aerr != nil {
				return planned{err: aerr}
			}
			g.reqCreds = req.anyCreds()
			if err := checkConfigGestures(&cc); err != nil {
				return planned{err: err}
			}
			p, err := g.planConfig(n, cur, a, &cc, false)
			return planned{n, cur, a, p, err}
		})
		switch {
		case perr != nil:
			return nil, perr
		case out.err != nil:
			return nil, out.err
		case out.p.replay != nil:
			return out.p.replay, nil
		}
		n, p := out.n, out.p
		if err := ddbRefusals(p.cfg); err != nil {
			return nil, err
		}
		gid, err := e.ddbStoreGrant(ctx, out.a)
		if err != nil {
			return nil, err
		}
		c := &ddb.Commit{
			NS: req.NS, Author: out.a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: out.a.noAuth,
			CfgPos: r.cfgs[n.configSeq].pos, CfgID: r.cfgRow(n.configSeq).ID,
			Config: &ddb.CommitConfig{ID: p.id.String(), Patches: string(p.canon), Doc: string(jsonv.Canonical(p.doc)), Frozen: p.cfg.Frozen},
			Entry:  map[string]any{"kind": "config", "target": p.id.String()}, Kind: "config",
			Gesture: cc.Gesture, Undoes: cc.Undoes,
		}
		cres, err := e.ddb.store.Commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return nil, ddbAsErr(err)
		}
		e.ddbForgetConfig(req.NS)
		var tags []string
		if out.cur.cachePublic() && !p.cfg.cachePublic() {
			// Public copies at the edge must go (§9, insertConfig).
			tags = append(tags, "ns:"+req.NS)
		}
		e.ddbCommitted(req.NS, tags...)
		return &WriteResult{Status: 201, NSID: cres.NSID, ConfigID: p.id.String(), Entry: &LogEntry{Gesture: cc.Gesture, Undoes: cc.Undoes}}, nil
	}
	return nil, apiErr(409, "conflict", "detail", "the namespace's configuration kept moving")
}

// ddbCreateNamespace is PUT /ns/{ns} with If-None-Match: * (writeConfig's
// create path): checked by the gate as createNamespace checks it, less
// what this backend refuses, then the store's creation transaction.
func (e *Engine) ddbCreateNamespace(ctx context.Context, req Request, cc ConfigChange) (res *WriteResult, err error) {
	g := &gate{checkReads: newDDBReads(e, ctx), checkState: &checkState{e: e, now: e.now(), write: true}}
	type planned struct {
		a   *actor
		err *Error
	}
	out, perr := ddbCheck(func() planned {
		if n := g.nsForWrite(req.NS); n != nil {
			// The name is taken (writeConfig): 412 to whoever may know.
			if err := g.authorizeTaken(n, req); err != nil {
				return planned{err: err}
			}
			return planned{err: apiErr(412, "stale", "config", g.configID(n.configSeq).String())}
		}
		a, _, cfg, err := g.planCreate(req, cc)
		if err == nil {
			err = ddbRefusals(cfg)
		}
		if err == nil {
			err = checkConfigGestures(&cc)
		}
		return planned{a, err}
	})
	switch {
	case perr != nil:
		return nil, perr
	case out.err != nil:
		return nil, out.err
	}
	grantID, err := e.ddbStoreGrant(ctx, out.a)
	if err != nil {
		return nil, err
	}
	sctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	cfgID, nsID, err := e.ddb.store.CreateNamespace(sctx, &ddb.Create{
		NS: req.NS, Author: out.a.id(), Patches: cc.Patches,
		Grant: grantID, NoAuth: out.a.noAuth,
	})
	if err != nil {
		return nil, ddbAsErr(err)
	}
	e.ddbCommitted(req.NS)
	return &WriteResult{Status: 201, NSID: nsID, ConfigID: cfgID, Entry: &LogEntry{Gesture: cc.Gesture, Undoes: cc.Undoes}}, nil
}

// grantRefOf is the grant reference an entry written under g serves
// (grantRef of grantref.go), nil for none.
func grantRefOf(g *grant.Grant) map[string]any {
	if g == nil || len(g.Blocks) == 0 {
		return nil
	}
	return map[string]any{"id": g.ID().String(), "sub": g.Blocks[0].Sub, "kid": g.Blocks[0].Kid}
}

// ddbStoreGrant stores the grant a write is made under (storeGrant of
// write.go), before its commit (ddb.Store.PutGrant), and returns its id:
// "" for none. A grant whose root the engine has cached (grantRoots,
// which holds stored grants only) is stored already.
func (e *Engine) ddbStoreGrant(ctx context.Context, a *actor) (string, error) {
	if a == nil || a.grant == nil {
		return "", nil
	}
	id := a.grant.ID()
	gid := id.String()
	if _, ok := e.grantRoots.get(id); ok {
		return gid, nil
	}
	sg := ddb.StoredGrant{Blocks: a.grant.Stored()}
	if len(a.grant.Blocks) > 0 {
		sg.Sub, sg.Kid = a.grant.Blocks[0].Sub, a.grant.Blocks[0].Kid
	}
	if err := e.ddb.store.PutGrant(ctx, gid, sg); err != nil {
		return "", ddbAsErr(err)
	}
	e.grantRoots.put(id, grantRoot{sub: sg.Sub, kid: sg.Kid})
	return gid, nil
}
