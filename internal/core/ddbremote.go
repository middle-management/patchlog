package core

// Remote branches on DynamoDB (§G.3). The branch side is a local branch of
// shadow namespaces imported from the verified base (createRemoteBranch,
// ddb/shadow.go). The source side: a registration is
// the gate's planRegistration over the table's reads, then a commit of
// its "branch" entry that records the registration (REG# items,
// ddb.Commit.Registration), conditioned on the latest entry the checks
// read; the registrations read back as SQL's remote_branches rows.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/verify"
)

func (b *ddbBackend) registerRemote(ctx context.Context, req Request, rr RemoteRegistration) (res *RegistrationResult, err error) {
	e := b.e
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	drawn := false
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true, rateDrawn: &drawn}}
		type planned struct {
			p      *regPlan
			replay *RegistrationResult
			err    *Error
		}
		out, perr := ddbCheck(func() planned {
			p, replay, err := g.planRegistration(req, rr)
			return planned{p, replay, err}
		})
		switch {
		case perr != nil:
			return nil, perr
		case out.err != nil:
			return nil, out.err
		case out.replay != nil:
			return out.replay, nil
		}
		p := out.p
		gid, err := b.storeGrant(ctx, p.a)
		if err != nil {
			return nil, err
		}
		reg := &ddb.CommitRegistration{Origin: rr.Origin, Name: rr.NS, AtPos: r.logs[p.atSeq].pos, Expires: p.expires.UnixMilli()}
		if p.row != nil {
			reg.PrevPos = r.logs[p.row.nsSeq].pos
		}
		c := &ddb.Commit{
			NS: req.NS, Author: p.a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: p.a.noAuth,
			CfgPos: r.cfgs[p.n.configSeq].pos, CfgID: r.cfgRow(p.n.configSeq).ID,
			Entry: p.entry, Kind: "branch", Registration: reg,
		}
		cres, err := b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return nil, ddbAsErr(err)
		}
		return p.result(cres.NSID), nil
	}
	return nil, apiErr(409, "conflict", "detail", "the registration kept moving")
}

// --- reads ---

func (r *ddbReads) registration(n *nsRow, origin, name string) *regRow {
	ns := r.nsName(n.id)
	reg, err := r.s.RegistrationOf(r.ctx, ns, origin, name)
	r.must(err)
	if reg == nil {
		return nil
	}
	out := &regRow{atSeq: r.logHandle(ns, reg.AtPos), nsSeq: r.logHandle(ns, reg.NSPos), expires: reg.Expires}
	if reg.PrevPos > 0 {
		out.prevSeq = sql.NullInt64{Int64: r.logHandle(ns, reg.PrevPos), Valid: true}
	}
	return out
}

func (r *ddbReads) entryBy(seq int64) (author, created int64) {
	k := r.logs[seq]
	le, err := r.s.EntryAt(r.ctx, k.ns, k.pos)
	r.must(err)
	if le == nil {
		return 0, 0
	}
	return r.authorHandle(le.Author), le.Created
}

// liveRegistrations: n's unexpired registrations.
func (r *ddbReads) liveRegistrations(n *nsRow) []map[string]any {
	ns := r.nsName(n.id)
	regs, err := r.s.Registrations(r.ctx, ns, r.e.now().UnixMilli())
	r.must(err)
	out := make([]map[string]any, 0, len(regs))
	for _, reg := range regs {
		out = append(out, map[string]any{
			"remote":  map[string]any{"origin": reg.Origin, "ns": reg.Name},
			"at":      r.nsLogID(r.logHandle(ns, reg.AtPos)).String(),
			"ns_id":   r.nsLogID(r.logHandle(ns, reg.NSPos)).String(),
			"expires": formatTime(reg.Expires),
		})
	}
	return out
}

// registeredAts: the ats of n's unexpired registrations, which protect
// history from pruning (§8.6).
func (r *ddbReads) registeredAts(n *nsRow) []int64 {
	ns := r.nsName(n.id)
	regs, err := r.s.Registrations(r.ctx, ns, r.e.now().UnixMilli())
	r.must(err)
	var out []int64
	for _, reg := range regs {
		out = append(out, r.logHandle(ns, reg.AtPos))
	}
	return out
}

// --- the branch side: creating a remote branch ---

// createRemoteBranch creates a remote branch (§G.3): the operator grant
// and genesis checked by the gate, the base fetched and verified outside
// any store work (fetchRemote), its schema closure mirrored by ordinary
// commits, the shadows imported (ddb.Store.ImportShadow), then the branch
// created over them in one transaction that checks the imports.
// Mirrored schemas stay if a later step fails: they are the base's
// verified history, and a retry finds them in place.
func (b *ddbBackend) createRemoteBranch(ctx context.Context, req Request, cc ConfigChange) (res *WriteResult, err error) {
	e := b.e
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	var cfg *Config
	taken := false
	if err := b.gateRead(ctx, func(t *gate) error {
		if t.nsByName(req.NS) != nil {
			taken = true
			return nil
		}
		c, _, _, err := t.checkRemoteGenesis(req, cc)
		cfg = c
		return asErr(err)
	}); err != nil {
		return nil, err
	}
	if taken {
		return b.createNamespace(ctx, req, cc) // 412 for a taken name
	}
	if err := ddbRefusals(cfg); err != nil {
		return nil, err
	}
	m, ferr := e.fetchRemote(ctx, cfg.Base)
	if ferr != nil {
		return nil, ferr
	}
	var doc map[string]any
	var a *actor
	if err := b.gateRead(ctx, func(t *gate) error {
		c, d, ac, err := t.checkRemoteGenesis(req, cc)
		if err != nil {
			return err
		}
		cfg, a = c, ac
		cc, doc, err = remoteObligations(c, d, cc, m)
		return asErr(err)
	}); err != nil {
		return nil, err
	}
	if err := ddbRefusals(cfg); err != nil {
		return nil, err
	}
	gid, err := b.storeGrant(ctx, a)
	if err != nil {
		return nil, err
	}
	if err := b.mirrorSchemas(ctx, m, req.NS, cfg, a, gid); err != nil {
		return nil, err
	}
	// The shadows, the bottom one first, each a branch of the one below
	// at that level's at.
	tokens := map[string]string{}
	heads := map[*remoteRes]shadowHead{}
	var below string
	var belowAt uint64
	now := e.now()
	for i := len(m.levels) - 1; i >= 0; i-- {
		name := shadowLevelName(req.NS, i)
		im, err := b.shadowImport(ctx, name, m.read, m.levels[i], below, belowAt, heads, now)
		if err != nil {
			return nil, err
		}
		tok, err := b.store.ImportShadow(ctx, im)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		tokens[name], below, belowAt = tok, name, uint64(len(im.Log))
	}
	inv := invalidation{nss: []string{req.NS}, meta: true}
	e.rc.begin(inv)
	defer e.invalidate(inv, false)
	cfgID, nsID, err := b.store.CreateRemoteBranch(ctx, &ddb.RemoteBranchCreate{
		NS: req.NS, Author: a.id(), Grant: gid, NoAuth: a.noAuth,
		Patches: string(jsonv.Canonical(cc.Patches)), Doc: string(jsonv.Canonical(doc)), Frozen: cfg.Frozen,
		Shadow: below, AtPos: belowAt, Tokens: tokens,
		Origin: m.base.Origin, BaseNS: m.base.NS, At: m.base.At,
	})
	if errors.Is(err, ddb.ErrStale) {
		return nil, apiErr(409, "conflict", "detail", "another creation of this remote branch overtook it")
	}
	if err != nil {
		return nil, ddbAsErr(err)
	}
	res = &WriteResult{Status: 201, NSID: nsID, ConfigID: cfgID}
	if e.opt.Remote.Register {
		if err := e.RegisterRemote(ctx, req.NS); err != nil {
			log.Printf("remote branch %s: registering with %s: %v", req.NS, cfg.Base.Origin, err)
		}
	}
	return res, nil
}

// shadowHead is where a mirrored resource's head is: a shadow's position.
type shadowHead struct {
	ns  string
	pos uint64
}

// shadowImport is one level's shadow (insertShadow of remote_branch.go,
// as data): its configuration genesis, its log up to at with identical
// ids, verified again, and the resources it mirrors, whose blobs' bytes
// it stores first. heads records each mirrored resource's head for the
// foreign parents of the levels above.
func (b *ddbBackend) shadowImport(ctx context.Context, name, read string, lv *remoteLevel, base string, baseAt uint64, heads map[*remoteRes]shadowHead, now time.Time) (*ddb.ShadowImport, error) {
	if lv.enc != nil {
		return nil, ddbUnsupported("e2e namespaces")
	}
	cdoc := map[string]any{"read": read}
	if lv.nonce {
		// The branch can't turn it off (checkNonceBase).
		cdoc["nonce"] = "required"
	}
	gcanon := jsonv.Canonical([]any{map[string]any{"op": "add", "path": "", "value": cdoc}})
	im := &ddb.ShadowImport{
		Name: name, Base: base, BaseAt: baseAt,
		CfgID: ids.Revision(nil, gcanon).String(), CfgPatches: string(gcanon), CfgDoc: string(jsonv.Canonical(cdoc)),
		Author: RemoteAuthor, Created: now.UnixMilli(),
	}
	for i, en := range lv.log {
		hf, err := verify.HashedForm(en)
		if err != nil {
			return nil, err
		}
		body := jsonv.Canonical(hf)
		var p *ids.ID
		if i > 0 {
			x := mustID(lv.log[i-1].ID)
			p = &x
		}
		if ids.Hash(p, body).String() != en.ID {
			return nil, fmt.Errorf("mirrored entry %s does not verify", en.ID)
		}
		author := RemoteAuthor
		if en.Author != "" {
			author = en.Author
		}
		im.Log = append(im.Log, ddb.ShadowEntry{ID: en.ID, Kind: en.Kind, Body: string(body), Author: author, Created: parseCreated(en.Created, now)})
	}
	for _, rr := range lv.res {
		if rr.chain == nil {
			// Purged at the base: only the head's id is known.
			kind := ""
			if rr.purgedKind == kindTombstone {
				kind = "tombstone"
			}
			im.Res = append(im.Res, ddb.ShadowRes{Name: rr.name, Purged: true, EntryIdx: rr.lastIdx,
				Revs: []ddb.ShadowRev{{ID: rr.target, Kind: kind, Author: RemoteAuthor, Created: now.UnixMilli()}}})
			heads[rr] = shadowHead{name, 1}
			continue
		}
		sr, err := b.shadowChain(ctx, rr, heads, now)
		if err != nil {
			return nil, err
		}
		if sr == nil {
			// Nothing of its own at this level: its head is the parent's.
			heads[rr] = heads[rr.parent]
			continue
		}
		sr.EntryIdx = rr.lastIdx
		im.Res = append(im.Res, *sr)
		heads[rr] = shadowHead{name, uint64(len(sr.Revs))}
	}
	return im, nil
}

// shadowChain is a mirrored resource's own part of its chain (insertChain
// of remote_branch.go, as data); nil if it has none at this level.
func (b *ddbBackend) shadowChain(ctx context.Context, rr *remoteRes, heads map[*remoteRes]shadowHead, now time.Time) (*ddb.ShadowRes, error) {
	ch := rr.chain
	if rr.from >= len(ch.entries) {
		return nil, nil
	}
	sr := &ddb.ShadowRes{Name: rr.name}
	if rr.parent != nil {
		h := heads[rr.parent]
		sr.ParentNS, sr.ParentPos = h.ns, h.pos
	}
	attached := map[ids.ID]bool{}
	var lastDoc []byte
	err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		if i < rr.from {
			return nil
		}
		pos := uint64(len(sr.Revs) + 1)
		v := ddb.ShadowRev{ID: e.ID, ParentID: e.Parent, Author: RemoteAuthor, Created: parseCreated(e.Created, now), Signature: e.Signature}
		if e.Author != "" {
			v.Author = e.Author
		}
		// One that isn't a gesture id is dropped, never stored.
		if ValidGesture(e.Gesture) {
			v.Gesture = e.Gesture
		}
		if ValidGesture(e.Undoes) {
			v.Undoes = e.Undoes
		}
		canon := jsonv.Canonical(doc)
		lastDoc = canon
		if e.Kind == "tombstone" {
			v.Kind = "tombstone"
			sr.Revs = append(sr.Revs, v)
			return nil
		}
		if e.HasPatches {
			v.Patches = string(jsonv.Canonical(e.Patches))
		} else {
			// The horizon: its document is kept as a snapshot (§8.6).
			sr.HorizonPos, sr.HorizonDoc = pos, string(canon)
		}
		if dm, ok := doc.(map[string]any); ok {
			if s, ok := dm["$schema"].(string); ok {
				v.SchemaRef = s
			}
		}
		size, digest := headMeta(canon)
		v.Size, v.Digest = uint64(size), digest
		sr.Revs = append(sr.Revs, v)
		sr.LastLivePos = pos
		// The blobs it references, fetched from the base: attached at
		// the first revision that does (attachMirrored).
		for _, ref := range blobRefsOf(doc) {
			bl := ch.blobs[ref.bid]
			if bl == nil || attached[ref.bid] {
				continue
			}
			attached[ref.bid] = true
			h := sha256.Sum256(bl.data)
			if err := b.putBytes(ctx, h[:], bl.data); err != nil {
				return err
			}
			sr.Attach = append(sr.Attach, ddb.ShadowBlob{Bid: ref.bid.String(), Type: bl.typ, Nonce: bl.nonce, Size: int64(len(bl.data)), Hash: h[:], RefPos: pos})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sr.HeadDoc = string(lastDoc)
	return sr, nil
}

// mirrorSchemas mirrors the schema closure into namespaces of this
// deployment that aren't branches (mirrorSchemas of remote_branch.go): a
// namespace created as SQL creates it, then one batch commit per
// namespace of the chains it lacks, each step with its own author and
// time; a namespace created for a source that requires nonces takes the
// setting last (requireNonces).
func (b *ddbBackend) mirrorSchemas(ctx context.Context, m *remoteMirror, branch string, cfg *Config, a *actor, gid string) error {
	byNS := map[string][]*remoteSchema{}
	for _, s := range m.schemas {
		byNS[s.ns] = append(byNS[s.ns], s)
	}
	conflict := func(s *remoteSchema, why string) *Error {
		return apiErr(409, "name_conflict", "path", "/r/"+s.ns+"/"+s.name+"/rev/"+s.chain.last().ID, "message", why)
	}
	for _, nsName := range sortedKeys(byNS) {
		row, err := b.store.Namespace(ctx, nsName)
		if err != nil {
			return ddbAsErr(err)
		}
		if nsName == branch || row != nil && (row.Base != "" || row.Purged) {
			return conflict(byNS[nsName][0], "the schema namespace here is a branch or purged")
		}
		created := row == nil
		if created {
			doc := map[string]any{"read": cfg.Read}
			for _, k := range []string{"keys", "roles", "encryption"} {
				if v, ok := cfg.Doc[k]; ok {
					doc[k] = jsonv.Clone(v)
				}
			}
			if _, _, err := b.store.CreateNamespace(ctx, &ddb.Create{NS: nsName, Author: a.id(), Grant: gid, NoAuth: a.noAuth,
				Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
				return ddbAsErr(err)
			}
		}
		if err := b.mirrorInto(ctx, nsName, byNS[nsName], a, gid, conflict); err != nil {
			return err
		}
		if created && m.schemaNonce[nsName] {
			if err := b.requireNonces(ctx, nsName, a, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

// mirrorInto commits the schema chains ns lacks as one batch entry.
func (b *ddbBackend) mirrorInto(ctx context.Context, ns string, schemas []*remoteSchema, a *actor, gid string, conflict func(*remoteSchema, string) *Error) error {
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		n, err := b.store.Namespace(ctx, ns)
		if err != nil || n == nil {
			return ddbAsErr(err)
		}
		c := &ddb.Commit{NS: ns, Author: a.id(), Created: b.e.now().UnixMilli(), Grant: gid, NoAuth: a.noAuth,
			CfgPos: n.ConfigPos, CfgID: n.ConfigID, Kind: "batch"}
		var entries []any
		for _, s := range schemas {
			own, err := b.store.Resource(ctx, ns, s.name)
			if err != nil {
				return ddbAsErr(err)
			}
			from := 0
			it := ddb.CommitItem{Name: s.name}
			if own != nil {
				if own.Purged {
					return conflict(s, "the resource here is purged")
				}
				i, ok := s.chain.index[own.HeadID]
				switch {
				case ok && i == len(s.chain.entries)-1:
					continue // same head
				case ok:
					from = i + 1 // a prefix: extend it
					it.HeadPos, it.HeadID, it.HeadTombstoned, it.LastID, it.LastPos = own.HeadPos, own.HeadID, own.Tombstoned, own.LastID, own.LastPos
				default:
					// Already containing the base's chain, or another
					// history.
					ri, err := b.store.ReadRevOf(ctx, ns, s.name, s.chain.last().ID)
					if err != nil {
						return ddbAsErr(err)
					}
					if ri != nil {
						continue
					}
					return conflict(s, "the resource here holds a different history")
				}
			}
			err = s.chain.fold(func(i int, e client.LogEntry, doc any) error {
				if i < from {
					return nil
				}
				if e.Kind != "tombstone" && !e.HasPatches {
					return ddbUnsupported("mirroring a schema the base pruned")
				}
				st := ddb.CommitStep{ID: e.ID, ParentID: e.Parent, Tombstone: e.Kind == "tombstone", Signature: e.Signature,
					Author: RemoteAuthor, Created: parseCreated(e.Created, b.e.now())}
				if e.Author != "" {
					st.Author = e.Author
				}
				if ValidGesture(e.Gesture) {
					st.Gesture = e.Gesture
				}
				if ValidGesture(e.Undoes) {
					st.Undoes = e.Undoes
				}
				if !st.Tombstone {
					st.Patches, st.Doc = string(jsonv.Canonical(e.Patches)), string(jsonv.Canonical(doc))
					if dm, ok := doc.(map[string]any); ok {
						st.SchemaRef, _ = dm["$schema"].(string)
					}
				}
				it.Steps = append(it.Steps, st)
				return nil
			})
			if err != nil {
				return asErrOrNil(err)
			}
			kind := "head"
			if s.chain.last().Kind == "tombstone" {
				kind = "tombstone"
			}
			entries = append(entries, map[string]any{"resource": s.name, "kind": kind, "target": s.chain.last().ID})
			c.Items = append(c.Items, it)
		}
		if len(c.Items) == 0 {
			return nil
		}
		c.Entry = map[string]any{"kind": "batch", "entries": entries}
		_, err = b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return ddbAsErr(err)
		}
		b.committed(ns, "ns:"+ns)
		return nil
	}
	return apiErr(409, "conflict", "detail", "a schema namespace kept moving")
}

// requireNonces turns on the nonce requirement of a schema namespace
// created for a source that requires nonces (requireNonces of nonce.go).
func (b *ddbBackend) requireNonces(ctx context.Context, ns string, a *actor, gid string) error {
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: b.e, now: b.e.now(), write: true}}
		type planned struct {
			n *nsRow
			p *configPlan
		}
		out, perr := ddbCheck(func() planned {
			n := g.nsForWrite(ns)
			cc := &ConfigChange{IfMatch: g.configID(n.configSeq).String(), Patches: []any{map[string]any{"op": "add", "path": "/nonce", "value": "required"}}}
			p, err := g.planConfig(n, g.config(n.configSeq), &actor{star: true}, cc, false)
			if err != nil {
				panic(err)
			}
			return planned{n, p}
		})
		if perr != nil {
			return perr
		}
		p := out.p
		c := &ddb.Commit{NS: ns, Author: a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: a.noAuth,
			CfgPos: r.cfgs[out.n.configSeq].pos, CfgID: r.cfgRow(out.n.configSeq).ID,
			Config: &ddb.CommitConfig{ID: p.id.String(), Patches: string(p.canon), Doc: string(jsonv.Canonical(p.doc)), Frozen: p.cfg.Frozen},
			Entry:  map[string]any{"kind": "config", "target": p.id.String()}, Kind: "config"}
		_, err := b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		return asErrOrNil(err)
	}
	return apiErr(409, "conflict", "detail", "a schema namespace kept moving")
}
