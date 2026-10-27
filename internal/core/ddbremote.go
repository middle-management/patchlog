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
	"sort"
	"strconv"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
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
		sealed, serr := r.atRest(p.n)
		if serr != nil {
			return nil, serr
		}
		gid, err := b.storeGrant(ctx, p.a, sealed)
		if err != nil {
			return nil, err
		}
		reg := &ddb.CommitRegistration{Origin: rr.Origin, Name: rr.NS, AtPos: r.logs[p.atSeq].pos, Expires: p.expires.UnixMilli()}
		if p.row != nil {
			reg.PrevPos = r.logs[p.row.nsSeq].pos
		}
		c := &ddb.Commit{
			NS: req.NS, Author: p.a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: p.a.noAuth, Via: viaOf(p.a),
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

func (r *ddbReads) entryGrantID(seq int64) []byte {
	if le := r.entry(seq); le != nil && le.GrantID != "" {
		id, err := ids.Parse(le.GrantID)
		r.must(err)
		return id[:]
	}
	return nil
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
		cfg, a, doc = c, ac, d
		if err := remoteObligations(req.NS, c, m); err != nil {
			return err
		}
		// Step 6, after the genesis is validated: the creating operator
		// grant's own rules (insertRemoteBranch).
		if err := t.checkCreationRules(ac, cc.Patches); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	gid, err := b.storeGrant(ctx, a, cfg.level >= levelAtRest)
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
		if err := b.store.ClearShadow(ctx, name); err != nil {
			return nil, ddbAsErr(err)
		}
		b.keys.flush() // a cleared shadow's data keys are gone
		im, err := b.shadowImport(ctx, name, m.read, m.levels[i], below, belowAt, heads, now, cfg.level)
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
		NS: req.NS, Author: a.id(), Grant: gid, NoAuth: a.noAuth, Via: viaOf(a),
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
//
// Its rows follow the branch's level: encrypted at rest, under the
// shadow's own data keys, at level at-rest or above.
func (b *ddbBackend) shadowImport(ctx context.Context, name, read string, lv *remoteLevel, base string, baseAt uint64, heads map[*remoteRes]shadowHead, now time.Time, level int) (*ddb.ShadowImport, error) {
	if lv.raise >= 0 {
		// A level raised to e2e before at mirrors its pre-raise history
		// and keys (Addendum E Levels), which this backend doesn't mirror.
		return nil, ddbUnsupported("mirroring a base raised to e2e")
	}
	cdoc := map[string]any{"read": read}
	if lv.enc != nil {
		// An e2e level: its epochs, for the keyring relay (§E.3.2).
		cdoc["encryption"] = lv.enc
	}
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
	for _, x := range lv.epochs {
		im.Epochs = append(im.Epochs, ddb.EpochKey{Epoch: x.e, Created: x.created.UnixMilli()})
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
		im.Log = append(im.Log, ddb.ShadowEntry{ID: en.ID, Kind: en.Kind, Body: string(body), Author: author, Created: parseCreated(en.Created, now), Via: viaJSON(en.Via)})
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
		sr, err := b.shadowChain(ctx, name, rr, heads, now, level)
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
func (b *ddbBackend) shadowChain(ctx context.Context, shadow string, rr *remoteRes, heads map[*remoteRes]shadowHead, now time.Time, level int) (*ddb.ShadowRes, error) {
	ch := rr.chain
	if rr.from >= len(ch.entries) {
		return nil, nil
	}
	owner := ownerFor(level, shadow, rr.name)
	seal := func(kind, key, plain string) string { return plain }
	if owner != "" {
		dek, err := b.dekFor(ctx, shadow, rr.name, true)
		if err != nil {
			return nil, err
		}
		seal = func(kind, key, plain string) string { return sealValue(dek, kind, shadow, rr.name, key, plain) }
	}
	sr := &ddb.ShadowRes{Name: rr.name}
	if rr.parent != nil {
		h := heads[rr.parent]
		sr.ParentNS, sr.ParentPos = h.ns, h.pos
	}
	attached := map[ids.ID]bool{}
	attach := func(bid ids.ID, pos uint64) error {
		bl := ch.blobs[bid]
		if bl == nil || attached[bid] {
			return nil
		}
		attached[bid] = true
		h := sha256.Sum256(bl.data)
		key, err := b.putOwnedBytes(ctx, owner, h[:], bl.data)
		if err != nil {
			return err
		}
		sr.Attach = append(sr.Attach, ddb.ShadowBlob{Bid: bid.String(), Type: bl.typ, Nonce: bl.nonce, Size: int64(len(bl.data)), Hash: key, Owner: owner, RefPos: pos})
		return nil
	}
	var declared [][]ids.ID
	if ch.opaque {
		var err error
		if declared, err = ch.declaredLists(); err != nil {
			return nil, err
		}
	}
	var lastDoc []byte
	err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		if i < rr.from {
			return nil
		}
		pos := uint64(len(sr.Revs) + 1)
		v := ddb.ShadowRev{ID: e.ID, ParentID: e.Parent, Author: RemoteAuthor, Created: parseCreated(e.Created, now), Signature: e.Signature, Via: viaJSON(e.Via),
			Legacy: mirroredLegacy(ch, e.ID)}
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
		if e.Kind == "tombstone" {
			v.Kind = "tombstone"
			sr.Revs = append(sr.Revs, v)
			return nil
		}
		if ch.opaque {
			// e2e content has no documents here (§E.3): its patch sets
			// and declared blobs (insertChain).
			v.Patches = seal("rev", e.ID, string(jsonv.Canonical(e.Patches)))
			for _, bid := range declared[i] {
				v.Declared = append(v.Declared, bid.String())
				if err := attach(bid, pos); err != nil {
					return err
				}
			}
			sr.Revs = append(sr.Revs, v)
			sr.LastLivePos = pos
			return nil
		}
		canon := jsonv.Canonical(doc)
		lastDoc = canon
		if e.HasPatches {
			v.Patches = seal("rev", e.ID, string(jsonv.Canonical(e.Patches)))
		} else {
			// The horizon: its document is kept as a snapshot (§8.6).
			sr.HorizonPos, sr.HorizonDoc = pos, seal("snap", strconv.FormatUint(pos, 10), string(canon))
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
			if err := attach(ref.bid, pos); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !ch.opaque {
		sr.HeadDoc = seal("head", strconv.FormatUint(sr.LastLivePos, 10), string(lastDoc))
	}
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
		if nsName == branch || row != nil && row.Base != "" {
			return conflict(byNS[nsName][0], "the schema namespace here is a branch")
		}
		if row != nil && row.Purged {
			// It refuses the history as any write to it (§8.5).
			var e *Error
			if err := b.gateRead(ctx, func(t *gate) error {
				e = t.purgedNS(t.nsByName(nsName))
				return nil
			}); err != nil {
				return err
			}
			e.Body["ns"] = nsName
			e.Body["message"] = "the schema namespace " + nsName + " here is purged, so the schemas can't be mirrored into it (§G.3, §8.5)"
			return e
		}
		src := m.schemaSources[nsName]
		if row != nil {
			// A mirror never ranks below its source (§2.1, §G.3).
			cur, err := b.configOf(ctx, nsName)
			if err != nil {
				return err
			}
			if targetRank(cur) < src.rank {
				return invalid(fmt.Sprintf("the schema namespace %s here is less protected than its source at the base (§2.1): "+
					"a remote branch's schema mirror never ranks below its source (§G.3)", nsName))
			}
		}
		created := row == nil
		if created {
			// By its source's protection (§2.1, mirrorSchemas of
			// remote_branch.go).
			read := "grant"
			if src.rank == rankPublic {
				read = "public"
			}
			doc := map[string]any{"read": read}
			if _, _, err := b.store.CreateNamespace(ctx, &ddb.Create{NS: nsName, Author: a.id(), Grant: gid, NoAuth: a.noAuth, Via: viaOf(a),
				Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
				return ddbAsErr(err)
			}
		}
		if err := b.mirrorInto(ctx, nsName, byNS[nsName], a, gid, conflict); err != nil {
			return err
		}
		if created && src.nonce {
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
		c := &ddb.Commit{NS: ns, Author: a.id(), Created: b.e.now().UnixMilli(), Grant: gid, NoAuth: a.noAuth, Via: viaOf(a),
			CfgPos: n.ConfigPos, CfgID: n.ConfigID, Kind: "batch"}
		level, err := b.nsLevelOf(ctx, ns)
		if err != nil {
			return err
		}
		var entries []any
		for _, s := range schemas {
			own, err := b.store.Resource(ctx, ns, s.name)
			if err != nil {
				return ddbAsErr(err)
			}
			from := 0
			it := ddb.CommitItem{Name: s.name}
			if own != nil {
				i, ok := s.chain.index[own.HeadID]
				if !ok {
					ri, err := b.store.ReadRevOf(ctx, ns, s.name, s.chain.last().ID)
					if err != nil {
						return ddbAsErr(err)
					}
					if ri == nil {
						return conflict(s, "the resource here holds a different history")
					}
				}
				if own.Purged {
					// One that holds the base's history refuses it as any
					// write to it does (410 gone, §7.2, §8.3).
					return gone("path", "/r/"+s.ns+"/"+s.name+"/rev/"+s.chain.last().ID,
						"message", "the resource here is purged, so its schema history can't be mirrored into it (§G.3, §8.3)")
				}
				switch {
				case ok && i == len(s.chain.entries)-1:
					continue // same head
				case ok:
					from = i + 1 // a prefix: extend it
					it.HeadPos, it.HeadID, it.HeadTombstoned, it.LastID, it.LastPos = own.HeadPos, own.HeadID, own.Tombstoned, own.LastID, own.LastPos
				default:
					continue // already contains the base's chain
				}
			}
			err = s.chain.fold(func(i int, e client.LogEntry, doc any) error {
				if i < from {
					return nil
				}
				if e.Kind != "tombstone" && !e.HasPatches {
					return ddbUnsupported("mirroring a schema the base pruned")
				}
				st := ddb.CommitStep{ID: e.ID, ParentID: e.Parent, Tombstone: e.Kind == "tombstone", Signature: e.Signature, Via: viaJSON(e.Via),
					Legacy: e.Kind != "tombstone" && mirroredLegacy(s.chain, e.ID),
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
		// Where history would be written: a frozen namespace refuses it as
		// any write to it (§8.4), and an e2e one, since only a key holder
		// seals content into e2e (§2.1, §E.3.1).
		cur, err := b.configOf(ctx, ns)
		if err != nil {
			return err
		}
		if cur.Frozen {
			e := apiErr(409, "frozen", "message", "the schema namespace "+ns+" here is frozen, so the schemas can't be mirrored into it (§G.3, §8.4)")
			if cur.Successor != "" {
				e.Body["successor"] = cur.Successor
			}
			return e
		}
		if cur.level == levelE2E {
			return invalid("the schema namespace " + ns + " here is end-to-end, so the schemas can't be mirrored into it: " +
				"only a key holder seals content into e2e (§2.1, §G.3)")
		}
		c.Entry = map[string]any{"kind": "batch", "entries": entries}
		names := make([]string, len(c.Items))
		for i, it := range c.Items {
			names[i] = it.Name
		}
		if c.Seal, err = b.sealer(ctx, ns, level, names); err != nil {
			return asErrOrNil(err)
		}
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
		c := &ddb.Commit{NS: ns, Author: a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: a.noAuth, Via: viaOf(a),
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

// --- following the base, and registering with it ---

func (b *ddbBackend) remoteBases(ctx context.Context, name string) ([]*remoteBase, error) {
	var rbs []*ddb.RemoteBase
	if name == "" {
		var err error
		if rbs, err = b.store.RemoteBases(ctx); err != nil {
			return nil, ddbAsErr(err)
		}
	} else {
		rb, err := b.store.RemoteBaseOf(ctx, name)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		if rb != nil {
			rbs = append(rbs, rb)
		}
	}
	out := make([]*remoteBase, 0, len(rbs))
	for _, rb := range rbs {
		n, err := b.store.Namespace(ctx, rb.Branch)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		x := &remoteBase{origin: rb.Origin, ns: rb.NS, at: rb.At, checkpoint: rb.Checkpoint, branchName: rb.Branch, purged: n == nil || n.Purged}
		if rb.RegNSID != "" {
			x.regNSID = sql.NullString{String: rb.RegNSID, Valid: true}
			x.regExpires = sql.NullInt64{Int64: rb.RegExpires, Valid: true}
		}
		out = append(out, x)
	}
	return out, nil
}

// followed is sqlFollowed on DynamoDB: the catch-up and each config
// change's epoch, level and read (followEpoch, followConfig); then each
// purge's notice, the purge applied to the branch as one in it would be
// (propagatePurge: its own entry, its branches', and the shadows'
// copies), then the checkpoint, moved from the one read — a follow that
// finds it moved does nothing.
func (b *ddbBackend) followed(ctx context.Context, rb *remoteBase, entries []client.NSEntry, head string, docs map[string]sourceDoc, catchUp *sourceDoc, catchErr error) error {
	// The epochs the base's config changes began, in the shadow mirroring
	// it, at the entries' times (followEpoch).
	// Then each config change's level and read (followConfig).
	var errs []error
	if catchUp != nil {
		errs = append(errs, b.followConfig(ctx, rb.branchName, rb.checkpoint, *catchUp))
	}
	for _, en := range entries {
		if d, ok := docs[en.ID]; ok {
			errs = append(errs, b.followEpoch(ctx, shadowName(rb.branchName), d, parseCreated(en.Created, b.e.now())),
				b.followConfig(ctx, rb.branchName, en.ID, d))
		}
	}
	return errors.Join(append(errs, b.followPurges(ctx, rb, entries, head), catchErr)...)
}

// followEpochs: each shadow's epoch, begun now.
func (b *ddbBackend) followEpochs(ctx context.Context, docs map[string]sourceDoc) error {
	var errs []error
	for name, d := range docs {
		errs = append(errs, b.followEpoch(ctx, name, d, b.e.now().UnixMilli()))
	}
	return errors.Join(errs...)
}

// followEpoch records epoch d.epoch of an e2e base in shadow sh, begun at
// created, unless recorded (followEpoch of remote_branch.go): a keyless
// EPOCHKEY item, as the shadow's own epochs are.
func (b *ddbBackend) followEpoch(ctx context.Context, sh string, d sourceDoc, created int64) error {
	if d.level != levelE2E || d.epoch < 1 {
		return nil
	}
	if lvl, err := b.nsLevelOf(ctx, sh); err != nil || lvl != levelE2E {
		return err
	}
	return asErrOrNil(b.store.PutEpochStart(ctx, sh, d.epoch, created))
}

// followPurges records and applies the purges of entries, then moves the
// checkpoint to head.
func (b *ddbBackend) followPurges(ctx context.Context, rb *remoteBase, entries []client.NSEntry, head string) error {
	cur, err := b.store.RemoteBaseOf(ctx, rb.branchName)
	if err != nil {
		return ddbAsErr(err)
	}
	if cur == nil || cur.Checkpoint != rb.checkpoint {
		return nil // followed concurrently
	}
	bn, err := b.store.Namespace(ctx, rb.branchName)
	if err != nil {
		return ddbAsErr(err)
	}
	now := b.e.now().UnixMilli()
	for i, en := range entries {
		var names []string
		switch en.Kind {
		case "purge":
			names = []string{en.Resource}
		case "purge-ns":
			// Every name the base had, including those it read through
			// from its own bases.
			set := map[string]bool{}
			for _, sh := range b.shadowsOf(ctx, rb.branchName) {
				ns, err := b.store.ResourceNamesOf(ctx, sh)
				if err != nil {
					return ddbAsErr(err)
				}
				for _, n := range ns {
					set[n] = true
				}
			}
			names = sortedKeys(set)
		default:
			continue
		}
		res := ""
		if en.Kind == "purge" {
			res = en.Resource
		}
		applied := bn != nil && !bn.Purged
		if err := b.store.PutNotice(ctx, rb.branchName, ddb.Notice{ID: en.ID, Kind: en.Kind, Resource: res, Applied: applied,
			Created: now, Seq: uint64(now)*1000 + uint64(i)}); err != nil {
			return ddbAsErr(err)
		}
		if !applied {
			log.Printf("remote branch %s: %s %v in %s/ns/%s recorded as a notice, not applied", rb.branchName, en.Kind, names, rb.origin, rb.ns)
			continue
		}
		for _, name := range names {
			if err := b.purgeAsServer(ctx, rb.branchName, name, RemoteAuthor); err != nil {
				return err
			}
		}
	}
	if err := b.store.SetCheckpoint(ctx, rb.branchName, rb.checkpoint, head); err != nil && !errors.Is(err, ddb.ErrStale) {
		return ddbAsErr(err)
	}
	return nil
}

// purgeAsServer purges name in ns and every branch of it as the server
// (purgeResource of nsops.go): entries recording no grant, the shadows'
// copies with them.
func (b *ddbBackend) purgeAsServer(ctx context.Context, ns, name, author string) error {
	all := append([]string{ns}, b.branchNames(ctx, ns)...)
	reach, err := newDDBReads(b, ctx).purgeReach(all, name)
	if err != nil {
		return err
	}
	for _, bp := range reach {
		if err := b.propagatePurge(ctx, bp, name, author, false); err != nil {
			return err
		}
	}
	for _, br := range all {
		if err := b.purgeShadows(ctx, br, name); err != nil {
			return err
		}
	}
	return nil
}

// shadowsOf lists the shadows a remote branch reads through, its base's
// first; none for another namespace.
func (b *ddbBackend) shadowsOf(ctx context.Context, branch string) []string {
	rb, err := b.store.RemoteBaseOf(ctx, branch)
	if err != nil || rb == nil {
		return nil
	}
	var out []string
	for sh := rb.Shadow; sh != ""; {
		out = append(out, sh)
		n, err := b.store.Namespace(ctx, sh)
		if err != nil || n == nil || n.Base == "" || n.Base[0] != '~' {
			break
		}
		sh = n.Base
	}
	return out
}

// purgeShadows removes name's mirrored copy ("" for every name) from
// every shadow of ns, if ns is a remote branch: the copy never outlives
// the branch's purge (purgeShadow of remote_branch.go).
func (b *ddbBackend) purgeShadows(ctx context.Context, ns, name string) error {
	for _, sh := range b.shadowsOf(ctx, ns) {
		if err := b.store.DeleteDEKs(ctx, sh, name); err != nil {
			return ddbAsErr(err)
		}
		b.keys.flush()
		hashes, err := b.store.PurgeShadow(ctx, sh, name)
		if err != nil {
			return ddbAsErr(err)
		}
		files, err := b.store.CollectBytes(ctx, hashes)
		b.e.removeFiles(files)
		if err != nil {
			return ddbAsErr(err)
		}
	}
	return nil
}

func (b *ddbBackend) registered(ctx context.Context, rb *remoteBase, nsID string, expires time.Time) error {
	return asErrOrNil(b.store.SetRegistration(ctx, rb.branchName, nsID, expires.UnixMilli()))
}

func (b *ddbBackend) remoteNotices(ctx context.Context, ns string) ([]RemoteNotice, error) {
	bases, err := b.remoteBases(ctx, ns)
	if err != nil {
		return nil, err
	}
	type seqd struct {
		n   RemoteNotice
		seq uint64
	}
	var all []seqd
	for _, rb := range bases {
		ns, err := b.store.Notices(ctx, rb.branchName)
		if err != nil {
			return nil, ddbAsErr(err)
		}
		for _, n := range ns {
			all = append(all, seqd{RemoteNotice{Branch: rb.branchName, ID: n.ID, Kind: n.Kind, Resource: n.Resource, Applied: n.Applied, Created: formatTime(n.Created)}, n.Seq})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].seq < all[j].seq })
	out := make([]RemoteNotice, len(all))
	for i, x := range all {
		out[i] = x.n
	}
	return out, nil
}

// viaJSON is a mirrored entry's delegation chain as the store records it
// (insertChain): canonical JSON, "" for none.
func viaJSON(via []string) string {
	if len(via) == 0 {
		return ""
	}
	return string(jsonv.Canonical(anyStrings(via)))
}

// mirroredLegacy reports whether a mirrored revision is under the schema
// rules before v0.73: unless the base serves it as v0.73's (fetchRules),
// as insertChain records a missing marker.
func mirroredLegacy(ch *remoteChain, id string) bool {
	r, ok := ch.rules[id]
	return !ok || r != schema.V073
}

// configOf is ns's configuration in force.
func (b *ddbBackend) configOf(ctx context.Context, ns string) (*Config, error) {
	var cfg *Config
	err := b.gateRead(ctx, func(t *gate) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		cfg = t.config(n.configSeq)
		return nil
	})
	return cfg, err
}
