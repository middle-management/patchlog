package core

// Remote branches on DynamoDB (§G.3). The source side: a registration is
// the gate's planRegistration over the table's reads, then a commit of
// its "branch" entry that records the registration (REG# items,
// ddb.Commit.Registration), conditioned on the latest entry the checks
// read; the registrations read back as SQL's remote_branches rows.

import (
	"context"
	"database/sql"
	"errors"

	"github.com/middle-management/patchlog/internal/ddb"
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
