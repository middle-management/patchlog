package core

// Branches on DynamoDB (§7.6): the gate's planBranch over the table's
// reads, then a commit to the base whose entry is the "branch" one and
// which creates the branch in the same transaction (ddb.Commit.Branch),
// checked again if what it pinned moved. Reading through to the base,
// foreign parents and the listing are the reads' (ddbreads.go).

import (
	"context"
	"errors"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func (b *ddbBackend) createBranch(ctx context.Context, req Request, br BranchRequest) (res *WriteResult, err error) {
	e := b.e
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(ctx, b)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true}}
		type planned struct {
			p      *branchPlan
			replay *WriteResult
			err    *Error
		}
		out, perr := ddbCheck(func() planned {
			p, replay, err := g.planBranch(req, br)
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
		sealed, serr := r.atRest(p.base)
		if serr != nil {
			return nil, serr
		}
		gid, err := b.storeGrant(ctx, p.a, sealed)
		if err != nil {
			return nil, err
		}
		c := &ddb.Commit{
			NS: req.NS, Author: p.a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: p.a.noAuth, Via: viaOf(p.a),
			CfgPos: r.cfgs[p.base.configSeq].pos, CfgID: r.cfgRow(p.base.configSeq).ID,
			Entry: map[string]any{"kind": "branch", "name": p.name, "at": p.atID.String(), "target": p.cfgID.String()},
			Kind:  "branch",
			Branch: &ddb.CommitBranch{
				Name: p.name, AtPos: r.logs[p.atSeq].pos,
				CfgID: p.cfgID.String(), Patches: string(p.canon), Doc: string(jsonv.Canonical(p.doc)), Frozen: p.cfg.Frozen,
			},
		}
		if c.Branch.EpochKey, err = b.beginsEpoch(ctx, p.name, nil, p.cfg); err != nil {
			return nil, asErrOrNil(err)
		}
		cres, err := b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return nil, ddbAsErr(err)
		}
		return &WriteResult{Status: 201, NSID: cres.NSID, ConfigID: p.cfgID.String()}, nil
	}
	return nil, apiErr(409, "conflict", "detail", "the base's state kept moving")
}
