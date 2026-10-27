package core

// Purges on DynamoDB (§8.3, §8.5): the gate's planPurge or planPurgeNS
// over the table's reads, then the commit of what they decided
// (ddb.Commit's Purge or PurgeNS), checked again if what it pinned moved;
// then the content, which doesn't fit the commit's transaction
// (ddb.Store.PurgeContent). Reads answer 410 from the commit on; the
// content goes in this request, or, if it stopped first, with the next
// blob sweep (sweepBlobs). There are no branches here to propagate to.

import (
	"context"
	"errors"
	"log"

	"github.com/middle-management/patchlog/internal/ddb"
)

func (b *ddbBackend) purge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error) {
	return b.purgeWith(ctx, req, name, func(g *gate) (*purgePlan, *Error) {
		return g.planPurge(req, name, ifMatch, force)
	})
}

func (b *ddbBackend) purgeNamespace(ctx context.Context, req Request, ifMatch string, force bool) (string, error) {
	return b.purgeWith(ctx, req, "", func(g *gate) (*purgePlan, *Error) {
		return g.planPurgeNS(req, ifMatch, force)
	})
}

// purgeWith runs a purge of name ("" for the namespace) planned by plan.
func (b *ddbBackend) purgeWith(ctx context.Context, req Request, name string, plan func(*gate) (*purgePlan, *Error)) (nsID string, err error) {
	e := b.e
	ctx, span := e.dbSpan(ctx, "core.db.update")
	defer func() { endDBSpan(span, err) }()
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: e, now: e.now(), write: true}}
		type planned struct {
			p   *purgePlan
			err *Error
		}
		out, perr := ddbCheck(func() planned {
			p, err := plan(g)
			return planned{p, err}
		})
		switch {
		case perr != nil:
			return "", perr
		case out.err != nil:
			return "", out.err
		}
		p := out.p
		gid, err := b.storeGrant(ctx, p.a)
		if err != nil {
			return "", err
		}
		c := &ddb.Commit{
			NS: req.NS, Author: p.a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: p.a.noAuth,
			CfgPos: r.cfgs[p.n.configSeq].pos, CfgID: r.cfgRow(p.n.configSeq).ID,
		}
		var tags []string
		if name == "" {
			c.PurgeNS = true
			c.Entry, c.Kind = map[string]any{"kind": "purge-ns"}, "purge-ns"
			tags = []string{"ns:" + req.NS}
		} else {
			c.Purge = &ddb.CommitPurge{Name: name, HeadPos: r.revs[p.head.seq].key.pos, HeadID: p.head.id.String()}
			c.Entry = map[string]any{"resource": name, "kind": "purge", "target": p.head.id.String()}
			c.Kind = "purge"
			tags = []string{"r:" + req.NS + "/" + name, "heads:" + req.NS}
		}
		if p.forced {
			c.Entry["forced"] = true
		}
		c.Repurge = b.repurgeOf(g.now, tags)
		res, err := b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return "", ddbAsErr(err)
		}
		b.committed(req.NS, tags...)
		// The content, then the bytes nothing names any more, as SQL's
		// purge does in its transaction (purgeBlobs). Committed already:
		// what fails here is left to the sweep (sweepBlobs).
		hashes, err := b.store.PurgeContent(ctx, req.NS, name)
		var files []string
		if err == nil {
			files, err = b.store.CollectBytes(ctx, hashes)
		}
		e.removeFiles(files)
		if err != nil {
			log.Printf("ddb: purge of %s/%s committed, its content left to the sweep: %v", req.NS, name, err)
		}
		return res.NSID, nil
	}
	return "", apiErr(409, "conflict", "detail", "the purge's state kept moving")
}
