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
		sealed, serr := r.atRest(p.n)
		if serr != nil {
			return "", serr
		}
		gid, err := b.storeGrant(ctx, p.a, sealed)
		if err != nil {
			return "", err
		}
		c := &ddb.Commit{
			NS: req.NS, Author: p.a.id(), Created: g.now.UnixMilli(), Grant: gid, NoAuth: p.a.noAuth, Via: viaOf(p.a),
			CfgPos: r.cfgs[p.n.configSeq].pos, CfgID: r.cfgRow(p.n.configSeq).ID,
		}
		var tags []string
		if name == "" {
			c.PurgeNS = true
			c.Entry, c.Kind = map[string]any{"kind": "purge-ns"}, "purge-ns"
			tags = []string{"ns:" + req.NS}
		} else {
			k := r.revs[p.head.seq].key
			c.Purge = &ddb.CommitPurge{Name: name, HeadPos: k.pos, HeadID: p.head.id.String()}
			if k.ns != req.NS {
				c.Purge.HeadNS = k.ns // read through from a base (§7.6)
			}
			c.Entry = map[string]any{"resource": name, "kind": "purge", "target": p.head.id.String()}
			c.Kind = "purge"
			tags = []string{"r:" + req.NS + "/" + name, "heads:" + req.NS}
		}
		if p.forced {
			c.Entry["forced"] = true
		}
		c.Repurge = b.repurgeOf(g.now, tags)
		// The copies its in_use check relied on stay (§6.1): another
		// purge of one makes this one stale.
		seen := map[ddb.ResourceRef]bool{{NS: req.NS, Name: name}: true}
		for _, cp := range r.copies {
			if !seen[cp] && (name == "" && cp.NS != req.NS || name != "") {
				seen[cp] = true
				c.Copies = append(c.Copies, cp)
			}
		}
		// The branches the purge reaches, as they read name before it
		// (purgeResource's branches first): one that sees no resource, or
		// a purged one, records nothing.
		var reach []branchPurge
		if name != "" {
			if reach, err = r.purgeReach(b.branchNames(ctx, req.NS), name); err != nil {
				return "", err
			}
		}
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
		b.purgedContent(ctx, req.NS, name)
		if name != "" {
			// Every branch the purge reaches records its own (§8.3).
			for _, bp := range reach {
				if err := b.propagatePurge(ctx, bp, name, p.a.id(), p.forced); err != nil {
					return "", err
				}
			}
		}
		return res.NSID, nil
	}
	return "", apiErr(409, "conflict", "detail", "the purge's state kept moving")
}

// purgedContent finishes a committed purge (finishPurge); what fails
// here is left to the sweep (sweepBlobs).
func (b *ddbBackend) purgedContent(ctx context.Context, ns, name string) {
	if err := b.finishPurge(ctx, ns, name); err != nil {
		log.Printf("ddb: purge of %s/%s committed, its content left to the sweep: %v", ns, name, err)
	}
}

// finishPurge deletes a committed purge's archives and content, then the
// bytes nothing names any more, as SQL's purge does in its transaction
// (deleteArchives, purgeBlobs). The archives go first: the content's
// deletion takes the marker that names the purge to finish.
func (b *ddbBackend) finishPurge(ctx context.Context, ns, name string) error {
	if err := b.deleteArchives(ctx, ns, name); err != nil {
		return err
	}
	// Destroying the data keys makes whatever survives of the content,
	// and of its archives, unreadable (§8.3, §E.1).
	if err := b.store.DeleteDEKs(ctx, ns, name); err != nil {
		return ddbAsErr(err)
	}
	b.keys.flush()
	// Its blobs' stored sealings (§E.2.2).
	sealings, err := b.store.DeleteBlobEpochs(ctx, ns, name, "")
	b.e.removeFiles(sealings)
	if err != nil {
		return ddbAsErr(err)
	}
	// A remote branch's mirrored copy goes too, in every shadow (§G.3).
	if err := b.purgeShadows(ctx, ns, name); err != nil {
		return err
	}
	hashes, err := b.store.PurgeContent(ctx, ns, name)
	var files []string
	if err == nil {
		files, err = b.store.CollectBytes(ctx, hashes)
	}
	b.e.removeFiles(files)
	return err
}

// branchNames lists the unpurged branches of ns, and theirs, depth first.
// purgeReach is what each of branches reads name at, before a purge
// (purgeResource's branches first): one that sees no resource, or a
// purged one, records nothing.
func (r *ddbReads) purgeReach(branches []string, name string) ([]branchPurge, error) {
	var reach []branchPurge
	for _, br := range branches {
		bn := r.nsByName(br)
		if bn == nil || bn.purged {
			continue
		}
		v, perr := ddbCheck(func() *view { return r.resolve(bn, name, nil) })
		if perr != nil {
			return nil, perr
		}
		if v.state == NotFound || v.state == Purged || v.head == nil {
			continue
		}
		k := r.revs[v.head.seq].key
		reach = append(reach, branchPurge{branch: br, headNS: k.ns, headPos: k.pos, headID: v.head.id.String()})
	}
	return reach, nil
}

// branchPurge is a branch a purge reaches and the head it read name at.
type branchPurge struct {
	branch, headNS, headID string
	headPos                uint64
}

func (b *ddbBackend) branchNames(ctx context.Context, ns string) []string {
	var out []string
	var walk func(string)
	walk = func(n string) {
		bs, err := b.store.Branches(ctx, n)
		if err != nil {
			return
		}
		for _, br := range bs {
			out = append(out, br.Name)
			walk(br.Name)
		}
	}
	walk(ns)
	return out
}

// propagatePurge records a purge of name in branch (purgeResource of
// nsops.go): the server's entry, which records no grant (§7.4), and the
// branch's own chain purged with it if it has one. A branch reading the
// resource through already answers 410: the base's is purged at every
// entry. bp is what the branch read before the base's purge.
func (b *ddbBackend) propagatePurge(ctx context.Context, bp branchPurge, name, author string, forced bool) error {
	branch := bp.branch
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		n := r.nsByName(branch)
		if n == nil || n.purged {
			return nil // a branch purged since is skipped (§8.5)
		}
		own, err := b.store.Resource(ctx, branch, name)
		if err != nil {
			return ddbAsErr(err)
		}
		if own != nil && own.Purged {
			return nil
		}
		target := bp.headID
		c := &ddb.Commit{
			NS: branch, Author: author, Created: b.e.now().UnixMilli(),
			CfgPos: r.cfgs[n.configSeq].pos, CfgID: r.cfgRow(n.configSeq).ID,
			Kind: "purge",
		}
		if own != nil {
			target = own.HeadID
			c.Purge = &ddb.CommitPurge{Name: name, HeadPos: own.HeadPos, HeadID: own.HeadID}
		} else {
			// Read through: the branch's own item, purged on the head it
			// read, as SQL inserts its row.
			hns := bp.headNS
			if hns == branch {
				hns = ""
			}
			c.Purge = &ddb.CommitPurge{Name: name, HeadPos: bp.headPos, HeadID: bp.headID, HeadNS: hns}
		}
		c.Entry = map[string]any{"resource": name, "kind": "purge", "target": target}
		if forced {
			c.Entry["forced"] = true
		}
		_, err = b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return ddbAsErr(err)
		}
		b.committed(branch, "r:"+branch+"/"+name, "heads:"+branch)
		b.purgedContent(ctx, branch, name)
		return nil
	}
	return apiErr(409, "conflict", "detail", "a branch's state kept moving")
}
