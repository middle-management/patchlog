package core

// The reads of Addendum E's Levels and of the later v0.73 checks on
// DynamoDB: a raise from sealed to e2e, remote branches' names, levels and
// sources, schema rules, and the prune reads below a horizon. Raising a
// namespace from sealed to e2e is refused here (ddbRaiseRefused), so no
// namespace on the table has a raise: e2eRaiseOf is nil, and the reads
// that only run for a raise answer 501.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// ddbRaiseRefused refuses a config change raising a namespace to e2e,
// which this backend refuses (501): the table records no raise.
func ddbRaiseRefused(old, cfg *Config) *Error {
	if cfg.level == levelE2E && old.level != levelE2E {
		return ddbUnsupported("raising a namespace to e2e")
	}
	return nil
}

// --- raises from sealed: none here ---

func (r *ddbReads) e2eRaiseOf(n *nsRow) *e2eRaise { return nil }

func (r *ddbReads) preRaiseBlob(n *nsRow, head *revRow, bid ids.ID) *preRaise { return nil }

func (r *ddbReads) preRaiseGrant(n *nsRow, id ids.ID) (*nsRow, *e2eRaise, int64) {
	return nil, nil, 0
}

func (r *ddbReads) preRaiseBlobEpochs(p *preRaise, head *revRow, bid ids.ID) map[int]bool {
	panic(ddbUnsupported("raising a namespace from sealed to e2e"))
}

func (r *ddbReads) preRaiseBlobRev(p *preRaise, head *revRow, bid ids.ID) *revRow {
	panic(ddbUnsupported("raising a namespace from sealed to e2e"))
}

func (r *ddbReads) preRaiseConfig(raise *e2eRaise) *Config {
	panic(ddbUnsupported("raising a namespace from sealed to e2e"))
}

func (r *ddbReads) preRaiseEntryEpoch(n *nsRow, raise *e2eRaise, seq int64) int {
	panic(ddbUnsupported("raising a namespace from sealed to e2e"))
}

func (r *ddbReads) preRaiseEpoch(n *nsRow, row *revRow, raise *e2eRaise) int {
	panic(ddbUnsupported("raising a namespace from sealed to e2e"))
}

func (r *ddbReads) preRaiseHead(raise *e2eRaise, res int64) int64 {
	panic(ddbUnsupported("raising a namespace from sealed to e2e"))
}

// --- remote branches ---

// kidName: a shadow's kids name the remote base's chain it mirrors, the
// base itself for "~{branch}", base.chain's i-th name for "~{branch}~{i}".
func (r *ddbReads) kidName(b *nsRow) string {
	if !b.isShadow() {
		return b.name
	}
	branch, level, _ := strings.Cut(b.name[1:], "~")
	rb, err := r.s.RemoteBaseOf(r.ctx, branch)
	r.must(err)
	if rb == nil {
		return b.name
	}
	if level == "" {
		return rb.NS
	}
	i, err := strconv.Atoi(level)
	bn := r.nsByName(branch)
	if err != nil || bn == nil {
		return b.name
	}
	if base := r.config(bn.configSeq).Base; base != nil && i < len(base.Chain) {
		return base.Chain[i]
	}
	return b.name
}

// successorBases: as SQL's, a remote base by origin and name from the
// branch's remote record.
func (r *ddbReads) successorBases(n *nsRow) map[string]bool {
	out := map[string]bool{}
	for b := n; b.isBranch(); {
		if sh := r.remoteShadow(b); sh != nil {
			rb, err := r.s.RemoteBaseOf(r.ctx, b.name)
			r.must(err)
			if rb != nil {
				out[rb.Origin+" "+rb.NS] = true
				if ref := r.config(b.configSeq).Base; ref != nil {
					for _, c := range ref.Chain {
						out[rb.Origin+" "+c] = true
					}
				}
			}
			break
		}
		b = r.nsByID(b.base.Int64)
		out[b.name] = true
	}
	return out
}

// remoteShadow: n's shadow, if n is a remote branch.
func (r *ddbReads) remoteShadow(n *nsRow) *nsRow {
	if !n.isBranch() {
		return nil
	}
	if b := r.nsByID(n.base.Int64); b != nil && b.isShadow() {
		return b
	}
	return nil
}

// remoteSourceFor: as SQL's, over the write's context (withRemoteSource).
func (r *ddbReads) remoteSourceFor(n *nsRow, withAt bool) *remoteSourceDoc {
	rb, err := r.s.RemoteBaseOf(r.ctx, n.name)
	r.must(err)
	if rb == nil {
		panic(fmt.Errorf("ddb: %s is not a remote branch", n.name))
	}
	h, _ := r.ctx.Value(remoteSourcesKey{}).(*remoteSources)
	if h == nil {
		return &remoteSourceDoc{origin: rb.Origin, ns: rb.NS, err: fmt.Errorf("not read for this write"), down: true}
	}
	if d := h.docs[n.name]; d != nil && (d.withAt || !withAt) {
		return d
	}
	panic(&errNeedSource{branch: n.name, origin: rb.Origin, ns: rb.NS, at: rb.At, withAt: withAt})
}

// --- epochs ---

// epochNow: a shadow's latest recorded epoch, if later than its
// document's (followEpoch); otherwise the document's.
func (r *ddbReads) epochNow(b *nsRow) int {
	cur := r.config(b.configSeq).Epoch
	if !b.isShadow() {
		return cur
	}
	ks, err := r.s.EpochKeys(r.ctx, b.name)
	r.must(err)
	for _, k := range ks {
		cur = max(cur, k.Epoch)
	}
	return cur
}

func (r *ddbReads) hasEpochKey(ns int64, epoch int) bool {
	k, err := r.s.EpochKeyOf(r.ctx, r.nsName(ns), epoch)
	r.must(err)
	return k != nil && len(k.Wrapped) > 0
}

// snapshotKid: as SQL's, without raises: the newest revision of h's
// chain that isn't a tombstone or [] sets it, or the snapshot kept at an
// earlier horizon.
func (r *ddbReads) snapshotKid(n *nsRow, cfg *Config, h *revRow) (string, int, string) {
	inForce := fmt.Sprintf("namespace %s's epoch in force", n.name)
	for _, seg := range r.ancestry(h) {
		k := r.res[seg.res]
		for pos := r.revs[seg.max].key.pos; pos >= 1; pos-- {
			ri, err := r.s.RevAt(r.ctx, k.ns, k.name, pos)
			r.must(err)
			if ri == nil {
				break
			}
			row := r.rev(r.revHandle(k.ns, k.name, pos))
			if snap := r.e2eSnapshot(row); snap != "" {
				if kns, e, err := seal.ParseKid(kidOf(snap)); err == nil && kns == n.name {
					return n.name, e, fmt.Sprintf("the epoch of the snapshot kept at horizon %s of its chain", ri.ID)
				}
				return n.name, cfg.Epoch, inForce
			}
			if ri.Kind == "tombstone" {
				continue
			}
			var canon []byte
			if !ri.Pruned {
				p, err := r.b.openValue(r.ctx, k.ns, k.name, "rev", ri.ID, ri.Patches)
				r.must(err)
				canon = []byte(p)
			}
			if !ri.Pruned && string(canon) == "[]" {
				continue
			}
			if jwe, _, ok := seal.SealedOp(canon); ok {
				if kns, e, err := seal.ParseKid(kidOf(jwe)); err == nil && kns == n.name {
					return n.name, e, fmt.Sprintf("set by revision %s of its chain", ri.ID)
				}
			}
			return n.name, cfg.Epoch, inForce
		}
	}
	return n.name, cfg.Epoch, inForce
}

// --- resources ---

func (r *ddbReads) resOwner(n *nsRow, res int64) *nsRow {
	if ns := r.res[res].ns; ns != r.nsName(n.id) {
		return r.nsByName(ns)
	}
	return n
}

func (r *ddbReads) resLevel(res int64) int {
	if n := r.nsByName(r.res[res].ns); n != nil {
		return r.nsLevel(n)
	}
	return levelNone
}

// blobRevServed: a served revision of head's history references bid.
func (r *ddbReads) blobRevServed(head *revRow, bid ids.ID) bool {
	for _, seg := range r.ancestry(head) {
		if len(r.blobRefPositions(seg)[bid]) > 0 {
			return true
		}
	}
	return false
}

// --- schema rules markers (schemaload.go) ---

// docRules: as SQL's, the marker a copy inherits from the rows of id in
// the namespaces the write may copy from (copiesIn): Legacy if any is.
func (r *ddbReads) docRules(id ids.ID, doc any, sc *schemaCtx) schema.Rules {
	if !schema.IsSchemaDoc(doc) {
		return schema.V073
	}
	if rules, ok := sc.copied[id]; ok {
		return rules
	}
	from := map[string]bool{}
	add := func(n *nsRow) {
		for x := n; x != nil; {
			from[x.name] = true
			if !x.isBranch() {
				return
			}
			x = r.nsByID(x.base.Int64)
		}
	}
	if sc.target != nil {
		add(sc.target)
	}
	if sc.source != nil && sc.source.n != nil {
		add(sc.source.n)
	}
	rows, err := r.s.RevsWithID(r.ctx, id.String())
	r.must(err)
	rules := schema.V073
	for _, x := range rows {
		if from[x.NS] && x.Rev.Kind != "tombstone" && x.Rev.Legacy {
			rules = schema.Legacy
		}
	}
	if sc.copied == nil {
		sc.copied = map[ids.ID]schema.Rules{}
	}
	sc.copied[id] = rules
	return rules
}

// rowRules: the revision's marker, its REV item's legacy flag.
func (r *ddbReads) rowRules(seq int64) schema.Rules {
	k := r.revs[seq].key
	ri, err := r.s.RevAt(r.ctx, k.ns, k.name, k.pos)
	r.must(err)
	if ri != nil && ri.Legacy {
		return schema.Legacy
	}
	return schema.V073
}

// --- pruning ---

func (r *ddbReads) genesisSeq(res int64) int64 {
	k := r.res[res]
	return r.revHandle(k.ns, k.name, 1)
}

func (r *ddbReads) revsBelow(res, seq int64) bool { return r.revs[seq].key.pos > 1 }

func (r *ddbReads) liveRevsBelow(res, seq int64) []revBelow {
	k := r.res[res]
	var out []revBelow
	r.must(r.s.RevsBetween(r.ctx, k.ns, k.name, 0, r.revs[seq].key.pos-1, 0, func(ri *ddb.RevInfo) bool {
		if ri.Kind == "tombstone" {
			return true
		}
		id, err := ids.Parse(ri.ID)
		r.must(err)
		out = append(out, revBelow{seq: r.revHandle(k.ns, k.name, ri.Pos), id: id, hasPatches: !ri.Pruned})
		return true
	}))
	return out
}

func (r *ddbReads) snapshotsBelow(res, seq int64) []int64 {
	k := r.res[res]
	below := r.revs[seq].key.pos
	var pos []uint64
	r.must(r.s.EachSnapshot(r.ctx, k.ns, k.name, func(p uint64, _ any) error {
		if p < below {
			pos = append(pos, p)
		}
		return nil
	}))
	slices.Sort(pos)
	out := make([]int64, len(pos))
	for i, p := range pos {
		out[i] = r.revHandle(k.ns, k.name, p)
	}
	return out
}
