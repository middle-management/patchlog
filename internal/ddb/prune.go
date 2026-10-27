package ddb

// Pruning (§8.6). What a prune decides commits in its transaction: the
// resource's RES item records the new horizon — its position and id, its
// last live revision's position, whose document a fold above the horizon
// starts from (horizonBase), the keep set, and the positions below the
// horizon whose documents stay (kept) — pinned on the head and the
// horizon the checks read; the prune entry; and a PRUNING# marker. Those documents
// are SNAP#<name>#<pos> items, written before the commit (PutSnapshots):
// one left by a commit that then failed is a document its revision still
// has, which reads serve alike.
//
// From the commit on, reads go by the horizon: a document below it is
// its snapshot or a *PrunedError, a fold above it starts from the
// horizon's snapshot, and a log range reaching below it is pruned
// (PrunedBelow). The rest — the patch sets below the horizon, and the
// snapshots an earlier prune kept that this one doesn't — can't fit a
// transaction's 100 actions, so it goes right after the commit
// (PruneContent), and the marker last (DonePruning), once core has ended
// the attachments no kept document references. One that remains (the
// instance stopped between) names a prune to finish, which the sweep does
// (Pruning, core's SweepBlobs).

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// PrunedError is a document or log range below a pruning horizon that
// nothing kept: name's revision pos in ns (§8.6's 410 pruned).
type PrunedError struct {
	NS, Name string
	Pos      uint64
}

func (e *PrunedError) Error() string {
	return fmt.Sprintf("ddb: %s/%s at %d is pruned", e.NS, e.Name, e.Pos)
}

func keySnap(ns, name string, pos uint64) Key {
	return Key{nsPK(ns), "SNAP#" + name + "#" + padPos(pos)}
}

// keyPruning marks a prune of name whose content is still to go.
func keyPruning(ns, name string) Key { return Key{nsPK(ns), "PRUNING#" + name} }

// CommitPrune is a prune of name to the horizon at HorizonPos, whose
// head and horizon the checks read (OldHorizon 0: none).
type CommitPrune struct {
	Name       string
	HeadPos    uint64
	HeadID     string
	OldHorizon uint64
	HorizonPos uint64
	HorizonID  string
	// Base is the horizon's last live revision: the horizon, or a
	// tombstone horizon's parent.
	Base uint64
	// Keep is the keep set as served (canonical JSON); Kept the positions
	// below the horizon whose snapshots stay, Base among them.
	Keep string
	Kept []uint64
	// Archive records the archive the prune wrote of the range below the
	// horizon, nil for none (archives.go).
	Archive *ArchiveRow
	// E2ESnapshot is an e2e resource's horizon document as its client
	// sealed it (e2e.go), "" for others.
	E2ESnapshot string
}

// pruneActs are a prune's actions in its commit's transaction.
func (s *Store) pruneActs(c *Commit) []types.TransactWriteItem {
	p := c.Prune
	if p == nil {
		return nil
	}
	table := &s.Table
	cond := "headPos = :h AND headId = :i AND #st <> :pg AND "
	vals := map[string]types.AttributeValue{
		":h": avN(p.HeadPos), ":i": avS(p.HeadID), ":pg": avS("purged"),
		":hp": avN(p.HorizonPos), ":hi": avS(p.HorizonID), ":hb": avN(p.Base), ":k": avS(p.Keep), ":kp": avNs(p.Kept),
	}
	if p.OldHorizon == 0 {
		cond += "attribute_not_exists(horizonPos)"
	} else {
		cond += "horizonPos = :oh"
		vals[":oh"] = avN(p.OldHorizon)
	}
	acts := []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: table, Key: keyAV(keyRes(c.NS, p.Name)),
			UpdateExpression:          strptr("SET horizonPos = :hp, horizonId = :hi, horizonBase = :hb, keep = :k, kept = :kp"),
			ConditionExpression:       &cond,
			ExpressionAttributeNames:  map[string]string{"#st": "state"},
			ExpressionAttributeValues: vals,
		}},
		{Put: &types.Put{TableName: table, Item: withKey(keyPruning(c.NS, p.Name), item{
			"name": avS(p.Name), "horizonPos": avN(p.HorizonPos), "kept": avNs(p.Kept),
		})}},
	}
	if a := p.Archive; a != nil {
		acts = append(acts, types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyArch(c.NS, p.Name, a.FromPos, a.ToPos), a.item(p.Name))}})
	}
	if p.E2ESnapshot != "" {
		acts = append(acts, e2eSnapAct(s.Table, c.NS, p.Name, p.HorizonPos, p.E2ESnapshot))
	}
	return acts
}

// actions counts a prune's actions: the RES update, the marker, its
// archive's record and an e2e snapshot.
func (p *CommitPrune) actions() int {
	n := 2
	if p.Archive != nil {
		n++
	}
	if p.E2ESnapshot != "" {
		n++
	}
	return n
}

// PutSnapshots writes the documents a prune of name keeps, by position,
// before its commit.
func (s *Store) PutSnapshots(ctx context.Context, ns, name string, docs map[uint64][]byte) error {
	for pos, doc := range docs {
		if _, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: &s.Table, Item: withKey(keySnap(ns, name, pos), item{"pos": avN(pos), "doc": avS(string(doc))}),
		}); err != nil {
			return err
		}
	}
	return nil
}

// snapshot reads name's kept document at pos.
func (s *Store) snapshot(ctx context.Context, ns, name string, pos uint64) ([]byte, bool, error) {
	it, err := s.getItem(ctx, keySnap(ns, name, pos))
	if it == nil || err != nil {
		return nil, false, err
	}
	d, err := s.open(ctx, ns, name, "snap", strconv.FormatUint(pos, 10), item(it).s("doc"))
	return []byte(d), err == nil, err
}

// PruneContent drops what a committed prune of name in ns left: the
// patch sets below its horizon, and the snapshots below it that it
// doesn't keep. Only patch sets go: ids, created times, gestures and a
// revision's size and digest stay, so /heads at an earlier entry lists a
// pruned head as it did. It is idempotent, and leaves the marker for
// DonePruning; ok is false when there is no prune to finish.
func (s *Store) PruneContent(ctx context.Context, ns, name string) (ok bool, err error) {
	mk, err := s.getItem(ctx, keyPruning(ns, name))
	if mk == nil || err != nil {
		return false, err
	}
	m := item(mk)
	horizon := m.n("horizonPos")
	if horizon < 2 {
		return true, nil // nothing below it
	}
	kept := map[uint64]bool{}
	for _, k := range m.ns("kept") {
		kept[k] = true
	}
	var strip []Key
	if err := s.rangeOf(ctx, ns, "REV#"+name+"#", 0, horizon-1, 0, func(i item) bool {
		if i.has("patches") {
			strip = append(strip, Key{i.s("PK"), i.s("SK")})
		}
		return true
	}); err != nil {
		return false, err
	}
	for _, k := range strip {
		if _, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: &s.Table, Key: keyAV(k), UpdateExpression: strptr("REMOVE patches"),
		}); err != nil {
			return false, err
		}
	}
	var drop []Key
	if err := s.rangeOf(ctx, ns, "SNAP#"+name+"#", 0, horizon-1, 0, func(i item) bool {
		if !kept[i.n("pos")] {
			drop = append(drop, Key{i.s("PK"), i.s("SK")})
		}
		return true
	}); err != nil {
		return false, err
	}
	for _, k := range drop {
		if err := s.deleteKey(ctx, k); err != nil {
			return false, err
		}
	}
	// Sealed copies of what was pruned go too (core's deletePrunedSealed);
	// kept documents keep theirs.
	if err := s.deletePrunedSealed(ctx, ns, name, horizon, kept); err != nil {
		return false, err
	}
	// An e2e resource's earlier snapshots: the horizon's stands now.
	if err := s.deleteE2ESnapshots(ctx, ns, name, horizon); err != nil {
		return false, err
	}
	return true, nil
}

// DonePruning deletes a finished prune's marker.
func (s *Store) DonePruning(ctx context.Context, ns, name string) error {
	return s.deleteKey(ctx, keyPruning(ns, name))
}

// Pruning lists the prunes whose content is still to go, as (namespace,
// resource) pairs — a scan, for the sweep.
func (s *Store) Pruning(ctx context.Context) (nss, names []string, err error) {
	in := &dynamodb.ScanInput{
		TableName:                 &s.Table,
		FilterExpression:          strptr("begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": avS("PRUNING#")},
		ConsistentRead:            boolptr(true),
	}
	for {
		out, err := s.Client.Scan(ctx, in)
		if err != nil {
			return nil, nil, err
		}
		for _, raw := range out.Items {
			i := item(raw)
			nss = append(nss, strings.TrimPrefix(i.s("PK"), "NS#"))
			names = append(names, i.s("name"))
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nss, names, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// PrunedBelow is the newest revision (not tombstone) of name after
// position from and below the horizon, up to position to, whose patch set
// is gone: a log range (from, to] that holds one is pruned (core's
// prunedIn). 0: none. Until its prune is finished (its marker), every one
// below the horizon is gone, stripped or not; after, those a restore put
// back (archives.go) are served again.
func (s *Store) PrunedBelow(ctx context.Context, ns, name string, from, to uint64) (uint64, error) {
	res, err := s.getRes(ctx, ns, name)
	if err != nil || res == nil || res.horizonPos == 0 {
		return 0, err
	}
	return s.newestPruned(ctx, ns, name, from, min(to, res.horizonPos), res.horizonPos)
}

// newestPruned is the newest revision of name in (from, to], none above
// the horizon, whose patch set is gone (PrunedBelow): the horizon's own
// only if it has none (a remote branch's shadow mirrors a pruned base's
// horizon without one, §G.3), as SQL's prunedIn looks up to it.
func (s *Store) newestPruned(ctx context.Context, ns, name string, from, to, horizon uint64) (uint64, error) {
	unfinished, err := s.pruning(ctx, ns, name)
	if err != nil {
		return 0, err
	}
	var pos uint64
	err = s.newestFirst(ctx, ns, name, from, to, func(i item) bool {
		if i.s("kind") != "tombstone" && (unfinished && i.n("pos") < horizon || !i.has("patches")) {
			pos = i.n("pos")
			return false
		}
		return true
	})
	return pos, err
}

// pruning reports whether a prune of name is unfinished.
func (s *Store) pruning(ctx context.Context, ns, name string) (bool, error) {
	it, err := s.getItem(ctx, keyPruning(ns, name))
	return it != nil, err
}

// FirstRevSince is the first of name's revisions created at or after
// cutoff (milliseconds), 0 for none: read newest first, as far as the
// first one created before — created times follow the chain's order but
// for the instances' clock skew.
func (s *Store) FirstRevSince(ctx context.Context, ns, name string, cutoff int64) (uint64, error) {
	var pos uint64
	err := s.newestFirst(ctx, ns, name, 0, 999999999999, func(i item) bool {
		if int64(i.n("created")) < cutoff {
			return false
		}
		pos = i.n("pos")
		return true
	})
	return pos, err
}

// NthNewestRev is the position of name's k-th newest revision (k ≥ 1),
// 0 when it has fewer.
func (s *Store) NthNewestRev(ctx context.Context, ns, name string, k int) (uint64, error) {
	var pos uint64
	n := 0
	err := s.newestFirst(ctx, ns, name, 0, 999999999999, func(i item) bool {
		if n++; n == k {
			pos = i.n("pos")
			return false
		}
		return true
	})
	return pos, err
}

// newestFirst visits name's revisions in (from, to], newest first, while
// visit returns true.
func (s *Store) newestFirst(ctx context.Context, ns, name string, from, to uint64, visit func(item) bool) error {
	if to <= from {
		return nil
	}
	prefix := "REV#" + name + "#"
	in := &dynamodb.QueryInput{
		TableName:              &s.Table,
		KeyConditionExpression: strptr("PK = :pk AND SK BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(nsPK(ns)), ":lo": avS(prefix + padPos(from+1)), ":hi": avS(prefix + padPos(to)),
		},
		ScanIndexForward: boolptr(false),
		ConsistentRead:   boolptr(true),
		Limit:            int32ptr(100),
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return err
		}
		for _, it := range q.Items {
			if !visit(item(it)) {
				return nil
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// RetainedNames lists ns's resources that retention looks at: not purged,
// with a head, in byte order of name.
func (s *Store) RetainedNames(ctx context.Context, ns string) ([]string, error) {
	var out []string
	err := s.eachItem(ctx, ns, "RES#", func(i item) error {
		if i.s("state") != "purged" && i.n("headPos") > 0 {
			out = append(out, resName(i.s("SK")))
		}
		return nil
	})
	return out, err
}

// EachDoc visits name's documents from its horizon's last live one (the
// genesis if unpruned) up to its head, oldest first (core's ending of
// attachments, which reads every document a prune leaves servable). Only
// a chain of its own: branches, whose chains continue a base's, don't
// prune.
// headPos bounds the walk: the head the caller read.
func (s *Store) EachDoc(ctx context.Context, ns, name string, headPos uint64, visit func(doc any) error) error {
	res, err := s.getRes(ctx, ns, name)
	if err != nil || res == nil {
		return err
	}
	var start any
	var exists bool
	from := uint64(0)
	if res.horizonPos > 0 {
		b, ok, err := s.snapshot(ctx, ns, name, res.horizonBase)
		if err != nil {
			return err
		}
		if !ok {
			return apiErr(409, "conflict", "detail", "horizon snapshot missing")
		}
		if start, err = jsonv.Parse(b); err != nil {
			return err
		}
		exists, from = true, res.horizonBase
		if err := visit(start); err != nil {
			return err
		}
	}
	_, err = s.walkChain(ctx, ns, name, from, headPos, start, exists, func(_ uint64, d any, exists bool, patches string) (any, error) {
		p, err := jsonv.Parse([]byte(patches))
		if err != nil {
			return nil, err
		}
		out, _, err := applyPatches(d, exists, p)
		if err != nil {
			return nil, err
		}
		return out, visit(out)
	})
	return err
}

// EachSnapshot visits name's kept documents, with their positions.
func (s *Store) EachSnapshot(ctx context.Context, ns, name string, visit func(pos uint64, doc any) error) error {
	return s.eachItem(ctx, ns, "SNAP#"+name+"#", func(i item) error {
		if resNameFromRev(i.s("SK")) != "SNAP#"+name {
			return nil // another resource whose name extends this one
		}
		raw, err := s.open(ctx, ns, name, "snap", strconv.FormatUint(i.n("pos"), 10), i.s("doc"))
		if err != nil {
			return err
		}
		doc, err := jsonv.Parse([]byte(raw))
		if err != nil {
			return err
		}
		return visit(i.n("pos"), doc)
	})
}

// Attachments lists name's attachments in ns: those pruning ended, or
// those it hasn't.
func (s *Store) Attachments(ctx context.Context, ns, name string, pruned bool) ([]*BlobRow, error) {
	var out []*BlobRow
	err := s.eachItem(ctx, ns, "BLOB#"+name+"#", func(i item) error {
		if b := scanBlob(i); b.Name == name && b.Pruned == pruned {
			out = append(out, b)
		}
		return nil
	})
	return out, err
}
