package ddb

// The reads core's write gate makes (core's checkReads, answered by
// core/ddbreads.go): the state a write is checked against, item by item,
// with no transaction around them — the commit (commit.go) pins what the
// checks relied on, and a commit that finds it moved is checked again
// (D.3's recheck).

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// NSRow is a namespace's meta and log tip.
type NSRow struct {
	Frozen, Purged bool
	// A branch's base, the position it branched at in the base's log, and
	// the base's configuration then (§7.6); "" for none.
	Base               string
	BaseAt, BaseCfgPos uint64
	ConfigPos          uint64
	ConfigID           string
	TipPos             uint64
	TipID              string
}

// Namespace reads ns's meta and tip; nil when it doesn't exist.
func (s *Store) Namespace(ctx context.Context, ns string) (*NSRow, error) {
	out, err := s.Client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			s.Table: {Keys: []map[string]types.AttributeValue{keyAV(keyMeta(ns)), keyAV(keyTip(ns))}, ConsistentRead: boolptr(true)},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(out.UnprocessedKeys) > 0 {
		return nil, apiErr(503, "throughput", "detail", "unprocessed keys")
	}
	var r *NSRow
	var t *tip
	for _, it := range out.Responses[s.Table] {
		switch i := item(it); i.s("SK") {
		case "#META":
			m := scanNSMeta(i)
			r = &NSRow{Frozen: m.frozen, Purged: m.purged, ConfigPos: m.configPos, ConfigID: m.configID,
				Base: m.base, BaseAt: m.baseAt, BaseCfgPos: m.baseCfgPos}
		case "#TIP":
			t = scanTip(i)
		}
	}
	if r != nil && t != nil {
		r.TipPos, r.TipID = t.headPos, t.headID
	}
	return r, nil
}

// ConfigRow is one configuration of a namespace's chain.
type ConfigRow struct {
	Pos    uint64
	ID     string
	Doc    any
	Author string
	LogPos uint64 // the entry that put it in force
}

func scanConfigRow(i item) (*ConfigRow, error) {
	doc, err := jsonv.Parse([]byte(i.s("doc")))
	if err != nil {
		return nil, err
	}
	return &ConfigRow{Pos: i.n("pos"), ID: i.s("id"), Doc: doc, Author: i.s("author"), LogPos: i.n("logPos")}, nil
}

// ConfigAt reads ns's configuration at pos; nil when there is none.
func (s *Store) ConfigAt(ctx context.Context, ns string, pos uint64) (*ConfigRow, error) {
	it, err := s.getItem(ctx, keyCfg(ns, pos))
	if err != nil || it == nil {
		return nil, err
	}
	return scanConfigRow(item(it))
}

// ConfigByID finds ns's configuration id (GSI1); nil when there is none.
func (s *Store) ConfigByID(ctx context.Context, ns, id string) (*ConfigRow, error) {
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.Table,
		IndexName:              strptr(gsiName),
		KeyConditionExpression: strptr("G1PK = :g"),
		FilterExpression:       strptr("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":g": avS(g1RevID(id)), ":pk": avS(nsPK(ns)), ":sk": avS("CFG#"),
		},
	})
	if err != nil {
		return nil, err
	}
	for _, it := range q.Items {
		return scanConfigRow(item(it))
	}
	return nil, nil
}

// ResRow is a resource's head pointer: the head revision or tombstone,
// its state, the entry that moved it there, and a tombstone's last live
// revision.
type ResRow struct {
	HeadPos    uint64
	HeadID     string
	HeadNS     string // a purged read-through resource's head's namespace
	Tombstoned bool
	Purged     bool
	EntryID    string
	LastID     string
	LastPos    uint64
	// HorizonPos and HorizonID are the pruning horizon (0: none), Keep
	// its keep set as served (prune.go).
	HorizonPos uint64
	HorizonID  string
	Keep       string
}

// Resource reads ns's resource name; nil when it has none.
func (s *Store) Resource(ctx context.Context, ns, name string) (*ResRow, error) {
	r, err := s.getRes(ctx, ns, name)
	if err != nil || r == nil || r.headPos == 0 {
		return nil, err
	}
	return &ResRow{HeadPos: r.headPos, HeadID: r.headID, HeadNS: r.headNS, Tombstoned: r.state == "tombstoned", Purged: r.state == "purged", EntryID: r.entryID, LastID: r.lastID, LastPos: r.lastPos,
		HorizonPos: r.horizonPos, HorizonID: r.horizonID, Keep: r.keep}, nil
}

// RevAt reads resource name's chain at pos; nil when there is none.
func (s *Store) RevAt(ctx context.Context, ns, name string, pos uint64) (*RevInfo, error) {
	it, err := s.getItem(ctx, keyRev(ns, name, pos))
	if err != nil || it == nil {
		return nil, err
	}
	r := scanRevInfo(item(it))
	return &r, nil
}

// DocAt is the canonical document at resource name's pos — for a
// tombstone, the last live one (a restore's base): the head's from the
// document item the head keeps, a kept one's below a pruning horizon
// from its snapshot (prune.go), any other by folding the chain — from the
// horizon's document if pruned. One below the horizon that isn't kept is
// a *PrunedError.
func (s *Store) DocAt(ctx context.Context, ns, name string, pos uint64) ([]byte, error) {
	res, err := s.getRes(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	if res != nil && res.headPos == pos {
		it, err := s.getItem(ctx, keyDocHead(ns, name))
		if err != nil {
			return nil, err
		}
		if it == nil {
			return nil, apiErr(409, "conflict", "detail", "head document missing")
		}
		return []byte(item(it).s("doc")), nil
	}
	r, err := s.RevAt(ctx, ns, name, pos)
	if err != nil {
		return nil, err
	}
	if r != nil && r.Kind == "tombstone" {
		if pos == 1 && r.ParentNS != "" {
			// A tombstone on a revision read through from the base.
			return s.DocAt(ctx, r.ParentNS, name, r.ParentPos)
		}
		pos-- // the chain is linear: the tombstone's parent
	}
	if res != nil && res.horizonPos > 0 {
		// Below the horizon only a kept position's snapshot is served:
		// one an earlier prune kept goes after this one's commit.
		if pos >= res.horizonPos || res.keeps(pos) {
			if doc, ok, err := s.snapshot(ctx, ns, name, pos); err != nil || ok {
				return doc, err
			}
		}
		if pos < res.horizonPos {
			return s.docBelow(ctx, ns, name, res, pos)
		}
		base, ok, err := s.snapshot(ctx, ns, name, res.horizonBase)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, apiErr(409, "conflict", "detail", "horizon snapshot missing")
		}
		start, err := jsonv.Parse(base)
		if err != nil {
			return nil, err
		}
		_, canon, err := s.foldFrom(ctx, ns, name, res.horizonBase, pos, start, true)
		return canon, err
	}
	first := r
	if first == nil || first.Pos != 1 {
		if first, err = s.RevAt(ctx, ns, name, 1); err != nil {
			return nil, err
		}
	}
	// A chain whose first revision continues a foreign parent (§7.6)
	// folds from that parent's document.
	var start any
	var exists bool
	if first != nil && first.ParentNS != "" {
		b, err := s.DocAt(ctx, first.ParentNS, name, first.ParentPos)
		if err != nil {
			return nil, err
		}
		if start, err = jsonv.Parse(b); err != nil {
			return nil, err
		}
		exists = true
	}
	_, canon, err := s.foldFrom(ctx, ns, name, 0, pos, start, exists)
	return canon, err
}

// docBelow is the document at pos below res's horizon that isn't kept:
// pruned, unless a restore put back every patch set from the genesis or
// the nearest kept snapshot below it up to it (archives.go) — and its
// prune is finished (newestPruned).
func (s *Store) docBelow(ctx context.Context, ns, name string, res *resRow, pos uint64) ([]byte, error) {
	var from uint64
	for _, k := range res.kept {
		if k < pos && k > from {
			from = k
		}
	}
	if p, err := s.newestPruned(ctx, ns, name, from, pos); err != nil || p > 0 {
		if err == nil {
			err = &PrunedError{NS: ns, Name: name, Pos: p}
		}
		return nil, err
	}
	var start any
	var exists bool
	if from > 0 {
		b, ok, err := s.snapshot(ctx, ns, name, from)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, &PrunedError{NS: ns, Name: name, Pos: pos}
		}
		if start, err = jsonv.Parse(b); err != nil {
			return nil, err
		}
		exists = true
	}
	_, canon, err := s.foldFrom(ctx, ns, name, from, pos, start, exists)
	return canon, err
}

// EntryRow is one namespace log entry as stored.
type EntryRow struct {
	Pos      uint64
	PrevPos  uint64 // 0: the first entry
	ID       string
	Kind     string
	Body     string
	Author   string
	Created  int64
	Gesture  string
	Undoes   string
	Gestures string
	CfgPos   uint64
	GrantID  string
	NoAuth   bool
}

// EntryAt reads ns's log entry at pos; nil when there is none.
func (s *Store) EntryAt(ctx context.Context, ns string, pos uint64) (*EntryRow, error) {
	it, err := s.getItem(ctx, keyLog(ns, pos))
	if err != nil || it == nil {
		return nil, err
	}
	return scanEntry(item(it)), nil
}

func scanEntry(i item) *EntryRow {
	return &EntryRow{
		Pos: i.n("pos"), PrevPos: i.n("prevPos"), ID: i.s("id"), Kind: i.s("kind"), Body: i.s("body"), Author: i.s("author"),
		Created: int64(i.n("created")), Gesture: i.s("gesture"), Undoes: i.s("undoes"), Gestures: i.s("gestures"),
		CfgPos: i.n("cfgPos"), GrantID: i.s("grantId"), NoAuth: i.n("noAuth") != 0,
	}
}

// EntriesBetween visits ns's log entries after position from up to and
// including position to, in chain order, at most limit of them (0: all),
// while visit returns true.
func (s *Store) EntriesBetween(ctx context.Context, ns string, from, to uint64, limit int, visit func(*EntryRow) bool) error {
	return s.rangeOf(ctx, ns, "LOG#", from, to, limit, func(i item) bool { return visit(scanEntry(i)) })
}

// RevsBetween visits name's revisions after position from up to and
// including position to, oldest first, at most limit of them (0: all),
// while visit returns true.
func (s *Store) RevsBetween(ctx context.Context, ns, name string, from, to uint64, limit int, visit func(*RevInfo) bool) error {
	return s.rangeOf(ctx, ns, "REV#"+name+"#", from, to, limit, func(i item) bool {
		ri := scanRevInfo(i)
		return visit(&ri)
	})
}

// rangeOf visits the items prefix+pos of ns's partition for positions in
// (from, to], in order, at most limit (0: all), while visit returns true.
func (s *Store) rangeOf(ctx context.Context, ns, prefix string, from, to uint64, limit int, visit func(item) bool) error {
	if to <= from {
		return nil
	}
	in := &dynamodb.QueryInput{
		TableName:              &s.Table,
		KeyConditionExpression: strptr("PK = :pk AND SK BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(nsPK(ns)), ":lo": avS(prefix + padPos(from+1)), ":hi": avS(prefix + padPos(to)),
		},
		ConsistentRead: boolptr(true),
	}
	if limit > 0 {
		in.Limit = int32ptr(int32(min(limit, 1000)))
	}
	n := 0
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return err
		}
		for _, it := range q.Items {
			if !visit(item(it)) {
				return nil
			}
			if n++; limit > 0 && n >= limit {
				return nil
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// EntryPos resolves ns's entry id to its position (the NSID marker,
// UNIQUE(ns, id)); 0 when there is none.
func (s *Store) EntryPos(ctx context.Context, ns, id string) (uint64, error) {
	it, err := s.getItem(ctx, keyNSID(ns, id))
	if err != nil || it == nil {
		return 0, err
	}
	return item(it).n("logPos"), nil
}
