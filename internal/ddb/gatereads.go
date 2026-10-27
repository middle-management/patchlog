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
	ConfigPos      uint64
	ConfigID       string
	TipPos         uint64
	TipID          string
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
			r = &NSRow{Frozen: m.frozen, Purged: m.purged, ConfigPos: m.configPos, ConfigID: m.configID}
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
	Tombstoned bool
	EntryID    string
	LastID     string
	LastPos    uint64
}

// Resource reads ns's resource name; nil when it has none.
func (s *Store) Resource(ctx context.Context, ns, name string) (*ResRow, error) {
	r, err := s.getRes(ctx, ns, name)
	if err != nil || r == nil || r.headPos == 0 {
		return nil, err
	}
	return &ResRow{HeadPos: r.headPos, HeadID: r.headID, Tombstoned: r.state == "tombstoned", EntryID: r.entryID, LastID: r.lastID, LastPos: r.lastPos}, nil
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
// document item the head keeps, any other by folding the chain.
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
		pos-- // the chain is linear: the tombstone's parent
	}
	_, canon, err := s.FoldResource(ctx, ns, name, pos)
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
