package ddb

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Config changes (the chain of ns_config, D.2): genesis is CreateNamespace;
// WriteConfig appends.

// ConfigState is WriteConfig's check-hook view of a namespace. Doc holds
// the *new* namespace document (after apply); NewFrozen, initialised to
// the current flag, is what the transaction writes — the hook sets it
// from the new document (§7.4).
type ConfigState struct {
	Exists    bool
	Frozen    bool
	Purged    bool
	ConfigID  string
	Cur       any // the current namespace document, the change's base
	Doc       any // the new namespace document (nil when absent)
	NewFrozen bool
}

// ConfigResult is a committed (or replayed) config change. A replay
// carries the gestures its entry recorded (§7.2).
type ConfigResult struct {
	ConfigID string
	NSID     string
	Created  int64 // the entry's stored time, milliseconds
	Replayed bool
	Gesture  string
	Undoes   string
}

// WriteConfig appends a configuration revision: the config chain's child
// of the current one, a config log entry, the tip move and the marker, in
// one transaction pinned on the configuration the check phase read
// (insertConfig + appendNS of nsops.go, as one transaction).
//
// apply folds the caller's config patches into a new namespace document;
// it runs inside the retry loop, after each state read, like
// WriteResource's check. checkConfig runs the caller's gate on the
// resulting state (after apply, so it sees the new document) and vetoes
// with a non-nil error. Both run per attempt.
//
// ifMatch is the request's precondition (§7.2, planConfig of nsops.go):
// required (428); one naming another configuration is first looked up as
// the change's own retry — the configuration it computes, written by this
// author — and otherwise 412 naming the current one. Both come before
// apply, as steps 2 and 3 are ordered.
func (s *Store) WriteConfig(ctx context.Context, ns, author, ifMatch string, patches any, gesture, undoes string, apply func(doc any, exists bool, patches any) (any, error), check func(*ConfigState) error) (*ConfigResult, error) {
	// Each attempt holds the namespace's commit lock, as a batch's does.
	var held func()
	defer func() { release(held) }()
	for attempt := 0; ; attempt++ {
		release(held)
		held = s.serialize(ns)
		m, cfgDoc, err := s.readConfigState(ctx, ns)
		if err != nil {
			return nil, err
		}
		t, err := s.getTip(ctx, ns)
		if err != nil {
			return nil, err
		}
		if m == nil {
			return nil, apiErr(404, "not_found", "namespace", ns)
		}
		if m.purged {
			return nil, apiErr(410, "purged", "namespace", ns)
		}
		if ifMatch == "" {
			return nil, apiErr(428, "precondition_required")
		}
		if ifMatch != m.configID {
			if res, err := s.replayConfig(ctx, ns, ifMatch, patches, author); res != nil || err != nil {
				return res, err
			}
			return nil, apiErr(412, "stale", "config", m.configID)
		}

		st := &ConfigState{Exists: true, Frozen: m.frozen, Purged: m.purged, ConfigID: m.configID, Cur: cfgDoc, Doc: cfgDoc, NewFrozen: m.frozen}
		doc, err := apply(cfgDoc, true, patches)
		if err != nil {
			return nil, err
		}
		st.Doc = doc
		if check != nil {
			if err := check(st); err != nil {
				return nil, err
			}
		}

		// The config revision ids like a resource's (§3.5, insertConfig):
		// over the canonical patches, parent the current configuration.
		parent, err := ids.Parse(m.configID)
		if err != nil {
			return nil, apiErr(500, "stored_config", "namespace", ns)
		}
		canon := jsonv.Canonical(patches)
		cfgID := ids.Revision(&parent, canon)

		var tipID *ids.ID
		if t.headID != "" {
			p, err := ids.Parse(t.headID)
			if err != nil {
				return nil, apiErr(500, "stored_tip", "namespace", ns)
			}
			tipID = &p
		}
		now := s.now().UnixMilli()
		body := jsonv.Canonical(map[string]any{"kind": "config", "target": cfgID.String()})
		entryID := ids.Hash(tipID, body)
		newPos := m.configPos + 1
		entry := logRow{pos: t.headPos + 1, id: entryID.String(), prevPos: t.headPos, kind: "config", body: string(body), author: author, created: now, cfgPos: newPos, gesture: gesture, undoes: undoes}

		frozen := "0"
		if st.NewFrozen {
			frozen = "1"
		}
		metaK, tipK := keyMeta(ns), keyTip(ns)
		cfgK, logK, nsidK := keyCfg(ns, newPos), keyLog(ns, entry.pos), keyNSID(ns, entry.id)
		_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []types.TransactWriteItem{
				// Action order: 0 #META, 1 CFG, 2 LOG, 3 #TIP, 4 NSID.
				{Update: &types.Update{
					TableName:           &s.Table,
					Key:                 keyAV(metaK),
					UpdateExpression:    strptr("SET configPos = :new, configId = :newi, frozen = :fr"),
					ConditionExpression: strptr("configPos = :old AND configId = :oldi"),
					ExpressionAttributeValues: map[string]types.AttributeValue{
						":new": avN(newPos), ":newi": avS(cfgID.String()), ":fr": avS(frozen),
						":old": avN(m.configPos), ":oldi": avS(m.configID),
					},
				}},
				{Put: &types.Put{TableName: &s.Table, Item: withKey(cfgK, item{
					"pos": avN(newPos), "id": avS(cfgID.String()), "parentPos": avN(m.configPos), "logPos": avN(entry.pos),
					"patches": avS(string(canon)), "doc": avS(string(jsonv.Canonical(doc))), "author": avS(author), "created": avI(now),
					"G1PK": avS(g1RevID(cfgID.String())),
				})}},
				{Put: &types.Put{TableName: &s.Table, Item: withKey(logK, entry.item()), ConditionExpression: strptr("attribute_not_exists(PK)")}},
				{Update: &types.Update{
					TableName:           &s.Table,
					Key:                 keyAV(tipK),
					UpdateExpression:    strptr("SET headPos = :new, headId = :newi"),
					ConditionExpression: strptr("headPos = :h AND headId = :i"),
					ExpressionAttributeValues: map[string]types.AttributeValue{
						":new": avN(entry.pos), ":newi": avS(entry.id),
						":h": avN(t.headPos), ":i": avS(t.headID),
					},
				}},
				{Put: &types.Put{TableName: &s.Table, Item: withKey(nsidK, item{"ns": avS(ns), "logPos": avN(entry.pos), "revId": avS(cfgID.String())}), ConditionExpression: strptr("attribute_not_exists(PK)")}},
			},
		})
		if err == nil {
			return &ConfigResult{ConfigID: cfgID.String(), NSID: entry.id, Created: entry.created}, nil
		}
		var ce *types.TransactionCanceledException
		var xe *types.TransactionConflictException
		switch {
		case errors.As(err, &xe):
			// A concurrent transaction on the namespace: retry.
		case errors.As(err, &ce) && len(ce.CancellationReasons) > 0:
			failed := func(i int) bool {
				return i < len(ce.CancellationReasons) && ce.CancellationReasons[i].Code != nil && *ce.CancellationReasons[i].Code == "ConditionalCheckFailed"
			}
			if failed(4) {
				// The marker exists: this very change committed.
				created, _ := s.entryCreated(ctx, ns, entry.id)
				return &ConfigResult{ConfigID: cfgID.String(), NSID: entry.id, Created: created, Replayed: true}, nil
			}
			if failed(0) || failed(2) || failed(3) {
				continue // a config change or a log append raced us: re-read and retry
			}
			return nil, err
		default:
			return nil, err
		}
		if attempt+1 >= maxWriteAttempts {
			return nil, apiErr(409, "conflict", "detail", "log tip contention")
		}
	}
}

// replayConfig is a config change's retry lookup (planConfig of
// nsops.go): the configuration the request computes over its If-Match, if
// this author wrote it to the namespace, answered with the entry that put
// it in force and that entry's gestures; nil when there is none.
func (s *Store) replayConfig(ctx context.Context, ns, ifMatch string, patches any, author string) (*ConfigResult, error) {
	parent, err := ids.Parse(ifMatch)
	if err != nil {
		return nil, nil
	}
	want := ids.Revision(&parent, jsonv.Canonical(patches)).String()
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.Table,
		IndexName:              strptr(gsiName),
		KeyConditionExpression: strptr("G1PK = :g"),
		FilterExpression:       strptr("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":g": avS(g1RevID(want)), ":pk": avS(nsPK(ns)), ":sk": avS("CFG#"),
		},
	})
	if err != nil {
		return nil, err
	}
	for _, it := range q.Items {
		c := item(it)
		if c.s("author") != author {
			continue
		}
		res := &ConfigResult{ConfigID: want, Replayed: true}
		if lp := c.n("logPos"); lp > 0 {
			le, err := s.getItem(ctx, keyLog(ns, lp))
			if err != nil {
				return nil, err
			}
			if le != nil {
				l := item(le)
				res.NSID, res.Created = l.s("id"), int64(l.n("created"))
				res.Gesture, res.Undoes = l.s("gesture"), l.s("undoes")
			}
		}
		return res, nil
	}
	return nil, nil
}

// readConfigState reads the namespace's meta and current configuration
// document (two point reads).
func (s *Store) readConfigState(ctx context.Context, ns string) (*nsMeta, any, error) {
	m, err := s.getMeta(ctx, ns)
	if err != nil || m == nil {
		return m, nil, err
	}
	it, err := s.getItem(ctx, keyCfg(ns, m.configPos))
	if err != nil {
		return nil, nil, err
	}
	if it == nil {
		return nil, nil, apiErr(500, "stored_config", "namespace", ns)
	}
	doc, err := jsonv.Parse([]byte(item(it).s("doc")))
	return m, doc, err
}

// ReadConfig serves the current namespace document and its id.
func (s *Store) ReadConfig(ctx context.Context, ns string) (doc any, cfgID string, err error) {
	m, doc, err := s.readConfigState(ctx, ns)
	if err != nil {
		return nil, "", err
	}
	if m == nil {
		return nil, "", apiErr(404, "not_found", "namespace", ns)
	}
	return doc, m.configID, nil
}
