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
	Doc       any // the new namespace document (nil when absent)
	NewFrozen bool
}

// ConfigResult is a committed (or replayed) config change.
type ConfigResult struct {
	ConfigID string
	NSID     string
	Created  int64 // the entry's stored time, milliseconds
	Replayed bool
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
func (s *Store) WriteConfig(ctx context.Context, ns, author string, patches any, apply func(doc any, exists bool, patches any) (any, error), check func(*ConfigState) error) (*ConfigResult, error) {
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

		st := &ConfigState{Exists: true, Frozen: m.frozen, Purged: m.purged, ConfigID: m.configID, Doc: cfgDoc, NewFrozen: m.frozen}
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

		// Idempotent replay: this change is already the configuration.
		// The CFG item names its log entry, so the answer carries it.
		if cfgID.String() == m.configID {
			entryID, err := s.configEntryID(ctx, ns, m.configPos)
			if err != nil {
				return nil, err
			}
			created, _ := s.entryCreated(ctx, ns, entryID)
			return &ConfigResult{ConfigID: m.configID, NSID: entryID, Created: created, Replayed: true}, nil
		}

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
		entry := logRow{pos: t.headPos + 1, id: entryID.String(), prevPos: t.headPos, kind: "config", body: string(body), author: author, created: now, cfgPos: newPos}

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

// configEntryID is the id of the log entry that appended the
// configuration at pos (CFG items carry their entry's position).
func (s *Store) configEntryID(ctx context.Context, ns string, pos uint64) (string, error) {
	it, err := s.getItem(ctx, keyCfg(ns, pos))
	if err != nil {
		return "", err
	}
	if it == nil {
		return "", apiErr(500, "stored_config", "namespace", ns)
	}
	lp := item(it).n("logPos")
	if lp == 0 {
		return "", nil // a genesis written before logPos: no entry to name
	}
	le, err := s.getItem(ctx, keyLog(ns, lp))
	if err != nil {
		return "", err
	}
	return item(le).s("id"), nil
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
