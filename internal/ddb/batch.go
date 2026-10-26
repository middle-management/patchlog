package ddb

// Batches (§7.5): several resources' writes as one transaction — the
// atomicity the SQL backends get from a database transaction, as actions
// of one TransactWriteItems. One namespace log entry of kind "batch"
// records them all; its id chains over the tip like any entry's.
//
// The budget is DynamoDB's 100 actions per transaction: three shared
// (entry, tip, marker), two for an optional config change, four per
// patch-set item (revision, head, document, history) and three per
// delete (tombstone, head, the document's removal).

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// BatchItem is one item of a batch: a single patch-set step or a delete,
// like the SQL phase's single-step constraint (multi-step items remain
// out of scope).
type BatchItem struct {
	Name        string
	IfMatch     string
	IfNoneMatch bool
	Delete      bool
	Patches     any
	Gesture     string
	Undoes      string
}

// BatchResult is a committed (or replayed, or dry-run) batch.
type BatchResult struct {
	Status   int // 201 committed, 200 replayed or dry run
	NSID     string
	Created  int64
	Replayed bool
	IDs      map[string]string // resource → revision or tombstone id
	ConfigID string            // the configuration the batch ran under (changed or not)
}

// BatchFailure carries the per-item errors of a refused batch (§7.5's
// failure list): the gate and the plans are evaluated for every item
// before the failures are answered, as checkItems collects them.
type BatchFailure struct {
	Items []BatchItemError
}

// BatchItemError is one item's refusal, by batch index.
type BatchItemError struct {
	Index int
	Err   *Error
}

func (e *BatchFailure) Error() string { return "ddb: batch refused per item" }

// maxTxActions is DynamoDB's transaction action cap; a batch's actions
// must fit (docs/DYNAMODB.md §10's lowered ItemsPerBatch).
const maxTxActions = 100

// BatchActions counts a batch's transaction actions: three shared, two
// for a config change, four per write, three per delete.
func BatchActions(items []BatchItem, withConfig bool) int {
	n := 3
	if withConfig {
		n += 2
	}
	for _, it := range items {
		if it.Delete {
			n += 3
		} else {
			n += 4
		}
	}
	return n
}

// WriteBatch commits a batch (§7.5): every item's plan, the optional
// config change, and the shared batch entry, in one transaction pinned
// on every checked head and the tip. dryRun runs the whole gate and
// answers the computed ids without committing (write.go's dry run).
//
// check runs the caller's gate per item (name, state) inside the retry
// loop, as WriteResource's does; applyCfg and checkCfg are a config
// change's, as WriteConfig's. A *BatchFailure collects every item's
// refusal; a plan error that isn't an item's (the namespace's state, the
// action budget) aborts directly.
func (s *Store) WriteBatch(ctx context.Context, ns, author string, items []BatchItem, ccPatches any, applyCfg func(doc any, exists bool, patches any) (any, error), checkCfg func(*ConfigState) error, check func(name string, st *WriteState) error, dryRun bool) (*BatchResult, error) {
	if acts := BatchActions(items, ccPatches != nil); acts > maxTxActions {
		return nil, apiErr(413, "limit", "key", "itemsPerBatch", "measured", acts, "max", maxTxActions)
	}
	for attempt := 0; ; attempt++ {
		m, t, heads, docs, cfgDoc, err := s.readBatchState(ctx, ns, items, ccPatches != nil)
		if err != nil {
			return nil, err
		}
		if m == nil {
			return nil, apiErr(404, "not_found", "namespace", ns)
		}
		if m.purged {
			return nil, apiErr(410, "purged", "namespace", ns)
		}

		// The config change, as WriteConfig's: id over the canonical
		// patches, the new document through the caller's apply and check.
		// An unchanged configuration adds no actions.
		cfgID, cfgPos := m.configID, m.configPos
		var cfgDocNew any
		newFrozen := m.frozen
		configActs := false
		if ccPatches != nil {
			doc, err := applyCfg(cfgDoc, true, ccPatches)
			if err != nil {
				return nil, err
			}
			st := &ConfigState{Exists: true, Frozen: m.frozen, Purged: m.purged, ConfigID: m.configID, Doc: doc, NewFrozen: m.frozen}
			if checkCfg != nil {
				if err := checkCfg(st); err != nil {
					return nil, err
				}
			}
			newFrozen = st.NewFrozen
			parent, err := ids.Parse(m.configID)
			if err != nil {
				return nil, apiErr(500, "stored_config", "namespace", ns)
			}
			cfgID = ids.Revision(&parent, jsonv.Canonical(ccPatches)).String()
			cfgDocNew = doc
			if cfgID != m.configID {
				configActs = true
				cfgPos = m.configPos + 1
			}
		}

		// Every item's plan, and every item's gate: the failures collect
		// (§7.5); the transaction is never built with a refused item.
		now := s.now().UnixMilli()
		plans := make([]*writePlan, len(items))
		var fails []BatchItemError
		for i, it := range items {
			head, doc := heads[i], docs[i]
			var p *writePlan
			var perr *Error
			if it.Delete {
				p, perr = planDelete(ns, it.Name, m, t, head, it.IfMatch, it.Gesture, it.Undoes, author, now)
			} else {
				p, perr = planWrite(ns, it.Name, m, t, head, doc, it.IfMatch, it.Patches, it.Gesture, it.Undoes, author, now, applyPatches)
			}
			if perr != nil {
				fails = append(fails, BatchItemError{i, perr})
				continue
			}
			if p.replay {
				// Item 0's head is its target: the whole batch may be a
				// retry (§7.5's expectedIDs lookup).
				if i == 0 {
					if res, _ := s.replayBatch(ctx, ns, items, ccPatches != nil, cfgID, head); res != nil {
						return res, nil
					}
				}
				fails = append(fails, BatchItemError{i, apiErr(412, "stale", "head", head.headID)})
				continue
			}
			plans[i] = p
			if check == nil {
				continue
			}
			st := &WriteState{
				Exists: true, ResExists: head != nil && head.headPos > 0, HeadDoc: doc,
				ConfigID: cfgID, RevID: p.rev.id, Doc: p.docAny, DocCanon: []byte(p.doc), Writes: p.writes,
			}
			if head != nil {
				st.HeadID = head.headID
			}
			switch {
			case p.del:
				st.Action = "delete"
				st.Doc, st.DocCanon = doc, nil
			case p.create:
				st.Action = "create"
			case p.restore:
				st.Action = "restore"
			default:
				st.Action = "append"
			}
			if it.IfNoneMatch && st.ResExists {
				fails = append(fails, BatchItemError{i, apiErr(412, "stale", "head", st.HeadID)})
				continue
			}
			if err := check(it.Name, st); err != nil {
				pe, ok := err.(*Error)
				if !ok {
					return nil, err
				}
				fails = append(fails, BatchItemError{i, pe})
			}
		}
		if len(fails) > 0 {
			return nil, &BatchFailure{Items: fails}
		}

		// The batch entry (planEntry of write.go): the config target
		// first, then every item's.
		entries := make([]any, 0, len(items)+1)
		if ccPatches != nil {
			entries = append(entries, map[string]any{"kind": "config", "target": cfgID})
		}
		idsByName := make(map[string]string, len(items))
		for i, it := range items {
			kind := "head"
			if it.Delete {
				kind = "tombstone"
			}
			entries = append(entries, map[string]any{"resource": it.Name, "kind": kind, "target": plans[i].rev.id})
			idsByName[it.Name] = plans[i].rev.id
		}
		body := jsonv.Canonical(map[string]any{"kind": "batch", "entries": entries})
		var tipID *ids.ID
		if t.headID != "" {
			p, err := ids.Parse(t.headID)
			if err != nil {
				return nil, apiErr(500, "stored_tip", "namespace", ns)
			}
			tipID = &p
		}
		entryID := ids.Hash(tipID, body)
		entry := logRow{pos: t.headPos + 1, id: entryID.String(), prevPos: t.headPos, kind: "batch", body: string(body), author: author, created: now, cfgPos: cfgPos}

		res := &BatchResult{Status: 201, NSID: entry.id, Created: now, IDs: idsByName, ConfigID: cfgID}
		if dryRun {
			res.Status = 200
			return res, nil
		}

		_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: s.buildBatchTx(ns, items, plans, entry, *t, m, configActs, cfgID, cfgDocNew, newFrozen),
		})
		if err == nil {
			return res, nil
		}
		rc, retry, cerr := s.mapBatchCancel(ctx, ns, items, plans, entry, res, configActs, err)
		if rc != nil || cerr != nil {
			return rc, cerr
		}
		if !retry {
			return nil, err
		}
		if attempt+1 >= maxWriteAttempts {
			return nil, apiErr(409, "conflict", "detail", "log tip contention")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
}

// replayBatch answers for a retried batch: item 0's head is the batch's
// target for it, and the entry that moved it there is this batch's,
// known by comparing the stored entry's body with the one this request
// computes (§7.5's expectedIDs lookup — the ids are content hashes, so
// the request determines them, and the entry's id itself chained over a
// tip that has moved on).
//
// The lookup needs every item's target computable from the request: a
// write's id covers its precondition's parent (or nil for a create), a
// tombstone's its deleted head. An append without If-Match makes it
// uncomputable; the lookup then finds nothing.
func (s *Store) replayBatch(ctx context.Context, ns string, items []BatchItem, withConfig bool, cfgID string, head0 *resRow) (*BatchResult, error) {
	mk, err := s.getItem(ctx, keyNSID(ns, head0.entryID))
	if err != nil || mk == nil {
		return nil, err
	}
	le, err := s.getItem(ctx, keyLog(ns, item(mk).n("logPos")))
	if err != nil || le == nil {
		return nil, err
	}
	entries := make([]any, 0, len(items)+1)
	if withConfig {
		entries = append(entries, map[string]any{"kind": "config", "target": cfgID})
	}
	idsByName := make(map[string]string, len(items))
	for _, it := range items {
		var id ids.ID
		if it.Delete {
			if it.IfMatch == "" {
				return nil, nil
			}
			parent, err := ids.Parse(it.IfMatch)
			if err != nil {
				return nil, nil
			}
			id = ids.Tombstone(parent)
		} else {
			var parent *ids.ID
			if it.IfMatch != "" {
				p, err := ids.Parse(it.IfMatch)
				if err != nil {
					return nil, nil
				}
				parent = &p
			} else if !it.IfNoneMatch {
				return nil, nil // an append without a parent: uncomputable
			}
			id = ids.Revision(parent, jsonv.Canonical(it.Patches))
		}
		kind := "head"
		if it.Delete {
			kind = "tombstone"
		}
		entries = append(entries, map[string]any{"resource": it.Name, "kind": kind, "target": id.String()})
		idsByName[it.Name] = id.String()
	}
	want := string(jsonv.Canonical(map[string]any{"kind": "batch", "entries": entries}))
	stored := item(le)
	if stored.s("kind") != "batch" || stored.s("body") != want {
		return nil, nil
	}
	return &BatchResult{
		Status: 200, NSID: stored.s("id"), Created: int64(stored.n("created")),
		Replayed: true, IDs: idsByName, ConfigID: cfgID,
	}, nil
}

// readBatchState is a batch's check phase: #META, #TIP, every item's RES#
// and head document, and the current configuration when the batch
// changes it — one BatchGetItem plus the config's reads.
func (s *Store) readBatchState(ctx context.Context, ns string, items []BatchItem, withConfig bool) (*nsMeta, *tip, []*resRow, []any, any, error) {
	keys := []map[string]types.AttributeValue{keyAV(keyMeta(ns)), keyAV(keyTip(ns))}
	for _, it := range items {
		keys = append(keys, keyAV(keyRes(ns, it.Name)), keyAV(keyDocHead(ns, it.Name)))
	}
	out, err := s.Client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{s.Table: {Keys: keys, ConsistentRead: boolptr(true)}},
	})
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if len(out.UnprocessedKeys) > 0 {
		return nil, nil, nil, nil, nil, apiErr(503, "throughput", "detail", "unprocessed keys")
	}
	var m *nsMeta
	t := &tip{}
	heads := make([]*resRow, len(items))
	docs := make([]any, len(items))
	docByName := map[string]any{}
	for _, it := range out.Responses[s.Table] {
		i := item(it)
		sk := i.s("SK")
		switch {
		case sk == "#META":
			m = scanNSMeta(i)
		case sk == "#TIP":
			t = scanTip(i)
		case len(sk) > 4 && sk[:4] == "RES#":
			for j, bit := range items {
				if sk == "RES#"+bit.Name {
					heads[j] = scanRes(i)
				}
			}
		case len(sk) > 4 && sk[:4] == "DOC#":
			doc, err := jsonv.Parse([]byte(i.s("doc")))
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			docByName[sk[4:len(sk)-5]] = doc
		}
	}
	for j, bit := range items {
		docs[j] = docByName[bit.Name]
	}
	if m == nil {
		return nil, nil, nil, nil, nil, nil
	}
	var cfgDoc any
	if withConfig {
		if _, cfgDoc, err = s.readConfigState(ctx, ns); err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}
	return m, t, heads, docs, cfgDoc, nil
}

// buildBatchTx assembles the batch's transaction: the config change's
// actions first, then each item's (a write's four, a delete's three),
// then the shared three.
func (s *Store) buildBatchTx(ns string, items []BatchItem, plans []*writePlan, entry logRow, oldTip tip, m *nsMeta, configActs bool, cfgID string, cfgDoc any, newFrozen bool) []types.TransactWriteItem {
	var out []types.TransactWriteItem
	if configActs {
		frozen := "0"
		if newFrozen {
			frozen = "1"
		}
		metaK, cfgK := keyMeta(ns), keyCfg(ns, m.configPos+1)
		out = append(out,
			types.TransactWriteItem{Update: &types.Update{
				TableName:           &s.Table,
				Key:                 keyAV(metaK),
				UpdateExpression:    strptr("SET configPos = :new, configId = :newi, frozen = :fr"),
				ConditionExpression: strptr("configPos = :old AND configId = :oldi"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":new": avN(m.configPos + 1), ":newi": avS(cfgID), ":fr": avS(frozen),
					":old": avN(m.configPos), ":oldi": avS(m.configID),
				},
			}},
			types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(cfgK, item{
				"pos": avN(m.configPos + 1), "id": avS(cfgID), "parentPos": avN(m.configPos), "logPos": avN(entry.pos),
				"doc": avS(string(jsonv.Canonical(cfgDoc))), "author": avS(entry.author), "created": avI(entry.created),
				"G1PK": avS(g1RevID(cfgID)),
			})}})
	}
	for i, it := range items {
		out = append(out, batchItemActs(s.Table, ns, it.Name, plans[i], entry)...)
	}
	logK, tipK, nsidK := keyLog(ns, entry.pos), keyTip(ns), keyNSID(ns, entry.id)
	out = append(out,
		types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(logK, entry.item()), ConditionExpression: strptr("attribute_not_exists(PK)")}},
		types.TransactWriteItem{Update: &types.Update{
			TableName:           &s.Table,
			Key:                 keyAV(tipK),
			UpdateExpression:    strptr("SET headPos = :new, headId = :newi"),
			ConditionExpression: strptr("headPos = :h AND headId = :i"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":new": avN(entry.pos), ":newi": avS(entry.id),
				":h": avN(oldTip.headPos), ":i": avS(oldTip.headID),
			},
		}},
		types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(nsidK, item{"ns": avS(ns), "logPos": avN(entry.pos)}), ConditionExpression: strptr("attribute_not_exists(PK)")}},
	)
	return out
}

// batchItemActs is one item's actions of a batch's transaction: the
// write's revision, head and documents, or the delete's tombstone, head
// and removal — buildWriteTx/buildDeleteTx's per-item parts, keyed by
// the shared entry's position.
func batchItemActs(table, ns, name string, p *writePlan, entry logRow) []types.TransactWriteItem {
	revK, resK := keyRev(ns, name, p.rev.pos), keyRes(ns, name)
	docK, histK := keyDocHead(ns, name), keyHist(ns, name, entry.pos)
	rev := types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(revK, p.rev.item()),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	if p.del {
		return []types.TransactWriteItem{rev,
			{Update: &types.Update{
				TableName:                &table,
				Key:                      keyAV(resK),
				UpdateExpression:         strptr("SET headPos = :h, headId = :i, #st = :tomb, entryId = :e, lastId = :l, lastPos = :lp REMOVE headCreated, headSize, headDigest"),
				ConditionExpression:      strptr("headPos = :old AND headId = :oldi"),
				ExpressionAttributeNames: map[string]string{"#st": "state"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":h": avN(p.newHead.headPos), ":i": avS(p.newHead.headID), ":tomb": avS("tombstoned"), ":e": avS(entry.id),
					":l": avS(p.newHead.lastID), ":lp": avN(p.newHead.lastPos),
					":old": avN(p.oldHead), ":oldi": avS(p.rev.parentID),
				},
			}},
			{Delete: &types.Delete{TableName: &table, Key: keyAV(docK)}},
		}
	}
	resCond := "attribute_not_exists(PK)"
	resVals := map[string]types.AttributeValue{}
	if p.resExists {
		resCond = "headPos = :old"
		resVals[":old"] = avN(p.oldHead)
	}
	resUpdate := "SET headPos = :h, headId = :i, #st = :live, entryId = :e, headCreated = :c, headSize = :s, headDigest = :d"
	if p.restore {
		resUpdate += " REMOVE lastId, lastPos"
	}
	return []types.TransactWriteItem{rev,
		{Update: &types.Update{
			TableName:                &table,
			Key:                      keyAV(resK),
			UpdateExpression:         strptr(resUpdate),
			ConditionExpression:      &resCond,
			ExpressionAttributeNames: map[string]string{"#st": "state"},
			ExpressionAttributeValues: mergeVals(resVals, map[string]types.AttributeValue{
				":h": avN(p.newHead.headPos), ":i": avS(p.newHead.headID), ":live": avS("live"), ":e": avS(entry.id),
				":c": avI(p.newHead.headCreated), ":s": avN(p.newHead.headSize), ":d": avB(p.newHead.headDigest),
			}),
		}},
		{Put: &types.Put{TableName: &table, Item: withKey(docK, item{"revPos": avN(p.rev.pos), "doc": avS(p.doc)})}},
		{Put: &types.Put{TableName: &table, Item: withKey(histK, item{"revPos": avN(p.rev.pos)})}},
	}
}

// mapBatchCancel classifies a cancelled batch transaction: a config
// condition means a concurrent config change (retry), an item's
// conditions its conflict (412, or 410 where a delete raced it), the
// tip's or entry's a log race (retry), the marker's a committed
// duplicate of the whole batch (a replayed result).
func (s *Store) mapBatchCancel(ctx context.Context, ns string, items []BatchItem, plans []*writePlan, entry logRow, res *BatchResult, configActs bool, err error) (*BatchResult, bool, error) {
	var xe *types.TransactionConflictException
	if errors.As(err, &xe) {
		return nil, true, nil
	}
	var ce *types.TransactionCanceledException
	if !errors.As(err, &ce) {
		return nil, false, err
	}
	reasons := ce.CancellationReasons
	failed := func(i int) bool {
		return i < len(reasons) && reasons[i].Code != nil && *reasons[i].Code == "ConditionalCheckFailed"
	}
	// The shared three end the transaction.
	last := len(reasons) - 1
	switch {
	case failed(last): // the NSID marker
		if mk, gerr := s.getItem(ctx, keyNSID(ns, entry.id)); gerr == nil && mk != nil {
			res.Status, res.Replayed = 200, true
			created, _ := s.entryCreated(ctx, ns, entry.id)
			res.Created = created
			return res, false, nil
		}
		return nil, false, apiErr(409, "conflict")
	case failed(last - 1), failed(last - 2): // #TIP or the entry: a log race.
		return nil, true, nil
	}
	// Otherwise an item's or the config's action. Layout: the config's
	// two lead, then each item's four (write) or three (delete).
	itemAt := map[int]int{}
	i := 0
	if configActs {
		i = 2
	}
	for j, it := range items {
		n := 4
		if it.Delete {
			n = 3
		}
		for k := 0; k < n; k++ {
			itemAt[i+k] = j
		}
		i += n
	}
	for a := range reasons {
		if !failed(a) {
			continue
		}
		j, ok := itemAt[a]
		if !ok {
			// The config's condition: a concurrent change.
			return nil, true, nil
		}
		cur, gerr := s.getRes(ctx, ns, items[j].Name)
		if gerr != nil || cur == nil {
			return nil, false, gone()
		}
		if cur.headID == plans[j].rev.id {
			// The winner was this very batch: a replay.
			res.Status, res.Replayed = 200, true
			res.NSID = cur.entryID
			created, _ := s.entryCreated(ctx, ns, cur.entryID)
			res.Created = created
			return res, false, nil
		}
		if cur.state == "tombstoned" && items[j].Delete {
			return nil, false, gone()
		}
		return nil, false, apiErr(412, "stale", "head", cur.headID)
	}
	return nil, false, err
}
