package ddb

// Batches (§7.5): several resources' writes as one transaction — the
// atomicity the SQL backends get from a database transaction, as actions
// of one TransactWriteItems. One namespace log entry of kind "batch"
// records them all; its id chains over the tip like any entry's.
//
// The budget is DynamoDB's 100 actions per transaction: three shared
// (entry, tip, marker), two for an optional config change, four per
// patch-set item (revision, head, document, history) and two per
// delete (tombstone, head: the last live document stays).

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

// Pre is the item's precondition.
func (it BatchItem) Pre() Pre { return Pre{IfMatch: it.IfMatch, IfNoneMatch: it.IfNoneMatch} }

// BatchResult is a committed (or replayed, or dry-run) batch. A dry run
// reports its refused items in Fails, and IDs holds the others' (§7.5).
type BatchResult struct {
	Fails    []BatchItemError
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
	Err   error // the store's *Error, or the caller's gate's own
}

func (e *BatchFailure) Error() string { return "ddb: batch refused per item" }

// maxTxActions is DynamoDB's transaction action cap; a batch's actions
// must fit (docs/DYNAMODB.md §10's lowered ItemsPerBatch).
const maxTxActions = 100

// MaxBatchItems is the most items a batch is sure to fit in one
// transaction, a config change's actions included and every item a write
// (the costlier kind): docs/DYNAMODB.md §10's lowered ItemsPerBatch.
const MaxBatchItems = (maxTxActions - 3 - 2) / 4

// BatchActions counts a batch's transaction actions: three shared, two
// for a config change, four per write, two per delete.
func BatchActions(items []BatchItem, withConfig bool) int {
	n := 3
	if withConfig {
		n += 2
	}
	for _, it := range items {
		if it.Delete {
			n += 2
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
//
// ccIfMatch is the config change's precondition (required, 428): one
// naming another configuration is first looked up as the batch's own
// retry (§7.5, over the configuration it computes), else 412.
func (s *Store) WriteBatch(ctx context.Context, ns, author string, items []BatchItem, ccIfMatch string, ccPatches any, applyCfg func(doc any, exists bool, patches any) (any, error), checkCfg func(*ConfigState) error, check func(name string, st *WriteState) error, dryRun bool) (*BatchResult, error) {
	if acts := BatchActions(items, ccPatches != nil); acts > maxTxActions {
		return nil, apiErr(413, "limit", "key", "itemsPerBatch", "measured", acts, "max", maxTxActions)
	}
	// Each attempt holds the namespace's commit lock from its reads
	// through its commit, so the group worker doesn't move the tip under
	// it (group.go).
	var held func()
	defer func() { release(held) }()
	for attempt := 0; ; attempt++ {
		release(held)
		held = s.serialize(ns)
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
			if ccIfMatch == "" {
				return nil, apiErr(428, "precondition_required")
			}
			if ccIfMatch != m.configID {
				if parent, err := ids.Parse(ccIfMatch); err == nil {
					want := ids.Revision(&parent, jsonv.Canonical(ccPatches)).String()
					var head0 *resRow
					if len(items) > 0 {
						head0 = heads[0]
					}
					if res, err := s.replayBatch(ctx, ns, items, true, want, head0, author); res != nil || err != nil {
						return res, err
					}
				}
				return nil, apiErr(412, "stale", "config", m.configID)
			}
			doc, err := applyCfg(cfgDoc, true, ccPatches)
			if err != nil {
				return nil, err
			}
			st := &ConfigState{Exists: true, Frozen: m.frozen, Purged: m.purged, ConfigID: m.configID, Cur: cfgDoc, Doc: doc, NewFrozen: m.frozen}
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
		// A frozen namespace refuses the batch's items, after the retry
		// lookup (§6.2 step 2) — the configuration in force decides, not
		// the batch's own change.
		if m.frozen && len(items) > 0 {
			if res, err := s.replayBatch(ctx, ns, items, ccPatches != nil, cfgID, heads[0], author); res != nil || err != nil {
				return res, err
			}
			return nil, frozen()
		}
		now := s.now().UnixMilli()
		plans := make([]*writePlan, len(items))
		var fails []BatchItemError
		for i, it := range items {
			head, doc := heads[i], docs[i]
			var p *writePlan
			var perr *Error
			if it.Delete {
				p, perr = planDelete(ns, it.Name, m, t, head, it.Pre(), it.Gesture, it.Undoes, author, now)
			} else {
				p, perr = planWrite(ns, it.Name, m, t, head, doc, it.Pre(), it.Patches, it.Gesture, it.Undoes, author, now, applyPatches)
			}
			if perr != nil {
				fails = append(fails, BatchItemError{i, perr})
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
			if err := check(it.Name, st); err != nil {
				// The gate's refusal is the item's (§7.5's failure
				// list), whatever its error type: the caller's own.
				fails = append(fails, BatchItemError{i, err})
			}
		}
		if len(fails) > 0 {
			// Items refused at step 2 may be the batch's own retry.
			if res, err := s.replayBatch(ctx, ns, items, ccPatches != nil, cfgID, heads[0], author); res != nil || err != nil {
				return res, err
			}
			if !dryRun {
				return nil, &BatchFailure{Items: fails}
			}
			// A dry run reports every item: the refused with their
			// errors, the others with their ids (§7.5).
			idsByName := map[string]string{}
			for i, p := range plans {
				if p != nil {
					idsByName[items[i].Name] = p.rev.id
				}
			}
			return &BatchResult{Status: 200, IDs: idsByName, ConfigID: cfgID, Fails: fails}, nil
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
		entry := logRow{pos: t.headPos + 1, id: entryID.String(), prevPos: t.headPos, kind: "batch", body: string(body), author: author, created: now, cfgPos: cfgPos, gestures: batchGestures(items)}

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
		release(held)
		held = nil
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
}

// batchGestures is a batch entry's gestures member (batchGestures of
// write.go): each resource's steps' { gesture?, undoes? }, {} for one with
// neither; "" when no item has one, so a batch without gestures serves no
// member.
func batchGestures(items []BatchItem) string {
	has := false
	out := map[string]any{}
	for _, it := range items {
		g := map[string]any{}
		if it.Gesture != "" {
			g["gesture"] = it.Gesture
		}
		if it.Undoes != "" {
			g["undoes"] = it.Undoes
		}
		has = has || len(g) > 0
		out[it.Name] = []any{g}
	}
	if !has {
		return ""
	}
	return string(jsonv.Canonical(out))
}

// replayBatch answers for a retried batch (§7.5's retry lookup, replay of
// write.go): the batch, if it was written, is an entry by this author that
// moved item 0's resource to the target the request computes for it — the
// ids are content hashes, so the request determines every item's, and the
// entry's body with them. The revision records that entry (logPos), so one
// lookup finds it, wherever the head has gone since.
//
// The lookup needs every item's target computable from the request: an
// item without a precondition makes it uncomputable, and finds nothing.
func (s *Store) replayBatch(ctx context.Context, ns string, items []BatchItem, withConfig bool, cfgID string, head0 *resRow, author string) (*BatchResult, error) {
	if len(items) > 0 && (head0 == nil || head0.headPos == 0) {
		return nil, nil
	}
	if len(items) == 0 && !withConfig {
		return nil, nil
	}
	entries := make([]any, 0, len(items)+1)
	if withConfig {
		entries = append(entries, map[string]any{"kind": "config", "target": cfgID})
	}
	idsByName := make(map[string]string, len(items))
	for _, it := range items {
		id, ok := it.Pre().expectedID(it.Delete, it.Patches)
		if !ok {
			return nil, nil
		}
		kind := "head"
		if it.Delete {
			kind = "tombstone"
		}
		entries = append(entries, map[string]any{"resource": it.Name, "kind": kind, "target": id})
		idsByName[it.Name] = id
	}
	// The entry: the one that committed item 0's target, or, for a batch
	// of only a config change, the one that put its configuration in
	// force (both recorded as logPos).
	var logPos uint64
	if len(items) > 0 {
		rev, err := s.revOf(ctx, ns, items[0].Name, head0, idsByName[items[0].Name])
		if err != nil || rev == nil {
			return nil, err
		}
		logPos = rev.LogPos
	} else {
		c, err := s.cfgByID(ctx, ns, cfgID, author)
		if err != nil || c == nil {
			return nil, err
		}
		logPos = c.n("logPos")
	}
	if logPos == 0 {
		return nil, nil
	}
	le, err := s.getItem(ctx, keyLog(ns, logPos))
	if err != nil || le == nil {
		return nil, err
	}
	want := string(jsonv.Canonical(map[string]any{"kind": "batch", "entries": entries}))
	stored := item(le)
	if stored.s("kind") != "batch" || stored.s("body") != want || stored.s("author") != author {
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
// actions first, then each item's (a write's four, a delete's two),
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
// write's revision, head and documents, or the delete's tombstone and head
// — buildWriteTx/buildDeleteTx's per-item parts, keyed by
// the shared entry's position.
func batchItemActs(table, ns, name string, p *writePlan, entry logRow) []types.TransactWriteItem {
	revK, resK := keyRev(ns, name, p.rev.pos), keyRes(ns, name)
	docK, histK := keyDocHead(ns, name), keyHist(ns, name, entry.pos)
	rr := p.rev
	rr.logPos = entry.pos
	rev := types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(revK, rr.item()),
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
	// two lead, then each item's four (write) or two (delete).
	itemAt := map[int]int{}
	i := 0
	if configActs {
		i = 2
	}
	for j, it := range items {
		n := 4
		if it.Delete {
			n = 2
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
