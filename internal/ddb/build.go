package ddb

import (
	"crypto/sha256"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// The pure half of the write path (docs/DYNAMODB.md §4): from the state
// the check phase read, build the transaction. No I/O — the hermetic tests
// of build_test.go prove positions, conditions and id computations here;
// local_test.go proves DynamoDB enforces them.

// Error is a refusal, shaped after internal/core's: an HTTP status and the
// body's members.
type Error struct {
	Status int
	Body   map[string]any
}

func (e *Error) Error() string { return string(jsonv.Canonical(e.Body)) }

// apiErr builds an error in the core's body shape (engine.go's apiErr):
// {"code": …, …members}, so the server serves either backend alike.
func apiErr(status int, code string, members ...any) *Error {
	e := &Error{Status: status, Body: map[string]any{"code": code}}
	for i := 0; i+1 < len(members); i += 2 {
		e.Body[members[i].(string)] = members[i+1]
	}
	return e
}

// writePlan is a single-resource write ready to commit: the revision, the
// namespace log entry, and the states the transaction's conditions pin.
type writePlan struct {
	rev     revRow
	entry   logRow
	newHead resRow
	doc     string   // canonical JSON of the resulting head document
	docAny  any      // the document itself (the gate's rules read it, §6.4.1)
	writes  []string // the patch set's write pointers (§6.4.1's envelope)

	resExists bool // pin RES# headPos, else attribute_not_exists
	oldHead   uint64
	tip       tip  // pin #TIP (headPos, headID)
	create    bool // the write creates the resource
	restore   bool // the write restores a tombstoned resource
	del       bool // the write is a tombstone
	replay    bool // the write is already committed: store nothing
}

// Action indexes in the transaction buildWriteTx returns: cancellation
// reasons align with the actions (store.go maps them).
const (
	actRev = iota
	actRes
	actDoc
	actHist
	actLog
	actTip
	actNSID
	numActs
)

// planWrite turns the check phase's reads into a write plan (D.3 steps
// 1–6, spike subset: no grants, rules, schemas, limits or blobs).
//
// head is the resource's current row (nil: absent), headDoc its current
// document (nil when head is), m the namespace's meta, t its log tip.
// ifMatch pins the parent's revision id ("" pins nothing). patches is the
// decoded patch set; apply folds it into a document.
func planWrite(ns, name string, m *nsMeta, t *tip, head *resRow, headDoc any, ifMatch string, patches any, gesture, undoes, author string, now int64, apply func(doc any, exists bool, patches any) (any, []string, error)) (*writePlan, *Error) {
	switch {
	case m == nil:
		return nil, apiErr(404, "not_found", "namespace", ns)
	case m.purged:
		return nil, apiErr(410, "purged", "namespace", ns)
	case m.frozen:
		return nil, apiErr(409, "frozen", "namespace", ns)
	}

	// The parent the request names: ifMatch, else the current head (a
	// create names nothing). The write's revision id covers this parent,
	// so a retried write recomputes the id of its first attempt even
	// after the head moved on — which is what makes replay detectable.
	var parentID *ids.ID
	if ifMatch != "" {
		p, err := ids.Parse(ifMatch)
		if err != nil {
			return nil, apiErr(400, "bad_input", "detail", "malformed If-Match")
		}
		parentID = &p
	} else if head != nil && head.headPos > 0 {
		p, err := ids.Parse(head.headID)
		if err != nil {
			return nil, apiErr(500, "stored_head", "namespace", ns, "resource", name)
		}
		parentID = &p
	}

	canon := jsonv.Canonical(patches)
	revID := ids.Revision(parentID, canon)

	// Idempotent replay: the write's revision is already the head — the
	// first attempt committed (recheck.go's replay, spike shape). The
	// entry id the answer needs is on the RES item (entryId), since the
	// entry's own id chains over a tip that has moved past it.
	if head != nil && head.headID == revID.String() {
		return &writePlan{replay: true, rev: revRow{id: head.headID}, entry: logRow{id: head.entryID}}, nil
	}
	if ifMatch != "" && (head == nil || head.headPos == 0 || head.headID != ifMatch) {
		cur := ""
		if head != nil {
			cur = head.headID
		}
		return nil, apiErr(412, "stale", "head", cur)
	}

	// The document the patches fold into: none for a create, and none for
	// a restore either — a tombstone deleted it, so the write root-replaces
	// like a create (§6.2's restore verb).
	restore := head != nil && head.state == "tombstoned"
	doc, writes, err := apply(headDoc, head != nil && head.headPos > 0 && !restore, patches)
	if err != nil {
		return nil, apiErr(422, "patch", "detail", err.Error())
	}
	docCanon := jsonv.Canonical(doc)
	digest := sha256.Sum256(docCanon)

	pos := uint64(1)
	if head != nil && head.headPos > 0 {
		pos = head.headPos + 1
	}
	body := jsonv.Canonical(map[string]any{"resource": name, "kind": "head", "target": revID.String()})
	var tipID *ids.ID
	if t.headID != "" {
		p, err := ids.Parse(t.headID)
		if err != nil {
			return nil, apiErr(500, "stored_tip", "namespace", ns)
		}
		tipID = &p
	}
	entryID := ids.Hash(tipID, body)

	return &writePlan{
		rev: revRow{
			pos:      pos,
			id:       revID.String(),
			parentID: parentString(parentID),
			patches:  string(canon),
			author:   author,
			created:  now,
			size:     uint64(len(docCanon)),
			digest:   digest[:],
			gesture:  gesture,
			undoes:   undoes,
		},
		entry: logRow{
			pos:     t.headPos + 1,
			id:      entryID.String(),
			prevPos: t.headPos,
			kind:    "head",
			body:    string(body),
			author:  author,
			created: now,
			gesture: gesture,
			undoes:  undoes,
			cfgPos:  m.configPos,
		},
		newHead:   resRow{headPos: pos, headID: revID.String(), entryID: entryID.String(), state: "live", headCreated: now, headSize: uint64(len(docCanon)), headDigest: digest[:]},
		doc:       string(docCanon),
		docAny:    doc,
		writes:    writes,
		resExists: head != nil,
		oldHead:   pos - 1, // the head position the RES condition pins
		tip:       *t,
		create:    head == nil || head.headPos == 0,
		restore:   restore,
	}, nil
}

// planDelete turns a DELETE's reads into a tombstone plan (§7.2, §8.1).
// The tombstone id covers only the deleted head (ids.Tombstone), so a
// retried DELETE recomputes it and replays.
func planDelete(ns, name string, m *nsMeta, t *tip, head *resRow, ifMatch, gesture, undoes, author string, now int64) (*writePlan, *Error) {
	switch {
	case m == nil:
		return nil, apiErr(404, "not_found", "namespace", ns)
	case m.purged:
		return nil, apiErr(410, "purged", "namespace", ns)
	case m.frozen:
		return nil, apiErr(409, "frozen", "namespace", ns)
	}
	if ifMatch == "" {
		return nil, apiErr(428, "precondition_required")
	}
	parent, err := ids.Parse(ifMatch)
	if err != nil {
		return nil, apiErr(400, "bad_input", "detail", "malformed If-Match")
	}
	tid := ids.Tombstone(parent)
	if head == nil || head.headPos == 0 {
		return nil, gone()
	}
	if head.state == "tombstoned" {
		if head.headID == tid.String() {
			// This very delete committed: replay.
			return &writePlan{replay: true, rev: revRow{id: head.headID}, entry: logRow{id: head.entryID}}, nil
		}
		return nil, gone() // a delete of a tombstoned resource is 410
	}
	if head.headID != ifMatch {
		return nil, apiErr(412, "stale", "head", head.headID)
	}

	body := jsonv.Canonical(map[string]any{"resource": name, "kind": "tombstone", "target": tid.String()})
	var tipID *ids.ID
	if t.headID != "" {
		p, err := ids.Parse(t.headID)
		if err != nil {
			return nil, apiErr(500, "stored_tip", "namespace", ns)
		}
		tipID = &p
	}
	entryID := ids.Hash(tipID, body)
	pos := head.headPos + 1
	return &writePlan{
		rev: revRow{
			pos: pos, id: tid.String(), kind: "tombstone", parentID: ifMatch,
			author: author, created: now, gesture: gesture, undoes: undoes,
		},
		entry: logRow{
			pos: t.headPos + 1, id: entryID.String(), prevPos: t.headPos,
			kind: "tombstone", body: string(body), author: author, created: now,
			gesture: gesture, undoes: undoes, cfgPos: m.configPos,
		},
		newHead: resRow{
			headPos: pos, headID: tid.String(), entryID: entryID.String(), state: "tombstoned",
			lastID: head.headID, lastPos: head.headPos,
		},
		resExists: true,
		oldHead:   head.headPos,
		tip:       *t,
		del:       true,
	}, nil
}

// gone is DELETE's answer for an absent or tombstoned resource (write.go's).
func gone() *Error { return apiErr(410, "gone") }

func parentString(p *ids.ID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// buildWriteTx renders a write plan as the seven actions of
// docs/DYNAMODB.md §4, in actX order. Each condition rides on its target's
// own action (two actions may not share an item).
func buildWriteTx(table, ns, name string, p *writePlan) []types.TransactWriteItem {
	revK, resK := keyRev(ns, name, p.rev.pos), keyRes(ns, name)
	docK, histK := keyDocHead(ns, name), keyHist(ns, name, p.entry.pos)
	logK, tipK, nsidK := keyLog(ns, p.entry.pos), keyTip(ns), keyNSID(ns, p.entry.id)

	resCond := "attribute_not_exists(PK)"
	resVals := map[string]types.AttributeValue{}
	if p.resExists {
		resCond = "headPos = :old"
		resVals[":old"] = avN(p.oldHead)
	}

	out := make([]types.TransactWriteItem, numActs)
	out[actRev] = types.TransactWriteItem{Put: &types.Put{
		TableName: &table,
		Item:      withKey(revK, p.rev.item()),
		// UNIQUE(res, parent_seq): one child per parent.
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	resUpdate := "SET headPos = :h, headId = :i, #st = :live, entryId = :e, headCreated = :c, headSize = :s, headDigest = :d"
	if p.restore {
		// A tombstone's lastId/lastPos don't survive the restore.
		resUpdate += " REMOVE lastId, lastPos"
	}
	out[actRes] = types.TransactWriteItem{Update: &types.Update{
		TableName:                &table,
		Key:                      keyAV(resK),
		UpdateExpression:         strptr(resUpdate),
		ConditionExpression:      &resCond,
		ExpressionAttributeNames: map[string]string{"#st": "state"},
		ExpressionAttributeValues: mergeVals(resVals, map[string]types.AttributeValue{
			":h": avN(p.newHead.headPos), ":i": avS(p.newHead.headID), ":live": avS("live"), ":e": avS(p.entry.id),
			":c": avI(p.newHead.headCreated), ":s": avN(p.newHead.headSize), ":d": avB(p.newHead.headDigest),
		}),
	}}
	out[actDoc] = types.TransactWriteItem{Put: &types.Put{
		TableName: &table,
		Item:      withKey(docK, item{"revPos": avN(p.rev.pos), "doc": avS(p.doc)}),
	}}
	out[actHist] = types.TransactWriteItem{Put: &types.Put{
		TableName: &table,
		Item:      withKey(histK, item{"revPos": avN(p.rev.pos)}),
	}}
	out[actLog] = types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(logK, p.entry.item()),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	out[actTip] = types.TransactWriteItem{Update: &types.Update{
		TableName:        &table,
		Key:              keyAV(tipK),
		UpdateExpression: strptr("SET headPos = :new, headId = :newi"),
		// The log lock (pglock.go's logClass): entries commit in chain
		// order with no gaps, or the transaction cancels and retries.
		ConditionExpression: strptr("headPos = :h AND headId = :i"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new": avN(p.entry.pos), ":newi": avS(p.entry.id),
			":h": avN(p.tip.headPos), ":i": avS(p.tip.headID),
		},
	}}
	out[actNSID] = types.TransactWriteItem{Put: &types.Put{
		TableName: &table,
		Item:      withKey(nsidK, item{"ns": avS(ns), "logPos": avN(p.entry.pos), "revId": avS(p.rev.id)}),
		// UNIQUE(ns, id): the idempotent-retry marker.
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	return out
}

// Action indexes of a delete's transaction (buildDeleteTx).
const (
	delActRev = iota
	delActRes
	delActDoc
	delActLog
	delActTip
	delActNSID
	delNumActs
)

// buildDeleteTx is a tombstone's transaction: the tombstone chain row, the
// head move to it (pinning the checked head), the live document's removal,
// the log entry, the tip move and the entry marker — the write's seven
// actions minus the document upserts, plus the deletion.
func buildDeleteTx(table, ns, name string, p *writePlan) []types.TransactWriteItem {
	resK, revK := keyRes(ns, name), keyRev(ns, name, p.rev.pos)
	docK, logK, tipK := keyDocHead(ns, name), keyLog(ns, p.entry.pos), keyTip(ns)
	nsidK := keyNSID(ns, p.entry.id)

	out := make([]types.TransactWriteItem, delNumActs)
	out[delActRev] = types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(revK, p.rev.item()),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	out[delActRes] = types.TransactWriteItem{Update: &types.Update{
		TableName: &table,
		Key:       keyAV(resK),
		// The /heads metadata dies with the document; the last live
		// revision is what Head.Last answers (§8.1).
		UpdateExpression: strptr("SET headPos = :h, headId = :i, #st = :tomb, entryId = :e, lastId = :l, lastPos = :lp REMOVE headCreated, headSize, headDigest"),
		// The head is still the revision the check phase read.
		ConditionExpression:      strptr("headPos = :old AND headId = :oldi"),
		ExpressionAttributeNames: map[string]string{"#st": "state"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":h": avN(p.newHead.headPos), ":i": avS(p.newHead.headID), ":tomb": avS("tombstoned"), ":e": avS(p.entry.id),
			":l": avS(p.newHead.lastID), ":lp": avN(p.newHead.lastPos),
			":old": avN(p.oldHead), ":oldi": avS(p.rev.parentID),
		},
	}}
	out[delActDoc] = types.TransactWriteItem{Delete: &types.Delete{
		TableName: &table,
		Key:       keyAV(docK),
	}}
	out[delActLog] = types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(logK, p.entry.item()),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	out[delActTip] = types.TransactWriteItem{Update: &types.Update{
		TableName:           &table,
		Key:                 keyAV(tipK),
		UpdateExpression:    strptr("SET headPos = :new, headId = :newi"),
		ConditionExpression: strptr("headPos = :h AND headId = :i"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new": avN(p.entry.pos), ":newi": avS(p.entry.id),
			":h": avN(p.tip.headPos), ":i": avS(p.tip.headID),
		},
	}}
	out[delActNSID] = types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(nsidK, item{"ns": avS(ns), "logPos": avN(p.entry.pos), "revId": avS(p.rev.id)}),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
	return out
}

// buildCreateTx is namespace creation: the namespace, its config genesis
// and the first log entry, atomically (insertNamespace of nsops.go).
func buildCreateTx(table, ns string, m *nsMeta, cfgID string, patchesCanon, docCanon string, entry logRow) []types.TransactWriteItem {
	metaK, tipK := keyMeta(ns), keyTip(ns)
	cfgK, logK, nsidK := keyCfg(ns, 1), keyLog(ns, 1), keyNSID(ns, entry.id)
	notExists := "attribute_not_exists(PK)"
	return []types.TransactWriteItem{
		{Put: &types.Put{TableName: &table, Item: withKey(metaK, m.item()), ConditionExpression: &notExists}},
		{Put: &types.Put{TableName: &table, Item: withKey(cfgK, item{
			"pos": avN(1), "id": avS(cfgID), "logPos": avN(1), "patches": avS(patchesCanon), "doc": avS(docCanon), "author": avS(entry.author), "created": avI(entry.created),
			"G1PK": avS(g1RevID(cfgID)),
		})}},
		{Put: &types.Put{TableName: &table, Item: withKey(logK, entry.item())}},
		{Put: &types.Put{TableName: &table, Item: withKey(tipK, (&tip{headPos: 1, headID: entry.id}).item())}},
		{Put: &types.Put{TableName: &table, Item: withKey(nsidK, item{"ns": avS(ns), "logPos": avN(1), "revId": avS(cfgID)}), ConditionExpression: &notExists}},
	}
}

func strptr(s string) *string { return &s }

func keyAV(k Key) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"PK": avS(k.PK), "SK": avS(k.SK)}
}

func withKey(k Key, it item) map[string]types.AttributeValue {
	out := make(map[string]types.AttributeValue, len(it)+2)
	for a, v := range it {
		out[a] = v
	}
	out["PK"], out["SK"] = avS(k.PK), avS(k.SK)
	return out
}

func mergeVals(ms ...map[string]types.AttributeValue) map[string]types.AttributeValue {
	out := map[string]types.AttributeValue{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
