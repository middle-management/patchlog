package ddb

import (
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

func apiErr(status int, code string, members ...any) *Error {
	e := &Error{Status: status, Body: map[string]any{"status": status, "error": code}}
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
	doc     string // canonical JSON of the resulting head document

	resExists bool // pin RES# headPos, else attribute_not_exists
	oldHead   uint64
	tip       tip  // pin #TIP (headPos, headID)
	create    bool // the write creates the resource
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
func planWrite(ns, name string, m *nsMeta, t *tip, head *resRow, headDoc any, ifMatch string, patches any, author string, now int64, apply func(doc any, exists bool, patches any) (any, error)) (*writePlan, *Error) {
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

	doc, err := apply(headDoc, head != nil && head.headPos > 0, patches)
	if err != nil {
		return nil, apiErr(422, "patch", "detail", err.Error())
	}

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
		},
		entry: logRow{
			pos:     t.headPos + 1,
			id:      entryID.String(),
			prevPos: t.headPos,
			kind:    "head",
			body:    string(body),
			author:  author,
			created: now,
		},
		newHead:   resRow{headPos: pos, headID: revID.String(), entryID: entryID.String(), state: "live"},
		doc:       string(jsonv.Canonical(doc)),
		resExists: head != nil,
		oldHead:   pos - 1, // the head position the RES condition pins
		tip:       *t,
		create:    head == nil || head.headPos == 0,
	}, nil
}

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
	out[actRes] = types.TransactWriteItem{Update: &types.Update{
		TableName:                &table,
		Key:                      keyAV(resK),
		UpdateExpression:         strptr("SET headPos = :h, headId = :i, #st = :live, entryId = :e"),
		ConditionExpression:      &resCond,
		ExpressionAttributeNames: map[string]string{"#st": "state"},
		ExpressionAttributeValues: mergeVals(resVals, map[string]types.AttributeValue{
			":h": avN(p.newHead.headPos), ":i": avS(p.newHead.headID), ":live": avS("live"), ":e": avS(p.entry.id),
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

// buildCreateTx is namespace creation: the namespace, its config genesis
// and the first log entry, atomically (insertNamespace of nsops.go).
func buildCreateTx(table, ns string, m *nsMeta, cfgID string, patchesCanon, docCanon string, entry logRow) []types.TransactWriteItem {
	metaK, tipK := keyMeta(ns), keyTip(ns)
	cfgK, logK, nsidK := keyCfg(ns, 1), keyLog(ns, 1), keyNSID(ns, entry.id)
	notExists := "attribute_not_exists(PK)"
	return []types.TransactWriteItem{
		{Put: &types.Put{TableName: &table, Item: withKey(metaK, m.item()), ConditionExpression: &notExists}},
		{Put: &types.Put{TableName: &table, Item: withKey(cfgK, item{
			"pos": avN(1), "id": avS(cfgID), "patches": avS(patchesCanon), "doc": avS(docCanon), "author": avS(entry.author), "created": avI(entry.created),
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
