package ddbstore

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/patch"
)

// The pure half of the write path (docs/DYNAMODB.md §4): from the state
// the check phase read, build the transaction. No I/O — the hermetic tests
// of build_test.go prove positions, conditions and id computations here;
// local_test.go proves DynamoDB enforces them.

// apiErr builds an error in the core's body shape (engine.go's apiErr):
// {"code": …, …members}, so the server serves either backend alike.
func apiErr(status int, code string, members ...any) *Error {
	e := &Error{Status: status, Body: map[string]any{"code": code}}
	for i := 0; i+1 < len(members); i += 2 {
		e.Body[members[i].(string)] = members[i+1]
	}
	return e
}

// patchErr is a patch set that doesn't apply (patchErr of write.go): 422
// invalid, naming the operation and pointer that failed.
func patchErr(err error) *Error {
	var pe *patch.Error
	if errors.As(err, &pe) {
		return apiErr(422, "invalid", "message", pe.Message, "index", pe.Index, "pointer", pe.Pointer)
	}
	return apiErr(422, "invalid", "message", err.Error())
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
