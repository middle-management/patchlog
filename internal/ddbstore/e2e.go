package ddbstore

// End-to-end namespaces (Addendum E.3). The server holds no key and no
// document of their content: revisions keep their sealed patch sets as
// sent and the blobs their documents declare (REV declared), the
// resource no head document (CommitItem.E2E); each epoch's start is an
// EPOCHKEY item without a key (sealed.go). A prune keeps the horizon's
// document as the client sealed it, E2ESNAP#<name>#<pos12>, which
// GET …/rev/{id} serves for the horizon and names as the start of a fold
// for the revisions after it.

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func e2eSnapPrefix(name string) string { return "E2ESNAP#" + name + "#" }
func keyE2ESnap(ns, name string, pos uint64) Key {
	return Key{nsPK(ns), e2eSnapPrefix(name) + padPos(pos)}
}

// E2ESnapshot reads name's client-sealed snapshot at pos; "" for none.
func (s *Store) E2ESnapshot(ctx context.Context, ns, name string, pos uint64) (string, error) {
	it, err := s.getItem(ctx, keyE2ESnap(ns, name, pos))
	if it == nil || err != nil {
		return "", err
	}
	return item(it).s("jwe"), nil
}

// LatestE2ESnapshot is the position of name's latest snapshot at or
// before pos; 0 for none.
func (s *Store) LatestE2ESnapshot(ctx context.Context, ns, name string, pos uint64) (uint64, error) {
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.Table,
		KeyConditionExpression: strptr("PK = :pk AND SK BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(nsPK(ns)), ":lo": avS(e2eSnapPrefix(name)), ":hi": avS(e2eSnapPrefix(name) + padPos(pos)),
		},
		ScanIndexForward: boolptr(false),
		Limit:            int32ptr(1),
		ConsistentRead:   boolptr(true),
	})
	if err != nil || len(q.Items) == 0 {
		return 0, err
	}
	return item(q.Items[0]).n("pos"), nil
}

func e2eSnapAct(table, ns, name string, pos uint64, jwe string) types.TransactWriteItem {
	return types.TransactWriteItem{Put: &types.Put{
		TableName: &table,
		Item:      withKey(keyE2ESnap(ns, name, pos), item{"name": avS(name), "pos": avN(pos), "jwe": avS(jwe)}),
	}}
}

// deleteE2ESnapshots deletes name's snapshots below pos (all of them for
// pos 0; all of ns's for name "").
func (s *Store) deleteE2ESnapshots(ctx context.Context, ns, name string, below uint64) error {
	prefix := "E2ESNAP#"
	if name != "" {
		prefix = e2eSnapPrefix(name)
	}
	return s.eachItem(ctx, ns, prefix, func(i item) error {
		if name != "" && i.s("name") != name || below > 0 && i.n("pos") >= below {
			return nil
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}
