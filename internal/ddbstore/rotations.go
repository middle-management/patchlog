package ddbstore

// Rotations due (sealed.go's rotations_due): a sealed namespace whose
// rotation after a revocation hasn't run yet. A commit revoking access
// records one for each namespace the revocation reaches, in its
// transaction (Commit.RotationsDue); a commit beginning a new epoch
// clears its namespace's, since that is the rotation that was due.

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// rotDuePK is the partition listing the rotations due, one item per
// namespace.
const rotDuePK = "#ROTDUE"

func keyRotDue(ns string) Key { return Key{rotDuePK, ns} }

// rotDueActs are a commit's due rotations: put if absent (the first
// revocation's time stays), and its own cleared when it begins an epoch.
func (s *Store) rotDueActs(c *Commit) []types.TransactWriteItem {
	var out []types.TransactWriteItem
	for _, ns := range c.RotationsDue {
		if c.EpochKey != nil && ns == c.NS {
			continue
		}
		out = append(out, types.TransactWriteItem{Update: &types.Update{
			TableName: &s.Table, Key: keyAV(keyRotDue(ns)),
			UpdateExpression:          strptr("SET since = if_not_exists(since, :t)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":t": avI(c.Created)},
		}})
	}
	if c.EpochKey != nil {
		out = append(out, types.TransactWriteItem{Delete: &types.Delete{TableName: &s.Table, Key: keyAV(keyRotDue(c.NS))}})
	}
	return out
}

// rotDueActions counts rotDueActs's actions.
func rotDueActions(c *Commit) int {
	n := len(c.RotationsDue)
	if c.EpochKey != nil {
		n++
		for _, ns := range c.RotationsDue {
			if ns == c.NS {
				n--
			}
		}
	}
	return n
}

// RotationsDue lists the namespaces with a rotation due, by name.
func (s *Store) RotationsDue(ctx context.Context) ([]string, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(rotDuePK)},
		ConsistentRead:            boolptr(true),
	}
	var out []string
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			out = append(out, item(it).s("SK"))
		}
		if q.LastEvaluatedKey == nil {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// RotationDue reports whether ns has a rotation due.
func (s *Store) RotationDue(ctx context.Context, ns string) (bool, error) {
	it, err := s.getItem(ctx, keyRotDue(ns))
	return it != nil, err
}

// ClearRotationDue drops ns's due rotation: nothing is left to rotate.
func (s *Store) ClearRotationDue(ctx context.Context, ns string) error {
	return s.deleteKey(ctx, keyRotDue(ns))
}
