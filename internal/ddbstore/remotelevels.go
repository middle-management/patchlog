package ddbstore

// Remote levels (remote_levels of the SQL schema): a remote branch whose
// base's level, as last seen in the log it follows, is above its own,
// because it couldn't follow the raise (core's followLevel). One item per
// branch, in one partition, so they list in one query.

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const remLevelPK = "#REMLEVEL"

func keyRemLevel(branch string) Key { return Key{remLevelPK, branch} }

func scanRemoteLevel(i item) RemoteLevel {
	return RemoteLevel{Branch: i.s("SK"), Level: int(i.n("level")), Lacks: i.s("lacks") == "1", Rebase: i.s("rebase") == "1", ID: i.s("id"), Created: int64(i.n("created"))}
}

func flag(b bool) types.AttributeValue {
	if b {
		return avS("1")
	}
	return avS("0")
}

// PutRemoteLevel records l, replacing the branch's earlier record.
func (s *Store) PutRemoteLevel(ctx context.Context, l RemoteLevel) error {
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: withKey(keyRemLevel(l.Branch), item{
		"level": avN(uint64(l.Level)), "lacks": flag(l.Lacks), "rebase": flag(l.Rebase), "id": avS(l.ID), "created": avI(l.Created),
	})})
	return err
}

// RemoteLevelOf is branch's record, nil for none.
func (s *Store) RemoteLevelOf(ctx context.Context, branch string) (*RemoteLevel, error) {
	it, err := s.getItem(ctx, keyRemLevel(branch))
	if it == nil || err != nil {
		return nil, err
	}
	l := scanRemoteLevel(item(it))
	return &l, nil
}

// RemoteLevels lists every branch's record, by branch name.
func (s *Store) RemoteLevels(ctx context.Context) ([]RemoteLevel, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(remLevelPK)},
		ConsistentRead:            boolptr(true),
	}
	var out []RemoteLevel
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			out = append(out, scanRemoteLevel(item(it)))
		}
		if q.LastEvaluatedKey == nil {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}
