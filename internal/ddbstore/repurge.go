package ddbstore

// Second CDN purges (core's repurge.go, D.8): a commit that purges CDN
// tags queues them again in its own transaction (Commit.Repurge), so a
// crash loses none, as SQL's cdn_repurge. The queue is one partition,
// sorted by when each is due.

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const repurgePK = "#REPURGE"

// repurgeAct queues c's second purge, keyed by when it is due and by the
// entry, which is unique in its namespace.
func (s *Store) repurgeAct(c *Commit, entry logRow) []types.TransactWriteItem {
	if c.Repurge == nil {
		return nil
	}
	tags, _ := json.Marshal(c.Repurge.Tags)
	sk := padPos(uint64(c.Repurge.Due)) + "#" + c.NS + "#" + entry.id
	return []types.TransactWriteItem{{Put: &types.Put{TableName: &s.Table, Item: withKey(Key{repurgePK, sk}, item{"tags": avS(string(tags))})}}}
}

// DueRepurges lists up to limit second purges due at now (milliseconds),
// the earliest first.
func (s *Store) DueRepurges(ctx context.Context, now int64, limit int) ([]Repurge, error) {
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.Table,
		KeyConditionExpression: strptr("PK = :pk AND SK < :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(repurgePK), ":hi": avS(padPos(uint64(now) + 1)),
		},
		Limit:          int32ptr(int32(limit)),
		ConsistentRead: boolptr(true),
	})
	if err != nil {
		return nil, err
	}
	var out []Repurge
	for _, it := range q.Items {
		i := item(it)
		sk := i.s("SK")
		due, _ := parsePos(sk[:strings.IndexByte(sk, '#')])
		r := Repurge{Key: sk, Due: int64(due)}
		if json.Unmarshal([]byte(i.s("tags")), &r.Tags) != nil {
			r.Tags = nil // unreadable: dropped
		}
		out = append(out, r)
	}
	return out, nil
}

// DoneRepurge dequeues a sent second purge.
func (s *Store) DoneRepurge(ctx context.Context, key string) error {
	return s.deleteKey(ctx, Key{repurgePK, key})
}
