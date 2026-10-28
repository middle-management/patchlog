package ddbstore

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// The serving reads beyond the head and the log: revision-by-id,
// folds, resource logs, namespace info.

// resNameFromRev is the resource name of a REV# sort key.
func resNameFromRev(sk string) string {
	rest := strings.TrimPrefix(sk, "REV#")
	if i := strings.LastIndex(rest, "#"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// walkChain applies each revision's patches in order, after fromPos (0:
// from the genesis) up to toPos (0: all), to start (exists: whether it
// is a document — a JSON null document exists). A fold ending at a
// tombstone has no document; one crossing it applies the restore's
// patches to the last live document, as the write did (§6.2's restore
// verb, applySteps of write.go).
func (s *Store) walkChain(ctx context.Context, ns, name string, fromPos, toPos uint64, start any, exists bool, apply func(pos uint64, doc any, exists bool, patches string) (any, error)) (any, error) {
	if toPos == 0 {
		toPos = 999999999999
	}
	doc, dead := start, false
	last := fromPos
	var ferr error
	err := s.rangeOf(ctx, ns, "REV#"+name+"#", fromPos, toPos, 0, func(i item) bool {
		pos := i.n("pos")
		switch {
		case pos != last+1:
			// A missing revision mid-chain: a lost race with a purge, or
			// corruption (docs/DYNAMODB.md §5). Never serve a partial fold.
			ferr = apiErr(409, "conflict", "detail", "gap in the revision chain")
			return false
		case i.s("kind") == "tombstone":
			last, dead = pos, true
			return true
		case !i.has("patches"):
			ferr = &PrunedError{NS: ns, Name: name, Pos: pos}
			return false
		}
		last = pos
		var patches string
		if patches, ferr = s.open(ctx, ns, name, "rev", i.s("id"), i.s("patches")); ferr != nil {
			return false
		}
		doc, ferr = apply(pos, doc, exists, patches)
		exists, dead = true, false
		return ferr == nil
	})
	switch {
	case err != nil:
		return nil, err
	case ferr != nil:
		return nil, ferr
	case dead:
		return nil, nil
	}
	return doc, nil
}

// ReadRevOf finds a revision of one resource by its id: ReadRevByID's
// GSI1 lookup narrowed to the resource's chain. Genesis twins (one patch
// set creating two resources) share an id within a namespace, so the
// namespace alone doesn't decide which revision an id names, and a read
// of one twin must not answer the other's (findInAncestry walks the
// resource's own chain). Absent is nil, not an error.
func (s *Store) ReadRevOf(ctx context.Context, ns, name, id string) (*RevInfo, error) {
	in := &dynamodb.QueryInput{
		TableName:              &s.Table,
		IndexName:              strptr(gsiName),
		KeyConditionExpression: strptr("G1PK = :g"),
		FilterExpression:       strptr("PK = :pk AND begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":g": avS(g1RevID(id)), ":pk": avS(nsPK(ns)), ":pfx": avS("REV#" + name + "#"),
		},
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			i := item(it)
			if resNameFromRev(i.s("SK")) != name {
				continue // a name of which this one is a prefix
			}
			r := scanRevInfo(i)
			return &r, nil
		}
		if q.LastEvaluatedKey == nil {
			return nil, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// Ping checks the table is reachable (the /_ready check, Engine.Ping).
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.Client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &s.Table})
	return err
}

// FormatTime renders a stored millisecond timestamp the way the API
// serves it (reads.go's formatTime).
func FormatTime(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// FoldResource folds a resource's chain from the genesis up to and
// including position toPos (0: the head), applying each revision's patch
// set with the production engine. One ordered query; the §5 audit turns a
// gap into an error, never a partial document.
func (s *Store) FoldResource(ctx context.Context, ns, name string, toPos uint64) (doc any, canon []byte, err error) {
	return s.foldFrom(ctx, ns, name, 0, toPos, nil, false)
}

// foldFrom is FoldResource after fromPos, from start (exists: whether it
// is a document): a foreign parent's document for a chain that continues
// one, or a pruned chain's horizon's.
func (s *Store) foldFrom(ctx context.Context, ns, name string, fromPos, toPos uint64, start any, exists bool) (doc any, canon []byte, err error) {
	doc, err = s.walkChain(ctx, ns, name, fromPos, toPos, start, exists, func(_ uint64, d any, exists bool, patches string) (any, error) {
		p, err := jsonv.Parse([]byte(patches))
		if err != nil {
			return nil, err
		}
		// A genesis applies to the document null, as its create did (§6.2 step 3).
		out, _, err := applyPatches(d, true, p)
		return out, err
	})
	if err != nil {
		return nil, nil, err
	}
	return doc, jsonv.Canonical(doc), nil
}

// RevsWithID lists every revision of id, in any namespace and resource
// (GSI1): the copies of a revision.
func (s *Store) RevsWithID(ctx context.Context, id string) ([]IDRev, error) {
	in := &dynamodb.QueryInput{
		TableName:              &s.Table,
		IndexName:              strptr(gsiName),
		KeyConditionExpression: strptr("G1PK = :g"),
		FilterExpression:       strptr("begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":g": avS(g1RevID(id)), ":pfx": avS("REV#"),
		},
	}
	var out []IDRev
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			i := item(it)
			out = append(out, IDRev{NS: strings.TrimPrefix(i.s("PK"), "NS#"), Rev: scanRevInfo(i)})
		}
		if q.LastEvaluatedKey == nil {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}
