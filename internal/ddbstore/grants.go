package ddbstore

// Grants (§C.3, §7.4): the stored, non-bearer form of each grant a write
// was made under, deployment-wide (keyGrant), and per namespace a marker
// that one of its entries records it (keyNSGrant), which GET
// /ns/{ns}/grants/{gid} answers by. Entries and revisions carry the
// grant's id (grantId); the reference they serve, its root sub and kid,
// is read from the stored grant.

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// PutGrant stores grant gid. It is written before the commits that record
// it, outside their transactions (a group's commits may share a grant):
// one whose commit then fails is never served, since no entry names it.
// Grant ids are content hashes, so rewriting one is harmless — but for
// its encryption: blocks encrypted at rest (sealed) replace what is
// stored, plaintext ones are only stored if nothing is, so a grant used
// in an encrypted namespace stays encrypted.
func (s *Store) PutGrant(ctx context.Context, gid string, g StoredGrant, sealed bool) error {
	in := &dynamodb.PutItemInput{
		TableName: &s.Table,
		Item:      withKey(keyGrant(gid), item{"blocks": avB(g.Blocks), "rootSub": avS(g.Sub), "rootKid": avS(g.Kid)}),
	}
	if !sealed {
		in.ConditionExpression = strptr("attribute_not_exists(PK)")
	}
	_, err := s.Client.PutItem(ctx, in)
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return nil
	}
	return err
}

// Grant reads grant gid's stored form; nil when it isn't stored.
func (s *Store) Grant(ctx context.Context, gid string) (*StoredGrant, error) {
	it, err := s.getItem(ctx, keyGrant(gid))
	if it == nil || err != nil {
		return nil, err
	}
	i := item(it)
	return &StoredGrant{Blocks: i.b("blocks"), Sub: i.s("rootSub"), Kid: i.s("rootKid")}, nil
}

// RecordsGrant reports whether an entry of ns at or before position upTo
// (0: any) records grant gid: its marker keeps the first that does.
func (s *Store) RecordsGrant(ctx context.Context, ns, gid string, upTo uint64) (bool, error) {
	it, err := s.getItem(ctx, keyNSGrant(ns, gid))
	if it == nil || err != nil {
		return false, err
	}
	return upTo == 0 || item(it).n("firstPos") <= upTo, nil
}

// FirstEntryTime is the created time (milliseconds) of the deployment's
// first namespace entry, which every namespace creation offers and the
// first keeps; ok is false when there is none yet.
func (s *Store) FirstEntryTime(ctx context.Context) (ms int64, ok bool, err error) {
	it, err := s.getItem(ctx, keyDeploy())
	if it == nil || err != nil {
		return 0, false, err
	}
	return int64(item(it).n("firstCreated")), true, nil
}

// deployFirst offers created as the deployment's first entry's time.
func deployFirst(table string, created int64) types.TransactWriteItem {
	return types.TransactWriteItem{Update: &types.Update{
		TableName:                 &table,
		Key:                       keyAV(keyDeploy()),
		UpdateExpression:          strptr("SET firstCreated = if_not_exists(firstCreated, :c)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":c": avI(created)},
	}}
}
