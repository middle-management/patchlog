package ddbstore

// Sealed namespaces (Addendum E.2). The store keeps what core's sealing
// needs and holds no keys: each epoch's key, wrapped by the key store,
// as EPOCHKEY#<epoch> in the namespace's partition, written by the commit
// that begins the epoch (Commit.EpochKey) with its time as the epoch's
// start; each revision's epoch (REV epoch, Commit.Epoch); and the sealed
// bytes served, SEALED#<kind>#<key>, stored on first read put-if-absent so
// every reader serves the first stored (§E.2.2). Purges delete a
// resource's sealed items, and a namespace's also its epoch keys; a prune
// those of the revisions it pruned (PruneContent).

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func keyEpochKey(ns string, epoch int) Key { return Key{nsPK(ns), "EPOCHKEY#" + padPos(uint64(epoch))} }

func epochKeyAct(table, ns string, k *EpochKey, created int64) types.TransactWriteItem {
	return types.TransactWriteItem{Put: &types.Put{
		TableName:           &table,
		Item:                withKey(keyEpochKey(ns, k.Epoch), epochKeyItem(k, created)),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	}}
}

// item is k's EPOCHKEY item: an e2e namespace's has no key, only the
// epoch's start (§E.3).
func epochKeyItem(k *EpochKey, created int64) item {
	it := item{"epoch": avN(uint64(k.Epoch)), "created": avI(created)}
	if len(k.Wrapped) > 0 {
		it["wrapped"], it["keystore"] = avB(k.Wrapped), avS(k.KeyStore)
	}
	return it
}

func scanEpochKey(i item) *EpochKey {
	return &EpochKey{Epoch: int(i.n("epoch")), Wrapped: i.b("wrapped"), KeyStore: i.s("keystore"), Created: int64(i.n("created"))}
}

// EpochKeyOf reads ns's key of epoch; nil when there is none.
func (s *Store) EpochKeyOf(ctx context.Context, ns string, epoch int) (*EpochKey, error) {
	it, err := s.getItem(ctx, keyEpochKey(ns, epoch))
	if it == nil || err != nil {
		return nil, err
	}
	return scanEpochKey(item(it)), nil
}

// EpochKeys lists ns's epoch keys, ascending.
func (s *Store) EpochKeys(ctx context.Context, ns string) ([]*EpochKey, error) {
	var out []*EpochKey
	err := s.eachItem(ctx, ns, "EPOCHKEY#", func(i item) error {
		out = append(out, scanEpochKey(i))
		return nil
	})
	return out, err
}

// AnyEpochKey is one stored epoch key and its namespace, for checking at
// start-up that the key store unwraps them; nil for none. e2e epochs,
// which have no key, don't count.
func (s *Store) AnyEpochKey(ctx context.Context) (string, *EpochKey, error) {
	in := &dynamodb.ScanInput{
		TableName:                 &s.Table,
		FilterExpression:          strptr("begins_with(SK, :p) AND attribute_exists(#w)"),
		ExpressionAttributeNames:  map[string]string{"#w": "wrapped"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": avS("EPOCHKEY#")},
	}
	for {
		out, err := s.Client.Scan(ctx, in)
		if err != nil {
			return "", nil, err
		}
		for _, raw := range out.Items {
			i := item(raw)
			return strings.TrimPrefix(i.s("PK"), "NS#"), scanEpochKey(i), nil
		}
		if len(out.LastEvaluatedKey) == 0 {
			return "", nil, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// DeleteEpochKeys destroys ns's epoch keys (a namespace purge).
func (s *Store) DeleteEpochKeys(ctx context.Context, ns string) error {
	return s.eachItem(ctx, ns, "EPOCHKEY#", func(i item) error {
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}

func keySealed(ns, kind, key string) Key { return Key{nsPK(ns), "SEALED#" + kind + "#" + key} }

// Sealed reads ns's stored sealed value of kind and key; "" for none.
func (s *Store) Sealed(ctx context.Context, ns, kind, key string) (jwe string, created int64, err error) {
	it, err := s.getItem(ctx, keySealed(ns, kind, key))
	if it == nil || err != nil {
		return "", 0, err
	}
	return item(it).s("jwe"), int64(item(it).n("created")), nil
}

// PutSealed stores v unless a value of its kind and key is stored, and
// returns the one stored.
func (s *Store) PutSealed(ctx context.Context, ns string, v SealedValue, now int64) (string, error) {
	it := item{"jwe": avS(v.JWE), "created": avI(now), "kind": avS(v.Kind)}
	if v.Name != "" {
		it["name"] = avS(v.Name)
	}
	if v.RevPos > 0 {
		it["revPos"] = avN(v.RevPos)
	}
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.Table, Item: withKey(keySealed(ns, v.Kind, v.Key), it),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		jwe, _, err := s.Sealed(ctx, ns, v.Kind, v.Key)
		return jwe, err
	}
	return v.JWE, err
}

// DeleteSealed deletes ns's sealed values of resource name, or all of
// ns's for name "".
func (s *Store) DeleteSealed(ctx context.Context, ns, name string) error {
	return s.eachItem(ctx, ns, "SEALED#", func(i item) error {
		if name != "" && i.s("name") != name {
			return nil
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}

// deletePrunedSealed deletes the sealed documents and entries of name's
// revisions below horizon, but a kept document's (kept positions).
func (s *Store) deletePrunedSealed(ctx context.Context, ns, name string, horizon uint64, kept map[uint64]bool) error {
	return s.eachItem(ctx, ns, "SEALED#", func(i item) error {
		pos := i.n("revPos")
		if i.s("name") != name || pos == 0 || pos >= horizon {
			return nil
		}
		if kept[pos] && i.s("kind") != "entry" {
			return nil
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}

// PutEpochStart records that epoch of ns began at created, unless it is
// recorded: a keyless EPOCHKEY item, an e2e epoch's (a remote branch's
// shadow following its base's epochs).
func (s *Store) PutEpochStart(ctx context.Context, ns string, epoch int, created int64) error {
	k := &EpochKey{Epoch: epoch}
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.Table, Item: withKey(keyEpochKey(ns, epoch), epochKeyItem(k, created)),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return nil
	}
	return err
}
