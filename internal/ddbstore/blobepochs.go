package ddbstore

// Blob sealings of sealed namespaces (§E.2.2; blob_epochs of the SQL
// schema): BLOBEPOCH#<name>#<bid>#<epoch12> in the serving namespace's
// partition holds a blob's sealing under an epoch, inline or as the name
// of a file of the engine's blob store, stored once on its first read
// and served from then on; or, with neither, the marker of an epoch whose
// referencing revisions pruning removed (410). Which epochs a blob is
// served under is derived from the documents when asked (core's
// ddbsealedblobs.go); these items keep only what can't be.

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func blobEpochPrefix(name, bid string) string { return "BLOBEPOCH#" + name + "#" + bid + "#" }
func keyBlobEpoch(ns, name, bid string, epoch int) Key {
	return Key{nsPK(ns), blobEpochPrefix(name, bid) + padPos(uint64(epoch))}
}

// BlobEpoch reads name's sealing of bid in ns under epoch: its bytes or
// the file holding them; ok with neither for a pruned epoch's marker.
func (s *Store) BlobEpoch(ctx context.Context, ns, name, bid string, epoch int) (data []byte, file string, ok bool, err error) {
	it, err := s.getItem(ctx, keyBlobEpoch(ns, name, bid, epoch))
	if it == nil || err != nil {
		return nil, "", false, err
	}
	return item(it).b("data"), item(it).s("file"), true, nil
}

// PutBlobEpoch stores a sealing, inline (data) or as file, unless one is
// stored, and returns the one stored. A marker is replaced.
func (s *Store) PutBlobEpoch(ctx context.Context, ns, name, bid string, epoch int, data []byte, file string, now int64) (storedData []byte, storedFile string, err error) {
	it := item{"name": avS(name), "bid": avS(bid), "epoch": avN(uint64(epoch)), "created": avI(now)}
	if file != "" {
		it["file"] = avS(file)
	} else {
		it["data"] = avB(data)
	}
	_, err = s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.Table, Item: withKey(keyBlobEpoch(ns, name, bid, epoch), it),
		ConditionExpression:      strptr("attribute_not_exists(PK) OR (attribute_not_exists(#d) AND attribute_not_exists(#f))"),
		ExpressionAttributeNames: map[string]string{"#d": "data", "#f": "file"},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		d, f, _, err := s.BlobEpoch(ctx, ns, name, bid, epoch)
		return d, f, err
	}
	return data, file, err
}

// MarkBlobEpoch replaces name's sealing of bid under epoch with the marker
// of a pruned epoch, and returns the file the sealing was in, if any.
func (s *Store) MarkBlobEpoch(ctx context.Context, ns, name, bid string, epoch int, now int64) (file string, err error) {
	out, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:    &s.Table,
		Item:         withKey(keyBlobEpoch(ns, name, bid, epoch), item{"name": avS(name), "bid": avS(bid), "epoch": avN(uint64(epoch)), "created": avI(now)}),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return "", err
	}
	return item(out.Attributes).s("file"), nil
}

// DeleteBlobEpochs deletes ns's blob sealings and markers: name's of bid,
// all of name's for bid "", all of ns's for name "". It returns the files
// they named, for the caller to delete.
func (s *Store) DeleteBlobEpochs(ctx context.Context, ns, name, bid string) (files []string, err error) {
	err = s.eachBlobEpoch(ctx, ns, name, bid, func(i item) (bool, error) {
		if f := i.s("file"); f != "" {
			files = append(files, f)
		}
		return true, nil
	})
	return files, err
}

// ClearBlobEpochMarkers deletes the markers of name's pruned epochs: a
// restored archive serves their revisions again (§E.2.2, D.4).
func (s *Store) ClearBlobEpochMarkers(ctx context.Context, ns, name string) error {
	return s.eachBlobEpoch(ctx, ns, name, "", func(i item) (bool, error) {
		return !i.has("data") && !i.has("file"), nil
	})
}

// eachBlobEpoch deletes the items DeleteBlobEpochs selects for which del
// says so.
func (s *Store) eachBlobEpoch(ctx context.Context, ns, name, bid string, del func(item) (bool, error)) error {
	prefix := "BLOBEPOCH#"
	if name != "" {
		prefix += name + "#"
		if bid != "" {
			prefix = blobEpochPrefix(name, bid)
		}
	}
	return s.eachItem(ctx, ns, prefix, func(i item) error {
		if name != "" && i.s("name") != name || bid != "" && i.s("bid") != bid {
			return nil // another resource whose name extends this one
		}
		ok, err := del(i)
		if !ok || err != nil {
			return err
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}
