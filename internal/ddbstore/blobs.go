package ddbstore

// Blobs (§7.8, docs/DYNAMODB.md §3): a resource's attachments and its
// pending uploads are items of the namespace's partition, and the bytes
// items of their own, by sha256:
//
//   - BLOB#<name>#<bid>: an attachment — type, nonce, size, hash, the
//     first revision that referenced it. Written by the commit of the
//     write whose document first references the blob (CommitItem.Attach).
//   - PEND#<name>#<bid>#<uploader>: a pending entry, one per uploader
//     (base64url, so the key has no '#' of its own), with its created
//     time; reads ignore one older than blobGrace. An upload writes it
//     conditioned on the configuration it was checked under (PutPending);
//     the attaching commit deletes those of the blob.
//   - BYTES#<sha256 hex>: the bytes, inline (at most MaxInlineBytes) or
//     the name of the file of the engine's blob store that holds them.
//     Written before the item that names them, outside its transaction,
//     like grants. Encrypted bytes are core's, under their owner's data
//     key and a hash of owner and content (BlobRow.Owner).
//
// The sweep (core's SweepBlobs) deletes expired pending entries and the
// bytes no item names any more, by a scan. An attachment pruning ended
// (pruned, prune.go) names none. There are no reference intervals
// (blob_refs of the SQL schema): which revisions reference a blob, for
// archives and sealed blobs, core derives from the revisions themselves.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ddb"
)

func keyBlob(ns, name, bid string) Key { return Key{resPK(ns, name), "BLOB#" + name + "#" + bid} }
func keyPending(ns, name, bid, uploader string) Key {
	return Key{nsPK(ns), pendingPrefix(name, bid) + base64.RawURLEncoding.EncodeToString([]byte(uploader))}
}

// keyUploader orders an uploader's uploads in ns (blob_uploaders of the
// SQL schema): each upload moves its version, conditioned on the version
// read before its pending total, so two concurrent ones can't both fit
// blobPending.
func keyUploader(ns, uploader string) Key {
	return Key{nsPK(ns), "UPL#" + base64.RawURLEncoding.EncodeToString([]byte(uploader))}
}

func pendingPrefix(name, bid string) string { return "PEND#" + name + "#" + bid + "#" }
func keyBytes(hash []byte) Key              { return Key{"BYTES#" + hex.EncodeToString(hash), "#"} }

func blobItem(b *ddb.BlobRow) item {
	it := item{"name": avS(b.Name), "bid": avS(b.Bid), "type": avS(b.Type), "size": avI(b.Size), "hash": avB(b.Hash), "created": avI(b.Created)}
	if b.Nonce != "" {
		it["nonce"] = avS(b.Nonce)
	}
	if b.Uploader != "" {
		it["uploader"] = avS(b.Uploader)
	}
	if b.RefPos > 0 {
		it["refPos"] = avN(b.RefPos)
	}
	if b.Owner != "" {
		it["owner"] = avS(b.Owner)
	}
	return it
}

func scanBlob(i item) *ddb.BlobRow {
	return &ddb.BlobRow{
		Name: i.s("name"), Bid: i.s("bid"), Type: i.s("type"), Nonce: i.s("nonce"), Size: int64(i.n("size")),
		Hash: i.b("hash"), Created: int64(i.n("created")), Uploader: i.s("uploader"), RefPos: i.n("refPos"),
		Attachment: strings.HasPrefix(i.s("SK"), "BLOB#"), Pruned: i.n("pruned") != 0, Owner: i.s("owner"),
	}
}

// EndAttachment marks name's attachment of bid in ns pruned, if name's
// head is still the one at headPos the caller read every document up to
// (core's ending of attachments after a prune): a write since may
// reference it. ErrStale if it moved.
func (s *Store) EndAttachment(ctx context.Context, ns, name, bid string, headPos uint64, headID string) error {
	_, err := s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName: &s.Table, Key: keyAV(keyRes(ns, name)),
			ConditionExpression:       strptr("headPos = :h AND headId = :i"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":h": avN(headPos), ":i": avS(headID)},
		}},
		{Update: &types.Update{
			TableName: &s.Table, Key: keyAV(keyBlob(ns, name, bid)),
			UpdateExpression:          strptr("SET pruned = :one"),
			ConditionExpression:       strptr("attribute_exists(PK)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": avN(1)},
		}},
	}})
	var ce *types.TransactionCanceledException
	if errors.As(err, &ce) {
		return ddb.ErrStale
	}
	return err
}

// Attachment reads name's attachment of bid in ns; nil when there is none.
func (s *Store) Attachment(ctx context.Context, ns, name, bid string) (*ddb.BlobRow, error) {
	it, err := s.getItem(ctx, keyBlob(ns, name, bid))
	if it == nil || err != nil {
		return nil, err
	}
	return scanBlob(item(it)), nil
}

// Pending reads uploader's pending entry of bid for name in ns; nil when
// there is none (expired or not: the caller compares Created).
func (s *Store) Pending(ctx context.Context, ns, name, bid, uploader string) (*ddb.BlobRow, error) {
	it, err := s.getItem(ctx, keyPending(ns, name, bid, uploader))
	if it == nil || err != nil {
		return nil, err
	}
	return scanBlob(item(it)), nil
}

// PendingOf lists every pending entry of ns, expired ones included (the
// caller filters): an upload sums an uploader's, an attaching commit
// deletes a blob's. Pending entries are short-lived, so the partition's
// PEND# range stays small.
func (s *Store) PendingOf(ctx context.Context, ns string) ([]*ddb.BlobRow, error) {
	var out []*ddb.BlobRow
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":p": avS("PEND#")},
		ConsistentRead:            boolptr(true),
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			out = append(out, scanBlob(item(it)))
		}
		if len(q.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// UploaderVersion reads the version of uploader's uploads in ns (0 for
// none yet); read before the pending entries a total is summed from.
func (s *Store) UploaderVersion(ctx context.Context, ns, uploader string) (uint64, error) {
	it, err := s.getItem(ctx, keyUploader(ns, uploader))
	if it == nil || err != nil {
		return 0, err
	}
	return item(it).n("ver"), nil
}

// PutPending writes (or renews: uploading again restarts the grace time)
// a pending entry of ns, conditioned on the configuration the upload was
// checked under and on the uploader's version (ver) its pending total
// was read at, and on its bytes being stored (a purge collects the bytes
// nothing names, which these may be until the entry is written):
// ErrStale when any of them moved.
func (s *Store) PutPending(ctx context.Context, ns string, cfgPos uint64, cfgID string, ver uint64, p *ddb.BlobRow) error {
	cond, vals := "ver = :old", map[string]types.AttributeValue{":old": avN(ver), ":new": avN(ver + 1)}
	if ver == 0 {
		cond = "attribute_not_exists(PK)"
		delete(vals, ":old")
	}
	_, err := s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: &s.Table, Key: keyAV(keyUploader(ns, p.Uploader)),
			UpdateExpression: strptr("SET ver = :new"), ConditionExpression: &cond, ExpressionAttributeValues: vals,
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 &s.Table,
			Key:                       keyAV(keyMeta(ns)),
			ConditionExpression:       strptr(metaCond),
			ExpressionAttributeValues: metaVals(cfgPos, cfgID),
		}},
		{Put: &types.Put{TableName: &s.Table, Item: withKey(keyPending(ns, p.Name, p.Bid, p.Uploader), blobItem(p))}},
		// The bytes stay while the entry names them: their version moves,
		// so a collection that scanned them before this commit doesn't
		// delete them after it (CollectBytes); one that deleted them first
		// fails this condition, and the upload stores them again.
		{Update: &types.Update{
			TableName: &s.Table, Key: keyAV(keyBytes(p.Hash)),
			UpdateExpression:          strptr("ADD ver :one"),
			ConditionExpression:       strptr("attribute_exists(PK)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": avI(1)},
		}},
	}})
	var ce *types.TransactionCanceledException
	if errors.As(err, &ce) {
		return ddb.ErrStale
	}
	return err
}

// PutBytes stores the bytes with sha256 hash: data inline, or file, the
// name in the blob store holding them. It reports whether they were
// stored already, by an earlier upload: then file, if any, is the
// caller's to discard. Either way the bytes are touched at now, which
// keeps the sweep from collecting them before the item naming them is
// written (SweepBytes).
func (s *Store) PutBytes(ctx context.Context, hash, data []byte, file string, now int64) (existed bool, err error) {
	it := item{"data": avB(data), "size": avI(int64(len(data))), "touched": avI(now)}
	if file != "" {
		it = item{"file": avS(file), "size": avI(int64(len(data))), "touched": avI(now)}
	}
	_, err = s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.Table, Item: withKey(keyBytes(hash), it),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	})
	var cf *types.ConditionalCheckFailedException
	if !errors.As(err, &cf) {
		return false, err
	}
	_, err = s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyBytes(hash)),
		UpdateExpression:          strptr("SET touched = :t"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": avI(now)},
	})
	return true, err
}

// Bytes reads the bytes with sha256 hash: inline, or the name of their
// file; ok is false when they aren't stored.
func (s *Store) Bytes(ctx context.Context, hash []byte) (data []byte, file string, ok bool, err error) {
	it, err := s.getItem(ctx, keyBytes(hash))
	if it == nil || err != nil {
		return nil, "", false, err
	}
	i := item(it)
	return i.b("data"), i.s("file"), true, nil
}

// attachActs are an item's attachments (BLOB items) and the deletions of
// the pending entries it ends.
func (s *Store) attachActs(c *ddb.Commit, it *ddb.CommitItem) []types.TransactWriteItem {
	var out []types.TransactWriteItem
	for _, a := range it.Attach {
		b := &ddb.BlobRow{Name: it.Name, Bid: a.Bid, Type: a.Type, Nonce: a.Nonce, Size: a.Size, Hash: a.Hash, Owner: a.Owner,
			Created: c.Created, RefPos: it.HeadPos + uint64(a.Step) + 1}
		out = append(out, types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(keyBlob(c.NS, it.Name, a.Bid), blobItem(b))}})
	}
	for _, p := range it.EndPending {
		out = append(out, types.TransactWriteItem{Delete: &types.Delete{TableName: &s.Table, Key: keyAV(keyPending(c.NS, it.Name, p.Bid, p.Uploader))}})
	}
	return out
}

func attachActions(it *ddb.CommitItem) int { return len(it.Attach) + len(it.EndPending) }

// ScanBlobs lists every attachment, pending entry and bytes item of the
// table — a scan: operators' statistics and the sweep, never a request.
// NS is set on the attachments and pending entries.
func (s *Store) ScanBlobs(ctx context.Context) (blobs []*ddb.BlobRow, nss []string, bytes []*ddb.BytesRow, err error) {
	in := &dynamodb.ScanInput{
		TableName:        &s.Table,
		FilterExpression: strptr("begins_with(SK, :b) OR begins_with(SK, :p) OR begins_with(PK, :y)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":b": avS("BLOB#"), ":p": avS("PEND#"), ":y": avS("BYTES#"),
		},
		ConsistentRead: boolptr(true),
	}
	for {
		out, err := s.Client.Scan(ctx, in)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, raw := range out.Items {
			i := item(raw)
			if pk := i.s("PK"); strings.HasPrefix(pk, "BYTES#") {
				h, _ := hex.DecodeString(strings.TrimPrefix(pk, "BYTES#"))
				bytes = append(bytes, &ddb.BytesRow{Hash: h, File: i.s("file"), Size: int64(i.n("size")), Touched: int64(i.n("touched")), Ver: int64(i.n("ver"))})
				continue
			}
			blobs = append(blobs, scanBlob(i))
			nss = append(nss, nsOfPK(i.s("PK")))
		}
		if len(out.LastEvaluatedKey) == 0 {
			return blobs, nss, bytes, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// DeletePending deletes a pending entry of ns if it was created before
// cutoff (one renewed since stays); it reports whether it did.
func (s *Store) DeletePending(ctx context.Context, ns string, p *ddb.BlobRow, cutoff int64) (bool, error) {
	_, err := s.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.Table, Key: keyAV(keyPending(ns, p.Name, p.Bid, p.Uploader)),
		ConditionExpression:       strptr("created < :c"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":c": avI(cutoff)},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return false, nil
	}
	return err == nil, err
}

// DeleteBytes deletes the bytes with sha256 hash if they weren't touched
// at or after cutoff (an upload storing them may not have written its
// pending entry yet); it reports whether it did.
func (s *Store) DeleteBytes(ctx context.Context, hash []byte, cutoff int64) (bool, error) {
	_, err := s.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.Table, Key: keyAV(keyBytes(hash)),
		ConditionExpression:       strptr("touched < :c"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":c": avI(cutoff)},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return false, nil
	}
	return err == nil, err
}

// CollectBytes deletes the bytes among hashes that no attachment or
// pending entry names any more (gcBytes of core's SQL path), and returns
// the files of those it deleted, for the caller to remove. Whether any
// item names them is a scan: purges are rare.
func (s *Store) CollectBytes(ctx context.Context, hashes [][]byte) (files []string, err error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	blobs, _, bytes, err := s.ScanBlobs(ctx)
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	for _, b := range blobs {
		if !b.Pruned {
			named[string(b.Hash)] = true
		}
	}
	stored := map[string]*ddb.BytesRow{}
	for _, b := range bytes {
		stored[string(b.Hash)] = b
	}
	for _, h := range hashes {
		b, ok := stored[string(h)]
		if !ok || named[string(h)] {
			continue
		}
		delete(stored, string(h))
		// Only while no pending entry named them since the scan
		// (PutPending moves the version): that one keeps them.
		cond, vals := "attribute_not_exists(ver)", map[string]types.AttributeValue(nil)
		if b.Ver > 0 {
			cond, vals = "ver = :v", map[string]types.AttributeValue{":v": avI(b.Ver)}
		}
		_, err := s.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: &s.Table, Key: keyAV(keyBytes(h)), ConditionExpression: &cond, ExpressionAttributeValues: vals,
		})
		var cf *types.ConditionalCheckFailedException
		if errors.As(err, &cf) {
			continue
		}
		if err != nil {
			return files, err
		}
		if b.File != "" {
			files = append(files, b.File)
		}
	}
	return files, nil
}
