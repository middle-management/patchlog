package ddb

// Archives (§8.6, §D.4). A prune that archives writes the archive first
// (core's Archiver, outside the table), then records it in its commit:
// an ARCH#<name>#<fromPos>#<toPos> item with the archive's key and URL,
// the range it holds and the blobs its blob lines carry — what a pruned
// revision's or blob's 410 names (ArchiveFor, BlobArchive). A purge
// deletes the archives and their records. Restoring one (core's
// RestoreResource) puts patch sets back (RestorePatches); once none is
// missing below the horizon, the horizon goes (ClearHorizon) and the
// attachments pruning ended come back from the blob lines
// (RestoreAttachment).

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func keyArch(ns, name string, from, to uint64) Key {
	return Key{nsPK(ns), "ARCH#" + name + "#" + padPos(from) + "#" + padPos(to)}
}

// ArchiveRow is an archive of a resource's range [FromPos, ToPos].
type ArchiveRow struct {
	Name           string
	FromPos, ToPos uint64
	Key, URL       string
	Created        int64
	Bids           []string // the blobs its blob lines carry
}

func (a *ArchiveRow) item(name string) item {
	bids := make([]types.AttributeValue, len(a.Bids))
	for i, b := range a.Bids {
		bids[i] = avS(b)
	}
	return item{
		"name": avS(name), "fromPos": avN(a.FromPos), "toPos": avN(a.ToPos),
		"key": avS(a.Key), "url": avS(a.URL), "created": avI(a.Created),
		"bids": &types.AttributeValueMemberL{Value: bids},
	}
}

func scanArchive(i item) *ArchiveRow {
	a := &ArchiveRow{Name: i.s("name"), FromPos: i.n("fromPos"), ToPos: i.n("toPos"), Key: i.s("key"), URL: i.s("url"), Created: int64(i.n("created"))}
	if l, ok := i["bids"].(*types.AttributeValueMemberL); ok {
		for _, v := range l.Value {
			a.Bids = append(a.Bids, item{"b": v}.s("b"))
		}
	}
	return a
}

// Archives lists the archives of name in ns ("" for all of ns's), by
// name, then range.
func (s *Store) Archives(ctx context.Context, ns, name string) ([]*ArchiveRow, error) {
	prefix := "ARCH#"
	if name != "" {
		prefix += name + "#"
	}
	var out []*ArchiveRow
	err := s.eachItem(ctx, ns, prefix, func(i item) error {
		if a := scanArchive(i); name == "" || a.Name == name {
			out = append(out, a)
		}
		return nil
	})
	return out, err
}

// ArchiveFor is the URL of the newest archive of name holding position
// pos, "" for none.
func (s *Store) ArchiveFor(ctx context.Context, ns, name string, pos uint64) (string, error) {
	return s.newestArchive(ctx, ns, name, func(a *ArchiveRow) bool { return a.FromPos <= pos && pos <= a.ToPos })
}

// BlobArchive is the URL of the newest archive of name whose blob lines
// carry bid, "" for none.
func (s *Store) BlobArchive(ctx context.Context, ns, name, bid string) (string, error) {
	return s.newestArchive(ctx, ns, name, func(a *ArchiveRow) bool {
		for _, b := range a.Bids {
			if b == bid {
				return true
			}
		}
		return false
	})
}

func (s *Store) newestArchive(ctx context.Context, ns, name string, match func(*ArchiveRow) bool) (string, error) {
	as, err := s.Archives(ctx, ns, name)
	if err != nil {
		return "", err
	}
	var best *ArchiveRow
	for _, a := range as {
		if match(a) && (best == nil || a.Created >= best.Created) {
			best = a
		}
	}
	if best == nil {
		return "", nil
	}
	return best.URL, nil
}

// DeleteArchive deletes an archive's record.
func (s *Store) DeleteArchive(ctx context.Context, ns string, a *ArchiveRow) error {
	return s.deleteKey(ctx, keyArch(ns, a.Name, a.FromPos, a.ToPos))
}

// GrantFirstPos is the position of ns's first entry that records grant
// gid (its marker's), 0 for none.
func (s *Store) GrantFirstPos(ctx context.Context, ns, gid string) (uint64, error) {
	it, err := s.getItem(ctx, keyNSGrant(ns, gid))
	if it == nil || err != nil {
		return 0, err
	}
	return item(it).n("firstPos"), nil
}

// ConfigAtTime is the position of ns's configuration in force at created
// (milliseconds): the newest created at or before it, 0 for none.
func (s *Store) ConfigAtTime(ctx context.Context, ns string, created int64) (uint64, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":p": avS("CFG#")},
		ScanIndexForward:          boolptr(false),
		ConsistentRead:            boolptr(true),
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return 0, err
		}
		for _, it := range q.Items {
			if i := item(it); int64(i.n("created")) <= created {
				return i.n("pos"), nil
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return 0, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// EachDocIn visits name's documents at positions from up to to, oldest
// first, each live revision's with its position: an archive's range, the
// first of them read as DocAt reads it (from a horizon's snapshot, say).
func (s *Store) EachDocIn(ctx context.Context, ns, name string, from, to uint64, visit func(pos uint64, doc any) error) error {
	var start any
	var exists bool
	walkFrom := uint64(0)
	// The first read as DocAt does: a branch's first revision applies
	// to its parent's document.
	if from >= 1 {
		r, err := s.RevAt(ctx, ns, name, from)
		if err != nil {
			return err
		}
		b, err := s.DocAt(ctx, ns, name, from)
		if err != nil {
			return err
		}
		if start, err = jsonv.Parse(b); err != nil {
			return err
		}
		exists, walkFrom = true, from
		if r != nil && r.Kind != "tombstone" {
			if err := visit(from, start); err != nil {
				return err
			}
		}
	}
	_, err := s.walkChain(ctx, ns, name, walkFrom, to, start, exists, func(pos uint64, d any, exists bool, patches string) (any, error) {
		p, err := jsonv.Parse([]byte(patches))
		if err != nil {
			return nil, err
		}
		// A genesis applies to the document null, as its create did (§6.2 step 3).
		out, _, err := applyPatches(d, true, p)
		if err != nil {
			return nil, err
		}
		return out, visit(pos, out)
	})
	return err
}

// RestorePatches puts an archived patch set back on name's revision at
// pos, if it has none; it reports whether it did.
func (s *Store) RestorePatches(ctx context.Context, ns, name string, pos uint64, patches string) (bool, error) {
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyRev(ns, name, pos)),
		UpdateExpression:          strptr("SET patches = :p"),
		ConditionExpression:       strptr("attribute_exists(PK) AND attribute_not_exists(patches)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": avS(patches)},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return false, nil
	}
	return err == nil, err
}

// PatchesMissing reports whether a revision of name below position below
// has no patch set.
func (s *Store) PatchesMissing(ctx context.Context, ns, name string, below uint64) (bool, error) {
	missing := false
	if below < 2 {
		return false, nil
	}
	err := s.rangeOf(ctx, ns, "REV#"+name+"#", 0, below-1, 0, func(i item) bool {
		if i.s("kind") != "tombstone" && !i.has("patches") {
			missing = true
			return false
		}
		return true
	})
	return missing, err
}

// ClearHorizon removes name's pruning horizon at horizonPos, every patch
// set below it being back (ErrStale if the horizon moved), then the
// snapshots it kept, which reads no longer use.
func (s *Store) ClearHorizon(ctx context.Context, ns, name string, horizonPos uint64) error {
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyRes(ns, name)),
		UpdateExpression:          strptr("REMOVE horizonPos, horizonId, horizonBase, keep, kept"),
		ConditionExpression:       strptr("horizonPos = :h"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":h": avN(horizonPos)},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return ErrStale
	}
	if err != nil {
		return err
	}
	return s.eachItem(ctx, ns, "SNAP#"+name+"#", func(i item) error {
		if resNameFromRev(i.s("SK")) != "SNAP#"+name {
			return nil
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}

// RestoreAttachment brings back an attachment pruning ended, its bytes
// stored again under hash, encrypted by owner's key ("" for none).
func (s *Store) RestoreAttachment(ctx context.Context, ns, name, bid string, hash []byte, owner string) error {
	upd, vals := "SET #h = :h REMOVE pruned, #o", map[string]types.AttributeValue{":h": avB(hash)}
	if owner != "" {
		upd = "SET #h = :h, #o = :o REMOVE pruned"
		vals[":o"] = avS(owner)
	}
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyBlob(ns, name, bid)),
		UpdateExpression:          &upd,
		ConditionExpression:       strptr("attribute_exists(PK)"),
		ExpressionAttributeNames:  map[string]string{"#h": "hash", "#o": "owner"},
		ExpressionAttributeValues: vals,
	})
	return err
}
