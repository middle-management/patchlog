package ddbstore

// Remote branches (§G.3), the branch side. A remote branch is a local
// branch of a hidden shadow namespace, "~" + its name, which mirrors the
// base's chain up to at with identical ids; a base that is itself a
// branch gets a shadow per level, each a branch of the next (core's
// remote_branch.go). Reads are a local branch's.
//
// A shadow's content is unbounded, so it can't be one transaction: it is
// imported first (ImportShadow, batched puts into a partition nobody reads
// yet — no branch reads through it), each import stamping its #META with
// a token, and the remote branch is then created in one transaction
// (CreateRemoteBranch) that checks every shadow's token: an import that
// raced it and overwrote a shadow makes it fail. An import first deletes
// whatever an earlier, failed one left. The branch's #REMOTE item records
// its base (origin, ns, at) and how far its log was followed (checkpoint,
// remote.go's following).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// ClearShadow deletes whatever an earlier, failed import of a shadow
// left, before the next import (whose data keys it must not take).
func (s *Store) ClearShadow(ctx context.Context, name string) error {
	return s.deletePartition(ctx, name)
}

// ImportShadow writes a shadow's content, into a partition ClearShadow
// cleared, and returns its token.
func (s *Store) ImportShadow(ctx context.Context, im *ddb.ShadowImport) (string, error) {
	tok := make([]byte, 16)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	ns := im.Name
	var puts []map[string]types.AttributeValue
	put := func(k Key, it item) { puts = append(puts, withKey(k, it)) }

	meta := &nsMeta{configPos: 1, configID: im.CfgID}
	if im.Base != "" {
		meta.base, meta.baseAt, meta.baseCfgPos = im.Base, im.BaseAt, 1
	}
	mi := meta.item()
	mi["importToken"] = avS(token)
	put(keyMeta(ns), mi)
	put(keyCfg(ns, 1), item{
		"pos": avN(1), "id": avS(im.CfgID), "logPos": avN(1), "patches": avS(im.CfgPatches), "doc": avS(im.CfgDoc),
		"author": avS(im.Author), "created": avI(im.Created), "G1PK": avS(g1RevID(im.CfgID)),
	})
	for i, e := range im.Log {
		l := logRow{pos: uint64(i + 1), id: e.ID, kind: e.Kind, body: e.Body, author: e.Author, created: e.Created, cfgPos: 1, via: e.Via}
		if i > 0 {
			l.prevPos = uint64(i)
		}
		put(keyLog(ns, l.pos), l.item())
		put(keyNSID(ns, e.ID), item{"ns": avS(ns), "logPos": avN(l.pos)})
	}
	if n := len(im.Log); n > 0 {
		put(keyTip(ns), (&tip{headPos: uint64(n), headID: im.Log[n-1].ID}).item())
	}
	for _, r := range im.Res {
		s.shadowRes(ns, im, &r, put)
	}
	for _, k := range im.Epochs {
		put(keyEpochKey(ns, k.Epoch), epochKeyItem(&k, k.Created))
	}
	put(keyNSList(ns), item{})
	return token, s.putAll(ctx, puts)
}

func (s *Store) shadowRes(ns string, im *ddb.ShadowImport, r *ddb.ShadowRes, put func(Key, item)) {
	entryID, entryPos := "", uint64(0)
	if r.EntryIdx >= 0 && r.EntryIdx < len(im.Log) {
		entryID, entryPos = im.Log[r.EntryIdx].ID, uint64(r.EntryIdx+1)
	}
	head := uint64(len(r.Revs))
	last := r.Revs[head-1]
	for i, v := range r.Revs {
		pos := uint64(i + 1)
		rr := revRow{pos: pos, id: v.ID, kind: v.Kind, parentID: v.ParentID, patches: v.Patches, author: v.Author, created: v.Created,
			size: v.Size, digest: v.Digest, gesture: v.Gesture, undoes: v.Undoes, schemaRef: v.SchemaRef, signature: v.Signature, declared: strings.Join(v.Declared, ","), via: v.Via, legacy: v.Legacy}
		if pos == 1 && r.ParentNS != "" {
			rr.parentNS, rr.parentPos = r.ParentNS, r.ParentPos
		}
		if pos == head {
			rr.logPos = entryPos
		}
		it := rr.item()
		if v.Kind != "tombstone" && v.Patches == "" {
			delete(it, "patches") // the horizon, or purged at the base
		}
		if r.Purged {
			delete(it, "size")
			delete(it, "digest")
		}
		put(keyRev(ns, r.Name, pos), it)
	}
	res := item{"headPos": avN(head), "headId": avS(last.ID), "entryId": avS(entryID)}
	switch {
	case r.Purged:
		res["state"] = avS("purged")
	case last.Kind == "tombstone":
		res["state"] = avS("tombstoned")
		if r.LastLivePos > 0 {
			res["lastPos"], res["lastId"] = avN(r.LastLivePos), avS(r.Revs[r.LastLivePos-1].ID)
		}
	default:
		res["state"] = avS("live")
		res["headCreated"] = avI(last.Created)
		if len(last.Digest) > 0 { // none for e2e content
			res["headSize"], res["headDigest"] = avN(last.Size), avB(last.Digest)
		}
		if entryPos > 0 {
			put(keyHist(ns, r.Name, entryPos), item{"revPos": avN(head)})
		}
	}
	if r.HorizonPos > 0 {
		res["horizonPos"], res["horizonId"], res["horizonBase"] = avN(r.HorizonPos), avS(r.Revs[r.HorizonPos-1].ID), avN(r.HorizonPos)
		res["keep"], res["kept"] = avS("[]"), avNs([]uint64{r.HorizonPos})
		put(keySnap(ns, r.Name, r.HorizonPos), item{"pos": avN(r.HorizonPos), "doc": avS(r.HorizonDoc)})
	}
	put(keyRes(ns, r.Name), res)
	if r.HeadDoc != "" {
		put(keyDocHead(ns, r.Name), item{"revPos": avN(r.LastLivePos), "doc": avS(r.HeadDoc)})
	}
	for _, b := range r.Attach {
		row := &ddb.BlobRow{Name: r.Name, Bid: b.Bid, Type: b.Type, Nonce: b.Nonce, Size: b.Size, Hash: b.Hash, Owner: b.Owner, Created: im.Created, RefPos: b.RefPos}
		put(keyBlob(ns, r.Name, b.Bid), blobItem(row))
	}
}

// putAll writes items in batches, retrying what DynamoDB leaves
// unprocessed.
func (s *Store) putAll(ctx context.Context, items []map[string]types.AttributeValue) error {
	for len(items) > 0 {
		n := min(25, len(items))
		reqs := make([]types.WriteRequest, n)
		for i, it := range items[:n] {
			reqs[i] = types.WriteRequest{PutRequest: &types.PutRequest{Item: it}}
		}
		items = items[n:]
		for attempt := 0; len(reqs) > 0; attempt++ {
			out, err := s.Client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: map[string][]types.WriteRequest{s.Table: reqs}})
			if err != nil {
				return err
			}
			reqs = out.UnprocessedItems[s.Table]
			if len(reqs) > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Duration(1<<min(attempt, 6)) * 10 * time.Millisecond):
				}
			}
		}
	}
	return nil
}

// deletePartition deletes every item of ns's partitions, its resources'
// with its own, and its entry in the namespace list.
func (s *Store) deletePartition(ctx context.Context, ns string) error {
	pks, err := s.partitions(ctx, ns)
	if err != nil {
		return err
	}
	var keys []Key
	for _, pk := range pks {
		if err := s.eachInPartition(ctx, pk, "", func(i item) error {
			keys = append(keys, Key{i.s("PK"), i.s("SK")})
			return nil
		}); err != nil {
			return err
		}
	}
	for _, k := range keys {
		if err := s.deleteKey(ctx, k); err != nil {
			return err
		}
	}
	return s.deleteKey(ctx, keyNSList(ns))
}

// CreateRemoteBranch creates a remote branch over its imported shadows;
// 412 if the name is taken, ErrStale if a shadow isn't the import the
// caller made.
func (s *Store) CreateRemoteBranch(ctx context.Context, c *ddb.RemoteBranchCreate) (cfgID, nsID string, err error) {
	cfg := ids.Revision(nil, []byte(c.Patches))
	body := jsonv.Canonical(map[string]any{"kind": "config", "target": cfg.String()})
	entryID := ids.Hash(nil, body)
	now := s.now().UnixMilli()
	entry := logRow{pos: 1, id: entryID.String(), kind: "config", body: string(body), author: c.Author, created: now, cfgPos: 1,
		grantID: c.Grant, noAuth: c.NoAuth, via: c.Via}
	meta := &nsMeta{frozen: c.Frozen, configPos: 1, configID: cfg.String(), base: c.Shadow, baseAt: c.AtPos, baseCfgPos: 1}
	acts := buildCreateTx(s.Table, c.NS, meta, cfg.String(), c.Patches, c.Doc, entry)
	acts = append(acts, deployFirst(s.Table, now),
		types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(keyNSList(c.NS), item{})}},
		types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(keyRemoteList(c.NS), item{})}},
		types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(keyRemote(c.NS), item{
			"shadow": avS(c.Shadow), "origin": avS(c.Origin), "ns": avS(c.BaseNS), "at": avS(c.At), "checkpoint": avS(c.At),
		})}},
	)
	names := make([]string, 0, len(c.Tokens))
	for name := range c.Tokens {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		acts = append(acts, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName: &s.Table, Key: keyAV(keyMeta(name)),
			ConditionExpression:       strptr("importToken = :t"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":t": avS(c.Tokens[name])},
		}})
	}
	if c.Grant != "" {
		acts = append(acts, grantMark(s.Table, c.NS, c.Grant, 1))
	}
	_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: acts})
	var ce *types.TransactionCanceledException
	if errors.As(err, &ce) {
		if r := ce.CancellationReasons; len(r) > 0 && r[0].Code != nil && *r[0].Code == "ConditionalCheckFailed" {
			return "", "", apiErr(412, "stale")
		}
		return "", "", ddb.ErrStale
	}
	if err != nil {
		return "", "", err
	}
	return cfg.String(), entryID.String(), nil
}

func keyRemote(ns string) Key { return Key{nsPK(ns), "#REMOTE"} }

// RemoteBaseOf reads branch's base; nil if it isn't a remote branch.
func (s *Store) RemoteBaseOf(ctx context.Context, branch string) (*ddb.RemoteBase, error) {
	it, err := s.getItem(ctx, keyRemote(branch))
	if it == nil || err != nil {
		return nil, err
	}
	i := item(it)
	return &ddb.RemoteBase{Branch: branch, Shadow: i.s("shadow"), Origin: i.s("origin"), NS: i.s("ns"), At: i.s("at"),
		Checkpoint: i.s("checkpoint"), RegNSID: i.s("regNsId"), RegExpires: int64(i.n("regExpires"))}, nil
}

// keyRemoteList lists the remote branches, one item each (RemoteBases).
func keyRemoteList(ns string) Key { return Key{"#REMOTES", ns} }

// RemoteBases lists every remote branch's base, by branch name.
func (s *Store) RemoteBases(ctx context.Context) ([]*ddb.RemoteBase, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS("#REMOTES")},
		ConsistentRead:            boolptr(true),
	}
	var out []*ddb.RemoteBase
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			rb, err := s.RemoteBaseOf(ctx, item(it).s("SK"))
			if err != nil {
				return nil, err
			}
			if rb != nil {
				out = append(out, rb)
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// SetCheckpoint moves branch's checkpoint from old to cp; ErrStale if
// another follow moved it first.
func (s *Store) SetCheckpoint(ctx context.Context, branch, old, cp string) error {
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyRemote(branch)),
		UpdateExpression:          strptr("SET checkpoint = :n"),
		ConditionExpression:       strptr("checkpoint = :o"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":n": avS(cp), ":o": avS(old)},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return ddb.ErrStale
	}
	return err
}

// SetRegistration records branch's registration at its base: the
// registration's latest entry there and when it expires.
func (s *Store) SetRegistration(ctx context.Context, branch, nsID string, expires int64) error {
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyRemote(branch)),
		UpdateExpression:          strptr("SET regNsId = :i, regExpires = :e"),
		ConditionExpression:       strptr("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":i": avS(nsID), ":e": avI(expires)},
	})
	return err
}

// PutNotice records a notice, unless one of its id is recorded already.
func (s *Store) PutNotice(ctx context.Context, branch string, n ddb.Notice) error {
	applied := "0"
	if n.Applied {
		applied = "1"
	}
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.Table,
		Item: withKey(Key{nsPK(branch), "NOTICE#" + n.ID}, item{
			"id": avS(n.ID), "kind": avS(n.Kind), "resource": avS(n.Resource), "applied": avS(applied), "created": avI(n.Created), "seq": avN(n.Seq),
		}),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return nil
	}
	return err
}

// Notices lists branch's notices in the order they were recorded.
func (s *Store) Notices(ctx context.Context, branch string) ([]ddb.Notice, error) {
	var out []ddb.Notice
	err := s.eachItem(ctx, branch, "NOTICE#", func(i item) error {
		out = append(out, ddb.Notice{ID: i.s("id"), Kind: i.s("kind"), Resource: i.s("resource"), Applied: i.s("applied") == "1",
			Created: int64(i.n("created")), Seq: i.n("seq")})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, err
}

// PurgeShadow removes name's content from a shadow, without an entry (its
// chain mirrors the base's), or, for name "", all of the shadow's
// (core's purgeShadow and purgeShadowNS). It returns the hashes of the
// bytes its attachments named, for the caller to collect.
func (s *Store) PurgeShadow(ctx context.Context, shadow, name string) ([][]byte, error) {
	if name == "" {
		if _, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: &s.Table, Key: keyAV(keyMeta(shadow)),
			UpdateExpression:          strptr("SET purged = :one"),
			ConditionExpression:       strptr("attribute_exists(PK)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": avS("1")},
		}); err != nil {
			var cf *types.ConditionalCheckFailedException
			if errors.As(err, &cf) {
				return nil, nil
			}
			return nil, err
		}
		return s.PurgeContent(ctx, shadow, "")
	}
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: keyAV(keyRes(shadow, name)),
		UpdateExpression:          strptr("SET #st = :pg REMOVE headCreated, headSize, headDigest, keep, kept, horizonPos, horizonId, horizonBase"),
		ConditionExpression:       strptr("attribute_exists(PK)"),
		ExpressionAttributeNames:  map[string]string{"#st": "state"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pg": avS("purged")},
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return nil, nil // nothing of it here
	}
	if err != nil {
		return nil, err
	}
	if err := s.deleteKey(ctx, keyDocHead(shadow, name)); err != nil {
		return nil, err
	}
	return s.PurgeContent(ctx, shadow, name)
}

// ResourceNamesOf lists every resource name of ns, purged ones included.
func (s *Store) ResourceNamesOf(ctx context.Context, ns string) ([]string, error) {
	return s.resourceNames(ctx, ns)
}
