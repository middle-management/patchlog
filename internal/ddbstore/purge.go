package ddbstore

// Purges (§8.3, §8.5). What a purge decides commits in its transaction:
// a resource's RES item marked purged (on the head the checks read) and
// its head document deleted, or the namespace's #META marked purged (on
// the configuration in force); the purge entry; and a PURGING# marker.
// Every read answers 410 from those flags at once, and every later write
// is refused by them: writes condition RES items and #META on not purged.
//
// The bulk of the content — every revision's patch set and document
// metadata, attachments and pending entries — can't fit a transaction's
// 100 actions, so it goes right after the commit (PurgeContent), and the
// marker with it; one that remains (the instance stopped between) names
// a purge to finish, which the sweep does (Purging, core's SweepBlobs).
// Blob bytes no item names any more go with the blob sweep.

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ddb"
)

// keyPurging marks a purge whose content is still to go: of resource
// name, or of the whole namespace for "" (no resource is named "").
func keyPurging(ns, name string) Key { return Key{nsPK(ns), "PURGING#" + name} }

// purgeActs are a purge's actions in its commit's transaction.
func (s *Store) purgeActs(c *ddb.Commit) []types.TransactWriteItem {
	table, ns := &s.Table, c.NS
	switch {
	case c.Purge != nil && c.Purge.HeadNS != "":
		p := c.Purge
		return []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: table, Item: withKey(keyRes(ns, p.Name), item{
					"headPos": avN(p.HeadPos), "headId": avS(p.HeadID), "headNs": avS(p.HeadNS), "state": avS("purged"),
				}),
				ConditionExpression: strptr("attribute_not_exists(PK)"),
			}},
			// There is no head document here (it is the base's); the
			// delete keeps a purge's three actions.
			{Delete: &types.Delete{TableName: table, Key: keyAV(keyDocHead(ns, p.Name))}},
			{Put: &types.Put{TableName: table, Item: withKey(keyPurging(ns, p.Name), item{"name": avS(p.Name)})}},
		}
	case c.Purge != nil:
		p := c.Purge
		return []types.TransactWriteItem{
			{Update: &types.Update{
				TableName: table, Key: keyAV(keyRes(ns, p.Name)),
				// The head stays (Purged answers with it); its document's
				// metadata goes with the document.
				UpdateExpression:          strptr("SET #st = :pg REMOVE headCreated, headSize, headDigest, doc, docPos"),
				ConditionExpression:       strptr("headPos = :h AND headId = :i AND #st <> :pg"),
				ExpressionAttributeNames:  map[string]string{"#st": "state"},
				ExpressionAttributeValues: map[string]types.AttributeValue{":pg": avS("purged"), ":h": avN(p.HeadPos), ":i": avS(p.HeadID)},
			}},
			{Delete: &types.Delete{TableName: table, Key: keyAV(keyDocHead(ns, p.Name))}},
			{Put: &types.Put{TableName: table, Item: withKey(keyPurging(ns, p.Name), item{"name": avS(p.Name)})}},
		}
	case c.PurgeNS:
		return []types.TransactWriteItem{
			{Update: &types.Update{
				TableName: table, Key: keyAV(keyMeta(ns)),
				UpdateExpression:          strptr("SET purged = :one"),
				ConditionExpression:       strptr(metaCond),
				ExpressionAttributeValues: map[string]types.AttributeValue{":cp": avN(c.CfgPos), ":ci": avS(c.CfgID), ":np": avS("0"), ":one": avS("1")},
			}},
			{Put: &types.Put{TableName: table, Item: withKey(keyPurging(ns, ""), item{"name": avS("")})}},
		}
	}
	return nil
}

// PurgeContent deletes what a committed purge of name in ns ("" for the
// namespace's) left: every revision's patch set and document metadata,
// the head documents, attachments and pending entries, every resource
// of a purged namespace marked purged; then the purge's marker. It is
// idempotent: a purge interrupted is finished by calling it again.
//
// It returns the hashes of the bytes the attachments and pending entries
// it deleted named: the caller collects those nothing names any more
// (core's purge, as SQL's purgeBlobs does in the purge).
func (s *Store) PurgeContent(ctx context.Context, ns, name string) (hashes [][]byte, err error) {
	names := []string{name}
	if name == "" {
		if names, err = s.resourceNames(ctx, ns); err != nil {
			return nil, err
		}
	}
	for _, n := range names {
		if name == "" {
			// A purged namespace's resources are purged (§8.5).
			if _, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
				TableName: &s.Table, Key: keyAV(keyRes(ns, n)),
				UpdateExpression:          strptr("SET #st = :pg REMOVE headCreated, headSize, headDigest, doc, docPos"),
				ExpressionAttributeNames:  map[string]string{"#st": "state"},
				ExpressionAttributeValues: map[string]types.AttributeValue{":pg": avS("purged")},
			}); err != nil {
				return nil, err
			}
			if err := s.deleteKey(ctx, keyDocHead(ns, n)); err != nil {
				return nil, err
			}
		}
		if err := s.purgeRevisions(ctx, ns, n); err != nil {
			return nil, err
		}
	}
	// Attachments and pending entries: a resource's, or all of the
	// namespace's, pending ones of names never created included.
	for _, prefix := range []string{"BLOB#", "PEND#"} {
		if name != "" {
			prefix += name + "#"
		}
		if err := s.eachItem(ctx, ns, prefix, func(i item) error {
			if name != "" && i.s("name") != name {
				return nil // another resource whose name extends this one
			}
			hashes = append(hashes, i.b("hash"))
			return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
		}); err != nil {
			return nil, err
		}
	}
	// A pruned resource's kept documents, and a prune left to finish.
	snaps, prunes := "SNAP#", "PRUNING#"
	if name != "" {
		snaps, prunes = snaps+name+"#", prunes+name
	}
	if err := s.eachItem(ctx, ns, snaps, func(i item) error {
		if name != "" && resNameFromRev(i.s("SK")) != "SNAP#"+name {
			return nil // another resource whose name extends this one
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	}); err != nil {
		return nil, err
	}
	// Its sealed values (§E.2.2), a namespace's epoch keys too: whatever
	// survives of its sealings can no longer be opened (§8.5).
	if err := s.DeleteSealed(ctx, ns, name); err != nil {
		return nil, err
	}
	// An e2e resource's client-sealed snapshots (e2e.go).
	if err := s.deleteE2ESnapshots(ctx, ns, name, 0); err != nil {
		return nil, err
	}
	if name == "" {
		if err := s.DeleteEpochKeys(ctx, ns); err != nil {
			return nil, err
		}
	}
	// Its gestures' markers: the listing leaves purged resources out.
	if err := s.eachItem(ctx, ns, "GEST#", func(i item) error {
		if name != "" && i.s("name") != name {
			return nil
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	}); err != nil {
		return nil, err
	}
	if err := s.eachItem(ctx, ns, prunes, func(i item) error {
		if name != "" && i.s("name") != name {
			return nil
		}
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	}); err != nil {
		return nil, err
	}
	return hashes, s.deleteKey(ctx, keyPurging(ns, name))
}

// purgeRevisions strips name's revisions of their patch sets and
// document metadata.
func (s *Store) purgeRevisions(ctx context.Context, ns, name string) error {
	return s.eachItem(ctx, ns, "REV#"+name+"#", func(i item) error {
		if resNameFromRev(i.s("SK")) != name || !i.has("patches") && !i.has("size") {
			return nil
		}
		_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: &s.Table, Key: keyAV(Key{i.s("PK"), i.s("SK")}),
			UpdateExpression: strptr("REMOVE patches, size, digest"),
		})
		return err
	})
}

// Purging lists the purges whose content is still to go, as (namespace,
// resource) pairs, resource "" for a namespace's — a scan, for the sweep.
func (s *Store) Purging(ctx context.Context) (nss, names []string, err error) {
	in := &dynamodb.ScanInput{
		TableName:                 &s.Table,
		FilterExpression:          strptr("begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": avS("PURGING#")},
		ConsistentRead:            boolptr(true),
	}
	for {
		out, err := s.Client.Scan(ctx, in)
		if err != nil {
			return nil, nil, err
		}
		for _, raw := range out.Items {
			i := item(raw)
			nss = append(nss, nsOfPK(i.s("PK")))
			names = append(names, i.s("name"))
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nss, names, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// resourceNames lists ns's resources.
func (s *Store) resourceNames(ctx context.Context, ns string) ([]string, error) {
	var out []string
	err := s.eachItem(ctx, ns, "RES#", func(i item) error {
		out = append(out, resName(i.s("SK")))
		return nil
	})
	return out, err
}

// partitions are ns's partition keys: the namespace's, then each of its
// resources'.
func (s *Store) partitions(ctx context.Context, ns string) ([]string, error) {
	names, err := s.resourceNames(ctx, ns)
	if err != nil {
		return nil, err
	}
	pks := []string{nsPK(ns)}
	for _, name := range names {
		pks = append(pks, resPK(ns, name))
	}
	return pks, nil
}

// eachItem visits ns's items whose sort keys begin with prefix, in the
// partition holding them (partitionOf): a resource type without a name
// visits each resource's.
func (s *Store) eachItem(ctx context.Context, ns, prefix string, visit func(item) error) error {
	pk, every := partitionOf(ns, prefix)
	if every {
		names, err := s.resourceNames(ctx, ns)
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := s.eachInPartition(ctx, resPK(ns, name), prefix, visit); err != nil {
				return err
			}
		}
		return nil
	}
	return s.eachInPartition(ctx, pk, prefix, visit)
}

// eachInPartition visits partition pk's items whose sort keys begin with
// prefix ("": all of them).
func (s *Store) eachInPartition(ctx context.Context, pk, prefix string, visit func(item) error) error {
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(pk), ":p": avS(prefix)},
		ConsistentRead:            boolptr(true),
	}
	if prefix == "" {
		in.KeyConditionExpression = strptr("PK = :pk")
		delete(in.ExpressionAttributeValues, ":p")
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return err
		}
		for _, it := range q.Items {
			if err := visit(item(it)); err != nil {
				return err
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

func (s *Store) deleteKey(ctx context.Context, k Key) error {
	_, err := s.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.Table, Key: keyAV(k)})
	return err
}
