package ddb

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// /heads at a namespace revision (§7.4): every resource as of a log entry,
// not only as of the tip. The SQL backends resolve a name's head at an
// entry from head_history (resolve's asOf); here it is the HIST# items a
// write puts (docs/DYNAMODB.md §3, §5: "?at= is a descending HIST# query,
// limit 1"), with the one case they don't cover — a delete puts none —
// settled from the chain and, rarely, the log.

// HeadsAt pages a namespace's resources as of the log entry at, in byte
// order of name after after, at most limit (0: all), with the name to
// resume after when more follow (pageHeads of core's reads.go). Names with
// no head at the entry — created after it — are skipped, however many lie
// between two that have one: the page is filled from chunks of names, not
// from one. found is false when at is no entry of the log (the 404 of an
// unknown ns_id).
func (s *Store) HeadsAt(ctx context.Context, ns, at, after string, limit int) (page []HeadEntry, next string, found bool, err error) {
	mk, err := s.getItem(ctx, keyNSID(ns, at))
	if err != nil || mk == nil {
		return nil, "", false, err
	}
	atPos := item(mk).n("logPos")
	chunk := limit + 1
	if limit <= 0 {
		chunk = 1000
	}
	for {
		names, rows, err := s.resChunk(ctx, ns, after, chunk)
		if err != nil {
			return nil, "", false, err
		}
		heads, err := s.headsAtPos(ctx, ns, names, rows, atPos)
		if err != nil {
			return nil, "", false, err
		}
		for _, h := range heads {
			if h == nil {
				continue
			}
			if limit > 0 && len(page) == limit {
				return page, page[len(page)-1].Name, true, nil
			}
			page = append(page, *h)
		}
		if len(names) < chunk {
			return page, "", true, nil
		}
		after = names[len(names)-1]
	}
}

// resChunk reads up to k RES# items with names after after, in byte
// order (ListHeads's query, keeping the rows: headsAtPos needs their
// entry ids).
func (s *Store) resChunk(ctx context.Context, ns, after string, k int) ([]string, []*resRow, error) {
	cond := "PK = :pk AND begins_with(SK, :pfx)"
	vals := map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":pfx": avS("RES#")}
	if after != "" {
		// SK > the bound can run past RES# into REV#: the loop stops at
		// the prefix boundary.
		cond = "PK = :pk AND SK > :after"
		vals = map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":after": avS("RES#" + after)}
	}
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    &cond,
		ExpressionAttributeValues: vals,
		Limit:                     int32ptr(int32(k)),
		ConsistentRead:            boolptr(true),
	})
	if err != nil {
		return nil, nil, err
	}
	var names []string
	var rows []*resRow
	for _, it := range q.Items {
		i := item(it)
		if !strings.HasPrefix(i.s("SK"), "RES#") {
			break
		}
		names = append(names, resName(i.s("SK")))
		rows = append(rows, scanRes(i))
	}
	return names, rows, nil
}

// headsAtPos resolves each resource's head as of log position atPos (nil:
// none there). A resource whose current head was moved by an entry at or
// before atPos has it still; the entry's position is its NSID marker's,
// read in one batch for the chunk, so a page at the tip costs no more
// than its markers. Created, size and digest are the head revision's,
// created alone a tombstone's (NamespaceHeads's metadata, §7.4).
func (s *Store) headsAtPos(ctx context.Context, ns string, names []string, rows []*resRow, atPos uint64) ([]*HeadEntry, error) {
	var keys []Key
	for _, r := range rows {
		if r.headPos > 0 {
			keys = append(keys, keyNSID(ns, r.entryID))
		}
	}
	marks, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, err
	}
	out := make([]*HeadEntry, len(rows))
	var tombs []Key // current tombstones: their created
	for i, r := range rows {
		if r.headPos == 0 {
			continue
		}
		mk, ok := marks[keyNSID(ns, r.entryID)]
		if !ok {
			return nil, apiErr(500, "stored_log", "namespace", ns, "resource", names[i])
		}
		if mk.n("logPos") <= atPos {
			h := &HeadEntry{Name: names[i], ID: r.headID, Tombstoned: r.state == "tombstoned"}
			if h.Tombstoned {
				tombs = append(tombs, keyRev(ns, names[i], r.headPos))
			} else {
				h.Created, h.Size, h.Digest = r.headCreated, r.headSize, r.headDigest
			}
			out[i] = h
			continue
		}
		// Moved since atPos: the head as of it, from the history.
		h, err := s.headBefore(ctx, ns, names[i], r, atPos)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	revs, err := s.batchGet(ctx, tombs)
	if err != nil {
		return nil, err
	}
	for i, h := range out {
		if h != nil && h.Tombstoned && h.Created == 0 {
			if rv, ok := revs[keyRev(ns, names[i], rows[i].headPos)]; ok {
				h.Created = int64(rv.n("created"))
			}
		}
	}
	return out, nil
}

// headBefore is a resource's head as of log position atPos, where its
// current head (r) was moved by a later entry: the last write at or
// before atPos is its newest HIST# item there (none: the resource didn't
// exist yet), unless a delete followed it, also at or before atPos.
// Deletes put no HIST# item, but a tombstone can only follow that write
// directly in the chain, and only one: the next revision is it or a later
// write. When it is a tombstone that isn't the current head, its entry
// lies between the write's and the restore's, and whether that is at or
// before atPos takes a look at the log over (write, atPos] for it.
func (s *Store) headBefore(ctx context.Context, ns, name string, r *resRow, atPos uint64) (*HeadEntry, error) {
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.Table,
		KeyConditionExpression: strptr("PK = :pk AND SK BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(nsPK(ns)), ":lo": avS("HIST#" + name + "#"), ":hi": avS("HIST#" + name + "#" + padPos(atPos)),
		},
		ScanIndexForward: boolptr(false),
		Limit:            int32ptr(1),
		ConsistentRead:   boolptr(true),
	})
	if err != nil {
		return nil, err
	}
	if len(q.Items) == 0 {
		return nil, nil // no head at atPos
	}
	// The write's log position is the sort key's (HIST items carry
	// revPos only).
	hist := item(q.Items[0])
	revPos, sk := hist.n("revPos"), hist.s("SK")
	histPos, err := parsePos(sk[len(sk)-posDigits:])
	if err != nil {
		return nil, err
	}
	revs, err := s.batchGet(ctx, []Key{keyRev(ns, name, revPos), keyRev(ns, name, revPos+1)})
	if err != nil {
		return nil, err
	}
	live, ok := revs[keyRev(ns, name, revPos)]
	if !ok {
		return nil, apiErr(409, "conflict", "detail", "gap in the revision chain")
	}
	if next, ok := revs[keyRev(ns, name, revPos+1)]; ok && next.s("kind") == "tombstone" && revPos+1 != r.headPos {
		// A tombstone the current head isn't (that one's entry is after
		// atPos): deleted at or before atPos if its entry is.
		// A REV item that records the position of the entry that
		// committed it (logPos) answers by itself; one written before
		// it did, by the log.
		tid := next.s("id")
		deleted := next.has("logPos") && next.n("logPos") <= atPos
		if !next.has("logPos") {
			if deleted, err = s.loggedTombstone(ctx, ns, name, tid, histPos, atPos); err != nil {
				return nil, err
			}
		}
		if deleted {
			return &HeadEntry{Name: name, ID: tid, Tombstoned: true, Created: int64(next.n("created"))}, nil
		}
	}
	return &HeadEntry{
		Name: name, ID: live.s("id"),
		Created: int64(live.n("created")), Size: live.n("size"), Digest: live.b("digest"),
	}, nil
}

// loggedTombstone reports whether the log entries (from, to] hold the
// tombstone tid of name: a single delete's entry or a batch item's. The
// body filter narrows the read to entries naming the id; the parsed body
// decides, since an id names the same tombstone in twin resources.
func (s *Store) loggedTombstone(ctx context.Context, ns, name, tid string, from, to uint64) (bool, error) {
	if to <= from {
		return false, nil
	}
	in := &dynamodb.QueryInput{
		TableName:              &s.Table,
		KeyConditionExpression: strptr("PK = :pk AND SK BETWEEN :lo AND :hi"),
		FilterExpression:       strptr("contains(body, :t)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(nsPK(ns)), ":lo": avS("LOG#" + padPos(from+1)), ":hi": avS("LOG#" + padPos(to)), ":t": avS(tid),
		},
		ConsistentRead: boolptr(true),
	}
	names := func(e map[string]any) bool {
		return e["kind"] == "tombstone" && e["resource"] == name && e["target"] == tid
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return false, err
		}
		for _, it := range q.Items {
			body, err := jsonv.Parse([]byte(item(it).s("body")))
			if err != nil {
				return false, err
			}
			m, _ := body.(map[string]any)
			if names(m) {
				return true, nil
			}
			es, _ := m["entries"].([]any)
			for _, x := range es {
				if e, ok := x.(map[string]any); ok && names(e) {
					return true, nil
				}
			}
		}
		if q.LastEvaluatedKey == nil {
			return false, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// batchGet reads items by key, strongly consistent, 100 keys a request
// (BatchGetItem's bound), retrying what comes back unprocessed; absent
// keys are absent from the map. Keys may repeat (a batch's resources
// share an entry id): each is asked for once.
func (s *Store) batchGet(ctx context.Context, keys []Key) (map[Key]item, error) {
	out := map[Key]item{}
	seen := map[Key]bool{}
	var uniq []Key
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, k)
		}
	}
	for len(uniq) > 0 {
		n := min(len(uniq), 100)
		req := make([]map[string]types.AttributeValue, n)
		for i, k := range uniq[:n] {
			req[i] = keyAV(k)
		}
		uniq = uniq[n:]
		pending := map[string]types.KeysAndAttributes{s.Table: {Keys: req, ConsistentRead: boolptr(true)}}
		for len(pending) > 0 {
			res, err := s.Client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: pending})
			if err != nil {
				return nil, err
			}
			for _, it := range res.Responses[s.Table] {
				i := item(it)
				out[Key{i.s("PK"), i.s("SK")}] = i
			}
			pending = res.UnprocessedKeys
		}
	}
	return out, nil
}
