package ddb

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// The serving reads beyond the spike's head and log: revision-by-id,
// folds, resource logs, namespace info.

// RevInfo is a revision found by id (GSI1): where it lives and what the
// serving paths need of it. Kind "tombstone" answers 410s (§8.1).
type RevInfo struct {
	Name     string
	Pos      uint64
	Kind     string // "": a revision; "tombstone"
	ParentID string
	Patches  string
	Author   string
	Created  int64
	Size     uint64
	Digest   []byte
}

// ReadRevByID finds a revision of a namespace by its id (the revisions_by_id
// index of D.2, as GSI1). Ids are unique per resource, not globally, so the
// GSI answer is filtered by namespace; absent is nil, not an error.
func (s *Store) ReadRevByID(ctx context.Context, ns, id string) (*RevInfo, error) {
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &s.Table,
		IndexName:                 strptr(gsiName),
		KeyConditionExpression:    strptr("G1PK = :g"),
		FilterExpression:          strptr("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":g": avS(g1RevID(id)), ":pk": avS(nsPK(ns))},
	})
	if err != nil {
		return nil, err
	}
	for _, it := range q.Items {
		i := item(it)
		return &RevInfo{
			Name:     resNameFromRev(i.s("SK")),
			Pos:      i.n("pos"),
			Kind:     i.s("kind"),
			ParentID: i.s("parentId"),
			Patches:  i.s("patches"),
			Author:   i.s("author"),
			Created:  int64(i.n("created")),
			Size:     i.n("size"),
			Digest:   i.b("digest"),
		}, nil
	}
	return nil, nil
}

// resNameFromRev is the resource name of a REV# sort key.
func resNameFromRev(sk string) string {
	rest := strings.TrimPrefix(sk, "REV#")
	if i := strings.LastIndex(rest, "#"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// FoldResource folds a resource's chain from the genesis up to and
// including position toPos (0: the head), applying each revision's patch
// set with the production engine. One ordered query; the §5 audit turns a
// gap into an error, never a partial document.
func (s *Store) FoldResource(ctx context.Context, ns, name string, toPos uint64) (doc any, canon []byte, err error) {
	doc, err = s.walkChain(ctx, ns, name, toPos, func(d any, exists bool, patches string) (any, error) {
		p, err := jsonv.Parse([]byte(patches))
		if err != nil {
			return nil, err
		}
		out, _, err := applyPatches(d, exists, p)
		return out, err
	})
	if err != nil {
		return nil, nil, err
	}
	return doc, jsonv.Canonical(doc), nil
}

// walkChain applies each revision's patches in order, from genesis to
// toPos (0: all). exists tracks whether the document exists — a JSON null
// document exists, a tombstoned one does not.
func (s *Store) walkChain(ctx context.Context, ns, name string, toPos uint64, apply func(doc any, exists bool, patches string) (any, error)) (any, error) {
	hi := "REV#" + name + "#" + padPos(toPos)
	if toPos == 0 {
		hi = "REV#" + name + "#" + padPos(999999999999)
	}
	q, err := s.Client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk AND SK BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":lo": avS("REV#" + name + "#"), ":hi": avS(hi)},
	})
	if err != nil {
		return nil, err
	}
	var doc any
	exists := false
	var last uint64
	for _, it := range q.Items {
		i := item(it)
		pos := i.n("pos")
		if pos != last+1 {
			// A missing revision mid-chain: a lost race with a purge, or
			// corruption (docs/DYNAMODB.md §5). Never serve a partial fold.
			return nil, apiErr(409, "conflict", "detail", "gap in the revision chain")
		}
		last = pos
		if i.s("kind") == "tombstone" {
			// The chain crosses a delete: the document dies with it, and
			// the next revision (a restore) root-replaces from nothing.
			doc, exists = nil, false
			continue
		}
		doc, err = apply(doc, exists, i.s("patches"))
		if err != nil {
			return nil, err
		}
		exists = true
	}
	return doc, nil
}

// ResLogEntry is one entry of a resource's log (§7.1): a revision or a
// tombstone, served with its parent and metadata. Kind is "head" or
// "tombstone"; a tombstone has no Patches.
type ResLogEntry struct {
	Pos      uint64
	ID       string
	Kind     string
	ParentID string
	Patches  any
	Author   string
	Created  int64
	Gesture  string
	Undoes   string
}

// ResourceLogEntries reads a resource's revisions in chain order, from
// after position from (0: the start), at most limit (0: all). It is the
// resource log of §7.1 and the fold source for /rev reads.
func (s *Store) ResourceLogEntries(ctx context.Context, ns, name string, from uint64, limit int) ([]ResLogEntry, error) {
	cond := "PK = :pk AND SK > :lo"
	vals := map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":lo": avS("REV#" + name + "#" + padPos(from))}
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    &cond,
		ExpressionAttributeValues: vals,
	}
	if limit > 0 {
		in.Limit = int32ptr(int32(limit + 1))
	}
	q, err := s.Client.Query(ctx, in)
	if err != nil {
		return nil, err
	}
	var out []ResLogEntry
	for _, it := range q.Items {
		i := item(it)
		if !strings.HasPrefix(i.s("SK"), "REV#"+name+"#") {
			break
		}
		if limit > 0 && len(out) == limit {
			break
		}
		re := ResLogEntry{
			Pos:      i.n("pos"),
			ID:       i.s("id"),
			Kind:     "head",
			ParentID: i.s("parentId"),
			Author:   i.s("author"),
			Created:  int64(i.n("created")),
			Gesture:  i.s("gesture"),
			Undoes:   i.s("undoes"),
		}
		if i.s("kind") == "tombstone" {
			re.Kind = "tombstone"
		} else {
			re.Patches, _ = jsonv.Parse([]byte(i.s("patches")))
		}
		out = append(out, re)
	}
	return out, nil
}

// RevPos resolves a revision id of a resource to its chain position
// (0: not an ancestor).
func (s *Store) RevPos(ctx context.Context, ns, name, id string) (uint64, error) {
	rev, err := s.ReadRevByID(ctx, ns, id)
	if err != nil || rev == nil {
		return 0, err
	}
	if rev.Name != name {
		return 0, nil
	}
	return rev.Pos, nil
}

// NSInfo is a namespace's serving state: the log tip and the
// configuration, for GET /ns/{ns} and the read paths' guards.
type NSInfo struct {
	Exists   bool
	Frozen   bool
	Purged   bool
	HeadID   string
	ConfigID string
	Doc      any
}

// ReadNSInfo reads a namespace's meta, tip and configuration document
// (one batch read).
func (s *Store) ReadNSInfo(ctx context.Context, ns string) (*NSInfo, error) {
	m, err := s.getMeta(ctx, ns)
	if err != nil || m == nil {
		return &NSInfo{}, err
	}
	t, err := s.getTip(ctx, ns)
	if err != nil {
		return nil, err
	}
	_, doc, err := s.readConfigState(ctx, ns)
	if err != nil {
		return nil, err
	}
	out := &NSInfo{Exists: true, Frozen: m.frozen, Purged: m.purged, ConfigID: m.configID, Doc: doc}
	if t != nil {
		out.HeadID = t.headID
	}
	return out, nil
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

// ReadDocAtEntry serves the namespace document in force at a log entry
// (NamespaceRev's /ns/{ns}/rev/{id}: the SQL's ns_log JOIN ns_config on
// config_seq): the entry's NSID marker gives its position, the entry its
// cfgPos, the CFG item the document and configuration id. An unknown id
// is a 404.
func (s *Store) ReadDocAtEntry(ctx context.Context, ns, id string) (doc any, cfgID string, err error) {
	mk, err := s.getItem(ctx, keyNSID(ns, id))
	if err != nil {
		return nil, "", err
	}
	if mk == nil {
		return nil, "", apiErr(404, "not_found", "ns_id", id)
	}
	le, err := s.getItem(ctx, keyLog(ns, item(mk).n("logPos")))
	if err != nil {
		return nil, "", err
	}
	if le == nil {
		return nil, "", apiErr(500, "stored_log", "namespace", ns)
	}
	cfg, err := s.getItem(ctx, keyCfg(ns, item(le).n("cfgPos")))
	if err != nil {
		return nil, "", err
	}
	if cfg == nil {
		return nil, "", apiErr(500, "stored_config", "namespace", ns)
	}
	doc, err = jsonv.Parse([]byte(item(cfg).s("doc")))
	if err != nil {
		return nil, "", err
	}
	return doc, item(cfg).s("id"), nil
}

// KnownEntry reports whether id names an entry of the namespace's log
// (NamespaceHeads's ns_id check, §8.5: heads at an entry, not after one).
func (s *Store) KnownEntry(ctx context.Context, ns, id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	mk, err := s.getItem(ctx, keyNSID(ns, id))
	if err != nil || mk != nil {
		return mk != nil, err
	}
	return false, nil
}
