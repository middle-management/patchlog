package ddb

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

// API is the DynamoDB surface the spike uses. *dynamodb.Client satisfies
// it; tests may fake it.
type API interface {
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opt ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, opt ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opt ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opt ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, opt ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Scan(ctx context.Context, in *dynamodb.ScanInput, opt ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opt ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opt ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, opt ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Store is the spike's storage backend: one DynamoDB table, the key design
// of keys.go.
type Store struct {
	Client API
	Table  string
	Now    func() time.Time // nil: time.Now
	// GroupCommit is at most how many checked writes of a namespace one
	// transaction appends (group.go); ≤ 1 commits each write on its own.
	GroupCommit int

	g groups
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Create is a namespace's creation, as core's checks decided it. Patches
// is the decoded JSON Patch set producing the namespace document.
type Create struct {
	NS, Author      string
	Patches         any
	Gesture, Undoes string
	// Grant and NoAuth are Commit's.
	Grant  string
	NoAuth bool
}

// CreateNamespace bootstraps a namespace with its config genesis and first
// log entry (insertNamespace of nsops.go).

func (s *Store) CreateNamespace(ctx context.Context, c *Create) (cfgID, nsID string, err error) {
	ns, author, patches := c.NS, c.Author, c.Patches
	doc, _, err := applyPatches(nil, false, patches)
	if err != nil {
		return "", "", patchErr(err)
	}
	canon := jsonv.Canonical(patches)
	cfg := ids.Revision(nil, canon)
	body := jsonv.Canonical(map[string]any{"kind": "config", "target": cfg.String()})
	entryID := ids.Hash(nil, body)
	now := s.now().UnixMilli()
	entry := logRow{pos: 1, id: entryID.String(), kind: "config", body: string(body), author: author, created: now, cfgPos: 1,
		grantID: c.Grant, noAuth: c.NoAuth, gesture: c.Gesture, undoes: c.Undoes}
	meta := &nsMeta{configPos: 1, configID: cfg.String()}

	// buildCreateTx's action order: 0 #META, 1 CFG, 2 LOG, 3 #TIP, 4 NSID;
	// then the deployment's first entry time and the grant's marker.
	acts := buildCreateTx(s.Table, ns, meta, cfg.String(), string(canon), string(jsonv.Canonical(doc)), entry)
	acts = append(acts, deployFirst(s.Table, now))
	if c.Grant != "" {
		acts = append(acts, grantMark(s.Table, ns, c.Grant, 1))
	}
	_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: acts})
	if err != nil {
		var ce *types.TransactionCanceledException
		if errors.As(err, &ce) && len(ce.CancellationReasons) > 0 {
			// A retried create finds its own marker (the marker's id
			// covers the config id, so it is this very request); an
			// existing namespace answers 412 with its config id
			// (writeConfig's IfNoneMatch path).
			if ce.CancellationReasons[4].Code != nil && *ce.CancellationReasons[4].Code == "ConditionalCheckFailed" {
				return cfg.String(), entryID.String(), nil
			}
			if ce.CancellationReasons[0].Code != nil && *ce.CancellationReasons[0].Code == "ConditionalCheckFailed" {
				cur, gerr := s.getMeta(ctx, ns)
				if gerr == nil && cur != nil {
					return "", "", apiErr(412, "stale", "config", cur.configID)
				}
				return "", "", apiErr(412, "stale")
			}
		}
		return "", "", err
	}
	return cfg.String(), entryID.String(), nil
}

// HeadInfo is a resource's head answer: the document and id of a live
// head, or a tombstone's id and last live revision (§8.1).
type HeadInfo struct {
	Doc     any // nil for a tombstone (its document is gone)
	ID      string
	Live    bool
	LastID  string
	LastPos uint64
}

// ReadHead serves a resource's head (GET /r/{ns}/{name}): one batch read
// of the resource and its head document; nil when the resource is absent.
// Not a snapshot (docs/DYNAMODB.md §5), which is benign here — the head
// document is immutable per revision.
func (s *Store) ReadHead(ctx context.Context, ns, name string) (*HeadInfo, error) {
	out, err := s.Client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			s.Table: {Keys: []map[string]types.AttributeValue{keyAV(keyRes(ns, name)), keyAV(keyDocHead(ns, name))}, ConsistentRead: boolptr(true)},
		},
	})
	if err != nil {
		return nil, err
	}
	var res *resRow
	var doc any
	for _, it := range out.Responses[s.Table] {
		i := item(it)
		switch {
		case i.s("SK") == "RES#"+name:
			res = scanRes(i)
		case i.s("SK") == "DOC#"+name+"#HEAD":
			doc, err = jsonv.Parse([]byte(i.s("doc")))
			if err != nil {
				return nil, err
			}
		}
	}
	if res == nil || res.headPos == 0 {
		return nil, nil // absent
	}
	h := &HeadInfo{Doc: doc, ID: res.headID, Live: res.state != "tombstoned", LastID: res.lastID, LastPos: res.lastPos}
	if !h.Live {
		// A tombstone keeps the last live document (a restore applies
		// to it), but the head serves none (§8.1).
		h.Doc = nil
	}
	if h.Live && doc == nil {
		return nil, apiErr(409, "conflict", "detail", "head document missing")
	}
	return h, nil
}

// LogEntry is a served namespace log entry (namespaceLog of reads.go):
// the hashed body merged with id, prev, author and created. Its "grant"
// is a GrantID the caller resolves to the grant reference, nil for an
// entry written while authentication was disabled, absent for none.
type LogEntry map[string]any

// GrantID is a grant's id in text form (§C.3).
type GrantID string

// ReadLog pages the namespace log (§7.1, spike shape): entries after
// since ("" for the start), at most limit; next is the cursor for the
// following page ("" at the end).
// ReadLog serves the namespace log (§7.4): entries after since ("" from
// the start) up to and including at ("" the tip), a page of at most limit
// (0: all). Both ids resolve through their NSID markers; one that no
// entry has is a 404.
func (s *Store) ReadLog(ctx context.Context, ns, at, since string, limit int) (entries []LogEntry, next string, err error) {
	var from, to uint64
	resolve := func(id string) (uint64, *Error) {
		mk, err := s.getItem(ctx, keyNSID(ns, id))
		if err != nil {
			return 0, apiErr(500, "internal", "message", err.Error())
		}
		if mk == nil {
			return 0, apiErr(404, "not_found", "ns_id", id)
		}
		return item(mk).n("logPos"), nil
	}
	if since != "" {
		var perr *Error
		if from, perr = resolve(since); perr != nil {
			return nil, "", perr
		}
	}
	if at != "" {
		var perr *Error
		if to, perr = resolve(at); perr != nil {
			return nil, "", perr
		}
		if from > to {
			return nil, "", apiErr(404, "not_found", "ns_id", since)
		}
	}
	// SK > LOG#from matches every sort key after it, including other
	// entities' (RES# sorts after LOG#): the loop stops at the first
	// non-LOG# item. One extra row decides whether a page follows.
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk AND SK > :lo"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":lo": avS("LOG#" + padPos(from))},
	}
	if limit > 0 {
		in.Limit = int32ptr(int32(limit + 1))
	}
	q, err := s.Client.Query(ctx, in)
	if err != nil {
		return nil, "", err
	}
	idsByPos := map[uint64]string{}
	for _, it := range q.Items {
		i := item(it)
		sk := i.s("SK")
		if !strings.HasPrefix(sk, "LOG#") {
			break
		}
		pos := i.n("pos")
		if to > 0 && pos > to {
			break
		}
		if limit > 0 && len(entries) == limit {
			next = entries[len(entries)-1]["id"].(string)
			break
		}
		body, _ := jsonv.Parse([]byte(i.s("body")))
		e, _ := body.(map[string]any)
		e["id"] = i.s("id")
		e["author"] = i.s("author")
		e["created"] = FormatTime(int64(i.n("created")))
		if g := i.s("gesture"); g != "" {
			e["gesture"] = g
		}
		if u := i.s("undoes"); u != "" {
			e["undoes"] = u
		}
		if gs := i.s("gestures"); gs != "" {
			e["gestures"], _ = jsonv.Parse([]byte(gs))
		}
		switch {
		case i.s("grantId") != "":
			e["grant"] = GrantID(i.s("grantId"))
		case i.n("noAuth") != 0:
			e["grant"] = nil
		}
		idsByPos[pos] = e["id"].(string)
		if prev := i.n("prevPos"); prev > 0 {
			if pid, ok := idsByPos[prev]; ok {
				e["prev"] = pid
			} else {
				pv, err := s.getItem(ctx, keyLog(ns, prev))
				if err != nil {
					return nil, "", err
				}
				e["prev"] = item(pv).s("id")
			}
		}
		entries = append(entries, e)
	}
	return entries, next, nil
}

// HeadEntry is one resource of a /heads page: its name, head id (a live
// revision or a tombstone id) and, for a live head, the /heads metadata
// of §7.4 (the head revision's created, size, digest).
type HeadEntry struct {
	Name, ID   string
	Tombstoned bool
	Created    int64
	Size       uint64
	Digest     []byte
}

// ListHeads pages a namespace's resources in byte order of name (§7.4,
// spike shape). DynamoDB allows one sort-key condition per query: the
// first page uses begins_with(RES#); later pages use SK > the cursor,
// which can run past RES# into REV# — the loop stops at the prefix
// boundary, as ReadLog's does.
func (s *Store) ListHeads(ctx context.Context, ns, after string, limit int) ([]HeadEntry, string, error) {
	cond := "PK = :pk AND begins_with(SK, :pfx)"
	vals := map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":pfx": avS("RES#")}
	if after != "" {
		cond = "PK = :pk AND SK > :after"
		vals = map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":after": avS("RES#" + after)}
	}
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
		return nil, "", err
	}
	var out []HeadEntry
	var next string
	for _, it := range q.Items {
		i := item(it)
		if !strings.HasPrefix(i.s("SK"), "RES#") {
			break
		}
		if limit > 0 && len(out) == limit {
			next = out[len(out)-1].Name
			break
		}
		out = append(out, HeadEntry{
			Name: resName(i.s("SK")), ID: i.s("headId"), Tombstoned: i.s("state") == "tombstoned",
			Created: int64(i.n("headCreated")), Size: i.n("headSize"), Digest: i.b("headDigest"),
		})
	}
	return out, next, nil
}

// --- point reads ---

func (s *Store) getItem(ctx context.Context, k Key) (map[string]types.AttributeValue, error) {
	out, err := s.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &s.Table,
		Key:            keyAV(k),
		ConsistentRead: boolptr(true),
	})
	if err != nil {
		return nil, err
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	return out.Item, nil
}

func (s *Store) getMeta(ctx context.Context, ns string) (*nsMeta, error) {
	it, err := s.getItem(ctx, keyMeta(ns))
	if it == nil || err != nil {
		return nil, err
	}
	return scanNSMeta(item(it)), nil
}

func (s *Store) getTip(ctx context.Context, ns string) (*tip, error) {
	it, err := s.getItem(ctx, keyTip(ns))
	if it == nil || err != nil {
		return nil, err
	}
	return scanTip(item(it)), nil
}

func (s *Store) getRes(ctx context.Context, ns, name string) (*resRow, error) {
	it, err := s.getItem(ctx, keyRes(ns, name))
	if it == nil || err != nil {
		return nil, err
	}
	return scanRes(item(it)), nil
}

// applyPatches folds a JSON Patch set into a document with the production
// engine (internal/patch), so head documents are the real thing, not a
// stub. The writes are the patch set's write pointers (§6.4.1's envelope).
func applyPatches(doc any, exists bool, patches any) (any, []string, error) {
	ops, err := patch.Parse(patches)
	if err != nil {
		return nil, nil, err
	}
	out, writes, err := patch.Apply(doc, exists, ops, patch.Options{ResourceEnvelope: true, ShareLast: true})
	return out, patch.WritesStrings(writes), err
}

func boolptr(b bool) *bool    { return &b }
func int32ptr(n int32) *int32 { return &n }

// scanRevInfo reads a REV# item (a revision or a tombstone) as served.
func scanRevInfo(i item) RevInfo {
	return RevInfo{
		Name:     resNameFromRev(i.s("SK")),
		ID:       i.s("id"),
		Pos:      i.n("pos"),
		Kind:     i.s("kind"),
		ParentID: i.s("parentId"),
		Patches:  i.s("patches"),
		Author:   i.s("author"),
		Created:  int64(i.n("created")),
		Size:     i.n("size"),
		Digest:   i.b("digest"),
		Gesture:  i.s("gesture"),
		Undoes:   i.s("undoes"),
		LogPos:   i.n("logPos"),
		GrantID:  i.s("grantId"),
	}
}
