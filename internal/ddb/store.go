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

// maxWriteAttempts bounds the tip-conflict retry loop (the SQL backends'
// constant of the same name).
const maxWriteAttempts = 8

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// WriteResult is a committed (or replayed) write, shaped after
// internal/core's: the revision and the namespace log entry.
type WriteResult struct {
	Status   int    // 201 committed, 200 replayed
	ID       string // revision id
	NSID     string // namespace log entry id
	Created  int64  // the entry's stored time, milliseconds
	Replayed bool
}

// CreateNamespace bootstraps a namespace with its config genesis and first
// log entry (insertNamespace of nsops.go). patches is the decoded JSON
// Patch set producing the namespace document.
func (s *Store) CreateNamespace(ctx context.Context, ns, author string, patches any) (cfgID, nsID string, err error) {
	doc, _, err := applyPatches(nil, false, patches)
	if err != nil {
		return "", "", apiErr(422, "patch", "detail", err.Error())
	}
	canon := jsonv.Canonical(patches)
	cfg := ids.Revision(nil, canon)
	body := jsonv.Canonical(map[string]any{"kind": "config", "target": cfg.String()})
	entryID := ids.Hash(nil, body)
	now := s.now().UnixMilli()
	entry := logRow{pos: 1, id: entryID.String(), kind: "config", body: string(body), author: author, created: now, cfgPos: 1}
	meta := &nsMeta{configPos: 1, configID: cfg.String()}

	_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		// buildCreateTx's action order: 0 #META, 1 CFG, 2 LOG, 3 #TIP, 4 NSID.
		TransactItems: buildCreateTx(s.Table, ns, meta, cfg.String(), string(canon), string(jsonv.Canonical(doc)), entry),
	})
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

// WriteState is what the check phase read, handed to WriteResource's
// check hook: the gate's view of the namespace and resource, re-read and
// re-checked on every attempt of the retry loop (D.3's recheck shape).
type WriteState struct {
	Exists    bool // the namespace exists
	Frozen    bool
	Purged    bool
	ConfigID  string
	ResExists bool
	HeadID    string
	HeadDoc   any    // nil when the resource has no live head
	Action    string // "create" or "append"
	RevID     string // the revision the write will commit
	Doc       any    // the resulting document (§6.4.1's envelope reads it)
	DocCanon  []byte
	Writes    []string // the patch set's write pointers
}

// WriteResource creates or appends to a resource (D.3's check-then-commit,
// spike subset). ifMatch pins the parent's revision id ("" pins nothing).
// check, when set, runs the caller's gate on every attempt, after the
// state read and the plan and before the commit; a non-nil error vetoes
// the write. A replayed write is answered before check runs.
func (s *Store) WriteResource(ctx context.Context, ns, name, ifMatch string, patches any, gesture, undoes, author string, check func(*WriteState) error) (*WriteResult, error) {
	for attempt := 0; ; attempt++ {
		// The check phase: reads outside any serialisation (D.3 steps
		// 1–6). One batch read — the four keys are all known from the
		// request — then one transaction: two round trips a write.
		m, t, head, headDoc, err := s.readWriteState(ctx, ns, name)
		if err != nil {
			return nil, err
		}

		p, aerr := planWrite(ns, name, m, t, head, headDoc, ifMatch, patches, gesture, undoes, author, s.now().UnixMilli(), applyPatches)
		if aerr != nil {
			return nil, aerr
		}
		if p.replay {
			created, _ := s.entryCreated(ctx, ns, p.entry.id)
			return &WriteResult{Status: 200, ID: p.rev.id, NSID: p.entry.id, Created: created, Replayed: true}, nil
		}
		if check != nil {
			st := &WriteState{
				Exists: m != nil, ResExists: head != nil && head.headPos > 0, HeadDoc: headDoc,
				RevID: p.rev.id, Doc: p.docAny, DocCanon: []byte(p.doc), Writes: p.writes,
			}
			if m != nil {
				st.Frozen, st.Purged, st.ConfigID = m.frozen, m.purged, m.configID
			}
			if head != nil {
				st.HeadID = head.headID
			}
			switch {
			case p.create:
				st.Action = "create"
			case p.restore:
				st.Action = "restore"
			default:
				st.Action = "append"
			}
			if err := check(st); err != nil {
				return nil, err
			}
		}

		res, retry, err := s.commitWrite(ctx, ns, name, p)
		if res != nil || err != nil {
			return res, err
		}
		if !retry {
			return nil, apiErr(409, "conflict")
		}
		if attempt+1 >= maxWriteAttempts {
			return nil, apiErr(409, "conflict", "detail", "log tip contention")
		}
		// Another write appended an entry between the check and the
		// commit: re-read the tip, recompute the entry id over it, and
		// try again. The revision id is unaffected (its parent is the
		// resource's head). A short backoff keeps racers off each other.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
}

// commitWrite commits a checked write: in its namespace's group (group.go)
// when grouping, else as its own transaction. retry asks the caller's loop
// to read, plan and check it again.
func (s *Store) commitWrite(ctx context.Context, ns, name string, p *writePlan) (*WriteResult, bool, error) {
	if s.grouping() {
		return s.commitGrouped(ctx, ns, name, p)
	}
	_, err := s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: buildWriteTx(s.Table, ns, name, p),
	})
	if err == nil {
		return &WriteResult{Status: 201, ID: p.rev.id, NSID: p.entry.id, Created: p.entry.created}, false, nil
	}
	res, retry, cerr := s.mapCancel(ctx, ns, name, p, err)
	if res == nil && cerr == nil && !retry {
		cerr = err
	}
	return res, retry, cerr
}

// commitDelete is commitWrite for a tombstone.
func (s *Store) commitDelete(ctx context.Context, ns, name string, p *writePlan) (*WriteResult, bool, error) {
	if s.grouping() {
		return s.commitGrouped(ctx, ns, name, p)
	}
	_, err := s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: buildDeleteTx(s.Table, ns, name, p),
	})
	if err == nil {
		return &WriteResult{Status: 201, ID: p.rev.id, NSID: p.entry.id, Created: p.entry.created}, false, nil
	}
	res, retry, cerr := s.mapDeleteCancel(ctx, ns, name, p, err)
	if res == nil && cerr == nil && !retry {
		cerr = err
	}
	return res, retry, cerr
}

// entryCreated is a committed entry's stored time, for replayed answers
// (the plan's own time is the retry's, not the original write's).
func (s *Store) entryCreated(ctx context.Context, ns, entryID string) (int64, error) {
	mk, err := s.getItem(ctx, keyNSID(ns, entryID))
	if err != nil || mk == nil {
		return 0, err
	}
	le, err := s.getItem(ctx, keyLog(ns, item(mk).n("logPos")))
	if err != nil || le == nil {
		return 0, err
	}
	return int64(item(le).n("created")), nil
}

// mapCancel classifies a cancelled write transaction: a replayed result,
// or retry (the log tip moved; the loop rebuilds the plan), or the error
// to answer with.
func (s *Store) mapCancel(ctx context.Context, ns, name string, p *writePlan, err error) (res *WriteResult, retry bool, retErr error) {
	// A concurrent transaction touching the same items (the #TIP of a hot
	// namespace, say): DynamoDB rejects it outright; the retry loop is
	// the answer, as for a cancelled tip condition.
	var xe *types.TransactionConflictException
	if errors.As(err, &xe) {
		return nil, true, nil
	}
	var ce *types.TransactionCanceledException
	if !errors.As(err, &ce) {
		// A throughput or other error that is not a conditional failure:
		// retrying is the caller's choice; surface it raw.
		return nil, false, err
	}
	reasons := ce.CancellationReasons
	failed := func(i int) bool {
		return i < len(reasons) && reasons[i].Code != nil && *reasons[i].Code == "ConditionalCheckFailed"
	}
	switch {
	case failed(actNSID):
		// The entry exists: this very write committed (a retry after an
		// ambiguous failure). Answer from the marker.
		mk, gerr := s.getItem(ctx, keyNSID(ns, p.entry.id))
		if gerr == nil && mk != nil {
			created, _ := s.entryCreated(ctx, ns, p.entry.id)
			return &WriteResult{Status: 200, ID: item(mk).s("revId"), NSID: p.entry.id, Created: created, Replayed: true}, false, nil
		}
		return nil, false, apiErr(409, "conflict")
	case failed(actRes), failed(actRev):
		return s.writeConflict(ctx, ns, name, p)
	case failed(actTip):
		return nil, true, nil
	default:
		return nil, false, err
	}
}

// writeConflict answers a write whose resource's head moved since the
// check (D.3's conflict, isConflict): 412 with the current head — unless
// it moved to this very write (a duplicate committed first): a replay.
func (s *Store) writeConflict(ctx context.Context, ns, name string, p *writePlan) (*WriteResult, bool, error) {
	cur, gerr := s.getRes(ctx, ns, name)
	if gerr == nil && cur != nil {
		if cur.headID == p.rev.id {
			created, _ := s.entryCreated(ctx, ns, cur.entryID)
			return &WriteResult{Status: 200, ID: p.rev.id, NSID: cur.entryID, Created: created, Replayed: true}, false, nil
		}
		return nil, false, apiErr(412, "stale", "head", cur.headID)
	}
	return nil, false, apiErr(412, "stale", "head", "")
}

// DeleteResource tombstones a resource (§7.2's DELETE, §8.1): the
// tombstone chain row, the head move, the log entry and the markers of a
// write, in one transaction pinned on the checked head. ifMatch names the
// deleted head (required, 428 otherwise). check runs the caller's gate per
// attempt, as WriteResource's does; its state's Doc is the last live
// document (§6.4.1's delete envelope).
func (s *Store) DeleteResource(ctx context.Context, ns, name, ifMatch string, gesture, undoes, author string, check func(*WriteState) error) (*WriteResult, error) {
	for attempt := 0; ; attempt++ {
		m, t, head, headDoc, err := s.readWriteState(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		p, aerr := planDelete(ns, name, m, t, head, ifMatch, gesture, undoes, author, s.now().UnixMilli())
		if aerr != nil {
			return nil, aerr
		}
		if p.replay {
			created, _ := s.entryCreated(ctx, ns, p.entry.id)
			return &WriteResult{Status: 200, ID: p.rev.id, NSID: p.entry.id, Created: created, Replayed: true}, nil
		}
		if check != nil {
			st := &WriteState{
				Exists: true, ResExists: true, HeadID: head.headID, HeadDoc: headDoc,
				Action: "delete", RevID: p.rev.id, Doc: headDoc, DocCanon: nil, Writes: []string{},
			}
			st.Frozen, st.Purged, st.ConfigID = m.frozen, m.purged, m.configID
			if err := check(st); err != nil {
				return nil, err
			}
		}

		res, retry, err := s.commitDelete(ctx, ns, name, p)
		if res != nil || err != nil {
			return res, err
		}
		if !retry {
			return nil, apiErr(409, "conflict")
		}
		if attempt+1 >= maxWriteAttempts {
			return nil, apiErr(409, "conflict", "detail", "log tip contention")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
}

// mapDeleteCancel classifies a cancelled delete transaction, as mapCancel
// does a write's: a replayed result, a conflict (the head moved: 412, or
// 410 if the winner deleted first), or retry (the tip moved).
func (s *Store) mapDeleteCancel(ctx context.Context, ns, name string, p *writePlan, err error) (res *WriteResult, retry bool, retErr error) {
	var xe *types.TransactionConflictException
	if errors.As(err, &xe) {
		return nil, true, nil
	}
	var ce *types.TransactionCanceledException
	if !errors.As(err, &ce) {
		return nil, false, err
	}
	reasons := ce.CancellationReasons
	failed := func(i int) bool {
		return i < len(reasons) && reasons[i].Code != nil && *reasons[i].Code == "ConditionalCheckFailed"
	}
	switch {
	case failed(delActNSID):
		return nil, false, apiErr(409, "conflict") // the marker without us: ambiguous
	case failed(delActRes), failed(delActRev):
		return s.deleteConflict(ctx, ns, name, p)
	case failed(delActTip):
		return nil, true, nil
	default:
		return nil, false, err
	}
}

// deleteConflict answers a delete whose resource's head moved since the
// check: 412 with the new head, 410 if the winner deleted it — or a
// replay, if the winner was this very delete.
func (s *Store) deleteConflict(ctx context.Context, ns, name string, p *writePlan) (*WriteResult, bool, error) {
	cur, gerr := s.getRes(ctx, ns, name)
	if gerr == nil && cur != nil {
		if cur.state == "tombstoned" {
			if cur.headID == p.rev.id {
				created, _ := s.entryCreated(ctx, ns, cur.entryID)
				return &WriteResult{Status: 200, ID: p.rev.id, NSID: cur.entryID, Created: created, Replayed: true}, false, nil
			}
			return nil, false, gone()
		}
		return nil, false, apiErr(412, "stale", "head", cur.headID)
	}
	return nil, false, gone()
}

// readWriteState is the check phase's batch read: #META, #TIP, RES# and
// the head document, in one request. The head document is keyed only by
// (ns, name), so it can ride along speculatively; a resource that does not
// exist simply has no such item.
func (s *Store) readWriteState(ctx context.Context, ns, name string) (m *nsMeta, t *tip, head *resRow, headDoc any, err error) {
	keys := []map[string]types.AttributeValue{
		keyAV(keyMeta(ns)), keyAV(keyTip(ns)), keyAV(keyRes(ns, name)), keyAV(keyDocHead(ns, name)),
	}
	out, err := s.Client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			s.Table: {Keys: keys, ConsistentRead: boolptr(true)},
		},
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(out.UnprocessedKeys) > 0 {
		return nil, nil, nil, nil, apiErr(503, "throughput", "detail", "unprocessed keys")
	}
	for _, it := range out.Responses[s.Table] {
		i := item(it)
		switch i.s("PK") + "/" + i.s("SK") {
		case nsPK(ns) + "/#META":
			m = scanNSMeta(i)
		case nsPK(ns) + "/#TIP":
			t = scanTip(i)
		case nsPK(ns) + "/RES#" + name:
			head = scanRes(i)
		case nsPK(ns) + "/DOC#" + name + "#HEAD":
			headDoc, err = jsonv.Parse([]byte(i.s("doc")))
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}
	}
	return m, t, head, headDoc, nil
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
	if h.Live && doc == nil {
		return nil, apiErr(409, "conflict", "detail", "head document missing")
	}
	return h, nil
}

// LogEntry is a served namespace log entry (namespaceLog of reads.go):
// the hashed body merged with id, prev, author and created.
type LogEntry map[string]any

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

func (s *Store) getHeadDoc(ctx context.Context, ns, name string) (any, error) {
	it, err := s.getItem(ctx, keyDocHead(ns, name))
	if err != nil {
		return nil, err
	}
	if it == nil {
		// RES said there is a head but the document is gone: the §5
		// race, or corruption. Treat as lost race.
		return nil, apiErr(409, "conflict", "detail", "head document missing")
	}
	return jsonv.Parse([]byte(item(it).s("doc")))
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
