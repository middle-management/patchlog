package ddb

// Committing a checked write (docs/DYNAMODB.md §4): core's write gate
// (gate.go, over core/ddbreads.go's reads) decides a write — its items'
// revisions and documents, a config change, the namespace entry — and
// the store commits that decision as one TransactWriteItems, conditioned
// on what the checks read: every item's head, and the configuration in
// force (rules, limits and the frozen flag are the configuration's). If
// either moved, the commit fails with ErrStale and core checks the write
// again (D.3's recheck); the log tip, which no check reads, it re-reads
// and re-chains over itself.

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// ErrStale is a commit whose checks no longer hold: a head or the
// configuration moved since they read it. The write is checked again.
var ErrStale = errors.New("ddb: the state a write was checked against moved")

// maxWriteAttempts bounds a commit's re-chaining over a moving tip.
const maxWriteAttempts = 8

// maxTxActions is DynamoDB's transaction action cap.
const maxTxActions = 100

// MaxBatchItems is the most single-step items a batch is sure to fit in
// one transaction, a config change's actions included: docs/DYNAMODB.md
// §10's lowered ItemsPerBatch.
const MaxBatchItems = (maxTxActions - txShared - (commitShared - 1) - 2 - 1) / 4

// commitShared are a commit's actions beyond its items' and its config
// change's: the entry, the tip move, the entry's marker.
const commitShared = 3

// txShared are a transaction's actions beyond its commits' own: the tip
// move and the configuration's condition (one, however many commits).
const txShared = 2

// Commit is a checked write, as the gate decided it.
type Commit struct {
	NS      string
	Author  string
	Created int64 // milliseconds
	// CfgPos and CfgID are the configuration the write was checked under.
	CfgPos uint64
	CfgID  string
	Config *CommitConfig // a config change, or nil
	Items  []CommitItem
	// Entry is the namespace entry's hashed members (§3.5); its id chains
	// over the tip at commit. Kind is its kind; Gesture and Undoes a
	// single write's or config change's gesture members, Gestures a
	// batch's (all unhashed, §7.4).
	Entry           map[string]any
	Kind            string
	Gesture, Undoes string
	Gestures        any
	// Grant is the id of the grant the write was made under (§7.4), ""
	// for none; its stored form is PutGrant's. NoAuth is a write made
	// while authentication was disabled: its entry serves "grant": null.
	Grant  string
	NoAuth bool
	// Purge is a resource purge (§8.3), PurgeNS the namespace's (§8.5):
	// what they commit at once (purgeActs); the bulk of the content goes
	// after the commit (PurgeContent).
	Purge   *CommitPurge
	PurgeNS bool
	// Prune moves a resource's pruning horizon (§8.6, prune.go); the
	// patch sets below it go after the commit (PruneContent).
	Prune *CommitPrune
	// Repurge queues the second CDN purge of the tags the commit purges
	// (repurge.go), in its transaction.
	Repurge *Repurge
	// Branch creates a branch of NS at the commit's entry (branch.go).
	Branch *CommitBranch
	// Registration records a remote branch's registration with the
	// commit's entry (remote.go).
	Registration *CommitRegistration
	// Copies are resources of other namespaces whose copies of a schema
	// revision a purge's in_use check relied on (§6.1): it is stale if
	// one is purged meanwhile, as SQL's locks order the two.
	Copies []ResourceRef
	// EpochKey is the key of the epoch a sealed config change begins
	// (sealed.go), written with it; Epoch is the epoch the items'
	// revisions are written in, 0 outside a sealed namespace.
	EpochKey *EpochKey
	Epoch    int
	// Encrypting marks a config change that raises the namespace to
	// encryption at rest: its plaintext content is encrypted after the
	// commit (EncryptContent), the #ENCRYPTING marker naming the work
	// until it is done.
	Encrypting bool
	// Seal, when set, encrypts the items' patch sets and head documents
	// at rest (Store.Open): of name, a kind and its key, the plaintext.
	Seal func(name, kind, key, plain string) string
	// Pins are the configurations of other namespaces the checks relied
	// on (the schemas' namespaces: whether the writer may read them): a
	// pin that moved makes the commit stale, as its own configuration's.
	Pins []NSPin
}

// CommitPurge is a resource purge: of name, whose head the checks read.
// HeadNS names the base whose revision that head is, when the namespace
// read the resource through (§7.6): the purge then creates its own item,
// purged, on that head.
type CommitPurge struct {
	Name    string
	HeadPos uint64
	HeadID  string
	HeadNS  string
}

// metaCond is a commit's condition on a namespace's #META: the
// configuration its checks ran under, and not purged (§8.5).
const metaCond = "configPos = :cp AND configId = :ci AND purged = :np"

func metaVals(pos uint64, id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{":cp": avN(pos), ":ci": avS(id), ":np": avS("0")}
}

// ResourceRef names a resource of a namespace.
type ResourceRef struct{ NS, Name string }

// NSPin is a namespace's configuration as a check read it.
type NSPin struct {
	NS     string
	CfgPos uint64
	CfgID  string
}

// CommitConfig is a config change: the configuration it makes.
type CommitConfig struct {
	ID      string
	Patches string // canonical
	Doc     string // canonical
	Frozen  bool
}

// CommitItem is one resource's steps, applied to the head the checks read
// (HeadPos 0: the resource didn't exist). LastID and LastPos are a
// tombstoned head's last live revision.
type CommitItem struct {
	Name           string
	HeadPos        uint64
	HeadID         string
	HeadTombstoned bool
	LastID         string
	LastPos        uint64
	Steps          []CommitStep
	// ParentNS and ParentPos are the foreign parent of a first write to a
	// resource read through from a base (§7.6): its first revision
	// continues that one.
	ParentNS  string
	ParentPos uint64
	// E2E marks an e2e namespace's sealed content (§E.3): its steps
	// carry no documents, and the resource has no head document.
	E2E bool
	// Attach are the blobs the item's documents reference that aren't
	// attached to its resource yet, EndPending the pending entries of
	// the blobs they reference (blobs.go).
	Attach     []BlobAttach
	EndPending []BlobPending
}

// CommitStep is one revision or tombstone. Doc is a revision's canonical
// document.
type CommitStep struct {
	ID        string
	ParentID  string
	Tombstone bool
	Patches   string
	Doc       string
	Gesture   string
	Undoes    string
	SchemaRef string // the schema revision path the document was typed by
	// Signature is the step's author signature (§C.3.1), "" for none:
	// unhashed, stored and served with the revision.
	Signature string
	// Author and Created, when set, are a mirrored step's own (a remote
	// branch's schema closure, §G.3), not the commit's.
	Author  string
	Created int64
	// Declared are an e2e step's declared blobs (§E.3.1).
	Declared []string
}

// CommitResult is a committed write's entry.
type CommitResult struct {
	NSID    string
	Pos     uint64
	Created int64
}

// Commit commits c, re-chaining over the tip as other writes move it, or
// returns ErrStale. With group commit, a write without a config change
// commits in its namespace's group (group.go).
func (s *Store) Commit(ctx context.Context, c *Commit) (*CommitResult, error) {
	if acts := c.txActions() + txShared; acts > maxTxActions {
		return nil, apiErr(413, "limit", "limit", "itemsPerBatch", "measured", acts, "max", maxTxActions,
			"message", "the batch's transaction exceeds 100 actions")
	}
	if s.grouping() && !c.alone() {
		return s.commitGrouped(ctx, c)
	}
	// A config change takes the namespace's commit lock, which the group
	// worker holds through each group's commit: they don't race for the
	// tip on this instance (group.go).
	if s.grouping() {
		defer release(s.serialize(c.NS))
	}
	var known *tip
	for attempt := 0; attempt < maxWriteAttempts; attempt++ {
		t := known
		if t == nil {
			cur, err := s.getTip(ctx, c.NS)
			if err != nil {
				return nil, err
			}
			if cur == nil {
				return nil, ErrStale // the namespace is gone
			}
			t = cur
		}
		acts, res, err := s.buildCommits(c.NS, []*Commit{c}, *t)
		if err != nil {
			return nil, err
		}
		_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: acts})
		if err == nil {
			return res[0], nil
		}
		stale, tipMoved, cerr := classifyCancel(err, []*Commit{c}, len(acts))
		switch {
		case cerr != nil:
			return nil, cerr
		case stale[0]:
			return nil, ErrStale
		case tipMoved:
			known = nil
			continue
		}
		// A conflict with another transaction in flight: back off.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 5 * time.Millisecond):
		}
	}
	return nil, apiErr(409, "conflict", "detail", "log tip contention")
}

// actions counts c's own actions: its config change's, its items', the
// entry and its marker (not the transaction's tip move and condition).
func (c *Commit) actions() int {
	n := commitShared - 1 // entry, marker
	if c.Config != nil {
		n += 2 // the META update, the CFG put
	}
	if c.Repurge != nil {
		n++ // the queued second purge
	}
	n += len(c.Copies)
	if c.Registration != nil {
		n++
	}
	if c.Encrypting {
		n++
	}
	if c.EpochKey != nil {
		n++
	}
	if c.Branch != nil {
		n += branchActions
		if c.Grant != "" {
			n++ // the branch's grant marker
		}
		if c.Branch.EpochKey != nil {
			n++
		}
	}
	switch {
	case c.Purge != nil:
		n += 3 // the RES update, the document's delete, the PURGING marker
	case c.PurgeNS:
		n += 2 // the META update, the PURGING marker
	case c.Prune != nil:
		n += c.Prune.actions()
	}
	for _, it := range c.Items {
		n += len(it.Steps) + 1 + it.attachActions() // the revisions, the head, attachments
		if it.lastLive() != nil {
			n++ // the head document
		}
		if !it.Steps[len(it.Steps)-1].Tombstone {
			n++ // the history row
		}
	}
	return n
}

// txActions counts the actions c adds to a transaction: its own, and the
// grant's namespace marker, which a transaction writes once however many
// of its commits record the grant (grantMarks).
func (c *Commit) txActions() int {
	n := c.actions() + len(c.Pins)
	if c.Grant != "" {
		n++
	}
	return n
}

// groupPins are cs's pins, one per namespace (a transaction can't touch
// an item twice; take groups only commits whose pins agree), in order.
func groupPins(cs []*Commit) []NSPin {
	var out []NSPin
	seen := map[string]bool{}
	for _, c := range cs {
		for _, p := range c.Pins {
			if !seen[p.NS] {
				seen[p.NS] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// lastLive is the item's last revision step, nil if all are tombstones.
func (it *CommitItem) lastLive() *CommitStep {
	for i := len(it.Steps) - 1; i >= 0; i-- {
		if !it.Steps[i].Tombstone {
			return &it.Steps[i]
		}
	}
	return nil
}

func (c *Commit) bytes() int {
	n := 0
	for _, it := range c.Items {
		for _, st := range it.Steps {
			n += len(st.Doc) + len(st.Patches)
		}
	}
	return n
}

// buildCommits chains cs's entries over t, at consecutive positions, and
// renders them as one transaction: each commit's actions, then the tip
// move, then — unless a commit changes the configuration, which its META
// update conditions itself — one condition that the configuration is
// still the one they were all checked under (a transaction can't touch
// an item twice). It returns each commit's result.
func (s *Store) buildCommits(ns string, cs []*Commit, t tip) ([]types.TransactWriteItem, []*CommitResult, error) {
	var out []types.TransactWriteItem
	var res []*CommitResult
	prev := t
	for _, c := range cs {
		var prevID *ids.ID
		if prev.headID != "" {
			p, err := ids.Parse(prev.headID)
			if err != nil {
				return nil, nil, apiErr(500, "stored_tip", "namespace", ns)
			}
			prevID = &p
		}
		body := jsonv.Canonical(c.Entry)
		entry := logRow{
			pos: prev.headPos + 1, id: ids.Hash(prevID, body).String(), prevPos: prev.headPos,
			kind: c.Kind, body: string(body), author: c.Author, created: c.Created,
			gesture: c.Gesture, undoes: c.Undoes, cfgPos: c.CfgPos,
			grantID: c.Grant, noAuth: c.NoAuth,
		}
		if c.Gestures != nil {
			entry.gestures = string(jsonv.Canonical(c.Gestures))
		}
		if c.Config != nil {
			entry.cfgPos = c.CfgPos + 1
		}
		out = append(out, s.commitActs(c, entry)...)
		res = append(res, &CommitResult{NSID: entry.id, Pos: entry.pos, Created: c.Created})
		prev = tip{headPos: entry.pos, headID: entry.id}
	}
	out = append(out, s.grantMarks(ns, cs, res)...)
	for _, p := range groupPins(cs) {
		out = append(out, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:                 &s.Table,
			Key:                       keyAV(keyMeta(p.NS)),
			ConditionExpression:       strptr(metaCond),
			ExpressionAttributeValues: metaVals(p.CfgPos, p.CfgID),
		}})
	}
	out = append(out, types.TransactWriteItem{Update: &types.Update{
		TableName:        &s.Table,
		Key:              keyAV(keyTip(ns)),
		UpdateExpression: strptr("SET headPos = :new, headId = :newi"),
		// The log lock (pglock.go's logClass): entries commit in chain
		// order with no gaps, or the transaction cancels.
		ConditionExpression: strptr("headPos = :h AND headId = :i"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new": avN(prev.headPos), ":newi": avS(prev.headID),
			":h": avN(t.headPos), ":i": avS(t.headID),
		},
	}})
	if !touchesMeta(cs) {
		c := cs[0]
		out = append(out, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:                 &s.Table,
			Key:                       keyAV(keyMeta(ns)),
			ConditionExpression:       strptr(metaCond),
			ExpressionAttributeValues: metaVals(c.CfgPos, c.CfgID),
		}})
	}
	return out, res, nil
}

// grantMarks are the namespace markers of the grants cs record, one per
// grant (a transaction can't touch an item twice), each keeping the first
// entry that records it. Unconditional: they never cancel a transaction,
// so classifyCancel's layout ignores them.
func (s *Store) grantMarks(ns string, cs []*Commit, res []*CommitResult) []types.TransactWriteItem {
	var out []types.TransactWriteItem
	seen := map[string]bool{}
	for i, c := range cs {
		if c.Grant == "" || seen[c.Grant] {
			continue
		}
		seen[c.Grant] = true
		out = append(out, grantMark(s.Table, ns, c.Grant, res[i].Pos))
	}
	return out
}

func grantMark(table, ns, gid string, pos uint64) types.TransactWriteItem {
	return types.TransactWriteItem{Update: &types.Update{
		TableName:                 &table,
		Key:                       keyAV(keyNSGrant(ns, gid)),
		UpdateExpression:          strptr("SET firstPos = if_not_exists(firstPos, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": avN(pos)},
	}}
}

// touchesMeta reports whether one of cs updates #META — a config change
// or a namespace purge, which conditions the update itself (and commits on
// its own).
func touchesMeta(cs []*Commit) bool {
	for _, c := range cs {
		if c.Config != nil || c.PurgeNS {
			return true
		}
	}
	return false
}

// alone reports whether c commits on its own, outside group commit: one
// that updates #META, purges, prunes or branches.
func (c *Commit) alone() bool {
	return c.Config != nil || c.PurgeNS || c.Purge != nil || c.Branch != nil || c.Prune != nil || c.Registration != nil || c.EpochKey != nil
}

// commitActs are one commit's actions, in this order — the layout
// classifyCancel reads: a config change's META update and CFG put; each
// item's revisions, head, document and history row; the entry; the
// marker (last).
func (s *Store) commitActs(c *Commit, entry logRow) []types.TransactWriteItem {
	table, ns := &s.Table, c.NS
	var out []types.TransactWriteItem
	if cc := c.Config; cc != nil {
		frozen := "0"
		if cc.Frozen {
			frozen = "1"
		}
		out = append(out,
			types.TransactWriteItem{Update: &types.Update{
				TableName:           table,
				Key:                 keyAV(keyMeta(ns)),
				UpdateExpression:    strptr("SET configPos = :new, configId = :newi, frozen = :fr"),
				ConditionExpression: strptr("configPos = :old AND configId = :oldi AND purged = :np"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":new": avN(c.CfgPos + 1), ":newi": avS(cc.ID), ":fr": avS(frozen),
					":old": avN(c.CfgPos), ":oldi": avS(c.CfgID), ":np": avS("0"),
				},
			}},
			types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyCfg(ns, c.CfgPos+1), item{
				"pos": avN(c.CfgPos + 1), "id": avS(cc.ID), "parentPos": avN(c.CfgPos), "logPos": avN(entry.pos),
				"patches": avS(cc.Patches), "doc": avS(cc.Doc), "author": avS(c.Author), "created": avI(c.Created),
				"G1PK": avS(g1RevID(cc.ID)),
			})}},
		)
	}
	for i := range c.Items {
		out = append(out, s.itemActs(c, &c.Items[i], entry)...)
	}
	out = append(out, s.purgeActs(c)...)
	out = append(out, s.pruneActs(c)...)
	out = append(out, s.repurgeAct(c, entry)...)
	for _, cp := range c.Copies {
		out = append(out, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName: table, Key: keyAV(keyRes(cp.NS, cp.Name)),
			ConditionExpression:       strptr("attribute_not_exists(#st) OR #st <> :pg"),
			ExpressionAttributeNames:  map[string]string{"#st": "state"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":pg": avS("purged")},
		}})
	}
	out = append(out, s.branchActs(c, entry)...)
	out = append(out, s.registrationActs(c, entry)...)
	if c.Encrypting {
		out = append(out, types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyEncrypting(ns), item{"ns": avS(ns)})}})
	}
	if c.EpochKey != nil {
		out = append(out, epochKeyAct(s.Table, ns, c.EpochKey, c.Created))
	}
	marker := item{"ns": avS(ns), "logPos": avN(entry.pos)}
	if len(c.Items) == 1 && c.Kind != "batch" {
		marker["revId"] = avS(c.Items[0].Steps[len(c.Items[0].Steps)-1].ID)
	}
	out = append(out,
		types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyLog(ns, entry.pos), entry.item()), ConditionExpression: strptr("attribute_not_exists(PK)")}},
		// UNIQUE(ns, id): the entry's marker.
		types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyNSID(ns, entry.id), marker), ConditionExpression: strptr("attribute_not_exists(PK)")}},
	)
	return out
}

// itemActs are one item's actions: each step's revision (one child per
// parent: attribute_not_exists), the head moved from the one the checks
// read, the head document (the last live one, which a tombstone keeps)
// and, for a live head, its history row.
func (s *Store) itemActs(c *Commit, it *CommitItem, entry logRow) []types.TransactWriteItem {
	table, ns := &s.Table, c.NS
	var out []types.TransactWriteItem
	pos := it.HeadPos
	lastID, lastPos := it.HeadID, it.HeadPos
	if it.HeadTombstoned {
		lastID, lastPos = it.LastID, it.LastPos
	}
	var final *revRow
	for i := range it.Steps {
		st := &it.Steps[i]
		pos++
		r := revRow{pos: pos, id: st.ID, parentID: st.ParentID, author: c.Author, created: c.Created, gesture: st.Gesture, undoes: st.Undoes, logPos: entry.pos, grantID: c.Grant, schemaRef: st.SchemaRef, signature: st.Signature, epoch: c.Epoch, declared: strings.Join(st.Declared, ",")}
		if pos == 1 {
			r.parentNS, r.parentPos = it.ParentNS, it.ParentPos
		}
		if st.Author != "" {
			r.author, r.created = st.Author, st.Created
		}
		if st.Tombstone {
			r.kind = "tombstone"
		} else {
			digest := sha256.Sum256([]byte(st.Doc))
			r.patches, r.size, r.digest = c.seal(it.Name, "rev", st.ID, st.Patches), uint64(len(st.Doc)), digest[:]
		}
		out = append(out, types.TransactWriteItem{Put: &types.Put{
			TableName: table, Item: withKey(keyRev(ns, it.Name, pos), r.item()),
			ConditionExpression: strptr("attribute_not_exists(PK)"),
		}})
		if !st.Tombstone {
			lastID, lastPos = st.ID, pos
		}
		final = &r
	}

	var cond string
	vals := map[string]types.AttributeValue{}
	if it.HeadPos == 0 {
		cond = "attribute_not_exists(PK)"
	} else {
		// Not purged since (§8.3): the head stays a purged resource's.
		cond = "headPos = :old AND headId = :oldi AND #st <> :pg"
		vals[":old"], vals[":oldi"], vals[":pg"] = avN(it.HeadPos), avS(it.HeadID), avS("purged")
	}
	vals[":h"], vals[":i"], vals[":e"] = avN(final.pos), avS(final.id), avS(entry.id)
	var update string
	if final.kind == "tombstone" {
		// The /heads metadata dies with the document; the last live
		// revision is what Head.Last answers (§8.1).
		update = "SET headPos = :h, headId = :i, #st = :tomb, entryId = :e, lastId = :l, lastPos = :lp REMOVE headCreated, headSize, headDigest"
		vals[":tomb"], vals[":l"], vals[":lp"] = avS("tombstoned"), avS(lastID), avN(lastPos)
	} else {
		update = "SET headPos = :h, headId = :i, #st = :live, entryId = :e, headCreated = :c, headSize = :s, headDigest = :d REMOVE lastId, lastPos"
		vals[":live"], vals[":c"], vals[":s"], vals[":d"] = avS("live"), avI(final.created), avN(final.size), avB(final.digest)
	}
	out = append(out, types.TransactWriteItem{Update: &types.Update{
		TableName: table, Key: keyAV(keyRes(ns, it.Name)),
		UpdateExpression: &update, ConditionExpression: &cond,
		ExpressionAttributeNames:  map[string]string{"#st": "state"},
		ExpressionAttributeValues: vals,
	}})
	if live := it.lastLive(); live != nil && !it.E2E {
		out = append(out, types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyDocHead(ns, it.Name), item{"revPos": avN(lastPos), "doc": avS(c.seal(it.Name, "head", strconv.FormatUint(lastPos, 10), live.Doc))})}})
	}
	if final.kind != "tombstone" {
		out = append(out, types.TransactWriteItem{Put: &types.Put{TableName: table, Item: withKey(keyHist(ns, it.Name, entry.pos), item{"revPos": avN(final.pos)})}})
	}
	return append(out, s.attachActs(c, it)...)
}

// classifyCancel sorts a cancelled transaction of commits cs (built by
// buildCommits): stale[i] when commit i's own conditions failed (a head,
// a revision, its config change, its marker) or the shared configuration
// condition did (every commit's), tipMoved when the tip's or an entry's
// did (another write took the position). err is a failure that isn't a
// cancellation, which nothing here can retry.
func classifyCancel(err error, cs []*Commit, n int) (stale []bool, tipMoved bool, outErr error) {
	stale = make([]bool, len(cs))
	var xe *types.TransactionConflictException
	if errors.As(err, &xe) {
		return stale, false, nil
	}
	var ce *types.TransactionCanceledException
	if !errors.As(err, &ce) {
		return stale, false, err
	}
	failed := func(i int) bool {
		r := ce.CancellationReasons
		return i < len(r) && r[i].Code != nil && *r[i].Code == "ConditionalCheckFailed"
	}
	tipAt := n - 1
	if !touchesMeta(cs) {
		tipAt = n - 2
		if failed(n - 1) {
			for i := range stale {
				stale[i] = true
			}
		}
	}
	tipMoved = failed(tipAt)
	// The pins just before the tip move: one that failed makes every
	// commit pinning its namespace stale.
	pins := groupPins(cs)
	for i, p := range pins {
		if !failed(tipAt - len(pins) + i) {
			continue
		}
		for j, c := range cs {
			for _, cp := range c.Pins {
				if cp.NS == p.NS {
					stale[j] = true
				}
			}
		}
	}
	off := 0
	for i, c := range cs {
		k := c.actions()
		entryAt := off + k - 2
		for a := off; a < off+k; a++ {
			if !failed(a) {
				continue
			}
			if a == entryAt {
				tipMoved = true // its position was taken: the tip moved
			} else {
				stale[i] = true
			}
		}
		off += k
	}
	return stale, tipMoved, nil
}

// seal is Seal, for a commit that has one.
func (c *Commit) seal(name, kind, key, plain string) string {
	if c.Seal == nil {
		return plain
	}
	return c.Seal(name, kind, key, plain)
}
