package ddb

import (
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Item shapes. All values inline: nothing in the spike approaches the
// 400 KiB item limit (docs/DYNAMODB.md §3's S3 offload is unimplemented).
//
// The SQL backend stores entry kinds as ints and authors as integer keys;
// the spike stores kind names and author names, denormalised as §3 allows
// (both are unhashed metadata).

func avS(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }
func avN(v uint64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatUint(v, 10)}
}
func avI(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}
func avB(v []byte) types.AttributeValue { return &types.AttributeValueMemberB{Value: v} }

type item map[string]types.AttributeValue

func (it item) s(attr string) string {
	if v, ok := it[attr].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func (it item) n(attr string) uint64 {
	if v, ok := it[attr].(*types.AttributeValueMemberN); ok {
		n, _ := strconv.ParseUint(v.Value, 10, 64)
		return n
	}
	return 0
}

func (it item) b(attr string) []byte {
	if v, ok := it[attr].(*types.AttributeValueMemberB); ok {
		return v.Value
	}
	return nil
}

func (it item) has(attr string) bool { _, ok := it[attr]; return ok }

// nsMeta is the #META item: the namespace's configuration state.
type nsMeta struct {
	frozen, purged bool
	configPos      uint64
	configID       string
}

func (m *nsMeta) item() item {
	fr, pu := "0", "0"
	if m.frozen {
		fr = "1"
	}
	if m.purged {
		pu = "1"
	}
	return item{
		"frozen":    avS(fr),
		"purged":    avS(pu),
		"configPos": avN(m.configPos),
		"configId":  avS(m.configID),
	}
}

func scanNSMeta(it item) *nsMeta {
	return &nsMeta{
		frozen:    it.s("frozen") == "1",
		purged:    it.s("purged") == "1",
		configPos: it.n("configPos"),
		configID:  it.s("configId"),
	}
}

// tip is the #TIP item: the namespace log's chain tip, the item every
// write conditions on (docs/DYNAMODB.md §4).
type tip struct {
	headPos uint64
	headID  string
}

func (t *tip) item() item  { return item{"headPos": avN(t.headPos), "headId": avS(t.headID)} }
func scanTip(it item) *tip { return &tip{headPos: it.n("headPos"), headID: it.s("headId")} }

// resRow is the RES# item: a resource's head pointer and state. entryID is
// the namespace log entry that moved the head here, so a retried write
// (replay) can answer with its entry id without a scan. headCreated,
// headSize and headDigest are the head revision's /heads metadata (§7.4),
// absent on a tombstone. lastId/lastPos are a tombstone's last live
// revision (Head.Last's answer, §8.1).
type resRow struct {
	headPos     uint64 // 0: no live revision
	headID      string // head revision or tombstone id
	entryID     string
	state       string // "live" or "tombstoned"
	headCreated int64
	headSize    uint64
	headDigest  []byte
	lastID      string
	lastPos     uint64
}

func scanRes(it item) *resRow {
	return &resRow{
		headPos: it.n("headPos"), headID: it.s("headId"), entryID: it.s("entryId"), state: it.s("state"),
		headCreated: int64(it.n("headCreated")), headSize: it.n("headSize"), headDigest: it.b("headDigest"),
		lastID: it.s("lastId"), lastPos: it.n("lastPos"),
	}
}

// revRow is the REV# item: one row of a resource's chain. kind is "rev"
// ("" alike) or "tombstone"; a tombstone carries neither patches nor
// document metadata. size and digest are the canonical document's length
// and sha-256 as of this revision (headMeta, §7.1); G1PK is the GSI1 key
// for revision-by-id.
type revRow struct {
	pos       uint64
	id        string
	kind      string // "": a revision; "tombstone"
	parentID  string // "": genesis
	patches   string // canonical JSON of the patch set
	author    string
	created   int64
	size      uint64
	digest    []byte
	gesture   string
	undoes    string
	logPos    uint64 // the namespace entry that committed it: the retry lookup's answer
	grantID   string // the grant it was written under, "" for none
	schemaRef string // the schema revision path it was typed by
}

func (r *revRow) item() item {
	it := item{
		"pos":     avN(r.pos),
		"id":      avS(r.id),
		"author":  avS(r.author),
		"created": avI(r.created),
		"G1PK":    avS(g1RevID(r.id)),
	}
	if r.kind != "" {
		it["kind"] = avS(r.kind)
	}
	if r.kind != "tombstone" {
		it["patches"] = avS(r.patches)
		it["size"] = avN(r.size)
		it["digest"] = avB(r.digest)
	}
	if r.parentID != "" {
		it["parentId"] = avS(r.parentID)
	}
	if r.gesture != "" {
		it["gesture"] = avS(r.gesture)
	}
	if r.undoes != "" {
		it["undoes"] = avS(r.undoes)
	}
	if r.logPos > 0 {
		it["logPos"] = avN(r.logPos)
	}
	if r.grantID != "" {
		it["grantId"] = avS(r.grantID)
	}
	if r.schemaRef != "" {
		it["schemaRef"] = avS(r.schemaRef)
	}
	return it
}

// logRow is the LOG# item: one namespace log entry. gesture and undoes
// are the unhashed gesture members (§7.4), merged into the entry when it
// is served, like the SQL schema's gestures column. cfgPos is the
// configuration in force at the entry, denormalized like ns_log's
// config_seq: NamespaceRev joins on it.
type logRow struct {
	pos     uint64
	id      string
	prevPos uint64 // 0: first entry
	kind    string // "config", "head"
	body    string // canonical JSON of the hashed entry members (§3.5)
	author  string
	created int64
	gesture string
	undoes  string
	// gestures is a batch entry's "gestures" member (batchGestures of
	// write.go): canonical JSON mapping each resource to its steps'
	// { gesture?, undoes? }, "" when no step has one. Unhashed, merged in
	// when served, like gesture and undoes.
	gestures string
	cfgPos   uint64
	// grantID is the grant the entry was written under (§7.4), "" for
	// none; noAuth an entry written while authentication was disabled,
	// which serves "grant": null (§1).
	grantID string
	noAuth  bool
}

func (l *logRow) item() item {
	it := item{
		"pos":     avN(l.pos),
		"id":      avS(l.id),
		"kind":    avS(l.kind),
		"body":    avS(l.body),
		"author":  avS(l.author),
		"created": avI(l.created),
		"cfgPos":  avN(l.cfgPos),
	}
	if l.prevPos > 0 {
		it["prevPos"] = avN(l.prevPos)
	}
	if l.gesture != "" {
		it["gesture"] = avS(l.gesture)
	}
	if l.undoes != "" {
		it["undoes"] = avS(l.undoes)
	}
	if l.gestures != "" {
		it["gestures"] = avS(l.gestures)
	}
	if l.grantID != "" {
		it["grantId"] = avS(l.grantID)
	}
	if l.noAuth {
		it["noAuth"] = avN(1)
	}
	return it
}
