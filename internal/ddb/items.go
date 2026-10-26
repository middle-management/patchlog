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
// (replay) can answer with its entry id without a scan.
type resRow struct {
	headPos uint64 // 0: no live revision
	headID  string
	entryID string
	state   string // "live"; tombstone/purge are out of the spike's scope
}

func (r *resRow) item() item {
	return item{"headPos": avN(r.headPos), "headId": avS(r.headID), "entryId": avS(r.entryID), "state": avS(r.state)}
}

func scanRes(it item) *resRow {
	return &resRow{headPos: it.n("headPos"), headID: it.s("headId"), entryID: it.s("entryId"), state: it.s("state")}
}

// revRow is the REV# item: one revision of a resource's chain.
type revRow struct {
	pos      uint64
	id       string
	parentID string // "": genesis
	patches  string // canonical JSON of the patch set
	author   string
	created  int64
}

func (r *revRow) item() item {
	it := item{
		"pos":     avN(r.pos),
		"id":      avS(r.id),
		"patches": avS(r.patches),
		"author":  avS(r.author),
		"created": avI(r.created),
	}
	if r.parentID != "" {
		it["parentId"] = avS(r.parentID)
	}
	return it
}

// logRow is the LOG# item: one namespace log entry.
type logRow struct {
	pos     uint64
	id      string
	prevPos uint64 // 0: first entry
	kind    string // "config", "head"
	body    string // canonical JSON of the hashed entry members (§3.5)
	author  string
	created int64
}

func (l *logRow) item() item {
	it := item{
		"pos":     avN(l.pos),
		"id":      avS(l.id),
		"kind":    avS(l.kind),
		"body":    avS(l.body),
		"author":  avS(l.author),
		"created": avI(l.created),
	}
	if l.prevPos > 0 {
		it["prevPos"] = avN(l.prevPos)
	}
	return it
}
