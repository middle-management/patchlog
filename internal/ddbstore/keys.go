// Package ddbstore is the DynamoDB store of docs/DYNAMODB.md, the
// implementation of internal/ddb's Store: the single table's keys and
// items (§3) and the transactions committing what core's write gate
// decided (§4), with the reads core's gate and serving paths make over
// them. It registers itself with internal/ddb (open.go), so a build that
// serves dynamodb:// URLs imports it; internal/core doesn't. It reuses the production id and canonical JSON schemes
// (internal/ids, internal/jsonv) and the production patch application
// (internal/patch), so the bytes it hashes are the bytes internal/core
// hashes. Authorisation and every other check are core's (README.md).
package ddbstore

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
)

// Key is a table key: partition and sort key of one item of the single
// table of docs/DYNAMODB.md §3.
type Key struct {
	PK, SK string
}

// posDigits is the zero-padding width of chain positions, so byte order of
// sort keys is chain order (12 digits: 10^12 revisions per chain).
const posDigits = 12

// padPos renders a chain position for a sort key.
func padPos(n uint64) string { return fmt.Sprintf("%0*d", posDigits, n) }

// parsePos is padPos's inverse.
func parsePos(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }

// nsPK is the partition of one namespace: its registry, chains and log,
// its resources' items (RES#, listed by name), and what is keyed across
// its resources (gestures, pending uploads, sealed values, schema
// references).
func nsPK(ns string) string { return "NS#" + ns }

// resPK is the partition of one resource's own items: its revisions, head
// document, head history, kept snapshots, attachments, data key, epoch
// forms and archives (resourceTypes). A namespace's partition key takes
// what DynamoDB gives one key, ~1,000 write and ~3,000 read units a
// second; with these apart, a write puts its log entry and resource item
// there and the rest under its resource's key (docs/DYNAMODB.md §3).
// Names have no "#" (§3.6), so the key is unambiguous.
func resPK(ns, name string) string { return "R#" + ns + "#" + name }

// nsOfPK is the namespace of a namespace's or a resource's partition key.
func nsOfPK(pk string) string {
	if rest, ok := strings.CutPrefix(pk, "R#"); ok {
		ns, _, _ := strings.Cut(rest, "#")
		return ns
	}
	return strings.TrimPrefix(pk, "NS#")
}

// resourceTypes are the sort-key types kept under a resource's key, each
// "TYPE#<name>…".
var resourceTypes = map[string]bool{
	"REV": true, "DOC": true, "HIST": true, "SNAP": true, "BLOB": true,
	"DEK": true, "E2ESNAP": true, "BLOBEPOCH": true, "ARCH": true,
}

// partitionOf is the partition of ns's items whose sort keys begin with
// prefix: a resource's, for a resource type with its name, the
// namespace's for the rest. every reports a resource type without a name
// ("DEK#"): its items are in each resource's partition.
func partitionOf(ns, prefix string) (pk string, every bool) {
	typ, rest, _ := strings.Cut(prefix, "#")
	if !resourceTypes[typ] {
		return nsPK(ns), false
	}
	name, _, _ := strings.Cut(rest, "#")
	if name == "" {
		return "", true
	}
	return resPK(ns, name), false
}

// Namespace registry and chains.
func keyMeta(ns string) Key            { return Key{nsPK(ns), "#META"} }
func keyTip(ns string) Key             { return Key{nsPK(ns), "#TIP"} }
func keyCfg(ns string, pos uint64) Key { return Key{nsPK(ns), "CFG#" + padPos(pos)} }
func keyLog(ns string, pos uint64) Key { return Key{nsPK(ns), "LOG#" + padPos(pos)} }

// Resources and their chains. RES# items sort before REV# (byte order), so
// a begins_with(RES#) query lists resources only — /heads in byte order.
func keyRes(ns, name string) Key { return Key{nsPK(ns), "RES#" + name} }
func keyRev(ns, name string, pos uint64) Key {
	return Key{resPK(ns, name), "REV#" + name + "#" + padPos(pos)}
}
func keyDocHead(ns, name string) Key { return Key{resPK(ns, name), "DOC#" + name + "#HEAD"} }
func keyHist(ns, name string, logPos uint64) Key {
	return Key{resPK(ns, name), "HIST#" + name + "#" + padPos(logPos)}
}

// keyNSGrant marks that an entry of ns records grant gid (recordsGrant
// of core's grants.go): the grant is served under the namespace.
func keyNSGrant(ns, gid string) Key { return Key{nsPK(ns), "GRANT#" + gid} }

// keyGrant is a grant's stored, non-bearer form (§C.3), deployment-wide
// as the SQL grants table is.
func keyGrant(gid string) Key { return Key{"GRANT#" + gid, "#"} }

// keyDeploy holds deployment-wide facts: the first entry's created time.
func keyDeploy() Key { return Key{"#DEPLOY", "#"} }

// keyNSID is the idempotency marker of a namespace log entry: one item per
// (namespace, entry id), written with attribute_not_exists in the entry's
// transaction (docs/DYNAMODB.md §4). Entry ids are content hashes over the
// namespace's own chain tip, so they are unique per namespace, not
// globally: the marker's key carries the namespace. It also resolves a
// served id back to its log position (ReadLog's since), the role of
// UNIQUE(ns, id) in the SQL schema.
func keyNSID(ns, entryID string) Key { return Key{"NSID#" + ns + "#" + entryID, "#"} }

// gsiName is the table's one GSI (docs/DYNAMODB.md §3, GSI1): global id
// lookups, sparse. Revision and configuration items project G1PK =
// REVID#<id>#<shard>; ids are unique per resource, not globally (genesis
// twins share one), so answers are filtered by namespace.
const gsiName = "GSI1"

// g1Shards is how many GSI1 keys an id's items are spread over, by
// resource (g1Shard). Resources created with the same patches share their
// first revision's id, and namespaces created with the same configuration
// their first configuration's: under one key, every such creation would
// write the one GSI1 key, which DynamoDB holds to ~1,000 writes a second,
// and a throttled index throttles the writes feeding it.
const g1Shards = 16

// g1Shard is resource name of ns's shard ("" for ns's configuration).
func g1Shard(ns, name string) int {
	h := fnv.New32a()
	h.Write([]byte(ns))
	h.Write([]byte{0})
	h.Write([]byte(name))
	return int(h.Sum32() % g1Shards)
}

// g1Key is the GSI1 key of id's item in resource name of ns ("": ns's
// configuration chain): a lookup that knows the resource reads one key.
func g1Key(id, ns, name string) string {
	return "REVID#" + id + "#" + strconv.Itoa(g1Shard(ns, name))
}

// g1Keys are every GSI1 key id's items can be under, for a lookup that
// doesn't know the resource; legacy adds a layout 2 table's unsharded one
// (Store.legacyG1).
func g1Keys(id string, legacy bool) []string {
	keys := make([]string, 0, g1Shards+1)
	for i := range g1Shards {
		keys = append(keys, "REVID#"+id+"#"+strconv.Itoa(i))
	}
	if legacy {
		keys = append(keys, g1Legacy(id))
	}
	return keys
}

// g1Legacy is the GSI1 key layout 2 gave every item of id.
func g1Legacy(id string) string { return "REVID#" + id }

// resName is the resource name of a RES# sort key.
func resName(sk string) string { return strings.TrimPrefix(sk, "RES#") }
