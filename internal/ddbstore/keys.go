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

// nsPK is the partition holding everything of one namespace.
func nsPK(ns string) string { return "NS#" + ns }

// Namespace registry and chains.
func keyMeta(ns string) Key            { return Key{nsPK(ns), "#META"} }
func keyTip(ns string) Key             { return Key{nsPK(ns), "#TIP"} }
func keyCfg(ns string, pos uint64) Key { return Key{nsPK(ns), "CFG#" + padPos(pos)} }
func keyLog(ns string, pos uint64) Key { return Key{nsPK(ns), "LOG#" + padPos(pos)} }

// Resources and their chains. RES# items sort before REV# (byte order), so
// a begins_with(RES#) query lists resources only — /heads in byte order.
func keyRes(ns, name string) Key { return Key{nsPK(ns), "RES#" + name} }
func keyRev(ns, name string, pos uint64) Key {
	return Key{nsPK(ns), "REV#" + name + "#" + padPos(pos)}
}
func keyDocHead(ns, name string) Key { return Key{nsPK(ns), "DOC#" + name + "#HEAD"} }
func keyHist(ns, name string, logPos uint64) Key {
	return Key{nsPK(ns), "HIST#" + name + "#" + padPos(logPos)}
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
// lookups, sparse. Revision items project G1PK = REVID#<id>; ids are
// unique per resource, not globally (genesis twins share one), so answers
// are filtered by namespace.
const gsiName = "GSI1"

// g1RevID is a revision's GSI1 partition key.
func g1RevID(id string) string { return "REVID#" + id }

// resName is the resource name of a RES# sort key.
func resName(sk string) string { return strings.TrimPrefix(sk, "RES#") }
