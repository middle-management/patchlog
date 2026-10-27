package core

import (
	"context"
	"database/sql"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
)

// The write gate: §6.2's check phase — authentication and authorisation,
// rate limits, the retry lookup, preconditions, applying the patches,
// limits, schemas and rules — and the helpers it shares with the rest of
// the engine (authenticate, authorize, envelopes, grants), apart from the
// storage it reads. A gate runs its checks against checkReads, the reads
// of one store; the SQL transaction implements them (tx), so a store
// that implements them too runs the same checks (docs/DYNAMODB.md).
//
// A gate's methods keep their receiver's name, t, and live in the files
// of the features they check; their state is checkState's.

// checkReads is what the gate reads from its store: namespaces (taking
// the locks a write needs, where the store has any), resources and
// their revisions, configurations, blobs, keys, branches and schemas, the
// retry lookup and a config change's plan.
type checkReads interface {
	ancestry(head *revRow) []segment
	archiveURL(res, seq int64) string
	attachedBlob(res int64, bid ids.ID) *blobRow
	authorName(id int64) string
	baseIdentity(n *nsRow) string
	branchesOf(n *nsRow) []*nsRow
	checkAt(n *nsRow) func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error
	config(seq int64) *Config
	copyRows(id ids.ID, name string) []copyRow
	declaredAt(row *revRow) []ids.ID
	dek(res int64, create bool) []byte
	docBytesAt(r *revRow) ([]byte, error)
	e2eEpochOK(n *nsRow, cfg *Config, e int) bool
	grantRef(id []byte) map[string]any
	horizonID(res int64) string
	locate(segs []segment, id ids.ID) (int, *revRow)
	lockNS(ns int64, mode lockMode)
	namesAfter(n *nsRow, after string, k int) []string
	nsByID(id int64) *nsRow
	nsByName(name string) *nsRow
	nsForResources(name string) *nsRow
	nsForWrite(name string) *nsRow
	nsLevel(n *nsRow) int
	nsLogID(seq int64) ids.ID
	nsLogSeq(ns int64, id ids.ID) (int64, bool)
	nsRowUnlocked(id int64) *nsRow
	pendingBlob(res int64, bid ids.ID, uploader string, cutoff int64) *blobRow
	planConfig(n *nsRow, cur *Config, a *actor, cc *ConfigChange, inBatch bool) (*configPlan, error)
	prefetchHeads(n *nsRow, names []string, asOf *int64)
	prefetchResources(ns int64, names []string)
	prefetchSchemas(refs []schema.Ref)
	referencedUpTo(res, max int64, bid ids.ID) bool
	replay(n *nsRow, a *actor, st []*itemState, cp *configPlan, isBatch bool) *WriteResult
	resolve(n *nsRow, name string, asOf *int64) *view
	rev(seq int64) *revRow
	revID(seq int64) ids.ID
	schemaNS(name string) *nsRow
	schemaUses(exclude func(ns *nsRow, res string) bool) map[string]map[int64]*nsRow
}

// checkState is the gate's state in one transaction, shared with the
// store's reads (the transaction embeds it).
type checkState struct {
	e     *Engine
	now   time.Time
	write bool
	// reqCreds are the request's grant and those of Source-Authorization,
	// for an in_use answer's referencing list (§6.1, the rule for other
	// namespaces of §7.5).
	reqCreds []Credentials
	// decoded are bearer grants this transaction already decoded and
	// hasn't verified (decodeGrant), so a request naming many namespaces
	// decodes each grant once (POST /edge-grants).
	decoded map[string]*grant.Grant
	// deps, when set, records what a write's check phase read that a
	// concurrent write could change (D.3 re-check).
	deps *writeDeps
	// schemas are the schema paths resolved in this transaction, per
	// writer (loadSchema).
	schemas map[schemaKey]schemaLoaded
	// rateDrawn, when set, records that a write drew its rate-limit tokens,
	// so a transaction run again doesn't draw them twice.
	rateDrawn *bool
	// exclusive makes a resource write or batch lock its namespace
	// exclusively, as other writes do (writeLocked's last attempt).
	exclusive bool
}

// gate runs the checks of §6.2 over a store's reads.
type gate struct {
	checkReads
	*checkState
}

// newTx starts a transaction's state: its gate reads through it.
func newTx(sqlTx *sql.Tx, ctx context.Context, e *Engine, write bool) *tx {
	t := &tx{Tx: sqlTx, ctx: ctx, checkState: &checkState{e: e, now: e.now(), write: write}}
	t.gate = &gate{checkReads: t, checkState: t.checkState}
	return t
}

var _ checkReads = (*tx)(nil)
