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
	actorID(a *actor) int64
	ancestry(head *revRow) []segment
	archiveURL(res, seq int64) string
	attachedBlob(res int64, bid ids.ID) *blobRow
	blobArchive(res int64, bid ids.ID) string
	sealedBlobHead(n *nsRow, name string, bid ids.ID, out *Blob) *sealJob
	openBytes(owner int64, hash []byte) blobContent
	pendingUsed(n *nsRow, uploader string, cutoff, res int64, bid ids.ID) int64
	authorName(id int64) string
	baseIdentity(n *nsRow) string
	batchEntry(n *nsRow, seq, author int64) (ids.ID, string, bool)
	branchesOf(n *nsRow) []*nsRow
	nextEntryCreated(ns, seq int64) (int64, bool)
	config(seq int64) *Config
	configByID(n *nsRow, id ids.ID) (seq, author int64, ok bool)
	configEntryGestures(seq int64) (string, bool)
	configID(seq int64) ids.ID
	copyRows(id ids.ID, name string) []copyRow
	declaredAt(row *revRow) []ids.ID
	dek(res int64, create bool) []byte
	docBytesAt(r *revRow) ([]byte, error)
	entriesTo(row *revRow) []int64
	e2eEpochOK(n *nsRow, cfg *Config, e int) bool
	firstEntryOfConfig(n *nsRow, seq int64) (int64, bool)
	grantRow(id []byte) (blocks []byte, root *grantRoot, ok bool)
	recordsGrant(n *nsRow, id ids.ID) bool
	grantJob(n *nsRow, id ids.ID, plain func() []byte) *sealJob
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
	prefetchHeads(n *nsRow, names []string, asOf *int64)
	prefetchResources(ns int64, names []string)
	prefetchSchemas(refs []schema.Ref)
	referencedUpTo(res, max int64, bid ids.ID) bool
	resolve(n *nsRow, name string, asOf *int64) *view
	rev(seq int64) *revRow
	revByID(n *nsRow, name string, id ids.ID) *revRow
	revID(seq int64) ids.ID
	schemaNS(name string) *nsRow

	// Serving reads (reads.go, resolve.go).
	knowRevID(seq int64, id ids.ID)
	prunedIn(segs []segment, lo int64) error
	revsBetween(res, from, max int64, limit int, visit func(*revRow) bool)
	nsLogRows(n *nsRow, from, to int64, limit int, visit func(nsLogRow) bool)
	resState(res int64) int
	entryConfig(seq int64) (cseq int64, doc string)
	// Sealed and e2e serving (sealed.go, e2e.go).
	resJob(n *nsRow, name string, row *revRow, kind string, plain func() []byte) *sealJob
	stored(n *nsRow, j *sealJob) bool
	entryEpoch(n *nsRow, seq int64) int
	epochKey(ns int64, epoch int) []byte
	e2eSnapshot(row *revRow) string
	e2eFoldSince(row *revRow) string
	nsNames() []string
	noLocks() func()
	pinnedRefs(l *nsRow) []string
	pinningNames(l *nsRow, ref string) []string
	schemaRefOf(seq int64) (string, bool)
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

// gateRead runs f on a gate over the store's reads, outside any write:
// the read transaction's gate on SQL, DynamoDB's reads otherwise
// (ddbGateRead). An Engine method whose body needs only the gate's logic
// and reads runs on every backend this way.
func (e *Engine) gateRead(ctx context.Context, f func(t *gate) error) error {
	if e.ddb != nil {
		return e.ddbGateRead(ctx, f)
	}
	return e.read(ctx, func(t *tx) error { return f(t.gate) })
}
