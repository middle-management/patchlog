package core

import (
	"context"
	"database/sql"
	"io"
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
	nsReads
	configReads
	logReads
	resourceReads
	grantReads
	blobReads
	schemaReads
	branchReads
	sealedReads
	archiveReads
}

// nsReads are namespace rows and their locks.
type nsReads interface {
	nsByName(name string) *nsRow
	nsByID(id int64) *nsRow
	nsForResources(name string) *nsRow
	nsForWrite(name string) *nsRow
	nsRowUnlocked(id int64) *nsRow
	nsNames() []string
	allNamespaces() []*nsRow
	nsLevel(n *nsRow) int
	lockNS(ns int64, mode lockMode)
	noLocks() func()
}

// configReads are a namespace's configurations.
type configReads interface {
	config(seq int64) *Config
	configID(seq int64) ids.ID
	configByID(n *nsRow, id ids.ID) (seq, author int64, ok bool)
	configEntryGestures(seq int64) (string, bool)
	firstEntryOfConfig(n *nsRow, seq int64) (int64, bool)
	entryConfig(seq int64) (cseq int64, doc string)
}

// logReads are the namespace log and its authors.
type logReads interface {
	nsLogID(seq int64) ids.ID
	nsLogSeq(ns int64, id ids.ID) (int64, bool)
	nsLogRows(n *nsRow, from, to int64, limit int, visit func(nsLogRow) bool)
	nextEntryCreated(ns, seq int64) (int64, bool)
	batchEntry(n *nsRow, seq, author int64) (ids.ID, string, bool)
	entriesTo(row *revRow) []int64
	actorID(a *actor) int64
	authorName(id int64) string
}

// resourceReads are resources, their chains and documents.
type resourceReads interface {
	resolve(n *nsRow, name string, asOf *int64) *view
	resState(res int64) int
	namesAfter(n *nsRow, after string, k int) []string
	retainedNames(n *nsRow) []string
	prefetchResources(ns int64, names []string)
	prefetchHeads(n *nsRow, names []string, asOf *int64)
	rev(seq int64) *revRow
	revID(seq int64) ids.ID
	knowRevID(seq int64, id ids.ID)
	revByID(n *nsRow, name string, id ids.ID) *revRow
	revsBetween(res, from, max int64, limit int, visit func(*revRow) bool)
	firstRev(res int64) int64
	firstRevSince(res, cutoff int64) (int64, bool)
	nthNewestRev(res int64, k int) (int64, bool)
	headAtEntry(res, at int64) (int64, bool)
	gestureRows(n *nsRow, gesture string, after *gestureRow, limit int) []gestureRow
	writingEntry(res, seq int64) (int64, bool)
	ancestry(head *revRow) []segment
	locate(segs []segment, id ids.ID) (int, *revRow)
	docBytesAt(r *revRow) ([]byte, error)
	prunedIn(segs []segment, lo int64) error
	horizonID(res int64) string
	archiveURL(res, seq int64) string
}

// grantReads are stored grants and the entries recording them.
type grantReads interface {
	grantRow(id []byte) (blocks []byte, root *grantRoot, ok bool)
	recordsGrant(n *nsRow, id ids.ID) bool
}

// blobReads are attachments, pending entries and their bytes (§7.8).
type blobReads interface {
	attachedBlob(res int64, bid ids.ID) *blobRow
	pendingBlob(res int64, bid ids.ID, uploader string, cutoff int64) *blobRow
	pendingUsed(n *nsRow, uploader string, cutoff, res int64, bid ids.ID) int64
	referencedUpTo(res, max int64, bid ids.ID) bool
	blobArchive(res int64, bid ids.ID) string
	openBytes(owner int64, hash []byte) blobContent
}

// schemaReads are schema namespaces and the references to schemas (§6.1).
type schemaReads interface {
	schemaNS(name string) *nsRow
	prefetchSchemas(refs []schema.Ref)
	pinnedRefs(l *nsRow) []string
	pinningNames(l *nsRow, ref string) []string
	schemaRefOf(seq int64) (string, bool)
	schemaPinsIn(n *nsRow) []schemaUse
}

// branchReads are branches, their bases and draft copies (§7.6).
type branchReads interface {
	branchesOf(n *nsRow) []*nsRow
	configGenesis(n *nsRow) (seq, author int64, id ids.ID, ok bool)
	branchEntry(base *nsRow, gseq int64) (int64, bool)
	liveRegistrations(n *nsRow) []map[string]any
	registeredAts(n *nsRow) []int64
	registration(n *nsRow, origin, name string) *regRow
	entryBy(seq int64) (author, created int64)
	baseIdentity(n *nsRow) string
	copyRows(id ids.ID, name string) []copyRow
}

// sealedReads are encryption at rest, sealed and e2e namespaces' keys and
// sealings (Addendum E).
type sealedReads interface {
	dek(res int64, create bool) []byte
	epochKey(ns int64, epoch int) []byte
	entryEpoch(n *nsRow, seq int64) int
	e2eEpochOK(n *nsRow, cfg *Config, e int) bool
	declaredAt(row *revRow) []ids.ID
	stored(n *nsRow, j *sealJob) bool
	resJob(n *nsRow, name string, row *revRow, kind string, plain func() []byte) *sealJob
	grantJob(n *nsRow, id ids.ID, plain func() []byte) *sealJob
	sealedBlobHead(n *nsRow, name string, bid ids.ID, out *Blob) *sealJob
	e2eSnapshot(row *revRow) string
	e2eFoldSince(row *revRow) string
}

// archiveReads are what an archive's building reads beyond the chain
// (§8.6): the blobs its documents reference, where its grants were first
// recorded and with which keys, and how it is sealed.
type archiveReads interface {
	archivedBlobs(res, fromSeq, lastSeq int64) map[int64][]ids.ID
	grantFirstEntry(n *nsRow, gid ids.ID, bound sql.NullInt64) (cfg, created int64, ok bool)
	configAtTime(n *nsRow, created int64) (int64, bool)
	firstEntryCreated() (int64, bool)
	archiveSealer(res int64) func(io.Writer) (io.WriteCloser, error)
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

// gateRead runs f on a gate over the backend's reads, outside any write
// (backend.gateRead). An Engine method whose body needs only the gate's
// logic and reads runs on every backend this way.
func (e *Engine) gateRead(ctx context.Context, f func(t *gate) error) error {
	return e.be.gateRead(ctx, f)
}
