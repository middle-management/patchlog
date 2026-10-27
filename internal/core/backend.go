package core

import (
	"context"
	"database/sql"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// backend is an Engine's storage: what core asks of it beyond the gate's
// reads (checkReads, gate.go), which every read and every write's checks
// run over. The SQL databases (sqlBackend) and DynamoDB (ddbBackend,
// ddb.go) implement it; core proper doesn't know which one it has.
//
// A backend that lacks a feature says so (lacks), and the Engine method
// answers its 501 before doing anything; a read it can't answer panics
// with that 501 from inside the gate (ddbUnsupported), which gateRead
// returns.
type backend interface {
	// gateRead runs f on a gate over the backend's reads, one snapshot
	// where the backend has them.
	gateRead(ctx context.Context, f func(t *gate) error) error

	// writeItems is a resource write or a batch (WriteResource, Batch):
	// the gate's checks, then the backend's commit of their plan.
	writeItems(ctx context.Context, req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun bool) (*WriteResult, error)
	// writeConfig is a namespace's creation or config change.
	writeConfig(ctx context.Context, req Request, cc ConfigChange) (*WriteResult, error)
	// purge and purgeNamespace are §8.3's and §8.5's purges: the gate's
	// planPurge or planPurgeNS, then the backend's commit. They return
	// the purge entry's ns_id.
	purge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error)
	purgeNamespace(ctx context.Context, req Request, ifMatch string, force bool) (string, error)
	// prune is §8.6's prune: the gate's planPrune, then the backend's
	// commit; retain applies retention to one resource (ApplyRetention).
	prune(ctx context.Context, req Request, name string, pr PruneRequest) (*PruneResult, error)
	retain(ctx context.Context, ns, name string) (checked, pruned bool, err error)
	// createBranch is a branch's creation (§7.6): the gate's planBranch,
	// then the backend's commit.
	createBranch(ctx context.Context, req Request, br BranchRequest) (*WriteResult, error)
	// uploadBlob is an upload or copy of blob bid to name (§7.8).
	uploadBlob(ctx context.Context, req Request, name string, bid ids.ID, up BlobUpload) error

	// registerRemote is a remote branch's registration with this, its
	// base's deployment (RegisterRemoteBranch, §G.3).
	registerRemote(ctx context.Context, req Request, rr RemoteRegistration) (*RegistrationResult, error)

	// remoteBases lists remote branches' bases, by branch name ("" all);
	// followed records what following one found (notices, purges, the
	// checkpoint), registered its registration at the base; remoteNotices
	// lists the notices (§G.3).
	remoteBases(ctx context.Context, name string) ([]*remoteBase, error)
	followed(ctx context.Context, b *remoteBase, entries []client.NSEntry, head string, follow bool) error
	registered(ctx context.Context, b *remoteBase, nsID string, expires time.Time) error
	remoteNotices(ctx context.Context, ns string) ([]RemoteNotice, error)

	// rotateEpoch is RotateEpoch's config change (§E.2.1).
	rotateEpoch(ctx context.Context, ns, author string) (int, error)
	// storeSealed stores sealed values of namespace ns the first time
	// they are served, the first one stored winning (finishSeal, §E.2.2).
	storeSealed(ctx context.Context, ns string, jobs []*sealJob) error

	// archiveDEK is the data key an encrypted archive of ns/name is
	// sealed with (OpenArchive).
	archiveDEK(ctx context.Context, ns, name string) ([]byte, error)

	// archives lists the archives of unpurged resources (Archives);
	// restore puts archived patch sets back (RestoreResource, §D.4).
	archives(ctx context.Context, ns, name string) ([]ArchiveRecord, error)
	restore(ctx context.Context, ns, name string, entries func(yield func(ArchiveEntry) error) error) (*RestoreResult, error)

	// blobStats counts what blob storage holds; sweepBlobs deletes the
	// pending entries past their grace and the bytes nothing names;
	// orphanFiles are the blob files of cands no row or item names.
	blobStats(ctx context.Context) (*BlobStats, error)
	sweepBlobs(ctx context.Context) (int, error)
	orphanFiles(ctx context.Context, cands map[fileGroup][]string) ([]string, error)

	// firstEntryTime is the created time (milliseconds) of the
	// deployment's first namespace entry; ok is false for none yet.
	firstEntryTime(ctx context.Context) (ms int64, ok bool, err error)

	// dueRepurges lists queued second CDN purges due at now (repurge.go),
	// a batch; doneRepurge dequeues one sent.
	dueRepurges(ctx context.Context, now time.Time) ([]dueRepurge, error)
	doneRepurge(ctx context.Context, key any) error

	ping(ctx context.Context) error
	close() error
	// dbSystem names the database for telemetry (db.system).
	dbSystem() string
	// lacks answers a feature the backend doesn't implement: 501
	// "unsupported", or nil.
	lacks(feature string) *Error
}

// backends are the storages other than SQL, by the -db paths they handle
// (registerBackend); Open tries them before opening a SQL database.
var backends []registeredBackend

type registeredBackend struct {
	handles func(path string) bool
	open    func(Options) (*Engine, error)
}

// registerBackend adds a storage Open uses for the paths handles accepts:
// open builds an Engine over it, with e.be set.
func registerBackend(handles func(path string) bool, open func(Options) (*Engine, error)) {
	backends = append(backends, registeredBackend{handles, open})
}

// sqlBackend is SQLite and Postgres: the Engine's own transactions.
type sqlBackend struct{ e *Engine }

func (b sqlBackend) gateRead(ctx context.Context, f func(t *gate) error) error {
	return b.e.read(ctx, func(t *tx) error { return f(t.gate) })
}

func (b sqlBackend) writeItems(ctx context.Context, req Request, items []Item, cc *ConfigChange, source any, isBatch, dryRun bool) (*WriteResult, error) {
	if !isBatch {
		return b.e.writeOptimistic(ctx, req, items, nil, false)
	}
	return b.e.sqlBatch(ctx, req, items, cc, source, dryRun)
}

func (b sqlBackend) writeConfig(ctx context.Context, req Request, cc ConfigChange) (*WriteResult, error) {
	return b.e.sqlWriteConfig(ctx, req, cc)
}

func (b sqlBackend) purge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error) {
	return b.e.sqlPurge(ctx, req, name, ifMatch, force)
}

func (b sqlBackend) purgeNamespace(ctx context.Context, req Request, ifMatch string, force bool) (string, error) {
	return b.e.sqlPurgeNamespace(ctx, req, ifMatch, force)
}

func (b sqlBackend) prune(ctx context.Context, req Request, name string, pr PruneRequest) (*PruneResult, error) {
	return b.e.sqlPrune(ctx, req, name, pr)
}

func (b sqlBackend) retain(ctx context.Context, ns, name string) (bool, bool, error) {
	return b.e.sqlRetain(ctx, ns, name)
}

func (b sqlBackend) createBranch(ctx context.Context, req Request, br BranchRequest) (*WriteResult, error) {
	return b.e.sqlCreateBranch(ctx, req, br)
}

func (b sqlBackend) uploadBlob(ctx context.Context, req Request, name string, bid ids.ID, up BlobUpload) error {
	return b.e.sqlUploadBlob(ctx, req, name, bid, up)
}

func (b sqlBackend) registerRemote(ctx context.Context, req Request, rr RemoteRegistration) (*RegistrationResult, error) {
	return b.e.sqlRegisterRemote(ctx, req, rr)
}

func (b sqlBackend) remoteBases(ctx context.Context, name string) ([]*remoteBase, error) {
	return b.e.sqlRemoteBases(ctx, name)
}

func (b sqlBackend) followed(ctx context.Context, rb *remoteBase, entries []client.NSEntry, head string, follow bool) error {
	return b.e.sqlFollowed(ctx, rb, entries, head, follow)
}

func (b sqlBackend) registered(ctx context.Context, rb *remoteBase, nsID string, expires time.Time) error {
	return b.e.sqlRegistered(ctx, rb, nsID, expires)
}

func (b sqlBackend) remoteNotices(ctx context.Context, ns string) ([]RemoteNotice, error) {
	return b.e.sqlRemoteNotices(ctx, ns)
}

func (b sqlBackend) rotateEpoch(ctx context.Context, ns, author string) (int, error) {
	return b.e.sqlRotateEpoch(ctx, ns, author)
}

func (b sqlBackend) storeSealed(ctx context.Context, ns string, jobs []*sealJob) error {
	return b.e.sqlStoreSealed(ctx, ns, jobs)
}

func (b sqlBackend) archiveDEK(ctx context.Context, ns, name string) ([]byte, error) {
	return b.e.sqlArchiveDEK(ctx, ns, name)
}

func (b sqlBackend) archives(ctx context.Context, ns, name string) ([]ArchiveRecord, error) {
	return b.e.sqlArchives(ctx, ns, name)
}

func (b sqlBackend) restore(ctx context.Context, ns, name string, entries func(yield func(ArchiveEntry) error) error) (*RestoreResult, error) {
	return b.e.sqlRestore(ctx, ns, name, entries)
}

func (b sqlBackend) blobStats(ctx context.Context) (*BlobStats, error) {
	return b.e.sqlBlobStats(ctx)
}

func (b sqlBackend) sweepBlobs(ctx context.Context) (int, error) { return b.e.sqlSweepBlobs(ctx) }

func (b sqlBackend) orphanFiles(ctx context.Context, cands map[fileGroup][]string) ([]string, error) {
	return b.e.sqlOrphanFiles(ctx, cands)
}

func (b sqlBackend) firstEntryTime(ctx context.Context) (int64, bool, error) {
	var ms sql.NullInt64
	err := b.e.read(ctx, func(t *tx) error {
		return t.QueryRow(`SELECT MIN(created) FROM ns_log WHERE seq = (SELECT MIN(seq) FROM ns_log)`).Scan(&ms)
	})
	return ms.Int64, ms.Valid, err
}

func (b sqlBackend) dueRepurges(ctx context.Context, now time.Time) ([]dueRepurge, error) {
	return b.e.sqlDueRepurges(ctx, now)
}

func (b sqlBackend) doneRepurge(ctx context.Context, key any) error {
	return b.e.sqlDoneRepurge(ctx, key)
}

func (b sqlBackend) ping(ctx context.Context) error { return b.e.db.PingContext(ctx) }
func (b sqlBackend) close() error                   { return b.e.sqlClose() }

func (b sqlBackend) dbSystem() string {
	if b.e.pg {
		return "postgresql"
	}
	return "sqlite"
}

func (b sqlBackend) lacks(string) *Error { return nil }
