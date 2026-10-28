// Package ddb is the contract between core's DynamoDB backend and the
// store that keeps its table (docs/DYNAMODB.md §3, §4): the Store
// interface, the data its methods take and return, and the errors and
// limits core answers by. It imports no AWS package; the store itself is
// internal/ddbstore, which registers itself (Register) where a build
// links it in, so internal/core doesn't link the AWS SDK.
package ddb

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Store is a table's storage, as core's backend uses it. Each method's
// doc is on its implementation in internal/ddbstore, grouped here by the
// file that holds it.
type Store interface {
	// MaxBatchItems is the most single-step items a batch is sure to fit
	// in one transaction, a config change's actions included:
	// docs/DYNAMODB.md §10's lowered ItemsPerBatch.
	MaxBatchItems() int

	// archives.go
	Archives(ctx context.Context, ns, name string) ([]*ArchiveRow, error)
	ArchiveFor(ctx context.Context, ns, name string, pos uint64) (string, error)
	BlobArchive(ctx context.Context, ns, name, bid string) (string, error)
	DeleteArchive(ctx context.Context, ns string, a *ArchiveRow) error
	GrantFirstPos(ctx context.Context, ns, gid string) (uint64, error)
	ConfigAtTime(ctx context.Context, ns string, created int64) (uint64, error)
	EachDocIn(ctx context.Context, ns, name string, from, to uint64, visit func(pos uint64, doc any) error) error
	RestorePatches(ctx context.Context, ns, name string, pos uint64, patches string) (bool, error)
	PatchesMissing(ctx context.Context, ns, name string, below uint64) (bool, error)
	ClearHorizon(ctx context.Context, ns, name string, horizonPos uint64) error
	RestoreAttachment(ctx context.Context, ns, name, bid string, hash []byte, owner string) error

	// blobepochs.go
	BlobEpoch(ctx context.Context, ns, name, bid string, epoch int) (data []byte, file string, ok bool, err error)
	PutBlobEpoch(ctx context.Context, ns, name, bid string, epoch int, data []byte, file string, now int64) (storedData []byte, storedFile string, err error)
	MarkBlobEpoch(ctx context.Context, ns, name, bid string, epoch int, now int64) (file string, err error)
	DeleteBlobEpochs(ctx context.Context, ns, name, bid string) (files []string, err error)
	ClearBlobEpochMarkers(ctx context.Context, ns, name string) error

	// blobs.go
	EndAttachment(ctx context.Context, ns, name, bid string, headPos uint64, headID string) error
	Attachment(ctx context.Context, ns, name, bid string) (*BlobRow, error)
	Pending(ctx context.Context, ns, name, bid, uploader string) (*BlobRow, error)
	PendingOf(ctx context.Context, ns string) ([]*BlobRow, error)
	UploaderVersion(ctx context.Context, ns, uploader string) (uint64, error)
	PutPending(ctx context.Context, ns string, cfgPos uint64, cfgID string, ver uint64, p *BlobRow) error
	PutBytes(ctx context.Context, hash, data []byte, file string, now int64) (existed bool, err error)
	Bytes(ctx context.Context, hash []byte) (data []byte, file string, ok bool, err error)
	ScanBlobs(ctx context.Context) (blobs []*BlobRow, nss []string, bytes []*BytesRow, err error)
	DeletePending(ctx context.Context, ns string, p *BlobRow, cutoff int64) (bool, error)
	DeleteBytes(ctx context.Context, hash []byte, cutoff int64) (bool, error)
	CollectBytes(ctx context.Context, hashes [][]byte) (files []string, err error)

	// branch.go
	Branches(ctx context.Context, base string) ([]BranchRow, error)
	Branch(ctx context.Context, base, name string) (*BranchRow, error)

	// commit.go
	Commit(ctx context.Context, c *Commit) (*CommitResult, error)

	// crypt.go
	DEK(ctx context.Context, ns, name string) (*WrappedDEK, error)
	PutDEK(ctx context.Context, ns, name string, k WrappedDEK, now int64) (*WrappedDEK, error)
	DeleteDEKs(ctx context.Context, ns, name string) error
	AnyDEK(ctx context.Context) (ns, name string, k *WrappedDEK, err error)
	Encrypting(ctx context.Context) ([]string, error)
	DoneEncrypting(ctx context.Context, ns string) error
	EncryptContent(ctx context.Context, ns string, seal func(name, kind, key, plain string) (string, error),
		reown func(*BlobRow) ([]byte, string, error)) (grants []string, err error)

	// e2e.go
	E2ESnapshot(ctx context.Context, ns, name string, pos uint64) (string, error)
	LatestE2ESnapshot(ctx context.Context, ns, name string, pos uint64) (uint64, error)

	// gatereads.go
	Namespace(ctx context.Context, ns string) (*NSRow, error)
	ConfigAt(ctx context.Context, ns string, pos uint64) (*ConfigRow, error)
	ConfigByID(ctx context.Context, ns, id string) (*ConfigRow, error)
	Resource(ctx context.Context, ns, name string) (*ResRow, error)
	RevAt(ctx context.Context, ns, name string, pos uint64) (*RevInfo, error)
	DocAt(ctx context.Context, ns, name string, pos uint64) ([]byte, error)
	EntryAt(ctx context.Context, ns string, pos uint64) (*EntryRow, error)
	EntriesBetween(ctx context.Context, ns string, from, to uint64, limit int, visit func(*EntryRow) bool) error
	RevsBetween(ctx context.Context, ns, name string, from, to uint64, limit int, visit func(*RevInfo) bool) error
	EntryPos(ctx context.Context, ns, id string) (uint64, error)

	// gestures.go
	PutGestureMarks(ctx context.Context, ns string, ms []GestureMark) error
	GestureRevs(ctx context.Context, ns, gesture string) ([]GestureRev, error)

	// grants.go
	PutGrant(ctx context.Context, gid string, g StoredGrant, sealed bool) error
	Grant(ctx context.Context, gid string) (*StoredGrant, error)
	RecordsGrant(ctx context.Context, ns, gid string, upTo uint64) (bool, error)
	FirstEntryTime(ctx context.Context) (ms int64, ok bool, err error)

	// group.go
	GroupStats() (groups, writes int64)

	// heads.go
	HeadAt(ctx context.Context, ns, name string, atPos uint64) (*HeadEntry, error)
	HasHistory(ctx context.Context, ns, name string) (bool, error)

	// prune.go
	PutSnapshots(ctx context.Context, ns, name string, docs map[uint64][]byte) error
	PruneContent(ctx context.Context, ns, name string) (ok bool, err error)
	DonePruning(ctx context.Context, ns, name string) error
	Pruning(ctx context.Context) (nss, names []string, err error)
	PrunedBelow(ctx context.Context, ns, name string, from, to uint64) (uint64, error)
	FirstRevSince(ctx context.Context, ns, name string, cutoff int64) (uint64, error)
	NthNewestRev(ctx context.Context, ns, name string, k int) (uint64, error)
	RetainedNames(ctx context.Context, ns string) ([]string, error)
	EachDoc(ctx context.Context, ns, name string, headPos uint64, visit func(doc any) error) error
	EachSnapshot(ctx context.Context, ns, name string, visit func(pos uint64, doc any) error) error
	Attachments(ctx context.Context, ns, name string, pruned bool) ([]*BlobRow, error)

	// purge.go
	PurgeContent(ctx context.Context, ns, name string) (hashes [][]byte, err error)
	Purging(ctx context.Context) (nss, names []string, err error)

	// reads.go
	ReadRevOf(ctx context.Context, ns, name, id string) (*RevInfo, error)
	Ping(ctx context.Context) error
	FoldResource(ctx context.Context, ns, name string, toPos uint64) (doc any, canon []byte, err error)
	RevsWithID(ctx context.Context, id string) ([]IDRev, error)

	// remote.go
	RegistrationOf(ctx context.Context, ns, origin, name string) (*Registration, error)
	Registrations(ctx context.Context, ns string, now int64) ([]*Registration, error)

	// remotelevels.go
	PutRemoteLevel(ctx context.Context, l RemoteLevel) error
	RemoteLevelOf(ctx context.Context, branch string) (*RemoteLevel, error)
	RemoteLevels(ctx context.Context) ([]RemoteLevel, error)

	// repurge.go
	DueRepurges(ctx context.Context, now int64, limit int) ([]Repurge, error)
	DoneRepurge(ctx context.Context, key string) error

	// rotations.go
	RotationsDue(ctx context.Context) ([]string, error)
	RotationDue(ctx context.Context, ns string) (bool, error)
	ClearRotationDue(ctx context.Context, ns string) error

	// schemas.go
	PutSchemaRefs(ctx context.Context, ns string, pins []SchemaPin) error
	SchemaRefs(ctx context.Context, ns, ref string) ([]SchemaPin, error)
	Namespaces(ctx context.Context) ([]string, error)
	RevsByID(ctx context.Context, id, name string) ([]RevCopy, error)

	// sealed.go
	EpochKeyOf(ctx context.Context, ns string, epoch int) (*EpochKey, error)
	EpochKeys(ctx context.Context, ns string) ([]*EpochKey, error)
	AnyEpochKey(ctx context.Context) (string, *EpochKey, error)
	DeleteEpochKeys(ctx context.Context, ns string) error
	Sealed(ctx context.Context, ns, kind, key string) (jwe string, created int64, err error)
	PutSealed(ctx context.Context, ns string, v SealedValue, now int64) (string, error)
	DeleteSealed(ctx context.Context, ns, name string) error
	PutEpochStart(ctx context.Context, ns string, epoch int, created int64) error

	// shadow.go
	ClearShadow(ctx context.Context, name string) error
	ImportShadow(ctx context.Context, im *ShadowImport) (string, error)
	CreateRemoteBranch(ctx context.Context, c *RemoteBranchCreate) (cfgID, nsID string, err error)
	RemoteBaseOf(ctx context.Context, branch string) (*RemoteBase, error)
	RemoteBases(ctx context.Context) ([]*RemoteBase, error)
	SetCheckpoint(ctx context.Context, branch, old, cp string) error
	SetRegistration(ctx context.Context, branch, nsID string, expires int64) error
	PutNotice(ctx context.Context, branch string, n Notice) error
	Notices(ctx context.Context, branch string) ([]Notice, error)
	PurgeShadow(ctx context.Context, shadow, name string) ([][]byte, error)
	ResourceNamesOf(ctx context.Context, ns string) ([]string, error)

	// store.go
	CreateNamespace(ctx context.Context, c *Create) (cfgID, nsID string, err error)
	ListHeads(ctx context.Context, ns, after string, limit int) ([]HeadEntry, string, error)
}

// Options are what core sets on a store it opens.
type Options struct {
	// Now stamps what the store writes (created times); nil: time.Now.
	Now func() time.Time
	// OpenValue, when set, opens a stored value the store folds or serves
	// itself — a revision's patch set ("rev", keyed by the revision id),
	// a head document ("head", by its revision's position), a snapshot
	// ("snap", by position) — that core encrypted at rest (core's
	// ddbcrypt.go). A value is encrypted exactly when it starts with
	// Sealed; the store holds no keys.
	OpenValue func(ctx context.Context, ns, name, kind, key, raw string) (string, error)
	// GroupCommit is at most how many checked writes of a namespace one
	// transaction appends; ≤ 1 commits each write on its own.
	GroupCommit int
	// OnGroup, when set, is called with the size of each group of
	// writes one transaction committed.
	OnGroup func(size int)
}

// Opener opens the table a dynamodb:// URL names.
type Opener func(ctx context.Context, rawurl string, o Options) (Store, error)

var (
	openerMu sync.Mutex
	opener   Opener
)

// Register makes o the store Open opens: internal/ddbstore registers
// itself in its init.
func Register(o Opener) {
	openerMu.Lock()
	defer openerMu.Unlock()
	opener = o
}

// Open opens the table a dynamodb:// URL names with the registered store.
func Open(ctx context.Context, rawurl string, o Options) (Store, error) {
	openerMu.Lock()
	op := opener
	openerMu.Unlock()
	if op == nil {
		return nil, fmt.Errorf("ddb: %s names a DynamoDB table, but this build doesn't link the DynamoDB store (internal/ddbstore)", rawurl)
	}
	return op(ctx, rawurl, o)
}
