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

// Store is a table's storage, as core's backend uses it.
type Store interface {
	// MaxBatchItems is the most single-step items a batch is sure to fit
	// in one transaction, a config change's actions included:
	// docs/DYNAMODB.md §10's lowered ItemsPerBatch.
	MaxBatchItems() int

	// archives.go
	// Archives lists the archives of name in ns ("" for all of ns's), by
	// name, then range.
	Archives(ctx context.Context, ns, name string) ([]*ArchiveRow, error)
	// ArchiveFor is the URL of the newest archive of name holding position
	// pos, "" for none.
	ArchiveFor(ctx context.Context, ns, name string, pos uint64) (string, error)
	// BlobArchive is the URL of the newest archive of name whose blob lines
	// carry bid, "" for none.
	BlobArchive(ctx context.Context, ns, name, bid string) (string, error)
	// DeleteArchive deletes an archive's record.
	DeleteArchive(ctx context.Context, ns string, a *ArchiveRow) error
	// GrantFirstPos is the position of ns's first entry that records grant
	// gid (its marker's), 0 for none.
	GrantFirstPos(ctx context.Context, ns, gid string) (uint64, error)
	// ConfigAtTime is the position of ns's configuration in force at created
	// (milliseconds): the newest created at or before it, 0 for none.
	ConfigAtTime(ctx context.Context, ns string, created int64) (uint64, error)
	// EachDocIn visits name's documents at positions from up to to, oldest
	// first, each live revision's with its position: an archive's range, the
	// first of them read as DocAt reads it (from a horizon's snapshot, say).
	EachDocIn(ctx context.Context, ns, name string, from, to uint64, visit func(pos uint64, doc any) error) error
	// RestorePatches puts an archived patch set back on name's revision at
	// pos, if it has none; it reports whether it did.
	RestorePatches(ctx context.Context, ns, name string, pos uint64, patches string) (bool, error)
	// PatchesMissing reports whether a revision of name below position below
	// has no patch set.
	PatchesMissing(ctx context.Context, ns, name string, below uint64) (bool, error)
	// ClearHorizon removes name's pruning horizon at horizonPos, every patch
	// set below it being back (ErrStale if the horizon moved), then the
	// snapshots it kept, which reads no longer use.
	ClearHorizon(ctx context.Context, ns, name string, horizonPos uint64) error
	// RestoreAttachment brings back an attachment pruning ended, its bytes
	// stored again under hash, encrypted by owner's key ("" for none).
	RestoreAttachment(ctx context.Context, ns, name, bid string, hash []byte, owner string) error

	// blobepochs.go
	// BlobEpoch reads name's sealing of bid in ns under epoch: its bytes or
	// the file holding them; ok with neither for a pruned epoch's marker.
	BlobEpoch(ctx context.Context, ns, name, bid string, epoch int) (data []byte, file string, ok bool, err error)
	// PutBlobEpoch stores a sealing, inline (data) or as file, unless one is
	// stored, and returns the one stored. A marker is replaced.
	PutBlobEpoch(ctx context.Context, ns, name, bid string, epoch int, data []byte, file string, now int64) (storedData []byte, storedFile string, err error)
	// MarkBlobEpoch replaces name's sealing of bid under epoch with the marker
	// of a pruned epoch, and returns the file the sealing was in, if any.
	MarkBlobEpoch(ctx context.Context, ns, name, bid string, epoch int, now int64) (file string, err error)
	// DeleteBlobEpochs deletes ns's blob sealings and markers: name's of bid,
	// all of name's for bid "", all of ns's for name "". It returns the files
	// they named, for the caller to delete.
	DeleteBlobEpochs(ctx context.Context, ns, name, bid string) (files []string, err error)
	// ClearBlobEpochMarkers deletes the markers of name's pruned epochs: a
	// restored archive serves their revisions again (§E.2.2, D.4).
	ClearBlobEpochMarkers(ctx context.Context, ns, name string) error

	// blobs.go
	// EndAttachment marks name's attachment of bid in ns pruned, if name's
	// head is still the one at headPos the caller read every document up to
	// (core's ending of attachments after a prune): a write since may
	// reference it. ErrStale if it moved.
	EndAttachment(ctx context.Context, ns, name, bid string, headPos uint64, headID string) error
	// Attachment reads name's attachment of bid in ns; nil when there is none.
	Attachment(ctx context.Context, ns, name, bid string) (*BlobRow, error)
	// Pending reads uploader's pending entry of bid for name in ns; nil when
	// there is none (expired or not: the caller compares Created).
	Pending(ctx context.Context, ns, name, bid, uploader string) (*BlobRow, error)
	// PendingOf lists every pending entry of ns, expired ones included (the
	// caller filters): an upload sums an uploader's, an attaching commit
	// deletes a blob's. Pending entries are short-lived, so the partition's
	// PEND# range stays small.
	PendingOf(ctx context.Context, ns string) ([]*BlobRow, error)
	// UploaderVersion reads the version of uploader's uploads in ns (0 for
	// none yet); read before the pending entries a total is summed from.
	UploaderVersion(ctx context.Context, ns, uploader string) (uint64, error)
	// PutPending writes (or renews: uploading again restarts the grace time)
	// a pending entry of ns, conditioned on the configuration the upload was
	// checked under and on the uploader's version (ver) its pending total
	// was read at, and on its bytes being stored (a purge collects the bytes
	// nothing names, which these may be until the entry is written):
	// ErrStale when any of them moved.
	PutPending(ctx context.Context, ns string, cfgPos uint64, cfgID string, ver uint64, p *BlobRow) error
	// PutBytes stores the bytes with sha256 hash: data inline, or file, the
	// name in the blob store holding them. It reports whether they were
	// stored already, by an earlier upload: then file, if any, is the
	// caller's to discard. Either way the bytes are touched at now, which
	// keeps the sweep from collecting them before the item naming them is
	// written (SweepBytes).
	PutBytes(ctx context.Context, hash, data []byte, file string, now int64) (existed bool, err error)
	// Bytes reads the bytes with sha256 hash: inline, or the name of their
	// file; ok is false when they aren't stored.
	Bytes(ctx context.Context, hash []byte) (data []byte, file string, ok bool, err error)
	// ScanBlobs lists every attachment, pending entry and bytes item of the
	// table — a scan: operators' statistics and the sweep, never a request.
	// NS is set on the attachments and pending entries.
	ScanBlobs(ctx context.Context) (blobs []*BlobRow, nss []string, bytes []*BytesRow, err error)
	// DeletePending deletes a pending entry of ns if it was created before
	// cutoff (one renewed since stays); it reports whether it did.
	DeletePending(ctx context.Context, ns string, p *BlobRow, cutoff int64) (bool, error)
	// DeleteBytes deletes the bytes with sha256 hash if they weren't touched
	// at or after cutoff (an upload storing them may not have written its
	// pending entry yet); it reports whether it did.
	DeleteBytes(ctx context.Context, hash []byte, cutoff int64) (bool, error)
	// CollectBytes deletes the bytes among hashes that no attachment or
	// pending entry names any more (gcBytes of core's SQL path), and returns
	// the files of those it deleted, for the caller to remove. Whether any
	// item names them is a scan: purges are rare.
	CollectBytes(ctx context.Context, hashes [][]byte) (files []string, err error)

	// branch.go
	// Branches lists base's branches, in byte order of name.
	Branches(ctx context.Context, base string) ([]BranchRow, error)
	// Branch reads base's branch name; nil when it has none of that name.
	Branch(ctx context.Context, base, name string) (*BranchRow, error)

	// commit.go
	// Commit commits c, re-chaining over the tip as other writes move it, or
	// returns ErrStale. With group commit, a write without a config change
	// commits in its namespace's group (group.go).
	Commit(ctx context.Context, c *Commit) (*CommitResult, error)

	// crypt.go
	// DEK reads name's data key in ns (ns "": the grants key); nil when none.
	DEK(ctx context.Context, ns, name string) (*WrappedDEK, error)
	// PutDEK stores a data key unless one exists, and returns the one stored.
	PutDEK(ctx context.Context, ns, name string, k WrappedDEK, now int64) (*WrappedDEK, error)
	// DeleteDEKs destroys name's data key in ns, or every one of ns's for
	// name "".
	DeleteDEKs(ctx context.Context, ns, name string) error
	// AnyDEK is one stored data key, the grants key if there is one, for
	// checking at start-up that the key store unwraps them; nil for none.
	AnyDEK(ctx context.Context) (ns, name string, k *WrappedDEK, err error)
	// Encrypting lists the namespaces whose content is still to be encrypted
	// (Commit.Encrypting) — a scan, for the sweep.
	Encrypting(ctx context.Context) ([]string, error)
	// DoneEncrypting deletes ns's marker.
	DoneEncrypting(ctx context.Context, ns string) error
	// EncryptContent encrypts what of ns is still plaintext: every revision's
	// patch set, head document and snapshot (seal: of name, a kind and its
	// key, the plaintext), and moves the bytes of every attachment and
	// pending entry under its resource's key (reown: the hash and owner that
	// now name them). Each value is replaced only if it is still the one
	// read, so a write since keeps its own. It returns the grants the
	// namespace's entries and revisions were written under, for the caller
	// to encrypt.
	EncryptContent(ctx context.Context, ns string, seal func(name, kind, key, plain string) (string, error),
		reown func(*BlobRow) ([]byte, string, error)) (grants []string, err error)

	// e2e.go
	// E2ESnapshot reads name's client-sealed snapshot at pos; "" for none.
	E2ESnapshot(ctx context.Context, ns, name string, pos uint64) (string, error)
	// LatestE2ESnapshot is the position of name's latest snapshot at or
	// before pos; 0 for none.
	LatestE2ESnapshot(ctx context.Context, ns, name string, pos uint64) (uint64, error)

	// gatereads.go
	// Namespace reads ns's meta and tip; nil when it doesn't exist.
	Namespace(ctx context.Context, ns string) (*NSRow, error)
	// ConfigAt reads ns's configuration at pos; nil when there is none.
	ConfigAt(ctx context.Context, ns string, pos uint64) (*ConfigRow, error)
	// ConfigByID finds ns's configuration id (GSI1); nil when there is none.
	ConfigByID(ctx context.Context, ns, id string) (*ConfigRow, error)
	// Resource reads ns's resource name; nil when it has none.
	Resource(ctx context.Context, ns, name string) (*ResRow, error)
	// RevAt reads resource name's chain at pos; nil when there is none.
	RevAt(ctx context.Context, ns, name string, pos uint64) (*RevInfo, error)
	// DocAt is the canonical document at resource name's pos — for a
	// tombstone, the last live one (a restore's base): the head's from the
	// document item the head keeps, a kept one's below a pruning horizon
	// from its snapshot (prune.go), any other by folding the chain — from the
	// horizon's document if pruned. One below the horizon that isn't kept is
	// a *PrunedError.
	DocAt(ctx context.Context, ns, name string, pos uint64) ([]byte, error)
	// EntryAt reads ns's log entry at pos; nil when there is none.
	EntryAt(ctx context.Context, ns string, pos uint64) (*EntryRow, error)
	// EntriesBetween visits ns's log entries after position from up to and
	// including position to, in chain order, at most limit of them (0: all),
	// while visit returns true.
	EntriesBetween(ctx context.Context, ns string, from, to uint64, limit int, visit func(*EntryRow) bool) error
	// RevsBetween visits name's revisions after position from up to and
	// including position to, oldest first, at most limit of them (0: all),
	// while visit returns true.
	RevsBetween(ctx context.Context, ns, name string, from, to uint64, limit int, visit func(*RevInfo) bool) error
	// EntryPos resolves ns's entry id to its position (the NSID marker,
	// UNIQUE(ns, id)); 0 when there is none.
	EntryPos(ctx context.Context, ns, id string) (uint64, error)

	// gestures.go
	// PutGestureMarks writes markers in ns, before the commit of their
	// revisions.
	PutGestureMarks(ctx context.Context, ns string, ms []GestureMark) error
	// GestureRevs lists ns's revisions written with gesture or undoing it,
	// in the order they were written: by the entry that wrote them, then
	// their item and step in it.
	GestureRevs(ctx context.Context, ns, gesture string) ([]GestureRev, error)

	// grants.go
	// PutGrant stores grant gid. It is written before the commits that record
	// it, outside their transactions (a group's commits may share a grant):
	// one whose commit then fails is never served, since no entry names it.
	// Grant ids are content hashes, so rewriting one is harmless — but for
	// its encryption: blocks encrypted at rest (sealed) replace what is
	// stored, plaintext ones are only stored if nothing is, so a grant used
	// in an encrypted namespace stays encrypted.
	PutGrant(ctx context.Context, gid string, g StoredGrant, sealed bool) error
	// Grant reads grant gid's stored form; nil when it isn't stored.
	Grant(ctx context.Context, gid string) (*StoredGrant, error)
	// RecordsGrant reports whether an entry of ns at or before position upTo
	// (0: any) records grant gid: its marker keeps the first that does.
	RecordsGrant(ctx context.Context, ns, gid string, upTo uint64) (bool, error)
	// FirstEntryTime is the created time (milliseconds) of the deployment's
	// first namespace entry, which every namespace creation offers and the
	// first keeps; ok is false when there is none yet.
	FirstEntryTime(ctx context.Context) (ms int64, ok bool, err error)

	// group.go
	// GroupStats reports how many groups committed and how many commits they
	// appended.
	GroupStats() (groups, writes int64)

	// heads.go
	// HeadAt is name's head in ns as of log position atPos (core's resolve
	// at an earlier entry): nil when it had none.
	HeadAt(ctx context.Context, ns, name string, atPos uint64) (*HeadEntry, error)
	// HasHistory reports whether name has HIST# items: writes recorded in its
	// own chain (resolve.go's hasHistory over head_history).
	HasHistory(ctx context.Context, ns, name string) (bool, error)

	// prune.go
	// PutSnapshots writes the documents a prune of name keeps, by position,
	// before its commit.
	PutSnapshots(ctx context.Context, ns, name string, docs map[uint64][]byte) error
	// PruneContent drops what a committed prune of name in ns left: the
	// patch sets below its horizon, and the snapshots below it that it
	// doesn't keep. Only patch sets go: ids, created times, gestures and a
	// revision's size and digest stay, so /heads at an earlier entry lists a
	// pruned head as it did. It is idempotent, and leaves the marker for
	// DonePruning; ok is false when there is no prune to finish.
	PruneContent(ctx context.Context, ns, name string) (ok bool, err error)
	// DonePruning deletes a finished prune's marker.
	DonePruning(ctx context.Context, ns, name string) error
	// Pruning lists the prunes whose content is still to go, as (namespace,
	// resource) pairs — a scan, for the sweep.
	Pruning(ctx context.Context) (nss, names []string, err error)
	// PrunedBelow is the newest revision (not tombstone) of name after
	// position from and below the horizon, up to position to, whose patch set
	// is gone: a log range (from, to] that holds one is pruned (core's
	// prunedIn). 0: none. Until its prune is finished (its marker), every one
	// below the horizon is gone, stripped or not; after, those a restore put
	// back (archives.go) are served again.
	PrunedBelow(ctx context.Context, ns, name string, from, to uint64) (uint64, error)
	// FirstRevSince is the first of name's revisions created at or after
	// cutoff (milliseconds), 0 for none: read newest first, as far as the
	// first one created before — created times follow the chain's order but
	// for the instances' clock skew.
	FirstRevSince(ctx context.Context, ns, name string, cutoff int64) (uint64, error)
	// NthNewestRev is the position of name's k-th newest revision (k ≥ 1),
	// 0 when it has fewer.
	NthNewestRev(ctx context.Context, ns, name string, k int) (uint64, error)
	// RetainedNames lists ns's resources that retention looks at: not purged,
	// with a head, in byte order of name.
	RetainedNames(ctx context.Context, ns string) ([]string, error)
	// EachDoc visits name's documents from its horizon's last live one (the
	// genesis if unpruned) up to its head, oldest first (core's ending of
	// attachments, which reads every document a prune leaves servable). Only
	// a chain of its own: branches, whose chains continue a base's, don't
	// prune.
	// headPos bounds the walk: the head the caller read.
	EachDoc(ctx context.Context, ns, name string, headPos uint64, visit func(doc any) error) error
	// EachSnapshot visits name's kept documents, with their positions.
	EachSnapshot(ctx context.Context, ns, name string, visit func(pos uint64, doc any) error) error
	// Attachments lists name's attachments in ns: those pruning ended, or
	// those it hasn't.
	Attachments(ctx context.Context, ns, name string, pruned bool) ([]*BlobRow, error)

	// purge.go
	// PurgeContent deletes what a committed purge of name in ns ("" for the
	// namespace's) left: every revision's patch set and document metadata,
	// the head documents, attachments and pending entries, every resource
	// of a purged namespace marked purged; then the purge's marker. It is
	// idempotent: a purge interrupted is finished by calling it again.
	//
	// It returns the hashes of the bytes the attachments and pending entries
	// it deleted named: the caller collects those nothing names any more
	// (core's purge, as SQL's purgeBlobs does in the purge).
	PurgeContent(ctx context.Context, ns, name string) (hashes [][]byte, err error)
	// Purging lists the purges whose content is still to go, as (namespace,
	// resource) pairs, resource "" for a namespace's — a scan, for the sweep.
	Purging(ctx context.Context) (nss, names []string, err error)

	// reads.go
	// ReadRevOf finds a revision of one resource by its id: ReadRevByID's
	// GSI1 lookup narrowed to the resource's chain. Genesis twins (one patch
	// set creating two resources) share an id within a namespace, so the
	// namespace alone doesn't decide which revision an id names, and a read
	// of one twin must not answer the other's (findInAncestry walks the
	// resource's own chain). Absent is nil, not an error.
	ReadRevOf(ctx context.Context, ns, name, id string) (*RevInfo, error)
	// Ping checks the table is reachable (the /_ready check, Engine.Ping).
	Ping(ctx context.Context) error
	// FoldResource folds a resource's chain from the genesis up to and
	// including position toPos (0: the head), applying each revision's patch
	// set with the production engine. One ordered query; the §5 audit turns a
	// gap into an error, never a partial document.
	FoldResource(ctx context.Context, ns, name string, toPos uint64) (doc any, canon []byte, err error)
	// RevsWithID lists every revision of id, in any namespace and resource
	// (GSI1): the copies of a revision.
	RevsWithID(ctx context.Context, id string) ([]IDRev, error)

	// remote.go
	// RegistrationOf reads ns's registration of origin's name; nil for none.
	RegistrationOf(ctx context.Context, ns, origin, name string) (*Registration, error)
	// Registrations lists ns's registrations unexpired at now (milliseconds),
	// by origin, then name.
	Registrations(ctx context.Context, ns string, now int64) ([]*Registration, error)

	// remotelevels.go
	// PutRemoteLevel records l, replacing the branch's earlier record.
	PutRemoteLevel(ctx context.Context, l RemoteLevel) error
	// RemoteLevelOf is branch's record, nil for none.
	RemoteLevelOf(ctx context.Context, branch string) (*RemoteLevel, error)
	// RemoteLevels lists every branch's record, by branch name.
	RemoteLevels(ctx context.Context) ([]RemoteLevel, error)

	// repurge.go
	// DueRepurges lists up to limit second purges due at now (milliseconds),
	// the earliest first.
	DueRepurges(ctx context.Context, now int64, limit int) ([]Repurge, error)
	// DoneRepurge dequeues a sent second purge.
	DoneRepurge(ctx context.Context, key string) error

	// rotations.go
	// RotationsDue lists the namespaces with a rotation due, by name.
	RotationsDue(ctx context.Context) ([]string, error)
	// RotationDue reports whether ns has a rotation due.
	RotationDue(ctx context.Context, ns string) (bool, error)
	// ClearRotationDue drops ns's due rotation: nothing is left to rotate.
	ClearRotationDue(ctx context.Context, ns string) error

	// schemas.go
	// PutSchemaRefs marks ns's pins (idempotent).
	PutSchemaRefs(ctx context.Context, ns string, pins []SchemaPin) error
	// SchemaRefs lists ns's pins; with ref, only that schema's.
	SchemaRefs(ctx context.Context, ns, ref string) ([]SchemaPin, error)
	// Namespaces lists every namespace's name.
	Namespaces(ctx context.Context) ([]string, error)
	// RevsByID lists the revisions with id named name, in every namespace
	// (GSI1; the copies of §6.1).
	RevsByID(ctx context.Context, id, name string) ([]RevCopy, error)

	// sealed.go
	// EpochKeyOf reads ns's key of epoch; nil when there is none.
	EpochKeyOf(ctx context.Context, ns string, epoch int) (*EpochKey, error)
	// EpochKeys lists ns's epoch keys, ascending.
	EpochKeys(ctx context.Context, ns string) ([]*EpochKey, error)
	// AnyEpochKey is one stored epoch key and its namespace, for checking at
	// start-up that the key store unwraps them; nil for none. e2e epochs,
	// which have no key, don't count.
	AnyEpochKey(ctx context.Context) (string, *EpochKey, error)
	// DeleteEpochKeys destroys ns's epoch keys (a namespace purge).
	DeleteEpochKeys(ctx context.Context, ns string) error
	// Sealed reads ns's stored sealed value of kind and key; "" for none.
	Sealed(ctx context.Context, ns, kind, key string) (jwe string, created int64, err error)
	// PutSealed stores v unless a value of its kind and key is stored, and
	// returns the one stored.
	PutSealed(ctx context.Context, ns string, v SealedValue, now int64) (string, error)
	// DeleteSealed deletes ns's sealed values of resource name, or all of
	// ns's for name "".
	DeleteSealed(ctx context.Context, ns, name string) error
	// PutEpochStart records that epoch of ns began at created, unless it is
	// recorded: a keyless EPOCHKEY item, an e2e epoch's (a remote branch's
	// shadow following its base's epochs).
	PutEpochStart(ctx context.Context, ns string, epoch int, created int64) error

	// shadow.go
	// ClearShadow deletes whatever an earlier, failed import of a shadow
	// left, before the next import (whose data keys it must not take).
	ClearShadow(ctx context.Context, name string) error
	// ImportShadow writes a shadow's content, into a partition ClearShadow
	// cleared, and returns its token.
	ImportShadow(ctx context.Context, im *ShadowImport) (string, error)
	// CreateRemoteBranch creates a remote branch over its imported shadows;
	// 412 if the name is taken, ErrStale if a shadow isn't the import the
	// caller made.
	CreateRemoteBranch(ctx context.Context, c *RemoteBranchCreate) (cfgID, nsID string, err error)
	// RemoteBaseOf reads branch's base; nil if it isn't a remote branch.
	RemoteBaseOf(ctx context.Context, branch string) (*RemoteBase, error)
	// RemoteBases lists every remote branch's base, by branch name.
	RemoteBases(ctx context.Context) ([]*RemoteBase, error)
	// SetCheckpoint moves branch's checkpoint from old to cp; ErrStale if
	// another follow moved it first.
	SetCheckpoint(ctx context.Context, branch, old, cp string) error
	// SetRegistration records branch's registration at its base: the
	// registration's latest entry there and when it expires.
	SetRegistration(ctx context.Context, branch, nsID string, expires int64) error
	// PutNotice records a notice, unless one of its id is recorded already.
	PutNotice(ctx context.Context, branch string, n Notice) error
	// Notices lists branch's notices in the order they were recorded.
	Notices(ctx context.Context, branch string) ([]Notice, error)
	// PurgeShadow removes name's content from a shadow, without an entry (its
	// chain mirrors the base's), or, for name "", all of the shadow's
	// (core's purgeShadow and purgeShadowNS). It returns the hashes of the
	// bytes its attachments named, for the caller to collect.
	PurgeShadow(ctx context.Context, shadow, name string) ([][]byte, error)
	// ResourceNamesOf lists every resource name of ns, purged ones included.
	ResourceNamesOf(ctx context.Context, ns string) ([]string, error)

	// store.go
	CreateNamespace(ctx context.Context, c *Create) (cfgID, nsID string, err error)
	// ListHeads pages a namespace's resources in byte order of name (§7.4,
	// spike shape). DynamoDB allows one sort-key condition per query: the
	// first page uses begins_with(RES#); later pages use SK > the cursor,
	// which can run past RES# into REV# — the loop stops at the prefix
	// boundary, as ReadLog's does.
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
