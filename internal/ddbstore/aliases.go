package ddbstore

// The store's data are internal/ddb's, the contract core holds it to;
// these names keep the store's code as it was written before the split.

import "github.com/middle-management/patchlog/internal/ddb"

type (
	ArchiveRow         = ddb.ArchiveRow
	BlobAttach         = ddb.BlobAttach
	BlobPending        = ddb.BlobPending
	BlobRow            = ddb.BlobRow
	BranchRow          = ddb.BranchRow
	BytesRow           = ddb.BytesRow
	Commit             = ddb.Commit
	CommitBranch       = ddb.CommitBranch
	CommitConfig       = ddb.CommitConfig
	CommitItem         = ddb.CommitItem
	CommitPrune        = ddb.CommitPrune
	CommitPurge        = ddb.CommitPurge
	CommitRegistration = ddb.CommitRegistration
	CommitResult       = ddb.CommitResult
	CommitStep         = ddb.CommitStep
	ConfigRow          = ddb.ConfigRow
	Create             = ddb.Create
	EntryRow           = ddb.EntryRow
	EpochKey           = ddb.EpochKey
	Error              = ddb.Error
	GestureMark        = ddb.GestureMark
	GestureRev         = ddb.GestureRev
	HeadEntry          = ddb.HeadEntry
	IDRev              = ddb.IDRev
	NSPin              = ddb.NSPin
	NSRow              = ddb.NSRow
	Notice             = ddb.Notice
	PrunedError        = ddb.PrunedError
	Registration       = ddb.Registration
	RemoteBase         = ddb.RemoteBase
	RemoteBranchCreate = ddb.RemoteBranchCreate
	RemoteLevel        = ddb.RemoteLevel
	Repurge            = ddb.Repurge
	ResRow             = ddb.ResRow
	ResourceRef        = ddb.ResourceRef
	RevCopy            = ddb.RevCopy
	RevInfo            = ddb.RevInfo
	SchemaPin          = ddb.SchemaPin
	SealedValue        = ddb.SealedValue
	ShadowBlob         = ddb.ShadowBlob
	ShadowEntry        = ddb.ShadowEntry
	ShadowImport       = ddb.ShadowImport
	ShadowRes          = ddb.ShadowRes
	ShadowRev          = ddb.ShadowRev
	StoredGrant        = ddb.StoredGrant
	WrappedDEK         = ddb.WrappedDEK
)

const (
	MaxInlineBytes = ddb.MaxInlineBytes
	Sealed         = ddb.Sealed
)

var ErrStale = ddb.ErrStale

// IsURL, GestureMarks and BlobEpochFile are ddb's.
var (
	IsURL         = ddb.IsURL
	GestureMarks  = ddb.GestureMarks
	BlobEpochFile = ddb.BlobEpochFile
)
