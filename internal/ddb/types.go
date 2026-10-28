package ddb

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// ArchiveRow is an archive of a resource's range [FromPos, ToPos].
type ArchiveRow struct {
	Name           string
	FromPos, ToPos uint64
	Key, URL       string
	Created        int64
	Bids           []string // the blobs its blob lines carry
}

// BlobEpochFile is the file name prefix of a sealing in ns: under "e/",
// apart from blob bytes.
func BlobEpochFile(ns, hexBid string, epoch int) string {
	return "e/" + hex.EncodeToString([]byte(ns)) + "/" + hexBid[:2] + "/" + hexBid + "." + strconv.Itoa(epoch)
}

// MaxInlineBytes is the most bytes a BYTES item holds itself, under
// DynamoDB's 400 KB item limit: without a blob store it is the
// deployment's blobSize maximum.
const MaxInlineBytes = 350 << 10

// BlobRow is an attachment or a pending entry.
type BlobRow struct {
	Name, Bid  string
	Type       string
	Nonce      string
	Size       int64
	Hash       []byte
	Created    int64
	Uploader   string // a pending entry's
	RefPos     uint64 // an attachment's first referencing revision
	Attachment bool
	// Pruned is an attachment pruning ended (§7.8): no document kept
	// references it, and it names its bytes no more.
	Pruned bool
	// Owner is the resource ("ns\x00name") whose data key encrypts the
	// bytes Hash names, "" for plaintext ones (core's ddbcrypt.go).
	Owner string
}

// BlobAttach is a blob a commit attaches to its item's resource, and the
// first of its steps (Step, an index) whose document references it.
type BlobAttach struct {
	Bid, Type, Nonce string
	Size             int64
	Hash             []byte
	Owner            string // whose data key encrypts the bytes (BlobRow)
	Step             int
}

// BlobPending names a pending entry of the item's resource: a write
// whose documents reference the blob ends it, whoever uploaded it, also
// when the blob was attached already (§7.8 Pending).
type BlobPending struct{ Bid, Uploader string }

// CommitBranch is a branch the commit creates, of the commit's namespace.
type CommitBranch struct {
	Name string
	// AtPos is the base's entry it branches at.
	AtPos uint64
	// CfgID, Patches and Doc are its configuration genesis.
	CfgID, Patches, Doc string
	Frozen              bool
	// EpochKey is a sealed branch's first epoch key (sealed.go).
	EpochKey *EpochKey
}

// Error is a refusal, shaped after internal/core's: an HTTP status and the
// body's members.
type Error struct {
	Status int
	Body   map[string]any
	// RetryAfter is the seconds a client should wait before trying again
	// (Retry-After), 0 for none: DynamoDB throttling the table.
	RetryAfter int
}

func (e *Error) Error() string { return string(jsonv.Canonical(e.Body)) }

// ErrStale is a commit whose checks no longer hold: a head or the
// configuration moved since they read it. The write is checked again.
var ErrStale = errors.New("ddb: the state a write was checked against moved")

// Commit is a checked write, as the gate decided it.
type Commit struct {
	NS      string
	Author  string
	Created int64 // milliseconds
	// CfgPos and CfgID are the configuration the write was checked under.
	CfgPos uint64
	CfgID  string
	// TipPos and TipID are the namespace's log tip as the checks read it
	// (0, "": unknown): the commit chains over it first, and reads the
	// tip again only if its condition finds it moved — a round trip
	// saved, the tip's condition still deciding.
	TipPos uint64
	TipID  string
	Config *CommitConfig // a config change, or nil
	Items  []CommitItem
	// Entry is the namespace entry's hashed members (§3.5); its id chains
	// over the tip at commit. Kind is its kind; Gesture and Undoes a
	// single write's or config change's gesture members, Gestures a
	// batch's (all unhashed, §7.4).
	Entry           map[string]any
	Kind            string
	Gesture, Undoes string
	Gestures        any
	// Grant is the id of the grant the write was made under (§7.4), ""
	// for none; its stored form is PutGrant's. NoAuth is a write made
	// while authentication was disabled: its entry serves "grant": null.
	Grant  string
	NoAuth bool
	// Via is the grant's delegatees (§6.4.1, §C.1), canonical JSON, ""
	// for none: recorded on the entry and the revisions it writes.
	Via string
	// Purge is a resource purge (§8.3), PurgeNS the namespace's (§8.5):
	// what they commit at once (purgeActs); the bulk of the content goes
	// after the commit (PurgeContent).
	Purge   *CommitPurge
	PurgeNS bool
	// Prune moves a resource's pruning horizon (§8.6, prune.go); the
	// patch sets below it go after the commit (PruneContent).
	Prune *CommitPrune
	// Repurge queues the second CDN purge of the tags the commit purges
	// (repurge.go), in its transaction.
	Repurge *Repurge
	// Branch creates a branch of NS at the commit's entry (branch.go).
	Branch *CommitBranch
	// Registration records a remote branch's registration with the
	// commit's entry (remote.go).
	Registration *CommitRegistration
	// Copies are resources of other namespaces whose copies of a schema
	// revision a purge's in_use check relied on (§6.1): it is stale if
	// one is purged meanwhile, as SQL's locks order the two.
	Copies []ResourceRef
	// EpochKey is the key of the epoch a sealed config change begins
	// (sealed.go), written with it; Epoch is the epoch the items'
	// revisions are written in, 0 outside a sealed namespace.
	EpochKey *EpochKey
	Epoch    int
	// RotationsDue are the namespaces a revocation committed with this
	// one reaches, each to rotate its epoch (rotations.go); a commit
	// with an EpochKey clears its own.
	RotationsDue []string
	// Encrypting marks a config change that raises the namespace to
	// encryption at rest: its plaintext content is encrypted after the
	// commit (EncryptContent), the #ENCRYPTING marker naming the work
	// until it is done.
	Encrypting bool
	// Seal, when set, encrypts the items' patch sets and head documents
	// at rest (Store.Open): of name, a kind and its key, the plaintext.
	Seal func(name, kind, key, plain string) string
	// Pins are the configurations of other namespaces the checks relied
	// on (the schemas' namespaces: whether the writer may read them): a
	// pin that moved makes the commit stale, as its own configuration's.
	Pins []NSPin
}

// CommitPurge is a resource purge: of name, whose head the checks read.
// HeadNS names the base whose revision that head is, when the namespace
// read the resource through (§7.6): the purge then creates its own item,
// purged, on that head.
type CommitPurge struct {
	Name    string
	HeadPos uint64
	HeadID  string
	HeadNS  string
}

// ResourceRef names a resource of a namespace.
type ResourceRef struct{ NS, Name string }

// NSPin is a namespace's configuration as a check read it.
type NSPin struct {
	NS     string
	CfgPos uint64
	CfgID  string
}

// CommitConfig is a config change: the configuration it makes.
type CommitConfig struct {
	ID      string
	Patches string // canonical
	Doc     string // canonical
	Frozen  bool
}

// CommitItem is one resource's steps, applied to the head the checks read
// (HeadPos 0: the resource didn't exist). LastID and LastPos are a
// tombstoned head's last live revision.
type CommitItem struct {
	Name           string
	HeadPos        uint64
	HeadID         string
	HeadTombstoned bool
	LastID         string
	LastPos        uint64
	Steps          []CommitStep
	// ParentNS and ParentPos are the foreign parent of a first write to a
	// resource read through from a base (§7.6): its first revision
	// continues that one.
	ParentNS  string
	ParentPos uint64
	// E2E marks an e2e namespace's sealed content (§E.3): its steps
	// carry no documents, and the resource has no head document.
	E2E bool
	// Attach are the blobs the item's documents reference that aren't
	// attached to its resource yet, EndPending the pending entries of
	// the blobs they reference (blobs.go).
	Attach     []BlobAttach
	EndPending []BlobPending
}

// CommitStep is one revision or tombstone. Doc is a revision's canonical
// document.
type CommitStep struct {
	ID        string
	ParentID  string
	Tombstone bool
	Patches   string
	Doc       string
	Gesture   string
	Undoes    string
	SchemaRef string // the schema revision path the document was typed by
	// Signature is the step's author signature (§C.3.1), "" for none:
	// unhashed, stored and served with the revision.
	Signature string
	// Author and Created, when set, are a mirrored step's own (a remote
	// branch's schema closure, §G.3), not the commit's.
	Author  string
	Created int64
	// Declared are an e2e step's declared blobs (§E.3.1).
	Declared []string
	// Via is a mirrored step's own delegation chain (with Author).
	Via string
	// Legacy marks a revision under the schema rules before v0.73.
	Legacy bool
}

// CommitResult is a committed write's entry.
type CommitResult struct {
	NSID    string
	Pos     uint64
	Created int64
}

// WrappedDEK is a stored data key: wrapped by the key store named.
type WrappedDEK struct {
	Wrapped  []byte
	KeyStore string
}

// NSRow is a namespace's meta and log tip.
type NSRow struct {
	Frozen, Purged bool
	// A branch's base, the position it branched at in the base's log, and
	// the base's configuration then (§7.6); "" for none.
	Base               string
	BaseAt, BaseCfgPos uint64
	ConfigPos          uint64
	ConfigID           string
	TipPos             uint64
	TipID              string
}

// ConfigRow is one configuration of a namespace's chain.
type ConfigRow struct {
	Pos    uint64
	ID     string
	Doc    any
	Author string
	LogPos uint64 // the entry that put it in force
}

// ResRow is a resource's head pointer: the head revision or tombstone,
// its state, the entry that moved it there, and a tombstone's last live
// revision.
type ResRow struct {
	HeadPos    uint64
	HeadID     string
	HeadNS     string // a purged read-through resource's head's namespace
	Tombstoned bool
	Purged     bool
	EntryID    string
	LastID     string
	LastPos    uint64
	// HorizonPos and HorizonID are the pruning horizon (0: none), Keep
	// its keep set as served (prune.go).
	HorizonPos uint64
	HorizonID  string
	Keep       string
}

// Prefetched is what Store.Prefetch read of one resource: its item as
// Resource answers it (nil: none, or no head), and its head document
// (DocPos 0: none), the document at DocPos.
type Prefetched struct {
	Res    *ResRow
	DocPos uint64
	Doc    []byte
}

// EntryRow is one namespace log entry as stored.
type EntryRow struct {
	Pos      uint64
	PrevPos  uint64 // 0: the first entry
	ID       string
	Kind     string
	Body     string
	Author   string
	Created  int64
	Gesture  string
	Undoes   string
	Gestures string
	CfgPos   uint64
	GrantID  string
	NoAuth   bool
	Via      string // canonical JSON, "" for none
}

// GestureMark is a revision listed under a gesture: name's revision at
// Pos, of id RevID, written at Created as its commit's Item-th item.
type GestureMark struct {
	Gesture string
	Created int64
	Item    int
	Pos     uint64
	Name    string
	RevID   string
}

// GestureMarks lists the markers of c's steps: one under each step's
// gesture, one under what it undoes.
func GestureMarks(c *Commit) []GestureMark {
	var out []GestureMark
	for i, it := range c.Items {
		for j, st := range it.Steps {
			m := GestureMark{Created: c.Created, Item: i, Pos: it.HeadPos + uint64(j) + 1, Name: it.Name, RevID: st.ID}
			if st.Gesture != "" {
				m.Gesture = st.Gesture
				out = append(out, m)
			}
			if st.Undoes != "" && st.Undoes != st.Gesture {
				m.Gesture = st.Undoes
				out = append(out, m)
			}
		}
	}
	return out
}

// StoredGrant is a grant's stored form and its root's sub and kid.
type StoredGrant struct {
	Blocks   []byte
	Sub, Kid string
}

// IsURL reports whether a -db path names a DynamoDB table
// (docs/DYNAMODB.md §10): dynamodb://<table>?region=…&endpoint=…, next to
// SQLite file paths and postgres:// URLs.
func IsURL(path string) bool { return strings.HasPrefix(path, "dynamodb://") }

// PrunedError is a document or log range below a pruning horizon that
// nothing kept: name's revision pos in ns (§8.6's 410 pruned).
type PrunedError struct {
	NS, Name string
	Pos      uint64
}

func (e *PrunedError) Error() string {
	return fmt.Sprintf("ddb: %s/%s at %d is pruned", e.NS, e.Name, e.Pos)
}

// CommitPrune is a prune of name to the horizon at HorizonPos, whose
// head and horizon the checks read (OldHorizon 0: none).
type CommitPrune struct {
	Name       string
	HeadPos    uint64
	HeadID     string
	OldHorizon uint64
	HorizonPos uint64
	HorizonID  string
	// Base is the horizon's last live revision: the horizon, or a
	// tombstone horizon's parent.
	Base uint64
	// Keep is the keep set as served (canonical JSON); Kept the positions
	// below the horizon whose snapshots stay, Base among them.
	Keep string
	Kept []uint64
	// Archive records the archive the prune wrote of the range below the
	// horizon, nil for none (archives.go).
	Archive *ArchiveRow
	// E2ESnapshot is an e2e resource's horizon document as its client
	// sealed it (e2e.go), "" for others.
	E2ESnapshot string
}

// RevInfo is a revision found by id (GSI1): where it lives and what the
// serving paths need of it. Kind "tombstone" answers 410s (§8.1).
type RevInfo struct {
	Name      string
	ID        string
	Pos       uint64
	Kind      string // "": a revision; "tombstone"
	ParentID  string
	Patches   string
	Author    string
	Created   int64
	Size      uint64
	Digest    []byte
	Gesture   string
	Undoes    string
	LogPos    uint64 // the namespace entry that committed it (0: unknown)
	GrantID   string // the grant it was written under, "" for none
	SchemaRef string
	Signature string // the author signature (§C.3.1)
	Via       string // the writing principal's delegation chain, canonical JSON
	Legacy    bool   // the schema rules before v0.73 (schema.Legacy)
	Epoch     int    // the epoch it was written in (sealed namespaces)
	// Declared are the blobs an e2e revision's document references, as
	// its sealed op declared them (§E.3.1).
	Declared []string
	// ParentNS and ParentPos are a first revision's foreign parent.
	ParentNS  string
	ParentPos uint64
	// Pruned is a revision whose patch set pruning dropped (§8.6).
	Pruned bool
}

// Registration is a remote branch registration of a namespace.
type Registration struct {
	Origin, Name string
	AtPos, NSPos uint64
	PrevPos      uint64 // 0: none
	Expires      int64  // milliseconds
}

// CommitRegistration records a registration with the commit's entry:
// renewing the one whose latest entry is PrevPos (0: there is none).
type CommitRegistration struct {
	Origin, Name string
	AtPos        uint64
	PrevPos      uint64
	Expires      int64
}

// RemoteLevel is a remote branch's record of a raise it couldn't follow.
type RemoteLevel struct {
	Branch  string
	Level   int
	Lacks   bool
	Rebase  bool
	ID      string // the base's ns_id of the entry that raised it
	Created int64
}

// Repurge is a second purge of Tags, due at Due (milliseconds); Key is
// its place in the queue.
type Repurge struct {
	Key  string
	Due  int64
	Tags []string
}

// SchemaPin is a resource whose revision was typed by a schema revision.
type SchemaPin struct{ Ref, Name string }

// EpochKey is an epoch's key, wrapped, and when the epoch began.
type EpochKey struct {
	Epoch    int
	Wrapped  []byte
	KeyStore string
	Created  int64
}

// SealedValue is a sealed value to store: of kind and key, of resource
// Name's revision at RevPos for a document or entry ("", 0 otherwise).
type SealedValue struct {
	Kind, Key string
	Name      string
	RevPos    uint64
	JWE       string
}

// ShadowImport is one shadow's mirrored content.
type ShadowImport struct {
	Name string
	// Base is the shadow below, "" for the bottom one, at BaseAt in it.
	Base   string
	BaseAt uint64
	// The shadow's configuration genesis: its id, patch set and document.
	CfgID, CfgPatches, CfgDoc string
	Author                    string // the genesis's
	Created                   int64
	Log                       []ShadowEntry
	Res                       []ShadowRes
	// Epochs are an e2e level's epochs with when each began, keyless
	// (§E.3.2): the keyring relay's.
	Epochs []EpochKey
}

// ShadowEntry is a mirrored namespace log entry: its id, kind and hashed
// body as verified.
type ShadowEntry struct {
	ID, Kind, Body, Author string
	Created                int64
	Via                    string // canonical JSON, "" for none
}

// ShadowRes is a mirrored resource: its chain from position 1, or for a
// resource purged at the base only its head.
type ShadowRes struct {
	Name   string
	Purged bool
	Revs   []ShadowRev
	// ParentNS and ParentPos are the first revision's foreign parent in
	// the shadow below.
	ParentNS  string
	ParentPos uint64
	// EntryIdx is the log entry (index into Log) that set the head.
	EntryIdx int
	// HeadDoc is the last live document, at LastLivePos (0: in the
	// parent's chain; "" none).
	HeadDoc     string
	LastLivePos uint64
	// HorizonPos is the base's pruning horizon (0: none), whose document
	// is HorizonDoc.
	HorizonPos uint64
	HorizonDoc string
	Attach     []ShadowBlob
}

// ShadowRev is a mirrored revision or tombstone. Patches is "" for a
// horizon or a tombstone.
type ShadowRev struct {
	ID, ParentID, Kind, Patches, Author string
	Created                             int64
	Signature, Gesture, Undoes          string
	SchemaRef                           string
	Size                                uint64
	Digest                              []byte
	// Declared are an e2e revision's declared blobs (§E.3.1).
	Declared []string
	// Via is the base's entry's delegation chain, canonical JSON.
	Via string
	// Legacy: the base serves it under the schema rules before v0.73.
	Legacy bool
}

// ShadowBlob is an attachment of a mirrored resource, its bytes stored
// already (PutBytes), first referenced at RefPos.
type ShadowBlob struct {
	Bid, Type, Nonce string
	Size             int64
	Hash             []byte
	Owner            string
	RefPos           uint64
}

// RemoteBranchCreate is a remote branch's creation: its configuration
// genesis, as a namespace's, as a branch of Shadow at AtPos, whose
// shadows' imports (by name, their tokens) it checks, and its base.
type RemoteBranchCreate struct {
	NS, Author         string
	Grant              string
	NoAuth             bool
	Via                string
	Patches, Doc       string // canonical
	Frozen             bool
	Shadow             string
	AtPos              uint64
	Tokens             map[string]string
	Origin, BaseNS, At string
}

// RemoteBase is a remote branch's base as its #REMOTE item records it.
type RemoteBase struct {
	Branch, Shadow string
	Origin, NS, At string
	Checkpoint     string
	RegNSID        string // the registration's latest entry at the base, "" for none
	RegExpires     int64
}

// Notice is a purge seen in a remote base's log (§G.3), recorded in the
// branch's partition, once per entry id. Seq orders them as recorded.
type Notice struct {
	ID, Kind, Resource string
	Applied            bool
	Created            int64
	Seq                uint64
}

// Create is a namespace's creation, as core's checks decided it. Patches
// is the decoded JSON Patch set producing the namespace document.
type Create struct {
	NS, Author      string
	Patches         any
	Gesture, Undoes string
	// Grant, NoAuth and Via are Commit's.
	Grant  string
	NoAuth bool
	Via    string
	// EpochKey is a sealed namespace's first epoch key (sealed.go).
	EpochKey *EpochKey
}

// HeadEntry is one resource of a /heads page: its name, head id (a live
// revision or a tombstone id) and, for a live head, the /heads metadata
// of §7.4 (the head revision's created, size, digest).
type HeadEntry struct {
	Name, ID   string
	Pos        uint64 // the head's revision position
	Tombstoned bool
	Created    int64
	Size       uint64
	Digest     []byte
}

// Sealed starts a value encrypted at rest (Store.Open, Commit.Seal).
const Sealed = "\x01"

// BytesRow is a BYTES item, as ScanBlobs lists it.
type BytesRow struct {
	Hash    []byte
	File    string
	Size    int64
	Touched int64
	// Ver counts the pending entries that have named the bytes (PutPending):
	// a collection deletes them only while it is what its scan read.
	Ver int64
}

// BranchRow is a branch as its base lists it.
type BranchRow struct {
	Name     string
	EntryPos uint64 // the base's entry that created it
}

// GestureRev is a revision a marker confirmed, with its place in the
// commit that wrote it.
type GestureRev struct {
	Name string
	Item int
	Rev  *RevInfo
}

// IDRev is a revision found by id, with its namespace.
type IDRev struct {
	NS  string
	Rev RevInfo
}

// RevCopy is a revision with a given id in some namespace.
type RevCopy struct {
	NS string
	RevInfo
}
