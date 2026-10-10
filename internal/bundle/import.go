package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/sig"
	"github.com/middle-management/patchlog/internal/verify"
)

// ImportMode says how an import is sized (§G.4.4, §6.6). There is no
// default: the caller chooses.
type ImportMode string

const (
	// Atomic submits one batch per target namespace. A batch larger than
	// the namespace's limits fails with 413 unless the importer has an
	// allowance (§6.6); nothing is split.
	Atomic ImportMode = "atomic"
	// Backfill splits batches to fit the namespace's limits (non-atomic)
	// and paces them at ImportOptions.Pace of the namespace rate, or by
	// the importer's allowance there (§6.6).
	Backfill ImportMode = "backfill"
)

// Resolution resolves a conflicting document (§G.4.4, as in §F.3).
type Resolution string

const (
	// ResolveSkip leaves the target's document as it is. For a snapshot
	// document the upstream namespace is still updated.
	ResolveSkip Resolution = "skip"
	// ResolveTake makes the target's document the bundle's version, with
	// one patch set (or a delete) on the target's head: new ids.
	ResolveTake Resolution = "take"
	// ResolveReplay replays the bundle's (or upstream's) entries after the
	// common ancestor onto the target's head, with new ids, overlaps or not.
	ResolveReplay Resolution = "replay"
)

// Conflict kinds added to those of package merge.
const (
	ConflictDiverged = "diverged" // a full document with a different history in the target
	ConflictRequires = "requires" // the target moved on along another line than requires
	ConflictPurged   = "purged"   // purged in the target (or its upstream)
)

// Opener opens a bundle for reading.
type Opener func() (io.ReadCloser, error)

// FileOpener opens a file.
func FileOpener(path string) Opener {
	return func() (io.ReadCloser, error) { return os.Open(path) }
}

// BytesOpener reads a bundle held in memory.
func BytesOpener(b []byte) Opener {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

// ImportOptions configure an import.
type ImportOptions struct {
	// Mode is required: Atomic or Backfill.
	Mode ImportMode
	// Pace is the fraction of the namespace rate a backfill uses (default
	// 0.5), counting every request, dry runs included (§G.4.4). The rate is
	// the target namespace's ratePerNamespace, capped by ratePerPrincipal
	// (the importer's own bucket, which would answer 429 first). An
	// importer with an allowance in the target namespace (§6.6; its sub and
	// kid as client.Principal reads them) goes by that instead: batches of
	// the allowance's itemsPerBatch and batchSize where it sets them, paced
	// at the full rate of its bucket where it has one, which holds up no
	// other writer. From a minute before the allowance's until, the rest
	// are split again and paced by the namespace's limits. Either way a
	// chain cut between batches goes no faster than ratePerResource.
	Pace float64
	// DryRun classifies, checks and dry-runs each namespace's first batch
	// and every later one that moves heads the target had, but for one
	// that goes on with a chain an earlier batch cut, and writes nothing.
	DryRun bool
	// NSMap maps source namespaces to target namespaces (default: the
	// same name, §G.1). Schema namespaces must not be mapped, since
	// $schema paths name them.
	NSMap map[string]string
	// Only, if set, are the source namespaces to import (partial.go): the
	// others' documents are left out as external dependencies are
	// (§G.4.1), and the target must have what the imported documents
	// reference in them, as the bundle has it, which is checked first.
	Only []string
	// UpstreamSuffix names the upstream namespace of a source namespace
	// (default "-upstream": matches → matches-upstream).
	UpstreamSuffix string
	// Resolutions resolve conflicting documents, by source key "ns/name".
	Resolutions map[string]Resolution
	// CreateNamespaces creates missing target and upstream namespaces.
	CreateNamespaces bool
	// NamespaceDoc is the namespace document for a namespace created by
	// the import; upstreamOf is the target namespace an upstream namespace
	// serves, "" otherwise. Default: {} for document namespaces, and for
	// upstream namespaces the read mode of the namespace they serve. Its
	// limits and allowances split and pace the batches into the namespace,
	// as an existing namespace's own do (Pace).
	NamespaceDoc func(ns, upstreamOf string) any
	// Sleep waits between paced batches and retries (default: a timer).
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock that pacing takes the time a batch took from, and
	// allowances' until is judged by (default time.Now).
	Now func() time.Time
	// MaxRetries bounds retries of a batch after 429, 5xx or a transport
	// error (default 5). Retries are safe: an identical batch by the same
	// principal is answered with the earlier result (§7.5).
	MaxRetries int
	// Progress, if set, is told about each batch as it is submitted.
	Progress func(b *BatchReport)
	// Concurrency is how many batches a backfill under an allowance
	// submits at once (default 4; 1 submits one at a time), or fewer: as
	// many as the allowance's burst holds the draws of. Dependency order
	// holds all the same (§G.4.4): a namespace's batches start once those
	// of the namespaces it depends on have committed, and a batch waits
	// for one in flight that it goes on with or whose documents it pins.
	// Paced batches, without an allowance, go one at a time.
	Concurrency int
	// AllowLessProtected is the operator's explicit override, for this
	// import, of the refusal to import a private or sealed namespace into a
	// public target (§G.5.1).
	AllowLessProtected bool
	// Signer, if set, signs every step the import writes (§C.3.1) with the
	// importer's own key, bound to the target deployment's origin, the
	// target namespace (an upstream namespace for a snapshot document's
	// upstream chain), the resource and the step's parent. Targets with
	// "signatures": "required" need it, and the key must be listed in the
	// signers of the grant the import runs under. The bundle's own
	// signatures are never re-sent: they stay in the bundle, which the
	// batches' source names (§G.4.4), where they verify against the source
	// (VerifyWith).
	Signer *sig.Key

	// keepTrees keeps the snapshot documents as the trees the Reader
	// parses, as imports did before they kept their canonical forms
	// (Line.docCanon). Tests only (KeepSnapshotTrees): the golden test
	// checks that both send the same requests.
	keepTrees bool
}

// DocReport is one bundled document, classified.
type DocReport struct {
	Doc        string           `json:"doc"`    // source "ns/name"
	Target     string           `json:"target"` // target "ns/name"
	History    string           `json:"history"`
	Class      string           `json:"class"` // create, fast-forward, present, behind, replay, take, conflict, skipped, purged, absent
	TargetHead string           `json:"targetHead,omitempty"`
	BundleHead string           `json:"bundleHead"`
	Ancestor   string           `json:"ancestor,omitempty"`
	Steps      int              `json:"steps,omitempty"`
	Expected   []string         `json:"expected,omitempty"`
	Conflicts  []merge.Conflict `json:"conflicts,omitempty"`
	Unresolved bool             `json:"unresolved,omitempty"`
	Resolution Resolution       `json:"resolution,omitempty"`
	Upstream   *UpstreamReport  `json:"upstream,omitempty"`
	Rewritten  []RewrittenRef   `json:"rewritten,omitempty"`
	Note       string           `json:"note,omitempty"`
}

// UpstreamReport is what an import appends to a snapshot document's
// upstream chain.
type UpstreamReport struct {
	Target   string `json:"target"`             // upstream "ns/name"
	Class    string `json:"class"`              // create, append, restore, delete, unchanged, absent
	Previous string `json:"previous,omitempty"` // the upstream head before the import
	Head     string `json:"head,omitempty"`     // the upstream head after it
}

// RewrittenRef is a pinned reference rewritten to an upstream revision path.
type RewrittenRef struct {
	Pointer string `json:"pointer"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// UndeclaredRef is a string in a snapshot document that looks like a pinned
// reference but isn't declared with x-ref, so it can't be rewritten.
type UndeclaredRef struct {
	Doc     string `json:"doc"`
	Pointer string `json:"pointer"`
	Value   string `json:"value"`
	// Bundled: it points at a snapshot document of this bundle, so it
	// would have needed rewriting.
	Bundled bool `json:"bundled,omitempty"`
}

// BatchReport is one batch, dry-run or submitted.
type BatchReport struct {
	NS        string         `json:"ns"`
	Upstream  bool           `json:"upstream,omitempty"`
	Part      int            `json:"part"`  // 1-based within the namespace
	Parts     int            `json:"parts"` // batches for the namespace
	Resources []string       `json:"resources"`
	Steps     int            `json:"steps"`
	Size      int            `json:"size"` // bytes of canonical patch sets
	Source    map[string]any `json:"source"`
	DryRun    string         `json:"dryRun,omitempty"` // ok, deferred, failed; "" if not dry-run (only a namespace's first batch is, its first item if the import creates it, and those that move heads the target had)
	Status    int            `json:"status,omitempty"` // submit status
	NSID      string         `json:"ns_id,omitempty"`
	Error     string         `json:"error,omitempty"`
	Failures  []string       `json:"failures,omitempty"`
	Uploaded  int            `json:"uploaded,omitempty"` // blobs uploaded before it (§G.4.4)
	Copied    int            `json:"copied,omitempty"`   // blobs copied with Blob-From before it
	// ViaSource counts the blobs its local source made available, which
	// needed no copy (§7.8, §G.4.4).
	ViaSource int `json:"viaSource,omitempty"`
	// PacedBy is the bucket a backfill paces the namespace's batches by
	// (§6.6): "allowance", the importer's own, at its full rate, else
	// "ratePerPrincipal" or "ratePerNamespace", whichever is lower, at
	// Pace of it. Rate is that pace, in items per second.
	PacedBy string  `json:"pacedBy,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
}

// Report is the outcome of an import or a dry run.
type Report struct {
	Origin       string          `json:"origin"`
	Digest       string          `json:"digest"`
	TargetOrigin string          `json:"targetOrigin"`
	Mode         ImportMode      `json:"mode"`
	DryRun       bool            `json:"dryRun"`
	Docs         []*DocReport    `json:"docs"`
	Undeclared   []UndeclaredRef `json:"undeclared,omitempty"`
	Only         []string        `json:"only,omitempty"` // the source namespaces imported, if not all (ImportOptions.Only)
	Create       []string        `json:"createNamespaces,omitempty"`
	Order        []string        `json:"order"`
	Batches      []*BatchReport  `json:"batches"`
	Notes        []string        `json:"notes,omitempty"`
	Timings      Timings         `json:"timings"`
}

// Timings say where an import's time went, in seconds.
type Timings struct {
	Total float64 `json:"total"`
	// Planning is the time before the first batch request or blob upload:
	// reading the bundle and the target, classifying and splitting.
	Planning float64 `json:"planning"`
	// Blobs is the time blob uploads and copies took (§G.4.4).
	Blobs float64 `json:"blobs"`
	// Batches is the time Requests batch requests took, DryRuns of them dry
	// runs: mostly the server's.
	Batches  float64 `json:"batches"`
	Requests int     `json:"requests"`
	DryRuns  int     `json:"dryRuns"`
	// Paced is the time a backfill waited between batches (§G.4.4), and
	// RateLimited the time spent waiting after 429s (§6.6).
	Paced       float64 `json:"paced"`
	RateLimited float64 `json:"rateLimited"`
}

// Doc returns the report of a source document.
func (r *Report) Doc(key string) *DocReport {
	for _, d := range r.Docs {
		if d.Doc == key {
			return d
		}
	}
	return nil
}

// Unresolved lists documents with conflicts that need a resolution.
func (r *Report) Unresolved() []*DocReport {
	var out []*DocReport
	for _, d := range r.Docs {
		if d.Unresolved {
			out = append(out, d)
		}
	}
	return out
}

// ErrConflicts is returned (with the report) when some document needs a
// resolution; nothing was written.
var ErrConflicts = errors.New("import: unresolved conflicts; resolve them (skip, take or replay) and import again")

// CheckError reports a bundle that fails its checks against the target
// (requires, external): nothing was written.
type CheckError struct{ Problems []string }

func (e *CheckError) Error() string {
	return "import: the bundle doesn't fit the target: " + strings.Join(e.Problems, "; ")
}

// TooLargeError reports an atomic batch over the namespace's limits.
type TooLargeError struct {
	NS          string
	Items, Size int
	Err         error
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("import: the atomic batch into %s (%d items, %d bytes of patch sets) is over the namespace's batch limits (%v). "+
		"An import that must land at once runs as one batch under an allowance (§6.6): an administrator adds "+
		`{"sub", "kid", "bucket": {"rate", "burst"}, "itemsPerBatch", "batchSize"} for the importer's principal to /allowances of %s, `+
		"within the deployment maximums (1000 items and 16 MiB unless raised with patchlog serve -max-items-per-batch and -max-batch-size). "+
		"Otherwise import in backfill mode (-pace), which splits the import into batches that fit and is not atomic.",
		e.NS, e.Items, e.Size, e.Err, e.NS)
}

func (e *TooLargeError) Unwrap() error { return e.Err }

// --- internal model ------------------------------------------------------

type bdoc struct {
	key, ns, name string // source
	tns           string // target namespace
	info          DocInfo
	requires      string
	lines         []*Line
	idx           map[string]int
	snap          *Line
	pinKeys       map[string]bool // over-approximated pinned references, schemas' included (source keys)
	rep           *DocReport
	requiresBad   bool             // requires isn't in the target's chain (the target moved on)
	blobs         map[string]*Line // its blob lines, by blob id (§G.4.1)
	refd          map[string]bool  // blobs its lines read so far reference
	// The snapshot document is gone once planUpstream has replaced it with
	// its rewritten form (snapDoc). snapBlobs, when load keeps the
	// document's canonical form, are the blobs its genesis revision brings
	// (stepBlobs of it), as load found them, rewritten or not (a rewrite
	// changes strings that pin, never a blob reference); nil otherwise.
	snapGone  bool
	snapBlobs []string
}

type item struct {
	d        *bdoc
	ns, name string // target
	upstream bool
	ifMatch  string
	ifNone   bool
	steps    []client.Step
	expected []string
	sizes    []int      // per step, its patch set's canonical size (stepSizes)
	sameIDs  bool       // the ids are the source's (fast-forward): source.ids follows them
	srcID    string     // source.ids member otherwise
	blobs    [][]string // per step, the blobs it may bring in (blobs.go)
}

type upPlan struct {
	ns, name string
	prev     string // head before ("" absent)
	prevLive bool
	purged   bool
	it       *item // nil if unchanged
	head     string
	headDel  bool
	added    []chainEntry // what this import adds to the chain
	chain    []chainEntry // the upstream chain after this import (truncated at a horizon), once loaded (upChain)
	loaded   bool
	newDoc   any // the rewritten snapshot, parsed, only for a take (planSnapshotTarget)
}

type chainEntry struct {
	id   string
	step client.Step
	size int // the step's canonical size, -1 until known
	// The blobs the step may bring in (stepBlobs), if hasBlobs: an upstream
	// item and the target's fast-forward share the step, and its blobs.
	blobs    []string
	hasBlobs bool
}

type point struct{ baseU, baseT string }

type node struct {
	ns       string
	srcNS    string
	upstream bool
	items    []*item
	deps     map[string]bool
	missing  bool
	batches  []*batch
}

type batch struct {
	n     *node
	parts []part
	size  int
	rep   *BatchReport
	keys  map[string]bool // its items' source documents (keysOf)
}

type part struct {
	it       *item
	from, to int
}

type importer struct {
	c      *client.Client
	opt    ImportOptions
	h      *Header
	digest string
	docs   map[string]*bdoc
	keys   []string // the documents the import brings, in order
	rep    *Report

	// A partial import (partial.go): the source namespaces it brings; what
	// its documents reference of those it leaves out (source key → the
	// pinned revisions, "" for a live reference); the snapshot documents
	// left out that they pin; and how many it leaves out.
	only     map[string]bool
	outRefs  map[string]map[string]bool
	held     map[string]bool
	heldKeys []string
	left     int

	local bool      // the bundle's origin is the target's own
	start time.Time // when the import began (Timings)

	origin  string // the target deployment's origin, for signing
	signErr error  // a step that request couldn't sign

	up      map[string]*upPlan
	points  map[string]map[string]point // target ns → "srcNS/name" → point
	schemas map[string]any
	nodes   map[string]*node
	order   []*node

	// §G.5.1 (access.go).
	create  map[string]any  // target ns → the document it is created with
	sealedT map[string]bool // target ns is (or is created) sealed
	bump    map[string]int  // new e2e target → the epoch to move it to

	// Target heads (heads.go): the resources looked up per namespace, and
	// the namespaces' listings (nil: looked up one by one).
	want   map[string][]string
	listed map[string]*listing

	sent  map[string]time.Time // "ns/name/bid" → when the blob was last uploaded or copied there
	draws map[string][]draw    // target ns → what the import drew there since its last paced batch
	// mu guards the importer's state while batches run concurrently
	// (concurrent.go), when concurrent is set.
	mu         sync.Mutex
	concurrent bool
	gates      map[string]*gate // target ns → its concurrent batches' pacing
	run        *runner          // while batches run concurrently
	// Wall time covered by paced waits, batch requests and blob requests,
	// which overlap when batches run concurrently.
	paced, batching, uploading span

	// noSource marks target namespaces whose batches' local source didn't
	// make their blobs available (the importer can't read the source
	// unrestricted, §7.5): their blobs are copied or uploaded instead.
	noSource map[string]bool
}

// Import imports a bundle into the deployment c talks to (§G.4.4). It
// returns the report even with an error, when there is one.
func Import(ctx context.Context, c *client.Client, open Opener, opt ImportOptions) (*Report, error) {
	if opt.Mode != Atomic && opt.Mode != Backfill {
		return nil, fmt.Errorf("import: choose a mode: %q (one batch per namespace, under an allowance if large) or %q (split and paced)", Atomic, Backfill)
	}
	if opt.Pace <= 0 {
		opt.Pace = 0.5
	}
	if opt.Pace > 1 {
		return nil, fmt.Errorf("import: pace must be a fraction of the namespace rate, in (0, 1]")
	}
	if opt.UpstreamSuffix == "" {
		opt.UpstreamSuffix = "-upstream"
	}
	if opt.MaxRetries <= 0 {
		opt.MaxRetries = 5
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = defaultConcurrency
	}
	if opt.Sleep == nil {
		opt.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	im := &importer{c: c, opt: opt, docs: map[string]*bdoc{}, up: map[string]*upPlan{}, start: opt.Now(),
		points: map[string]map[string]point{}, schemas: map[string]any{}, nodes: map[string]*node{}, listed: map[string]*listing{}, gates: map[string]*gate{}}
	if len(opt.Only) > 0 {
		im.only, im.outRefs, im.held = map[string]bool{}, map[string]map[string]bool{}, map[string]bool{}
		for _, ns := range opt.Only {
			im.only[ns] = true
		}
	}
	if err := im.load(open); err != nil {
		return nil, err
	}
	im.leaveOut()
	im.rep = &Report{Origin: im.h.Origin, Digest: im.digest, Mode: opt.Mode, DryRun: opt.DryRun}
	if im.only != nil {
		for ns := range im.only {
			im.rep.Only = append(im.rep.Only, ns)
		}
		sort.Strings(im.rep.Only)
		im.rep.Notes = append(im.rep.Notes, fmt.Sprintf("imports namespaces %s only, leaving out %d documents; checked in the target first: the %d of them its documents reference",
			strings.Join(im.rep.Only, ", "), im.left, len(im.outRefs)+len(im.held)))
	}
	defer im.timed(&im.rep.Timings.Total, im.start)
	to, err := c.Origin(ctx)
	if err != nil {
		return nil, fmt.Errorf("import: target origin: %w", err)
	}
	im.rep.TargetOrigin = to
	im.origin = to
	if to == im.h.Origin {
		im.local = true
		im.rep.Notes = append(im.rep.Notes, "the bundle comes from this deployment: batch sources carry no origin, so the server checks source.at against source.ns (§7.5)")
	}
	if err := im.checkAccess(ctx); err != nil {
		// Its reads are the import's first requests to the target
		// namespaces (existing).
		if client.IsAuth(err) {
			err = fmt.Errorf("%w; the import's grant needs read and write (create, append, …) in every target namespace, from a key it lists, "+
				"and an allowance there for speed (§6.6); an operator grant only creates namespaces (§C.4), so create missing ones first", err)
		}
		return im.rep, err
	}
	if err := im.check(ctx); err != nil {
		return im.rep, err
	}
	if err := im.plan(ctx); err != nil {
		return im.rep, err
	}
	if err := im.execute(ctx); err != nil {
		return im.rep, err
	}
	return im.rep, nil
}

// load reads and verifies the whole bundle (§G.4.1) before anything else.
// The content is kept in memory: it becomes batch requests, which are held
// in memory anyway.
func (im *importer) load(open Opener) error {
	r, err := open()
	if err != nil {
		return err
	}
	defer r.Close()
	rd, err := NewReader(r)
	if err != nil {
		return err
	}
	if !im.opt.keepTrees {
		rd.keepDocCanon()
	}
	rd.parallel(runtime.GOMAXPROCS(0))
	defer rd.Close()
	im.h = rd.Header()
	for ns := range im.only {
		if _, ok := im.h.At[ns]; !ok {
			return fmt.Errorf("import: the bundle has no namespace %s to import", ns)
		}
	}
	targets := map[string]string{}
	for k, info := range im.h.Docs {
		ns, name, _ := SplitKey(k)
		d := &bdoc{key: k, ns: ns, name: name, tns: im.mapNS(ns), info: info, requires: im.h.Requires[k],
			idx: map[string]int{}, pinKeys: map[string]bool{}, blobs: map[string]*Line{}, refd: map[string]bool{}}
		d.rep = &DocReport{Doc: k, Target: Key(d.tns, name), History: info.History, BundleHead: info.Head}
		im.docs[k] = d
		if prev, ok := targets[d.tns]; ok && prev != ns {
			return fmt.Errorf("import: namespaces %s and %s both map to %s", prev, ns, d.tns)
		}
		targets[d.tns] = ns
		if !client.ValidNSName(d.tns) {
			return fmt.Errorf("import: invalid target namespace %q", d.tns)
		}
	}
	for {
		l, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if l.IsGrant() {
			// Grant lines (§G.4.1) are provenance of the bundle's
			// signatures; an import never re-sends them (§C.3.1).
			continue
		}
		d := im.docs[l.Key()]
		if l.IsBlob() {
			// Its id was recomputed by the Reader (§G.4.1); it must come
			// before the first line that references it.
			if d.refd[l.Blob] {
				return &Error{Key: l.Key(), Msg: fmt.Sprintf("blob %s comes after a line that references it (§G.4.1)", l.Blob)}
			}
			d.blobs[l.Blob] = l
			continue
		}
		if l.IsSnapshot() {
			d.snap = l
			if !l.Deleted {
				im.scanRefs(d, l.Doc)
				refs := blobRefs(l.Doc)
				if !schemaDoc(l.Doc) { // docBlobs
					for _, r := range refs {
						d.refd[r.bid] = true
					}
				}
				if l.docCanon != nil {
					// The import holds the document's canonical form instead
					// of its tree, which takes 1.3 to 5 times the memory: the
					// steps that read it parse it again (snapDoc). Then the
					// blobs a genesis revision of it brings need no parse
					// (planUpstream).
					d.snapBlobs = make([]string, len(refs))
					for i, r := range refs {
						d.snapBlobs[i] = r.bid
					}
					l.Doc = nil
				}
			}
		} else {
			d.idx[l.ID] = len(d.lines)
			d.lines = append(d.lines, l)
			im.scanRefs(d, l.Patches)
			if l.Kind == "rev" {
				for _, b := range mentions(client.PatchStep(l.Patches)) {
					d.refd[b] = true
				}
			}
		}
	}
	im.digest = rd.Digest()
	for k := range im.docs {
		im.keys = append(im.keys, k)
	}
	sort.Strings(im.keys)
	for _, d := range im.docs {
		if d.info.History == Snapshot {
			u := im.upstreamNS(d.ns)
			if !client.ValidNSName(u) {
				return fmt.Errorf("import: upstream namespace name %q is invalid", u)
			}
			if src, ok := targets[u]; ok {
				return fmt.Errorf("import: %s is both the upstream of %s and the target of %s", u, d.ns, src)
			}
		}
	}
	return nil
}

// snapHeld is the snapshot document as the import holds it: its canonical
// form (jsonv.Raw), which load keeps, or with keepTrees the Reader's tree.
// It fails for a deleted or left-out snapshot, and once planUpstream has
// replaced the document with its rewritten form (dropSnap), rather than
// answer null: a document of JSON null is held as one.
func (d *bdoc) snapHeld() (any, error) {
	l := d.snap
	switch {
	case l == nil || l.Deleted:
		return nil, fmt.Errorf("%s: no snapshot document (deleted or left out)", d.key)
	case l.docCanon != nil:
		return l.docCanon, nil
	case d.snapGone:
		return nil, fmt.Errorf("%s: the snapshot document is no longer held: planning replaced it with its rewritten form", d.key)
	}
	return l.Doc, nil
}

// snapDoc is the snapshot document as a tree, for the planning steps that
// read it: parsed again from its canonical form, a copy of its own for
// each call, which they hold one at a time; or with keepTrees the line's
// tree.
func (d *bdoc) snapDoc() (any, error) {
	v, err := d.snapHeld()
	if err != nil {
		return nil, err
	}
	return parsedDoc(v)
}

// dropSnap lets go of the snapshot document, which its rewritten form
// replaces (rewrite): snapDoc fails from then on.
func (d *bdoc) dropSnap() {
	d.snap.Doc, d.snap.docCanon, d.snapGone = nil, nil, true
}

// parsedDoc is a document as a tree: one held as its canonical form
// (jsonv.Raw) parsed, any other as it is.
func parsedDoc(v any) (any, error) {
	if r, ok := v.(jsonv.Raw); ok {
		return jsonv.Parse(r)
	}
	return v, nil
}

// scanRefs over-approximates what a document pins, for ordering only:
// every string of the reference form that names a revision (including
// $schema and $ref).
func (im *importer) scanRefs(d *bdoc, v any) {
	brought := im.only != nil && im.only[d.ns] // a partial import's (partial.go)
	walkStrings(v, func(_ *strPath, s string) {
		r, ok := annot.ParseRefString(s)
		if !ok {
			return
		}
		if r.Rev != "" {
			d.pinKeys[Key(r.NS, r.Name)] = true
		}
		if brought {
			im.noteOut(r)
		}
	})
}

func (im *importer) mapNS(ns string) string {
	if t, ok := im.opt.NSMap[ns]; ok && t != "" {
		return t
	}
	return ns
}

func (im *importer) upstreamNS(srcNS string) string { return srcNS + im.opt.UpstreamSuffix }

// --- checks against the target -------------------------------------------

// inChain reports whether id is head or one of its ancestors in ns/name.
func (im *importer) inChain(ctx context.Context, ns, name, head, id string) (bool, error) {
	if head == id {
		return true, nil
	}
	// One page answers it: ancestry is decided for the whole range on
	// every page (§7.1 Paging).
	_, _, err := im.c.LogPage(ctx, ns, name, head, id)
	switch {
	case err == nil:
		return true, nil
	case client.IsPruned(err):
		return true, nil // ancestry is decided before pruning (§7.1)
	case client.IsNotFound(err):
		return false, nil
	}
	return false, err
}

func (im *importer) check(ctx context.Context) error {
	var problems []string
	for _, k := range im.keys {
		d := im.docs[k]
		if d.requires == "" {
			continue
		}
		th, err := im.head(ctx, d.tns, d.name)
		if err != nil {
			return err
		}
		switch th.State {
		case client.NotFound, client.Purged:
			problems = append(problems, fmt.Sprintf("requires %s: %s is %s in the target", d.requires, d.rep.Target, th.State))
			continue
		}
		ok, err := im.inChain(ctx, d.tns, d.name, th.ID, d.requires)
		if err != nil {
			return err
		}
		d.requiresBad = !ok
	}
	out, err := im.checkOut(ctx)
	if err != nil {
		return err
	}
	problems = append(problems, out...)
	for _, e := range im.h.External {
		ext, _ := ParseExternal(e)
		tns := im.mapNS(ext.NS)
		if ext.Rev != "" {
			if _, err := im.c.Doc(ctx, tns, ext.Name, ext.Rev); err != nil {
				if client.IsNotFound(err) || client.IsGone(err) || client.IsPruned(err) {
					problems = append(problems, fmt.Sprintf("external %s: revision %s is not in the target", e, ext.Rev))
					continue
				}
				return err
			}
			continue
		}
		th, err := im.c.Head(ctx, tns, ext.Name)
		if err != nil {
			return err
		}
		if th.State != client.Live {
			problems = append(problems, fmt.Sprintf("external %s: %s is %s in the target", e, Key(tns, ext.Name), th.State))
		}
	}
	if len(problems) > 0 {
		return &CheckError{Problems: problems}
	}
	return nil
}

// --- documents and states ------------------------------------------------

// targetState returns the document at id in ns/name: for a tombstone, the
// last live document with live false.
func (im *importer) targetState(ctx context.Context, ns, name, id string) (any, bool, error) {
	d, err := im.c.Doc(ctx, ns, name, id)
	if err == nil {
		return d.Value, true, nil
	}
	if !client.IsGone(err) {
		return nil, false, err
	}
	es, err := im.c.Log(ctx, ns, name, id, "")
	if err != nil {
		return nil, false, err
	}
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Kind == "rev" {
			d, err := im.c.Doc(ctx, ns, name, es[i].ID)
			if err != nil {
				return nil, false, err
			}
			return d.Value, false, nil
		}
	}
	return nil, false, nil
}

// bundleState folds a full document's lines up to id.
func (im *importer) bundleState(ctx context.Context, d *bdoc, id string) (any, bool, error) {
	var doc any
	live := false
	var err error
	if d.requires != "" {
		if doc, live, err = im.targetState(ctx, d.tns, d.name, d.requires); err != nil {
			return nil, false, err
		}
		if id == d.requires {
			return doc, live, nil
		}
	}
	for _, l := range d.lines {
		doc, live, err = verify.Replay(doc, live, []client.LogEntry{l.LogEntry()})
		if err != nil {
			return nil, false, err
		}
		if l.ID == id {
			return doc, live, nil
		}
	}
	return nil, false, fmt.Errorf("%s: %s is not in the bundle", d.key, id)
}

// stepsOfLines are the steps that write history lines, each with the
// line's gesture and undoes, which a bundle carries with "authors": true
// (§G.4.1), as a merge carries them (§F.3).
func stepsOfLines(ls []*Line) []client.Step {
	out := make([]client.Step, len(ls))
	for i, l := range ls {
		if l.Kind == "tombstone" {
			out[i] = client.DeleteStep()
		} else {
			out[i] = client.PatchStep(l.Patches)
		}
		out[i] = out[i].WithGesture(l.Gesture, l.Undoes)
	}
	return out
}

// stepsOfLog are the steps that write log entries, with their gestures
// (§F.3).
func stepsOfLog(es []client.LogEntry) []client.Step {
	out := make([]client.Step, len(es))
	for i, e := range es {
		if e.Kind == "tombstone" {
			out[i] = client.DeleteStep()
		} else {
			out[i] = client.Step{Patches: e.Patches}
		}
		out[i] = out[i].WithGesture(e.Gesture, e.Undoes)
	}
	return out
}

// expectedIDs chains the ids steps produce on parent ("" = genesis), and
// sizes them: each step's patch set's canonical length (0 for a delete),
// by which batches are split. Each patch set is serialised once.
func expectedIDs(parent string, steps []client.Step) ([]string, []int, error) {
	out := make([]string, 0, len(steps))
	sizes := make([]int, len(steps))
	prev := parent
	for i, s := range steps {
		var id string
		var err error
		if s.Delete {
			id, err = client.ExpectedTombstone(prev)
		} else {
			if s.Patches == nil {
				return nil, nil, fmt.Errorf("a patch set the import needs was pruned")
			}
			var canon []byte
			if canon, err = canonical(s.Patches); err == nil {
				sizes[i] = len(canon)
				id, err = revisionID(prev, canon)
			}
		}
		if err != nil {
			return nil, nil, err
		}
		out = append(out, id)
		prev = id
	}
	return out, sizes, nil
}

// canonical serialises a patch set (§3.3), which is never a jsonv.Raw
// itself (errRawPatchSet).
func canonical(patches any) ([]byte, error) {
	if _, ok := patches.(jsonv.Raw); ok {
		return nil, errRawPatchSet
	}
	if canon, ok := jsonv.CanonicalOf(patches); ok {
		return canon, nil
	}
	v, err := client.Value(patches)
	if err != nil {
		return nil, err
	}
	return jsonv.Canonical(v), nil
}

// errRawPatchSet refuses a patch set that is a jsonv.Raw itself. The
// import never makes one: a snapshot document held as its canonical form
// is a value inside a patch set (client.GenesisPatches), whose ops stay
// readable. The code that reads a patch set's ops would find none in one
// (nonced, patchBlobs and sealedBlobs, sides, canonical), and nonced runs
// before the ids are computed, so the id checks wouldn't catch a document
// written without them.
var errRawPatchSet = errors.New("import: a patch set held as canonical bytes (only a value inside one may be)")

// noRawPatchSet panics on a patch set that is a jsonv.Raw (errRawPatchSet),
// for code without an error to return: the import's own steps never are.
func noRawPatchSet(patches any) {
	if _, ok := patches.(jsonv.Raw); ok {
		panic(errRawPatchSet)
	}
}

// revisionID is the id of the revision of canonical patches on parent ("" =
// genesis, §3.3).
func revisionID(parent string, canon []byte) (string, error) {
	if parent == "" {
		return ids.Revision(nil, canon).String(), nil
	}
	p, err := ids.Parse(parent)
	if err != nil {
		return "", err
	}
	return ids.Revision(&p, canon).String(), nil
}

// stepSizes are the canonical sizes of an item's steps, computed once.
func (it *item) stepSizes() []int {
	if it.sizes == nil {
		it.sizes = make([]int, len(it.steps))
		for i, s := range it.steps {
			if !s.Delete {
				if canon, err := canonical(s.Patches); err == nil {
					it.sizes[i] = len(canon)
				}
			}
		}
	}
	return it.sizes
}

// takeSteps turn the target's document into the bundle's version; in a
// sealed target, ignoring the $nonce and setting a fresh one (§E.2.5).
func (im *importer) takeSteps(ns string, tdoc any, tlive bool, bdoc any, blive bool) []client.Step {
	if im.sealedT[ns] {
		return nonced(takeSteps(withoutNonce(tdoc), tlive, withoutNonce(bdoc), blive))
	}
	return takeSteps(tdoc, tlive, bdoc, blive)
}

// takeSteps turn the target's document into the bundle's version.
func takeSteps(tdoc any, tlive bool, bdoc any, blive bool) []client.Step {
	switch {
	case blive && tlive:
		d := merge.Diff(tdoc, bdoc)
		if len(d) == 0 {
			return nil
		}
		return []client.Step{client.PatchStep(d)}
	case blive: // restore
		return []client.Step{client.PatchStep(orEmpty(merge.Diff(tdoc, bdoc)))}
	case tlive:
		return []client.Step{client.DeleteStep()}
	}
	return nil
}

func orEmpty(d []any) []any {
	if d == nil {
		return []any{}
	}
	return d
}

func conflict(kind, msg string, paths ...string) merge.Conflict {
	return merge.Conflict{Kind: kind, Message: msg, Paths: paths}
}

func toPointers(ss []string) []pointer.Pointer {
	out := make([]pointer.Pointer, 0, len(ss))
	for _, s := range ss {
		if p, err := pointer.Parse(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// sides compares two sides' steps since a common ancestor (§F.3): the
// overlapping writes under the array rule, and the delete-versus-change
// cases.
func sides(anc any, ancExists bool, incoming, own []client.Step, ownDeleted bool) []merge.Conflict {
	var out []merge.Conflict
	// merge.Writes reads the values the ops write, and an upstream
	// genesis holds its document as its canonical form.
	incoming, err := expandSteps(incoming)
	if err != nil {
		return []merge.Conflict{conflict(merge.ConflictUnreadable, fmt.Sprintf("writes could not be computed: %v", err))}
	}
	iw, err1 := merge.Writes(anc, ancExists, incoming)
	ow, err2 := merge.Writes(anc, ancExists, own)
	if err1 != nil || err2 != nil {
		return []merge.Conflict{conflict(merge.ConflictUnreadable, fmt.Sprintf("writes could not be computed: %v", errors.Join(err1, err2)))}
	}
	has := func(ss []client.Step, del bool) bool {
		for _, s := range ss {
			if s.Delete == del {
				return true
			}
		}
		return false
	}
	incomingDeletes := len(incoming) > 0 && incoming[len(incoming)-1].Delete
	if incomingDeletes && has(own, false) {
		out = append(out, conflict(merge.ConflictDeleteVsChange, "the bundle deletes a document the target changed since the common ancestor"))
	}
	if ownDeleted && has(incoming, false) {
		out = append(out, conflict(merge.ConflictChangeVsDelete, "the bundle changes a document the target deleted since the common ancestor"))
	}
	if ov := merge.Overlaps(toPointers(iw), toPointers(ow)); len(ov) > 0 {
		out = append(out, conflict(merge.ConflictOverlap, "both sides wrote these paths since the common ancestor", ov...))
	}
	return out
}

// expandSteps are steps whose patch sets hold no jsonv.Raw, for code that
// reads their values. A patch set that is a Raw itself is refused
// (errRawPatchSet).
func expandSteps(ss []client.Step) ([]client.Step, error) {
	out := append([]client.Step(nil), ss...)
	for i := range out {
		noRawPatchSet(out[i].Patches)
		p, err := jsonv.Expand(out[i].Patches)
		if err != nil {
			return nil, err
		}
		out[i].Patches = p
	}
	return out, nil
}

// --- planning --------------------------------------------------------------

func (im *importer) plan(ctx context.Context) error {
	var items []*item
	// Full-history documents.
	for _, k := range im.keys {
		d := im.docs[k]
		if d.info.History != Full {
			continue
		}
		it, err := im.planFull(ctx, d)
		if err != nil {
			return fmt.Errorf("import: %s: %w", k, err)
		}
		if it != nil {
			items = append(items, it)
		}
	}
	// Snapshot documents: upstream first, in pinned-reference order, so
	// every rewrite knows its target's upstream id.
	order, refs, err := im.snapshotOrder(ctx)
	if err != nil {
		return err
	}
	pinned := im.heldPinned(refs)
	var held []string
	for _, d := range order {
		if im.held[d.key] && !pinned[d.key] {
			continue // nothing the import writes is rewritten to it
		}
		it, err := im.planUpstream(ctx, d, refs[d.key])
		if err != nil {
			return fmt.Errorf("import: %s upstream: %w", d.key, err)
		}
		if im.held[d.key] {
			// Left out, and pinned: its upstream must hold it already.
			if p := im.heldProblem(d, it); p != "" {
				held = append(held, p)
			}
			continue
		}
		if it != nil {
			items = append(items, it)
		}
	}
	if len(held) > 0 {
		return &CheckError{Problems: held}
	}
	for _, d := range order {
		if im.held[d.key] {
			continue
		}
		it, err := im.planSnapshotTarget(ctx, d)
		if err != nil {
			return fmt.Errorf("import: %s: %w", d.key, err)
		}
		if it != nil {
			items = append(items, it)
		}
	}
	for _, k := range im.keys {
		d := im.docs[k]
		d.rep.Unresolved = len(d.rep.Conflicts) > 0 && d.rep.Resolution == ""
		im.rep.Docs = append(im.rep.Docs, d.rep)
	}
	for _, it := range items {
		if it.expected == nil {
			exp, sizes, err := expectedIDs(it.ifMatch, it.steps)
			if err != nil {
				return fmt.Errorf("import: %s/%s: %w", it.ns, it.name, err)
			}
			it.expected, it.sizes = exp, sizes
		}
		exp := it.expected
		if it.blobs == nil {
			// Unless planUpstream knew them: an upstream item's, and a
			// fast-forward's along what it adds.
			it.blobs = make([][]string, len(it.steps))
			for i, st := range it.steps {
				it.blobs[i] = stepBlobs(st)
			}
		}
		if !it.upstream {
			it.d.rep.Steps = len(it.steps)
			it.d.rep.Expected = exp
		}
	}
	im.buildNodes(items)
	return nil
}

func (im *importer) planFull(ctx context.Context, d *bdoc) (*item, error) {
	r := d.rep
	th, err := im.head(ctx, d.tns, d.name)
	if err != nil {
		return nil, err
	}
	B, H := th.ID, d.info.Head
	r.TargetHead = B
	mk := func(class string, after int, parent string) *item {
		r.Class = class
		it := &item{d: d, ns: d.tns, name: d.name, ifMatch: parent, ifNone: parent == "", sameIDs: true,
			steps: stepsOfLines(d.lines[after+1:])}
		return it
	}
	switch {
	case th.State == client.Purged:
		r.Class = "purged"
		r.Conflicts = append(r.Conflicts, conflict(ConflictPurged, "purged in the target"))
		r.Resolution = ResolveSkip // nothing can be written; reported only
		r.Note = "purged in the target: not imported"
		return nil, nil
	case B == H:
		r.Class = "present"
		return nil, nil
	case th.State == client.NotFound:
		if d.requires != "" {
			return nil, fmt.Errorf("requires %s but the target has no %s", d.requires, r.Target) // caught by check
		}
		return mk("create", -1, ""), nil
	}
	if i, ok := d.idx[B]; ok {
		return mk("fast-forward", i, B), nil
	}
	if B == d.requires && !d.requiresBad {
		return mk("fast-forward", -1, B), nil
	}
	behind, err := im.inChain(ctx, d.tns, d.name, B, H)
	if err != nil {
		return nil, err
	}
	if behind {
		r.Class = "behind"
		r.Note = "the target already has the bundle's head, and more"
		return nil, nil
	}

	// A different history: conflict.
	r.Class = "conflict"
	if d.requiresBad {
		r.Conflicts = append(r.Conflicts, conflict(ConflictRequires, "the target moved on along another line: requires "+d.requires+" is not in its chain"))
	} else {
		r.Conflicts = append(r.Conflicts, conflict(ConflictDiverged, "the target has a different history"))
	}
	if im.h.AccessOf(d.ns) == AccessE2E {
		// Ciphertext can't be compared, and sealed patch sets bind their
		// parent, so they can't be replayed elsewhere (§E.3.1, §F.8).
		r.Conflicts = append(r.Conflicts, conflict(merge.ConflictUnreadable, "e2e content: only a client holding the keys can compare it and merge it by re-encrypting (§F.8)"))
		switch res := im.opt.Resolutions[d.key]; res {
		case "":
		case ResolveSkip:
			r.Resolution, r.Class = res, "skipped"
		default:
			return nil, fmt.Errorf("%s can't resolve e2e content: skip it, or merge it in a client holding the keys (§F.8)", res)
		}
		return nil, nil
	}
	tlog, err := im.c.Log(ctx, d.tns, d.name, B, "")
	if client.IsPruned(err) {
		tlog, err = im.c.Log(ctx, d.tns, d.name, B, client.Horizon(err))
	}
	if err != nil {
		return nil, err
	}
	tidx := map[string]int{}
	for i, e := range tlog {
		tidx[e.ID] = i
	}
	anc, ai := "", -2
	for i := len(d.lines) - 1; i >= 0; i-- {
		if _, ok := tidx[d.lines[i].ID]; ok {
			anc, ai = d.lines[i].ID, i
			break
		}
	}
	if anc == "" && d.requires != "" {
		if _, ok := tidx[d.requires]; ok {
			anc, ai = d.requires, -1
		}
	}
	var incoming []client.Step
	if anc != "" {
		r.Ancestor = anc
		incoming = stepsOfLines(d.lines[ai+1:])
		ancDoc, _, err := im.targetState(ctx, d.tns, d.name, anc)
		if err != nil {
			return nil, err
		}
		own := stepsOfLog(tlog[tidx[anc]+1:])
		r.Conflicts = append(r.Conflicts, sides(ancDoc, ancDoc != nil, incoming, own, th.State == client.Tombstoned)...)
	} else {
		r.Conflicts = append(r.Conflicts, conflict(merge.ConflictNoCommonAncestor, "the bundle and the target have no common ancestor"))
	}
	switch res := im.opt.Resolutions[d.key]; res {
	case "":
		return nil, nil
	case ResolveSkip:
		r.Resolution, r.Class = res, "skipped"
		return nil, nil
	case ResolveReplay:
		if anc == "" {
			r.Note = "replay needs a common ancestor"
			return nil, nil
		}
		r.Resolution, r.Class = res, "replay"
		return &item{d: d, ns: d.tns, name: d.name, ifMatch: B, steps: incoming, srcID: H}, nil
	case ResolveTake:
		r.Resolution, r.Class = res, "take"
		tdoc, tlive, err := im.targetState(ctx, d.tns, d.name, B)
		if err != nil {
			return nil, err
		}
		bdoc, blive, err := im.bundleState(ctx, d, H)
		if err != nil {
			return nil, err
		}
		steps := im.takeSteps(d.tns, tdoc, tlive, bdoc, blive)
		if len(steps) == 0 {
			r.Note = "the target's document already equals the bundle's"
			return nil, nil
		}
		return &item{d: d, ns: d.tns, name: d.name, ifMatch: B, steps: steps, srcID: H}, nil
	default:
		return nil, fmt.Errorf("unknown resolution %q", res)
	}
}

// schemaLoader loads schema revisions for x-ref walks: from the bundle's
// full documents, else from the target (where $schema paths resolve, or
// drafts in branches of their namespaces do).
func (im *importer) schemaLoader(ctx context.Context) schema.Loader {
	return func(ref schema.Ref) (any, error) {
		p := ref.Path()
		if v, ok := im.schemas[p]; ok {
			return v, nil
		}
		if d, ok := im.docs[Key(ref.NS, ref.Name)]; ok && d.info.History == Full {
			if _, in := d.idx[ref.Rev]; in {
				v, _, err := im.bundleState(ctx, d, ref.Rev)
				if err != nil {
					return nil, err
				}
				im.schemas[p] = v
				return v, nil
			}
		}
		// A draft in a branch of the path's namespace has the same content
		// as any copy (§3.3, §6.1); whether a write may use it is the gate's
		// to decide.
		r, err := im.c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true})
		if err != nil {
			if client.IsNotFound(err) || client.IsGone(err) {
				return nil, &schema.UnavailableError{Ref: p}
			}
			return nil, err
		}
		im.schemas[p] = r.Doc.Value
		return r.Doc.Value, nil
	}
}

// snapshotOrder finds each snapshot document's declared references and
// orders the documents so that pinned references between snapshot
// documents point at documents planned earlier. It also lists pinned
// strings that aren't declared.
func (im *importer) snapshotOrder(ctx context.Context) ([]*bdoc, map[string][]annot.Ref, error) {
	refs := map[string][]annot.Ref{}
	deps := map[string][]string{}
	var snaps []*bdoc
	for _, k := range im.keys {
		if d := im.docs[k]; d.info.History == Snapshot {
			snaps = append(snaps, d)
		}
	}
	for _, k := range im.heldKeys {
		snaps = append(snaps, im.docs[k])
	}
	// Each document's walk on its own, on parallel workers (the schema
	// loader one at a time), then their findings in key order.
	type found struct {
		refs       []annot.Ref
		undeclared []UndeclaredRef
		err        error
	}
	results := make([]found, len(snaps))
	var mu sync.Mutex
	loader := im.schemaLoader(ctx)
	load := func(ref schema.Ref) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		return loader(ref)
	}
	eachParallel(len(snaps), func(i int) {
		d, f := snaps[i], &results[i]
		if d.snap.Deleted {
			return
		}
		doc, err := d.snapDoc()
		if err != nil {
			f.err = err
			return
		}
		if f.refs, f.err = annot.FindRefs(doc, load); f.err != nil {
			return
		}
		declared := map[string]bool{}
		for _, r := range f.refs {
			declared[r.Pointer] = true
		}
		walkStrings(doc, func(at *strPath, s string) {
			r, ok := annot.ParseRefString(s)
			if !ok || r.Rev == "" {
				return
			}
			ptr := at.String()
			if declared[ptr] || ptr == "/$schema" {
				return
			}
			t := im.docs[Key(r.NS, r.Name)]
			bundled := t != nil && t.info.History == Snapshot && t.snap != nil && t.snap.Snapshot == r.Rev
			f.undeclared = append(f.undeclared, UndeclaredRef{Doc: d.key, Pointer: ptr, Value: s, Bundled: bundled})
		})
	})
	for i, d := range snaps {
		f := results[i]
		if f.err != nil {
			return nil, nil, fmt.Errorf("import: %s: x-ref walk: %w", d.key, f.err)
		}
		if d.snap.Deleted {
			continue
		}
		refs[d.key] = f.refs
		for _, r := range f.refs {
			if t := im.rewriteTarget(r); t != nil && t != d {
				deps[d.key] = append(deps[d.key], t.key)
			}
		}
		if !im.held[d.key] {
			im.rep.Undeclared = append(im.rep.Undeclared, f.undeclared...)
		}
	}
	// Depth-first topological order. Pinned references can't form a cycle
	// (a revision's id covers the ids it pins), so a cycle means a bundle
	// that lies about its snapshots.
	var out []*bdoc
	state := map[string]int{}
	var visit func(d *bdoc) error
	visit = func(d *bdoc) error {
		switch state[d.key] {
		case 1:
			return fmt.Errorf("import: pinned references between snapshot documents form a cycle at %s", d.key)
		case 2:
			return nil
		}
		state[d.key] = 1
		for _, dk := range deps[d.key] {
			if err := visit(im.docs[dk]); err != nil {
				return err
			}
		}
		state[d.key] = 2
		out = append(out, d)
		return nil
	}
	for _, d := range snaps {
		if err := visit(d); err != nil {
			return nil, nil, err
		}
	}
	return out, refs, nil
}

// eachParallel calls f for 0 to n-1, on as many goroutines as there are
// processors.
func eachParallel(n int, f func(i int)) {
	workers := min(n, runtime.GOMAXPROCS(0))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := int(next.Add(1)) - 1; i < n; i = int(next.Add(1)) - 1 {
				f(i)
			}
		}()
	}
	wg.Wait()
}

// rewriteTarget returns the bundled snapshot document a pinned reference
// points at, if it is exactly its snapshot.
func (im *importer) rewriteTarget(r annot.Ref) *bdoc {
	if r.Rev == "" {
		return nil
	}
	t := im.docs[Key(r.NS, r.Name)]
	if t == nil || t.info.History != Snapshot || t.snap == nil || t.snap.Deleted || t.snap.Snapshot != r.Rev {
		return nil
	}
	return t
}

// rewrite replaces pinned references to snapshot documents with the
// matching upstream revision path, keeping any #{id} fragment (§G.4.4). It
// returns the rewritten document as the import holds documents (snapHeld):
// its canonical form, the line's own without parsing it if nothing is
// rewritten; or with keepTrees the line's tree, rewritten in place.
// planUpstream calls it once per document, and a rewritten document
// replaces the line's (dropSnap): a copy of each would double what the
// import holds.
func (im *importer) rewrite(d *bdoc, refs []annot.Ref) (any, error) {
	var doc any
	parsed := false
	for _, r := range refs {
		t := im.rewriteTarget(r)
		if t == nil {
			continue
		}
		up := im.up[t.key]
		if up == nil || up.head == "" {
			return nil, fmt.Errorf("pinned reference %s at %s: no upstream revision for %s", r.Raw, r.Pointer, t.key)
		}
		if !parsed {
			var err error
			if doc, err = d.snapDoc(); err != nil {
				return nil, err
			}
			parsed = true
		}
		frag := ""
		if i := strings.IndexByte(r.Raw, '#'); i >= 0 {
			frag = r.Raw[i:]
		}
		to := "/r/" + up.ns + "/" + up.name + "/rev/" + up.head + frag
		var err error
		if doc, err = setAt(doc, r.Pointer, to); err != nil {
			return nil, err
		}
		d.rep.Rewritten = append(d.rep.Rewritten, RewrittenRef{Pointer: r.Pointer, From: r.Raw, To: to})
	}
	if !parsed {
		return d.snapHeld()
	}
	canon := d.snap.docCanon != nil
	d.dropSnap()
	if canon {
		return jsonv.Raw(jsonv.Canonical(doc)), nil
	}
	return doc, nil
}

// setAt sets the value at a JSON Pointer in doc (mutating doc).
func setAt(doc any, ptr string, v any) (any, error) {
	p, err := pointer.Parse(ptr)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return v, nil
	}
	cur := doc
	for i, tok := range p {
		last := i == len(p)-1
		switch c := cur.(type) {
		case map[string]any:
			if last {
				c[tok] = v
				return doc, nil
			}
			cur = c[tok]
		case []any:
			n, ok := pointer.ArrayIndex(tok)
			if !ok || n >= len(c) {
				return nil, fmt.Errorf("pointer %s: bad index", ptr)
			}
			if last {
				c[n] = v
				return doc, nil
			}
			cur = c[n]
		default:
			return nil, fmt.Errorf("pointer %s: no such location", ptr)
		}
	}
	return doc, nil
}

// upstreamChain returns the chain of an upstream resource up to head,
// starting at a pruning horizon if older history is gone.
func (im *importer) upstreamChain(ctx context.Context, ns, name, head string) ([]chainEntry, error) {
	es, err := im.c.Log(ctx, ns, name, head, "")
	if client.IsPruned(err) {
		hz := client.Horizon(err)
		es, err = im.c.Log(ctx, ns, name, head, hz)
		es = append([]client.LogEntry{{ID: hz}}, es...)
	}
	if err != nil {
		return nil, err
	}
	out := make([]chainEntry, len(es))
	steps := stepsOfLog(es)
	for i, e := range es {
		out[i] = chainEntry{id: e.ID, step: steps[i], size: -1}
	}
	return out, nil
}

// genesisEntry is the genesis revision of doc, d's snapshot document as
// rewritten (as held: snapHeld), as an upstream chain's first entry, with
// its blobs if load found them; not ok for a deleted snapshot or a sealed
// upstream, whose genesis carries a fresh nonce (§E.2.5). A document of
// JSON null has one too.
func genesisEntry(d *bdoc, doc any, sealed bool) (chainEntry, bool) {
	if d.snap.Deleted || sealed {
		return chainEntry{}, false
	}
	st := client.PatchStep(client.GenesisPatches(doc))
	canon, err := canonical(st.Patches)
	if err != nil {
		return chainEntry{}, false
	}
	id, err := revisionID("", canon)
	return chainEntry{id: id, step: st, size: len(canon), blobs: d.snapBlobs, hasBlobs: d.snapBlobs != nil}, err == nil
}

// upChain is the upstream chain after this import: the target's up to the
// previous head, read once and only when a fast-forward needs it, then
// what the import adds.
func (im *importer) upChain(ctx context.Context, u *upPlan) ([]chainEntry, error) {
	if !u.loaded {
		if u.prev != "" {
			old, err := im.upstreamChain(ctx, u.ns, u.name, u.prev)
			if err != nil {
				return nil, err
			}
			u.chain = old
		}
		u.chain = append(u.chain, u.added...)
		u.loaded = true
	}
	return u.chain, nil
}

// planUpstream plans one revision on the snapshot document's upstream
// chain: diff(previous snapshot, new snapshot), a genesis, a restore or a
// tombstone; nothing for an empty diff (§G.4.4).
func (im *importer) planUpstream(ctx context.Context, d *bdoc, refs []annot.Ref) (*item, error) {
	u := &upPlan{ns: im.upstreamNS(d.ns), name: d.name}
	im.up[d.key] = u
	ur := &UpstreamReport{Target: Key(u.ns, u.name)}
	d.rep.Upstream = ur
	uh, err := im.head(ctx, u.ns, u.name)
	if err != nil {
		return nil, err
	}
	var prevDoc any
	if uh.State == client.Purged {
		u.purged = true
		ur.Class = "purged"
		d.rep.Conflicts = append(d.rep.Conflicts, conflict(ConflictPurged, "purged in the upstream namespace "+u.ns))
		d.rep.Resolution = ResolveSkip
		return nil, nil
	}
	sealed := im.sealedT[u.ns]
	// The rewritten snapshot as the import holds it: its canonical form,
	// which a genesis revision's patch set holds and a batch request sends
	// as it is (jsonv.Raw), or with keepTrees its tree.
	var nd any
	if !d.snap.Deleted {
		if nd, err = im.rewrite(d, refs); err != nil {
			return nil, err
		}
		if im.opt.Resolutions[d.key] == ResolveTake {
			// Only a take reads it again (takeSteps).
			if u.newDoc, err = parsedDoc(nd); err != nil {
				return nil, err
			}
		}
	}
	switch uh.State {
	case client.Live:
		u.prev, u.prevLive = uh.ID, true
		if g, ok := genesisEntry(d, nd, sealed); ok && g.id == uh.ID {
			// The head is the genesis revision of the rewritten snapshot, as
			// an earlier import of it wrote: the document is the snapshot,
			// and the chain that one revision. Neither needs reading.
			u.chain, u.loaded = []chainEntry{g}, true
			u.head = u.prev
			ur.Previous, ur.Class, ur.Head = u.prev, "unchanged", u.head
			return nil, nil
		}
		doc, err := im.c.Doc(ctx, u.ns, u.name, uh.ID)
		if err != nil {
			return nil, err
		}
		prevDoc = doc.Value
	case client.Tombstoned:
		u.prev = uh.ID
		if prevDoc, _, err = im.targetState(ctx, u.ns, u.name, uh.ID); err != nil {
			return nil, err
		}
	}
	ur.Previous = u.prev
	var steps []client.Step
	var blobs [][]string // the steps' blobs (stepBlobs), if known without reading them
	if d.snap.Deleted {
		if u.prevLive {
			steps, ur.Class = []client.Step{client.DeleteStep()}, "delete"
		} else if u.prev == "" {
			ur.Class = "absent"
		} else {
			ur.Class = "unchanged"
		}
	} else {
		// The snapshot as a tree, for a diff or without its $nonce.
		var ndv any
		if u.prev != "" || sealed {
			if ndv, err = parsedDoc(nd); err != nil {
				return nil, err
			}
		}
		if sealed {
			// The upstream's own $nonce isn't part of the snapshot (§E.2.5).
			prevDoc, ndv = withoutNonce(prevDoc), withoutNonce(ndv)
		}
		switch {
		case u.prev == "":
			gd := nd // the genesis revision's document
			_, canon := nd.(jsonv.Raw)
			switch {
			case !sealed:
				if d.snapBlobs != nil {
					blobs = [][]string{d.snapBlobs}
				}
			case canon:
				// Without its $nonce, held as canonical as any other.
				gd = jsonv.Raw(jsonv.Canonical(ndv))
				blobs = [][]string{stepBlobs(client.PatchStep(client.GenesisPatches(ndv)))} // nonced adds none
			default:
				gd = ndv
			}
			steps, ur.Class = []client.Step{client.PatchStep(client.GenesisPatches(gd))}, "create"
		case !u.prevLive:
			steps, ur.Class = []client.Step{client.PatchStep(orEmpty(merge.Diff(prevDoc, ndv)))}, "restore"
		default:
			if diff := merge.Diff(prevDoc, ndv); len(diff) > 0 {
				steps, ur.Class = []client.Step{client.PatchStep(diff)}, "append"
			} else {
				ur.Class = "unchanged"
			}
		}
	}
	u.head, u.headDel = u.prev, u.prev != "" && !u.prevLive
	if len(steps) == 0 {
		ur.Head = u.head
		return nil, nil
	}
	if sealed {
		// A sealed upstream chain then depends on its nonces too, not only on
		// the sequence of snapshots (§E.2.5, §G.4.4).
		steps = nonced(steps)
	}
	exp, sizes, err := expectedIDs(u.prev, steps)
	if err != nil {
		return nil, err
	}
	if blobs == nil {
		blobs = make([][]string, len(steps))
		for i, s := range steps {
			blobs[i] = stepBlobs(s)
		}
	}
	for i, s := range steps {
		u.added = append(u.added, chainEntry{id: exp[i], step: s, size: sizes[i], blobs: blobs[i], hasBlobs: true})
	}
	u.head, u.headDel = exp[len(exp)-1], steps[len(steps)-1].Delete
	ur.Head = u.head
	u.it = &item{d: d, ns: u.ns, name: u.name, upstream: true, ifMatch: u.prev, ifNone: u.prev == "", steps: steps, srcID: d.snap.Snapshot,
		expected: exp, sizes: sizes, blobs: blobs}
	return u.it, nil
}

// mergePoints scans the target namespace's log for earlier import batches
// from the bundle's origin: source.ids maps each snapshot document to the
// upstream revision the target absorbed, and the batch entry names the
// target revision that produced.
func (im *importer) mergePoints(ctx context.Context, tns string) (map[string]point, error) {
	if pts, ok := im.points[tns]; ok {
		return pts, nil
	}
	pts := map[string]point{}
	im.points[tns] = pts
	h, err := im.c.NSHead(ctx, tns)
	if client.IsNotFound(err) {
		return pts, nil
	}
	if err != nil {
		return nil, err
	}
	log, err := im.c.NSLog(ctx, tns, h.ID, "")
	if err != nil {
		return nil, err
	}
	for _, e := range log {
		if e.Kind != "batch" || !e.HasSource || e.Source == nil {
			continue
		}
		o, hasOrigin := e.Source["origin"].(string)
		if im.local == hasOrigin || (hasOrigin && o != im.h.Origin) {
			continue
		}
		srcNS, _ := e.Source["ns"].(string)
		ids, _ := e.Source["ids"].(map[string]any)
		for _, s := range e.Entries {
			if id, ok := ids[s.Resource].(string); ok && s.Resource != "" {
				pts[Key(srcNS, s.Resource)] = point{baseU: id, baseT: s.Target}
			}
		}
	}
	return pts, nil
}

// planSnapshotTarget merges the upstream chain into the target document:
// a fast-forward the first time (sharing the upstream ids), later a replay
// of the upstream revisions after the one the previous import recorded.
func (im *importer) planSnapshotTarget(ctx context.Context, d *bdoc) (*item, error) {
	r := d.rep
	u := im.up[d.key]
	if u.purged {
		r.Class = "purged"
		return nil, nil
	}
	th, err := im.head(ctx, d.tns, d.name)
	if err != nil {
		return nil, err
	}
	B := th.ID
	r.TargetHead = B
	// ff fast-forwards the target along entries of the upstream chain.
	ff := func(class string, entries []chainEntry, parent string) (*item, error) {
		// The same steps on the same parent: the upstream chain's ids.
		n := len(entries)
		it := &item{d: d, ns: d.tns, name: d.name, ifMatch: parent, ifNone: parent == "", sameIDs: true,
			steps: make([]client.Step, 0, n), expected: make([]string, 0, n), sizes: make([]int, 0, n), blobs: make([][]string, 0, n)}
		for _, e := range entries {
			if !e.step.Delete && e.step.Patches == nil {
				r.Conflicts = append(r.Conflicts, conflict(merge.ConflictPruned, "upstream history the fast-forward needs was pruned"))
				return nil, nil
			}
			if e.size < 0 {
				it.expected, it.sizes = nil, nil // computed in plan
			}
			if !e.hasBlobs {
				it.blobs = nil // computed in plan
			}
			it.steps = append(it.steps, e.step)
			if it.expected != nil {
				it.expected, it.sizes = append(it.expected, e.id), append(it.sizes, e.size)
			}
			if it.blobs != nil {
				it.blobs = append(it.blobs, e.blobs)
			}
		}
		if len(it.steps) == 0 {
			it.expected, it.sizes, it.blobs = nil, nil, nil
		}
		r.Class = class
		return it, nil
	}
	switch {
	case th.State == client.Purged:
		r.Class = "purged"
		r.Conflicts = append(r.Conflicts, conflict(ConflictPurged, "purged in the target"))
		r.Resolution = ResolveSkip
		return nil, nil
	case B == u.head:
		r.Class = "present"
		return nil, nil
	case th.State == client.NotFound:
		if u.head == "" || u.headDel {
			r.Class = "absent"
			r.Note = "deleted at the source and absent in the target"
			return nil, nil
		}
		chain, err := im.upChain(ctx, u)
		if err != nil {
			return nil, err
		}
		if len(chain) > 0 && chain[0].step.Patches == nil && !chain[0].step.Delete {
			r.Conflicts = append(r.Conflicts, conflict(merge.ConflictPruned, "the upstream chain's early history was pruned"))
			return nil, nil
		}
		return ff("create", chain, "")
	case B == u.prev:
		// Where the previous import left both: on with what this one adds.
		return ff("fast-forward", u.added, B)
	}
	chain, err := im.upChain(ctx, u)
	if err != nil {
		return nil, err
	}
	cidx := map[string]int{}
	for i, e := range chain {
		cidx[e.id] = i
	}
	if i, ok := cidx[B]; ok {
		return ff("fast-forward", chain[i+1:], B)
	}
	pts, err := im.mergePoints(ctx, d.tns)
	if err != nil {
		return nil, err
	}
	pt, havePt := pts[d.key]
	var incoming []client.Step
	bi, inChain := cidx[pt.baseU]
	switch {
	case havePt && pt.baseU == u.head:
		r.Class = "present"
		r.Note = "the target changed the document since the last import, and upstream has nothing new"
		return nil, nil
	case havePt && inChain:
		r.Ancestor = pt.baseU
		for _, e := range chain[bi+1:] {
			incoming = append(incoming, e.step)
		}
		ancDoc, _, err := im.targetState(ctx, u.ns, u.name, pt.baseU)
		if err != nil {
			return nil, err
		}
		tlog, err := im.c.Log(ctx, d.tns, d.name, B, pt.baseT)
		switch {
		case err == nil:
			r.Conflicts = append(r.Conflicts, sides(ancDoc, ancDoc != nil, incoming, stepsOfLog(tlog), th.State == client.Tombstoned)...)
		case client.IsNotFound(err):
			r.Conflicts = append(r.Conflicts, conflict(merge.ConflictNoCommonAncestor, "the target's history no longer contains the previous import's revision "+pt.baseT))
		default:
			return nil, err
		}
	default:
		r.Conflicts = append(r.Conflicts, conflict(merge.ConflictNoCommonAncestor, "the target's document doesn't come from "+u.ns+" (no earlier import of it)"))
	}
	res := im.opt.Resolutions[d.key]
	if len(r.Conflicts) == 0 {
		r.Class = "replay"
		return &item{d: d, ns: d.tns, name: d.name, ifMatch: B, steps: incoming, srcID: u.head}, nil
	}
	r.Class = "conflict"
	switch res {
	case "":
		return nil, nil
	case ResolveSkip:
		r.Resolution, r.Class = res, "skipped"
		return nil, nil
	case ResolveReplay:
		if incoming == nil {
			r.Note = "replay needs a common ancestor"
			return nil, nil
		}
		r.Resolution, r.Class = res, "replay"
		return &item{d: d, ns: d.tns, name: d.name, ifMatch: B, steps: incoming, srcID: u.head}, nil
	case ResolveTake:
		r.Resolution, r.Class = res, "take"
		tdoc, tlive, err := im.targetState(ctx, d.tns, d.name, B)
		if err != nil {
			return nil, err
		}
		steps := im.takeSteps(d.tns, tdoc, tlive, u.newDoc, !d.snap.Deleted)
		if len(steps) == 0 {
			r.Note = "the target's document already equals the snapshot"
			return nil, nil
		}
		return &item{d: d, ns: d.tns, name: d.name, ifMatch: B, steps: steps, srcID: u.head}, nil
	}
	return nil, fmt.Errorf("unknown resolution %q", res)
}

// --- ordering ------------------------------------------------------------------

// buildNodes groups items by target namespace and orders the namespaces
// dependencies first (§G.4.4): what a namespace's documents pin (schemas
// included, as over-approximated by scanning their strings) comes before
// it, and a namespace's upstream before it. A pin of a full document needs
// that document's namespace; a snapshot document's pin of a bundled
// snapshot document points upstream once rewritten, and needs that
// upstream namespace. Live references don't order: they name no revision
// that must exist. Strongly connected namespaces (pin cycles) go next to
// each other.
func (im *importer) buildNodes(items []*item) {
	for _, it := range items {
		n := im.nodes[it.ns]
		if n == nil {
			n = &node{ns: it.ns, srcNS: it.d.ns, upstream: it.upstream, deps: map[string]bool{}}
			im.nodes[it.ns] = n
		}
		n.items = append(n.items, it)
		for k := range it.d.pinKeys {
			t := im.docs[k]
			switch {
			case t == nil || t == it.d:
				// Not a document this import brings.
			case t.info.History == Snapshot && it.d.info.History == Snapshot:
				n.deps[im.upstreamNS(t.ns)] = true
			default:
				n.deps[t.tns] = true
			}
		}
		if !it.upstream && it.d.info.History == Snapshot {
			n.deps[im.upstreamNS(it.d.ns)] = true
		}
	}
	for _, n := range im.nodes {
		delete(n.deps, n.ns)
		for dep := range n.deps {
			if im.nodes[dep] == nil {
				delete(n.deps, dep)
			}
		}
		n.items = orderItems(n.items)
	}
	im.order = tarjanOrder(im.nodes)
	for _, n := range im.order {
		im.rep.Order = append(im.rep.Order, n.ns)
	}
}

// orderItems puts items whose documents others in the same namespace pin
// first (e.g. schema resources before documents using them, §6.1: items
// may reference schema revisions created by earlier items). Live
// references don't order them: they name no revision that must exist.
func orderItems(items []*item) []*item {
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	byKey := map[string]*item{}
	for _, it := range items {
		byKey[it.d.key] = it
	}
	var out []*item
	state := map[*item]int{}
	var visit func(it *item)
	visit = func(it *item) {
		if state[it] != 0 {
			return // done, or a cycle: break it here
		}
		state[it] = 1
		deps := make([]string, 0, len(it.d.pinKeys))
		for k := range it.d.pinKeys {
			deps = append(deps, k)
		}
		sort.Strings(deps)
		for _, k := range deps {
			if dep, ok := byKey[k]; ok && dep != it {
				visit(dep)
			}
		}
		state[it] = 2
		out = append(out, it)
	}
	for _, it := range items {
		visit(it)
	}
	return out
}

// tarjanOrder returns the nodes in reverse topological order of their
// dependencies (dependencies first), strongly connected components kept
// together, within one upstream namespaces first but for what they need
// of it, ties broken by name.
func tarjanOrder(nodes map[string]*node) []*node {
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	index, low := map[string]int{}, map[string]int{}
	on := map[string]bool{}
	var stack []string
	var out []*node
	i := 0
	var strong func(v string)
	strong = func(v string) {
		index[v], low[v] = i, i
		i++
		stack = append(stack, v)
		on[v] = true
		deps := make([]string, 0, len(nodes[v].deps))
		for d := range nodes[v].deps {
			deps = append(deps, d)
		}
		sort.Strings(deps)
		for _, w := range deps {
			if _, seen := index[w]; !seen {
				strong(w)
				low[v] = min(low[v], low[w])
			} else if on[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] == index[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				on[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			// Upstream namespaces first (§G.4.4), but for what they
			// need of the component (schemas, full documents), then by
			// name.
			needed := map[string]bool{}
			for _, w := range comp {
				if nodes[w].upstream {
					for d := range nodes[w].deps {
						needed[d] = needed[d] || !nodes[d].upstream
					}
				}
			}
			rank := func(n *node) int {
				switch {
				case needed[n.ns]:
					return 0
				case n.upstream:
					return 1
				}
				return 2
			}
			sort.Slice(comp, func(i, j int) bool {
				a, b := nodes[comp[i]], nodes[comp[j]]
				if ra, rb := rank(a), rank(b); ra != rb {
					return ra < rb
				}
				return a.ns < b.ns
			})
			for _, w := range comp {
				out = append(out, nodes[w])
			}
		}
	}
	for _, n := range names {
		if _, seen := index[n]; !seen {
			strong(n)
		}
	}
	return out
}
