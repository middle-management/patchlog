package merge

// Releases across namespaces (§F.9): merging every branch a release
// document lists, one batch per branch and step, in an order that keeps
// each state in between safe.
//
//  1. Schema resources (documents whose $schema is a dialect URL, §6.1),
//     by fast-forward only, in $ref order: then $schema paths resolve in
//     the bases too. A schema resource the base changed since the branch
//     started can't fast-forward: a conflict (rebase the release, and
//     migrate documents with replace /$schema).
//  2. Catalog changes that narrow access: for every subject, the effective
//     roles on every node afterwards are a subset of those before, judged
//     by the test of §B.11.4 on the step-2 batch as a whole (whoever
//     merges). A folder the release creates goes here, with its own
//     $access, when a narrowing move needs it: an empty folder gives
//     access to nothing but its title and its tree powers, so the subset
//     test applies to the items moved into it, not to the folder itself.
//  3. Content branches, in any order: new documents aren't placed yet.
//  4. Catalog changes that widen access: new placements and the remaining
//     moves and $access edits. This publishes the release.
//
// Conflicts reported before anything is submitted (ReleaseConflict): a
// catalog node narrowing for some subjects and widening for others
// (resolved by a split: the document after step 2, given by a person,
// each half changing the node); a
// content item step 3 creates or restores that a placement in the catalog
// base already names (fine if step 2 removes that placement, or if the
// release keeps it unchanged and the approver accepts it); a pinned x-ref
// or manifest entry
// naming a revision of another listed branch that the merge replays; a
// document resolving a draft schema revision in a branch the release
// doesn't list; and every merge conflict of §F.3.
//
// Lifecycle. PlanRelease checks that each listed branch's base is the
// namespace it is keyed by (or, for a release built on another, that
// release's branch for the key), classifies and checks; the plan is stored
// as a resource ({release name}.merge) in a state namespace (by default the
// release document's own), with the release document's revision and the
// plan's digest (PlanDigest, §F.9): text(trunc160(sha256(canonical(plan))))
// over { release: <revision path>, batches: [{ ns, source: { ns, at },
// items: [{ resource, ifMatch | ifNoneMatch, steps }] }] }, the batches in
// submission order, each step its plaintext patch set without fresh $nonce
// ops (nor a fresh top-level $nonce in a root op's value) or "delete", and
// a precondition on an earlier batch's result (the second half of a split
// node) { batch, item }. ApproveRelease, run by the person approving, plans
// again, requires it clean, for the same revision and with the same
// digest, and freezes every listed branch (§8.4), recording each branch's
// config id and its ns_id before the freeze, which stays every batch's
// source.at; unfreezing a branch (any config change) invalidates the
// plan. ApplyRelease runs the steps from the stored plan, each classified
// again with a dry run right before it is submitted, and stops for a new
// approval if a step's items differ from the approved ones; it records
// each step as it completes, and resumes from there after a stop. It never
// reverts. A plan an earlier version stored (format 0, without the digest
// above or each branch's at) is planned and approved again, unless that
// version stopped part-way through merging it: that merge resumes from the
// stored plan, each step checked against the step digest the earlier
// version recorded. Catalog batches are submitted by the merge service
// under grants the catalog service signs for it for exactly that batch,
// or, where they change $access, under a catalog admin's grant narrowed
// with the merge service's via (§F.8, MergeGranter). Every branch records
// merged only after step 4, with at the target's ns_id after the last
// batch into it.
//
// One release per catalog base at a time: ApplyRelease holds the merge
// lock, resource merge-lock.{catalog base} in the release document's own
// namespace (§F.9), whose document is { "holder": <the merge service's
// sub>, "plan": <plan digest> } while held and {} while free (with a
// $nonce where one is needed). Taking it is a create with If-None-Match: *
// or an append with If-Match on a free head, setting holder; then plan is
// set by a further compare-and-append, and releasing is an append back to
// {}. A merge resuming from a stored plan takes over (sets holder, by
// compare-and-append) only a lock whose plan is that plan's digest, or,
// resuming a merge an earlier version stopped, the lock that version took
// for the release ({ "release" }, in StateNS); any other held lock, one
// written by an earlier version included, is released by a person. It is
// held from the first step until every branch records merged.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
	"github.com/middle-management/patchlog/internal/tree"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// Release plan states.
const (
	ReleasePlanned   = "planned"
	ReleaseApproved  = "approved"
	ReleaseMerging   = "merging"
	ReleaseDone      = "done"
	ReleaseAbandoned = "abandoned"
)

// Release conflict kinds.
const (
	RCBaseChain      = "base_chain"         // the branch's base isn't the namespace it is keyed by (§F.9)
	RCFrozen         = "frozen"             // the branch is frozen (not by this plan's approval)
	RCPurged         = "purged"             // the branch is purged
	RCSchemaChanged  = "schema_changed"     // a schema resource can't fast-forward (§F.9)
	RCNarrowAndWiden = "narrows_and_widens" // a catalog node narrows for some subjects, widens for others
	RCStep2Widens    = "step2_widens"       // the narrowing batch as a whole widens
	RCBadSplit       = "bad_split"          // a split's halves don't narrow, then widen, or one changes nothing
	RCPlacedItem     = "placed_item"        // step 3 would publish an item under an existing placement
	RCDanglingPin    = "dangling_pin"       // a pinned link to a revision the merge replays
	RCForeignDraft   = "foreign_draft"      // a draft resolved in a branch the release doesn't list
	RCUnresolved     = "schema_unavailable" // a $schema the merger can't resolve anywhere
	RCMerge          = "merge"              // a §F.3 conflict of a resource
)

// ReleaseConflict is a reason the release needs a person.
type ReleaseConflict struct {
	Kind     string   `json:"kind"`
	Key      string   `json:"key,omitempty"` // the release key (base namespace)
	NS       string   `json:"ns,omitempty"`  // the branch
	Resource string   `json:"resource,omitempty"`
	Message  string   `json:"message"`
	Paths    []string `json:"paths,omitempty"`
}

// ReleaseBranch is one listed branch in a plan.
type ReleaseBranch struct {
	Key    string `json:"key"`
	NS     string `json:"ns"`
	Target string `json:"target"` // the namespace it merges into
	// Catalog: the target is a catalog namespace (§B.6).
	Catalog bool `json:"catalog,omitempty"`
	// Schemas are its schema resources in $ref order (step 1), Content the
	// rest (step 3; for a catalog, steps 2 and 4).
	Schemas []string `json:"schemas,omitempty"`
	Content []string `json:"content,omitempty"`
	// At is the branch's ns_id the plan classifies from, every batch's
	// source.at: its head when planned, and from the approval on its ns_id
	// before the approval's freeze (§F.9).
	At string `json:"at,omitempty"`
	// FrozenConfig is the config id the approval's freeze produced.
	FrozenConfig string `json:"frozenConfig,omitempty"`
	// Merged is the merged.at recorded after step 4.
	Merged string `json:"merged,omitempty"`
}

// ReleaseStep is one batch of the merge.
type ReleaseStep struct {
	Step      int      `json:"step"`
	Key       string   `json:"key"`
	Resources []string `json:"resources"`
	// Done is the batch's ns_id once submitted ("noop" if there was
	// nothing left to do).
	Done string `json:"done,omitempty"`
	// Digest is the digest of this step's part of the plan (its items),
	// which the step must still have when it is submitted.
	Digest string `json:"digest,omitempty"`
}

// Half is a catalog node merged in two halves: the document after step 2
// (Narrow) and after step 4 (Wide, the branch's document). Reason is
// "split": a person's resolution of a node that narrows and widens. Its
// step-2 batch records a pair for it, but the step-4 batch is more recent
// and replaces that pair (§F.3); until then the stored plan, not
// classification, decides what is left.
type Half struct {
	Narrow any    `json:"narrow"`
	Wide   any    `json:"wide"`
	Reason string `json:"reason"`
}

// PlanFormat is the stored plan's format. 2: the plan digest of v0.73
// (§F.9) and each branch's at; a plan stored under an earlier format (0,
// none recorded) is planned and approved again, unless its merge stopped
// part-way, which ApplyRelease resumes.
const PlanFormat = 2

// ReleasePlan is the stored plan of a release merge.
type ReleasePlan struct {
	Format   int    `json:"format,omitempty"` // PlanFormat
	Release  string `json:"release"`          // the release document's live link
	Revision string `json:"revision"`         // the revision planned
	Name     string `json:"name"`
	State    string `json:"state"`

	PlannedBy  string `json:"plannedBy,omitempty"`
	ApprovedBy string `json:"approvedBy,omitempty"`
	ApprovedAt string `json:"approvedAt,omitempty"`
	// Digest is the plan's digest (PlanDigest), what a person approves.
	Digest string `json:"digest,omitempty"`

	Branches  []*ReleaseBranch           `json:"branches"`
	Steps     []*ReleaseStep             `json:"steps"`
	Halves    map[string]map[string]Half `json:"halves,omitempty"` // key -> node -> halves
	Conflicts []ReleaseConflict          `json:"conflicts,omitempty"`
	// Accepted lists placements (ns.name) whose item step 3 publishes,
	// accepted by the approver.
	Accepted []string `json:"acceptedPlacements,omitempty"`
	// Resolutions are resolution sets of content resources, "key/name" ->
	// { steps, at } (§F.3).
	Resolutions map[string]StoredResolution `json:"resolutions,omitempty"`
	// Notes explain decisions that need no person.
	Notes []string `json:"notes,omitempty"`

	head   string // the plan resource's head when loaded
	nonced bool   // the plan resource's head has a $nonce (stateNonce)
}

// StoredResolution is a resolution set kept in the plan.
type StoredResolution struct {
	Steps []any  `json:"steps"`
	At    string `json:"at"` // the base head it was written against
}

// Clean reports whether nothing needs a person.
func (rp *ReleasePlan) Clean() bool { return len(rp.Conflicts) == 0 }

// Branch returns the plan's branch for a key, or nil.
func (rp *ReleasePlan) Branch(key string) *ReleaseBranch {
	for _, b := range rp.Branches {
		if b.Key == key {
			return b
		}
	}
	return nil
}

// MergeGrantResult is a catalog service's answer for one catalog merge
// batch (§F.8): a grant covering exactly that batch, signed with the
// catalog's merge key for the merge service, or, for a batch that needs
// catalog-admins (§B.11.3: it changes $access, restores a folder, or
// widens), Admin: checked as a dry run with CheckedAs, the admin whose
// grant it goes under, as the caller, to be submitted under that grant.
type MergeGrantResult struct {
	Grant      string
	Admin      bool
	ApprovedBy string
	CheckedAs  string
}

// MergeGranter obtains a catalog service's decision on exactly one catalog
// merge batch (§F.8). adminGrant, if set, is the grant of the catalog
// admin the batch would go under: for a batch that needs catalog-admins,
// the service judges its dry run with that admin as the caller too (F-T4).
// A catalog the service offers no merge grants for (an end-to-end one,
// 404 not_offered) is an error wrapping ErrNotOffered.
type MergeGranter interface {
	MergeGrant(ctx context.Context, catalog string, batch map[string]any, adminGrant string) (*MergeGrantResult, error)
}

// HTTPGranter asks catalog services over HTTP: POST {URL}/merge-grants
// with the merge service's grant for the catalog as Authorization, the
// approving person's in Approver-Authorization and, when given, the
// catalog admin's in Admin-Authorization (catalog.AdminHeader).
type HTTPGranter struct {
	URLs map[string]string // catalog namespace -> catalog service base URL
	// Bearer is the merge service's own grant for the catalog: merge
	// grants are issued only to it (§F.8).
	Bearer string
	// Approver is the approving person's grant for the catalog, whose
	// powers the catalog service checks ("" sends none: Bearer's).
	Approver string
	Author   string // X-Author, for development servers
	HTTP     *http.Client
}

// ErrBehind is returned when a catalog service hasn't caught up yet.
var ErrBehind = errors.New("merge: the catalog service is behind")

// ErrAdminNeeded is returned when a catalog batch needs catalog-admins
// (§B.11.3, §F.8) and no catalog admin's grant to submit it under is
// given (ReleaseOptions.AdminGrant).
var ErrAdminNeeded = errors.New("merge: the catalog batch needs catalog-admins")

// ErrNotOffered is returned when a catalog service offers no merge grants
// for a catalog, as for an end-to-end one (§F.8, 404 not_offered).
var ErrNotOffered = errors.New("merge: the catalog service issues no merge grants for this catalog")

// MergeGrant implements MergeGranter.
func (h *HTTPGranter) MergeGrant(ctx context.Context, cat string, batch map[string]any, adminGrant string) (*MergeGrantResult, error) {
	u := h.URLs[cat]
	if u == "" {
		return nil, fmt.Errorf("merge: no catalog service for %s (give one with -catalog-service %s=URL)", cat, cat)
	}
	body, err := json.Marshal(map[string]any{"batch": batch})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(u, "/")+"/merge-grants", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+h.Bearer)
	}
	if h.Approver != "" {
		req.Header.Set(catalog.ApproverHeader, "Bearer "+h.Approver)
	}
	if adminGrant != "" {
		req.Header.Set(catalog.AdminHeader, "Bearer "+adminGrant)
	}
	if h.Author != "" {
		req.Header.Set("X-Author", h.Author)
	}
	hc := h.HTTP
	if hc == nil {
		hc = telemetry.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Grant      string `json:"grant"`
		Admin      bool   `json:"admin"`
		ApprovedBy string `json:"approvedBy"`
		CheckedAs  string `json:"checkedAs"`
		Code       string `json:"code"`
		Message    string `json:"message"`
	}
	_ = json.Unmarshal(b, &out)
	switch {
	case resp.StatusCode == 503 && out.Code == "behind":
		return nil, fmt.Errorf("%w: %s", ErrBehind, out.Message)
	case resp.StatusCode == 404 && out.Code == "not_offered":
		return nil, fmt.Errorf("%w (%s): %s", ErrNotOffered, cat, out.Message)
	case resp.StatusCode != 200 || (out.Grant == "" && !out.Admin):
		return nil, fmt.Errorf("merge: catalog service for %s refused the merge grant: %d %s %s", cat, resp.StatusCode, out.Code, out.Message)
	}
	return &MergeGrantResult{Grant: out.Grant, Admin: out.Admin, ApprovedBy: out.ApprovedBy, CheckedAs: out.CheckedAs}, nil
}

// ReleaseOptions configure the release functions.
type ReleaseOptions struct {
	// Release is the release document's link, /r/{ns}/{name}.
	Release string
	// StateNS holds the stored plan (default: the release document's
	// namespace). The merge locks are always in the release document's
	// namespace, which every release on a catalog base shares (§F.9).
	StateNS string
	// Granter signs catalog merge batches (needed when a branch's target
	// is a catalog).
	Granter MergeGranter
	// AdminGrant is a catalog admin's grant for the catalog (often the
	// approver's), under which a catalog batch that needs catalog-admins
	// (it changes $access, restores a folder, or widens) is submitted,
	// narrowed to exactly that batch with Via (§F.8). The catalog service
	// judges such a batch, which only an approver in catalog-admins gets
	// through, with this admin as the caller too (F-T4); for an end-to-end
	// catalog, which it checks no batch of, the merge service judges
	// whether a batch needs catalog-admins itself. Via is the merge
	// service's sub (default: Who).
	AdminGrant string
	Via        string
	// Digest, if set, is the digest the approving person reviewed:
	// ApproveRelease fails unless planning again gives it (§F.9).
	Digest string
	// Splits are resolutions of catalog nodes that narrow and widen:
	// key -> node -> the document after step 2 (§F.3 two resolution sets).
	Splits map[string]map[string]any
	// Accept lists placements (ns.name) whose existing placement the
	// approver accepts publishing under.
	Accept []string
	// Resolutions resolve content conflicts: "key/name" -> steps against
	// the base's current head.
	Resolutions map[string][]client.Step
	// SourceAuthorizations are sent with every batch (§7.8, §6.1).
	SourceAuthorizations []string
	// Who is recorded as planner or approver.
	Who string
	// Now is the clock (default time.Now).
	Now func() time.Time
	// AfterStep, if set, is called after each step is submitted and
	// recorded; an error stops the merge there (tests simulate a crash).
	AfterStep func(step *ReleaseStep) error
	// BehindWait bounds how long a catalog service that is behind is
	// waited for (default 30s).
	BehindWait time.Duration
	// AcceptFrozen are freezes this release's own approval made (branch
	// -> config id, ReleasePlan.FrozenBy): PlanRelease doesn't count them
	// as frozen, and classifies those branches as of their ns_id before
	// the freeze, which stays their source.at (§F.9).
	AcceptFrozen map[string]string
	// Signer, if set, signs every step the release writes (§C.3.1). Its
	// key must be listed in the signers of the grant the batches are sent
	// under, which for catalog batches is the service's, so a catalog
	// merge normally signs with the service's key or not at all.
	Signer *sig.Key
}

func (o *ReleaseOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// PlanName is the stored plan's resource name for a release.
func PlanName(rel string) string { return rel + ".merge" }

// LockName is the lock resource of a catalog base.
func LockName(catalogBase string) string { return "merge-lock." + catalogBase }

type relCtx struct {
	c   *client.Client
	e2e *client.E2E // if set, catalogBase reads an end-to-end catalog's documents with it (Plan.e2eTarget)
	opt ReleaseOptions
	rel *release.Loaded
	rp  *ReleasePlan
	// per key
	docs    map[string]map[string]any // key -> resource -> branch head doc (nil = deleted)
	plans   map[string]*Plan          // "step/key" -> plan used for classification
	listed  map[string]bool           // branch namespaces listed
	ownCfgs map[string]string         // branch -> config id our approval left (resume)
}

// PlanRelease classifies a release and reports its conflicts, without
// storing or changing anything.
func PlanRelease(ctx context.Context, c *client.Client, opt ReleaseOptions) (*ReleasePlan, error) {
	return planRelease(ctx, c, opt, opt.AcceptFrozen)
}

// AdoptHead makes rp replace the stored plan old when saved, keeping the
// freezes old's approval made (a plan made again after an approval).
func AdoptHead(rp, old *ReleasePlan) {
	rp.head, rp.nonced = old.head, old.nonced
	for _, b := range rp.Branches {
		if ob := old.Branch(b.Key); ob != nil && ob.NS == b.NS {
			b.FrozenConfig = ob.FrozenConfig
		}
	}
}

// FrozenBy returns the config ids of the freezes a stored plan's approval
// made, by branch (for ReleaseOptions.AcceptFrozen).
func (rp *ReleasePlan) FrozenBy() map[string]string {
	out := map[string]string{}
	for _, b := range rp.Branches {
		if b.FrozenConfig != "" {
			out[b.NS] = b.FrozenConfig
		}
	}
	return out
}

func planRelease(ctx context.Context, c *client.Client, opt ReleaseOptions, own map[string]string) (*ReleasePlan, error) {
	rel, err := release.Load(ctx, c, opt.Release)
	if err != nil {
		return nil, err
	}
	x := &relCtx{c: c, opt: opt, rel: rel, docs: map[string]map[string]any{}, plans: map[string]*Plan{}, listed: map[string]bool{}, ownCfgs: own}
	x.rp = &ReleasePlan{Format: PlanFormat, Release: rel.Ref.Live(), Revision: rel.Ref.Rev, Name: rel.Doc.Name, State: ReleasePlanned,
		PlannedBy: opt.Who, Halves: map[string]map[string]Half{}, Accepted: append([]string(nil), opt.Accept...)}
	for _, k := range rel.Doc.Keys() {
		x.listed[rel.Doc.Branches[k].NS] = true
	}
	if err := x.branches(ctx); err != nil {
		return nil, err
	}
	if err := x.classify(ctx); err != nil {
		return nil, err
	}
	if x.rp.Clean() {
		if err := x.digest(ctx); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(x.rp.Conflicts, func(i, j int) bool {
		a, b := x.rp.Conflicts[i], x.rp.Conflicts[j]
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Resource < b.Resource
	})
	return x.rp, nil
}

func (x *relCtx) conflict(kind, key, ns, res, msg string, paths ...string) {
	x.rp.Conflicts = append(x.rp.Conflicts, ReleaseConflict{Kind: kind, Key: key, NS: ns, Resource: res, Message: msg, Paths: paths})
}

func (x *relCtx) nsDoc(ctx context.Context, ns string) (map[string]any, string, error) {
	h, err := x.c.NSHead(ctx, ns)
	if err != nil {
		return nil, "", err
	}
	d, err := x.c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return nil, "", err
	}
	return d.Value, h.Config, nil
}

// targets resolves where each key merges: the key itself, or for a
// release built on another one (on), the earlier release's branch for the
// key (§F.9 Several releases).
func (x *relCtx) targets(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range x.rel.Doc.Keys() {
		out[k] = k
	}
	if x.rel.Doc.On == "" {
		return out, nil
	}
	on, err := release.Load(ctx, x.c, x.rel.Doc.On)
	if err != nil {
		return nil, fmt.Errorf("merge: the release this one builds on: %w", err)
	}
	for k, b := range on.Doc.Branches {
		if _, ok := out[k]; ok {
			out[k] = b.NS
		}
	}
	return out, nil
}

// branches runs the pre-approval checks (§F.9 Merging): each listed
// branch's base is the namespace it is keyed by, or for a release built on
// another, that release's branch for the key (targets), and it is neither
// frozen (but by our own approval) nor purged; and sorts its changed
// resources into schemas and content.
func (x *relCtx) branches(ctx context.Context) error {
	tg, err := x.targets(ctx)
	if err != nil {
		return err
	}
	for _, k := range x.rel.Doc.Keys() {
		br := x.rel.Doc.Branches[k].NS
		b := &ReleaseBranch{Key: k, NS: br, Target: tg[k]}
		x.rp.Branches = append(x.rp.Branches, b)
		doc, cfgID, err := x.nsDoc(ctx, br)
		if client.IsPurged(err) {
			// A sealed branch's document, once it is purged (§8.5): the
			// 410 is how the planner learns of the purge.
			x.conflict(RCPurged, k, br, "", br+" is purged")
			continue
		}
		if err != nil {
			return fmt.Errorf("merge: branch %s: %w", br, err)
		}
		// The base must be the target itself, not a namespace further down
		// a chain that reaches it (v0.63).
		bref, _ := doc["base"].(map[string]any)
		if bns, _ := bref["ns"].(string); bns != b.Target {
			what := br + " isn't a branch"
			if bns != "" {
				what = "the base of " + br + " is " + bns
			}
			want := "the namespace it is keyed by"
			if b.Target != k {
				want = "the branch the release it builds on lists for " + k
			}
			x.conflict(RCBaseChain, k, br, "", fmt.Sprintf("%s, not %s, %s (§F.9)", what, b.Target, want))
			continue
		}
		bl, err := x.c.Branches(ctx, b.Target)
		if client.IsPurged(err) {
			// A purged target's /branches is 410 (§7.4, §8.5), and its
			// branches were purged before it.
			x.conflict(RCPurged, k, br, "", br+" is purged, as is its base "+b.Target)
			continue
		}
		if err != nil {
			return fmt.Errorf("merge: branches of %s: %w", b.Target, err)
		}
		for _, e := range bl {
			if e.Name == br && e.Purged {
				x.conflict(RCPurged, k, br, "", br+" is purged")
			}
		}
		ownFreeze := false
		if f, _ := doc["frozen"].(bool); f {
			if own := x.ownCfgs[br]; own == "" || own != cfgID {
				x.conflict(RCFrozen, k, br, "", br+" is frozen (not by this release's approval): unfreeze it, or rebase the release")
			} else {
				ownFreeze = true
			}
		}
		tdoc, _, err := x.nsDoc(ctx, b.Target)
		if err != nil {
			return fmt.Errorf("merge: target %s: %w", b.Target, err)
		}
		_, b.Catalog = tdoc["catalog"].(map[string]any)

		// Changed resources, sorted into schemas and the rest, as of the
		// branch's at: its head, or once our approval froze it, its ns_id
		// before that freeze (§F.9).
		h, err := x.c.NSHead(ctx, br)
		if err != nil {
			return err
		}
		log, err := x.c.NSLog(ctx, br, h.ID, "")
		if client.IsPurged(err) {
			// Purged since its document was read (§8.5).
			x.conflict(RCPurged, k, br, "", br+" is purged")
			continue
		}
		if err != nil {
			return err
		}
		b.At = h.ID
		for i := len(log) - 1; ownFreeze && i > 0; i-- {
			if log[i].Kind == "config" && log[i].Target == cfgID {
				b.At, log = log[i].Prev, log[:i]
				break
			}
		}
		docs := map[string]any{}
		x.docs[k] = map[string]any{}
		var schemas []string
		for _, ch := range Collect(log) {
			if ch.Purged {
				continue
			}
			var d any
			schemaRes := false
			if ch.Kind == "head" {
				dd, err := x.c.Doc(ctx, br, ch.Resource, ch.Target)
				if err != nil {
					return fmt.Errorf("merge: %s/%s: %w", br, ch.Resource, err)
				}
				d = dd.Value
				schemaRes = isSchemaDoc(d)
			} else if hh, err := x.c.Head(ctx, br, ch.Resource); err == nil && hh.Last != "" {
				// A tombstoned schema resource is still one: its tombstones
				// and restores fast-forward like any entry (§F.9).
				if dd, err := x.c.Doc(ctx, br, ch.Resource, hh.Last); err == nil {
					schemaRes = isSchemaDoc(dd.Value)
				}
			}
			docs[ch.Resource] = d
			x.docs[k][ch.Resource] = d
			if schemaRes && !b.Catalog {
				schemas = append(schemas, ch.Resource)
			} else {
				b.Content = append(b.Content, ch.Resource)
			}
		}
		b.Schemas = refOrder(k, schemas, docs)
	}
	return nil
}

// isSchemaDoc reports a schema: a document whose $schema is a dialect URL.
func isSchemaDoc(d any) bool {
	m, _ := d.(map[string]any)
	s, _ := m["$schema"].(string)
	return s != "" && schema.IsDialect(s)
}

// refOrder sorts a namespace's schema resources so that each comes after
// those it references with $ref (cycles keep name order).
func refOrder(ns string, names []string, docs map[string]any) []string {
	sort.Strings(names)
	in := map[string]bool{}
	for _, n := range names {
		in[n] = true
	}
	var out []string
	state := map[string]int{}
	var visit func(n string)
	visit = func(n string) {
		if state[n] != 0 {
			return
		}
		state[n] = 1
		for _, r := range schema.Refs(docs[n]) {
			if r.NS == ns && in[r.Name] && r.Name != n {
				visit(r.Name)
			}
		}
		state[n] = 2
		out = append(out, n)
	}
	for _, n := range names {
		visit(n)
	}
	return out
}

func (x *relCtx) classify(ctx context.Context) error {
	if len(x.rp.Conflicts) > 0 {
		// The branches themselves are wrong: nothing else is meaningful.
		return nil
	}
	rp := x.rp
	// Step 1: schemas, by fast-forward only, keys in $ref order.
	keyDeps := map[string][]string{}
	for _, b := range rp.Branches {
		for _, s := range b.Schemas {
			for _, r := range schema.Refs(x.docs[b.Key][s]) {
				if r.NS != b.Key && rp.Branch(r.NS) != nil {
					keyDeps[b.Key] = append(keyDeps[b.Key], r.NS)
				}
			}
		}
	}
	var keyOrder []string
	seen := map[string]bool{}
	var visit func(k string)
	visit = func(k string) {
		if seen[k] {
			return
		}
		seen[k] = true
		for _, d := range keyDeps[k] {
			visit(d)
		}
		keyOrder = append(keyOrder, k)
	}
	for _, b := range rp.Branches {
		visit(b.Key)
	}
	for _, k := range keyOrder {
		b := rp.Branch(k)
		if len(b.Schemas) == 0 {
			continue
		}
		p, err := NewPlan(ctx, x.c, b.Target, b.NS, Options{Resources: b.Schemas, BranchAt: b.At, SourceAuthorizations: x.opt.SourceAuthorizations, Signer: x.opt.Signer})
		if err != nil {
			return err
		}
		x.plans[stepKey(1, k)] = p
		x.schemaConflicts(b, p)
		rp.Steps = append(rp.Steps, &ReleaseStep{Step: 1, Key: k, Resources: b.Schemas})
	}
	// Step 3 plans (content), classified now for the conflict checks.
	var contentSteps []*ReleaseStep
	for _, b := range rp.Branches {
		if b.Catalog || len(b.Content) == 0 {
			continue
		}
		p, err := NewPlan(ctx, x.c, b.Target, b.NS, Options{Resources: b.Content, BranchAt: b.At, SourceAuthorizations: x.opt.SourceAuthorizations, Signer: x.opt.Signer})
		if err != nil {
			return err
		}
		if err := x.applyResolutions(b, p); err != nil {
			return err
		}
		x.plans[stepKey(3, b.Key)] = p
		for _, r := range p.Conflicting() {
			kinds := []string{}
			var paths []string
			for _, c := range r.Conflicts {
				kinds = append(kinds, c.Kind)
				paths = append(paths, c.Paths...)
			}
			x.conflict(RCMerge, b.Key, b.NS, r.Name, "merge conflict ("+strings.Join(kinds, ", ")+"): resolve with -resolve "+b.Key+"/"+r.Name+"=file.json, or rebase the release", paths...)
		}
		contentSteps = append(contentSteps, &ReleaseStep{Step: 3, Key: b.Key, Resources: b.Content})
	}
	// Steps 2 and 4: catalog branches.
	var narrow, wide []*ReleaseStep
	for _, b := range rp.Branches {
		if !b.Catalog || len(b.Content) == 0 {
			continue
		}
		n, w, err := x.catalogSteps(ctx, b)
		if err != nil {
			return err
		}
		if len(n) > 0 {
			narrow = append(narrow, &ReleaseStep{Step: 2, Key: b.Key, Resources: n})
		}
		if len(w) > 0 {
			wide = append(wide, &ReleaseStep{Step: 4, Key: b.Key, Resources: w})
		}
	}
	rp.Steps = append(rp.Steps, narrow...)
	rp.Steps = append(rp.Steps, contentSteps...)
	rp.Steps = append(rp.Steps, wide...)

	if err := x.placedItems(ctx); err != nil {
		return err
	}
	if err := x.pins(ctx); err != nil {
		return err
	}
	return x.drafts(ctx)
}

func stepKey(step int, key string) string { return fmt.Sprintf("%d/%s", step, key) }

func (x *relCtx) schemaConflicts(b *ReleaseBranch, p *Plan) {
	for _, r := range p.Resources {
		switch r.Class {
		case FastForward:
			if r.NeedsPerson() {
				x.conflict(RCSchemaChanged, b.Key, b.NS, r.Name, "the schema resource can't fast-forward: "+conflictText(r))
			}
		case Replay:
			x.conflict(RCSchemaChanged, b.Key, b.NS, r.Name, b.Target+" changed the schema resource since the branch started, so it can't fast-forward (replaying would give ids no document references): rebase the release (§F.9), then migrate documents with replace /$schema")
		case Purged:
			x.conflict(RCSchemaChanged, b.Key, b.NS, r.Name, "the schema resource is purged: "+r.Note)
		}
	}
}

func conflictText(r *Resource) string {
	var out []string
	for _, c := range r.Conflicts {
		out = append(out, c.Kind+": "+c.Message)
	}
	return strings.Join(out, "; ")
}

func (x *relCtx) applyResolutions(b *ReleaseBranch, p *Plan) error {
	for name, steps := range x.opt.Resolutions {
		k, res, ok := strings.Cut(name, "/")
		if !ok || k != b.Key {
			continue
		}
		r := p.Resource(res)
		if r == nil {
			return fmt.Errorf("merge: resolution for %s: not a content resource of %s", name, b.NS)
		}
		if err := p.Resolve(res, steps...); err != nil {
			return err
		}
		if x.rp.Resolutions == nil {
			x.rp.Resolutions = map[string]StoredResolution{}
		}
		x.rp.Resolutions[name] = StoredResolution{Steps: StepsJSON(steps), At: r.resolvedAt}
	}
	return nil
}

// catalogBase reads a catalog target's configuration, node documents and
// the declared role inclusions of its trusted namespaces.
func (x *relCtx) catalogBase(ctx context.Context, target string) (map[string]any, map[string]any, map[string]catalog.Includes, error) {
	cfg, _, err := x.nsDoc(ctx, target)
	if err != nil {
		return nil, nil, nil, err
	}
	h, err := x.c.NSHead(ctx, target)
	if err != nil {
		return nil, nil, nil, err
	}
	heads, err := x.c.Heads(ctx, target, h.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	docs := map[string]any{}
	for _, hi := range heads {
		if hi.Kind != "head" {
			continue
		}
		if x.e2e != nil {
			// An end-to-end catalog: its documents folded with the keys,
			// its plaintext keyring no node (§E.3.2).
			if hi.Resource == client.KeyringName {
				continue
			}
			d, err := x.e2e.DocE2E(ctx, target, hi.Resource, hi.Target)
			if err != nil {
				return nil, nil, nil, err
			}
			docs[hi.Resource] = d.Value
			continue
		}
		d, err := x.c.Doc(ctx, target, hi.Resource, hi.Target)
		if err != nil {
			return nil, nil, nil, err
		}
		docs[hi.Resource] = d.Value
	}
	incs := map[string]catalog.Includes{}
	g := tree.BuildGraph(target, cfg, nil)
	for ns := range g.Trust {
		d, _, err := x.nsDoc(ctx, ns)
		if err != nil {
			if client.IsAuth(err) || client.IsNotFound(err) {
				continue
			}
			return nil, nil, nil, err
		}
		incs[ns] = catalog.ParseIncludes(d)
	}
	return cfg, docs, incs, nil
}

// catalogSteps sorts a catalog branch's changes into step 2 (narrowing)
// and step 4 (the rest), with halves for split nodes and for new folders
// a narrowing move needs.
func (x *relCtx) catalogSteps(ctx context.Context, b *ReleaseBranch) (narrow, wide []string, err error) {
	p, err := NewPlan(ctx, x.c, b.Target, b.NS, Options{Resources: b.Content, BranchAt: b.At, Signer: x.opt.Signer})
	if err != nil {
		return nil, nil, err
	}
	x.plans[stepKey(2, b.Key)] = p
	cfg, baseDocs, incs, err := x.catalogBase(ctx, b.Target)
	if err != nil {
		return nil, nil, err
	}
	before := tree.BuildGraph(b.Target, cfg, baseDocs)
	brDocs := x.docs[b.Key]
	halves := map[string]Half{}
	splits := x.opt.Splits[b.Key]

	var changed []string
	for _, r := range p.Resources {
		if r.Class == Merged || r.Class == Behind {
			continue
		}
		if r.NeedsPerson() {
			x.conflict(RCMerge, b.Key, b.NS, r.Name, "merge conflict in the catalog: "+conflictText(r)+"; rebase the release")
			continue
		}
		if r.Class == Purged {
			x.conflict(RCMerge, b.Key, b.NS, r.Name, "purged: "+r.Note)
			continue
		}
		changed = append(changed, r.Name)
	}
	isNewFolder := func(name string) bool {
		_, inBase := baseDocs[name]
		return !inBase && !strings.Contains(name, ".") && brDocs[name] != nil
	}
	parentsOf := func(doc any) []string {
		var out []string
		for _, pp := range tree.ParseNode(b.Target, "x", "", doc).Parents {
			if pp.Name != "" {
				out = append(out, pp.Name)
			}
		}
		return out
	}
	// Each change, with the new folders it moves into created with their
	// own $access; their own appearance doesn't count (§F.9: an empty
	// folder gives access to nothing but its title and its tree powers, so
	// the subset test applies to the items moved into it).
	without := func(d catalog.AccessDiff, skip map[string]bool) catalog.AccessDiff {
		var o catalog.AccessDiff
		for _, w := range d.Widens {
			if !skip[w.Node] {
				o.Widens = append(o.Widens, w)
			}
		}
		for _, n := range d.Narrows {
			if !skip[n.Node] {
				o.Narrows = append(o.Narrows, n)
			}
		}
		return o
	}
	inStep2 := map[string]bool{}
	helpers := map[string]bool{}
	step2Docs := map[string]any{}
	for _, name := range changed {
		if isNewFolder(name) {
			continue // decided below, with the moves that need it
		}
		doc := brDocs[name]
		if sd, ok := splits[name]; ok {
			// A person's split: the first half must narrow, the second
			// mustn't.
			mid := before.With(map[string]any{name: sd})
			d1 := catalog.DiffAccess(before, mid, incs)
			d2 := catalog.DiffAccess(mid, mid.With(map[string]any{name: doc}), incs)
			if len(d1.Widens) > 0 || len(d2.Narrows) > 0 {
				x.conflict(RCBadSplit, b.Key, b.NS, name, fmt.Sprintf("the split must narrow, then widen: its first half %s, its second %s", d1.Kind(), d2.Kind()))
				continue
			}
			// Each half must change the node ($nonce aside), or its step
			// has no item for it, and the plan's digest no item for the
			// second half's precondition to name (§F.9).
			if bd, ok := baseDocs[name]; ok && jsonv.Equal(dropNonce(bd), dropNonce(jsonv.FromGo(sd))) {
				x.conflict(RCBadSplit, b.Key, b.NS, name, "the split's first half is the catalog base's document as it is, so step 2 has nothing to merge for it: drop the split, and the change merges whole (§F.9)")
				continue
			}
			if jsonv.Equal(dropNonce(jsonv.FromGo(sd)), dropNonce(doc)) {
				x.conflict(RCBadSplit, b.Key, b.NS, name, "the split's second half is its first, so step 4 has nothing to merge for it: drop the split, and the change merges whole (§F.9)")
				continue
			}
			halves[name] = Half{Narrow: sd, Wide: doc, Reason: "split"}
			inStep2[name], step2Docs[name] = true, sd
			continue
		}
		ch := map[string]any{name: doc}
		hs := map[string]bool{}
		for _, pn := range parentsOf(doc) {
			if isNewFolder(pn) {
				ch[pn] = brDocs[pn]
				hs[pn] = true
			}
		}
		d := without(catalog.DiffAccess(before, before.With(ch), incs), hs)
		switch d.Kind() {
		case "narrows":
			inStep2[name], step2Docs[name] = true, doc
			for f := range hs {
				helpers[f] = true
				step2Docs[f] = ch[f]
			}
		case "both":
			var who []string
			for _, w := range d.Widens {
				who = append(who, w.Subject+" +"+w.Role+" on "+w.Node)
			}
			for _, n := range d.Narrows {
				who = append(who, n.Subject+" -"+n.Role+" on "+n.Node)
			}
			x.conflict(RCNarrowAndWiden, b.Key, b.NS, name, "the change narrows access for some subjects and widens it for others; resolve it with two resolution sets: -split "+b.Key+"/"+name+"=narrow.json, the document after the narrowing step (§F.3, §F.9)", who...)
		}
	}
	for f := range helpers {
		inStep2[f] = true
	}
	// The narrowing batch as a whole.
	if len(step2Docs) > 0 {
		d := without(catalog.DiffAccess(before, before.With(step2Docs), incs), helpers)
		if len(d.Widens) > 0 {
			var who []string
			for _, w := range d.Widens {
				who = append(who, w.Subject+" +"+w.Role+" on "+w.Node)
			}
			x.conflict(RCStep2Widens, b.Key, b.NS, "", "the narrowing changes widen access together (judged as one batch, §F.9)", who...)
		}
	}
	for _, name := range changed {
		if inStep2[name] {
			narrow = append(narrow, name)
		}
		if !inStep2[name] || halves[name].Wide != nil {
			wide = append(wide, name)
		}
	}
	if len(halves) > 0 {
		x.rp.Halves[b.Key] = halves
	}
	for f := range helpers {
		x.rp.Notes = append(x.rp.Notes, fmt.Sprintf("%s/%s: created in step 2, with its own $access, since a narrowing move needs it; its title, and the tree powers its $access gives, take effect from then on", b.Key, f))
	}
	sort.Strings(x.rp.Notes)
	return narrow, wide, nil
}

// placedItems: a content item step 3 creates or restores that a placement
// in a catalog base already names would be published under it by step 3
// (§F.9), unless the release keeps that placement and the approver accepts.
func (x *relCtx) placedItems(ctx context.Context) error {
	accepted := map[string]bool{}
	for _, a := range x.opt.Accept {
		accepted[a] = true
	}
	for _, cb := range x.rp.Branches {
		if !cb.Catalog {
			continue
		}
		cfg, _, err := x.nsDoc(ctx, cb.Target)
		if err != nil {
			return err
		}
		g := tree.BuildGraph(cb.Target, cfg, nil)
		changedInRelease := map[string]bool{}
		for _, n := range cb.Content {
			changedInRelease[n] = true
		}
		// Placements step 2 removes: unplacing narrows (§F.9).
		unplacedInStep2 := map[string]bool{}
		for _, st := range x.rp.Steps {
			if st.Step == 2 && st.Key == cb.Key {
				for _, n := range st.Resources {
					if d, ok := x.docs[cb.Key][n]; ok && d == nil {
						unplacedInStep2[n] = true
					}
				}
			}
		}
		for _, b := range x.rp.Branches {
			if b.Catalog || !g.Trust[b.Key] {
				continue
			}
			p := x.plans[stepKey(3, b.Key)]
			if p == nil {
				continue
			}
			for _, r := range p.Resources {
				creates := r.HasItem() && !r.BranchDeleted && (r.BaseState == client.NotFound.String() || r.BaseState == client.Tombstoned.String() || r.Base == "")
				if !creates {
					continue
				}
				pl := b.Key + "." + r.Name
				h, err := x.c.Head(ctx, cb.Target, pl)
				if err != nil {
					return err
				}
				if h.State != client.Live {
					continue
				}
				switch {
				case unplacedInStep2[pl]:
					// Step 2 removes it before step 3 creates the item.
				case changedInRelease[pl]:
					x.conflict(RCPlacedItem, b.Key, b.NS, r.Name, fmt.Sprintf("step 3 creates or restores %s/%s, which the placement %s/%s already names, and the release changes that placement other than by removing it in step 2: step 3 would publish the item under the base's placement before step 4 changes it", b.Key, r.Name, cb.Target, pl))
				case !accepted[pl]:
					x.conflict(RCPlacedItem, b.Key, b.NS, r.Name, fmt.Sprintf("step 3 creates or restores %s/%s, which the placement %s/%s already names: step 3 publishes it under that placement; accept with -accept-placement %s, or unplace it in the release", b.Key, r.Name, cb.Target, pl, pl))
				}
			}
		}
	}
	return nil
}

var pinRe = regexp.MustCompile(`^/r/([a-z0-9][a-z0-9_-]{0,63})/([a-z0-9][a-z0-9._-]{0,127})/rev/(1[a-z2-7]{32})(#.*)?$`)

// pins: a pinned reference (§6.5) or manifest entry (§B.4) naming a
// revision of another listed branch that the merge replays would dangle.
func (x *relCtx) pins(ctx context.Context) error {
	for _, b := range x.rp.Branches {
		for name, d := range x.docs[b.Key] {
			for _, link := range pinnedLinks(d) {
				m := pinRe.FindStringSubmatch(link)
				ns, res, id := m[1], m[2], m[3]
				var tb *ReleaseBranch
				for _, ob := range x.rp.Branches {
					if ob.Key == ns || ob.NS == ns {
						tb = ob
					}
				}
				if tb == nil {
					continue
				}
				var r *Resource
				for _, step := range []int{1, 2, 3} {
					if p := x.plans[stepKey(step, tb.Key)]; p != nil {
						if rr := p.Resource(res); rr != nil {
							r = rr
						}
					}
				}
				replays := r != nil && (r.Class == Replay || (r.Class == FastForward && p0(x, tb).Reencrypt))
				if !replays {
					continue
				}
				if _, err := x.c.Doc(ctx, tb.Target, res, id); err == nil {
					continue // the base has it: it doesn't dangle
				}
				x.conflict(RCDanglingPin, b.Key, b.NS, name, fmt.Sprintf("%s pins %s, a revision of %s that the merge replays with new ids, so the pin would dangle; rewrite it after the merge, or rebase so it fast-forwards", name, link, tb.NS))
			}
		}
	}
	return nil
}

func p0(x *relCtx, b *ReleaseBranch) *Plan {
	for _, s := range []int{3, 2, 1} {
		if p := x.plans[stepKey(s, b.Key)]; p != nil {
			return p
		}
	}
	return &Plan{}
}

// pinnedLinks lists strings in d that are pinned links, except $schema
// and $ref, which name schema revisions (merged by fast-forward).
func pinnedLinks(d any) []string {
	var out []string
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch t := v.(type) {
		case map[string]any:
			for k, c := range t {
				walk(c, k)
			}
		case []any:
			for _, c := range t {
				walk(c, key)
			}
		case string:
			if key != "$schema" && key != "$ref" && pinRe.MatchString(t) {
				out = append(out, t)
			}
		}
	}
	walk(d, "")
	sort.Strings(out)
	return out
}

// drafts: a document resolving a draft in a branch the release doesn't
// list ties this release to another one (§F.9). Schema paths are resolved
// as clients do (§6.1): the path's namespace, then the release's branches,
// then the others.
func (x *relCtx) drafts(ctx context.Context) error {
	prefer := x.rel.Doc.BranchNames()
	checked := map[string]bool{}
	var check func(b *ReleaseBranch, name, path string, depth int) error
	check = func(b *ReleaseBranch, name, path string, depth int) error {
		if checked[path] || depth > 32 {
			return nil
		}
		checked[path] = true
		ref, ok := schema.ParseRef(path)
		if !ok {
			return nil
		}
		r, err := x.c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true, Prefer: prefer})
		if err != nil {
			if client.IsNotFound(err) || client.IsGone(err) || client.IsAuth(err) {
				x.conflict(RCUnresolved, b.Key, b.NS, name, path+" resolves nowhere you can read")
				return nil
			}
			return err
		}
		if r.NS != ref.NS && !x.listed[r.NS] {
			x.conflict(RCForeignDraft, b.Key, b.NS, name, fmt.Sprintf("%s resolves to a draft in %s, which the release doesn't list: that ties it to another release; list %s, or merge that release first", path, r.NS, r.NS))
		}
		for _, rr := range schema.Refs(r.Doc.Value) {
			if err := check(b, name, rr.Path(), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, b := range x.rp.Branches {
		names := make([]string, 0, len(x.docs[b.Key]))
		for n := range x.docs[b.Key] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			m, _ := x.docs[b.Key][n].(map[string]any)
			if s, _ := m["$schema"].(string); s != "" && !schema.IsDialect(s) {
				if err := check(b, n, s, 0); err != nil {
					return err
				}
			} else if isSchemaDoc(m) {
				for _, rr := range schema.Refs(m) {
					if err := check(b, n, rr.Path(), 1); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// --- the stored plan --------------------------------------------------------

func (o ReleaseOptions) stateNS(rel string) (string, error) {
	if o.StateNS != "" {
		return o.StateNS, nil
	}
	r, err := release.ParseRef(rel)
	if err != nil {
		return "", err
	}
	return r.NS, nil
}

// LoadReleasePlan reads the stored plan of a release, nil if there is none.
func LoadReleasePlan(ctx context.Context, c *client.Client, opt ReleaseOptions) (*ReleasePlan, error) {
	ns, err := opt.stateNS(opt.Release)
	if err != nil {
		return nil, err
	}
	ref, err := release.ParseRef(opt.Release)
	if err != nil {
		return nil, err
	}
	h, d, err := c.Load(ctx, ns, PlanName(ref.Name))
	if err != nil {
		return nil, err
	}
	if h.State != client.Live {
		return nil, nil
	}
	b, err := json.Marshal(d.Value)
	if err != nil {
		return nil, err
	}
	var rp ReleasePlan
	if err := json.Unmarshal(b, &rp); err != nil {
		return nil, fmt.Errorf("merge: stored plan %s/%s: %w", ns, PlanName(ref.Name), err)
	}
	rp.head = h.ID
	m, _ := d.Value.(map[string]any)
	_, rp.nonced = m["$nonce"]
	return &rp, nil
}

// SaveReleasePlan stores rp (a new revision with If-Match on the one
// loaded, or a new resource), with a fresh $nonce where the state
// namespace needs one (stateNonce).
func SaveReleasePlan(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan) error {
	ns, err := opt.stateNS(rp.Release)
	if err != nil {
		return err
	}
	name := PlanName(rp.Name)
	b, err := json.Marshal(rp)
	if err != nil {
		return err
	}
	val, err := jsonv.Parse(b)
	if err != nil {
		return err
	}
	replace := []any{map[string]any{"op": "replace", "path": "", "value": val}}
	if rp.head == "" {
		h, err := c.Head(ctx, ns, name)
		if err != nil {
			return err
		}
		switch h.State {
		case client.Live:
			rp.head = h.ID
		case client.Tombstoned:
			ps, nonced := stateNonce(ctx, c, ns, false, replace)
			res, err := c.Restore(ctx, ns, name, h.ID, ps)
			if err != nil {
				return fmt.Errorf("merge: storing the plan: %w", err)
			}
			rp.head, rp.nonced = res.ID, nonced
			return nil
		default:
			ps, nonced := stateNonce(ctx, c, ns, false, client.GenesisPatches(val))
			res, err := c.Create(ctx, ns, name, ps)
			if err != nil {
				return fmt.Errorf("merge: storing the plan: %w", err)
			}
			rp.head, rp.nonced = res.ID, nonced
			return nil
		}
	}
	ps, nonced := stateNonce(ctx, c, ns, rp.nonced, replace)
	res, err := c.Append(ctx, ns, name, rp.head, ps)
	if err != nil {
		return fmt.Errorf("merge: storing the plan: %w", err)
	}
	rp.head, rp.nonced = res.ID, nonced
	return nil
}

// ApproveRelease plans again and, if the plan is clean and for the
// release document's revision that was planned, freezes every listed
// branch and stores the approved plan. A stored plan that is already
// approved, or an approval that stopped part-way, is resumed: freezes
// recorded by this approval are accepted.
func ApproveRelease(ctx context.Context, c *client.Client, opt ReleaseOptions) (*ReleasePlan, error) {
	stored, err := LoadReleasePlan(ctx, c, opt)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, errors.New("merge: no stored plan: run plan first, and review it")
	}
	switch stored.State {
	case ReleaseMerging, ReleaseDone, ReleaseAbandoned:
		return stored, fmt.Errorf("merge: the release is already %s", stored.State)
	}
	if stored.Format != PlanFormat {
		return stored, fmt.Errorf("%w: the stored plan predates the plan digest of §F.9 (format %d, now %d): plan again and review", ErrDigest, stored.Format, PlanFormat)
	}
	own := stored.FrozenBy()
	// The person approves what they reviewed: the stored plan's choices.
	if opt.Splits == nil {
		opt.Splits = stored.splits()
	}
	if opt.Accept == nil {
		opt.Accept = stored.Accepted
	}
	if opt.Resolutions == nil {
		opt.Resolutions = stored.resolutions()
	}
	fresh, err := planRelease(ctx, c, opt, own)
	if err != nil {
		return nil, err
	}
	if fresh.Revision != stored.Revision {
		return fresh, fmt.Errorf("merge: the release document changed since it was planned (%s, now %s): plan again and review", stored.Revision, fresh.Revision)
	}
	if !fresh.Clean() {
		return fresh, ErrConflicts
	}
	// The person approves the digest of what they reviewed (§F.9).
	if opt.Digest != "" && opt.Digest != stored.Digest {
		return fresh, fmt.Errorf("%w: you reviewed %s, the stored plan is %s", ErrDigest, opt.Digest, stored.Digest)
	}
	if fresh.Digest != stored.Digest {
		return fresh, fmt.Errorf("%w: planning again gives %s, the stored plan is %s: plan again and review", ErrDigest, fresh.Digest, stored.Digest)
	}
	fresh.head, fresh.nonced = stored.head, stored.nonced
	fresh.State = ReleaseApproved
	fresh.PlannedBy = stored.PlannedBy
	fresh.ApprovedBy, fresh.ApprovedAt = opt.Who, opt.now().UTC().Format(time.RFC3339)
	for _, b := range fresh.Branches {
		b.FrozenConfig = own[b.NS]
	}
	for _, b := range fresh.Branches {
		if b.FrozenConfig != "" {
			continue
		}
		res, err := configWrite(ctx, c, b.NS, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}})
		if err != nil {
			return fresh, fmt.Errorf("merge: freezing %s: %w", b.NS, err)
		}
		b.FrozenConfig = res.Config
		// Each source.at stays the branch's ns_id before this freeze
		// (§F.9): the one planned, unless the branch moved in between,
		// which a new plan must take in.
		prev, err := entryBefore(ctx, c, b.NS, res.NSID, b.At)
		if err != nil {
			return fresh, fmt.Errorf("merge: freezing %s: %w", b.NS, err)
		}
		moved := prev != b.At
		b.At = prev
		if moved {
			fresh.State, fresh.ApprovedBy, fresh.ApprovedAt = ReleasePlanned, "", ""
		}
		// Record each freeze as it happens, so a stopped approval resumes.
		if err := SaveReleasePlan(ctx, c, opt, fresh); err != nil {
			return fresh, err
		}
		if moved {
			return fresh, fmt.Errorf("%w: %s changed after it was planned, before the approval froze it: plan again and review", ErrDigest, b.NS)
		}
	}
	return fresh, SaveReleasePlan(ctx, c, opt, fresh)
}

// legacyAts gives each branch of a plan an earlier version stored, which
// records no at, its ns_id before the approval's freeze (§F.9): the entry
// before the config entry of its FrozenConfig. A branch that records
// merged has no step left and keeps none.
func legacyAts(ctx context.Context, c *client.Client, rp *ReleasePlan) error {
	for _, b := range rp.Branches {
		if b.At != "" || b.Merged != "" || b.FrozenConfig == "" {
			continue
		}
		h, err := c.NSHead(ctx, b.NS)
		if err != nil {
			return err
		}
		log, err := c.NSLog(ctx, b.NS, h.ID, "")
		if err != nil {
			return err
		}
		for i := len(log) - 1; i > 0 && b.At == ""; i-- {
			if log[i].Kind == "config" && log[i].Target == b.FrozenConfig {
				b.At = log[i].Prev
			}
		}
		if b.At == "" {
			return fmt.Errorf("%w: %s's log has no freeze %s by the approval", ErrInvalidPlan, b.NS, b.FrozenConfig)
		}
	}
	return nil
}

// entryBefore returns the ns_id before the entry id of ns's chain, which
// follows since (an ns_id in that chain).
func entryBefore(ctx context.Context, c *client.Client, ns, id, since string) (string, error) {
	log, err := c.NSLog(ctx, ns, id, since)
	if err != nil {
		return "", err
	}
	if len(log) == 0 || log[len(log)-1].ID != id {
		return "", fmt.Errorf("merge: %s's log after %s doesn't end with %s", ns, since, id)
	}
	return log[len(log)-1].Prev, nil
}

func (rp *ReleasePlan) splits() map[string]map[string]any {
	out := map[string]map[string]any{}
	for k, hs := range rp.Halves {
		for n, h := range hs {
			if h.Reason != "split" {
				continue
			}
			if out[k] == nil {
				out[k] = map[string]any{}
			}
			out[k][n] = h.Narrow
		}
	}
	return out
}

func (rp *ReleasePlan) resolutions() map[string][]client.Step {
	out := map[string][]client.Step{}
	for k, r := range rp.Resolutions {
		var steps []client.Step
		for _, s := range r.Steps {
			if str, ok := s.(string); ok && str == "delete" {
				steps = append(steps, client.DeleteStep())
			} else {
				steps = append(steps, client.PatchStep(s))
			}
		}
		out[k] = steps
	}
	return out
}

// ErrInvalidPlan is returned when the stored plan no longer holds: the
// release document changed, or a branch was unfrozen or changed.
var ErrInvalidPlan = errors.New("merge: the plan is no longer valid")

// ErrDigest is returned when an approval's plan digest doesn't match
// (§F.9): the plan changed since it was reviewed.
var ErrDigest = errors.New("merge: the plan's digest changed")

// ApplyRelease merges an approved release from its stored plan, resuming
// where it stopped.
func ApplyRelease(ctx context.Context, c *client.Client, opt ReleaseOptions) (*ReleasePlan, error) {
	rp, err := LoadReleasePlan(ctx, c, opt)
	if err != nil {
		return nil, err
	}
	if rp == nil {
		return nil, errors.New("merge: no stored plan: plan and approve first")
	}
	switch rp.State {
	case ReleaseDone:
		return rp, nil
	case ReleaseAbandoned:
		return rp, errors.New("merge: the release was abandoned")
	case ReleaseApproved, ReleaseMerging:
	default:
		return rp, fmt.Errorf("merge: the plan is %s, not approved", rp.State)
	}
	// A plan an earlier version stored (format 0) is planned and approved
	// again, unless that version stopped part-way through merging it: such
	// a merge resumes from that plan and never reverts (§F.9), its steps
	// checked against the step digests it stored (approvedStep), each
	// source.at its branch's ns_id before the approval's freeze
	// (legacyAts), and the lock it took for its release taken over
	// (acquireLock).
	legacy := rp.Format == 0 && rp.State == ReleaseMerging
	if rp.Digest == "" || (rp.Format != PlanFormat && !legacy) {
		return rp, fmt.Errorf("%w: it was approved without the plan digest of §F.9 (format %d, now %d): plan and approve again", ErrInvalidPlan, rp.Format, PlanFormat)
	}
	if err := checkApproved(ctx, c, rp); err != nil {
		return rp, err
	}
	if legacy {
		if err := legacyAts(ctx, c, rp); err != nil {
			return rp, err
		}
	}
	// One release per catalog base at a time.
	for _, b := range rp.Branches {
		if b.Catalog {
			if err := acquireLock(ctx, c, opt, rp, b.Target); err != nil {
				return rp, err
			}
		}
	}
	if rp.State == ReleaseApproved {
		rp.State = ReleaseMerging
		if err := SaveReleasePlan(ctx, c, opt, rp); err != nil {
			return rp, err
		}
	}
	for _, st := range rp.Steps {
		if st.Done != "" {
			continue
		}
		done, err := runStep(ctx, c, opt, rp, st)
		if err != nil {
			return rp, fmt.Errorf("merge: step %d (%s): %w", st.Step, st.Key, err)
		}
		st.Done = done
		if err := SaveReleasePlan(ctx, c, opt, rp); err != nil {
			return rp, err
		}
		if opt.AfterStep != nil {
			if err := opt.AfterStep(st); err != nil {
				return rp, err
			}
		}
	}
	// Every branch records merged only after step 4, with at the target's
	// ns_id after the last batch into it (§F.9): for the catalog, after
	// step 4. A branch none of whose batches had anything left to do
	// records the target's head.
	for _, b := range rp.Branches {
		if b.Merged != "" {
			continue
		}
		at := ""
		for _, st := range rp.Steps {
			if st.Key == b.Key && st.Done != "" && st.Done != "noop" {
				at = st.Done
			}
		}
		if at == "" {
			h, err := c.NSHead(ctx, b.Target)
			if err != nil {
				return rp, err
			}
			at = h.ID
		}
		if _, err := Freeze(ctx, c, b.NS, at); err != nil {
			return rp, fmt.Errorf("merge: recording merged on %s: %w", b.NS, err)
		}
		b.Merged = at
		if err := SaveReleasePlan(ctx, c, opt, rp); err != nil {
			return rp, err
		}
	}
	rp.State = ReleaseDone
	if err := SaveReleasePlan(ctx, c, opt, rp); err != nil {
		return rp, err
	}
	for _, b := range rp.Branches {
		if b.Catalog {
			if err := releaseLock(ctx, c, opt, rp, b.Target); err != nil {
				return rp, err
			}
		}
	}
	return rp, nil
}

// checkApproved verifies that the plan still holds: the release document
// is the revision planned, and every branch is frozen by the approval and
// unchanged since (any config change, unfreezing included, moves its
// config id). A branch that already records merged (by this merge) passes.
func checkApproved(ctx context.Context, c *client.Client, rp *ReleasePlan) error {
	rel, err := release.Load(ctx, c, rp.Release)
	if err != nil {
		return err
	}
	if rel.Ref.Rev != rp.Revision {
		return fmt.Errorf("%w: the release document changed since it was planned (%s, now %s)", ErrInvalidPlan, rp.Revision, rel.Ref.Rev)
	}
	for _, b := range rp.Branches {
		h, err := c.NSHead(ctx, b.NS)
		if err != nil {
			return err
		}
		if h.Config == b.FrozenConfig {
			continue
		}
		d, err := c.NSDoc(ctx, b.NS, h.ID)
		if err != nil {
			return err
		}
		f, _ := d.Value["frozen"].(bool)
		_, merged := d.Value["merged"]
		if f && merged && b.Merged != "" {
			continue
		}
		if f && merged && allDone(rp) {
			continue // merged recorded, but the plan not saved after it
		}
		return fmt.Errorf("%w: %s changed after the approval froze it (unfrozen, or its configuration changed): plan and approve again", ErrInvalidPlan, b.NS)
	}
	return nil
}

func allDone(rp *ReleasePlan) bool {
	for _, s := range rp.Steps {
		if s.Done == "" {
			return false
		}
	}
	return true
}

// AbandonRelease gives a release up (§F.9 Abandoning): every listed
// branch is frozen with "abandoned": true, which the janitor accepts only
// from a grant chained to a * key of the branch (§F.6), so c should carry
// an administrator's. A stored plan is marked abandoned and its catalog
// locks released. What step 1 merged stays in the schema namespace's
// history, unused. It returns the branches it abandoned.
func AbandonRelease(ctx context.Context, c *client.Client, opt ReleaseOptions) ([]string, error) {
	rel, err := release.Load(ctx, c, opt.Release)
	if err != nil {
		return nil, err
	}
	rp, err := LoadReleasePlan(ctx, c, opt)
	if err != nil {
		return nil, err
	}
	if rp != nil && rp.State == ReleaseDone {
		return nil, errors.New("merge: the release is merged; there is nothing to abandon")
	}
	var out []string
	for _, k := range rel.Doc.Keys() {
		ns := rel.Doc.Branches[k].NS
		h, err := c.NSHead(ctx, ns)
		if err != nil {
			return out, err
		}
		d, err := c.NSDoc(ctx, ns, h.ID)
		if err != nil {
			return out, err
		}
		if f, _ := d.Value["frozen"].(bool); f {
			if ab, _ := d.Value["abandoned"].(bool); ab {
				continue
			}
		}
		patches := []any{map[string]any{"op": "add", "path": "/frozen", "value": true},
			map[string]any{"op": "add", "path": "/abandoned", "value": true}}
		if _, err := configWrite(ctx, c, ns, patches); err != nil {
			return out, fmt.Errorf("merge: abandoning %s: %w", ns, err)
		}
		out = append(out, ns)
	}
	if rp != nil {
		rp.State = ReleaseAbandoned
		if err := SaveReleasePlan(ctx, c, opt, rp); err != nil {
			return out, err
		}
		for _, b := range rp.Branches {
			if b.Catalog {
				if err := releaseLock(ctx, c, opt, rp, b.Target); err != nil {
					return out, err
				}
			}
		}
	}
	return out, nil
}

// ErrLocked is returned when another release holds a catalog base.
var ErrLocked = errors.New("merge: another release is merging into the catalog base")

// Lock is the state of a catalog base's merge lock (§F.9).
type Lock struct {
	NS    string       `json:"ns"` // the release document's namespace
	Name  string       `json:"name"`
	Head  string       `json:"head,omitempty"` // "" if it doesn't exist
	State client.State `json:"-"`
	// Holder is the sub of the merge service that holds it, and Plan the
	// digest of its plan; both "" while it is free.
	Holder string `json:"holder,omitempty"`
	Plan   string `json:"plan,omitempty"`
	// Legacy is the release an earlier version's lock ({ "release" })
	// names: held, for a person to release.
	Legacy string `json:"legacy,omitempty"`
	nonced bool
}

// Free reports a lock nobody holds: absent, or {} aside from $nonce (an
// earlier version's { "release": null } counts as free too).
func (l *Lock) Free() bool {
	return l.State == client.NotFound || (l.State == client.Live && l.Holder == "" && l.Plan == "" && l.Legacy == "")
}

// heldFor reports a lock held for rp: for its digest, or, for a plan an
// earlier version stored (format 0), the lock ({ "release" }) that version
// took for rp's release.
func (l *Lock) heldFor(rp *ReleasePlan) bool {
	if l.State != client.Live {
		return false
	}
	return (l.Plan != "" && l.Plan == rp.Digest) || (rp.Format == 0 && l.Legacy != "" && l.Legacy == rp.Release)
}

// lockNS is the namespace of a release's merge locks: the release
// document's own, which every release on a catalog base shares (§F.9),
// whatever StateNS says.
func lockNS(rel string) (string, error) {
	r, err := release.ParseRef(rel)
	if err != nil {
		return "", err
	}
	return r.NS, nil
}

// ReadLock reads the merge lock of a catalog base for the release opt
// names.
func ReadLock(ctx context.Context, c *client.Client, opt ReleaseOptions, catalogBase string) (*Lock, error) {
	ns, err := lockNS(opt.Release)
	if err != nil {
		return nil, err
	}
	return readLock(ctx, c, ns, catalogBase)
}

func readLock(ctx context.Context, c *client.Client, ns, base string) (*Lock, error) {
	l := &Lock{NS: ns, Name: LockName(base)}
	h, err := c.Head(ctx, ns, l.Name)
	if err != nil {
		return nil, err
	}
	l.State = h.State
	if h.State != client.Live {
		return l, nil
	}
	l.Head = h.ID
	d, err := c.Doc(ctx, ns, l.Name, h.ID)
	if err != nil {
		return nil, err
	}
	m, _ := d.Value.(map[string]any)
	l.Holder, _ = m["holder"].(string)
	l.Plan, _ = m["plan"].(string)
	l.Legacy, _ = m["release"].(string)
	_, l.nonced = m["$nonce"]
	return l, nil
}

// LockHolder returns the sub of the merge service holding a catalog base's
// lock, or the release an earlier version's lock names ("" if it is free).
func LockHolder(ctx context.Context, c *client.Client, opt ReleaseOptions, catalogBase string) (string, error) {
	l, err := ReadLock(ctx, c, opt, catalogBase)
	if err != nil {
		return "", err
	}
	if l.Holder == "" && l.Legacy != "" {
		return l.Legacy, nil
	}
	return l.Holder, nil
}

// writeLock writes doc to the lock: a create with If-None-Match: * when it
// doesn't exist, otherwise an append with If-Match on the head read, with
// a fresh $nonce where one is needed (stateNonce).
func writeLock(ctx context.Context, c *client.Client, l *Lock, doc map[string]any) error {
	if l.State == client.NotFound {
		ps, _ := stateNonce(ctx, c, l.NS, false, client.GenesisPatches(doc))
		_, err := c.Create(ctx, l.NS, l.Name, ps)
		return err
	}
	ps, _ := stateNonce(ctx, c, l.NS, l.nonced, []any{map[string]any{"op": "replace", "path": "", "value": doc}})
	_, err := c.Append(ctx, l.NS, l.Name, l.Head, ps)
	return err
}

// acquireLock takes the lock of a catalog base for rp (§F.9): a free lock
// is taken by setting holder, this service's sub (a create with
// If-None-Match: *, or an append with If-Match on its free head), then
// plan, rp's digest, is set by a further compare-and-append. A lock held
// for rp (heldFor: for its digest, or the lock an earlier version took
// for the release of a plan it stored and stopped merging) is resumed,
// set to this service's sub and rp's digest where it differs. Any other
// held lock is ErrLocked, naming its holder and plan, for a person to
// release; so too, resuming a merge an earlier version stopped, a lock
// held for another release in StateNS, where that version kept its locks.
func acquireLock(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, base string) error {
	ns, err := lockNS(rp.Release)
	if err != nil {
		return err
	}
	if sns, err := opt.stateNS(rp.Release); err == nil && rp.Format == 0 && sns != ns {
		l, err := readLock(ctx, c, sns, base)
		if err != nil {
			return err
		}
		if l.State == client.Live && !l.Free() && !l.heldFor(rp) {
			return lockedErr(l, rp)
		}
	}
	sub, _, err := c.Principal(ctx)
	if err != nil {
		return err
	}
	took := false
	for i := 0; i < 5; i++ {
		l, err := readLock(ctx, c, ns, base)
		if err != nil {
			return err
		}
		var doc map[string]any
		switch {
		case l.State != client.NotFound && l.State != client.Live:
			return fmt.Errorf("merge: the lock %s/%s is %s", ns, l.Name, l.State)
		case l.Free():
			doc = map[string]any{"holder": sub}
		case l.Plan == rp.Digest && l.Holder == sub:
			return nil
		case l.heldFor(rp), took && l.Holder == sub && l.Plan == "":
			// Resuming rp, or ours from this call's take: (re)set holder
			// and plan.
			doc = map[string]any{"holder": sub, "plan": rp.Digest}
		default:
			return lockedErr(l, rp)
		}
		err = writeLock(ctx, c, l, doc)
		switch {
		case err == nil && doc["plan"] != nil:
			return nil
		case err == nil:
			took = true
		case !client.IsStale(err) && !deletedSince(err):
			// Anything but a lock that moved since it was read, which the
			// next round reads again.
			return fmt.Errorf("merge: taking the lock %s/%s: %w", ns, l.Name, err)
		}
	}
	return fmt.Errorf("merge: the lock %s/%s keeps changing", ns, LockName(base))
}

// deletedSince reports the 410 gone with head that a create, or an
// append on an older head, gets on a resource deleted since it was read; a
// create used to get a 412 (§7.2, §8.1). The resource moved, as for a 412.
func deletedSince(err error) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == 410 && ae.Code == "gone" && ae.Head() != ""
}

// lockedErr is ErrLocked for a lock held other than for rp, naming its
// holder and plan.
func lockedErr(l *Lock, rp *ReleasePlan) error {
	holder, plan := l.Holder, l.Plan
	if l.Legacy != "" {
		holder = "an earlier version's merge of " + l.Legacy
	}
	if plan == "" {
		plan = "(none)"
	}
	return fmt.Errorf("%w: %s holds %s/%s for plan %s, not this release's %s; a person releases it", ErrLocked, holder, l.NS, l.Name, plan, rp.Digest)
}

// releaseLock releases the lock of a catalog base if it is held for rp
// (heldFor): an append back to {} (§F.9). For a plan an earlier version
// stored, so too the lock that version took in StateNS, where it kept its
// locks.
func releaseLock(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, base string) error {
	ns, err := lockNS(rp.Release)
	if err != nil {
		return err
	}
	nss := []string{ns}
	if sns, err := opt.stateNS(rp.Release); err == nil && rp.Format == 0 && sns != ns {
		nss = append(nss, sns)
	}
	for _, ns := range nss {
		l, err := readLock(ctx, c, ns, base)
		if err != nil {
			return err
		}
		if !l.heldFor(rp) {
			continue
		}
		if err := writeLock(ctx, c, l, map[string]any{}); err != nil {
			return err
		}
	}
	return nil
}

// stepItem is one item of a step's batch as a plan's digest renders it
// (digestItems): the resource, its precondition and its steps.
type stepItem struct {
	name  string
	pre   map[string]any
	steps []client.Step
}

// stepPlan builds one step's batch from the stored plan, classified again
// against the targets as they are: the plan (nil if nothing is left to
// do) and the step's items (§F.9). planning builds it before anything is
// submitted: the second half of a split node then applies to the first
// half's result, which isn't in the target yet.
func stepPlan(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, st *ReleaseStep, planning bool) (*Plan, []stepItem, error) {
	b := rp.Branch(st.Key)
	if b == nil {
		return nil, nil, fmt.Errorf("no branch for %s in the plan", st.Key)
	}
	halves := rp.Halves[st.Key]
	names := st.Resources
	var keep []string // resources with an item from the branch
	type half struct {
		name string
		doc  any // the document this step reaches
	}
	var hs []half
	if b.Catalog {
		for _, n := range names {
			h, ok := halves[n]
			if !ok {
				keep = append(keep, n)
				continue
			}
			target := h.Wide
			if st.Step == 2 {
				target = h.Narrow
			}
			hs = append(hs, half{n, target})
		}
	} else {
		keep = names
	}
	// Halves: resolution sets against the base's current head; one whose
	// head already has the document is done (a resumed step). Planned
	// second halves apply to the first half's result.
	var resolve []half
	var items []stepItem
	var np *Plan // the target's nonce needs, for planned second halves
	for _, h := range hs {
		if planning && st.Step == 4 {
			if np == nil {
				var err error
				if np, err = noncePlan(ctx, c, b.Target); err != nil {
					return nil, nil, err
				}
			}
			// As Force will build it from the first half's result.
			diff := Diff(np.nonceless(jsonv.FromGo(halves[h.name].Narrow)), np.nonceless(jsonv.FromGo(h.doc)))
			if diff == nil {
				diff = []any{}
			}
			items = append(items, stepItem{h.name, map[string]any{"after": map[string]any{"step": 2, "key": st.Key, "item": h.name}}, np.withNonces([]client.Step{client.PatchStep(diff)})})
			continue
		}
		cur, err := c.Head(ctx, b.Target, h.name)
		if err != nil {
			return nil, nil, err
		}
		if cur.State == client.Live {
			d, err := c.Doc(ctx, b.Target, h.name, cur.ID)
			if err != nil {
				return nil, nil, err
			}
			// $nonce aside: where the target needs one, the half was
			// written with a fresh one (§C.7).
			if jsonv.Equal(dropNonce(d.Value), dropNonce(jsonv.FromGo(h.doc))) {
				continue
			}
			if st.Step == 4 && !jsonv.Equal(dropNonce(d.Value), dropNonce(jsonv.FromGo(halves[h.name].Narrow))) {
				return nil, nil, fmt.Errorf("%s/%s changed in %s between steps 2 and 4: plan again", b.Target, h.name, b.Target)
			}
		}
		resolve = append(resolve, h)
	}
	all := append([]string(nil), keep...)
	for _, h := range resolve {
		all = append(all, h.name)
	}
	if len(all) == 0 {
		return nil, items, nil
	}
	p, err := NewPlan(ctx, c, b.Target, b.NS, Options{Resources: all, BranchAt: b.At, SourceAuthorizations: opt.SourceAuthorizations, Signer: opt.Signer})
	if err != nil {
		return nil, nil, err
	}
	if st.Step == 1 {
		p.Order(st.Resources)
		for _, r := range p.Resources {
			if r.Class == Replay || r.Class == Purged || (r.Class == FastForward && r.NeedsPerson()) {
				return nil, nil, fmt.Errorf("schema resource %s can't fast-forward any more (%s): rebase the release", r.Name, r.Class)
			}
		}
	}
	if st.Step == 3 {
		for k, sr := range rp.Resolutions {
			key, res, _ := strings.Cut(k, "/")
			if key != st.Key || p.Resource(res) == nil {
				continue
			}
			steps := (&ReleasePlan{Resolutions: map[string]StoredResolution{k: sr}}).resolutions()[k]
			if err := p.Resolve(res, steps...); err != nil {
				return nil, nil, err
			}
			if r := p.Resource(res); r.resolvedAt != sr.At {
				return nil, nil, fmt.Errorf("the resolution of %s was written against %s, but the base is at %s now: plan again", k, sr.At, r.resolvedAt)
			}
		}
	}
	second := map[string]bool{}
	for _, h := range resolve {
		r := p.Resource(h.name)
		if r == nil {
			return nil, nil, fmt.Errorf("%s: not changed by %s", h.name, b.NS)
		}
		var step client.Step
		switch {
		case r.Base == "" || r.BaseState != client.Live.String():
			step = client.PatchStep(client.GenesisPatches(jsonv.FromGo(h.doc)))
			if r.BaseState == client.Tombstoned.String() {
				step = client.PatchStep([]any{map[string]any{"op": "replace", "path": "", "value": jsonv.FromGo(h.doc)}})
			}
		default:
			d, err := c.Doc(ctx, b.Target, h.name, r.Base)
			if err != nil {
				return nil, nil, err
			}
			diff := Diff(p.nonceless(d.Value), p.nonceless(jsonv.FromGo(h.doc)))
			if diff == nil {
				diff = []any{}
			}
			step = client.PatchStep(diff)
		}
		if err := p.Force(h.name, step); err != nil {
			return nil, nil, err
		}
		second[h.name] = st.Step == 4
	}
	if !p.Clean() {
		var msgs []string
		for _, r := range p.Conflicting() {
			msgs = append(msgs, r.Name+": "+conflictText(r))
		}
		return nil, nil, fmt.Errorf("%w: %s", ErrConflicts, strings.Join(msgs, "; "))
	}
	for _, r := range p.Items() {
		var pre map[string]any
		switch {
		case second[r.Name]:
			pre = map[string]any{"after": map[string]any{"step": 2, "key": st.Key, "item": r.Name}}
		case r.IfNoneMatch:
			pre = map[string]any{"ifNoneMatch": "*"}
		default:
			pre = map[string]any{"ifMatch": r.IfMatch}
		}
		items = append(items, stepItem{r.Name, pre, r.Steps})
	}
	if len(p.Items()) == 0 {
		p = nil
	}
	return p, items, nil
}

// digestItems renders a step's items for the plan's digest (§F.9), in the
// order its batch sends them (orderItems).
func digestItems(st *ReleaseStep, items []stepItem) []any {
	out := make([]any, 0, len(items))
	for _, it := range items {
		out = append(out, digestItem(it.name, it.pre, it.steps))
	}
	return orderItems(st, out)
}

// digestItem is one item of a plan's digest (§F.9): the resource, its
// precondition and its steps (digestSteps). A precondition on the result
// of an earlier step, the second half of a split node, is written here as
// "after": { step, key, item }; PlanDigest turns it into { batch, item }.
func digestItem(name string, pre map[string]any, steps []client.Step) map[string]any {
	m := map[string]any{"resource": name, "steps": digestSteps(steps)}
	for k, v := range pre {
		m[k] = v
	}
	return m
}

// orderItems puts a step's digest items in the order its batch sends them:
// a schema step's in its $ref order (Plan.Order), the others' by name, as
// a plan lists resources.
func orderItems(st *ReleaseStep, items []any) []any {
	pos := map[string]int{}
	if st.Step == 1 {
		for i, n := range st.Resources {
			pos[n] = i + 1
		}
	}
	name := func(i int) string { return items[i].(map[string]any)["resource"].(string) }
	sort.SliceStable(items, func(i, j int) bool {
		if pi, pj := pos[name(i)], pos[name(j)]; pi != pj {
			return pi != 0 && (pj == 0 || pi < pj)
		}
		return name(i) < name(j)
	})
	return items
}

// digestSteps renders steps for a plan's digest (§F.9): each its
// plaintext patch set, before any sealing, without fresh $nonce ops (an
// add or replace at exactly /$nonce of the fresh form, as §6.4.1 leaves
// out of writes) and without a fresh top-level $nonce in the value of a
// root operation, or "delete". Gestures, undoes and signatures are left
// out, so fresh nonces, signatures and re-sealing don't change it.
func digestSteps(steps []client.Step) []any {
	out := []any{}
	for _, s := range steps {
		if s.Delete {
			out = append(out, "delete")
			continue
		}
		v, err := client.ToValue(s.Patches)
		if err != nil {
			v = jsonv.FromGo(s.Patches)
		}
		ops, ok := v.([]any)
		if !ok {
			out = append(out, v)
			continue
		}
		set := []any{}
		for _, o := range ops {
			m, ok := o.(map[string]any)
			if !ok {
				set = append(set, o)
				continue
			}
			path, _ := m["path"].(string)
			name, _ := m["op"].(string)
			switch {
			case path == "/$nonce" && (name == "add" || name == "replace") && freshNonce(m["value"]):
				continue
			case path == "":
				if val, ok := m["value"].(map[string]any); ok && freshNonce(val["$nonce"]) {
					nm := make(map[string]any, len(m))
					for k, x := range m {
						nm[k] = x
					}
					nm["value"] = dropNonce(val)
					m = nm
				}
			}
			set = append(set, m)
		}
		out = append(out, set)
	}
	return out
}

func freshNonce(v any) bool {
	s, ok := v.(string)
	return ok && seal.ValidNonce(s)
}

// stepDigest is the digest of one step's part of a plan, which the step
// must still have when it is submitted.
func stepDigest(st *ReleaseStep, items []any) string {
	return ids.Of(jsonv.Canonical(map[string]any{"step": float64(st.Step), "key": st.Key, "items": items})).String()
}

// approvedStep reports whether a step's items are the ones approved: its
// stored digest (stepDigest over digestItems), or, for a plan an earlier
// version stored (format 0), that digest as the earlier version rendered
// the items (legacyDigestItems), so a merge it stopped part-way resumes
// from that plan (§F.9).
func approvedStep(rp *ReleasePlan, st *ReleaseStep, items []stepItem) bool {
	if stepDigest(st, digestItems(st, items)) == st.Digest {
		return true
	}
	return rp.Format == 0 && stepDigest(st, legacyDigestItems(items)) == st.Digest
}

// legacyDigestItems renders a step's items as the step digests of format
// 0 did: each step list with every $nonce member of a value, and the value
// of every operation on a $nonce path, left out; the items by resource
// name.
func legacyDigestItems(items []stepItem) []any {
	out := make([]any, 0, len(items))
	for _, it := range items {
		m := map[string]any{"resource": it.name, "steps": legacyStripNonces(jsonv.FromGo(StepsJSON(it.steps)))}
		if m["steps"] == nil {
			m["steps"] = []any{}
		}
		for k, v := range it.pre {
			m[k] = v
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].(map[string]any)["resource"].(string) < out[j].(map[string]any)["resource"].(string)
	})
	return out
}

func legacyStripNonces(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if k == "$nonce" {
				continue
			}
			out[k] = legacyStripNonces(x)
		}
		if path, _ := t["path"].(string); path == "/$nonce" || strings.HasSuffix(path, "/$nonce") {
			delete(out, "value")
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = legacyStripNonces(x)
		}
		return out
	}
	return v
}

// PlanObject is the plan a release's digest is over (§F.9):
//
//	{ "release": <the release document's revision path>,
//	  "batches": [ { "ns", "source": { "ns", "at" },
//	                 "items": [ { "resource", "ifMatch" | "ifNoneMatch", "steps" } … ] } … ] }
//
// the batches in the order they are submitted, one per step with items
// (release batches carry no config), the items in batch order, and a
// precondition on the result of an earlier batch's item { "batch", "item" },
// indices from 0, in place of an id. items are each step's digest items
// (stepPlan).
func PlanObject(release string, branches []*ReleaseBranch, steps []*ReleaseStep, items map[*ReleaseStep][]any) (map[string]any, error) {
	branch := map[string]*ReleaseBranch{}
	for _, b := range branches {
		branch[b.Key] = b
	}
	batches := []any{}
	index := map[string]int{}      // step/key -> batch index
	names := map[string][]string{} // step/key -> item resources in order
	for _, st := range steps {
		its := items[st]
		b := branch[st.Key]
		if len(its) == 0 || b == nil {
			continue // nothing to submit
		}
		out := make([]any, 0, len(its))
		var ns []string
		for _, it := range its {
			m := it.(map[string]any)
			o := map[string]any{"resource": m["resource"], "steps": m["steps"]}
			switch {
			case m["after"] != nil:
				a := m["after"].(map[string]any)
				k := fmt.Sprintf("%v/%v", a["step"], a["key"])
				bi, ok := index[k]
				j := slicesIndex(names[k], fmt.Sprint(a["item"]))
				if !ok || j < 0 {
					return nil, fmt.Errorf("merge: %v of step %d follows no item of step %v", m["resource"], st.Step, a["step"])
				}
				o["ifMatch"] = map[string]any{"batch": float64(bi), "item": float64(j)}
			case m["ifNoneMatch"] != nil:
				o["ifNoneMatch"] = "*"
			default:
				o["ifMatch"] = m["ifMatch"]
			}
			out = append(out, o)
			ns = append(ns, fmt.Sprint(m["resource"]))
		}
		k := stepKey(st.Step, st.Key)
		index[k], names[k] = len(batches), ns
		batches = append(batches, map[string]any{"ns": b.Target, "source": map[string]any{"ns": b.NS, "at": b.At}, "items": out})
	}
	return map[string]any{"release": release, "batches": batches}, nil
}

// PlanDigest is text(trunc160(sha256(canonical(plan)))) (§F.9), plan as
// PlanObject builds it.
func PlanDigest(plan map[string]any) string {
	return ids.Of(jsonv.Canonical(plan)).String()
}

func slicesIndex(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// digest computes the plan's digest and each step's, building every step
// as it would be submitted (stepPlan, planning).
func (x *relCtx) digest(ctx context.Context) error {
	items := map[*ReleaseStep][]any{}
	for _, st := range x.rp.Steps {
		_, its, err := stepPlan(ctx, x.c, x.opt, x.rp, st, true)
		if err != nil {
			return err
		}
		items[st] = digestItems(st, its)
		st.Digest = stepDigest(st, items[st])
	}
	plan, err := PlanObject(x.rp.Release+"/rev/"+x.rp.Revision, x.rp.Branches, x.rp.Steps, items)
	if err != nil {
		return err
	}
	x.rp.Digest = PlanDigest(plan)
	return nil
}

// ErrPlanChanged is returned when a step no longer has the items that
// were approved: the merge stops for a new approval (§F.9).
var ErrPlanChanged = errors.New("merge: the step differs from the approved plan; plan and approve again")

// runStep classifies one step again, checks it against the approved
// plan, dry-runs it and submits it. It returns the batch's ns_id, or
// "noop".
func runStep(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, st *ReleaseStep) (string, error) {
	b := rp.Branch(st.Key)
	if b == nil {
		return "", fmt.Errorf("no branch for %s in the plan", st.Key)
	}
	p, items, err := stepPlan(ctx, c, opt, rp, st, false)
	if err != nil {
		return "", err
	}
	if p == nil {
		return "noop", nil // nothing left: a resumed step that went in
	}
	if st.Digest != "" && !approvedStep(rp, st, items) {
		return "", fmt.Errorf("%w (step %d, %s)", ErrPlanChanged, st.Step, st.Key)
	}
	if b.Catalog {
		if st.Step == 2 {
			if err := checkNarrowing(ctx, c, b, p); err != nil {
				return "", err
			}
		}
		if opt.Granter == nil {
			return "", errors.New("a catalog batch needs a catalog service's merge grant (§F.8), and no granter is configured")
		}
		if err := grantFor(ctx, c, opt, b.Target, p); err != nil {
			return "", err
		}
	}
	if _, err := p.DryRun(ctx); err != nil {
		return "", fmt.Errorf("dry run: %w", err)
	}
	res, err := p.Apply(ctx)
	if err != nil {
		return "", err
	}
	if res.Noop {
		return "noop", nil
	}
	return res.NSID, nil
}

// checkNarrowing judges the step-2 batch as a whole against the catalog
// base as it is now, with the dry run (§F.9 Several releases): its result
// must widen nothing (new folders' own appearance aside).
func checkNarrowing(ctx context.Context, c *client.Client, b *ReleaseBranch, p *Plan) error {
	x := &relCtx{c: c, e2e: p.e2eTarget()}
	cfg, docs, incs, err := x.catalogBase(ctx, b.Target)
	if err != nil {
		return err
	}
	before := tree.BuildGraph(b.Target, cfg, docs)
	changes := map[string]any{}
	newFolders := map[string]bool{}
	for _, r := range p.Items() {
		start := docState{}
		if d, ok := docs[r.Name]; ok {
			start = docState{doc: jsonv.Clone(d), exists: true}
		} else if !strings.Contains(r.Name, ".") {
			newFolders[r.Name] = true
		}
		sc, err := foldWrites(start, r.Steps, false)
		if err != nil {
			return err
		}
		if sc.final.deleted || !sc.final.exists {
			changes[r.Name] = nil
		} else {
			changes[r.Name] = sc.final.doc
		}
	}
	d := catalog.DiffAccess(before, before.With(changes), incs)
	for _, w := range d.Widens {
		if !newFolders[w.Node] {
			return fmt.Errorf("the narrowing batch would give %s the role %s on %s against %s as it is now; plan again", w.Subject, w.Role, w.Node, b.Target)
		}
	}
	return nil
}

// grantFor obtains the catalog service's decision on the plan's batch and
// sets the client the batch is submitted with, waiting while the service
// is behind (§F.8):
//
//   - the merge grant the service signs for the merge service, from the
//     approver's checks;
//   - for a batch that needs catalog-admins (it changes $access, restores
//     a folder, or widens), which the service answers Admin, and only to
//     an approver in catalog-admins (CONFORMANCE scenario 44), the
//     service's dry run asked again with AdminGrant in
//     Admin-Authorization, so that it is judged with the admin whose grant
//     the batch goes under as the caller too (F-T4), and then AdminGrant
//     narrowed to exactly that batch with the merge service's via;
//   - for an end-to-end catalog, whose batches the service doesn't check
//     (404 not_offered), grantE2E: every batch goes under AdminGrant.
func grantFor(ctx context.Context, c *client.Client, opt ReleaseOptions, cat string, p *Plan) error {
	if p.TargetLevel == "e2e" {
		return grantE2E(ctx, c, opt, cat, p)
	}
	wait := opt.BehindWait
	if wait == 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	pause := 20 * time.Millisecond
	body := BatchBody(p.Batch())
	for {
		res, err := opt.Granter.MergeGrant(ctx, cat, body, "")
		if err == nil && res.Admin {
			if opt.AdminGrant == "" {
				return fmt.Errorf("%w (§F.8): give a catalog admin's grant to submit it under (ReleaseOptions.AdminGrant)", ErrAdminNeeded)
			}
			res, err = opt.Granter.MergeGrant(ctx, cat, body, opt.AdminGrant)
		}
		if err == nil {
			g := res.Grant
			if res.Admin {
				if g, err = adminGrant(opt, cat, p); err != nil {
					return err
				}
			}
			p.SetBatchClient(c.With(client.WithBearer(g)))
			return nil
		}
		if !errors.Is(err, ErrBehind) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
		if pause < time.Second {
			pause *= 2
		}
	}
}

// grantE2E sets the client an end-to-end catalog's batch is submitted with
// (§F.8). The catalog service issues no merge grants and checks no batch
// for such a catalog, so every catalog batch of it, one that needs
// catalog-admins (adminChange) or not, goes only with an approver in
// catalog-admins: under AdminGrant, a grant whose root groups list
// catalog-admins, narrowed to exactly that batch with the merge service's
// via, without the service's dry run. adminChange says why the batch would
// need catalog-admins elsewhere, for the error only.
func grantE2E(ctx context.Context, c *client.Client, opt ReleaseOptions, cat string, p *Plan) error {
	why, err := adminChange(ctx, c, cat, p)
	if err != nil {
		return err
	}
	if why == "" {
		why = cat + " is an end-to-end catalog, whose every catalog batch goes under a catalog admin's grant"
	}
	if opt.AdminGrant != "" {
		g, err := grant.Decode(opt.AdminGrant, 0)
		if err != nil {
			return fmt.Errorf("merge: the admin grant: %w", err)
		}
		if len(g.Blocks) == 0 || !slicesContains(g.Blocks[0].Groups, "catalog-admins") {
			return fmt.Errorf("%s: %w: the grant given (ReleaseOptions.AdminGrant) isn't a catalog-admins member's (§F.8)", why, ErrAdminNeeded)
		}
	}
	g, err := adminGrant(opt, cat, p)
	if err != nil {
		return fmt.Errorf("%s: %w", why, err)
	}
	p.SetBatchClient(c.With(client.WithBearer(g)))
	return nil
}

// adminChange reports why the plan's catalog batch needs catalog-admins
// (§B.11.3, §B.11.4, §F.8), "" if it doesn't, as the merge service judges
// it for a catalog whose service checks no batch (an end-to-end one,
// grantE2E), from the catalog base's documents (decrypted with the plan's
// keys) and the batch's plaintext steps:
//
//   - it changes a node's $access, or creates one with $access;
//   - it restores a node: folders are restored only by catalog admins, and
//     the merge service holds no deleted placement's rows to judge a
//     re-placing against (§B.11.7), so one counts as widening;
//   - it widens: some subject gets a role at a node the base has that it
//     didn't have before, by §B.11.4's test (catalog.DiffAccess).
func adminChange(ctx context.Context, c *client.Client, cat string, p *Plan) (string, error) {
	x := &relCtx{c: c, e2e: p.e2eTarget()}
	cfg, docs, incs, err := x.catalogBase(ctx, cat)
	if err != nil {
		return "", err
	}
	before := tree.BuildGraph(cat, cfg, docs)
	changes := map[string]any{}
	for _, r := range p.Items() {
		start := docState{}
		if d, ok := docs[r.Name]; ok {
			start = docState{doc: jsonv.Clone(d), exists: true}
		}
		sc, err := foldWrites(start, r.Steps, false)
		if err != nil {
			return "", err
		}
		live := sc.final.exists && !sc.final.deleted
		if !live {
			changes[r.Name] = nil
			continue
		}
		if r.BaseState == client.Tombstoned.String() {
			return fmt.Sprintf("restoring %s needs catalog-admins (§B.11.4, §F.8)", r.Name), nil
		}
		bm, _ := docs[r.Name].(map[string]any)
		am, _ := sc.final.doc.(map[string]any)
		_, had := bm["$access"]
		_, has := am["$access"]
		if had != has || has && !jsonv.Equal(jsonv.FromGo(bm["$access"]), jsonv.FromGo(am["$access"])) {
			return fmt.Sprintf("changing the $access of %s needs catalog-admins (§B.11.3, §F.8)", r.Name), nil
		}
		if am == nil {
			am = map[string]any{}
		}
		changes[r.Name] = am
	}
	for _, w := range catalog.DiffAccess(before, before.With(changes), incs).Widens {
		if _, existed := docs[w.Node]; existed {
			return fmt.Sprintf("the batch would give %s the role %s on %s, which needs catalog-admins (§B.11.4, §F.8)", w.Subject, w.Role, w.Node), nil
		}
	}
	return "", nil
}

// e2eTarget is the plan's key-holding view if its target is end-to-end,
// which catalogBase then reads the catalog's documents with.
func (p *Plan) e2eTarget() *client.E2E {
	if p.TargetLevel == "e2e" {
		return p.opt.E2E
	}
	return nil
}

// adminGrant narrows a catalog admin's grant to exactly the plan's batch:
// a block with the merge service's via, the catalog only, the batch's
// actions, its pairs of /resource and /action, and a few minutes' life
// (§F.8, §C.1).
func adminGrant(opt ReleaseOptions, cat string, p *Plan) (string, error) {
	if opt.AdminGrant == "" {
		return "", fmt.Errorf("%w, under whose grant it is submitted (§F.8): give one (ReleaseOptions.AdminGrant)", ErrAdminNeeded)
	}
	g, err := grant.Decode(opt.AdminGrant, 0)
	if err != nil {
		return "", fmt.Errorf("merge: the admin grant: %w", err)
	}
	// The pairs as one alternative per action naming its resources, so
	// the rule's forms stay within rulesPerGrant (§12.2) however many
	// items the batch has.
	var can []string
	names := map[string][]any{}
	for _, r := range p.Items() {
		for _, a := range itemActions(r) {
			if !slicesContains(can, a) {
				can = append(can, a)
			}
			names[a] = append(names[a], r.Name)
		}
	}
	sort.Strings(can)
	alts := []any{}
	for _, a := range can {
		alts = append(alts, map[string]any{"all": []any{
			map[string]any{"op": "test", "path": "/action", "value": a},
			map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": names[a]}},
		}})
	}
	via := opt.Via
	if via == "" {
		via = opt.Who
	}
	block := map[string]any{"ns": []any{cat}, "can": anyStrings(can), "rules": []any{map[string]any{"any": alts}},
		"exp": opt.now().Add(5 * time.Minute).UTC().Format(time.RFC3339)}
	if via != "" {
		block["via"] = via
	}
	ng, err := g.Narrow(block)
	if err != nil {
		return "", fmt.Errorf("merge: narrowing the admin grant: %w", err)
	}
	return ng.Encode(), nil
}

// itemActions are the actions an item's steps take (§6.2): create on an
// absent resource, restore on a tombstone, append on a live document,
// delete for a "delete" step.
func itemActions(r *Resource) []string {
	var out []string
	add := func(a string) {
		if !slicesContains(out, a) {
			out = append(out, a)
		}
	}
	live := !r.IfNoneMatch && r.BaseState == client.Live.String()
	exists := !r.IfNoneMatch && r.BaseState != client.NotFound.String() && r.Base != ""
	for _, s := range r.Steps {
		switch {
		case s.Delete:
			add("delete")
			live = false
		case live:
			add("append")
		case exists:
			add("restore")
			live = true
		default:
			add("create")
			live, exists = true, true
		}
	}
	return out
}

func slicesContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func anyStrings(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// BatchBody renders a batch request as its JSON body.
func BatchBody(req client.BatchRequest) map[string]any {
	items := []any{}
	for _, it := range req.Items {
		m := map[string]any{"resource": it.Resource, "steps": StepsJSON(it.Steps)}
		if it.IfNoneMatch {
			m["ifNoneMatch"] = "*"
		} else {
			m["ifMatch"] = it.IfMatch
		}
		items = append(items, m)
	}
	out := map[string]any{"items": items}
	if req.Source != nil {
		out["source"] = req.Source
	}
	if req.Config != nil {
		out["config"] = map[string]any{"ifMatch": req.Config.IfMatch, "patches": req.Config.Patches}
	}
	return out
}
