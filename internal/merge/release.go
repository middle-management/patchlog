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
//  3. Content branches, in any order. (v0.87 removed steps 2 and 4; the
//     numbers are kept, as stored plans and their digests name them.)
//
// Conflicts reported before anything is submitted (ReleaseConflict): a
// pinned x-ref or manifest entry naming a revision of another listed
// branch that the merge replays; a document resolving a draft schema
// revision in a branch the release doesn't list; and every merge conflict
// of §F.3.
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
// ops (nor a fresh top-level $nonce in a root op's value) or "delete".
// ApproveRelease, run by the person approving, plans
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
// version recorded. Every branch records merged only after its last step,
// with at the target's ns_id after the last batch into it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
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
	RCBaseChain     = "base_chain"         // the branch's base isn't the namespace it is keyed by (§F.9)
	RCFrozen        = "frozen"             // the branch is frozen (not by this plan's approval)
	RCPurged        = "purged"             // the branch is purged
	RCSchemaChanged = "schema_changed"     // a schema resource can't fast-forward (§F.9)
	RCDanglingPin   = "dangling_pin"       // a pinned link to a revision the merge replays
	RCForeignDraft  = "foreign_draft"      // a draft resolved in a branch the release doesn't list
	RCUnresolved    = "schema_unavailable" // a $schema the merger can't resolve anywhere
	RCMerge         = "merge"              // a §F.3 conflict of a resource
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
	// Schemas are its schema resources in $ref order (step 1), Content the
	// rest (step 3).
	Schemas []string `json:"schemas,omitempty"`
	Content []string `json:"content,omitempty"`
	// At is the branch's ns_id the plan classifies from, every batch's
	// source.at: its head when planned, and from the approval on its ns_id
	// before the approval's freeze (§F.9).
	At string `json:"at,omitempty"`
	// FrozenConfig is the config id the approval's freeze produced.
	FrozenConfig string `json:"frozenConfig,omitempty"`
	// Merged is the merged.at recorded after its last step.
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

	Branches  []*ReleaseBranch  `json:"branches"`
	Steps     []*ReleaseStep    `json:"steps"`
	Conflicts []ReleaseConflict `json:"conflicts,omitempty"`
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

// ReleaseOptions configure the release functions.
type ReleaseOptions struct {
	// Release is the release document's link, /r/{ns}/{name}.
	Release string
	// StateNS holds the stored plan (default: the release document's
	// namespace).
	StateNS string
	// Digest, if set, is the digest the approving person reviewed:
	// ApproveRelease fails unless planning again gives it (§F.9).
	Digest string
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
	// AcceptFrozen are freezes this release's own approval made (branch
	// -> config id, ReleasePlan.FrozenBy): PlanRelease doesn't count them
	// as frozen, and classifies those branches as of their ns_id before
	// the freeze, which stays their source.at (§F.9).
	AcceptFrozen map[string]string
	// Signer, if set, signs every step the release writes (§C.3.1). Its
	// key must be listed in the signers of the grant the batches are sent
	// under.
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

type relCtx struct {
	c   *client.Client
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
		PlannedBy: opt.Who}
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
			if schemaRes {
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
		if len(b.Content) == 0 {
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
	rp.Steps = append(rp.Steps, contentSteps...)

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
	// (legacyAts).
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
	// Every branch records merged only after the last step, with at the
	// target's ns_id after the last batch into it (§F.9). A branch none of
	// whose batches had anything left to do records the target's head.
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
	return rp, SaveReleasePlan(ctx, c, opt, rp)
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
// an administrator's. A stored plan is marked abandoned. What step 1 merged stays in the schema namespace's
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
	}
	return out, nil
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
// submitted.
func stepPlan(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, st *ReleaseStep, planning bool) (*Plan, []stepItem, error) {
	b := rp.Branch(st.Key)
	if b == nil {
		return nil, nil, fmt.Errorf("no branch for %s in the plan", st.Key)
	}
	var items []stepItem
	all := st.Resources
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
// of an earlier step, written here as "after": { step, key, item },
// PlanDigest turns into { batch, item }.
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
// root operation, an add or replace whose path is "" (a test at "" keeps
// its value whole), or "delete". Gestures, undoes and signatures are left
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
			case path == "" && (name == "add" || name == "replace"):
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
