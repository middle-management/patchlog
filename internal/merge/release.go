package merge

// Releases across namespaces (§F.9): merging every branch a release
// document lists, one batch per branch and step, in three steps:
//
//  1. Schema resources (documents whose $schema is a dialect URL, §6.1),
//     by fast-forward only, in $ref order: then $schema paths resolve in
//     the bases too. A schema resource the base changed since the branch
//     started can't fast-forward: a conflict (rebase the release, and
//     migrate documents with replace /$schema).
//  2. Content, in any order.
//  3. Publishing (ReleaseOptions.Publish): where readers' rules test a
//     field that marks documents published, one batch per content
//     namespace, without source, sets it on the documents the release
//     created, which carried it unset. Each item's precondition is the id
//     step 2's item left the document at.
//
// Conflicts reported before anything is submitted (ReleaseConflict): a
// pinned x-ref naming a revision of another listed branch that the merge
// replays; a document resolving a draft schema revision in a branch the
// release doesn't list; a change to the published field in steps 1 and 2;
// and every merge conflict of §F.3.
//
// The published field and the merge service's grant. The content base
// guards the field as §6.4.4 guards fields that read rules test, with
// rules that only principals in a group its issuer asserts pass, e.g. for
// /published and the group publishers:
//
//	{ "if":   [{ "not": { "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "publishers" } } } },
//	           { "op": "test", "path": "/action", "schema": { "enum": ["append", "restore"] } }],
//	  "then": [{ "not": { "op": "writes", "overlaps": "/published" } }] },
//	{ "if":   [{ "not": { "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "publishers" } } } },
//	           { "op": "test", "path": "/action", "value": "create" }],
//	  "then": [{ "op": "test", "path": "/doc/published", "exists": false }] }
//
// and the grant the merge service submits under carries that group in its
// root block (a role the base defines works the same, but then grants the
// merge service's verbs too). Writers without it can't set the field;
// the merge service, and whoever else is in the group, can. A branch
// starts with a copy of these rules, but its own from then on (§7.6), and
// the server can't tell step 2 from step 3, as one grant submits both, so
// the planner keeps the field out of steps 1 and 2: an item whose
// resulting document has another value there than the base's live
// document (none for a document the release creates or restores) is a
// conflict (RCPublished). A release built on another merges into that
// release's branches, whose readers aren't filtered (§7.9), so it has no
// step 3: what it adds is created in the earlier release's branch, whose
// own step 3 publishes it.
//
// Lifecycle. PlanRelease checks that each listed branch's base is the
// namespace it is keyed by (or, for a release built on another, that
// release's branch for the key), classifies and checks, and builds the
// plan: { release: <revision path>, batches: [{ ns, source?, items: [{
// resource, ifMatch | ifNoneMatch, steps }] }] }, the batches in
// submission order, each step its plaintext patch set without fresh $nonce
// ops (nor a fresh top-level $nonce in a root op's value) or "delete", a
// precondition on an earlier batch's item { batch, item }. Its digest
// (PlanDigest) is text(trunc160(sha256(canonical(plan)))). The plan is
// stored, with the digest and each branch's at, as a resource ({release
// name}.merge) in a state namespace (by default the release document's
// own). ApproveRelease, run by the person approving, plans again, requires
// it clean, for the same revision and with the same digest, and freezes
// every listed branch (§8.4), recording each branch's config id and its
// ns_id before the freeze, which stays every batch's source.at;
// unfreezing a branch (any config change) invalidates the plan.
// ApplyRelease merges from the stored plan: each step is classified again
// and dry-run right before it is submitted, and stops for a new approval
// if its items differ from the stored plan's; a 412 stops it too. Each
// step's batch and the ids it left are recorded as it completes; a merge
// that stops resumes from the stored plan, finding a batch that went in
// before its record in the target's log, and never reverts. Every branch
// records merged only after the last step, with at the target's ns_id
// after the last batch into it.

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
	"github.com/middle-management/patchlog/internal/pointer"
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

// The steps of a release merge (§F.9 Merging).
const (
	StepSchemas = 1 // schema resources, by fast-forward only
	StepContent = 2 // the rest of each branch
	StepPublish = 3 // the published field, on the documents the release created
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
	RCPublished     = "published"          // steps 1 or 2 change the published field (§F.9)
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
	// rest (step 2).
	Schemas []string `json:"schemas,omitempty"`
	Content []string `json:"content,omitempty"`
	// At is the branch's ns_id the plan classifies from, every batch's
	// source.at: its head when planned, and from the approval on its ns_id
	// before the approval's freeze (§F.9).
	At string `json:"at,omitempty"`
	// FrozenConfig is the config id the approval's freeze produced.
	FrozenConfig string `json:"frozenConfig,omitempty"`
	// Merged is the merged.at recorded after the last step.
	Merged string `json:"merged,omitempty"`
}

// ReleaseStep is one batch of the merge.
type ReleaseStep struct {
	Step      int      `json:"step"` // StepSchemas, StepContent or StepPublish
	Key       string   `json:"key"`
	Resources []string `json:"resources"`
	// Batch is the step's index among the plan's batches, nil if it has
	// nothing to submit.
	Batch *int `json:"batch,omitempty"`
	// Done is the batch's ns_id once submitted ("noop" if there was
	// nothing to do).
	Done string `json:"done,omitempty"`
	// IDs are the ids the batch left its resources at, which step 3's
	// preconditions name.
	IDs map[string]string `json:"ids,omitempty"`
	// Carried, in step 3, are the documents a stored plan's step 3 was to
	// publish that steps 1 and 2 of an earlier, stopped merge have merged
	// already, still unset, by name, with the head each is published on
	// (§F.9: "Planning again after a stop takes step 3's documents, those
	// still unset, from the stored plan").
	Carried map[string]string `json:"carried,omitempty"`
}

// Publish is the field step 3 sets (§F.9): Path, a JSON pointer readers'
// rules test, e.g. /published, and Value, what it is set to (true if nil).
type Publish struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func (pb *Publish) check() error {
	p, err := pointer.Parse(pb.Path)
	if err != nil || len(p) == 0 {
		return fmt.Errorf("merge: the published field %q is not a JSON pointer below the document's root", pb.Path)
	}
	if strings.HasPrefix(pb.Path, "/$") {
		return fmt.Errorf("merge: the published field %q is a reserved member (§6.5)", pb.Path)
	}
	if pb.Value == nil {
		pb.Value = true
	}
	return nil
}

func (pb *Publish) ptr() pointer.Pointer { return pointer.MustParse(pb.Path) }

// step is the patch set step 3 writes.
func (pb *Publish) step() client.Step {
	return client.PatchStep([]any{map[string]any{"op": "add", "path": pb.Path, "value": jsonv.FromGo(pb.Value)}})
}

func samePublish(a, b *Publish) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	val := func(p *Publish) any {
		if p.Value == nil {
			return true
		}
		return jsonv.FromGo(p.Value)
	}
	return a.Path == b.Path && jsonv.Equal(val(a), val(b))
}

// PlanFormat is the stored plan's format: 3, the three steps of v0.87
// with the plan itself stored. A plan stored under another format is
// planned and approved again.
const PlanFormat = 3

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
	// Plan is what Digest is over (PlanObject), which the merge resumes
	// from: each step submits exactly its batch.
	Plan map[string]any `json:"plan,omitempty"`
	// Publish is step 3's field, nil for none.
	Publish *Publish `json:"publish,omitempty"`

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
	// Publish, if set, is the field step 3 sets on the documents the
	// release created (§F.9). PlanRelease plans with it; ApproveRelease
	// and ApplyRelease take the stored plan's.
	Publish *Publish
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
	// AfterSubmit, if set, is called right after a step's batch went in,
	// before it is recorded; an error stops the merge there (tests
	// simulate a crash between the two).
	AfterSubmit func(step *ReleaseStep) error
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
	listed  map[string]bool           // branch namespaces listed, by this release or one it builds on
	ownCfgs map[string]string         // branch -> config id our approval left (resume)
	// onBranches are the branches of the releases this one builds on.
	onBranches []string
	// carried are, per key, step 3's documents taken from the stored plan
	// (carryPublished).
	carried map[string]map[string]string
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
	var pub *Publish
	if opt.Publish != nil {
		cp := *opt.Publish
		if err := cp.check(); err != nil {
			return nil, err
		}
		pub = &cp
	}
	rel, err := release.Load(ctx, c, opt.Release)
	if err != nil {
		return nil, err
	}
	x := &relCtx{c: c, opt: opt, rel: rel, docs: map[string]map[string]any{}, plans: map[string]*Plan{}, listed: map[string]bool{}, ownCfgs: own}
	x.rp = &ReleasePlan{Format: PlanFormat, Release: rel.Ref.Live(), Revision: rel.Ref.Rev, Name: rel.Doc.Name, State: ReleasePlanned,
		PlannedBy: opt.Who, Publish: pub}
	for _, k := range rel.Doc.Keys() {
		x.listed[rel.Doc.Branches[k].NS] = true
	}
	if err := x.branches(ctx); err != nil {
		return nil, err
	}
	if err := x.carryPublished(ctx); err != nil {
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
// key (§F.9 Releases built on another).
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
	// Its documents resolve drafts from the releases it builds on too
	// (§F.9, §6.1), so their branches count as listed for drafts.
	for depth, r := 0, on; r != nil && depth < 8; depth++ {
		for _, n := range r.Doc.BranchNames() {
			if !x.listed[n] {
				x.listed[n] = true
				x.onBranches = append(x.onBranches, n)
			}
		}
		if r.Doc.On == "" {
			break
		}
		if r, err = release.Load(ctx, x.c, r.Doc.On); err != nil {
			return nil, fmt.Errorf("merge: a release this one builds on: %w", err)
		}
	}
	return out, nil
}

// branches runs the checks before approval (§F.9): each listed branch's
// base is the namespace it is keyed by, or for a release built on another,
// that release's branch for the key (targets), and it is neither frozen
// (but by our own approval) nor purged; and sorts its changed resources
// into schemas and content.
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
		log, _, err := x.c.Unfiltered().NSLog(ctx, br, h.ID, "")
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
		x.plans[stepKey(StepSchemas, k)] = p
		x.schemaConflicts(b, p)
		if err := x.publishChanges(ctx, b, p); err != nil {
			return err
		}
		rp.Steps = append(rp.Steps, &ReleaseStep{Step: StepSchemas, Key: k, Resources: b.Schemas})
	}
	// Step 2 plans (content), classified now for the conflict checks, and
	// step 3's documents: those step 2 creates or restores.
	var contentSteps, publishSteps []*ReleaseStep
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
		x.plans[stepKey(StepContent, b.Key)] = p
		for _, r := range p.Conflicting() {
			kinds := []string{}
			var paths []string
			for _, c := range r.Conflicts {
				kinds = append(kinds, c.Kind)
				paths = append(paths, c.Paths...)
			}
			x.conflict(RCMerge, b.Key, b.NS, r.Name, "merge conflict ("+strings.Join(kinds, ", ")+"): resolve with --resolve "+b.Key+"/"+r.Name+"=file.json, or rebase the release", paths...)
		}
		if err := x.publishChanges(ctx, b, p); err != nil {
			return err
		}
		contentSteps = append(contentSteps, &ReleaseStep{Step: StepContent, Key: b.Key, Resources: b.Content})
		if rp.Publish == nil {
			continue
		}
		if b.Target != b.Key {
			rp.Notes = append(rp.Notes, fmt.Sprintf("%s merges into %s, a branch of the release this one builds on: no step 3 there, as that release's step 3 publishes what it creates", b.NS, b.Target))
			continue
		}
		created := createdItems(p)
		carried := map[string]string{}
		for name, id := range x.carried[b.Key] {
			if !slicesContains(created, name) {
				carried[name] = id
				created = append(created, name)
			}
		}
		if len(created) > 0 {
			sort.Strings(created)
			st := &ReleaseStep{Step: StepPublish, Key: b.Key, Resources: created}
			if len(carried) > 0 {
				st.Carried = carried
			}
			publishSteps = append(publishSteps, st)
		}
	}
	rp.Steps = append(rp.Steps, contentSteps...)
	rp.Steps = append(rp.Steps, publishSteps...)

	if err := x.pins(ctx); err != nil {
		return err
	}
	return x.drafts(ctx)
}

func stepKey(step int, key string) string { return fmt.Sprintf("%d/%s", step, key) }

// createdItems are the names of the resources p's batch creates or
// restores, leaving them live: the documents a release created, which
// step 3 publishes (§F.9).
func createdItems(p *Plan) []string {
	var out []string
	for _, r := range p.Items() {
		if r.BaseState == client.Live.String() || r.BranchDeleted || r.Dropped {
			continue
		}
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

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

// publishChanges reports a change to the published field in steps 1 and
// 2 (§F.9): an item whose resulting document has another value there, or
// one where there was none, than the target's live document, none for a
// document the item creates or restores, which must carry it unset. An
// item that deletes changes nothing there. Items that can't be folded are
// conflicts already.
func (x *relCtx) publishChanges(ctx context.Context, b *ReleaseBranch, p *Plan) error {
	pub := x.rp.Publish
	if pub == nil {
		return nil
	}
	ptr := pub.ptr()
	for _, r := range p.Items() {
		var start any
		exists, deleted, live := false, false, false
		switch r.BaseState {
		case client.Live.String():
			d, err := p.doc(ctx, p.Target, r.Name, r.Base)
			if err != nil {
				return fmt.Errorf("merge: %s/%s: %w", p.Target, r.Name, err)
			}
			start, exists, live = d, true, true
		case client.Tombstoned.String():
			if r.baseLast != "" {
				if d, err := p.doc(ctx, p.Target, r.Name, r.baseLast); err == nil {
					start, exists, deleted = d, true, true
				}
			}
		}
		after, del, err := ApplySteps(start, exists, deleted, r.Steps)
		if err != nil || del {
			continue
		}
		bv, bok := any(nil), false
		if live {
			bv, bok = pointer.Get(start, ptr)
		}
		av, aok := pointer.Get(after, ptr)
		if aok == bok && (!aok || jsonv.Equal(av, bv)) {
			continue
		}
		what := "changes " + pub.Path
		if !live {
			what = "creates the document with " + pub.Path + " set"
			if r.BaseState == client.Tombstoned.String() {
				what = "restores the document with " + pub.Path + " set"
			}
		}
		x.conflict(RCPublished, b.Key, b.NS, r.Name, fmt.Sprintf("%s %s, which only step 3 sets (§F.9): leave it as in %s, or unset in a document the release creates", r.Name, what, b.Target), pub.Path)
	}
	return nil
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

// pins: a pinned reference (§6.5) naming a revision of another listed
// branch that the merge replays would dangle.
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
				var tp *Plan
				for _, step := range []int{StepSchemas, StepContent} {
					if p := x.plans[stepKey(step, tb.Key)]; p != nil {
						if rr := p.Resource(res); rr != nil {
							r, tp = rr, p
						}
					}
				}
				replays := r != nil && (r.Class == Replay || (r.Class == FastForward && tp.Reencrypt))
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
	prefer := append(x.rel.Doc.BranchNames(), x.onBranches...)
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

// ApproveRelease plans again and, if the plan is clean, for the release
// document's revision that was planned and with the same digest, freezes
// every listed branch and stores the approved plan. A stored plan that is
// already approved, or an approval that stopped part-way, is resumed:
// freezes recorded by this approval are accepted.
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
		return stored, fmt.Errorf("%w: the stored plan is of format %d, not %d: plan again and review", ErrDigest, stored.Format, PlanFormat)
	}
	// The person approves what they reviewed: the stored plan's choices.
	if opt.Publish != nil && !samePublish(opt.Publish, stored.Publish) {
		return stored, fmt.Errorf("%w: the stored plan publishes %v, not %v: plan again and review", ErrDigest, stored.Publish, opt.Publish)
	}
	opt.Publish = stored.Publish
	if opt.Resolutions == nil {
		opt.Resolutions = stored.resolutions()
	}
	own := stored.FrozenBy()
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

// entryBefore returns the ns_id before the entry id of ns's chain, which
// follows since (an ns_id in that chain).
func entryBefore(ctx context.Context, c *client.Client, ns, id, since string) (string, error) {
	log, _, err := c.Unfiltered().NSLog(ctx, ns, id, since)
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
	if rp.Format != PlanFormat || rp.Plan == nil || rp.Digest != PlanDigest(rp.Plan) {
		return rp, fmt.Errorf("%w: the stored plan (format %d, now %d) doesn't hold the plan its digest is over: plan and approve again", ErrInvalidPlan, rp.Format, PlanFormat)
	}
	if err := checkApproved(ctx, c, rp); err != nil {
		return rp, err
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
		done, idsOf, err := runStep(ctx, c, opt, rp, st)
		if err != nil {
			return rp, fmt.Errorf("merge: step %d (%s): %w", st.Step, st.Key, err)
		}
		if done != "noop" && opt.AfterSubmit != nil {
			if err := opt.AfterSubmit(st); err != nil {
				return rp, err
			}
		}
		st.Done, st.IDs = done, idsOf
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
// an administrator's. A stored plan is marked abandoned. What step 1
// merged stays in the schema namespace's history, unused. It returns the
// branches it abandoned.
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

// stepPlan builds the batch of step 1 or 2 from the stored plan's
// branches, classified against the targets as they are: the plan (nil if
// nothing is left to do) and the step's items (§F.9). A 412 on submitting
// it stops the merge rather than classifying again (Options.noRetry).
func stepPlan(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, st *ReleaseStep) (*Plan, []stepItem, error) {
	b := rp.Branch(st.Key)
	if b == nil {
		return nil, nil, fmt.Errorf("no branch for %s in the plan", st.Key)
	}
	var items []stepItem
	if len(st.Resources) == 0 {
		return nil, items, nil
	}
	p, err := NewPlan(ctx, c, b.Target, b.NS, Options{Resources: st.Resources, BranchAt: b.At, SourceAuthorizations: opt.SourceAuthorizations, Signer: opt.Signer, noRetry: true})
	if err != nil {
		return nil, nil, err
	}
	if st.Step == StepSchemas {
		p.Order(st.Resources)
		for _, r := range p.Resources {
			if r.Class == Replay || r.Class == Purged || (r.Class == FastForward && r.NeedsPerson()) {
				return nil, nil, fmt.Errorf("schema resource %s can't fast-forward any more (%s): rebase the release", r.Name, r.Class)
			}
		}
	}
	if st.Step == StepContent {
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

// publishItems are step 3's digest items: for each document step 2
// created, the published field set, its precondition the id step 2's item
// leaves it at, { "batch", "item" } in the plan.
//
// A document carried from a stored plan (ReleaseStep.Carried), which
// steps 1 and 2 merged before the merge stopped, has no item in step 2:
// its precondition is the head it is published on, an id.
func publishItems(st *ReleaseStep, pub *Publish) []any {
	out := make([]any, 0, len(st.Resources))
	for _, name := range st.Resources {
		pre := map[string]any{"after": map[string]any{"step": StepContent, "key": st.Key, "item": name}}
		if id, ok := st.Carried[name]; ok {
			pre = map[string]any{"ifMatch": id}
		}
		out = append(out, digestItem(name, pre, []client.Step{pub.step()}))
	}
	return orderItems(st, out)
}

// carryPublished finds, in the stored plan of the release, the documents
// its step 3 was to publish that are now live in their target with the
// published field still unset: what a merge stopped between steps 2 and 3
// left (§F.9). Planning again takes them into step 3 (classify), on their
// heads now, whether or not step 2 still creates them; those it creates
// keep their step-2 precondition. Those no longer live (deleted, purged)
// are reported in the plan's notes (v0.90: "and reports those no longer
// live").
func (x *relCtx) carryPublished(ctx context.Context) error {
	pub := x.rp.Publish
	if pub == nil {
		return nil
	}
	stored, err := LoadReleasePlan(ctx, x.c, x.opt)
	if err != nil || stored == nil || !samePublish(stored.Publish, pub) {
		return err
	}
	ptr := pub.ptr()
	for _, st := range stored.Steps {
		if st.Step != StepPublish {
			continue
		}
		b := x.rp.Branch(st.Key)
		if b == nil || b.Target != b.Key {
			continue
		}
		for _, name := range st.Resources {
			h, err := x.c.Head(ctx, b.Target, name)
			if err != nil && !client.IsNotFound(err) && !client.IsGone(err) {
				return err
			}
			if err != nil || h.State != client.Live {
				// Reported, not dropped silently: the approved plan named
				// it (§F.9, v0.90: "reports those no longer live").
				x.rp.Notes = append(x.rp.Notes, fmt.Sprintf("%s in %s, which the stored plan's step 3 was to publish, is no longer live there: it is left out of step 3", name, b.Target))
				continue
			}
			d, err := x.c.Doc(ctx, b.Target, name, h.ID)
			if err != nil {
				return err
			}
			if v, ok := pointer.Get(d.Value, ptr); ok && jsonv.Equal(v, jsonv.FromGo(pub.Value)) {
				continue // published already
			}
			if x.carried == nil {
				x.carried = map[string]map[string]string{}
			}
			if x.carried[st.Key] == nil {
				x.carried[st.Key] = map[string]string{}
			}
			x.carried[st.Key][name] = h.ID
		}
	}
	return nil
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
// PlanObject turns into { batch, item }.
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
	if st.Step == StepSchemas {
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

// PlanObject is the plan a release's digest is over (§F.9):
//
//	{ "release": <the release document's revision path>,
//	  "batches": [ { "ns", "source"?: { "ns", "at" },
//	                 "items": [ { "resource", "ifMatch" | "ifNoneMatch", "steps" } … ] } … ] }
//
// the batches in the order they are submitted, one per step with items,
// only step 3's without source (release batches carry no config), the
// items in batch order, and a precondition on the result of an earlier
// batch's item { "batch", "item" }, indices from 0, in place of an id.
// items are each step's digest items (digestItems, publishItems).
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
		batch := map[string]any{"ns": b.Target, "items": out}
		if st.Step != StepPublish {
			batch["source"] = map[string]any{"ns": b.NS, "at": b.At}
		}
		batches = append(batches, batch)
	}
	return map[string]any{"release": release, "batches": batches}, nil
}

// PlanDigest is text(trunc160(sha256(canonical(plan)))) (§F.9), plan as
// PlanObject builds it.
func PlanDigest(plan map[string]any) string {
	return ids.Of(jsonv.Canonical(jsonv.FromGo(plan))).String()
}

func slicesIndex(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

// digest builds every step as it would be submitted (stepPlan,
// publishItems), the plan (PlanObject) and its digest, and each step's
// batch index.
func (x *relCtx) digest(ctx context.Context) error {
	items := map[*ReleaseStep][]any{}
	content := map[string][]stepItem{}
	for _, st := range x.rp.Steps {
		switch st.Step {
		case StepSchemas, StepContent:
			_, its, err := stepPlan(ctx, x.c, x.opt, x.rp, st)
			if err != nil {
				return err
			}
			items[st] = digestItems(st, its)
			if st.Step == StepContent {
				content[st.Key] = its
			}
		case StepPublish:
			for _, n := range st.Resources {
				_, found := st.Carried[n]
				for _, it := range content[st.Key] {
					found = found || it.name == n
				}
				if !found {
					return fmt.Errorf("merge: %s/%s is to be published but has no item in step 2", st.Key, n)
				}
			}
			items[st] = publishItems(st, x.rp.Publish)
		}
	}
	plan, err := PlanObject(x.rp.Release+"/rev/"+x.rp.Revision, x.rp.Branches, x.rp.Steps, items)
	if err != nil {
		return err
	}
	n := 0
	for _, st := range x.rp.Steps {
		st.Batch = nil
		if len(items[st]) > 0 && x.rp.Branch(st.Key) != nil {
			i := n
			st.Batch = &i
			n++
		}
	}
	// As stored: the JSON value model, so a reloaded plan compares equal.
	x.rp.Plan = jsonv.FromGo(plan).(map[string]any)
	x.rp.Digest = PlanDigest(x.rp.Plan)
	return nil
}

// batchItems returns the stored plan's items of batch i.
func (rp *ReleasePlan) batchItems(i int) ([]any, error) {
	bs, _ := rp.Plan["batches"].([]any)
	if i < 0 || i >= len(bs) {
		return nil, fmt.Errorf("%w: the stored plan has no batch %d", ErrInvalidPlan, i)
	}
	m, _ := bs[i].(map[string]any)
	its, _ := m["items"].([]any)
	return its, nil
}

// stepOfBatch returns the step whose batch is i.
func (rp *ReleasePlan) stepOfBatch(i int) *ReleaseStep {
	for _, st := range rp.Steps {
		if st.Batch != nil && *st.Batch == i {
			return st
		}
	}
	return nil
}

// ErrPlanChanged is returned when a step no longer has the items that
// were approved: the merge stops for a new approval (§F.9).
var ErrPlanChanged = errors.New("merge: the step differs from the approved plan; plan and approve again")

// runStep submits one step: classified again, checked against the stored
// plan's batch, dry-run and submitted. It returns the batch's ns_id, or
// "noop", and the ids the batch left its resources at. A step whose batch
// went in before it was recorded is found in the target's log.
func runStep(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, st *ReleaseStep) (string, map[string]string, error) {
	if st.Batch == nil {
		return "noop", nil, nil
	}
	want, err := rp.batchItems(*st.Batch)
	if err != nil {
		return "", nil, err
	}
	if st.Step == StepPublish {
		return runPublish(ctx, c, opt, rp, st, want)
	}
	b := rp.Branch(st.Key)
	p, items, err := stepPlan(ctx, c, opt, rp, st)
	if err != nil {
		return "", nil, err
	}
	if p == nil {
		// Nothing left: the batch went in before it was recorded.
		id, got, err := findMergeBatch(ctx, c, b.Target, b.NS, b.At, st.Resources)
		if err != nil {
			return "", nil, err
		}
		if id == "" {
			return "", nil, fmt.Errorf("%w (step %d, %s: nothing is left to merge, and %s's log has no batch of it)", ErrPlanChanged, st.Step, st.Key, b.Target)
		}
		return id, got, nil
	}
	if !jsonv.Equal(jsonv.FromGo(digestItems(st, items)), want) {
		return "", nil, fmt.Errorf("%w (step %d, %s)", ErrPlanChanged, st.Step, st.Key)
	}
	if _, err := p.DryRun(ctx); err != nil {
		return "", nil, fmt.Errorf("dry run: %w", err)
	}
	res, err := p.Apply(ctx)
	if err != nil {
		return "", nil, err
	}
	if res.Noop {
		return "noop", nil, nil
	}
	got := map[string]string{}
	for name, ids := range res.IDs {
		if len(ids) > 0 {
			got[name] = ids[len(ids)-1]
		}
	}
	return res.NSID, got, nil
}

// findMergeBatch finds, in target's log, the latest batch whose source is
// branch at at and that has an entry for one of resources: its ns_id and
// the ids its entries left them at, or "".
func findMergeBatch(ctx context.Context, c *client.Client, target, branch, at string, resources []string) (string, map[string]string, error) {
	return findBatch(ctx, c, target, func(e client.NSEntry) bool {
		if !IsMergeOf(e, branch) || e.Source["at"] != at {
			return false
		}
		for _, s := range e.Entries {
			if slicesContains(resources, s.Resource) {
				return true
			}
		}
		return false
	})
}

// findBatch returns the latest batch entry of ns's log that match accepts:
// its ns_id and, per resource, the id its entry left it at.
func findBatch(ctx context.Context, c *client.Client, ns string, match func(client.NSEntry) bool) (string, map[string]string, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return "", nil, err
	}
	log, _, err := c.Unfiltered().NSLog(ctx, ns, h.ID, "")
	if err != nil {
		return "", nil, err
	}
	for i := len(log) - 1; i >= 0; i-- {
		e := log[i]
		if e.Kind != "batch" || !match(e) {
			continue
		}
		got := map[string]string{}
		for _, s := range e.Entries {
			if s.Kind == "head" || s.Kind == "tombstone" {
				got[s.Resource] = s.Target
			}
		}
		return e.ID, got, nil
	}
	return "", nil, nil
}

// runPublish submits step 3 (§F.9): one batch without source, each item
// setting the published field on a document step 2 created, with If-Match
// the id step 2 left it at. A document that has moved on since is a
// change to the approved plan, unless the move is this step's own item,
// which went in before it was recorded.
func runPublish(ctx context.Context, c *client.Client, opt ReleaseOptions, rp *ReleasePlan, st *ReleaseStep, want []any) (string, map[string]string, error) {
	b := rp.Branch(st.Key)
	pub := rp.Publish
	if b == nil || pub == nil {
		return "", nil, fmt.Errorf("%w: step 3 of %s without a branch or a published field", ErrInvalidPlan, st.Key)
	}
	np, err := noncePlan(ctx, c, b.Target)
	if err != nil {
		return "", nil, err
	}
	if np.TargetLevel == "e2e" {
		return "", nil, fmt.Errorf("%s is an e2e namespace, whose readers aren't filtered by its documents (§7.9): it has no step 3", b.Target)
	}
	ptr := pub.ptr()
	// No source, so no Source-Authorization: step 3 reads nothing of the
	// branches, and the schemas its documents name are in the bases.
	req := client.BatchRequest{}
	got := map[string]string{}
	var gone []string // items that went in before they were recorded
	for i, it := range want {
		m, _ := it.(map[string]any)
		name, _ := m["resource"].(string)
		// The id step 2 left it at, or for a document carried from a
		// stored plan the head it was planned on (publishItems).
		parent, _ := m["ifMatch"].(string)
		left := "planning"
		if parent == "" {
			pre, _ := m["ifMatch"].(map[string]any)
			bi, ok1 := pre["batch"].(float64)
			ii, ok2 := pre["item"].(float64)
			src := rp.stepOfBatch(int(bi))
			if !ok1 || !ok2 || src == nil || src.Done == "" {
				return "", nil, fmt.Errorf("%w: step 3's item %d of %s names no submitted batch", ErrInvalidPlan, i, st.Key)
			}
			srcItems, err := rp.batchItems(int(bi))
			if err != nil {
				return "", nil, err
			}
			if int(ii) >= len(srcItems) || srcItems[int(ii)].(map[string]any)["resource"] != name {
				return "", nil, fmt.Errorf("%w: step 3's item %s of %s follows another resource", ErrInvalidPlan, name, st.Key)
			}
			if parent = src.IDs[name]; parent == "" {
				return "", nil, fmt.Errorf("%w: step %d recorded no id for %s", ErrInvalidPlan, src.Step, name)
			}
			left = fmt.Sprintf("step %d", src.Step)
		}
		steps := []client.Step{pub.step()}
		if !jsonv.Equal(jsonv.FromGo(digestItem(name, nil, steps)["steps"]), m["steps"]) {
			return "", nil, fmt.Errorf("%w (step 3, %s/%s)", ErrPlanChanged, st.Key, name)
		}
		h, err := c.Head(ctx, b.Target, name)
		if err != nil {
			return "", nil, err
		}
		if h.State == client.Live && h.ID != parent {
			// The item went in already: the one revision after step 2's
			// sets the field, and nothing else.
			es, err := c.Log(ctx, b.Target, name, h.ID, parent)
			if err == nil && len(es) == 1 && es[0].Parent == parent {
				if d, err := c.Doc(ctx, b.Target, name, h.ID); err == nil {
					pd, perr := c.Doc(ctx, b.Target, name, parent)
					if v, ok := pointer.Get(d.Value, ptr); ok && perr == nil && jsonv.Equal(v, jsonv.FromGo(pub.Value)) {
						if after, _, err := ApplySteps(pd.Value, true, false, steps); err == nil && jsonv.Equal(np.nonceless(after), np.nonceless(d.Value)) {
							got[name] = h.ID
							gone = append(gone, name)
							continue
						}
					}
				}
			}
		}
		if h.State != client.Live || h.ID != parent {
			return "", nil, fmt.Errorf("%w (step 3: %s/%s is %s %s, not %s, which %s left it at)", ErrPlanChanged, b.Target, name, h.State, h.ID, parent, left)
		}
		req.Items = append(req.Items, client.BatchItem{Resource: name, IfMatch: parent, Steps: np.withNonces(steps)})
	}
	if len(req.Items) == 0 {
		id, _, err := findBatch(ctx, c, b.Target, func(e client.NSEntry) bool {
			if e.HasSource {
				return false
			}
			for _, s := range e.Entries {
				if s.Kind == "head" && got[s.Resource] == s.Target {
					return true
				}
			}
			return false
		})
		if err != nil {
			return "", nil, err
		}
		if id == "" {
			id = "noop"
		}
		return id, got, nil
	}
	if len(gone) > 0 {
		// A batch is atomic (§7.5): part of one can't have gone in.
		return "", nil, fmt.Errorf("%w (step 3 of %s: %s published, the rest not)", ErrPlanChanged, st.Key, strings.Join(gone, ", "))
	}
	if opt.Signer != nil {
		origin, err := c.Origin(ctx)
		if err != nil {
			return "", nil, fmt.Errorf("signing needs the deployment's origin: %w", err)
		}
		for i, it := range req.Items {
			if req.Items[i].Steps, err = SignSteps(*opt.Signer, origin, b.Target, it.Resource, it.IfMatch, it.Steps); err != nil {
				return "", nil, err
			}
		}
	}
	dry, err := c.Batch(ctx, b.Target, req, true)
	if err != nil {
		return "", nil, fmt.Errorf("dry run: %w", err)
	}
	if fe := failedItems(b.Target, dry); fe != nil {
		return "", nil, fmt.Errorf("dry run: %w", fe)
	}
	res, err := c.Batch(ctx, b.Target, req, false)
	if err != nil {
		return "", nil, err
	}
	for _, it := range res.Items {
		if len(it.IDs) > 0 {
			got[it.Resource] = it.IDs[len(it.IDs)-1]
		}
	}
	return res.NSID, got, nil
}

func slicesContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
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
