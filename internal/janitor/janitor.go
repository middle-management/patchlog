// Package janitor is the branch cleanup service of §F.6. It follows base
// namespaces, discovers their branches (recursively), and purges a branch
// (§8.5) only when all of these hold:
//
//   - it is frozen, and merged, superseded or abandoned, and the claim is
//     verified (below), never trusted;
//   - its cleanup period for a state it is verified as has passed: the
//     member for that state of the branch document's own "cleanup":
//     { "merged": ISO duration, "superseded": ISO duration, "abandoned":
//     ISO duration }, counted from the created time of the last config
//     write that froze it or set or changed merged, successor or
//     abandoned. Without a member for a state it isn't purged as that
//     state, but may be as another it is verified as;
//   - so has the base's minimum for that state, if the base declares one;
//   - it has no dependents that aren't purged (leaves are purged first).
//
// Base minimums use the same shape in the base's own namespace document:
// "cleanup": { "merged": "P7D", "superseded": "P30D" }. They only lengthen
// a branch's own period: cleanup isn't copied into branches (§7.6), and a
// branch whose own cleanup has no member for a state is never purged as
// that state, whatever its base declares. Cleanup is opt-in, per branch.
// A stacked branch's own cleanup is also the minimum for its branches.
//
// Verification (§F.6):
//
//   - merged: the base's log has a batch without origin, written under a
//     grant whose root sub and kid are listed in the base's current
//     merge.authors (§7.4, merge.EntryListed), whose source.ns is the
//     branch and whose source.at is in the branch's chain, and the
//     branch's log has no head, tombstone or batch entry after that
//     source.at. Config, prune and propagated purge entries are allowed. A
//     base without merge.authors never verifies a merged claim this way.
//   - superseded: the successor is still one §7.4 allows: it exists,
//     isn't purged, and is a branch of the branch's base or of a namespace
//     further up its base chain in this deployment, listed in that
//     namespace's branches. One purged after the branch was frozen still
//     counts, checked from its log, which the purge leaves readable, but
//     not a sealed one, whose log the purge makes 410: that branch is
//     kept for a manual purge. The successor's log has a batch without
//     origin whose source.ns is the branch, whose source.at is in the
//     branch's chain, and whose recorded grant has a root sub and kid in
//     the base's current merge.authors or chains to a current * key of
//     the branch (as for abandoned, below), with nothing after it in the
//     branch. The rebase tool counts any such batch (§F.5); the janitor
//     only these, so a successor's writers can't get unmerged work purged.
//   - in both checks, every resource with a head, tombstone or batch entry
//     of the branch's own up to that source.at has an entry in a batch
//     that counts there whose source.at is at or after its last such
//     entry, or a head in the batch's namespace (the base, or the
//     successor) that equals or descends from the branch's revision of it
//     as of that source.at, as after a fast-forward. Otherwise the first
//     resource not covered is named, and a partial merge or replay doesn't
//     get the rest purged. Resources purged in the branch are left out.
//   - abandoned: the branch's document has "abandoned": true, set by a
//     config write whose recorded grant chains to a current * key of the
//     branch, inherited or its own (§F.6): the root kid of the entry's
//     grant (§7.4) names a key whose can lists "*" among the keys the
//     branch accepts now (§C.4: its bases' current keys, then its own,
//     less its copies of base keys the base has since dropped), and the
//     grant isn't revoked there now. Keys are inherited from local bases
//     only: the walk stops at a base in another deployment (base.origin),
//     so a namespace here that shares its name lends none. An entry
//     written while authentication was disabled records "grant": null
//     (§1): it counts while the deployment still runs disabled, as GET /
//     says ("auth": "disabled"), since every request then counts as
//     holding a * key, and for no one under "grants". An entry without
//     "grant" at all (the server's own, or one from before v0.37) counts
//     for no one.
//   - a branch with no head, tombstone or batch entry of its own counts as
//     merged.
//   - at E3, entries for the branch's keyring resource don't count in any
//     of these, since the keyring is never merged (§F.8.1); a batch counts
//     only if it has other items. Everything stays plaintext, so the
//     janitor needs no keys.
//
// The janitor needs read on bases and branches and purge-ns on branches;
// it never writes to a base.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/schema"
)

// Options configure a Janitor.
type Options struct {
	// Bases are the namespaces whose branch trees are cleaned.
	Bases []string
	// DryRun only reports: nothing is purged.
	DryRun bool
	// Now is the clock (default time.Now).
	Now func() time.Time
	// Interval is how often Run sweeps even without new entries, so that
	// cleanup periods that expire are noticed (default 1 minute).
	Interval time.Duration
	// OnDecision receives every decision Run makes (Sweep returns them).
	OnDecision func(Decision)
	// OnError receives errors Run retries.
	OnError func(error)
	// Releases are release documents (§F.9) whose branches the janitor
	// orders: those holding schema documents (drafts) are purged after
	// every other branch. A release document never authorises a purge;
	// each branch is checked as usual.
	Releases []string
}

// Actions of a decision.
const (
	ActionPurged     = "purged"
	ActionWouldPurge = "would-purge" // dry run
	ActionKeep       = "keep"
	// ActionRetry: eligible, but the purge was refused with in_use (§6.1);
	// a later sweep tries again.
	ActionRetry = "retry"
)

// Decision is the janitor's verdict on one branch.
type Decision struct {
	NS     string `json:"ns"`
	Base   string `json:"base"`
	Action string `json:"action"`
	// Claim is the verified claim ("merged", "superseded" or
	// "abandoned"), if any.
	Claim  string `json:"claim,omitempty"`
	Reason string `json:"reason"`
	// FrozenAt and EligibleAt are set once the claim is verified and has
	// a cleanup period: FrozenAt is when the period started counting, the
	// last config write that froze the branch or set merged, successor or
	// abandoned (§F.6), and EligibleAt when it ends.
	FrozenAt   time.Time `json:"frozenAt,omitzero"`
	EligibleAt time.Time `json:"eligibleAt,omitzero"`
	// Purge is the ns_id of the purge-ns entry the janitor wrote
	// (ActionPurged).
	Purge string `json:"purge,omitempty"`
}

// Janitor cleans up branches.
type Janitor struct {
	c   *client.Client
	opt Options
}

// New returns a janitor.
func New(c *client.Client, opt Options) *Janitor {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Interval <= 0 {
		opt.Interval = time.Minute
	}
	return &Janitor{c: c, opt: opt}
}

// Sweep makes one pass over every base's branch tree, leaves first, and
// returns a decision per live branch.
//
// Draft branches go last (§F.9 Cleanup): a branch holding draft schema
// revisions can't be purged while documents rely on its last copy of one
// (§6.1), so every other branch of every base is handled first, and with
// it the documents of a release that rely on the drafts. A draft branch is
// one whose namespace document has drafts (§7.4), or one a release in
// Options.Releases lists that holds schema documents. A purge refused with
// in_use, of a draft branch or any other, is retried once at the end of
// the sweep, and if it is still refused, the decision is ActionRetry: the
// next sweep tries again. The janitor never forces a purge, and a release
// document only orders the sweep: it never authorises a purge.
func (j *Janitor) Sweep(ctx context.Context) ([]Decision, error) {
	var cands []candidate
	var errs []error
	for _, b := range j.opt.Bases {
		cs, err := j.walk(ctx, b)
		cands = append(cands, cs...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	drafts, err := j.draftBranches(ctx, cands)
	if err != nil {
		errs = append(errs, err)
	}
	var first, last []candidate
	for _, c := range cands {
		if drafts[c.ns] {
			last = append(last, c)
		} else {
			first = append(first, c)
		}
	}
	var out []Decision
	var retry []candidate
	check := func(c candidate, final bool) {
		d, err := j.Check(ctx, c.base, c.ns)
		if err != nil {
			errs = append(errs, fmt.Errorf("janitor: %s: %w", c.ns, err))
			return
		}
		if d.Action == ActionRetry && !final {
			retry = append(retry, c)
			return
		}
		out = append(out, d)
	}
	for _, c := range first {
		check(c, false)
	}
	for _, c := range last {
		check(c, false)
	}
	for _, c := range retry {
		check(c, true)
	}
	return out, errors.Join(errs...)
}

type candidate struct{ base, ns string }

// walk lists ns's live branches, each after its own branches.
func (j *Janitor) walk(ctx context.Context, ns string) ([]candidate, error) {
	brs, err := j.c.Branches(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("janitor: branches of %s: %w", ns, err)
	}
	var out []candidate
	var errs []error
	for _, b := range brs {
		if b.Name == "" || b.Purged || b.Remote != nil {
			continue
		}
		cs, err := j.walk(ctx, b.Name)
		out = append(out, cs...)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, candidate{ns, b.Name})
	}
	return out, errors.Join(errs...)
}

// draftBranches finds the draft branches among the candidates: drafts in
// their namespace document, or listed by a release of Options.Releases
// and holding schema documents (a $schema that is a dialect URL).
func (j *Janitor) draftBranches(ctx context.Context, cands []candidate) (map[string]bool, error) {
	out := map[string]bool{}
	listed := map[string]bool{}
	var errs []error
	for _, link := range j.opt.Releases {
		rel, err := release.Load(ctx, j.c, link)
		if err != nil {
			errs = append(errs, fmt.Errorf("janitor: release %s: %w", link, err))
			continue
		}
		for _, b := range rel.Doc.Branches {
			listed[b.NS] = true
		}
	}
	for _, c := range cands {
		h, err := j.c.NSHead(ctx, c.ns)
		if err != nil {
			continue // Check reports it
		}
		doc, err := j.c.NSDoc(ctx, c.ns, h.ID)
		if err != nil {
			continue
		}
		if _, ok := doc.Value["drafts"]; ok {
			out[c.ns] = true
			continue
		}
		if !listed[c.ns] {
			continue
		}
		holds, err := j.holdsSchemas(ctx, c.ns, h.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("janitor: %s: %w", c.ns, err))
			continue
		}
		out[c.ns] = holds
	}
	return out, errors.Join(errs...)
}

// holdsSchemas reports whether a branch wrote a schema document.
func (j *Janitor) holdsSchemas(ctx context.Context, ns, at string) (bool, error) {
	log, err := j.c.NSLog(ctx, ns, at, "")
	if err != nil {
		return false, err
	}
	for _, ch := range merge.Collect(log) {
		if ch.Kind != "head" || ch.Purged {
			continue
		}
		d, err := j.c.Doc(ctx, ns, ch.Resource, ch.Target)
		if err != nil {
			if client.IsGone(err) || client.IsNotFound(err) {
				continue
			}
			return false, err
		}
		m, _ := d.Value.(map[string]any)
		if s, _ := m["$schema"].(string); schema.IsDialect(s) {
			return true, nil
		}
	}
	return false, nil
}

// Check evaluates one branch of base and purges it if every condition holds
// (unless DryRun).
func (j *Janitor) Check(ctx context.Context, base, ns string) (Decision, error) {
	d := Decision{NS: ns, Base: base, Action: ActionKeep}
	head, err := j.c.NSHead(ctx, ns)
	if err != nil {
		return d, err
	}
	doc, err := j.c.NSDoc(ctx, ns, head.ID)
	if client.IsPurged(err) {
		return purgedSince(d, err), nil
	}
	if err != nil {
		return d, err
	}
	bref, _ := doc.Value["base"].(map[string]any)
	if bns, _ := bref["ns"].(string); bns != base {
		d.Reason = fmt.Sprintf("its base is %q, not %s", bns, base)
		return d, nil
	}
	if frozen, _ := doc.Value["frozen"].(bool); !frozen {
		d.Reason = "not frozen"
		return d, nil
	}
	log, err := j.c.NSLog(ctx, ns, head.ID, "")
	if client.IsPurged(err) {
		return purgedSince(d, err), nil
	}
	if err != nil {
		return d, err
	}

	enc, _ := doc.Value["encryption"].(map[string]any)
	b := &branch{j: j, base: base, ns: ns, doc: doc.Value, log: log, e2e: enc["level"] == "e2e",
		docs: map[string]nsAt{ns: {head.ID, doc.Value}}, keyCache: map[string]map[string]nsKey{}}
	if b.cfgs, err = b.configDocs(ctx); err != nil {
		return d, err
	}
	frozeAt, since, err := freezeTimes(ns, b.cfgs)
	if err != nil {
		return d, err
	}

	// Claims, verified, in this order. The branch is purged as a verified
	// claim whose cleanup period has passed: the first one found, or else
	// the one whose period ends first. A claim without a period of the
	// branch's own isn't one it is purged as (§F.6).
	var why, noPeriod []string
	found := "" // the first verified claim
	var best struct {
		claim    string
		eligible time.Time
	}
	now := j.opt.Now()
	for _, claim := range claims {
		present, ok, reason, err := b.verify(ctx, claim, frozeAt)
		if err != nil {
			return d, err
		}
		if !present {
			continue
		}
		if !ok {
			why = append(why, claim+" claim not verified: "+reason)
			continue
		}
		if found == "" {
			found = claim
		}
		bdoc, err := b.current(ctx, base)
		if err != nil {
			return d, err
		}
		eligible, reason := cleanupPeriod(claim, doc.Value, bdoc, since)
		if reason != "" {
			noPeriod = append(noPeriod, reason)
			continue
		}
		if best.claim == "" || eligible.Before(best.eligible) {
			best.claim, best.eligible = claim, eligible
		}
		if !now.Before(eligible) {
			break
		}
	}
	switch {
	case found == "":
		if len(why) == 0 {
			why = append(why, "frozen, but neither merged, superseded nor abandoned")
		}
		d.Reason = strings.Join(why, "; ")
		return d, nil
	case best.claim == "":
		d.Claim, d.Reason = found, strings.Join(append(noPeriod, why...), "; ")
		return d, nil
	}
	d.Claim, d.FrozenAt, d.EligibleAt = best.claim, since, best.eligible
	if now.Before(best.eligible) {
		d.Reason = fmt.Sprintf("%s; cleanup period runs until %s", d.Claim, best.eligible.UTC().Format(time.RFC3339))
		return d, nil
	}

	// Dependents: leaves first.
	deps, err := j.c.Branches(ctx, ns)
	if err != nil {
		return d, err
	}
	var live []string
	for _, b := range deps {
		if b.Name != "" && !b.Purged && b.Remote == nil {
			live = append(live, b.Name)
		}
	}
	if len(live) > 0 {
		sort.Strings(live)
		d.Reason = fmt.Sprintf("%s and expired, but has dependents: %s", d.Claim, strings.Join(live, ", "))
		return d, nil
	}

	if j.opt.DryRun {
		d.Action, d.Reason = ActionWouldPurge, d.Claim+", verified and expired"
		return d, nil
	}
	id, err := j.c.PurgeNamespace(ctx, ns, head.ID)
	if err != nil {
		if client.IsStale(err) {
			d.Reason = "the branch changed while checking; next sweep"
			return d, nil
		}
		if client.IsInUse(err) {
			// Documents still rely on the branch's last copy of a schema
			// revision (§6.1), e.g. a release's drafts while its other
			// branches aren't purged yet (§F.9): try again later, never
			// force.
			ae, _ := client.AsAPIError(err)
			d.Action, d.Reason = ActionRetry, d.Claim+", verified and expired, but the purge is refused with in_use"
			if ae != nil && len(ae.Referencing()) > 0 {
				d.Reason += ": still referenced from " + strings.Join(ae.Referencing(), ", ")
			}
			d.Reason += "; retried later"
			return d, nil
		}
		if ae, ok := client.AsAPIError(err); ok && ae.Status == 409 {
			d.Reason = "purge refused: " + err.Error()
			return d, nil
		}
		return d, err
	}
	d.Action, d.Purge, d.Reason = ActionPurged, id, d.Claim+", verified and expired"
	return d, nil
}

// claims are the states a branch is purged as, in the order they are
// checked (§F.6).
var claims = []string{"merged", "superseded", "abandoned"}

// branch is one Check's view of a branch: its document and log as of its
// head, its config writes, and the current documents of the namespaces
// the checks read, each fetched once.
type branch struct {
	j    *Janitor
	base string
	ns   string
	doc  map[string]any
	log  []client.NSEntry
	e2e  bool // at E3 the keyring is never merged (§F.6, §F.8.1)
	cfgs []configEntry
	docs map[string]nsAt
	// keyCache holds keys by namespace.
	keyCache map[string]map[string]nsKey
}

// nsAt is a namespace's head and its document there.
type nsAt struct {
	id  string
	doc map[string]any
}

// head returns ns's head and its namespace document there.
func (b *branch) head(ctx context.Context, ns string) (string, map[string]any, error) {
	if d, ok := b.docs[ns]; ok {
		return d.id, d.doc, nil
	}
	h, err := b.j.c.NSHead(ctx, ns)
	if err != nil {
		return "", nil, err
	}
	d, err := b.j.c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return "", nil, err
	}
	b.docs[ns] = nsAt{h.ID, d.Value}
	return h.ID, d.Value, nil
}

// current returns ns's namespace document at its head.
func (b *branch) current(ctx context.Context, ns string) (map[string]any, error) {
	_, d, err := b.head(ctx, ns)
	return d, err
}

// verify checks one claim (§F.6); present is false when the branch
// doesn't make it. A branch with no head, tombstone or batch entry of its
// own (its keyring's aside at E3) counts as merged.
func (b *branch) verify(ctx context.Context, claim string, frozeAt time.Time) (present, ok bool, reason string, err error) {
	switch claim {
	case "merged":
		if !hasDocEntries(b.log, -1, b.e2e) {
			return true, true, "", nil
		}
		if _, has := b.doc["merged"]; !has {
			return false, false, "", nil
		}
		ok, reason, err = b.verifyMerged(ctx)
	case "superseded":
		s, _ := b.doc["successor"].(string)
		if s == "" {
			return false, false, "", nil
		}
		ok, reason, err = b.verifySuperseded(ctx, s, frozeAt)
	case "abandoned":
		if ab, _ := b.doc["abandoned"].(bool); !ab {
			return false, false, "", nil
		}
		ok, reason, err = b.verifyAbandoned(ctx)
	}
	return true, ok, reason, err
}

// cleanupPeriod returns when a branch verified as claim may be purged as
// that state (§F.6): the member of its own cleanup for claim, counted from
// since, or the base's member for claim where that is longer, as the base
// sets only minimums. A branch whose own cleanup has no member for claim
// isn't purged as claim, whatever its base's says (cleanup isn't copied
// into branches, §7.6): reason says why there is no time.
func cleanupPeriod(claim string, own, base map[string]any, since time.Time) (eligible time.Time, reason string) {
	cl, _ := own["cleanup"].(map[string]any)
	p, ok := cl[claim].(string)
	if !ok {
		return time.Time{}, fmt.Sprintf("%s, but no cleanup period for %s in the branch", claim, claim)
	}
	eligible, err := AddDuration(since, p)
	if err != nil {
		return time.Time{}, fmt.Sprintf("%s, but invalid cleanup period: %v", claim, err)
	}
	bcl, _ := base["cleanup"].(map[string]any)
	if bp, ok := bcl[claim].(string); ok {
		t, err := AddDuration(since, bp)
		if err != nil {
			return time.Time{}, fmt.Sprintf("%s, but invalid cleanup minimum in the base: %v", claim, err)
		}
		if t.After(eligible) {
			eligible = t
		}
	}
	return eligible, ""
}

// purgedSince is the decision on a sealed branch purged since it was
// listed, whose document and log answer 410 purged, with head its purge-ns
// entry (§8.5): kept, as there is nothing left to purge. Purge stays
// empty, as the janitor purged nothing; the reason names the entry.
func purgedSince(d Decision, gone error) Decision {
	d.Reason = "already purged"
	if ae, ok := client.AsAPIError(gone); ok && ae.Head() != "" {
		d.Reason += " (purge-ns " + ae.Head() + ")"
	}
	return d
}

// isDocEntry reports head, tombstone and batch entries: the ones that change
// documents. Config, prune and (propagated) purge entries don't count. In
// an e2e branch (e2e) neither do entries for its keyring resource, which is
// never merged (§F.8.1): a batch counts only if it has other items.
func isDocEntry(e client.NSEntry, e2e bool) bool {
	switch e.Kind {
	case "head", "tombstone":
		return !e2e || e.Resource != client.KeyringName
	case "batch":
		if !e2e {
			return true
		}
		for _, s := range e.Entries {
			if isDocEntry(s, e2e) {
				return true
			}
		}
	}
	return false
}

// hasDocEntries reports a document entry in log after index i.
func hasDocEntries(log []client.NSEntry, i int, e2e bool) bool {
	for _, e := range log[i+1:] {
		if isDocEntry(e, e2e) {
			return true
		}
	}
	return false
}

// coverage is what coveredBy found: best, the index in the branch's log of
// the latest counting batch's source.at, and at, per resource, the latest
// such index of a counting batch with an entry for it.
type coverage struct {
	best int
	at   map[string]int
}

// coveredBy finds the batches of entries that count for branch: those
// without origin whose source.ns is branch, whose source.at is in the
// branch's chain (blog), and that trusted accepts, as written by trustedBy
// (for the reason). It checks that the branch changed no document after
// the latest one's source.at. disabled says the deployment runs with
// authentication disabled (§1), for the reason too. A nil coverage comes
// with why.
func coveredBy(entries []client.NSEntry, branch string, blog []client.NSEntry, trusted func(client.NSEntry) (bool, error), trustedBy string, e2e, disabled bool) (*coverage, string, error) {
	pos := map[string]int{}
	for i, e := range blog {
		pos[e.ID] = i
	}
	cov := &coverage{best: -1, at: map[string]int{}}
	forged, untrusted := 0, []string{}
	for _, e := range entries {
		if !merge.IsMergeOf(e, branch) {
			continue
		}
		ok, err := trusted(e)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			who := e.Author
			switch {
			case e.Grant != nil:
				who = e.Grant.Sub + "/" + e.Grant.Kid
			case e.GrantNull && !disabled:
				who += " (written without authentication, which counts for no one under grants)"
			case !e.GrantNull:
				who += " (no grant recorded)"
			}
			untrusted = append(untrusted, e.ID+" by "+who)
			continue
		}
		at, _ := e.Source["at"].(string)
		i, ok := pos[at]
		if !ok {
			forged++
			continue
		}
		cov.best = max(cov.best, i)
		for _, s := range e.Entries {
			if s.Kind != "head" && s.Kind != "tombstone" {
				continue
			}
			if j, seen := cov.at[s.Resource]; !seen || i > j {
				cov.at[s.Resource] = i
			}
		}
	}
	if cov.best < 0 {
		if len(untrusted) > 0 {
			return nil, "no batch of the branch is by " + trustedBy + " (" + strings.Join(untrusted, ", ") + ")", nil
		}
		if forged > 0 {
			return nil, "its batches' source.at is not in the branch's chain", nil
		}
		return nil, "no batch without origin has source.ns = " + branch, nil
	}
	if hasDocEntries(blog, cov.best, e2e) {
		return nil, "the branch changed documents after " + blog[cov.best].ID, nil
	}
	return cov, "", nil
}

// closing checks §F.6's closing rule once coveredBy found cov in target's
// log (the base's, or the successor's): every resource with a head,
// tombstone or batch entry of the branch's own up to the latest counting
// batch's source.at, other than its keyring at E3, has an entry in a
// counting batch whose source.at is at or after its last such entry, or a
// head in target that equals or descends from the branch's revision of it
// as of that source.at, as after a fast-forward. Otherwise a partial merge
// or replay (one leaving a resource out, or a later merge that missed a
// resource changed again since an earlier one) would get unmerged work
// purged. A resource purged in the branch has nothing left to lose and is
// left out. why names the first resource not covered.
func (b *branch) closing(ctx context.Context, target string, cov *coverage) (bool, string, error) {
	last, rev := map[string]int{}, map[string]string{}
	note := func(i int, e client.NSEntry) {
		if (e.Kind == "head" || e.Kind == "tombstone") && !(b.e2e && e.Resource == client.KeyringName) {
			last[e.Resource], rev[e.Resource] = i, e.Target
		}
	}
	for i, e := range b.log[:cov.best+1] {
		note(i, e)
		if e.Kind == "batch" {
			for _, s := range e.Entries {
				note(i, s)
			}
		}
	}
	purged := map[string]bool{}
	for _, e := range b.log {
		if e.Kind == "purge" {
			purged[e.Resource] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(last)) {
		if purged[name] {
			continue
		}
		if i, ok := cov.at[name]; ok && i >= last[name] {
			continue
		}
		ok, err := b.descends(ctx, target, name, rev[name])
		if err != nil {
			return false, "", err
		}
		if !ok {
			return false, fmt.Sprintf("%s, changed by the branch in %s, has no entry in a batch that counts since, and %s's head for it neither equals nor descends from the branch's revision %s",
				name, b.log[last[name]].ID, target, rev[name]), nil
		}
	}
	return true, "", nil
}

// descends reports whether target's head for name equals rev or descends
// from it (rev is in its log). A head that can't be read, or whose range
// to rev is pruned, doesn't. At E3 ids never carry over from a branch, as
// merges and rebases re-seal (§F.8.1), so only equality is looked for.
func (b *branch) descends(ctx context.Context, target, name, rev string) (bool, error) {
	h, err := b.j.c.Head(ctx, target, name)
	if err != nil {
		if _, api := client.AsAPIError(err); api {
			return false, nil
		}
		return false, err
	}
	switch {
	case h.State != client.Live && h.State != client.Tombstoned:
		return false, nil
	case h.ID == rev:
		return true, nil
	case b.e2e:
		return false, nil
	}
	_, _, err = b.j.c.LogPage(ctx, target, name, h.ID, rev)
	if err == nil {
		return true, nil
	}
	if _, api := client.AsAPIError(err); api {
		return false, nil
	}
	return false, err
}

// covered runs coveredBy and closing against target.
func (b *branch) covered(ctx context.Context, target string, entries []client.NSEntry, trusted func(client.NSEntry) (bool, error), trustedBy string, disabled bool) (bool, string, error) {
	cov, why, err := coveredBy(entries, b.ns, b.log, trusted, trustedBy, b.e2e, disabled)
	if cov == nil || err != nil {
		return false, why, err
	}
	return b.closing(ctx, target, cov)
}

func (b *branch) verifyMerged(ctx context.Context) (bool, string, error) {
	bh, bdoc, err := b.head(ctx, b.base)
	if err != nil {
		return false, "", err
	}
	bref, _ := b.doc["base"].(map[string]any)
	at, _ := bref["at"].(string)
	entries, err := b.j.c.NSLog(ctx, b.base, bh, at)
	if client.IsNotFound(err) && at != "" {
		entries, err = b.j.c.NSLog(ctx, b.base, bh, "")
	}
	if err != nil {
		return false, "", err
	}
	authors, declared := merge.MergeAuthors(bdoc)
	if !declared {
		return false, "the base " + b.base + " declares no merge.authors, so no merge batch can be trusted (§F.3)", nil
	}
	disabled, err := b.j.c.AuthDisabled(ctx)
	if err != nil {
		return false, "", err
	}
	listed := func(e client.NSEntry) (bool, error) { return merge.EntryListed(authors, e, disabled), nil }
	return b.covered(ctx, b.base, entries, listed, "a principal in the base's merge.authors", disabled)
}

// sealedPurged is the reason a branch whose successor is a purged sealed
// namespace is kept: the purge made the successor's log 410 (§8.5), so its
// batches can't be checked, and the branch needs a manual purge.
func sealedPurged(succ string) string {
	return "successor " + succ + " is purged and sealed, so its log answers 410 (§8.5): sealed successor purged: verify by hand"
}

// baseChain returns the branch's bases in this deployment, its base first
// (§7.4, §7.6); it stops at a base in another deployment.
func (b *branch) baseChain(ctx context.Context) ([]string, error) {
	var out []string
	doc := b.doc
	for i := 0; i <= maxDepth; i++ {
		bns, _, ok := localBase(doc)
		if !ok {
			break
		}
		out = append(out, bns)
		var err error
		if doc, err = b.current(ctx, bns); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// verifySuperseded checks a superseded claim (§F.6):
//
//   - the successor is still one §7.4 allows: another namespace that
//     exists, isn't purged, and is a branch of the branch's base or of a
//     namespace further up its base chain in this deployment, listed as
//     such in that namespace's branches. A successor purged after the
//     branch was frozen (frozeAt) still counts, checked from its log,
//     which the purge leaves readable, except a sealed one, whose log the
//     purge makes 410: the branch is then kept for a manual purge;
//   - its log has a batch without origin whose source.ns is the branch,
//     whose source.at is in the branch's chain, and whose recorded grant
//     has a root sub and kid in the base's current merge.authors or
//     chains to a current * key of the branch (starKey), with nothing
//     after that source.at in the branch. One recording "grant": null
//     counts while the deployment runs with authentication disabled (§1).
//     The rebase tool counts any such batch as an earlier merge (§F.5),
//     the janitor only these.
func (b *branch) verifySuperseded(ctx context.Context, succ string, frozeAt time.Time) (bool, string, error) {
	if succ == b.ns {
		return false, "the successor is the branch itself", nil
	}
	sh, err := b.j.c.NSHead(ctx, succ)
	if client.IsNotFound(err) {
		return false, "successor " + succ + " doesn't exist", nil
	}
	if err != nil {
		return false, "", err
	}
	sdoc, err := b.j.c.NSDoc(ctx, succ, sh.ID)
	if client.IsPurged(err) {
		// A sealed successor's document, once it is purged (§8.5).
		return false, sealedPurged(succ), nil
	}
	if err != nil {
		return false, "", err
	}
	b.docs[succ] = nsAt{sh.ID, sdoc.Value}
	sref, _ := sdoc.Value["base"].(map[string]any)
	sbase, _ := sref["ns"].(string)
	if _, remote := sref["origin"]; remote || sbase == "" {
		return false, "successor " + succ + " is not a branch in this deployment (§7.4)", nil
	}
	chain, err := b.baseChain(ctx)
	if err != nil {
		return false, "", err
	}
	if !slices.Contains(chain, sbase) {
		return false, fmt.Sprintf("successor %s is a branch of %s, not of a namespace in the branch's base chain (%s, §7.4)", succ, sbase, strings.Join(chain, ", ")), nil
	}
	brs, err := b.j.c.Branches(ctx, sbase)
	if err != nil {
		return false, "", err
	}
	i := slices.IndexFunc(brs, func(br client.Branch) bool { return br.Name == succ })
	if i < 0 {
		return false, "successor " + succ + " is not a branch of " + sbase, nil
	}
	entries, err := b.j.c.NSLog(ctx, succ, sh.ID, "")
	if client.IsPurged(err) {
		return false, sealedPurged(succ), nil
	}
	if err != nil {
		return false, "", err
	}
	if brs[i].Purged {
		// Its log stays readable, the purge-ns entry its last (§8.5).
		var purgedAt time.Time
		if n := len(entries); n > 0 && entries[n-1].Kind == "purge-ns" {
			purgedAt, _ = time.Parse(time.RFC3339Nano, entries[n-1].Created)
		}
		if purgedAt.IsZero() {
			return false, "successor " + succ + " is purged, but its log has no purge-ns entry to date the purge by", nil
		}
		if !purgedAt.After(frozeAt) {
			return false, fmt.Sprintf("successor %s was purged at %s, before the branch was frozen at %s", succ,
				purgedAt.UTC().Format(time.RFC3339Nano), frozeAt.UTC().Format(time.RFC3339Nano)), nil
		}
	}
	_, bdoc, err := b.head(ctx, b.base)
	if err != nil {
		return false, "", err
	}
	authors, _ := merge.MergeAuthors(bdoc)
	disabled, err := b.j.c.AuthDisabled(ctx)
	if err != nil {
		return false, "", err
	}
	trusted := func(e client.NSEntry) (bool, error) {
		switch {
		case merge.EntryListed(authors, e, disabled):
			return true, nil
		case e.GrantNull:
			// Written while every request counted as holding a * key (§1).
			return disabled, nil
		}
		ok, _, err := b.starKey(ctx, e, succ)
		return ok, err
	}
	return b.covered(ctx, succ, entries, trusted, "a principal in the base's merge.authors or under a current * key of the branch", disabled)
}

// verifyAbandoned checks an abandoned claim (§F.6): the config write that
// set "abandoned": true was made under a grant chained to a current * key
// of the branch, inherited from a local base or its own (starKey): a key
// removed or replaced since, or one of a base in another deployment,
// doesn't count. Only its administrators can give up everyone's unmerged
// work.
func (b *branch) verifyAbandoned(ctx context.Context) (bool, string, error) {
	var setter *configEntry
	was := false
	for i := range b.cfgs {
		ab, _ := b.cfgs[i].doc["abandoned"].(bool)
		if ab && !was {
			setter = &b.cfgs[i]
		}
		was = ab
	}
	if setter == nil {
		return false, "no config write set abandoned", nil
	}
	e := setter.e
	if e.Grant == nil {
		if !e.GrantNull {
			return false, fmt.Sprintf("the config write %s that set it records no grant (§7.4), so its key can't be checked; set abandoned again", e.ID), nil
		}
		// Written while authentication was disabled (grant: null), when
		// every request counted as holding a * key: it counts only while
		// the deployment still runs disabled (§1).
		disabled, err := b.j.c.AuthDisabled(ctx)
		if err != nil {
			return false, "", err
		}
		if disabled {
			return true, "", nil
		}
		return false, fmt.Sprintf("the config write %s that set it was written while authentication was disabled (grant: null), which counts for no one now that the deployment runs with grants (§1); set abandoned again", e.ID), nil
	}
	ok, why, err := b.starKey(ctx, e, b.ns)
	if err != nil || ok {
		return ok, "", err
	}
	return false, fmt.Sprintf("the config write %s that set it was by %s, but %s", e.ID, e.Grant.Sub, why), nil
}

// nsKey is a namespace key as the janitor compares keys: its alg and pub,
// and whether its can lists "*".
type nsKey struct {
	alg, pub string
	star     bool
}

// parseKeys reads a namespace document's keys by kid. The core validates
// them, so malformed entries are skipped.
func parseKeys(v any) map[string]nsKey {
	out := map[string]nsKey{}
	arr, _ := v.([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		kid, _ := m["kid"].(string)
		if kid == "" {
			continue
		}
		var k nsKey
		k.alg, _ = m["alg"].(string)
		k.pub, _ = m["pub"].(string)
		can, _ := m["can"].([]any)
		k.star = slices.Contains(can, any("*"))
		out[kid] = k
	}
	return out
}

// localBase returns the base of a namespace document in this deployment:
// its name and at, and false for a namespace that isn't a branch, or whose
// base lives in another deployment (base.origin, §7.6, §G.3).
func localBase(doc map[string]any) (ns, at string, ok bool) {
	bref, _ := doc["base"].(map[string]any)
	ns, _ = bref["ns"].(string)
	at, _ = bref["at"].(string)
	if _, remote := bref["origin"]; remote || ns == "" {
		return "", "", false
	}
	return ns, at, true
}

// maxDepth bounds base chains (the deployment's branch depth is 8 by
// default, §6.6).
const maxDepth = 32

// keys returns the keys ns accepts now, by kid, as the core does (§C.4,
// keys follow the base): its base's, recursively, whose entries win over
// ns's own for a shared kid, then its own, less those it copied from its
// base at creation and the base has since removed. Only local bases count
// (§7.6): the walk stops at a namespace whose base has origin, so a local
// namespace that shares a remote base's name lends no keys.
func (b *branch) keys(ctx context.Context, ns string) (map[string]nsKey, error) {
	return b.keysAt(ctx, ns, 0)
}

func (b *branch) keysAt(ctx context.Context, ns string, depth int) (map[string]nsKey, error) {
	if k, ok := b.keyCache[ns]; ok {
		return k, nil
	}
	if depth > maxDepth {
		return nil, fmt.Errorf("janitor: base chain of %s too deep", ns)
	}
	doc, err := b.current(ctx, ns)
	if err != nil {
		return nil, err
	}
	out := parseKeys(doc["keys"])
	if bns, at, ok := localBase(doc); ok {
		baseKeys, err := b.keysAt(ctx, bns, depth+1)
		if err != nil {
			return nil, err
		}
		copied, err := b.copiedKids(ctx, ns, bns, at)
		if err != nil {
			return nil, err
		}
		own := out
		out = maps.Clone(baseKeys)
		for kid, k := range own {
			if _, inBase := baseKeys[kid]; inBase || copied[kid] {
				continue
			}
			out[kid] = k
		}
	}
	b.keyCache[ns] = out
	return out, nil
}

// copiedKids returns the kids a branch copied from its base at creation:
// those of the base's document in force at the base's branch entry for it,
// found in the base's log after the branch's at (§7.6, §C.4).
func (b *branch) copiedKids(ctx context.Context, ns, base, at string) (map[string]bool, error) {
	bh, _, err := b.head(ctx, base)
	if err != nil {
		return nil, err
	}
	entries, err := b.j.c.NSLog(ctx, base, bh, at)
	if err != nil {
		return nil, fmt.Errorf("janitor: log of %s, the base of %s: %w", base, ns, err)
	}
	for _, e := range entries {
		if e.Kind != "branch" || e.Name != ns || e.Remote != nil {
			continue
		}
		d, err := b.j.c.NSDoc(ctx, base, e.ID)
		if err != nil {
			return nil, err
		}
		out := map[string]bool{}
		for kid := range parseKeys(d.Value["keys"]) {
			out[kid] = true
		}
		return out, nil
	}
	return nil, fmt.Errorf("janitor: no branch entry for %s in %s after %s", ns, base, at)
}

// revoked returns the revocation ids in force in ns now: its own and those
// of its local bases (§C.4).
func (b *branch) revoked(ctx context.Context, ns string) (map[string]bool, error) {
	out := map[string]bool{}
	for i := 0; ns != "" && i <= maxDepth; i++ {
		doc, err := b.current(ctx, ns)
		if err != nil {
			return nil, err
		}
		rv, _ := doc["revoked"].([]any)
		for _, x := range rv {
			if s, ok := x.(string); ok {
				out[s] = true
			}
		}
		ns, _, _ = localBase(doc)
	}
	return out, nil
}

// starKey reports whether a namespace entry's recorded grant chains to a
// current * key of the branch (§F.6), as far as a janitor can tell from
// what the entry records, the grant's id and its root sub and kid (§7.4):
// the kid names a key whose can lists "*" among the keys the branch
// accepts now (keys: its own or a local base's), and the grant isn't
// revoked there now. A kid is a name within a namespace, so for an entry
// written in another namespace, in (a successor), the kid must also name
// the same key, alg and pub, among those in accepts now. why says what
// failed. An entry without a grant, such as one written while
// authentication was disabled, is the caller's to judge.
func (b *branch) starKey(ctx context.Context, e client.NSEntry, in string) (ok bool, why string, err error) {
	if e.Grant == nil || e.Grant.Kid == "" {
		return false, "it records no key", nil
	}
	kid := e.Grant.Kid
	keys, err := b.keys(ctx, b.ns)
	if err != nil {
		return false, "", err
	}
	k, found := keys[kid]
	switch {
	case !found:
		return false, fmt.Sprintf("key %q isn't one the branch accepts now (§C.4)", kid), nil
	case !k.star:
		return false, fmt.Sprintf("key %q isn't a * key of the branch", kid), nil
	}
	rv, err := b.revoked(ctx, b.ns)
	if err != nil {
		return false, "", err
	}
	if e.Grant.ID != "" && rv[e.Grant.ID] {
		return false, fmt.Sprintf("its grant %s is revoked in the branch (§C.4)", e.Grant.ID), nil
	}
	if in == b.ns {
		return true, "", nil
	}
	ks, err := b.keys(ctx, in)
	if err != nil {
		return false, "", err
	}
	if k2, found := ks[kid]; !found || !strings.EqualFold(k2.alg, k.alg) || k2.pub != k.pub {
		return false, fmt.Sprintf("key %q of %s isn't the branch's * key of that name", kid, in), nil
	}
	return true, "", nil
}

// configEntry is one of the branch's config writes, a config entry or a
// batch whose first item is one, with the namespace document it left in
// force.
type configEntry struct {
	e   client.NSEntry
	doc map[string]any
}

// configDocs returns the branch's config writes, oldest first, from its
// genesis.
func (b *branch) configDocs(ctx context.Context) ([]configEntry, error) {
	var out []configEntry
	for _, e := range b.log {
		if e.Kind != "config" && (e.Kind != "batch" || len(e.Entries) == 0 || e.Entries[0].Kind != "config") {
			continue
		}
		d, err := b.j.c.NSDoc(ctx, b.ns, e.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, configEntry{e, d.Value})
	}
	return out, nil
}

// freezeTimes returns, from a frozen branch's config writes, frozeAt, the
// created time of the write that froze it (the first of the trailing
// writes whose document is frozen), and since, that of the last write
// that froze it or set or changed merged, successor or abandoned, from
// which its cleanup period counts (§F.6). Other config writes, such as one
// changing cleanup, don't restart the period.
func freezeTimes(ns string, cfgs []configEntry) (frozeAt, since time.Time, err error) {
	var prev map[string]any
	fz, last := "", ""
	for _, c := range cfgs {
		was, _ := prev["frozen"].(bool)
		is, _ := c.doc["frozen"].(bool)
		switch {
		case !is:
			fz, last = "", ""
		case !was:
			fz, last = c.e.Created, c.e.Created
		default:
			for _, m := range []string{"merged", "successor", "abandoned"} {
				if v, ok := c.doc[m]; ok && !reflect.DeepEqual(v, prev[m]) {
					last = c.e.Created
				}
			}
		}
		prev = c.doc
	}
	if fz == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("janitor: %s: no freezing config entry", ns)
	}
	if frozeAt, err = time.Parse(time.RFC3339Nano, fz); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("janitor: %s: config entry created %q: %w", ns, fz, err)
	}
	if since, err = time.Parse(time.RFC3339Nano, last); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("janitor: %s: config entry created %q: %w", ns, last, err)
	}
	return frozeAt, since, nil
}

// Run follows the bases and their branches (follow.WithBranches) and sweeps
// whenever an entry arrives, and every Interval, until ctx is done. A base
// that is purged ends its follower, as nothing more arrives in its log
// (§8.5), and the sweeps go on.
func (j *Janitor) Run(ctx context.Context) error {
	origin, err := j.c.Origin(ctx)
	if err != nil {
		return err
	}
	cp := &follow.MemoryCheckpoints{}
	// Start at the current heads: the sweeps read the state themselves, so
	// the followers only need to wake them up and discover new branches.
	var seed func(ns string) error
	seed = func(ns string) error {
		h, err := j.c.NSHead(ctx, ns)
		if err != nil {
			return err
		}
		cp.Save(origin, ns, h.ID)
		brs, err := j.c.Branches(ctx, ns)
		if err != nil {
			return err
		}
		for _, b := range brs {
			if b.Name != "" && !b.Purged && b.Remote == nil {
				if err := seed(b.Name); err != nil && !client.IsNotFound(err) && !client.IsAuth(err) {
					return err
				}
			}
		}
		return nil
	}
	for _, b := range j.opt.Bases {
		if err := seed(b); err != nil {
			return err
		}
	}
	wake := make(chan struct{}, 1)
	h := follow.HandlerFunc(func(_ context.Context, b *follow.Batch) error {
		cp.SaveBatch(b.Origin, b.NS, b)
		select {
		case wake <- struct{}{}:
		default:
		}
		return nil
	})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, len(j.opt.Bases))
	for _, b := range j.opt.Bases {
		f := follow.New(j.c, b, cp, h, follow.WithBranches(), follow.WithMaxUnits(0),
			follow.WithOnError(func(ns string, err error) { j.reportErr(fmt.Errorf("%s: %w", ns, err)) }))
		go func() { done <- f.Run(ctx) }()
	}
	t := time.NewTicker(j.opt.Interval)
	defer t.Stop()
	for {
		ds, err := j.Sweep(ctx)
		if err != nil && ctx.Err() == nil {
			j.reportErr(err)
		}
		if j.opt.OnDecision != nil {
			for _, d := range ds {
				j.opt.OnDecision(d)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !errors.Is(err, follow.ErrPurged) {
				return fmt.Errorf("janitor: follower stopped: %w", err)
			}
		case <-wake:
		case <-t.C:
		}
	}
}

func (j *Janitor) reportErr(err error) {
	if j.opt.OnError != nil {
		j.opt.OnError(err)
	}
}
