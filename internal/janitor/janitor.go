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
//   - superseded: the successor exists, isn't purged, has the same base
//     namespace, and its log has a batch without origin whose source.ns is
//     the branch and whose source.at is in the branch's chain, with nothing
//     after it in the branch. §F.6 asks for no merge.authors check here:
//     the successor is a branch too, and its batches are the rebase.
//   - abandoned: the branch's document has "abandoned": true, set by a
//     config write whose recorded grant chains to a * key of the branch,
//     inherited or its own (§F.6): the root kid of the entry's grant (§7.4)
//     names a key with scope "*" in the branch's document as of that
//     write, or in a base's. An entry written while authentication was
//     disabled records "grant": null (§1): it counts while the deployment
//     still runs disabled, as GET / says ("auth": "disabled"), since every
//     request then counts as holding a * key, and for no one under
//     "grants". An entry without "grant" at all (the server's own, or one
//     from before v0.37) counts for no one.
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
	"reflect"
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
		docs: map[string]nsAt{ns: {head.ID, doc.Value}}}
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
		ok, reason, err = b.verifySuperseded(ctx, s)
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

// coveredBy finds the latest merge batch of branch in entries whose
// source.at is in the branch's chain, and checks that the branch changed no
// document after it. If authors is non-nil, only batches whose recorded
// grant has a root sub and kid listed in *authors count (merge.EntryListed),
// and those with "grant": null on their author alone while disabled: the
// deployment says, at GET /, it runs with authentication disabled (§1).
func coveredBy(entries []client.NSEntry, branch string, blog []client.NSEntry, authors *[]merge.Author, e2e, disabled bool) (bool, string) {
	pos := map[string]int{}
	for i, e := range blog {
		pos[e.ID] = i
	}
	best, found := -1, false
	forged, untrusted := 0, []string{}
	for _, e := range entries {
		if !merge.IsMergeOf(e, branch) {
			continue
		}
		if authors != nil && !merge.EntryListed(*authors, e, disabled) {
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
		found = true
		if i > best {
			best = i
		}
	}
	if !found {
		if len(untrusted) > 0 {
			return false, "no merge batch is by a principal in the base's merge.authors (" + strings.Join(untrusted, ", ") + ")"
		}
		if forged > 0 {
			return false, "its batches' source.at is not in the branch's chain"
		}
		return false, "no batch without origin has source.ns = " + branch
	}
	if hasDocEntries(blog, best, e2e) {
		return false, "the branch changed documents after " + blog[best].ID
	}
	return true, ""
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
	ok, why := coveredBy(entries, b.ns, b.log, &authors, b.e2e, disabled)
	return ok, why, nil
}

func (b *branch) verifySuperseded(ctx context.Context, succ string) (bool, string, error) {
	base, ns := b.base, b.ns
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
		return false, "successor " + succ + " is purged", nil
	}
	if err != nil {
		return false, "", err
	}
	sb, _ := sdoc.Value["base"].(map[string]any)
	if sns, _ := sb["ns"].(string); sns != base {
		return false, "successor " + succ + " has another base", nil
	}
	brs, err := b.j.c.Branches(ctx, base)
	if err != nil {
		return false, "", err
	}
	listed := false
	for _, br := range brs {
		if br.Name == succ {
			listed = true
			if br.Purged {
				return false, "successor " + succ + " is purged", nil
			}
		}
	}
	if !listed {
		return false, "successor " + succ + " is not a branch of " + base, nil
	}
	entries, err := b.j.c.NSLog(ctx, succ, sh.ID, "")
	if err != nil {
		return false, "", err
	}
	// §F.6 names no merge.authors check for the successor's batch.
	ok, why := coveredBy(entries, ns, b.log, nil, b.e2e, false)
	return ok, why, nil
}

// verifyAbandoned checks an abandoned claim (§F.6): the config write that
// set "abandoned": true was made under a grant chained to a * key of the
// branch, inherited or its own. Only its administrators can give up
// everyone's unmerged work.
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
	docs := []map[string]any{setter.doc}
	for cur, i := setter.doc, 0; i < 64; i++ {
		bref, _ := cur["base"].(map[string]any)
		bns, _ := bref["ns"].(string)
		if bns == "" {
			break
		}
		bd, err := b.current(ctx, bns)
		if err != nil {
			break // an unreadable base: its keys can't be checked
		}
		docs = append(docs, bd)
		cur = bd
	}
	for _, doc := range docs {
		keys, _ := doc["keys"].([]any)
		for _, k := range keys {
			km, _ := k.(map[string]any)
			if km["kid"] != e.Grant.Kid {
				continue
			}
			can, _ := km["can"].([]any)
			for _, c := range can {
				if c == "*" {
					return true, "", nil
				}
			}
		}
	}
	return false, fmt.Sprintf("the config write %s that set it was by %s under key %q, not a * key of the branch", e.ID, e.Grant.Sub, e.Grant.Kid), nil
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
