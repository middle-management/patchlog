// Package janitor is the branch cleanup service of §F.6. It follows base
// namespaces, discovers their branches (recursively), and purges a branch
// (§8.5) only when all of these hold:
//
//   - it is frozen, and merged, superseded or abandoned, and the claim is
//     verified (below), never trusted;
//   - its cleanup period has passed since it was frozen: the branch
//     document's "cleanup": { "merged": ISO duration, "superseded": ISO
//     duration, "abandoned": ISO duration } for the verified claim,
//     measured from the created time of the config entry that froze it;
//   - so has the base's minimum, if the base declares one;
//   - it has no dependents that aren't purged (leaves are purged first).
//
// Base minimums use the same shape in the base's own namespace document:
// "cleanup": { "merged": "P7D", "superseded": "P30D" }. A branch starts as a
// copy of its base's document (§7.6), so the base's cleanup is also every
// new branch's default; the janitor applies the longer of the branch's
// period and the base's. A stacked branch's own cleanup is therefore also
// the minimum for its branches. A branch whose claim has no period in
// either document is never purged: cleanup is opt-in.
//
// Verification (§F.6):
//
//   - merged: the base's log has a batch without origin, by a principal
//     listed in the base's current merge.authors (root sub and kid, matched
//     as in merge.Listed), whose source.ns is the branch and whose
//     source.at is in the branch's chain, and the branch's log has no head,
//     tombstone or batch entry after that source.at. Config, prune and
//     propagated purge entries are allowed. A base without merge.authors
//     never verifies a merged claim this way.
//   - superseded: the successor exists, isn't purged, has the same base
//     namespace, and its log has a batch without origin whose source.ns is
//     the branch and whose source.at is in the branch's chain, with nothing
//     after it in the branch. §F.6 asks for no merge.authors check here:
//     the successor is a branch too, and its batches are the rebase.
//   - abandoned: the branch's document has "abandoned": true, set by a
//     config write whose recorded grant chains to a * key of the branch,
//     inherited or its own (§F.6): the entry's kid names a key with scope
//     "*" in the branch's document as of that write, or in a base's. With
//     authentication disabled entries carry no kid, and the claim is taken
//     as the development server's operator's.
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
	// FrozenAt and EligibleAt are set once the claim is verified.
	FrozenAt   time.Time `json:"frozenAt,omitzero"`
	EligibleAt time.Time `json:"eligibleAt,omitzero"`
	// Purge is the purge-ns entry's ns_id.
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
	if err != nil {
		return d, err
	}

	// Claims, verified. At E3 the branch's keyring is never merged, so
	// its entries don't count as document changes (§F.6, §F.8.1).
	enc, _ := doc.Value["encryption"].(map[string]any)
	e2e := enc["level"] == "e2e"
	var why []string
	if !hasDocEntries(log, -1, e2e) {
		d.Claim = "merged"
	}
	if d.Claim == "" {
		if _, ok := doc.Value["merged"]; ok {
			at, _ := bref["at"].(string)
			ok, reason, err := j.verifyMerged(ctx, base, at, ns, log, e2e)
			if err != nil {
				return d, err
			}
			if ok {
				d.Claim = "merged"
			} else {
				why = append(why, "merged claim not verified: "+reason)
			}
		}
	}
	if d.Claim == "" {
		if s, _ := doc.Value["successor"].(string); s != "" {
			ok, reason, err := j.verifySuperseded(ctx, base, ns, s, log, e2e)
			if err != nil {
				return d, err
			}
			if ok {
				d.Claim = "superseded"
			} else {
				why = append(why, "superseded claim not verified: "+reason)
			}
		}
	}
	if d.Claim == "" {
		if ab, _ := doc.Value["abandoned"].(bool); ab {
			ok, reason, err := j.verifyAbandoned(ctx, ns, log)
			if err != nil {
				return d, err
			}
			if ok {
				d.Claim = "abandoned"
			} else {
				why = append(why, "abandoned claim not verified: "+reason)
			}
		}
	}
	if d.Claim == "" {
		if len(why) == 0 {
			why = append(why, "frozen, but neither merged, superseded nor abandoned")
		}
		d.Reason = strings.Join(why, "; ")
		return d, nil
	}

	// Cleanup periods from the freeze.
	frozenAt, err := j.frozenSince(ctx, ns, log)
	if err != nil {
		return d, err
	}
	d.FrozenAt = frozenAt
	bh, err := j.c.NSHead(ctx, base)
	if err != nil {
		return d, err
	}
	bdoc, err := j.c.NSDoc(ctx, base, bh.ID)
	if err != nil {
		return d, err
	}
	periods := []string{}
	for _, v := range []map[string]any{doc.Value, bdoc.Value} {
		cl, _ := v["cleanup"].(map[string]any)
		if p, ok := cl[d.Claim].(string); ok {
			periods = append(periods, p)
		}
	}
	if len(periods) == 0 {
		d.Reason = fmt.Sprintf("%s, but no cleanup period for %q is declared", d.Claim, d.Claim)
		return d, nil
	}
	eligible := frozenAt
	for _, p := range periods {
		t, err := AddDuration(frozenAt, p)
		if err != nil {
			d.Reason = "invalid cleanup period: " + err.Error()
			return d, nil
		}
		if t.After(eligible) {
			eligible = t
		}
	}
	d.EligibleAt = eligible
	if now := j.opt.Now(); now.Before(eligible) {
		d.Reason = fmt.Sprintf("%s; cleanup period runs until %s", d.Claim, eligible.UTC().Format(time.RFC3339))
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
// document after it. If authors is non-nil, only batches by a principal
// listed in *authors count.
func coveredBy(entries []client.NSEntry, branch string, blog []client.NSEntry, authors *[]merge.Author, e2e bool) (bool, string) {
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
		if authors != nil && !merge.Listed(*authors, e.Author, e.Kid) {
			who := e.Author
			if e.Kid != "" {
				who += "/" + e.Kid
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

func (j *Janitor) verifyMerged(ctx context.Context, base, at, ns string, blog []client.NSEntry, e2e bool) (bool, string, error) {
	bh, err := j.c.NSHead(ctx, base)
	if err != nil {
		return false, "", err
	}
	entries, err := j.c.NSLog(ctx, base, bh.ID, at)
	if client.IsNotFound(err) && at != "" {
		entries, err = j.c.NSLog(ctx, base, bh.ID, "")
	}
	if err != nil {
		return false, "", err
	}
	bdoc, err := j.c.NSDoc(ctx, base, bh.ID)
	if err != nil {
		return false, "", err
	}
	authors, declared := merge.MergeAuthors(bdoc.Value)
	if !declared {
		return false, "the base " + base + " declares no merge.authors, so no merge batch can be trusted (§F.3)", nil
	}
	ok, why := coveredBy(entries, ns, blog, &authors, e2e)
	return ok, why, nil
}

func (j *Janitor) verifySuperseded(ctx context.Context, base, ns, succ string, blog []client.NSEntry, e2e bool) (bool, string, error) {
	sh, err := j.c.NSHead(ctx, succ)
	if client.IsNotFound(err) {
		return false, "successor " + succ + " doesn't exist", nil
	}
	if err != nil {
		return false, "", err
	}
	sdoc, err := j.c.NSDoc(ctx, succ, sh.ID)
	if err != nil {
		return false, "", err
	}
	sb, _ := sdoc.Value["base"].(map[string]any)
	if sns, _ := sb["ns"].(string); sns != base {
		return false, "successor " + succ + " has another base", nil
	}
	brs, err := j.c.Branches(ctx, base)
	if err != nil {
		return false, "", err
	}
	listed := false
	for _, b := range brs {
		if b.Name == succ {
			listed = true
			if b.Purged {
				return false, "successor " + succ + " is purged", nil
			}
		}
	}
	if !listed {
		return false, "successor " + succ + " is not a branch of " + base, nil
	}
	entries, err := j.c.NSLog(ctx, succ, sh.ID, "")
	if err != nil {
		return false, "", err
	}
	// §F.6 names no merge.authors check for the successor's batch.
	ok, why := coveredBy(entries, ns, blog, nil, e2e)
	return ok, why, nil
}

// verifyAbandoned checks an abandoned claim (§F.6): the config write that
// set "abandoned": true was made under a grant chained to a * key of the
// branch, inherited or its own. Only its administrators can give up
// everyone's unmerged work.
func (j *Janitor) verifyAbandoned(ctx context.Context, ns string, log []client.NSEntry) (bool, string, error) {
	var setter *client.NSEntry
	was := false
	for i := range log {
		e := log[i]
		isConfig := e.Kind == "config" || (e.Kind == "batch" && len(e.Entries) > 0 && e.Entries[0].Kind == "config")
		if !isConfig {
			continue
		}
		d, err := j.c.NSDoc(ctx, ns, e.ID)
		if err != nil {
			return false, "", err
		}
		ab, _ := d.Value["abandoned"].(bool)
		if ab && !was {
			setter = &log[i]
		}
		was = ab
	}
	if setter == nil {
		return false, "no config write set abandoned", nil
	}
	if setter.Kid == "" {
		return true, "", nil // authentication disabled: the operator's
	}
	d, err := j.c.NSDoc(ctx, ns, setter.ID)
	if err != nil {
		return false, "", err
	}
	docs := []map[string]any{d.Value}
	for cur, i := d.Value, 0; i < 64; i++ {
		bref, _ := cur["base"].(map[string]any)
		bns, _ := bref["ns"].(string)
		if bns == "" {
			break
		}
		bh, err := j.c.NSHead(ctx, bns)
		if err != nil {
			break // an unreadable base: its keys can't be checked
		}
		bd, err := j.c.NSDoc(ctx, bns, bh.ID)
		if err != nil {
			break
		}
		docs = append(docs, bd.Value)
		cur = bd.Value
	}
	for _, doc := range docs {
		keys, _ := doc["keys"].([]any)
		for _, k := range keys {
			km, _ := k.(map[string]any)
			if km["kid"] != setter.Kid {
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
	return false, fmt.Sprintf("the config write %s that set it was by %s under key %q, not a * key of the branch", setter.ID, setter.Author, setter.Kid), nil
}

// frozenSince returns the created time of the config entry that froze the
// branch: the oldest of the trailing config changes whose document is
// frozen.
func (j *Janitor) frozenSince(ctx context.Context, ns string, log []client.NSEntry) (time.Time, error) {
	var at string
	for i := len(log) - 1; i >= 0; i-- {
		e := log[i]
		isConfig := e.Kind == "config" || (e.Kind == "batch" && len(e.Entries) > 0 && e.Entries[0].Kind == "config")
		if !isConfig {
			continue
		}
		d, err := j.c.NSDoc(ctx, ns, e.ID)
		if err != nil {
			return time.Time{}, err
		}
		if f, _ := d.Value["frozen"].(bool); !f {
			break
		}
		at = e.Created
	}
	if at == "" {
		return time.Time{}, fmt.Errorf("janitor: %s: no freezing config entry", ns)
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, fmt.Errorf("janitor: %s: config entry created %q: %w", ns, at, err)
	}
	return t, nil
}

// Run follows the bases and their branches (follow.WithBranches) and sweeps
// whenever an entry arrives, and every Interval, until ctx is done.
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
		cp.Save(b.Origin, b.NS, b.NewCheckpoint)
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
			return fmt.Errorf("janitor: follower stopped: %w", err)
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
