// Package janitor is the branch cleanup service of §F.6. It follows base
// namespaces, discovers their branches (recursively), and purges a branch
// (§8.5) only when all of these hold:
//
//   - it is frozen, and merged or superseded, and the claim is verified
//     (below), never trusted;
//   - its cleanup period has passed since it was frozen: the branch
//     document's "cleanup": { "merged": ISO duration, "superseded": ISO
//     duration } for the verified claim, measured from the created time of
//     the config entry that froze it;
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
//   - a branch with no head, tombstone or batch entry of its own counts as
//     merged.
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
}

// Actions of a decision.
const (
	ActionPurged     = "purged"
	ActionWouldPurge = "would-purge" // dry run
	ActionKeep       = "keep"
)

// Decision is the janitor's verdict on one branch.
type Decision struct {
	NS     string `json:"ns"`
	Base   string `json:"base"`
	Action string `json:"action"`
	// Claim is the verified claim ("merged" or "superseded"), if any.
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
func (j *Janitor) Sweep(ctx context.Context) ([]Decision, error) {
	var out []Decision
	var errs []error
	for _, b := range j.opt.Bases {
		ds, err := j.walk(ctx, b)
		out = append(out, ds...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

// walk handles ns's branches, each after its own branches.
func (j *Janitor) walk(ctx context.Context, ns string) ([]Decision, error) {
	brs, err := j.c.Branches(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("janitor: branches of %s: %w", ns, err)
	}
	var out []Decision
	var errs []error
	for _, b := range brs {
		if b.Name == "" || b.Purged || b.Remote != nil {
			continue
		}
		ds, err := j.walk(ctx, b.Name)
		out = append(out, ds...)
		if err != nil {
			errs = append(errs, err)
		}
		d, err := j.Check(ctx, ns, b.Name)
		if err != nil {
			errs = append(errs, fmt.Errorf("janitor: %s: %w", b.Name, err))
			continue
		}
		out = append(out, d)
	}
	return out, errors.Join(errs...)
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

	// Claims, verified.
	var why []string
	if !hasDocEntries(log, -1) {
		d.Claim = "merged"
	}
	if d.Claim == "" {
		if _, ok := doc.Value["merged"]; ok {
			at, _ := bref["at"].(string)
			ok, reason, err := j.verifyMerged(ctx, base, at, ns, log)
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
			ok, reason, err := j.verifySuperseded(ctx, base, ns, s, log)
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
		if len(why) == 0 {
			why = append(why, "frozen, but neither merged nor superseded")
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
// documents. Config, prune and (propagated) purge entries don't count.
func isDocEntry(e client.NSEntry) bool {
	switch e.Kind {
	case "head", "tombstone", "batch":
		return true
	}
	return false
}

// hasDocEntries reports a document entry in log after index i.
func hasDocEntries(log []client.NSEntry, i int) bool {
	for _, e := range log[i+1:] {
		if isDocEntry(e) {
			return true
		}
	}
	return false
}

// coveredBy finds the latest merge batch of branch in entries whose
// source.at is in the branch's chain, and checks that the branch changed no
// document after it. If authors is non-nil, only batches by a principal
// listed in *authors count.
func coveredBy(entries []client.NSEntry, branch string, blog []client.NSEntry, authors *[]merge.Author) (bool, string) {
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
	if hasDocEntries(blog, best) {
		return false, "the branch changed documents after " + blog[best].ID
	}
	return true, ""
}

func (j *Janitor) verifyMerged(ctx context.Context, base, at, ns string, blog []client.NSEntry) (bool, string, error) {
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
	ok, why := coveredBy(entries, ns, blog, &authors)
	return ok, why, nil
}

func (j *Janitor) verifySuperseded(ctx context.Context, base, ns, succ string, blog []client.NSEntry) (bool, string, error) {
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
	ok, why := coveredBy(entries, ns, blog, nil)
	return ok, why, nil
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
