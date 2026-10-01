package merge

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
)

// RebaseOptions configure Rebase (§F.5).
type RebaseOptions struct {
	// Branch is the branch to bring up to date.
	Branch string
	// New is the successor branch's name. If it already exists with the
	// same base, Rebase resumes into it.
	New string
	// Onto is the namespace the successor is created from; default the
	// branch's own base. Retargeting a stacked branch onto its base's base
	// after a fast-forward merge (§F.4) sets it; such a successor has a
	// different base, so it can't be switched to.
	Onto string
	// Switch freezes the old branch with successor: New once the first
	// replay is clean and applied, then replays what the old branch got
	// meanwhile.
	Switch bool
	// CopyConfig lists top-level keys of the old branch's namespace document
	// copied into the successor when it is created. Default: "read" and
	// "cleanup", so a private draft stays private and keeps its cleanup
	// policy (the successor otherwise starts as a copy of Onto's document).
	CopyConfig []string
	// Patches are further changes to the successor's namespace document
	// in its creation request, after CopyConfig's: e.g. the drafts.for of a
	// release's schema successor naming the other successors (§F.9).
	Patches []any
	// Prepare, if set, is called with each replay plan (the first and the
	// catch-up) before it is checked and applied, e.g. to resolve
	// resources by squashing them (§F.9 Rebasing).
	Prepare func(ctx context.Context, p *Plan) error
	// Plan options for the replays (Squash is ignored: a rebase keeps ids).
	// An e2e branch needs Plan.E2E.
	Plan Options
}

// RebaseResult reports what Rebase did.
type RebaseResult struct {
	New     string `json:"new"`
	Created bool   `json:"created"`
	// First is the replay of the branch into the successor; FirstResult is
	// nil if it was not applied (conflicts).
	First       *Plan   `json:"first"`
	FirstResult *Result `json:"firstResult,omitempty"`
	Switched    bool    `json:"switched"`
	// CatchUp replays what the old branch received between the first
	// replay and the switch.
	CatchUp       *Plan   `json:"catchUp,omitempty"`
	CatchUpResult *Result `json:"catchUpResult,omitempty"`
}

// Rebase creates a successor of a branch from its base's current head and
// replays the branch's changes into it, classified by ancestry as in §F.3:
// resources the base didn't change fast-forward and keep their ids. With
// Switch, the old branch is then frozen with successor: New, and anything
// it received after the first replay is replayed too.
//
// On conflicts it stops before switching and returns the plan with
// ErrConflicts; the successor exists and nobody uses it yet, so a person can
// resolve (Plan.Resolve, Plan.Apply) and run Rebase again, which resumes.
//
// An e2e branch (§F.8) needs Plan.E2E. The successor gets its own keyring
// first (successorKeyring), and the replays re-encrypt under it, so no id
// is kept. Every merge batch of the branch in the successor counts as a
// merge point, merge.authors or not (they are the rebase, as the janitor's
// superseded check assumes, §F.6), so a resumed rebase and the catch-up
// replay exactly what is new.
func Rebase(ctx context.Context, c *client.Client, opt RebaseOptions) (*RebaseResult, error) {
	opt.Plan.Squash = false
	if opt.Branch == "" || opt.New == "" {
		return nil, errors.New("merge: rebase needs a branch and a successor name")
	}
	bh, err := c.NSHead(ctx, opt.Branch)
	if err != nil {
		return nil, err
	}
	bdoc, err := c.NSDoc(ctx, opt.Branch, bh.ID)
	if err != nil {
		return nil, err
	}
	base, _ := bdoc.Value["base"].(map[string]any)
	baseNS, _ := base["ns"].(string)
	if baseNS == "" {
		return nil, fmt.Errorf("merge: %s is not a branch", opt.Branch)
	}
	if frozen, _ := bdoc.Value["frozen"].(bool); frozen {
		if s, _ := bdoc.Value["successor"].(string); s != "" && s != opt.New {
			return nil, fmt.Errorf("merge: %s is frozen with successor %s", opt.Branch, s)
		}
	}
	onto := opt.Onto
	if onto == "" {
		onto = baseNS
	}
	if opt.Switch && onto != baseNS {
		return nil, fmt.Errorf("merge: can't switch %s to a successor based on %s: a successor must have the same base (%s)", opt.Branch, onto, baseNS)
	}
	lv, err := c.EncryptionLevel(ctx, opt.Branch)
	if err != nil {
		return nil, err
	}
	e2e := lv == "e2e"
	if e2e && opt.Plan.E2E == nil {
		return nil, fmt.Errorf("merge: %s is an e2e namespace: rebasing it re-encrypts its changes under the successor's keys (§F.8) and needs a key-holding view (Plan.E2E)", opt.Branch)
	}
	keys := opt.CopyConfig
	if keys == nil {
		keys = []string{"read", "cleanup"}
	}
	var patches []any
	for _, k := range keys {
		switch k {
		case "base", "frozen", "successor", "merged":
			continue
		}
		if v, ok := bdoc.Value[k]; ok {
			patches = append(patches, map[string]any{"op": "add", "path": "/" + k, "value": v})
		}
	}
	patches = append(patches, opt.Patches...)
	out := &RebaseResult{New: opt.New}
	br := client.BranchRequest{Name: opt.New}
	if len(patches) > 0 {
		br.Patches = patches
	}
	res, err := c.CreateBranch(ctx, onto, br)
	switch {
	case err == nil:
		out.Created = res.Status == 201
	case client.IsStale(err):
		// Taken: resume if it is a successor-to-be of the same base.
		nh, err2 := c.NSHead(ctx, opt.New)
		if err2 != nil {
			return nil, fmt.Errorf("merge: %s exists: %w", opt.New, err)
		}
		nd, err2 := c.NSDoc(ctx, opt.New, nh.ID)
		if err2 != nil {
			return nil, err2
		}
		nb, _ := nd.Value["base"].(map[string]any)
		if ns, _ := nb["ns"].(string); ns != onto {
			return nil, fmt.Errorf("merge: %s exists and is not a branch of %s", opt.New, onto)
		}
	default:
		return nil, err
	}
	if e2e {
		if err := successorKeyring(ctx, opt.Plan.E2E, opt.Branch, onto, opt.New); err != nil {
			return out, err
		}
	}

	// The successor's merge batches of the branch are this rebase's own
	// replays (a resumed run's too): they count as merge points.
	opt.Plan.successor = true
	first, err := NewPlan(ctx, c, opt.New, opt.Branch, opt.Plan)
	if err != nil {
		return out, err
	}
	out.First = first
	if opt.Prepare != nil {
		if err := opt.Prepare(ctx, first); err != nil {
			return out, err
		}
	}
	if !first.Clean() {
		return out, ErrConflicts
	}
	if out.FirstResult, err = first.Apply(ctx); err != nil {
		return out, err
	}
	if !opt.Switch {
		return out, nil
	}
	if _, err := configWrite(ctx, c, opt.Branch, []any{
		map[string]any{"op": "add", "path": "/frozen", "value": true},
		map[string]any{"op": "add", "path": "/successor", "value": opt.New},
	}); err != nil {
		return out, fmt.Errorf("merge: switch: %w", err)
	}
	out.Switched = true
	after, err := c.NSHead(ctx, opt.Branch)
	if err != nil {
		return out, err
	}
	if after.ID == first.BranchAt {
		return out, nil
	}
	// Only document changes need a catch-up; the switch itself is a config
	// entry.
	newer, err := c.NSLog(ctx, opt.Branch, after.ID, first.BranchAt)
	if err != nil {
		return out, err
	}
	if len(Collect(newer)) == 0 {
		return out, nil
	}
	catch, err := NewPlan(ctx, c, opt.New, opt.Branch, opt.Plan)
	if err != nil {
		return out, err
	}
	out.CatchUp = catch
	if opt.Prepare != nil {
		if err := opt.Prepare(ctx, catch); err != nil {
			return out, err
		}
	}
	if !catch.Clean() {
		return out, ErrConflicts
	}
	out.CatchUpResult, err = catch.Apply(ctx)
	return out, err
}

// successorKeyring gives an e2e successor its own keyring (§F.8): its
// sealed patch sets bind it, so it can't write under the keyring it reads
// through from its base. The key is wrapped for the readers of the old
// branch's current epoch (its own keyring's, or the one it reads through)
// and for the view itself. A successor that has one already (a resumed
// rebase) is left as it is.
func successorKeyring(ctx context.Context, x *client.E2E, branch, onto, succ string) error {
	if kr, _, err := x.Keyring(ctx, succ); err == nil && kr.NS == succ {
		return nil
	} else if err != nil && !client.IsNotFound(err) {
		return err
	}
	kr, _, err := x.Keyring(ctx, branch)
	if client.IsNotFound(err) {
		kr, _, err = x.Keyring(ctx, onto)
	}
	if err != nil {
		return fmt.Errorf("merge: reading the keyring of %s: %w", branch, err)
	}
	var readers []*ecdh.PublicKey
	for _, rid := range kr.Readers(kr.Current) {
		if pub := kr.Recipients[rid]; pub != nil {
			readers = append(readers, pub)
		}
	}
	if _, err := x.InitKeyring(ctx, succ, readers...); err != nil {
		return fmt.Errorf("merge: keyring of %s: %w", succ, err)
	}
	return nil
}

// ResourceStatus is one line of Status.
type ResourceStatus struct {
	Resource  string     `json:"resource"`
	Status    string     `json:"status"`
	Class     Class      `json:"class"`
	Base      string     `json:"base,omitempty"`
	Branch    string     `json:"branch,omitempty"`
	Conflicts []Conflict `json:"conflicts,omitempty"`
	Note      string     `json:"note,omitempty"`
	// Pair is where the resource's common-ancestor pair came from: the
	// merge batch, its author and kid (§F.3).
	Pair *Pair `json:"pair,omitempty"`
}

// Status is the §F.7 status of every resource the branch changed, against
// target: ahead, behind, clean, conflicting, merged or purged.
func Status(ctx context.Context, c *client.Client, target, branch string) ([]ResourceStatus, error) {
	p, err := NewPlan(ctx, c, target, branch, Options{})
	if err != nil {
		return nil, err
	}
	return p.Status(), nil
}

// Status summarises the plan per resource.
func (p *Plan) Status() []ResourceStatus {
	out := make([]ResourceStatus, 0, len(p.Resources))
	for _, r := range p.Resources {
		out = append(out, ResourceStatus{Resource: r.Name, Status: r.Status(), Class: r.Class, Base: r.Base, Branch: r.Branch, Conflicts: r.Conflicts, Note: r.Note, Pair: r.Pair})
	}
	return out
}
