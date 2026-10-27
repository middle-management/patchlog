package merge

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
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
	// after a fast-forward merge (§F.4) sets it. Switch needs Onto in the
	// branch's base chain, since only a branch of a namespace up that chain
	// may be its successor (§7.4).
	Onto string
	// Switch freezes the old branch with successor: New once the first
	// replay is clean and applied, then replays what the old branch got
	// meanwhile.
	Switch bool
	// CopyConfig lists top-level keys of the old branch's namespace document
	// copied into the successor when it is created. Default: "read" and
	// "cleanup", so a private draft stays private and keeps its cleanup
	// policy (the successor otherwise starts as a copy of Onto's document).
	// read is set whatever CopyConfig says: the old branch's, or "grant"
	// where that would rank the successor below the old branch (§F.5).
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
	// SuccessorReaders are the public keys an e2e successor's keyring
	// wraps its key for (§F.8.1, §E.3.2), besides Plan.E2E's own
	// recipient key and the readers of the old branch's newest epoch
	// whose keys the view knows (client.E2E.KeyringReaders). A keyring
	// names its readers by thumbprint only, so a reader whose key the
	// view doesn't otherwise know is named here, not as a sender
	// (WithSenders): senders are the admins the view trusts to distribute
	// keys.
	SuccessorReaders []*ecdh.PublicKey
}

// ErrReadersDropped reports that an e2e successor's keyring holds no key
// for some readers of the old branch's newest epoch (RebaseResult.
// DroppedReaders), so switching would end their access: Rebase stops
// before replaying. Wrap the successor's key for them (client.E2E.
// AddReader) and run Rebase again, which resumes, or revoke them in the
// old branch first by rotating its epoch (§E.3.2).
var ErrReadersDropped = errors.New("merge: the successor's keyring drops readers of the old branch")

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
	// DroppedReaders lists, at E3, the thumbprints of the readers of the
	// old branch's newest epoch, in its own keyring, that the successor's
	// keyring holds no key for (ErrReadersDropped).
	DroppedReaders []string `json:"droppedReaders,omitempty"`
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
// is kept. With Switch, a successor whose keyring would drop readers of
// the old branch gets no replay (ErrReadersDropped). Every merge batch of the branch in the successor counts as a
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
		// A successor is a branch of the same base, or of a namespace
		// further up the old branch's base chain (§7.4, §F.5).
		chain, err := baseChain(ctx, c, baseNS)
		if err != nil {
			return nil, err
		}
		if !slicesContains(chain, onto) {
			return nil, fmt.Errorf("merge: can't switch %s to a successor based on %s: a successor must be a branch of a namespace in its base chain (%s)", opt.Branch, onto, strings.Join(chain, " → "))
		}
	}
	lv, err := c.EncryptionLevel(ctx, opt.Branch)
	if err != nil {
		return nil, err
	}
	e2e := lv == "e2e"
	if e2e && opt.Plan.E2E == nil {
		return nil, fmt.Errorf("merge: %s is an e2e namespace: rebasing it re-encrypts its changes under the successor's keys (§F.8) and needs a key-holding view (Plan.E2E)", opt.Branch)
	}
	old := docProtection(bdoc.Value)
	if lv != "" {
		old.level = lv // as served: "sealed" for a JWE document
	}
	keys := opt.CopyConfig
	if keys == nil {
		keys = []string{"read", "cleanup"}
	}
	var patches []any
	for _, k := range keys {
		switch k {
		case "base", "frozen", "successor", "merged", "read":
			continue
		}
		if v, ok := bdoc.Value[k]; ok {
			patches = append(patches, map[string]any{"op": "add", "path": "/" + k, "value": v})
		}
	}
	// The successor gets the old branch's read, or "grant" where that would
	// rank it below the old branch (§F.5, §2.1), as for a sealed branch
	// whose read is public. It starts as a copy of Onto's document, so its
	// level is Onto's.
	read, err := successorRead(ctx, c, old, onto)
	if err != nil {
		return nil, err
	}
	if _, had := bdoc.Value["read"]; had || read != old.read || !ontoReads(ctx, c, onto, read) {
		patches = append(patches, map[string]any{"op": "add", "path": "/read", "value": read})
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
		dropped, err := successorKeyring(ctx, opt.Plan.E2E, opt.Branch, onto, opt.New, opt.SuccessorReaders)
		if err != nil {
			return out, err
		}
		out.DroppedReaders = dropped
		if len(dropped) > 0 && opt.Switch {
			return out, fmt.Errorf("%w: %s holds no key of %s for %s; wrap it for them (AddReader) and rebase again, or revoke them in %s first by rotating its epoch",
				ErrReadersDropped, opt.New, opt.New, strings.Join(dropped, ", "), opt.Branch)
		}
	}

	// Created or resumed, a successor that ranks below the old branch gets
	// no replay (§F.5).
	succ, err := nsProtection(ctx, c, opt.New)
	if err != nil {
		return out, err
	}
	if err := checkSuccessorRank(old, succ, opt.Branch, opt.New); err != nil {
		return out, err
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

// baseChain lists ns and the namespaces up its base chain, nearest first
// (local bases only: a remote base ends it).
func baseChain(ctx context.Context, c *client.Client, ns string) ([]string, error) {
	chain := []string{ns}
	for i := 0; i < 64; i++ {
		h, err := c.NSHead(ctx, ns)
		if err != nil {
			return nil, err
		}
		d, err := c.NSDoc(ctx, ns, h.ID)
		if err != nil {
			return nil, err
		}
		b, _ := d.Value["base"].(map[string]any)
		next, _ := b["ns"].(string)
		if _, remote := b["remote"]; next == "" || remote || slicesContains(chain, next) {
			break
		}
		chain = append(chain, next)
		ns = next
	}
	return chain, nil
}

// successorRead is the read a successor created from onto gets (§F.5): the
// old branch's, or "grant" where, at onto's level, that would rank it below
// the old branch as a source.
func successorRead(ctx context.Context, c *client.Client, old protection, onto string) (string, error) {
	lv, err := c.EncryptionLevel(ctx, onto)
	if err != nil {
		return "", err
	}
	sr, _ := old.source()
	if tr, _ := (protection{level: lv, read: old.read}).target(); tr < sr {
		return "grant", nil
	}
	return old.read, nil
}

// ontoReads reports whether onto's current document already has read, so
// a successor copying it needs no read patch. An unreadable document
// doesn't.
func ontoReads(ctx context.Context, c *client.Client, onto, read string) bool {
	p, err := nsProtection(ctx, c, onto)
	return err == nil && p.read == read
}

// successorKeyring gives an e2e successor its own keyring (§F.8.1): its
// sealed patch sets bind it, so it can't write under the keyring it reads
// through from its base. The key is wrapped for the view itself, for
// readers, and for the readers of the old branch's newest epoch (its own
// keyring's, or the one it reads through) whose keys the view knows, each
// holding an entry from a sender it knows (client.E2E.KeyringReaders,
// §E.3.2). A successor that has one already (a resumed rebase) keeps it,
// its keys wrapped for those of readers it lacks (client.E2E.AddReader).
//
// It returns the thumbprints of the readers of the old branch's newest
// epoch in its own keyring that the successor's keyring holds no key for,
// from whichever sender: a reader the old branch's keys reach, and the
// successor's don't, would lose access by the switch. A branch without a
// keyring of its own has no writes of its own to lose.
//
// A keyring stored in the format before v0.63 that a namespace reads
// through from its base counts as none; one of the branch's or the
// successor's own is wrapped again first (client.E2E.MigrateKeyring).
func successorKeyring(ctx context.Context, x *client.E2E, branch, onto, succ string, readers []*ecdh.PublicKey) ([]string, error) {
	have, own, err := keyringAs(ctx, x, succ)
	if err != nil {
		return nil, err
	}
	kr, branchOwn, err := keyringAs(ctx, x, branch)
	if err == nil && kr == nil {
		kr, _, err = keyringAs(ctx, x, onto)
	}
	if err != nil {
		return nil, fmt.Errorf("merge: reading the keyring of %s: %w", branch, err)
	}
	held := map[string]bool{} // the successor's newest epoch's readers
	if own {
		for _, tp := range have.Recipients(seal.Kid(succ, have.Current(succ))) {
			held[tp] = true
		}
		// A resumed rebase wraps the successor's keys for readers named
		// since.
		for _, r := range readers {
			if tp := seal.Thumbprint(r); !held[tp] {
				if _, err := x.AddReader(ctx, succ, r, true); err != nil {
					return nil, fmt.Errorf("merge: adding a reader to the keyring of %s: %w", succ, err)
				}
				held[tp] = true
			}
		}
	} else {
		if kr != nil {
			readers = append(readers[:len(readers):len(readers)], x.KeyringReaders(kr)...)
		}
		if _, err := x.InitKeyring(ctx, succ, readers...); err != nil {
			return nil, fmt.Errorf("merge: keyring of %s: %w", succ, err)
		}
		// InitKeyring wraps for readers and the view's own key.
		if pub := x.PublicKey(); pub != nil {
			held[seal.Thumbprint(pub)] = true
		}
		for _, r := range readers {
			held[seal.Thumbprint(r)] = true
		}
	}
	if !branchOwn {
		return nil, nil
	}
	var dropped []string
	for _, tp := range kr.Recipients(seal.Kid(branch, kr.Current(branch))) {
		if !held[tp] {
			dropped = append(dropped, tp)
		}
	}
	return dropped, nil
}

// keyringAs reads the keyring of ns as ns sees it (client.E2E.Keyring),
// reporting whether it is ns's own, nil if ns has none, or reads through
// one stored in the format before v0.63. One of ns's own in that format is
// an error naming ns, to be wrapped again first.
func keyringAs(ctx context.Context, x *client.E2E, ns string) (*seal.KeyringV2, bool, error) {
	kr, _, err := x.Keyring(ctx, ns)
	switch {
	case err == nil:
		return kr, kr.Current(ns) > 0, nil
	case client.IsNotFound(err):
		return nil, false, nil
	case errors.Is(err, client.ErrLegacyKeyring):
		old, _, err := x.LegacyKeyring(ctx, ns)
		if err != nil {
			return nil, false, err
		}
		if old.NS == ns {
			return nil, false, fmt.Errorf("merge: the keyring of %s is in the format before v0.63: a key holder wraps it again first (patchlog e2e migrate-keyring -ns %s)", ns, ns)
		}
		return nil, false, nil
	}
	return nil, false, err
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
