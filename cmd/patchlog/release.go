package main

// Releases across namespaces (§F.9):
//
//	patchlog merge release plan|approve|apply|status|rebase|abandon --api URL [flags] /r/{ns}/{release}
//
// plan classifies the release and reports its conflicts, and stores the
// plan (as {release}.merge in --state-ns, default the release document's
// namespace) unless --dry-run. approve, run by the approving person, plans
// again, requires it clean and for the same release revision, and freezes
// every listed branch. apply merges in the four steps (schemas by
// fast-forward, catalog changes that narrow access, content, catalog
// changes that widen it), each classified again with a dry run right
// before it is submitted, and resumes a merge that stopped. status shows
// the stored plan and the catalog bases' merge locks, which live in the
// release document's namespace: { holder, plan } while held, {} while
// free (§F.9). A lock another plan holds, or one an earlier version wrote
// ({ "release" }), is released by a person: append {} to it. The one
// exception is a merge an earlier version stopped part-way: apply resumes
// it from its stored plan, taking over the lock that version took for it.
// rebase creates a successor of every branch (§F.5) and writes a new
// revision of the release document listing them. abandon freezes every
// branch with abandoned: true (needs a * key, §F.6).
//
// Catalog batches (§F.8): --merge-bearer is the merge service's own grant
// for the catalog (merge grants are issued only to it); --bearer, the
// person's, is the approver whose powers the catalog service checks, and
// for a batch that changes $access the catalog admin's grant it is
// submitted under, narrowed with the merge service's via. Without
// --merge-bearer, --bearer is sent for both.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
)

// releaseCmd is patchlog merge release.
type releaseCmd struct {
	Plan    *releaseVerbCmd `arg:"subcommand:plan" help:"classify the release, report its conflicts and store the plan"`
	Approve *releaseVerbCmd `arg:"subcommand:approve" help:"plan again, require it clean and unchanged (--digest), and freeze every branch"`
	Apply   *releaseVerbCmd `arg:"subcommand:apply" help:"merge the release in its four steps, or resume a merge that stopped"`
	Status  *releaseVerbCmd `arg:"subcommand:status" help:"show the stored plan and the catalog bases' merge locks"`
	Rebase  *releaseVerbCmd `arg:"subcommand:rebase" help:"create a successor of every branch and a new release document revision listing them (needs --suffix)"`
	Abandon *releaseVerbCmd `arg:"subcommand:abandon" help:"freeze every branch with abandoned: true (needs a * key, §F.6)"`
}

// releaseVerbCmd is one of patchlog merge release's subcommands.
type releaseVerbCmd struct {
	toolArgs
	StateNS         string   `arg:"--state-ns" placeholder:"NS" help:"namespace of the stored plan (default: the release document's); the catalog bases' merge locks are always in the release document's namespace (§F.9)"`
	DryRun          bool     `arg:"--dry-run" help:"plan: report only, store nothing"`
	Suffix          string   `arg:"--suffix" help:"rebase: successor names are each branch's name plus this suffix"`
	At              string   `arg:"--at" placeholder:"ID" help:"rebase: the new release document's combined checkpoint (§B.5), if known"`
	LeaveOut        bool     `arg:"--leave-out" help:"rebase: each branch's switch, although the replay leaves resources the old branch changed unrecorded in the successor (left out of an item, purged in the successor only), giving them up (§F.5): their changes stay only in the frozen old branch"`
	Digest          string   `arg:"--digest" placeholder:"D" help:"approve: the plan digest you reviewed (plan prints it); approval fails unless planning again gives it (§F.9)"`
	MergeBearer     string   `arg:"--merge-bearer" placeholder:"GRANT" help:"the merge service's own grant for catalogs, sent to catalog services as Authorization (§F.8); its root sub is the via of narrowed admin grants"`
	Identity        []string `arg:"--identity,separate" placeholder:"KEY.JWK" help:"rebase: file with an X25519 private key (a private JWK {kty, crv, x, d}, or base64url d) for e2e namespaces (Addendum E.3): the key the keyrings (and --bearer's enc) name, to read the branch and re-encrypt for the target (§F.8); repeatable when they name different keys"`
	Reader          []string `arg:"--reader,separate" placeholder:"PUB.JWK" help:"rebase, e2e: file with the X25519 public key (a JWK {kty, crv, x}, or base64url x) of a reader each successor's keyring wraps its key for, besides those of the old branch's readers the identities know (repeatable, §F.8.1)"`
	CatalogService  []string `arg:"--catalog-service,separate" placeholder:"CAT=URL" help:"the catalog service that signs merge grants for catalog base CAT (§F.8); repeatable"`
	Split           []string `arg:"--split,separate" placeholder:"KEY/NODE=NARROW.json" help:"a catalog node that narrows and widens, merged in two halves; the file is its document after the narrowing step (§F.9); repeatable"`
	AcceptPlacement []string `arg:"--accept-placement,separate" placeholder:"NS.NAME" help:"accept that step 3 publishes an item under this existing placement (§F.9); repeatable"`
	Resolve         []string `arg:"--resolve,separate" placeholder:"KEY/NAME=FILE.json" help:"resolution of a content resource's conflict, against its base's head (§F.3); repeatable"`
	SourceGrant     []string `arg:"--source-grant,separate" placeholder:"GRANT" help:"a grant sent as Source-Authorization with every batch (reads a branch: blobs, drafts; §7.8, §6.1); repeatable"`
	Release         string   `arg:"positional,required" placeholder:"/r/{ns}/{release}" help:"the release document"`
}

func (a *releaseVerbCmd) run(sub string) {
	tf := &a.toolArgs
	link := a.Release
	if _, err := release.ParseRef(link); err != nil {
		toolFatal(err)
	}
	ctx := context.Background()
	c := tf.client()

	if sub == "rebase" {
		if a.Suffix == "" {
			fmt.Fprintln(os.Stderr, "merge release rebase: --suffix is required")
			os.Exit(2)
		}
		succReaders, err := readPublicKeys(a.Reader)
		if err != nil {
			toolFatal(err)
		}
		res, err := merge.RebaseRelease(ctx, c, merge.RebaseReleaseOptions{Release: link, Suffix: a.Suffix, At: a.At, LeaveOut: a.LeaveOut, SuccessorReaders: succReaders,
			Plan: merge.Options{E2E: e2eView(c, a.Identity), Signer: tf.signer()}})
		if tf.JSON {
			out := map[string]any{"result": res}
			if err != nil {
				out["error"] = err.Error()
			}
			printJSON(out)
		} else if res != nil {
			for _, br := range res.Order {
				for k, r := range res.Rebases {
					if r != nil && r.First != nil && r.First.Branch == br {
						fmt.Printf("%s → %s (%s)\n", br, r.New, k)
						if !r.First.Clean() {
							printPlan(r.First)
						}
						printLeftOut(r, br)
					}
				}
			}
			for old, nw := range res.Drafts {
				fmt.Printf("draft %s moved to %s\n", old, nw)
			}
			for k, names := range res.Squashed {
				fmt.Printf("squashed in %s (they referenced replayed drafts): %s\n", k, strings.Join(names, ", "))
			}
			if res.Revision != "" {
				fmt.Printf("release document %s is at %s, listing the successors\n", link, res.Revision)
			}
		}
		if errors.Is(err, merge.ErrReadersDropped) {
			fmt.Fprintf(os.Stderr, "error: %v\nname their public keys with --reader and run rebase again\n", err)
			os.Exit(1)
		}
		if errors.Is(err, merge.ErrConflicts) {
			fmt.Fprintln(os.Stderr, "stopped on conflicts: resolve them with `patchlog merge apply --base SUCCESSOR --branch OLD --resolve …`, then run rebase again")
			os.Exit(1)
		}
		if errors.Is(err, merge.ErrLeftOut) {
			fmt.Fprintf(os.Stderr, "error: %v\nrecord them in the successor and run rebase again, or give them up with --leave-out (§F.5)\n", err)
			os.Exit(1)
		}
		if err != nil {
			toolFatal(err)
		}
		return
	}

	if sub == "abandon" {
		abandoned, err := merge.AbandonRelease(ctx, c, merge.ReleaseOptions{Release: link, StateNS: a.StateNS, Who: whoAmI(tf)})
		if tf.JSON {
			out := map[string]any{"abandoned": abandoned}
			if err != nil {
				out["error"] = err.Error()
			}
			printJSON(out)
		} else {
			for _, ns := range abandoned {
				fmt.Printf("%s: frozen, abandoned\n", ns)
			}
		}
		if err != nil {
			toolFatal(err)
		}
		return
	}

	opt := merge.ReleaseOptions{Release: link, StateNS: a.StateNS, Accept: a.AcceptPlacement, SourceAuthorizations: a.SourceGrant, Who: whoAmI(tf),
		Digest: a.Digest, AdminGrant: tf.Bearer, Signer: tf.signer()}
	if a.MergeBearer != "" {
		if g, err := grant.Decode(a.MergeBearer, 0); err == nil && len(g.Blocks) > 0 {
			opt.Via = g.Blocks[0].Sub
		}
	}
	if len(a.CatalogService) > 0 {
		g := &merge.HTTPGranter{URLs: map[string]string{}, Bearer: tf.Bearer, Author: tf.Author}
		if a.MergeBearer != "" {
			g.Bearer, g.Approver = a.MergeBearer, tf.Bearer
		}
		for _, s := range a.CatalogService {
			k, u, ok := strings.Cut(s, "=")
			if !ok {
				toolFatal(fmt.Errorf("--catalog-service %q: want CAT=URL", s))
			}
			g.URLs[k] = u
		}
		opt.Granter = g
	}
	for _, s := range a.Split {
		k, file, ok := strings.Cut(s, "=")
		key, node, ok2 := strings.Cut(k, "/")
		if !ok || !ok2 {
			toolFatal(fmt.Errorf("--split %q: want KEY/NODE=narrow.json", s))
		}
		v, err := readJSONFile(file)
		if err != nil {
			toolFatal(fmt.Errorf("--split %s: %w", k, err))
		}
		if opt.Splits == nil {
			opt.Splits = map[string]map[string]any{}
		}
		if opt.Splits[key] == nil {
			opt.Splits[key] = map[string]any{}
		}
		opt.Splits[key][node] = v
	}
	for _, s := range a.Resolve {
		k, file, ok := strings.Cut(s, "=")
		if !ok || !strings.Contains(k, "/") {
			toolFatal(fmt.Errorf("--resolve %q: want KEY/NAME=file.json", s))
		}
		steps, err := readResolution(file)
		if err != nil {
			toolFatal(fmt.Errorf("--resolve %s: %w", k, err))
		}
		if opt.Resolutions == nil {
			opt.Resolutions = map[string][]client.Step{}
		}
		opt.Resolutions[k] = steps
	}

	var rp *merge.ReleasePlan
	var locks []*merge.Lock
	var err error
	switch sub {
	case "status":
		rp, err = merge.LoadReleasePlan(ctx, c, opt)
		if err == nil && rp == nil {
			err = errors.New("no stored plan for this release")
		}
		for _, b := range planBranches(rp) {
			if !b.Catalog || err != nil {
				continue
			}
			var l *merge.Lock
			if l, err = merge.ReadLock(ctx, c, opt, b.Target); err == nil {
				locks = append(locks, l)
			}
		}
	case "plan":
		var old *merge.ReleasePlan
		old, err = merge.LoadReleasePlan(ctx, c, opt)
		if err != nil {
			break
		}
		if old != nil {
			if old.State == merge.ReleaseMerging || old.State == merge.ReleaseDone {
				err = fmt.Errorf("the release is %s; a new plan would replace its record (status shows it)", old.State)
				break
			}
			opt.AcceptFrozen = old.FrozenBy()
		}
		rp, err = merge.PlanRelease(ctx, c, opt)
		if err == nil && !a.DryRun {
			if old != nil {
				merge.AdoptHead(rp, old)
			}
			err = merge.SaveReleasePlan(ctx, c, opt, rp)
		}
	case "approve":
		rp, err = merge.ApproveRelease(ctx, c, opt)
	case "apply":
		rp, err = merge.ApplyRelease(ctx, c, opt)
	}
	if tf.JSON {
		out := map[string]any{"plan": rp}
		if locks != nil {
			out["locks"] = locks
		}
		if err != nil {
			out["error"] = err.Error()
		}
		printJSON(out)
	} else if rp != nil {
		printReleasePlan(rp)
		printLocks(rp, locks)
	}
	if err != nil {
		if !tf.JSON {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
	if sub == "plan" && !rp.Clean() {
		os.Exit(1)
	}
}

func planBranches(rp *merge.ReleasePlan) []*merge.ReleaseBranch {
	if rp == nil {
		return nil
	}
	return rp.Branches
}

// printLocks shows the catalog bases' merge locks (§F.9).
func printLocks(rp *merge.ReleasePlan, locks []*merge.Lock) {
	for _, l := range locks {
		where := l.NS + "/" + l.Name
		switch {
		case l.Free():
			fmt.Printf("  lock %s: free\n", where)
		case l.Legacy != "" && l.Legacy == rp.Release && rp.Format == 0 && rp.State == merge.ReleaseMerging:
			fmt.Printf("  lock %s: held by an earlier version's merge of this release, stopped part-way; apply resumes it and takes the lock over\n", where)
		case l.Legacy != "":
			fmt.Printf("  lock %s: held by an earlier version's merge of %s; a person releases it (append {})\n", where, l.Legacy)
		case l.Plan == rp.Digest:
			fmt.Printf("  lock %s: held by %s for this plan\n", where, l.Holder)
		default:
			plan := l.Plan
			if plan == "" {
				plan = "(none)"
			}
			fmt.Printf("  lock %s: held by %s for plan %s\n", where, l.Holder, plan)
		}
	}
}

// whoAmI names the caller: the root sub of --bearer, or --author.
func whoAmI(tf *toolArgs) string {
	if tf.Bearer != "" {
		if g, err := grant.Decode(tf.Bearer, 0); err == nil && len(g.Blocks) > 0 {
			return g.Blocks[0].Sub
		}
	}
	return tf.Author
}

func printReleasePlan(rp *merge.ReleasePlan) {
	fmt.Printf("release %s at %s: %s\n", rp.Release, short(rp.Revision), rp.State)
	if rp.Digest != "" {
		fmt.Printf("  digest %s (approve with --digest %s)\n", rp.Digest, rp.Digest)
	}
	if rp.ApprovedBy != "" {
		fmt.Printf("  approved by %s at %s\n", rp.ApprovedBy, rp.ApprovedAt)
	}
	for _, b := range rp.Branches {
		kind := "content"
		if b.Catalog {
			kind = "catalog"
		}
		line := fmt.Sprintf("  %-16s %-20s → %-16s %s", b.Key, b.NS, b.Target, kind)
		if len(b.Schemas) > 0 {
			line += fmt.Sprintf(", schemas %s", strings.Join(b.Schemas, " "))
		}
		if b.FrozenConfig != "" {
			line += ", frozen"
		}
		if b.Merged != "" {
			line += ", merged at " + short(b.Merged)
		}
		fmt.Println(line)
	}
	names := map[int]string{1: "schemas (fast-forward)", 2: "catalog: narrowing", 3: "content", 4: "catalog: widening"}
	for _, st := range rp.Steps {
		done := ""
		if st.Done != "" {
			done = "  done " + short(st.Done)
		}
		fmt.Printf("  step %d %-24s %-14s %s%s\n", st.Step, names[st.Step], st.Key, strings.Join(st.Resources, " "), done)
		for n, h := range rp.Halves[st.Key] {
			for _, r := range st.Resources {
				if r == n {
					fmt.Printf("      %s: in two halves (%s)\n", n, h.Reason)
				}
			}
		}
	}
	for _, n := range rp.Notes {
		fmt.Println("  note:", n)
	}
	for _, c := range rp.Conflicts {
		where := c.Key
		if c.Resource != "" {
			where += "/" + c.Resource
		}
		fmt.Printf("  CONFLICT %s %s: %s", c.Kind, where, c.Message)
		if len(c.Paths) > 0 {
			fmt.Printf(" [%s]", strings.Join(c.Paths, "; "))
		}
		fmt.Println()
	}
	if len(rp.Conflicts) == 0 && rp.State == merge.ReleasePlanned {
		fmt.Println("  clean: approve with `patchlog merge release approve …` (it freezes every listed branch)")
	}
}
