package main

// Releases across namespaces (§F.9):
//
//	patchlog merge release plan|approve|apply|status|rebase|abandon -api URL [flags] /r/{ns}/{release}
//
// plan classifies the release and reports its conflicts, and stores the
// plan (as {release}.merge in -state-ns, default the release document's
// namespace) unless -dry-run. approve, run by the approving person, plans
// again, requires it clean and for the same release revision, and freezes
// every listed branch. apply merges in the four steps (schemas by
// fast-forward, catalog changes that narrow access, content, catalog
// changes that widen it), each classified again with a dry run right
// before it is submitted, and resumes a merge that stopped. status shows
// the stored plan. rebase creates a successor of every branch (§F.5) and
// writes a new revision of the release document listing them. abandon
// freezes every branch with abandoned: true (needs a * key, §F.6).
//
// Catalog batches (§F.8): -merge-bearer is the merge service's own grant
// for the catalog (merge grants are issued only to it); -bearer, the
// person's, is the approver whose powers the catalog service checks, and
// for a batch that changes $access the catalog admin's grant it is
// submitted under, narrowed with the merge service's via. Without
// -merge-bearer, -bearer is sent for both.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
)

const releaseUsage = `usage:
  patchlog merge release plan|approve|apply|status -api URL [-bearer T] [-author A] [-state-ns NS]
          [-catalog-service CAT=URL]... [-merge-bearer G] [-split KEY/NODE=narrow.json]... [-accept-placement NS.NAME]...
          [-resolve KEY/NAME=file.json]... [-source-grant G]... [-digest D] [-dry-run] [-json] /r/{ns}/{release}
  patchlog merge release rebase -api URL -suffix SUFFIX [-at ID] [-bearer T] [-author A] [-json] /r/{ns}/{release}
  patchlog merge release abandon -api URL [-bearer T] [-author A] [-state-ns NS] /r/{ns}/{release}`

func releaseCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, releaseUsage)
		os.Exit(2)
	}
	sub := args[0]
	switch sub {
	case "plan", "approve", "apply", "status", "rebase", "abandon":
	default:
		fmt.Fprintln(os.Stderr, releaseUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("merge release "+sub, flag.ExitOnError)
	tf := addToolFlags(fs)
	stateNS := fs.String("state-ns", "", "namespace of the stored plan and the catalog locks (default: the release document's)")
	dry := fs.Bool("dry-run", false, "plan: report only, store nothing")
	suffix := fs.String("suffix", "", "rebase: successor names are each branch's name plus this suffix")
	at := fs.String("at", "", "rebase: the new release document's combined checkpoint (§B.5), if known")
	digest := fs.String("digest", "", "approve: the plan digest you reviewed (plan prints it); approval fails unless planning again gives it (§F.9)")
	mergeBearer := fs.String("merge-bearer", "", "the merge service's own grant for catalogs, sent to catalog services as Authorization (§F.8); its root sub is the via of narrowed admin grants")
	var catSvcs, splits, accepts, resolves, srcGrants multi
	fs.Var(&catSvcs, "catalog-service", "CAT=URL: the catalog service that signs merge grants for catalog base CAT (§F.8); repeatable")
	fs.Var(&splits, "split", "KEY/NODE=narrow.json: a catalog node that narrows and widens, merged in two halves; the file is its document after the narrowing step (§F.9); repeatable")
	fs.Var(&accepts, "accept-placement", "NS.NAME: accept that step 3 publishes an item under this existing placement (§F.9); repeatable")
	fs.Var(&resolves, "resolve", "KEY/NAME=file.json: resolution of a content resource's conflict, against its base's head (§F.3); repeatable")
	fs.Var(&srcGrants, "source-grant", "a grant sent as Source-Authorization with every batch (reads a branch: blobs, drafts; §7.8, §6.1); repeatable")
	fs.Parse(args[1:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, releaseUsage)
		os.Exit(2)
	}
	link := fs.Arg(0)
	if _, err := release.ParseRef(link); err != nil {
		toolFatal(err)
	}
	ctx := context.Background()
	c := tf.client()

	if sub == "rebase" {
		if *suffix == "" {
			fmt.Fprintln(os.Stderr, "merge release rebase: -suffix is required")
			os.Exit(2)
		}
		res, err := merge.RebaseRelease(ctx, c, merge.RebaseReleaseOptions{Release: link, Suffix: *suffix, At: *at})
		if *tf.asJSON {
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
		if errors.Is(err, merge.ErrConflicts) {
			fmt.Fprintln(os.Stderr, "stopped on conflicts: resolve them with `patchlog merge apply -base SUCCESSOR -branch OLD -resolve …`, then run rebase again")
			os.Exit(1)
		}
		if err != nil {
			toolFatal(err)
		}
		return
	}

	if sub == "abandon" {
		abandoned, err := merge.AbandonRelease(ctx, c, merge.ReleaseOptions{Release: link, StateNS: *stateNS, Who: whoAmI(tf)})
		if *tf.asJSON {
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

	opt := merge.ReleaseOptions{Release: link, StateNS: *stateNS, Accept: accepts, SourceAuthorizations: srcGrants, Who: whoAmI(tf),
		Digest: *digest, AdminGrant: *tf.bearer}
	if *mergeBearer != "" {
		if g, err := grant.Decode(*mergeBearer, 0); err == nil && len(g.Blocks) > 0 {
			opt.Via = g.Blocks[0].Sub
		}
	}
	if len(catSvcs) > 0 {
		g := &merge.HTTPGranter{URLs: map[string]string{}, Bearer: *tf.bearer, Author: *tf.author}
		if *mergeBearer != "" {
			g.Bearer, g.Approver = *mergeBearer, *tf.bearer
		}
		for _, s := range catSvcs {
			k, u, ok := strings.Cut(s, "=")
			if !ok {
				toolFatal(fmt.Errorf("-catalog-service %q: want CAT=URL", s))
			}
			g.URLs[k] = u
		}
		opt.Granter = g
	}
	for _, s := range splits {
		k, file, ok := strings.Cut(s, "=")
		key, node, ok2 := strings.Cut(k, "/")
		if !ok || !ok2 {
			toolFatal(fmt.Errorf("-split %q: want KEY/NODE=narrow.json", s))
		}
		v, err := readJSONFile(file)
		if err != nil {
			toolFatal(fmt.Errorf("-split %s: %w", k, err))
		}
		if opt.Splits == nil {
			opt.Splits = map[string]map[string]any{}
		}
		if opt.Splits[key] == nil {
			opt.Splits[key] = map[string]any{}
		}
		opt.Splits[key][node] = v
	}
	for _, s := range resolves {
		k, file, ok := strings.Cut(s, "=")
		if !ok || !strings.Contains(k, "/") {
			toolFatal(fmt.Errorf("-resolve %q: want KEY/NAME=file.json", s))
		}
		steps, err := readResolution(file)
		if err != nil {
			toolFatal(fmt.Errorf("-resolve %s: %w", k, err))
		}
		if opt.Resolutions == nil {
			opt.Resolutions = map[string][]client.Step{}
		}
		opt.Resolutions[k] = steps
	}

	var rp *merge.ReleasePlan
	var err error
	switch sub {
	case "status":
		rp, err = merge.LoadReleasePlan(ctx, c, opt)
		if err == nil && rp == nil {
			err = errors.New("no stored plan for this release")
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
		if err == nil && !*dry {
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
	if *tf.asJSON {
		out := map[string]any{"plan": rp}
		if err != nil {
			out["error"] = err.Error()
		}
		printJSON(out)
	} else if rp != nil {
		printReleasePlan(rp)
	}
	if err != nil {
		if !*tf.asJSON {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
	if sub == "plan" && !rp.Clean() {
		os.Exit(1)
	}
}

// whoAmI names the caller: the root sub of -bearer, or -author.
func whoAmI(tf toolFlags) string {
	if *tf.bearer != "" {
		if g, err := grant.Decode(*tf.bearer, 0); err == nil && len(g.Blocks) > 0 {
			return g.Blocks[0].Sub
		}
	}
	return *tf.author
}

func printReleasePlan(rp *merge.ReleasePlan) {
	fmt.Printf("release %s at %s: %s\n", rp.Release, short(rp.Revision), rp.State)
	if rp.Digest != "" {
		fmt.Printf("  digest %s (approve with -digest %s)\n", rp.Digest, rp.Digest)
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
