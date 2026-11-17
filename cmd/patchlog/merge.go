package main

// Addendum F tools: merge, rebase and the branch janitor. All of them are
// clients of the public API (internal/merge, internal/janitor). Releases
// across namespaces, patchlog merge release, are in release.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
)

// signer returns the key of --sign-key (or $PATCHLOG_SIGN_KEY), nil if unset.
func (tf *toolArgs) signer() *sig.Key {
	if tf.SignKey == "" {
		return nil
	}
	k, err := sig.ParseKey(tf.SignKey)
	if err != nil {
		toolFatal(fmt.Errorf("--sign-key: %w", err))
	}
	return &k
}

func (tf *toolArgs) client() *client.Client {
	var opts []client.Option
	if tf.Bearer != "" {
		opts = append(opts, client.WithBearer(tf.Bearer))
	}
	if tf.Author != "" {
		opts = append(opts, client.WithAuthor(tf.Author))
	}
	kopts, err := tf.keyringArgs.options()
	if err != nil {
		toolFatal(err)
	}
	c, err := client.New(tf.API, append(opts, kopts...)...)
	if err != nil {
		toolFatal(err)
	}
	return c
}

// e2eView returns a key-holding view of c with the --identity keys, or nil
// without any.
func e2eView(c *client.Client, identities []string) *client.E2E {
	if len(identities) == 0 {
		return nil
	}
	x := c.E2E(nil)
	for _, f := range identities {
		b, err := os.ReadFile(f)
		if err != nil {
			toolFatal(err)
		}
		priv, err := seal.ParseRecipientPrivate(b)
		if err != nil {
			toolFatal(fmt.Errorf("--identity %s: %w", f, err))
		}
		x = x.WithRecipient(priv)
	}
	return x
}

func toolFatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	if ae, ok := client.AsAPIError(err); ok && len(ae.Items()) > 0 {
		for _, it := range ae.Items() {
			fmt.Fprintf(os.Stderr, "  item %v: %v %v %v\n", it["index"], it["status"], it["code"], it["message"])
		}
	}
	os.Exit(1)
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		toolFatal(err)
	}
	fmt.Println(string(b))
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	if id == "" {
		return "-"
	}
	return id
}

// mergeCmd is patchlog merge.
type mergeCmd struct {
	Status  *mergeBranchCmd `arg:"subcommand:status" help:"show what merging a branch would do"`
	Plan    *mergeBranchCmd `arg:"subcommand:plan" help:"print the batch a merge would submit"`
	Apply   *mergeBranchCmd `arg:"subcommand:apply" help:"merge a branch into its base (§F.3)"`
	Release *releaseCmd     `arg:"subcommand:release" help:"plan, approve and apply releases across namespaces (§F.9)"`
}

// mergeBranchCmd is patchlog merge status|plan|apply.
type mergeBranchCmd struct {
	toolArgs
	Base    string   `arg:"--base" placeholder:"NS" help:"target namespace (default: the branch's base)"`
	Branch  string   `arg:"--branch,required" placeholder:"NS" help:"branch to merge"`
	Freeze  bool     `arg:"--freeze" help:"apply: freeze the branch afterwards, recording merged.at"`
	Squash  bool     `arg:"--squash" help:"one patch set per resource (loses per-set history and fast-forward ids)"`
	Config  string   `arg:"--config" placeholder:"FILE" help:"file with an explicit config change (a patch set) for the target"`
	Resolve []string `arg:"--resolve,separate" placeholder:"NAME=FILE.json" help:"resolution for a conflicting resource, against the target's head: a patch set, a list of steps, \"delete\", or \"keep\" (repeatable)"`
	identityArgs
	SourceGrant []string `arg:"--source-grant,separate" placeholder:"GRANT" help:"a grant sent as Source-Authorization with every batch and blob copy (reads the branch: its blobs, drafts; §7.5, §7.8); with unrestricted read on the branch, the batch's source makes its blobs available and nothing is copied (§F.3); repeatable"`
}

func (a *mergeBranchCmd) run(sub string) {
	tf := &a.toolArgs
	ctx := context.Background()
	c := tf.client()
	target := a.Base
	if target == "" {
		target = branchBase(ctx, c, a.Branch)
	}
	opt := merge.Options{Squash: a.Squash, E2E: e2eView(c, a.Identity), Signer: tf.signer(), SourceAuthorizations: a.SourceGrant}
	if a.Config != "" {
		v, err := readJSONFile(a.Config)
		if err != nil {
			toolFatal(err)
		}
		opt.Config = v
	}
	p, err := merge.NewPlan(ctx, c, target, a.Branch, opt)
	if err != nil {
		toolFatal(err)
	}
	for _, r := range a.Resolve {
		name, file, ok := strings.Cut(r, "=")
		if !ok {
			toolFatal(fmt.Errorf("--resolve %q: want name=file.json", r))
		}
		steps, err := readResolution(file)
		if err != nil {
			toolFatal(fmt.Errorf("--resolve %s: %w", name, err))
		}
		if err := p.Resolve(name, steps...); err != nil {
			toolFatal(err)
		}
	}

	hints := mergeHints(p, tf)
	switch sub {
	case "status":
		if tf.JSON {
			printJSON(map[string]any{"target": p.Target, "branch": p.Branch, "branchAt": p.BranchAt, "resources": p.Status(), "hints": hints})
			return
		}
		fmt.Printf("%s → %s (branch at %s)\n", p.Branch, p.Target, short(p.BranchAt))
		for _, s := range p.Status() {
			line := fmt.Sprintf("  %-28s %-12s %s", s.Resource, s.Status, s.Class)
			for _, c := range s.Conflicts {
				line += "  [" + c.Kind
				if len(c.Paths) > 0 {
					line += " " + strings.Join(c.Paths, ",")
				}
				line += "]"
			}
			if s.Note != "" {
				line += "  (" + s.Note + ")"
			}
			fmt.Println(line)
			if s.Pair != nil {
				fmt.Printf("      %s\n", s.Pair)
			}
		}
		if len(p.Resources) == 0 {
			fmt.Println("  (the branch changed nothing)")
		}
		printHints(hints)
	case "plan":
		dry, derr := p.DryRun(ctx)
		if tf.JSON {
			out := map[string]any{"plan": p, "clean": p.Clean(), "batch": batchJSON(p), "hints": hints}
			if dry != nil {
				out["dryRun"] = dry.Items
			}
			if derr != nil {
				out["dryRunError"] = derr.Error()
				if ae, ok := client.AsAPIError(derr); ok {
					out["dryRunItems"] = ae.Items()
				}
			}
			printJSON(out)
			return
		}
		printPlan(p)
		switch {
		case derr != nil:
			fmt.Println("dry run failed:", derr)
			if ae, ok := client.AsAPIError(derr); ok {
				items := p.Items()
				for _, it := range ae.Items() {
					name := "?"
					if i, ok := it["index"].(float64); ok && int(i) < len(items) {
						name = items[int(i)].Name
					}
					fmt.Printf("  %s: %v %v %v\n", name, it["status"], it["code"], it["message"])
				}
			}
		case dry == nil:
			fmt.Println("nothing to merge")
		default:
			fmt.Println("dry run ok:")
			for _, it := range dry.Items {
				fmt.Printf("  %-28s → %s\n", it.Resource, strings.Join(shortAll(it.IDs), " "))
			}
		}
		printHints(hints)
	case "apply":
		res, err := p.Apply(ctx)
		if errors.Is(err, merge.ErrConflicts) {
			if tf.JSON {
				printJSON(map[string]any{"plan": p, "clean": false, "error": err.Error(), "hints": hints})
			} else {
				printPlan(p)
				printHints(hints)
				fmt.Fprintln(os.Stderr, "not merged: resolve the conflicting resources with --resolve name=file.json")
			}
			os.Exit(1)
		}
		if err != nil {
			toolFatal(err)
		}
		out := map[string]any{"result": res}
		if a.Freeze {
			at := res.NSID
			if at == "" {
				h, err := c.NSHead(ctx, p.Target)
				if err != nil {
					toolFatal(err)
				}
				at = h.ID
			}
			fr, err := merge.Freeze(ctx, c, p.Branch, at)
			if err != nil {
				toolFatal(fmt.Errorf("merged, but freezing failed: %w", err))
			}
			out["frozen"] = map[string]any{"config": fr.Config, "ns_id": fr.NSID, "merged": at}
		}
		if tf.JSON {
			printJSON(out)
			return
		}
		if res.Noop {
			fmt.Println("nothing to merge: already up to date")
		} else {
			fmt.Printf("merged %s into %s as batch %s (%d attempt(s))\n", p.Branch, p.Target, res.NSID, res.Attempts)
			for _, r := range p.Items() {
				fmt.Printf("  %-28s %-12s %s\n", r.Name, r.Class, strings.Join(shortAll(res.IDs[r.Name]), " "))
			}
		}
		if a.Freeze {
			fmt.Printf("froze %s (merged.at %v)\n", p.Branch, out["frozen"].(map[string]any)["merged"])
		}
	}
}

func shortAll(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = short(id)
	}
	return out
}

func printPlan(p *merge.Plan) {
	fmt.Printf("merge %s → %s (branch at %s, target at %s)\n", p.Branch, p.Target, short(p.BranchAt), short(p.TargetAt))
	for _, r := range p.Resources {
		pre := "ifMatch " + short(r.IfMatch)
		if r.IfNoneMatch {
			pre = "ifNoneMatch *"
		}
		line := fmt.Sprintf("  %-28s %-12s %-13s", r.Name, r.Status(), r.Class)
		if r.HasItem() {
			line += fmt.Sprintf(" %d step(s), %s", len(r.Steps), pre)
			if r.Squashed {
				line += ", squashed"
			}
			if r.Resolved {
				line += ", resolved"
			}
		}
		if r.Dropped {
			if r.Kept {
				line += " (kept as in the target, recorded so a later merge has its pair)"
			} else {
				line += " kept as in the target, not recorded: stays unmerged"
			}
		}
		fmt.Println(line)
		if r.Ancestor != "" && r.Class == merge.Replay {
			fmt.Printf("      from ancestor %s; branch writes %v, target writes %v\n", short(r.Ancestor), r.BranchWrites, r.BaseWrites)
		}
		if r.Pair != nil {
			fmt.Printf("      %s\n", r.Pair)
		}
		for _, c := range r.Conflicts {
			fmt.Printf("      CONFLICT %s: %s %v\n", c.Kind, c.Message, c.Paths)
		}
		if r.Note != "" {
			fmt.Printf("      %s\n", r.Note)
		}
	}
	if !p.Clean() {
		fmt.Println("needs a person: resolve with --resolve name=file.json (a patch set against the target's head)")
	}
}

// mergeHints explains merge.authors (§F.3): the plan's own hints (no
// merge.authors in the target, earlier merge batches that don't count),
// plus one if the merger itself isn't listed, so its batch won't serve as
// a common ancestor for a later merge, nor verify a merged claim for the
// janitor (§F.6). The merger is the root sub and kid of --bearer, or the
// --author of a development server (no kid).
func mergeHints(p *merge.Plan, tf *toolArgs) []string {
	hints := p.Hints()
	if !p.AuthorsDeclared {
		return hints
	}
	sub, kid := tf.Author, ""
	if tf.Bearer != "" {
		g, err := grant.Decode(tf.Bearer, 0)
		if err != nil || len(g.Blocks) == 0 {
			return hints
		}
		sub, kid = g.Blocks[0].Sub, g.Blocks[0].Kid
	}
	if sub == "" || merge.Listed(p.MergeAuthors, sub, kid) {
		return hints
	}
	who := sub
	if kid != "" {
		who += "/" + kid
	}
	return append(hints, fmt.Sprintf("you (%s) aren't in %s's merge.authors: this merge won't count as a common ancestor for a later merge of %s, and the janitor won't accept it for a merged claim; merge as a listed principal, or rebase the branch (§F.5) before merging it again", who, p.Target, p.Branch))
}

func printHints(hints []string) {
	for _, h := range hints {
		fmt.Println("hint:", h)
	}
}

// batchJSON renders the batch body the plan would submit.
func batchJSON(p *merge.Plan) map[string]any {
	req := p.Batch()
	items := []any{}
	for _, it := range req.Items {
		m := map[string]any{"resource": it.Resource, "steps": merge.StepsJSON(it.Steps)}
		if it.IfNoneMatch {
			m["ifNoneMatch"] = "*"
		} else {
			m["ifMatch"] = it.IfMatch
		}
		items = append(items, m)
	}
	out := map[string]any{"items": items, "source": req.Source}
	if req.Config != nil {
		out["config"] = map[string]any{"ifMatch": req.Config.IfMatch, "patches": req.Config.Patches}
	}
	return out
}

func readJSONFile(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jsonv.Parse(b)
}

// readResolution reads a resolution: a patch set, a list of steps (patch
// sets and "delete"), "delete", or "keep" (drop the item).
func readResolution(path string) ([]client.Step, error) {
	v, err := readJSONFile(path)
	if err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case string:
		switch x {
		case "delete":
			return []client.Step{client.DeleteStep()}, nil
		case "keep":
			return nil, nil
		}
		return nil, fmt.Errorf("unknown resolution %q (want a patch set, a list of steps, \"delete\" or \"keep\")", x)
	case []any:
		isSteps := len(x) > 0
		for _, e := range x {
			switch e.(type) {
			case []any, string:
			default:
				isSteps = false
			}
		}
		if !isSteps {
			return []client.Step{client.PatchStep(x)}, nil
		}
		var steps []client.Step
		for _, e := range x {
			if s, ok := e.(string); ok {
				if s != "delete" {
					return nil, fmt.Errorf("unknown step %q", s)
				}
				steps = append(steps, client.DeleteStep())
				continue
			}
			steps = append(steps, client.PatchStep(e))
		}
		return steps, nil
	}
	return nil, errors.New("a resolution must be a patch set, a list of steps, \"delete\" or \"keep\"")
}

// branchBase reads a branch's base namespace from its document.
func branchBase(ctx context.Context, c *client.Client, branch string) string {
	h, err := c.NSHead(ctx, branch)
	if err != nil {
		toolFatal(err)
	}
	d, err := c.NSDoc(ctx, branch, h.ID)
	if err != nil {
		toolFatal(err)
	}
	b, _ := d.Value["base"].(map[string]any)
	ns, _ := b["ns"].(string)
	if ns == "" {
		toolFatal(fmt.Errorf("%s is not a branch; give --base", branch))
	}
	return ns
}

// rebaseCmd is patchlog rebase.
type rebaseCmd struct {
	toolArgs
	Branch   string `arg:"--branch,required" placeholder:"NS" help:"branch to rebase"`
	New      string `arg:"--new,required" placeholder:"NAME" help:"name of the successor branch (resumes if it exists)"`
	Onto     string `arg:"--onto" placeholder:"NS" help:"namespace to create the successor from (default: the branch's base)"`
	Switch   bool   `arg:"--switch" help:"freeze the old branch with successor: NEW, then replay what it got meanwhile"`
	LeaveOut bool   `arg:"--leave-out" help:"with --switch: switch although the replay leaves resources the old branch changed unrecorded in the successor (left out of an item, purged in the successor only), giving them up (§F.5): their changes stay only in the frozen old branch"`
	identityArgs
	Reader []string `arg:"--reader,separate" placeholder:"PUB.JWK" help:"e2e: file with the X25519 public key (a JWK {kty, crv, x}, or base64url x) of a reader the successor's keyring wraps its key for, besides those of the old branch's readers the identities know (repeatable, §F.8.1)"`
}

func (a *rebaseCmd) run(string) {
	tf := &a.toolArgs
	succReaders, err := readPublicKeys(a.Reader)
	if err != nil {
		toolFatal(err)
	}
	ctx := context.Background()
	c := tf.client()
	res, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: a.Branch, New: a.New, Onto: a.Onto, Switch: a.Switch, LeaveOut: a.LeaveOut, SuccessorReaders: succReaders,
		Plan: merge.Options{E2E: e2eView(c, a.Identity), Signer: tf.signer()}})
	if tf.JSON {
		out := map[string]any{"result": res}
		if err != nil {
			out["error"] = err.Error()
		}
		printJSON(out)
		if err != nil {
			os.Exit(1)
		}
		return
	}
	if res != nil {
		if res.Created {
			fmt.Printf("created %s\n", res.New)
		} else {
			fmt.Printf("resuming into %s\n", res.New)
		}
		if res.First != nil {
			printPlan(res.First)
		}
		if res.FirstResult != nil && !res.FirstResult.Noop {
			fmt.Printf("replayed into %s as batch %s\n", res.New, res.FirstResult.NSID)
		}
		if res.Switched {
			fmt.Printf("switched: %s is frozen with successor %s\n", a.Branch, res.New)
		}
		if res.CatchUp != nil {
			printPlan(res.CatchUp)
		}
		if res.CatchUpResult != nil && !res.CatchUpResult.Noop {
			fmt.Printf("caught up as batch %s\n", res.CatchUpResult.NSID)
		}
		printLeftOut(res, a.Branch)
		if len(res.DroppedReaders) > 0 && err == nil {
			fmt.Printf("%s's keyring holds no key for these readers of %s: %s\n", res.New, a.Branch, strings.Join(res.DroppedReaders, ", "))
		}
	}
	if errors.Is(err, merge.ErrReadersDropped) {
		fmt.Fprintf(os.Stderr, "error: %v\nname their public keys with --reader and run rebase again\n", err)
		os.Exit(1)
	}
	if errors.Is(err, merge.ErrConflicts) {
		fmt.Fprintf(os.Stderr, "stopped on conflicts: resolve them with `patchlog merge apply --base %s --branch %s --resolve …`, then run rebase again\n", a.New, a.Branch)
		os.Exit(1)
	}
	if errors.Is(err, merge.ErrLeftOut) && res != nil && !res.Switched {
		fmt.Fprintf(os.Stderr, "error: %v\nrecord them in %s and run rebase again, or give them up with --leave-out (§F.5)\n", err, a.New)
		os.Exit(1)
	}
	if err != nil {
		toolFatal(err)
	}
}

// printLeftOut prints the resources a rebase of branch left unrecorded in
// its successor (§F.5): given up when it switched, else holding it up.
func printLeftOut(res *merge.RebaseResult, branch string) {
	if len(res.LeftOut) == 0 {
		return
	}
	if res.Switched {
		fmt.Printf("left out, only in the frozen %s: %s\n", branch, strings.Join(res.LeftOut, ", "))
	} else {
		fmt.Printf("not recorded in %s, so %s isn't switched: %s\n", res.New, branch, strings.Join(res.LeftOut, ", "))
	}
}

// janitorCmd is patchlog janitor.
type janitorCmd struct {
	toolArgs
	NS       string        `arg:"--ns,required" placeholder:"BASE,BASE" help:"comma-separated base namespaces to clean up"`
	DryRun   bool          `arg:"--dry-run" help:"only report what would be purged"`
	Once     bool          `arg:"--once" help:"sweep once and exit instead of following the bases"`
	Interval time.Duration `arg:"--interval" default:"1m" placeholder:"DURATION" help:"sweep interval while following"`
	Release  []string      `arg:"--release,separate" placeholder:"/r/{ns}/{release}" help:"release document whose draft branches are purged after its other branches (§F.9); repeatable"`
}

func (a *janitorCmd) run(string) {
	tf := &a.toolArgs
	bases := splitList(a.NS)
	if len(bases) == 0 {
		fmt.Fprintln(os.Stderr, "janitor: --ns is required")
		os.Exit(2)
	}
	c := tf.client()
	report := func(d janitor.Decision) {
		if tf.JSON {
			b, _ := json.Marshal(d)
			fmt.Println(string(b))
			return
		}
		fmt.Printf("%-24s %-12s %s\n", d.NS, d.Action, d.Reason)
	}
	opt := janitor.Options{Bases: bases, DryRun: a.DryRun, Interval: a.Interval, Releases: a.Release,
		OnError: func(err error) { fmt.Fprintln(os.Stderr, "janitor:", err) }}
	if a.Once {
		ds, err := janitor.New(c, opt).Sweep(context.Background())
		if tf.JSON {
			printJSON(ds)
		} else {
			for _, d := range ds {
				report(d)
			}
			if len(ds) == 0 {
				fmt.Println("no live branches")
			}
		}
		if err != nil {
			toolFatal(err)
		}
		return
	}
	// Following: report only changes of a branch's decision.
	last := map[string]string{}
	opt.OnDecision = func(d janitor.Decision) {
		k := d.Action + "|" + d.Reason
		if last[d.NS] == k {
			return
		}
		last[d.NS] = k
		report(d)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := janitor.New(c, opt).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		toolFatal(err)
	}
}
