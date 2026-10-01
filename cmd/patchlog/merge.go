package main

// Addendum F tools: merge, rebase and the branch janitor. All of them are
// clients of the public API (internal/merge, internal/janitor).
//
//	patchlog merge release plan|approve|apply|status|rebase … /r/{ns}/{release}  (cmd/patchlog/release.go)
//	patchlog merge status|plan|apply -api URL -branch NS [-base NS] [-bearer T] [-author A]
//	        [-freeze] [-squash] [-resolve name=file.json]... [-config patches.json] [-identity key.jwk]... [-json]
//	patchlog rebase -api URL -branch NS -new NAME [-onto NS] [-switch] [-bearer T] [-author A] [-identity key.jwk]... [-json]
//	patchlog janitor -api URL -ns base1,base2 [-release LINK]... [-dry-run] [-once] [-interval 1m] [-bearer T] [-author A] [-json]

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
)

const mergeUsage = `usage:
  patchlog merge release plan|approve|apply|status|rebase … /r/{ns}/{release}   (§F.9; see patchlog merge release)
  patchlog merge status|plan|apply -api URL -branch NS [-base NS] [-bearer T] [-author A]
          [-freeze] [-squash] [-resolve name=file.json]... [-config patches.json] [-identity key.jwk]... [-json]
  patchlog rebase -api URL -branch NS -new NAME [-onto NS] [-switch] [-bearer T] [-author A] [-identity key.jwk]... [-json]
  patchlog janitor -api URL -ns base1,base2 [-release /r/{ns}/{release}]... [-dry-run] [-once] [-interval 1m] [-bearer T] [-author A] [-json]`

// toolFlags are the connection flags shared by the Addendum F tools.
type toolFlags struct {
	api, bearer, author *string
	asJSON              *bool
}

func addToolFlags(fs *flag.FlagSet) toolFlags {
	return toolFlags{
		api:    fs.String("api", "http://localhost:8080", "deployment base URL"),
		bearer: fs.String("bearer", "", "grant sent as Authorization: Bearer"),
		author: fs.String("author", "", "X-Author (development servers only)"),
		asJSON: fs.Bool("json", false, "print JSON"),
	}
}

func (tf toolFlags) client() *client.Client {
	var opts []client.Option
	if *tf.bearer != "" {
		opts = append(opts, client.WithBearer(*tf.bearer))
	}
	if *tf.author != "" {
		opts = append(opts, client.WithAuthor(*tf.author))
	}
	c, err := client.New(*tf.api, opts...)
	if err != nil {
		toolFatal(err)
	}
	return c
}

// identityHelp describes -identity for merge and rebase.
const identityHelp = "file with an X25519 private key (a private JWK {kty, crv, x, d}, or base64url d) for e2e namespaces (Addendum E.3): the key the keyrings (and -bearer's enc) name, to read the branch and re-encrypt for the target (§F.8); repeatable when they name different keys"

// e2eView returns a key-holding view of c with the -identity keys, or nil
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
			toolFatal(fmt.Errorf("-identity %s: %w", f, err))
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

func mergeCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, mergeUsage)
		os.Exit(2)
	}
	sub := args[0]
	switch sub {
	case "status", "plan", "apply":
	case "release":
		releaseCmd(args[1:])
		return
	default:
		fmt.Fprintln(os.Stderr, mergeUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("merge "+sub, flag.ExitOnError)
	tf := addToolFlags(fs)
	base := fs.String("base", "", "target namespace (default: the branch's base)")
	branch := fs.String("branch", "", "branch to merge")
	freeze := fs.Bool("freeze", false, "apply: freeze the branch afterwards, recording merged.at")
	squash := fs.Bool("squash", false, "one patch set per resource (loses per-set history and fast-forward ids)")
	cfgFile := fs.String("config", "", "file with an explicit config change (a patch set) for the target")
	var resolves multi
	fs.Var(&resolves, "resolve", "name=file.json: resolution for a conflicting resource, against the target's head: a patch set, a list of steps, \"delete\", or \"keep\" (repeatable)")
	var identities multi
	fs.Var(&identities, "identity", identityHelp)
	fs.Parse(args[1:])
	if *branch == "" {
		fmt.Fprintln(os.Stderr, "merge: -branch is required")
		os.Exit(2)
	}
	ctx := context.Background()
	c := tf.client()
	target := *base
	if target == "" {
		target = branchBase(ctx, c, *branch)
	}
	opt := merge.Options{Squash: *squash, E2E: e2eView(c, identities)}
	if *cfgFile != "" {
		v, err := readJSONFile(*cfgFile)
		if err != nil {
			toolFatal(err)
		}
		opt.Config = v
	}
	p, err := merge.NewPlan(ctx, c, target, *branch, opt)
	if err != nil {
		toolFatal(err)
	}
	for _, r := range resolves {
		name, file, ok := strings.Cut(r, "=")
		if !ok {
			toolFatal(fmt.Errorf("-resolve %q: want name=file.json", r))
		}
		steps, err := readResolution(file)
		if err != nil {
			toolFatal(fmt.Errorf("-resolve %s: %w", name, err))
		}
		if err := p.Resolve(name, steps...); err != nil {
			toolFatal(err)
		}
	}

	hints := mergeHints(p, tf)
	switch sub {
	case "status":
		if *tf.asJSON {
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
		if *tf.asJSON {
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
			if *tf.asJSON {
				printJSON(map[string]any{"plan": p, "clean": false, "error": err.Error(), "hints": hints})
			} else {
				printPlan(p)
				printHints(hints)
				fmt.Fprintln(os.Stderr, "not merged: resolve the conflicting resources with -resolve name=file.json")
			}
			os.Exit(1)
		}
		if err != nil {
			toolFatal(err)
		}
		out := map[string]any{"result": res}
		if *freeze {
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
		if *tf.asJSON {
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
		if *freeze {
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
		fmt.Println("needs a person: resolve with -resolve name=file.json (a patch set against the target's head)")
	}
}

// mergeHints explains merge.authors (§F.3): the plan's own hints (no
// merge.authors in the target, earlier merge batches that don't count),
// plus one if the merger itself isn't listed, so its batch won't serve as
// a common ancestor for a later merge, nor verify a merged claim for the
// janitor (§F.6). The merger is the root sub and kid of -bearer, or the
// -author of a development server (no kid).
func mergeHints(p *merge.Plan, tf toolFlags) []string {
	hints := p.Hints()
	if !p.AuthorsDeclared {
		return hints
	}
	sub, kid := *tf.author, ""
	if *tf.bearer != "" {
		g, err := grant.Decode(*tf.bearer, 0)
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
		toolFatal(fmt.Errorf("%s is not a branch; give -base", branch))
	}
	return ns
}

func rebaseCmd(args []string) {
	fs := flag.NewFlagSet("rebase", flag.ExitOnError)
	tf := addToolFlags(fs)
	branch := fs.String("branch", "", "branch to rebase")
	newName := fs.String("new", "", "name of the successor branch (resumes if it exists)")
	onto := fs.String("onto", "", "namespace to create the successor from (default: the branch's base)")
	sw := fs.Bool("switch", false, "freeze the old branch with successor: NEW, then replay what it got meanwhile")
	var identities multi
	fs.Var(&identities, "identity", identityHelp)
	fs.Parse(args)
	if *branch == "" || *newName == "" {
		fmt.Fprintln(os.Stderr, "rebase: -branch and -new are required")
		os.Exit(2)
	}
	ctx := context.Background()
	c := tf.client()
	res, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: *branch, New: *newName, Onto: *onto, Switch: *sw, Plan: merge.Options{E2E: e2eView(c, identities)}})
	if *tf.asJSON {
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
			fmt.Printf("switched: %s is frozen with successor %s\n", *branch, res.New)
		}
		if res.CatchUp != nil {
			printPlan(res.CatchUp)
		}
		if res.CatchUpResult != nil && !res.CatchUpResult.Noop {
			fmt.Printf("caught up as batch %s\n", res.CatchUpResult.NSID)
		}
	}
	if errors.Is(err, merge.ErrConflicts) {
		fmt.Fprintf(os.Stderr, "stopped on conflicts: resolve them with `patchlog merge apply -base %s -branch %s -resolve …`, then run rebase again\n", *newName, *branch)
		os.Exit(1)
	}
	if err != nil {
		toolFatal(err)
	}
}

func janitorCmd(args []string) {
	fs := flag.NewFlagSet("janitor", flag.ExitOnError)
	tf := addToolFlags(fs)
	nsList := fs.String("ns", "", "comma-separated base namespaces to clean up")
	dry := fs.Bool("dry-run", false, "only report what would be purged")
	once := fs.Bool("once", false, "sweep once and exit instead of following the bases")
	interval := fs.Duration("interval", time.Minute, "sweep interval while following")
	var releases multi
	fs.Var(&releases, "release", "release document /r/{ns}/{release} whose draft branches are purged after its other branches (§F.9); repeatable")
	fs.Parse(args)
	var bases []string
	for _, s := range strings.Split(*nsList, ",") {
		if s = strings.TrimSpace(s); s != "" {
			bases = append(bases, s)
		}
	}
	if len(bases) == 0 {
		fmt.Fprintln(os.Stderr, "janitor: -ns is required")
		os.Exit(2)
	}
	c := tf.client()
	report := func(d janitor.Decision) {
		if *tf.asJSON {
			b, _ := json.Marshal(d)
			fmt.Println(string(b))
			return
		}
		fmt.Printf("%-24s %-12s %s\n", d.NS, d.Action, d.Reason)
	}
	opt := janitor.Options{Bases: bases, DryRun: *dry, Interval: *interval, Releases: releases,
		OnError: func(err error) { fmt.Fprintln(os.Stderr, "janitor:", err) }}
	if *once {
		ds, err := janitor.New(c, opt).Sweep(context.Background())
		if *tf.asJSON {
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
