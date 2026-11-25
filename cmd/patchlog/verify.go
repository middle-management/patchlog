package main

// patchlog verify checks the integrity of what a deployment serves by
// recomputing ids (§G.2, internal/verify): the namespace chain from a
// trusted ns_id (by default genesis) to the head, and the log of each
// resource back to genesis, ending at the head the namespace lists for it.
// Ids travel, trust doesn't: the chain is only as trustworthy as the
// starting id, which should come from a source of your own (--from).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/verify"
)

// verifyCmd is patchlog verify NS.
type verifyCmd struct {
	toolArgs
	From     string   `arg:"--from" placeholder:"NS_ID" help:"a namespace entry you trust: the chain is checked from the entry after it (default: from the first entry, genesis)"`
	Resource []string `arg:"--resource,separate" placeholder:"NAME" help:"check only this resource's log (repeatable); default every resource; the namespace chain is checked either way"`
	NS       string   `arg:"positional,required"`
}

func (a *verifyCmd) run(string) { runClient(a) }

// verifyResult is one resource's outcome, for --json.
type verifyResult struct {
	Resource string `json:"resource"`
	Head     string `json:"head,omitempty"`
	Entries  int    `json:"entries"`
	Status   string `json:"status"` // ok, pruned, purged or mismatch
	Error    string `json:"error,omitempty"`
}

func (a *verifyCmd) exec(ctx context.Context, out, _ io.Writer) error {
	// Only the whole log verifies: a partial reader's is filtered (§10).
	c := a.client().Unfiltered()
	say := func(format string, args ...any) {
		if !a.JSON {
			fmt.Fprintf(out, format+"\n", args...)
		}
	}
	entries, head, err := verify.Namespace(ctx, c, a.NS, a.From)
	var ve *verify.Error
	if errors.As(err, &ve) {
		say("MISMATCH namespace %s: %v", a.NS, err)
		return a.report(out, a.NS, a.From, head, 0, nil, 1)
	}
	if fe, ok := client.AsFiltered(err); ok {
		return fmt.Errorf("can't verify %s: this grant reads it filtered, through view %s (§7.9), and a filtered log isn't chain-verifiable (§10); verify with a grant that reads %s unrestricted", a.NS, fe.View, a.NS)
	}
	if err != nil {
		return err
	}
	from := a.From
	if from == "" {
		from = "genesis"
	}
	say("namespace %s: %d entries verified, %s to %s", a.NS, len(entries), from, head)

	type target struct{ name, id, kind string }
	var targets []target
	if len(a.Resource) > 0 {
		for _, name := range a.Resource {
			h, err := c.Head(ctx, a.NS, name)
			if err != nil {
				return err
			}
			switch h.State {
			case client.NotFound:
				return fmt.Errorf("%s/%s doesn't exist", a.NS, name)
			case client.Purged:
				targets = append(targets, target{name, "", "purge"})
			case client.Tombstoned:
				targets = append(targets, target{name, h.ID, "tombstone"})
			default:
				targets = append(targets, target{name, h.ID, "head"})
			}
		}
	} else {
		items, _, err := c.Heads(ctx, a.NS, head)
		if err != nil {
			return err
		}
		for _, it := range items {
			targets = append(targets, target{it.Resource, it.Target, it.Kind})
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].name < targets[j].name })
	}

	var results []verifyResult
	bad := 0
	for _, t := range targets {
		r := verifyResult{Resource: t.name, Head: t.id}
		if t.kind == "purge" {
			r.Status = "purged"
			say("purged   %s/%s (nothing to check)", a.NS, t.name)
			results = append(results, r)
			continue
		}
		log, _, err := verify.Resource(ctx, c, a.NS, t.name, t.id, "")
		var pe *verify.PrunedError
		switch {
		case err == nil:
			r.Status, r.Entries = "ok", len(log)
			say("ok       %s/%s: %d entries back to genesis, head %s", a.NS, t.name, len(log), t.id)
		case errors.As(err, &pe):
			r.Status, r.Error = "pruned", err.Error()
			say("pruned   %s/%s: history below the pruning horizon is not served; not checked (%v)", a.NS, t.name, err)
		case errors.As(err, &ve):
			r.Status, r.Error = "mismatch", err.Error()
			bad++
			say("MISMATCH %s/%s: %v", a.NS, t.name, err)
		default:
			return fmt.Errorf("%s/%s: %w", a.NS, t.name, err)
		}
		results = append(results, r)
	}
	return a.report(out, a.NS, a.From, head, len(entries), results, bad)
}

// report ends a verification: the JSON answer with --json, and the error
// that makes the exit status 1 when anything mismatched.
func (a *verifyCmd) report(out io.Writer, ns, from, head string, n int, results []verifyResult, bad int) error {
	if a.JSON {
		m := map[string]any{"ns": ns, "head": head, "entries": n, "resources": results, "ok": bad == 0}
		if from != "" {
			m["from"] = from
		}
		if err := writeJSON(out, m); err != nil {
			return err
		}
	}
	if bad > 0 {
		return fmt.Errorf("verification failed: %d mismatch(es) in %s", bad, ns)
	}
	return nil
}
