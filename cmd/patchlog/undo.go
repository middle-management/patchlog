package main

// patchlog undo, redo and branch: client commands over client.Undo,
// client.Redo, client.UndoStack and client.CreateBranch.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
)

// undoArgs are the flags undo and redo share.
type undoArgs struct {
	toolArgs
	Of        string   `arg:"--of" placeholder:"AUTHOR" help:"whose stack, without GESTURE (default: the root sub of --bearer, else --author); with GESTURE, whose writes of it to undo (default: the author of its first revision found)"`
	Since     string   `arg:"--since" placeholder:"ID" help:"look for the gesture, or build the stack, after this namespace entry only (default: the whole log)"`
	Resources []string `arg:"--resource,separate" placeholder:"NAME" help:"a document the action touched, for a grant that can read neither the gesture listing nor the namespace log (§C.5); repeatable"`
	NS        string   `arg:"positional,required"`
	Gesture   string   `arg:"positional" help:"the gesture to act on (default: the last of the author's stack)"`
}

// options are the client.UndoOption of the flags.
func (a *undoArgs) options() []client.UndoOption {
	var opts []client.UndoOption
	if a.Of != "" && a.Gesture != "" {
		opts = append(opts, client.UndoAuthor(a.Of))
	}
	if a.Since != "" {
		opts = append(opts, client.UndoSince(a.Since))
	}
	if len(a.Resources) > 0 {
		opts = append(opts, client.UndoResources(a.Resources...))
	}
	return opts
}

// stack returns the undo stack of --of, or of the caller.
func (a *undoArgs) stack(ctx context.Context, c *client.Client) (*client.UndoStack, error) {
	who := a.Of
	if who == "" {
		who = whoAmI(&a.toolArgs)
	}
	if who == "" {
		return nil, errors.New("whose stack? give GESTURE, --of, --author or --bearer")
	}
	var opts []client.UndoOption
	if a.Since != "" {
		opts = append(opts, client.UndoSince(a.Since))
	}
	if len(a.Resources) > 0 {
		opts = append(opts, client.UndoResources(a.Resources...))
	}
	return c.UndoStack(ctx, a.NS, who, opts...)
}

// resolve finds gesture g on the stack, as the action it names or as one
// of its undos and redos (its Chain), so that GESTURE may be the action
// the user saw written: done reports whether the action stands, target is
// the gesture to undo (the latest redo of it, or the undo whose undo
// redoes it). ok is false when the stack can't be read or doesn't hold g.
func (a *undoArgs) resolve(ctx context.Context, c *client.Client, g string) (target string, done, ok bool) {
	st, err := a.stack(ctx, c)
	if err != nil {
		return "", false, false
	}
	for _, l := range []struct {
		items []client.StackItem
		done  bool
	}{{st.Done, true}, {st.Undone, false}} {
		for _, it := range l.items {
			if it.Gesture == g || it.Target == g || slices.Contains(it.Chain, g) {
				return it.Target, l.done, true
			}
		}
	}
	return "", false, false
}

// undid reports an undo or redo.
func (a *undoArgs) undid(out, errw io.Writer, what, action string, r *client.UndoResult) error {
	var names []string
	for _, res := range r.Plan.Resources {
		names = append(names, res.Resource)
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"gesture": r.Gesture, "action": action, "target": r.Plan.Gesture, "author": r.Plan.Author,
			"resources": names, "nsId": r.Batch.NSID})
	}
	fmt.Fprintf(errw, "%s %s by %s: %s (gesture %s, namespace entry %s)\n", what, action, r.Plan.Author, strings.Join(names, ", "), r.Gesture, r.Batch.NSID)
	fmt.Fprintln(out, r.Gesture)
	return nil
}

// undoCmd is patchlog undo NS [GESTURE].
type undoCmd struct {
	undoArgs
	Plan bool `arg:"--plan" help:"print the inverse and its conflicts; write nothing"`
	List bool `arg:"--list" help:"print the author's stack: actions done (the last is what undo undoes) and undone (the last is what redo redoes)"`
}

func (a *undoCmd) run(string) { runClient(a) }

func (a *undoCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.writer()
	if a.List {
		st, err := a.stack(ctx, c)
		if err != nil {
			return err
		}
		return printStack(out, st, a.JSON)
	}
	g, action := a.Gesture, a.Gesture
	if g != "" {
		if t, done, ok := a.resolve(ctx, c, g); ok && !done {
			return fmt.Errorf("%s is undone already: patchlog redo %s %s redoes it", g, a.NS, g)
		} else if ok {
			g = t
		}
	} else {
		st, err := a.stack(ctx, c)
		if err != nil {
			return err
		}
		if len(st.Done) == 0 {
			return fmt.Errorf("%s has nothing to undo in %s", st.Author, a.NS)
		}
		g, action = st.Done[len(st.Done)-1].Target, st.Done[len(st.Done)-1].Gesture
	}
	if a.Plan {
		p, err := c.PlanUndo(ctx, a.NS, g, a.options()...)
		if err != nil {
			return err
		}
		return printUndoPlan(out, p, a.JSON)
	}
	r, err := c.Undo(ctx, a.NS, g, a.options()...)
	if err != nil {
		return err
	}
	return a.undid(out, errw, "undid", action, r)
}

// redoCmd is patchlog redo NS [GESTURE].
type redoCmd struct {
	undoArgs
}

func (a *redoCmd) run(string) { runClient(a) }

func (a *redoCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.writer()
	var r *client.UndoResult
	var err error
	action := a.Gesture
	if a.Gesture != "" {
		if t, done, ok := a.resolve(ctx, c, a.Gesture); ok && done {
			return fmt.Errorf("%s stands: nothing to redo", a.Gesture)
		} else if ok {
			// Undoing the undo redoes it (§11.2 Redo).
			r, err = c.Undo(ctx, a.NS, t, a.options()...)
		} else {
			r, err = c.Redo(ctx, a.NS, a.Gesture, a.options()...)
		}
	} else {
		st, serr := a.stack(ctx, c)
		if serr != nil {
			return serr
		}
		if len(st.Undone) == 0 {
			return fmt.Errorf("%s has nothing to redo in %s", st.Author, a.NS)
		}
		// Undoing the author's undo of the action redoes it (§11.2 Redo).
		it := st.Undone[len(st.Undone)-1]
		action = it.Gesture
		r, err = c.Undo(ctx, a.NS, it.Target, a.options()...)
	}
	if errors.Is(err, client.ErrNotUndone) {
		return fmt.Errorf("%s: nobody undid it, so there is nothing to redo", a.Gesture)
	}
	if err != nil {
		return err
	}
	return a.undid(out, errw, "redid", action, r)
}

// printStack prints an undo stack, the most recent last in each list.
func printStack(out io.Writer, st *client.UndoStack, asJSON bool) error {
	item := func(it client.StackItem) map[string]any {
		return map[string]any{"gesture": it.Gesture, "target": it.Target, "resources": it.Resources, "created": it.Created}
	}
	if asJSON {
		done, undone := []any{}, []any{}
		for _, it := range st.Done {
			done = append(done, item(it))
		}
		for _, it := range st.Undone {
			undone = append(undone, item(it))
		}
		return writeJSON(out, map[string]any{"author": st.Author, "done": done, "undone": undone})
	}
	for _, l := range []struct {
		name  string
		items []client.StackItem
	}{{"done", st.Done}, {"undone", st.Undone}} {
		fmt.Fprintf(out, "%s (%d):\n", l.name, len(l.items))
		for _, it := range l.items {
			line := fmt.Sprintf("  %s  %s  %s", it.Gesture, it.Created, strings.Join(it.Resources, ", "))
			if it.Target != it.Gesture {
				line += "  (as " + it.Target + ")"
			}
			fmt.Fprintln(out, line)
		}
	}
	return nil
}

// printUndoPlan prints what undo would write, and what stops it.
func printUndoPlan(out io.Writer, p *client.UndoPlan, asJSON bool) error {
	if asJSON {
		var res []any
		for _, r := range p.Resources {
			res = append(res, map[string]any{"resource": r.Resource, "head": r.Head, "deleted": r.Deleted, "doc": r.Doc, "steps": len(r.Steps)})
		}
		var cs []string
		for _, c := range p.Conflicts {
			cs = append(cs, c.String())
		}
		return writeJSON(out, map[string]any{"gesture": p.Gesture, "author": p.Author, "resources": res, "conflicts": cs})
	}
	fmt.Fprintf(out, "undo of %s by %s in %s:\n", p.Gesture, p.Author, p.NS)
	for _, r := range p.Resources {
		switch {
		case r.Deleted:
			fmt.Fprintf(out, "  %s: deleted again\n", r.Resource)
		case r.State == client.Tombstoned:
			fmt.Fprintf(out, "  %s: restored\n", r.Resource)
		default:
			fmt.Fprintf(out, "  %s: %s\n", r.Resource, strings.Join(r.Writes, ", "))
		}
	}
	for _, c := range p.Conflicts {
		fmt.Fprintf(out, "  CONFLICT %s\n", c.String())
	}
	if len(p.Conflicts) > 0 {
		return p.Err()
	}
	return nil
}

// branchCmd is patchlog branch.
type branchCmd struct {
	Create *branchCreateCmd `arg:"subcommand:create" help:"create a branch of a namespace (§7.6)"`
	List   *branchListCmd   `arg:"subcommand:list" help:"list a namespace's branches"`
}

type branchCreateCmd struct {
	toolArgs
	At    string `arg:"--at" placeholder:"ID" help:"the base's namespace entry the branch starts at (default: its head)"`
	Patch string `arg:"--patch" placeholder:"JSON|@FILE|-" help:"a JSON Patch of the branch's namespace document, applied to the copy of the base's"`
	Base  string `arg:"positional,required" placeholder:"BASE"`
	Name  string `arg:"positional,required" help:"the branch's name"`
}

func (a *branchCreateCmd) run(string) { runClient(a) }

func (a *branchCreateCmd) exec(ctx context.Context, out, errw io.Writer) error {
	br := client.BranchRequest{Name: a.Name, At: a.At}
	if a.Patch != "" {
		p, err := jsonArg(a.Patch)
		if err != nil {
			return err
		}
		br.Patches = p
	}
	r, err := a.writer().CreateBranch(ctx, a.Base, br)
	if err != nil {
		return err
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"name": r.Name, "config": r.Config, "nsId": r.NSID})
	}
	fmt.Fprintf(errw, "created branch %s of %s (namespace entry %s in %s)\n", r.Name, a.Base, r.NSID, a.Base)
	fmt.Fprintln(out, r.Name)
	return nil
}

type branchListCmd struct {
	toolArgs
	Base string `arg:"positional,required" placeholder:"BASE"`
}

func (a *branchListCmd) run(string) { runClient(a) }

func (a *branchListCmd) exec(ctx context.Context, out, errw io.Writer) error {
	bs, err := a.client().Branches(ctx, a.Base)
	if err != nil {
		return err
	}
	for _, b := range bs {
		if a.JSON {
			if err := writeJSON(out, b.Raw); err != nil {
				return err
			}
			continue
		}
		var notes []string
		if b.Frozen {
			notes = append(notes, "frozen")
		}
		if b.Purged {
			notes = append(notes, "purged")
		}
		if b.Successor != "" {
			notes = append(notes, "successor "+b.Successor)
		}
		if len(b.Drafts) > 0 {
			notes = append(notes, "drafts for "+strings.Join(b.Drafts, ","))
		}
		fmt.Fprintln(out, strings.TrimRight(fmt.Sprintf("%-20s  %s  %s", b.Name, b.At, strings.Join(notes, ", ")), " "))
	}
	return nil
}
