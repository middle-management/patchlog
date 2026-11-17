package main

// Client commands: the public API from the shell, as client.Client calls
// (§7). Resources are named NS/NAME. Every write is conditional (§7.2),
// and these commands supply the precondition: put and ns create send
// If-None-Match: *, patch appends to the head it reads (trying again on
// the head a lost race's 412 names, client.AppendLatest) unless --if pins
// one, rm tombstones the head it reads, and ns config patches the config
// revision in force unless --if pins one.
//
// A write prints the new id on stdout, so R=$(patchlog patch …) keeps it,
// and what it did on stderr. --api, --bearer and --author default to
// $PATCHLOG_API, $PATCHLOG_BEARER and $PATCHLOG_AUTHOR.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// clientCommand is a client command: exec writes its output to out and
// what it did to errw.
type clientCommand interface {
	exec(ctx context.Context, out, errw io.Writer) error
}

// runClient runs cmd, interruptible by SIGINT, exiting 1 if it fails.
func runClient(cmd clientCommand) {
	if err := execClient(cmd, os.Stdout, os.Stderr); err != nil {
		toolFatal(err)
	}
}

// execClient runs cmd until it returns or SIGINT, returning its error
// unless it was interrupted.
func execClient(cmd clientCommand, out, errw io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := cmd.exec(ctx, out, errw)
	interrupted := ctx.Err() != nil // before stop, which cancels ctx
	stop()
	if interrupted {
		return nil
	}
	return err
}

// writer returns the client of tf, signing writes with --sign-key if set.
func (tf *toolArgs) writer() *client.Client {
	c := tf.client()
	if k := tf.signer(); k != nil {
		c = c.With(client.WithSigner(*k))
	}
	return c
}

// resourceArg splits NS/NAME.
func resourceArg(s string) (ns, name string, err error) {
	ns, name, ok := strings.Cut(s, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("%q: want NS/NAME", s)
	}
	return ns, name, nil
}

// jsonArg reads a JSON argument: inline, @FILE, or - for stdin.
func jsonArg(s string) (any, error) {
	var b []byte
	var err error
	switch {
	case s == "-":
		b, err = io.ReadAll(os.Stdin)
	case strings.HasPrefix(s, "@"):
		b, err = os.ReadFile(s[1:])
	default:
		b = []byte(s)
	}
	if err != nil {
		return nil, err
	}
	v, err := jsonv.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("JSON argument: %w", err)
	}
	return v, nil
}

// wrote reports a write: as JSON with --json, else the id on out and what
// was done, under which gesture, on errw.
func (tf *toolArgs) wrote(out, errw io.Writer, what, id, nsID, gesture string) error {
	if tf.JSON {
		m := map[string]any{"id": id, "nsId": nsID}
		if gesture != "" {
			m["gesture"] = gesture
		}
		return writeJSON(out, m)
	}
	if gesture != "" {
		fmt.Fprintf(errw, "%s (gesture %s, namespace entry %s)\n", what, gesture, nsID)
	} else {
		fmt.Fprintf(errw, "%s (namespace entry %s)\n", what, nsID)
	}
	fmt.Fprintln(out, id)
	return nil
}

// gestureArgs is --gesture, of the resource writes: each write is a
// user action of its own (a new gesture) that patchlog undo undoes, unless
// --gesture names one several writes share (§7.2, §11.2).
type gestureArgs struct {
	Gesture string `arg:"--gesture" placeholder:"ID" help:"the gesture (user action) the write belongs to, so several writes undo together; default a new one per write, printed with the result"`
}

// gesture returns the gesture of a write and its option.
func (g *gestureArgs) gesture() (string, client.WriteOption) {
	id := g.Gesture
	if id == "" {
		id = client.NewGesture()
	}
	return id, client.WithGesture(id)
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// liveHead returns the head revision of ns/name, an error unless it is
// live.
func liveHead(ctx context.Context, c *client.Client, ns, name string) (string, error) {
	h, err := c.Head(ctx, ns, name)
	if err != nil {
		return "", err
	}
	switch h.State {
	case client.NotFound:
		return "", fmt.Errorf("%s/%s doesn't exist", ns, name)
	case client.Tombstoned:
		return "", fmt.Errorf("%s/%s is deleted (tombstone %s)", ns, name, h.ID)
	case client.Purged:
		return "", fmt.Errorf("%s/%s is purged", ns, name)
	}
	return h.ID, nil
}

// getCmd is patchlog get NS/NAME.
type getCmd struct {
	toolArgs
	encArgs
	Rev      string `arg:"--rev" placeholder:"ID" help:"read this revision (default: the head)"`
	Meta     bool   `arg:"--meta" help:"print the revision id, Last-Modified and Repr-Digest on stderr (an encrypted namespace's revisions have neither: its kid instead)"`
	Follow   bool   `arg:"--follow,-f" help:"keep going: print each new revision as it is written, one line of JSON each (null when the resource is deleted), until interrupted or it is purged (§7.3)"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
}

func (a *getCmd) run(string) { runClient(a) }

func (a *getCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	if a.Follow && a.Rev != "" {
		return errors.New("--follow starts at the head: not with --rev")
	}
	v, err := a.view(ctx, a.client(), ns, name)
	if err != nil {
		return err
	}
	if a.Follow {
		return a.follow(ctx, v, out, errw)
	}
	id := a.Rev
	if id == "" {
		if id, err = liveHead(ctx, v.c, ns, name); err != nil {
			return err
		}
	}
	d, flags, err := v.doc(ctx, id)
	if err != nil {
		return err
	}
	a.meta(errw, d)
	v.warnFlags(errw, flags)
	return writeJSON(out, d.Value)
}

// meta prints d's id, Last-Modified and Repr-Digest (or kid) on errw with
// --meta.
func (a *getCmd) meta(errw io.Writer, d *client.Doc) {
	if !a.Meta {
		return
	}
	fmt.Fprintf(errw, "rev %s", d.ID)
	if !d.Modified.IsZero() {
		fmt.Fprintf(errw, "  modified %s", d.Modified.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if d.Digest != "" {
		fmt.Fprintf(errw, "  digest %s", d.Digest)
	}
	if d.Kid != "" {
		fmt.Fprintf(errw, "  kid %s", d.Kid)
	}
	fmt.Fprintln(errw)
}

// errPurged ends a follow: the resource's stream ends with its purge.
var errPurged = errors.New("purged")

// follow prints ns/name's document, then each revision written after it,
// one line of JSON each, reading its event stream (§7.3) and reconnecting
// from the last event when the stream ends, until ctx is done or the
// resource is purged. A tombstone prints null. A resource that doesn't
// exist yet is waited for. Documents are read through v, so an encrypted
// namespace's are opened, or folded, as get reads them.
func (a *getCmd) follow(ctx context.Context, v *encView, out, errw io.Writer) error {
	c, ns, name := v.c, v.ns, v.name
	line := func(x any) error {
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	doc := func(id string) error {
		d, flags, err := v.doc(ctx, id)
		if err != nil {
			return err
		}
		a.meta(errw, d)
		v.warnFlags(errw, flags)
		return line(d.Value)
	}
	h, err := c.Head(ctx, ns, name)
	if err != nil {
		return err
	}
	since := h.ID
	switch h.State {
	case client.Live:
		err = doc(h.ID)
	case client.Tombstoned:
		fmt.Fprintf(errw, "%s/%s is deleted (tombstone %s); following\n", ns, name, h.ID)
		err = line(nil)
	case client.NotFound:
		fmt.Fprintf(errw, "%s/%s doesn't exist yet; following\n", ns, name)
	case client.Purged:
		return fmt.Errorf("%s/%s is purged", ns, name)
	}
	if err != nil {
		return err
	}
	for {
		err := c.ResourceEvents(ctx, ns, name, since, func(ev client.Event) error {
			switch ev.Type {
			case "revision":
				since = ev.ID
				return doc(ev.ID)
			case "tombstone":
				since = ev.ID
				fmt.Fprintf(errw, "%s/%s deleted (tombstone %s)\n", ns, name, ev.ID)
				return line(nil)
			case "purge":
				return errPurged
			}
			return nil // prune: the document is unchanged
		})
		switch {
		case errors.Is(err, errPurged):
			return fmt.Errorf("%s/%s was purged", ns, name)
		case ctx.Err() != nil:
			return nil
		case err != nil:
			return err
		}
		// The stream ended cleanly (a server restart, a proxy's
		// timeout): resume after the last event.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

// putCmd is patchlog put NS/NAME DOC.
type putCmd struct {
	toolArgs
	encArgs
	gestureArgs
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
	Doc      string `arg:"positional,required" placeholder:"JSON|@FILE|-" help:"the document"`
}

func (a *putCmd) run(string) { runClient(a) }

func (a *putCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	doc, err := jsonArg(a.Doc)
	if err != nil {
		return err
	}
	v, err := a.view(ctx, a.writer(), ns, name)
	if err != nil {
		return err
	}
	_, opt := a.gesture()
	w, err := v.create(ctx, doc, opt)
	if err != nil {
		return err
	}
	return a.wrote(out, errw, "created "+a.Resource, w.ID, w.NSID, w.Gesture)
}

// patchCmd is patchlog patch NS/NAME PATCH.
type patchCmd struct {
	toolArgs
	encArgs
	gestureArgs
	If       string `arg:"--if" placeholder:"ID" help:"append to this revision only, failing (412 stale) if the head has moved; by default to the head, trying again when another writer gets there first"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
	Patch    string `arg:"positional,required" placeholder:"JSON|@FILE|-" help:"a JSON Patch (RFC 6902) array"`
}

func (a *patchCmd) run(string) { runClient(a) }

func (a *patchCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	p, err := jsonArg(a.Patch)
	if err != nil {
		return err
	}
	v, err := a.view(ctx, a.writer(), ns, name)
	if err != nil {
		return err
	}
	g, opt := a.gesture()
	w, err := v.append(ctx, a.If, p, opt)
	if err != nil {
		return err
	}
	if w.Gesture == "" {
		w.Gesture = g
	}
	return a.wrote(out, errw, "appended to "+a.Resource, w.ID, w.NSID, w.Gesture)
}

// rmCmd is patchlog rm NS/NAME.
type rmCmd struct {
	toolArgs
	// --identity is accepted, so command lines and $PATCHLOG_IDENTITY
	// work alike across the commands, and unused: a delete writes no
	// content, at any level (§E.3).
	encArgs
	gestureArgs
	If       string `arg:"--if" placeholder:"ID" help:"delete only if this is the head, failing (412 stale) otherwise; by default the head"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
}

func (a *rmCmd) run(string) { runClient(a) }

func (a *rmCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	c := a.writer()
	head := a.If
	if head == "" {
		if head, err = liveHead(ctx, c, ns, name); err != nil {
			return err
		}
	}
	_, opt := a.gesture()
	w, err := c.Delete(ctx, ns, name, head, opt)
	if err != nil {
		return err
	}
	return a.wrote(out, errw, "deleted "+a.Resource, w.ID, w.NSID, w.Gesture)
}

// logCmd is patchlog log NS/NAME.
type logCmd struct {
	toolArgs
	encArgs
	Since    string `arg:"--since" placeholder:"ID" help:"only the entries after this revision"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
}

func (a *logCmd) run(string) { runClient(a) }

func (a *logCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	v, err := a.view(ctx, a.client(), ns, name)
	if err != nil {
		return err
	}
	es, flags, err := v.log(ctx, a.Since)
	if err != nil {
		return err
	}
	for i, e := range es {
		if a.JSON {
			raw := e.Raw
			if v.e2e() {
				raw = openedRaw(e, flags[i])
			}
			b, _ := json.Marshal(raw)
			fmt.Fprintln(out, string(b))
			continue
		}
		line := fmt.Sprintf("%s  %-9s  %-10s  %s", e.ID, e.Kind, e.Author, e.Created)
		if e.HasPatches {
			p, _ := json.Marshal(e.Patches)
			line += "  " + string(p)
		}
		if flags[i] != "" {
			line += "  (flagged: " + flags[i] + ")"
		}
		fmt.Fprintln(out, line)
	}
	return nil
}

// nsEntryLine is the line patchlog ns log and watch print for e.
func nsEntryLine(e client.NSEntry) string {
	return strings.TrimRight(fmt.Sprintf("%s  %-9s  %-16s  %-33s  %s", e.ID, e.Kind, e.Resource, e.Target, e.Author), " ")
}

// watchCmd is patchlog watch NS.
type watchCmd struct {
	toolArgs
	Since string `arg:"--since" placeholder:"ID" help:"start after this namespace entry (default: from the first)"`
	NS    string `arg:"positional,required"`
}

func (a *watchCmd) run(string) { runClient(a) }

func (a *watchCmd) exec(ctx context.Context, out, errw io.Writer) error {
	return a.client().NSEvents(ctx, a.NS, a.Since, func(e client.NSEntry) error {
		if a.JSON {
			b, _ := json.Marshal(e.Raw)
			_, err := fmt.Fprintln(out, string(b))
			return err
		}
		_, err := fmt.Fprintln(out, nsEntryLine(e))
		return err
	})
}

// nsCmd is patchlog ns.
type nsCmd struct {
	Create *nsCreateCmd `arg:"subcommand:create" help:"create a namespace"`
	Get    *nsGetCmd    `arg:"subcommand:get" help:"print the namespace document in force"`
	Config *nsConfigCmd `arg:"subcommand:config" help:"patch the namespace document (its config)"`
	Log    *nsLogCmd    `arg:"subcommand:log" help:"print the namespace log"`
}

type nsCreateCmd struct {
	toolArgs
	NS  string `arg:"positional,required"`
	Doc string `arg:"positional" default:"{}" placeholder:"JSON|@FILE|-" help:"the namespace document"`
}

func (a *nsCreateCmd) run(string) { runClient(a) }

func (a *nsCreateCmd) exec(ctx context.Context, out, errw io.Writer) error {
	doc, err := jsonArg(a.Doc)
	if err != nil {
		return err
	}
	r, err := a.client().CreateNamespace(ctx, a.NS, doc)
	if err != nil {
		return err
	}
	return a.wrote(out, errw, "created namespace "+a.NS, r.Config, r.NSID, "")
}

type nsGetCmd struct {
	toolArgs
	At string `arg:"--at" placeholder:"ID" help:"the document in force at this namespace entry (default: the head)"`
	NS string `arg:"positional,required"`
}

func (a *nsGetCmd) run(string) { runClient(a) }

func (a *nsGetCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.client()
	at := a.At
	if at == "" {
		h, err := c.NSHead(ctx, a.NS)
		if err != nil {
			return err
		}
		at = h.ID
	}
	d, err := c.NSDoc(ctx, a.NS, at)
	if err != nil {
		return err
	}
	return writeJSON(out, d.Value)
}

type nsConfigCmd struct {
	toolArgs
	If    string `arg:"--if" placeholder:"CONFIG" help:"patch this config revision only, failing (412 stale) if another is in force; by default the one in force"`
	NS    string `arg:"positional,required"`
	Patch string `arg:"positional,required" placeholder:"JSON|@FILE|-" help:"a JSON Patch of the namespace document"`
}

func (a *nsConfigCmd) run(string) { runClient(a) }

func (a *nsConfigCmd) exec(ctx context.Context, out, errw io.Writer) error {
	p, err := jsonArg(a.Patch)
	if err != nil {
		return err
	}
	c := a.client()
	cfg := a.If
	if cfg == "" {
		h, err := c.NSHead(ctx, a.NS)
		if err != nil {
			return err
		}
		cfg = h.Config
	}
	r, err := c.PatchConfig(ctx, a.NS, cfg, p)
	if err != nil {
		return err
	}
	return a.wrote(out, errw, "patched the config of "+a.NS, r.Config, r.NSID, "")
}

type nsLogCmd struct {
	toolArgs
	Since string `arg:"--since" placeholder:"ID" help:"only the entries after this one"`
	NS    string `arg:"positional,required"`
}

func (a *nsLogCmd) run(string) { runClient(a) }

func (a *nsLogCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.client()
	h, err := c.NSHead(ctx, a.NS)
	if err != nil {
		return err
	}
	es, err := c.NSLog(ctx, a.NS, h.ID, a.Since)
	if err != nil {
		return err
	}
	for _, e := range es {
		if a.JSON {
			b, _ := json.Marshal(e.Raw)
			fmt.Fprintln(out, string(b))
			continue
		}
		fmt.Fprintln(out, nsEntryLine(e))
	}
	return nil
}
