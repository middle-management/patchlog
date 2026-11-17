package main

// Everyday resource commands: ls, restore, batch, whoami, validate, and
// the destructive purge and prune (also ns purge), as client.Client calls
// (§7, §8). The conventions are client.go's: NS/NAME arguments, the new id
// on stdout, what was done on stderr, --json for scripts.
//
// The destructive commands (purge, prune, ns purge) never destroy without
// --yes: without it they print exactly what they would destroy, and exit 1.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// lsCmd is patchlog ls NS [PREFIX].
type lsCmd struct {
	toolArgs
	NS     string `arg:"positional,required"`
	Prefix string `arg:"positional" placeholder:"PREFIX" help:"only the resources whose names start with this"`
}

func (a *lsCmd) run(string) { runClient(a) }

func (a *lsCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.client()
	h, err := c.NSHead(ctx, a.NS)
	if err != nil {
		return err
	}
	items, err := c.HeadsPrefix(ctx, a.NS, h.ID, a.Prefix)
	if err != nil {
		return err
	}
	if a.JSON {
		rows := make([]map[string]any, 0, len(items))
		for _, it := range items {
			m := map[string]any{"resource": it.Resource, "kind": it.Kind, "target": it.Target}
			if it.Created != "" {
				m["created"] = it.Created
			}
			if it.Size > 0 {
				m["size"] = it.Size
			}
			if it.Digest != "" {
				m["digest"] = it.Digest
			}
			rows = append(rows, m)
		}
		return writeJSON(out, rows)
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, it := range items {
		kind := it.Kind
		switch kind {
		case "head":
			kind = "live"
		case "purge":
			kind = "purged"
		}
		size := "-"
		if it.Size > 0 {
			size = fmt.Sprint(it.Size)
		}
		created := it.Created
		if created == "" {
			created = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", it.Resource, kind, it.Target, created, size)
	}
	return tw.Flush()
}

// restoreCmd is patchlog restore NS/NAME [PATCH].
type restoreCmd struct {
	toolArgs
	gestureArgs
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
	Patch    string `arg:"positional" default:"[]" placeholder:"JSON|@FILE|-" help:"a JSON Patch (RFC 6902) applied to the last live document as it is restored (default: [], unchanged)"`
}

func (a *restoreCmd) run(string) { runClient(a) }

func (a *restoreCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	p, err := jsonArg(a.Patch)
	if err != nil {
		return err
	}
	if _, ok := p.([]any); !ok {
		return errors.New("the patch must be a JSON array (RFC 6902)")
	}
	c := a.writer()
	h, err := c.Head(ctx, ns, name)
	if err != nil {
		return err
	}
	switch h.State {
	case client.NotFound:
		return fmt.Errorf("%s doesn't exist", a.Resource)
	case client.Live:
		return fmt.Errorf("%s isn't deleted (it is live at %s): nothing to restore", a.Resource, h.ID)
	case client.Purged:
		return fmt.Errorf("%s is purged: nothing is left to restore", a.Resource)
	}
	g, opt := a.gesture()
	w, err := c.Restore(ctx, ns, name, h.ID, p, opt)
	if err != nil {
		return err
	}
	if w.Gesture == "" {
		w.Gesture = g
	}
	return a.wrote(out, errw, "restored "+a.Resource, w.ID, w.NSID, w.Gesture)
}

// batchCmd is patchlog batch NS FILE|-.
type batchCmd struct {
	toolArgs
	gestureArgs
	DryRun bool   `arg:"--dry-run" help:"write nothing: report the ids a submit would produce, and any failure it would meet"`
	NS     string `arg:"positional,required"`
	File   string `arg:"positional,required" placeholder:"FILE|-" help:"the batch as JSON (- for stdin), the body of POST /ns/{ns}/batch (§7.5): {\"items\":[{\"resource\":NAME, \"ifNoneMatch\":\"*\" or \"ifMatch\":REV, \"steps\":[PATCH | \"delete\" | {\"patches\":PATCH,\"gesture\":G}]}], \"config\":{\"ifMatch\":CONFIG,\"patches\":PATCH}, \"gesture\":G}; each item needs exactly one of ifNoneMatch (create) and ifMatch (append); the batch is atomic"`
}

// The input of patchlog batch, documented here and in the flag help:
const _ = `The batch is a JSON object, the body of POST /ns/{ns}/batch (§7.5):

  {
    "items": [
      { "resource": "a", "ifNoneMatch": "*",          // create ...
        "steps": [ [ {"op":"add","path":"","value":{"n":1}} ] ] },
      { "resource": "b", "ifMatch": "REV",            // ... or append to REV
        "steps": [ [ {"op":"replace","path":"/n","value":2} ],  // a JSON Patch
                   "delete",                                    // a tombstone
                   { "patches": [ ... ], "gesture": "G" } ] }   // a step with options
    ],
    "config": { "ifMatch": "CONFIG", "patches": [ ... ] },      // optional
    "gesture": "G", "undoes": "G2", "source": { ... }           // optional
  }

Every item has "resource", exactly one of "ifMatch" (a revision) and
"ifNoneMatch" ("*", to create), and "steps": each a JSON Patch array, the
string "delete", or an object with "patches" (or "delete": true) and
"gesture", "undoes", "signature". Items may also carry "gesture" and
"undoes". Without --gesture and no "gesture" in the file, the batch is one
new gesture, so patchlog undo undoes it whole. The batch is atomic: if any
item fails none is written, and each failing item is printed.`

func (a *batchCmd) run(string) { runClient(a) }

func (a *batchCmd) exec(ctx context.Context, out, errw io.Writer) error {
	var b []byte
	var err error
	if a.File == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(a.File)
	}
	if err != nil {
		return err
	}
	v, err := jsonv.Parse(b)
	if err != nil {
		return fmt.Errorf("%s: %w", a.File, err)
	}
	req, err := batchRequest(v)
	if err != nil {
		return fmt.Errorf("%s: %w", a.File, err)
	}
	g := req.Gesture
	if g == "" {
		g, _ = a.gesture()
		req.Gesture = g
	}
	c := a.writer()
	res, err := c.Batch(ctx, a.NS, req, a.DryRun)
	if err != nil {
		return err
	}
	items := make([]map[string]any, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, map[string]any{"resource": it.Resource, "ids": it.IDs})
	}
	if a.DryRun {
		if ce := res.ConfigError(); ce != nil {
			return fmt.Errorf("a submit would fail changing the config: %w", ce)
		}
		if a.JSON {
			m := map[string]any{"dryRun": true, "items": items}
			if res.ConfigReport != nil {
				m["config"] = res.ConfigReport
			}
			return writeJSON(out, m)
		}
		fmt.Fprintf(errw, "dry run: nothing written; a submit to %s would write %d items\n", a.NS, len(res.Items))
		if res.ConfigReport != nil {
			fmt.Fprintf(errw, "  config -> %v\n", res.ConfigReport["config"])
		}
		for _, it := range res.Items {
			fmt.Fprintf(out, "%s  %s\n", it.Resource, strings.Join(it.IDs, " "))
		}
		return nil
	}
	if a.JSON {
		m := map[string]any{"nsId": res.NSID, "gesture": g, "items": items}
		if res.Config != "" {
			m["config"] = res.Config
		}
		return writeJSON(out, m)
	}
	for _, it := range res.Items {
		fmt.Fprintf(errw, "  %s  %s\n", it.Resource, strings.Join(it.IDs, " "))
	}
	if res.Config != "" {
		fmt.Fprintf(errw, "  config  %s\n", res.Config)
	}
	fmt.Fprintf(errw, "wrote %d items to %s (gesture %s)\n", len(res.Items), a.NS, g)
	fmt.Fprintln(out, res.NSID)
	return nil
}

// batchRequest reads the JSON form of a batch (batchHelp) into a request.
func batchRequest(v any) (client.BatchRequest, error) {
	var req client.BatchRequest
	m, ok := v.(map[string]any)
	if !ok {
		return req, errors.New("the batch must be a JSON object")
	}
	if err := onlyKeys("the batch", m, "items", "config", "source", "gesture", "undoes"); err != nil {
		return req, err
	}
	req.Gesture, _ = m["gesture"].(string)
	req.Undoes, _ = m["undoes"].(string)
	if src, ok := m["source"]; ok {
		sm, ok := src.(map[string]any)
		if !ok {
			return req, errors.New(`"source" must be an object`)
		}
		req.Source = sm
	}
	if c, ok := m["config"]; ok {
		cm, ok := c.(map[string]any)
		if !ok {
			return req, errors.New(`"config" must be an object`)
		}
		if err := onlyKeys(`"config"`, cm, "ifMatch", "patches"); err != nil {
			return req, err
		}
		if _, ok := cm["patches"].([]any); !ok {
			return req, errors.New(`"config" needs "patches", a JSON Patch array`)
		}
		ifm, _ := cm["ifMatch"].(string)
		req.Config = &client.BatchConfig{IfMatch: ifm, Patches: cm["patches"]}
	}
	items, _ := m["items"].([]any)
	if _, ok := m["items"]; ok && items == nil {
		return req, errors.New(`"items" must be an array`)
	}
	if len(items) == 0 && req.Config == nil {
		return req, errors.New(`the batch has no "items" and no "config"`)
	}
	for i, x := range items {
		im, ok := x.(map[string]any)
		if !ok {
			return req, fmt.Errorf("item %d: not an object", i)
		}
		where := fmt.Sprintf("item %d", i)
		if err := onlyKeys(where, im, "resource", "ifMatch", "ifNoneMatch", "steps", "gesture", "undoes"); err != nil {
			return req, err
		}
		var it client.BatchItem
		if it.Resource, _ = im["resource"].(string); it.Resource == "" {
			return req, fmt.Errorf(`%s: no "resource"`, where)
		}
		where = fmt.Sprintf("item %d (%s)", i, it.Resource)
		it.IfMatch, _ = im["ifMatch"].(string)
		switch n := im["ifNoneMatch"].(type) {
		case nil:
		case string:
			if n != "*" {
				return req, fmt.Errorf(`%s: "ifNoneMatch" is "*"`, where)
			}
			it.IfNoneMatch = true
		case bool:
			it.IfNoneMatch = n
		default:
			return req, fmt.Errorf(`%s: "ifNoneMatch" is "*"`, where)
		}
		if (it.IfMatch != "") == it.IfNoneMatch {
			return req, fmt.Errorf(`%s: give exactly one of "ifMatch" and "ifNoneMatch"`, where)
		}
		it.Gesture, _ = im["gesture"].(string)
		it.Undoes, _ = im["undoes"].(string)
		steps, _ := im["steps"].([]any)
		if len(steps) == 0 {
			return req, fmt.Errorf(`%s: no "steps"`, where)
		}
		for j, sv := range steps {
			st, err := batchStep(sv)
			if err != nil {
				return req, fmt.Errorf("%s, step %d: %w", where, j, err)
			}
			it.Steps = append(it.Steps, st)
		}
		req.Items = append(req.Items, it)
	}
	return req, nil
}

// batchStep reads a step: a patch array, "delete", or an object.
func batchStep(v any) (client.Step, error) {
	switch s := v.(type) {
	case string:
		if s != "delete" {
			return client.Step{}, fmt.Errorf(`a string step is "delete", not %q`, s)
		}
		return client.DeleteStep(), nil
	case []any:
		return client.PatchStep(s), nil
	case map[string]any:
		if err := onlyKeys("a step", s, "patches", "delete", "gesture", "undoes", "signature"); err != nil {
			return client.Step{}, err
		}
		var st client.Step
		del, _ := s["delete"].(bool)
		p, hasPatches := s["patches"].([]any)
		if del == hasPatches {
			return st, errors.New(`a step object has "patches" or "delete": true`)
		}
		st.Delete, st.Patches = del, p
		st.Gesture, _ = s["gesture"].(string)
		st.Undoes, _ = s["undoes"].(string)
		st.Signature, _ = s["signature"].(string)
		return st, nil
	}
	return client.Step{}, errors.New(`a step is a JSON Patch array, "delete", or an object`)
}

// onlyKeys is an error if m has a key other than keys: a typo that would
// otherwise be ignored.
func onlyKeys(what string, m map[string]any, keys ...string) error {
	for k := range m {
		known := false
		for _, w := range keys {
			known = known || k == w
		}
		if !known {
			return fmt.Errorf("%s: unknown member %q (want %s)", what, k, strings.Join(keys, ", "))
		}
	}
	return nil
}

// whoamiCmd is patchlog whoami [NS].
type whoamiCmd struct {
	toolArgs
	NS string `arg:"positional" help:"also ask this namespace what the grant can do there"`
}

func (a *whoamiCmd) run(string) { runClient(a) }

func (a *whoamiCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.client()
	if a.NS != "" {
		p, err := c.NSPrincipal(ctx, a.NS)
		if err != nil {
			return err
		}
		if a.JSON {
			return writeJSON(out, p.Raw)
		}
		if p.Principal == nil {
			fmt.Fprintln(out, "authentication is disabled: every request is allowed")
		} else {
			fmt.Fprintf(out, "sub       %s\nkid       %s\n", p.Sub, dash(p.Kid))
		}
		if p.Key != "" {
			fmt.Fprintf(out, "key       %s\n", p.Key)
		}
		fmt.Fprintf(out, "operator  %v\ncan       %s\nroles     %s\nconfig    %s\n",
			p.Operator, dash(strings.Join(p.Can, " ")), dash(strings.Join(p.Roles, " ")), p.Config)
		w := p.Writer
		fmt.Fprintf(out, "namespace %s: level %s, frozen %v", a.NS, dash(w.Level), w.Frozen)
		if w.NonceRequired {
			fmt.Fprint(out, ", nonces required")
		}
		if w.SignaturesRequired {
			fmt.Fprint(out, ", signatures required")
		}
		fmt.Fprintln(out)
		return nil
	}
	root, err := c.Root(ctx)
	if err != nil {
		return err
	}
	sub, kid, err := c.Principal(ctx)
	if err != nil {
		return err
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"sub": sub, "kid": kid, "authDisabled": root.AuthDisabled()})
	}
	if root.AuthDisabled() {
		fmt.Fprintf(errw, "%s has authentication disabled: any request is allowed, and the author name (--author) names you\n", c.BaseURL())
	}
	if sub == "" {
		fmt.Fprintln(errw, "no grant: give --bearer (or $PATCHLOG_BEARER)")
	}
	fmt.Fprintf(out, "sub  %s\nkid  %s\n", dash(sub), dash(kid))
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// validateCmd is patchlog validate NS/NAME DOC.
type validateCmd struct {
	toolArgs
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
	Doc      string `arg:"positional,required" placeholder:"JSON|@FILE|-" help:"the document to check"`
}

func (a *validateCmd) run(string) { runClient(a) }

// exec checks the document as a write of it to NS would (§6.2 step 5): by
// the schema its top-level $schema names, which the namespace resolves as
// it does for a write, among drafts in its branches if NS is a branch
// (§6.1). A document without $schema isn't validated by the server; here
// the one the resource's head names is used, if it has one, and the
// document is refused otherwise, since there is nothing to check.
func (a *validateCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	doc, err := jsonArg(a.Doc)
	if err != nil {
		return err
	}
	c := a.client()
	m, _ := doc.(map[string]any)
	if m == nil {
		return errors.New("the document must be a JSON object")
	}
	if _, typed := m["$schema"]; !typed {
		h, d, err := c.Load(ctx, ns, name)
		if err != nil {
			return err
		}
		s := ""
		if h.State == client.Live {
			s, _ = d.Value.(map[string]any)["$schema"].(string)
		}
		if s == "" {
			return fmt.Errorf("the document has no $schema, and %s has none to fall back on: nothing to check it against", a.Resource)
		}
		fmt.Fprintf(errw, "the document has no $schema (the server wouldn't check it); checking against the head's, %s\n", s)
		m = shallowCopy(m)
		m["$schema"] = s
		doc = m
	}
	// A branch resolves schema revisions drafted in its branches too,
	// as its write gate does (§6.1); best effort, as for E2E.Validate.
	drafts, _ := c.IsBranch(ctx, ns)
	res := client.NewSchemaResolver(c, client.ResolveOptions{Drafts: drafts, For: ns})
	err = schema.NewValidator().Validate(doc, res.Loader(ctx))
	if err == nil {
		fmt.Fprintf(errw, "valid\n")
		if a.JSON {
			return writeJSON(out, map[string]any{"valid": true})
		}
		return nil
	}
	var ve *schema.ValidationError
	if errors.As(err, &ve) {
		if a.JSON {
			if err := writeJSON(out, map[string]any{"valid": false, "errors": ve.Errors}); err != nil {
				return err
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s: the document is invalid:", a.Resource)
		for _, d := range ve.Errors {
			p := d.Pointer
			if p == "" {
				p = "(document)"
			}
			fmt.Fprintf(&b, "\n  %s: %s", p, d.Message)
		}
		return errors.New(b.String())
	}
	var ue *schema.UnavailableError
	if errors.Is(err, schema.ErrUnavailable) || errors.As(err, &ue) {
		return fmt.Errorf("a schema the document names isn't available (unknown, purged, or not readable by you): %w", err)
	}
	return err
}

func shallowCopy(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+1)
	for k, v := range m {
		c[k] = v
	}
	return c
}

// printRaw writes the bytes of the raw file d, a revision of ns/name
// (Addendum H), to out; binary bytes aren't written to a terminal.
func printRaw(ctx context.Context, c *client.Client, ns, name string, d *client.Doc, out io.Writer) error {
	bid, err := c.Raw(ctx, ns, name, d.ID)
	if err != nil {
		if client.IsNotFound(err) {
			return fmt.Errorf("%s/%s isn't a raw file: its document is not a single blob reference (Addendum H)", ns, name)
		}
		return err
	}
	nonce := ""
	if ref, ok := d.Value.(map[string]any); ok {
		nonce, _ = ref["nonce"].(string)
	}
	b, err := c.GetBlob(ctx, ns, name, bid, nonce)
	if err != nil {
		return err
	}
	if out == io.Writer(os.Stdout) && isTerminal(os.Stdout) && (!utf8.Valid(b.Data) || strings.ContainsRune(string(b.Data), 0)) {
		return fmt.Errorf("the file (%s, %d bytes) is binary and stdout is a terminal: redirect it", b.Type, len(b.Data))
	}
	_, err = out.Write(b.Data)
	return err
}

// yesArgs is --yes, of the commands that destroy data.
type yesArgs struct {
	Yes bool `arg:"--yes" help:"really do it: without this, only print what would be destroyed (and exit 1)"`
}

// refuse prints what a destructive command would do on errw, and returns
// the error that makes it exit 1 without --yes.
func refuse(errw io.Writer, what string) error {
	fmt.Fprintln(errw, what)
	return errors.New("nothing was destroyed: this cannot be undone; add --yes to do it")
}

// purgeCmd is patchlog purge NS/NAME.
type purgeCmd struct {
	toolArgs
	yesArgs
	Force    bool   `arg:"--force" help:"purge a schema that other documents reference, which leaves them unvalidatable (needs a grant chained to a * key)"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
}

func (a *purgeCmd) run(string) { runClient(a) }

func (a *purgeCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	c := a.writer()
	h, err := c.Head(ctx, ns, name)
	if err != nil {
		return err
	}
	switch h.State {
	case client.NotFound:
		return fmt.Errorf("%s doesn't exist", a.Resource)
	case client.Purged:
		return fmt.Errorf("%s is already purged", a.Resource)
	}
	if !a.Yes {
		es, horizon, err := retainedLog(ctx, c, ns, name)
		if err != nil {
			return err
		}
		n := len(es)
		if horizon != "" {
			n++
		}
		state := "live"
		if h.State == client.Tombstoned {
			state = "deleted"
		}
		return refuse(errw, fmt.Sprintf("would purge %s (%s, head %s): its %d retained log entries, every revision and the blobs only it references, for good; its name stays 410 purged", a.Resource, state, h.ID, n))
	}
	nsID, err := c.Purge(ctx, ns, name, h.ID, a.Force)
	if err != nil {
		return err
	}
	return a.wrote(out, errw, "purged "+a.Resource, nsID, nsID, "")
}

// retainedLog is the log of ns/name still served: all of it, or, for a
// resource pruned before, the entries after its horizon, which is returned
// ("" if never pruned) and is itself retained as the first revision.
func retainedLog(ctx context.Context, c *client.Client, ns, name string) (es []client.LogEntry, horizon string, err error) {
	es, err = c.Log(ctx, ns, name, "", "")
	if client.IsPruned(err) {
		ae, _ := client.AsAPIError(err)
		if horizon = ae.Horizon(); horizon != "" {
			es, err = c.Log(ctx, ns, name, "", horizon)
		}
	}
	return es, horizon, err
}

// pruneCmd is patchlog prune NS/NAME --below ID.
type pruneCmd struct {
	toolArgs
	yesArgs
	Below    string `arg:"--below,required" placeholder:"ID" help:"the horizon: the revisions before this one are destroyed (it is the oldest kept; the server may keep more)"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
}

func (a *pruneCmd) run(string) { runClient(a) }

func (a *pruneCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	c := a.writer()
	es, horizon, err := retainedLog(ctx, c, ns, name)
	if err != nil {
		return err
	}
	at := -1
	if a.Below == horizon {
		at = 0
	}
	for i, e := range es {
		if e.ID == a.Below {
			at = i
			if horizon != "" {
				at++ // the horizon itself is before es[0]
			}
		}
	}
	if at < 0 {
		return fmt.Errorf("%s isn't in the retained log of %s", a.Below, a.Resource)
	}
	if !a.Yes {
		return refuse(errw, fmt.Sprintf("would prune %s below %s: the %d older log entries and their documents are destroyed, for good (%d are kept)", a.Resource, a.Below, at, len(es)+b2i(horizon != "")-at))
	}
	r, err := c.Prune(ctx, ns, name, client.PruneRequest{Horizon: a.Below})
	if err != nil {
		return err
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"horizon": r.Horizon, "nsId": r.NSID})
	}
	if r.NSID == "" {
		fmt.Fprintf(errw, "nothing to prune: the horizon of %s is already %s\n", a.Resource, r.Horizon)
		return nil
	}
	fmt.Fprintf(errw, "pruned %s below %s (namespace entry %s)\n", a.Resource, r.Horizon, r.NSID)
	fmt.Fprintln(out, r.NSID)
	return nil
}

// nsPurgeCmd is patchlog ns purge NS.
type nsPurgeCmd struct {
	toolArgs
	yesArgs
	Force bool   `arg:"--force" help:"purge even if the namespace holds the last copy of a schema revision others reference (needs a grant chained to a * key)"`
	NS    string `arg:"positional,required"`
}

func (a *nsPurgeCmd) run(string) { runClient(a) }

func (a *nsPurgeCmd) exec(ctx context.Context, out, errw io.Writer) error {
	c := a.writer()
	h, err := c.NSHead(ctx, a.NS)
	if err != nil {
		return err
	}
	if !a.Yes {
		items, err := c.Heads(ctx, a.NS, h.ID)
		if err != nil {
			return err
		}
		return refuse(errw, fmt.Sprintf("would purge namespace %s (head %s): its %d resources with all their history and blobs, and its log, for good. Only a frozen namespace can be purged (§8.5)", a.NS, h.ID, len(items)))
	}
	nsID, err := c.PurgeNamespaceForce(ctx, a.NS, h.ID, a.Force)
	if err != nil {
		return err
	}
	return a.wrote(out, errw, "purged namespace "+a.NS, nsID, nsID, "")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
