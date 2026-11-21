package bundle

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/alexflint/go-arg"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
)

// SignKeyEnv names the environment variable that sets --sign-key.
const SignKeyEnv = "PATCHLOG_SIGN_KEY"

// parseSignKey parses a --sign-key value; "" is no key.
func parseSignKey(v string) (*sig.Key, error) {
	if v == "" {
		return nil, nil
	}
	k, err := sig.ParseKey(v)
	if err != nil {
		return nil, fmt.Errorf("--sign-key: %w", err)
	}
	return &k, nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// connect makes a client; identity unwraps the keys of sealed namespaces
// (§E.2.3) that the grant's enc names.
func connect(api, bearer, author string, identity *ecdh.PrivateKey, more ...client.Option) (*client.Client, error) {
	opts := append([]client.Option{client.WithKeys(client.NewKeys(identity))}, more...)
	if bearer != "" {
		opts = append(opts, client.WithBearer(bearer))
	}
	if author != "" {
		opts = append(opts, client.WithAuthor(author))
	}
	return client.New(api, opts...)
}

func writeJSON(w io.Writer, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(w, string(b))
}

// CLI runs "export", "import" or "bundle" with its arguments and returns
// the exit status. It is a thin wrapper over the command types, which the
// patchlog binary embeds as go-arg subcommands.
func CLI(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) int {
	var dest any
	var run func() error
	switch cmd {
	case "export":
		c := &ExportCmd{}
		dest, run = c, func() error { return c.Run(ctx, stdout, stderr) }
	case "import":
		c := &ImportCmd{}
		dest, run = c, func() error { return c.Run(ctx, stdout, stderr) }
	case "bundle":
		c := &BundleCmd{}
		dest = c
		run = func() error {
			switch {
			case c.Verify != nil:
				return c.Verify.Run(ctx, stdout, stderr)
			case c.Keygen != nil:
				return c.Keygen.Run(ctx, stdout, stderr)
			}
			return nil
		}
	default:
		fmt.Fprintf(stderr, "usage: patchlog export|import|bundle ... (unknown command %q)\n", cmd)
		return 2
	}
	p, err := arg.NewParser(arg.Config{Program: "patchlog " + cmd, Out: stderr, Exit: func(int) {}}, dest)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := p.Parse(args); err != nil {
		if errors.Is(err, arg.ErrHelp) {
			p.WriteHelp(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		p.WriteUsage(stderr)
		return 2
	}
	if b, ok := dest.(*BundleCmd); ok && b.Verify == nil && b.Keygen == nil {
		p.WriteUsage(stderr)
		return 2
	}
	if err := run(); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if ae, ok := client.AsAPIError(err); ok {
			for _, it := range ae.Items() {
				fmt.Fprintf(stderr, "  item %v: %v %v %v\n", it["index"], it["status"], it["code"], it["message"])
			}
		}
		return 1
	}
	return 0
}

// ExportCmd is "patchlog export".
type ExportCmd struct {
	API            string   `arg:"--api,env:PATCHLOG_API" default:"http://localhost:8080" help:"source deployment base URL"`
	NS             string   `arg:"--ns" help:"namespaces to export (comma-separated)"`
	Resource       string   `arg:"--resource" help:"resources to export (comma-separated names, or ns/name); default: every resource of --ns"`
	Mode           string   `arg:"--mode" default:"history" help:"history (full) or snapshot"`
	Out            string   `arg:"-o" help:"output file (default stdout)"`
	Bearer         string   `arg:"--bearer,env:PATCHLOG_BEARER" help:"grant sent as Authorization: Bearer (needs read, §G.2)"`
	BearerFile     string   `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer (exclusive with it)"`
	Author         string   `arg:"--author,env:PATCHLOG_AUTHOR" help:"X-Author (development servers only)"`
	External       string   `arg:"--external" help:"dependencies to leave out: ns or ns/name (comma-separated)"`
	Authors        bool     `arg:"--authors" help:"include authors, creation times, signatures and gestures (§G.4.1)"`
	UntypedRefs    bool     `arg:"--untyped-refs" help:"treat /r/… strings in untyped documents as references"`
	ForeignParents bool     `arg:"--foreign-parents" help:"branch namespaces: start chains after their foreign parent (in requires) and list read-through resources as external, instead of including the base's history (always so for an e2e branch, §G.5.1)"`
	JSON           bool     `arg:"--json" help:"print the export plan as JSON on stderr"`
	Recipient      []string `arg:"--recipient,separate" help:"seal the bundle to this X25519 public key: a JWK file, or inline JSON (repeatable, §G.5.1.1)"`
	Plaintext      bool     `arg:"--plaintext" help:"write private or sealed content unsealed (§G.5.1: it should be sealed to its recipient)"`
	Pad            bool     `arg:"--pad" help:"with --recipient: pad each sealed line to its size bucket (§E.2.2, §G.5.1.1)"`
	Identity       string   `arg:"--identity" help:"private key (JWK) that unwraps the keys of sealed source namespaces, when the grant's enc names it (§E.2.3)"`
}

// Description is the command's help text.
func (*ExportCmd) Description() string {
	return "Export namespaces (or chosen resources) of a deployment as a bundle: a JSON Lines file of documents and their history that another deployment can import. A bundle can be sealed to one or more recipients, and the plan of what went in is printed on stderr."
}

// Run exports a bundle.
func (c *ExportCmd) Run(ctx context.Context, stdout, stderr io.Writer) error {
	nss := splitList(c.NS)
	if len(nss) == 0 {
		return fmt.Errorf("export: --ns is required")
	}
	opt := ExportOptions{Bearer: c.Bearer, External: splitList(c.External), Authors: c.Authors, UntypedRefs: c.UntypedRefs, ForeignParents: c.ForeignParents, Plaintext: c.Plaintext, Pad: c.Pad}
	for _, r := range c.Recipient {
		pub, err := LoadRecipient(r)
		if err != nil {
			return fmt.Errorf("export: --recipient %s: %w", r, err)
		}
		opt.Recipients = append(opt.Recipients, pub)
	}
	if c.Pad && len(opt.Recipients) == 0 {
		return fmt.Errorf("export: --pad pads sealed lines, so it needs --recipient")
	}
	identity, err := loadIdentity(c.Identity)
	if err != nil {
		return err
	}
	opt.Identity = identity
	switch c.Mode {
	case "history", "full":
		opt.Mode = Full
	case "snapshot":
		opt.Mode = Snapshot
	default:
		return fmt.Errorf("export: --mode must be history or snapshot")
	}
	if res := splitList(c.Resource); len(res) > 0 {
		for _, r := range res {
			if strings.Contains(r, "/") {
				opt.Select = append(opt.Select, r)
				continue
			}
			if len(nss) != 1 {
				return fmt.Errorf("export: with several --ns, name resources as ns/name (%q)", r)
			}
			opt.Select = append(opt.Select, Key(nss[0], r))
		}
	} else {
		opt.Select = nss
	}
	cl, err := connect(c.API, c.Bearer, c.Author, identity)
	if err != nil {
		return err
	}
	plan, err := PlanExport(ctx, cl, opt)
	if err != nil {
		return err
	}
	var w io.Writer = stdout
	var f *os.File
	if c.Out != "" {
		if f, err = os.Create(c.Out); err != nil {
			return err
		}
		w = f
	}
	sum, err := plan.Write(ctx, w)
	if f != nil {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(c.Out)
		}
	}
	if err != nil {
		return err
	}
	if c.JSON {
		writeJSON(stderr, map[string]any{"plan": plan, "digest": sum.Digest, "lines": sum.Lines, "sealed": len(opt.Recipients) > 0})
		return nil
	}
	if len(opt.Recipients) > 0 {
		fmt.Fprintf(stderr, "sealed bundle (%s) for %d recipients\n", SealedMediaType, len(opt.Recipients))
	}
	keys := make([]string, 0, len(plan.Docs))
	for k := range plan.Docs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(stderr, "bundle %s from %s: %d documents, %d lines\n", sum.Digest, plan.Origin, len(sum.Header.Docs), sum.Lines)
	for _, k := range keys {
		d := plan.Docs[k]
		if _, in := sum.Header.Docs[k]; !in {
			continue
		}
		fmt.Fprintf(stderr, "  %-40s %-8s %s  (%s)\n", k, d.Mode, d.Head, strings.Join(d.Reasons, "; "))
	}
	for _, e := range plan.External {
		fmt.Fprintf(stderr, "  external %s\n", e)
	}
	for _, n := range plan.Notes {
		fmt.Fprintf(stderr, "  note: %s\n", n)
	}
	return nil
}

// namespaceMap interprets --ns for an import: "name" imports the bundle's
// namespace of that name as is; "src=dst" maps a source namespace, which
// renames it unless dst is a branch of it (ImportOptions.NSMap, §G.4.4); a
// single plain name that isn't in the bundle maps the bundle's one
// document namespace (a namespace no $schema or $ref names) to it, e.g.
// to import into a branch first. That is a src=dst mapping too: it
// renames unless the name is a branch of that namespace (§G.4.4).
func namespaceMap(h *Header, schemaNamespaces func() (map[string]bool, error), spec string) (map[string]string, error) {
	m := map[string]string{}
	var schemaNS map[string]bool
	needSchemaNS := func() error {
		var err error
		if schemaNS == nil {
			schemaNS, err = schemaNamespaces()
		}
		return err
	}
	inBundle := map[string]bool{}
	for ns := range h.At {
		inBundle[ns] = true
	}
	mappable := maps.Clone(inBundle) // and the namespaces of external dependencies
	for _, e := range h.External {
		if ext, ok := ParseExternal(e); ok {
			mappable[ext.NS] = true
		}
	}
	for _, s := range splitList(spec) {
		if src, dst, ok := strings.Cut(s, "="); ok {
			if !mappable[src] {
				return nil, fmt.Errorf("import: --ns %s: the bundle has no namespace %s", s, src)
			}
			if !client.ValidNSName(dst) {
				return nil, fmt.Errorf("import: --ns %s: invalid target namespace %q", s, dst)
			}
			m[src] = dst
			continue
		}
		if inBundle[s] {
			continue
		}
		if err := needSchemaNS(); err != nil {
			return nil, err
		}
		var docNS []string
		for ns := range inBundle {
			if !schemaNS[ns] {
				docNS = append(docNS, ns)
			}
		}
		if len(docNS) != 1 {
			return nil, fmt.Errorf("import: --ns %s: the bundle has no namespace %s, and not exactly one document namespace to map to it (%v); use src=dst", s, s, docNS)
		}
		m[docNS[0]] = s
	}
	return m, nil
}

// bundleHeader reads a bundle's header.
func bundleHeader(open Opener) (*Header, error) {
	r, err := open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	return rd.Header(), nil
}

// schemaNamespaces lists the namespaces named by $schema or $ref paths in a
// bundle, which reads all of it: only a --ns of one plain name that isn't
// in the bundle needs them.
func schemaNamespaces(open Opener) (map[string]bool, error) {
	r, err := open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	rd.parallel(runtime.GOMAXPROCS(0))
	defer rd.Close()
	out := map[string]bool{}
	note := func(v any) {
		walkStrings(v, func(at *strPath, s string) {
			if k := at.Last(); k == "$schema" || k == "$ref" {
				if r, _, err := schema.SplitRef(s); err == nil { // a $ref may have a #fragment
					out[r.NS] = true
				}
			}
		})
	}
	for {
		l, err := rd.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if l.IsBlob() || l.IsGrant() {
			continue
		}
		if l.IsSnapshot() {
			note(l.Doc)
		} else {
			note(l.Patches)
		}
	}
}

// ImportCmd is "patchlog import".
type ImportCmd struct {
	API                string   `arg:"--api,env:PATCHLOG_API" default:"http://localhost:8080" help:"target deployment base URL"`
	NS                 string   `arg:"--ns" help:"target namespaces: name, or src=dst to map a source namespace (comma-separated). src=dst renames, to clone a set of namespaces together: references to src ($schema, $ref, x-ref) are rewritten where they are declared in every document, and documents that change get new ids; undeclared ones are listed, not rewritten. Onto a branch of src it keeps references and ids. A single plain name that isn't in the bundle maps its one document namespace to it, so it renames too, unless it is a branch of that namespace. Namespace configuration isn't in the bundle: create renamed targets with theirs first (§G.4.4, §G.7)"`
	Only               string   `arg:"--only" help:"import only these source namespaces of the bundle (comma-separated): what their documents reference in the others must be in the target already, as the bundle has it, which is checked first (§G.4.1 external)"`
	In                 string   `arg:"-i" help:"bundle file"`
	DryRun             bool     `arg:"--dry-run" help:"classify, check and dry-run every batch; write nothing"`
	Atomic             bool     `arg:"--atomic" help:"one batch per namespace; over the namespace's limits it needs an allowance there, up to the deployment maximums (patchlog serve --max-items-per-batch, --max-batch-size; by default 1000 items, 16 MiB) (§6.6)"`
	Pace               string   `arg:"--pace" help:"backfill: split batches to fit the limits and pace them, dry runs included, at this fraction of the lower of the namespace's and the importer's rate, e.g. 0.5; an allowance of the importer's own in a namespace sets its batches and full rate there instead (§6.6)"`
	Bearer             string   `arg:"--bearer,env:PATCHLOG_BEARER" help:"grant sent as Authorization: Bearer"`
	BearerFile         string   `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer (exclusive with it)"`
	Author             string   `arg:"--author,env:PATCHLOG_AUTHOR" help:"X-Author (development servers only)"`
	Create             bool     `arg:"--create" default:"true" help:"create missing target and upstream namespaces (--create=false to refuse)"`
	UpstreamSuffix     string   `arg:"--upstream-suffix" default:"-upstream" help:"suffix of upstream namespaces for snapshot documents, after the new name of a renamed namespace (--ns src=dst: dst-upstream); an upstream name over the 64 characters of a namespace name is refused before anything is written (§3.6, §G.4.4)"`
	JSON               bool     `arg:"--json" help:"print the report as JSON"`
	Resolve            []string `arg:"--resolve,separate" help:"resolve a conflict: ns/name=skip|take|replay (repeatable)"`
	Identity           string   `arg:"--identity" help:"private key (JWK): opens a sealed bundle, and unwraps the keys of sealed targets (§G.5.1.1, §E.2.3)"`
	AllowLessProtected bool     `arg:"--allow-less-protected" help:"operator override: import private or sealed namespaces into public targets (§G.5.1)"`
	Concurrency        int      `arg:"--concurrency" default:"4" help:"backfill under an allowance: batches submitted at once, in dependency order all the same, or fewer: as many as the allowance's burst holds the draws of; 1 submits one at a time"`
	SignKey            string   `arg:"--sign-key,env:PATCHLOG_SIGN_KEY" help:"kid:seed (the seed 32 bytes in base64url; default $PATCHLOG_SIGN_KEY): sign every step this import writes with this key (§C.3.1). The kid must be listed in the signers of the grant (--bearer). The bundle's own signatures are never re-sent"`
}

// Description is the command's help text.
func (*ImportCmd) Description() string {
	return "Import a bundle into a deployment. Choose --atomic (one batch per namespace, for a release that must land at once) or --pace F (a backfill, split to fit the limits and paced at a fraction of the namespace rate). src=dst in --ns renames a namespace: references to src are rewritten, and documents that change get new ids (§G.4.4). Conflicts are reported and resolved with --resolve."
}

// Run imports a bundle.
func (c *ImportCmd) Run(ctx context.Context, stdout, stderr io.Writer) error {
	if c.In == "" {
		return fmt.Errorf("import: -i is required")
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("import: --concurrency must be at least 1")
	}
	signer, err := parseSignKey(c.SignKey)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(c.Identity)
	if err != nil {
		return err
	}
	opt := ImportOptions{DryRun: c.DryRun, CreateNamespaces: c.Create, UpstreamSuffix: c.UpstreamSuffix, Resolutions: map[string]Resolution{}, AllowLessProtected: c.AllowLessProtected, Signer: signer,
		Concurrency: c.Concurrency, Only: splitList(c.Only)}
	switch {
	case c.Atomic && c.Pace != "":
		return fmt.Errorf("import: choose one of --atomic and --pace")
	case c.Atomic:
		opt.Mode = Atomic
	case c.Pace != "":
		p, err := strconv.ParseFloat(c.Pace, 64)
		if err != nil || p <= 0 || p > 1 {
			return fmt.Errorf("import: --pace must be a fraction in (0, 1]")
		}
		opt.Mode, opt.Pace = Backfill, p
	default:
		return fmt.Errorf("import: choose --atomic (one batch per namespace; a release that must land at once, under an allowance if large) " +
			"or --pace F (a backfill: split to fit the limits, not atomic, paced at F of the namespace rate)")
	}
	for _, r := range c.Resolve {
		k, v, ok := strings.Cut(r, "=")
		res := Resolution(v)
		if !ok || (res != ResolveSkip && res != ResolveTake && res != ResolveReplay) {
			return fmt.Errorf("import: --resolve %q: want ns/name=skip|take|replay", r)
		}
		opt.Resolutions[k] = res
	}
	open := UnsealOpener(FileOpener(c.In), identity)
	h, err := bundleHeader(open)
	if err != nil {
		return err
	}
	if opt.NSMap, err = namespaceMap(h, func() (map[string]bool, error) { return schemaNamespaces(open) }, c.NS); err != nil {
		return err
	}
	cl, err := connect(c.API, c.Bearer, c.Author, identity, client.WithIdleConns(opt.Concurrency))
	if err != nil {
		return err
	}
	if !c.JSON {
		opt.Progress = func(b *BatchReport) {
			fmt.Fprintf(stderr, "batch %d/%d into %s: %d items, %d steps -> %s%s\n", b.Part, b.Parts, b.NS, len(b.Resources), b.Steps, b.NSID, paced(b))
		}
	}
	rep, err := Import(ctx, cl, open, opt)
	if rep != nil {
		if c.JSON {
			writeJSON(stdout, rep)
		} else {
			printReport(stdout, rep)
		}
	}
	return err
}

// paced describes how a backfill paces a batch's namespace, "" otherwise.
func paced(b *BatchReport) string {
	if b.PacedBy == "" {
		return ""
	}
	return fmt.Sprintf(", paced at %g items/s (%s)", b.Rate, b.PacedBy)
}

func printReport(w io.Writer, r *Report) {
	verb := "import"
	if r.DryRun {
		verb = "dry run"
	}
	fmt.Fprintf(w, "%s of bundle %s from %s into %s (%s)\n", verb, r.Digest, r.Origin, r.TargetOrigin, r.Mode)
	for _, d := range r.Docs {
		line := fmt.Sprintf("  %-32s -> %-32s %-8s %-12s", d.Doc, d.Target, d.History, d.Class)
		if d.Steps > 0 {
			line += fmt.Sprintf(" %d steps", d.Steps)
		}
		if d.Upstream != nil {
			line += fmt.Sprintf(" upstream %s %s", d.Upstream.Target, d.Upstream.Class)
		}
		if d.Resolution != "" {
			line += " resolved: " + string(d.Resolution)
		}
		if d.Renamed {
			line += " (rewritten: new ids)"
		}
		fmt.Fprintln(w, line)
		for _, c := range d.Conflicts {
			fmt.Fprintf(w, "      conflict %s: %s %s\n", c.Kind, c.Message, strings.Join(c.Paths, " "))
		}
		for _, rw := range d.Rewritten {
			fmt.Fprintf(w, "      rewrote %s: %s -> %s\n", rw.Pointer, rw.From, rw.To)
		}
		if d.Note != "" {
			fmt.Fprintf(w, "      %s\n", d.Note)
		}
	}
	for _, u := range r.Undeclared {
		switch {
		case u.Renamed && u.RewrittenFrom != "":
			fmt.Fprintf(w, "  undeclared reference in %s at %s, written by %s: %s (renamed, not rewritten before %s, which declares it)\n",
				u.Doc, u.Pointer, u.Rev, u.Value, u.RewrittenFrom)
		case u.Renamed && u.Rev != "":
			fmt.Fprintf(w, "  undeclared reference in %s at %s, written by %s: %s (renamed, not rewritten)\n", u.Doc, u.Pointer, u.Rev, u.Value)
		case u.Renamed:
			fmt.Fprintf(w, "  undeclared reference in %s at %s: %s (renamed, not rewritten)\n", u.Doc, u.Pointer, u.Value)
		default:
			fmt.Fprintf(w, "  undeclared pinned string in %s at %s: %s (not rewritten)\n", u.Doc, u.Pointer, u.Value)
		}
	}
	for _, ns := range r.Create {
		fmt.Fprintf(w, "  create namespace %s\n", ns)
	}
	for _, b := range r.Batches {
		fmt.Fprintf(w, "  batch %d/%d into %s: %d items, %d steps, %d bytes", b.Part, b.Parts, b.NS, len(b.Resources), b.Steps, b.Size)
		if b.DryRun != "" {
			fmt.Fprintf(w, ", dry run %s", b.DryRun)
		}
		if b.NSID != "" {
			fmt.Fprintf(w, ", committed %s", b.NSID)
		}
		fmt.Fprintln(w, paced(b))
		for _, f := range b.Failures {
			fmt.Fprintf(w, "      %s\n", f)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
	t := r.Timings
	fmt.Fprintf(w, "  time %.1fs: planning %.1fs, blobs %.1fs, batch requests %.1fs (%d of them, %d dry runs; mostly the server's time), paced %.1fs, after 429s %.1fs\n",
		t.Total, t.Planning, t.Blobs, t.Batches, t.Requests, t.DryRuns, t.Paced, t.RateLimited)
	if u := r.Unresolved(); len(u) > 0 {
		fmt.Fprintf(w, "%d unresolved conflicts: resolve each with --resolve ns/name=skip|take|replay\n", len(u))
	}
}

// VerifyCmd is "patchlog bundle verify".
type VerifyCmd struct {
	In         string `arg:"-i" help:"bundle file"`
	JSON       bool   `arg:"--json" help:"print JSON"`
	Identity   string `arg:"--identity" help:"private key (JWK) that opens a sealed bundle"`
	Source     string `arg:"--source" help:"the source deployment's base URL: checks the key of each grant line against its namespace log and operator key history (§C.3.1), so complete chains are verified, not only attested"`
	Bearer     string `arg:"--bearer,env:PATCHLOG_BEARER" help:"--source: grant sent as Authorization: Bearer (needs read)"`
	BearerFile string `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer (exclusive with it)"`
	Author     string `arg:"--author,env:PATCHLOG_AUTHOR" help:"--source: X-Author (development servers only)"`
	Signatures bool   `arg:"--signatures" help:"list the signature status of every revision"`
}

// Description is the command's help text.
func (*VerifyCmd) Description() string {
	return "Verify a bundle: every line is read and every document id recomputed. With --source, the signer keys of grant lines are checked against the source's namespace log (§C.3.1)."
}

// Run verifies a bundle.
func (c *VerifyCmd) Run(ctx context.Context, stdout, stderr io.Writer) error {
	if c.In == "" {
		return fmt.Errorf("bundle verify: -i is required")
	}
	identity, err := loadIdentity(c.Identity)
	if err != nil {
		return err
	}
	f, err := os.Open(c.In)
	if err != nil {
		return err
	}
	defer f.Close()
	plain, sealed, err := Unseal(f, identity)
	if err != nil {
		return err
	}
	var vo VerifyOptions
	if c.Source != "" {
		sc, err := connect(c.Source, c.Bearer, c.Author, identity)
		if err != nil {
			return err
		}
		vo.Keys, vo.Finder = SourceKeys(sc)
	}
	var results []SigResult
	if c.Signatures {
		vo.OnSignature = func(r SigResult) { results = append(results, r) }
	}
	s, err := VerifyWith(ctx, plain, vo)
	if err != nil {
		return err
	}
	full, snap := 0, 0
	for _, d := range s.Header.Docs {
		if d.History == Full {
			full++
		} else {
			snap++
		}
	}
	if c.JSON {
		out := map[string]any{"ok": true, "digest": s.Digest, "origin": s.Header.Origin, "created": s.Header.Created,
			"at": s.Header.At, "full": full, "snapshot": snap, "lines": s.Lines, "external": s.Header.External, "requires": s.Header.Requires,
			"access": s.Header.Access, "sealed": sealed}
		if s.Signatures != nil {
			out["signatures"] = s.Signatures
			if c.Signatures {
				out["revisions"] = results
			}
		}
		writeJSON(stdout, out)
		return nil
	}
	fmt.Fprintf(stdout, "ok: bundle %s from %s, created %s\n", s.Digest, s.Header.Origin, s.Header.Created)
	if sealed {
		fmt.Fprintln(stdout, "  sealed bundle: every line decrypted and checked in order (§G.5.1.1)")
	}
	for _, ns := range sortedKeys(s.Header.At) {
		fmt.Fprintf(stdout, "  %s: %s\n", ns, s.Header.AccessOf(ns))
	}
	fmt.Fprintf(stdout, "  %d full-history documents (every id recomputed), %d snapshots, %d lines\n", full, snap, s.Lines)
	if len(s.Header.Requires) > 0 {
		fmt.Fprintf(stdout, "  requires %d revisions in the target\n", len(s.Header.Requires))
	}
	if len(s.Header.External) > 0 {
		fmt.Fprintf(stdout, "  external: %s\n", strings.Join(s.Header.External, ", "))
	}
	printSignatures(stdout, s, results, c.Source != "")
	fmt.Fprintln(stdout, "  snapshot lines and the header are only as trustworthy as the channel that delivered the bundle (§G.4.1)")
	return nil
}

// printSignatures prints the signature report of a bundle with authors.
func printSignatures(w io.Writer, s *Summary, results []SigResult, online bool) {
	if s.Signatures == nil {
		return
	}
	r := s.Signatures
	fmt.Fprintf(w, "  signatures (%d grant lines): %d verified, %d attested, %d failed, %d unverifiable, %d unsigned\n", r.Grants,
		r.Counts[SigVerified], r.Counts[SigAttested], r.Counts[SigFailed], r.Counts[SigUnverifiable], r.Counts[SigUnsigned])
	if r.Counts[SigAttested] > 0 && !online {
		fmt.Fprintln(w, "    attested: the chain is complete up to the key the exporter names; check it against the source with --source (§C.3.1)")
	}
	for _, g := range r.BadGrants {
		fmt.Fprintf(w, "    bad grant line %s\n", g)
	}
	list := r.Problems
	if len(results) > 0 {
		list = results
	}
	for _, x := range list {
		line := fmt.Sprintf("    %s/%s %s: %s", x.NS, x.Resource, x.ID, x.Status)
		if x.Kid != "" {
			line += " kid " + x.Kid
		}
		if x.Sub != "" {
			line += " sub " + x.Sub
		}
		if x.Reason != "" {
			line += " (" + x.Reason + ")"
		}
		fmt.Fprintln(w, line)
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loadIdentity(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	id, err := LoadIdentity(path)
	if err != nil {
		return nil, fmt.Errorf("--identity %s: %w", path, err)
	}
	return id, nil
}

// BundleCmd groups the bundle utilities: "patchlog bundle verify|keygen".
type BundleCmd struct {
	Verify *VerifyCmd `arg:"subcommand:verify" help:"check a bundle: every line, every id, and the signatures"`
	Keygen *KeygenCmd `arg:"subcommand:keygen" help:"write a new X25519 identity and print its public key, for --recipient and a grant's enc"`
}

// KeygenCmd is "patchlog bundle keygen".
type KeygenCmd struct {
	Out string `arg:"-o" help:"file for the private key (JWK); must not exist"`
}

// Description is the command's help text.
func (*KeygenCmd) Description() string {
	return "Write a new X25519 identity (private JWK, mode 0600) to the file given with -o, which must not exist, and print its public JWK: use it as --recipient on export and as a grant's enc."
}

// Run writes a new X25519 identity (private JWK, mode 0600) and prints its
// public JWK.
func (c *KeygenCmd) Run(ctx context.Context, stdout, stderr io.Writer) error {
	if c.Out == "" {
		return fmt.Errorf("bundle keygen: -o is required")
	}
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(c.Out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(jsonv.Canonical(IdentityJWK(priv)), '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(jsonv.Canonical(seal.RecipientJWK(priv.PublicKey()))))
	return nil
}
