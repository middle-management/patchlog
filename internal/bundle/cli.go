package bundle

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// CLIUsage documents the bundle commands.
const CLIUsage = `  patchlog export -api URL -ns NS[,NS] [-resource a,b] [-mode history|snapshot] [-o file.jsonl] [-bearer T] [-author A]
          [-external ns|ns/name,…] [-authors] [-untyped-refs] [-foreign-parents] [-json]
          [-recipient key.jwk]... [-plaintext] [-identity id.jwk]
  patchlog import -api URL -ns TARGET[,src=dst] -i file.jsonl [-dry-run] (-atomic | -pace 0.5) [-bearer T] [-author A]
          [-resolve ns/name=skip|take|replay]... [-create=false] [-json] [-identity id.jwk] [-allow-less-protected]
  patchlog bundle verify -i file.jsonl [-identity id.jwk] [-json]
  patchlog bundle keygen -o id.jwk      (prints the public key, for -recipient and a grant's enc)`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

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
func connect(api, bearer, author string, identity *ecdh.PrivateKey) (*client.Client, error) {
	opts := []client.Option{client.WithKeys(client.NewKeys(identity))}
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
// the exit status.
func CLI(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) int {
	var err error
	switch cmd {
	case "export":
		err = cliExport(ctx, args, stdout, stderr)
	case "import":
		err = cliImport(ctx, args, stdout, stderr)
	case "bundle":
		switch {
		case len(args) >= 1 && args[0] == "verify":
			err = cliVerify(args[1:], stdout)
		case len(args) >= 1 && args[0] == "keygen":
			err = cliKeygen(args[1:], stdout)
		default:
			fmt.Fprintln(stderr, "usage:\n"+CLIUsage)
			return 2
		}
	default:
		fmt.Fprintln(stderr, "usage:\n"+CLIUsage)
		return 2
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	fmt.Fprintln(stderr, "error:", err)
	if ae, ok := client.AsAPIError(err); ok {
		for _, it := range ae.Items() {
			fmt.Fprintf(stderr, "  item %v: %v %v %v\n", it["index"], it["status"], it["code"], it["message"])
		}
	}
	return 1
}

func cliExport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", "http://localhost:8080", "source deployment base URL")
	nsList := fs.String("ns", "", "namespaces to export (comma-separated)")
	resList := fs.String("resource", "", "resources to export (comma-separated names, or ns/name); default: every resource of -ns")
	mode := fs.String("mode", "history", "history (full) or snapshot")
	out := fs.String("o", "", "output file (default stdout)")
	bearer := fs.String("bearer", "", "grant sent as Authorization: Bearer (needs read, §G.2)")
	author := fs.String("author", "", "X-Author (development servers only)")
	external := fs.String("external", "", "dependencies to leave out: ns or ns/name (comma-separated)")
	authors := fs.Bool("authors", false, "include authors, creation times, signatures and gestures (§G.4.1)")
	untyped := fs.Bool("untyped-refs", false, "treat /r/… strings in untyped documents as references")
	foreign := fs.Bool("foreign-parents", false, "branch namespaces: start chains after their foreign parent (in requires) and list read-through resources as external, instead of including the base's history")
	asJSON := fs.Bool("json", false, "print the export plan as JSON on stderr")
	var recipients multiFlag
	fs.Var(&recipients, "recipient", "seal the bundle to this X25519 public key: a JWK file, or inline JSON (repeatable, §G.5.1.1)")
	plaintext := fs.Bool("plaintext", false, "write private or sealed content unsealed (§G.5.1: it should be sealed to its recipient)")
	idFile := fs.String("identity", "", "private key (JWK) that unwraps the keys of sealed source namespaces, when the grant's enc names it (§E.2.3)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	nss := splitList(*nsList)
	if len(nss) == 0 {
		return fmt.Errorf("export: -ns is required")
	}
	opt := ExportOptions{External: splitList(*external), Authors: *authors, UntypedRefs: *untyped, ForeignParents: *foreign, Plaintext: *plaintext}
	for _, r := range recipients {
		pub, err := LoadRecipient(r)
		if err != nil {
			return fmt.Errorf("export: -recipient %s: %w", r, err)
		}
		opt.Recipients = append(opt.Recipients, pub)
	}
	identity, err := loadIdentity(*idFile)
	if err != nil {
		return err
	}
	switch *mode {
	case "history", "full":
		opt.Mode = Full
	case "snapshot":
		opt.Mode = Snapshot
	default:
		return fmt.Errorf("export: -mode must be history or snapshot")
	}
	if res := splitList(*resList); len(res) > 0 {
		for _, r := range res {
			if strings.Contains(r, "/") {
				opt.Select = append(opt.Select, r)
				continue
			}
			if len(nss) != 1 {
				return fmt.Errorf("export: with several -ns, name resources as ns/name (%q)", r)
			}
			opt.Select = append(opt.Select, Key(nss[0], r))
		}
	} else {
		opt.Select = nss
	}
	c, err := connect(*api, *bearer, *author, identity)
	if err != nil {
		return err
	}
	plan, err := PlanExport(ctx, c, opt)
	if err != nil {
		return err
	}
	var w io.Writer = stdout
	var f *os.File
	if *out != "" {
		if f, err = os.Create(*out); err != nil {
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
			os.Remove(*out)
		}
	}
	if err != nil {
		return err
	}
	if *asJSON {
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
	return nil
}

// namespaceMap interprets -ns for an import: "name" imports the bundle's
// namespace of that name as is; "src=dst" maps a source namespace; a
// single plain name that isn't in the bundle maps the bundle's one
// document namespace (a namespace no $schema or $ref names) to it, e.g.
// to import into a branch first (§G.4.4).
func namespaceMap(h *Header, schemaNS map[string]bool, spec string) (map[string]string, error) {
	m := map[string]string{}
	inBundle := map[string]bool{}
	for ns := range h.At {
		inBundle[ns] = true
	}
	for _, s := range splitList(spec) {
		if src, dst, ok := strings.Cut(s, "="); ok {
			if !inBundle[src] {
				return nil, fmt.Errorf("import: -ns %s: the bundle has no namespace %s", s, src)
			}
			if schemaNS[src] && src != dst {
				return nil, fmt.Errorf("import: -ns %s: %s holds schemas that $schema/$ref paths name, so it can't be renamed", s, src)
			}
			m[src] = dst
			continue
		}
		if inBundle[s] {
			continue
		}
		var docNS []string
		for ns := range inBundle {
			if !schemaNS[ns] {
				docNS = append(docNS, ns)
			}
		}
		if len(docNS) != 1 {
			return nil, fmt.Errorf("import: -ns %s: the bundle has no namespace %s, and not exactly one document namespace to map to it (%v); use src=dst", s, s, docNS)
		}
		m[docNS[0]] = s
	}
	return m, nil
}

// schemaNamespaces lists the namespaces named by $schema or $ref paths in a
// bundle.
func schemaNamespaces(open Opener) (map[string]bool, *Header, error) {
	r, err := open()
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	rd, err := NewReader(r)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]bool{}
	note := func(v any) {
		walkStrings(v, "", func(ptr, s string) {
			if strings.HasSuffix(ptr, "/$schema") || strings.HasSuffix(ptr, "/$ref") {
				if r, ok := schema.ParseRef(s); ok {
					out[r.NS] = true
				}
			}
		})
	}
	for {
		l, err := rd.Next()
		if err == io.EOF {
			return out, rd.Header(), nil
		}
		if err != nil {
			return nil, nil, err
		}
		if l.IsBlob() {
			continue
		}
		if l.IsSnapshot() {
			note(l.Doc)
		} else {
			note(l.Patches)
		}
	}
}

func cliImport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", "http://localhost:8080", "target deployment base URL")
	nsSpec := fs.String("ns", "", "target namespaces: name, or src=dst to map a source namespace (comma-separated)")
	in := fs.String("i", "", "bundle file")
	dry := fs.Bool("dry-run", false, "classify, check and dry-run every batch; write nothing")
	atomic := fs.Bool("atomic", false, "one batch per namespace (large imports need an allowance, §6.6)")
	pace := fs.String("pace", "", "backfill: split batches to fit the limits and pace them at this fraction of the namespace rate, e.g. 0.5")
	bearer := fs.String("bearer", "", "grant sent as Authorization: Bearer")
	author := fs.String("author", "", "X-Author (development servers only)")
	create := fs.Bool("create", true, "create missing target and upstream namespaces")
	suffix := fs.String("upstream-suffix", "-upstream", "suffix of upstream namespaces for snapshot documents")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var resolves multiFlag
	fs.Var(&resolves, "resolve", "resolve a conflict: ns/name=skip|take|replay (repeatable)")
	idFile := fs.String("identity", "", "private key (JWK): opens a sealed bundle, and unwraps the keys of sealed targets (§G.5.1.1, §E.2.3)")
	allowLess := fs.Bool("allow-less-protected", false, "operator override: import private or sealed namespaces into public targets (§G.5.1)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("import: -i is required")
	}
	identity, err := loadIdentity(*idFile)
	if err != nil {
		return err
	}
	opt := ImportOptions{DryRun: *dry, CreateNamespaces: *create, UpstreamSuffix: *suffix, Resolutions: map[string]Resolution{}, AllowLessProtected: *allowLess}
	switch {
	case *atomic && *pace != "":
		return fmt.Errorf("import: choose one of -atomic and -pace")
	case *atomic:
		opt.Mode = Atomic
	case *pace != "":
		p, err := strconv.ParseFloat(*pace, 64)
		if err != nil || p <= 0 || p > 1 {
			return fmt.Errorf("import: -pace must be a fraction in (0, 1]")
		}
		opt.Mode, opt.Pace = Backfill, p
	default:
		return fmt.Errorf("import: choose -atomic (one batch per namespace; a release that must land at once, under an allowance if large) " +
			"or -pace F (a backfill: split to fit the limits, not atomic, paced at F of the namespace rate)")
	}
	for _, r := range resolves {
		k, v, ok := strings.Cut(r, "=")
		res := Resolution(v)
		if !ok || (res != ResolveSkip && res != ResolveTake && res != ResolveReplay) {
			return fmt.Errorf("import: -resolve %q: want ns/name=skip|take|replay", r)
		}
		opt.Resolutions[k] = res
	}
	open := UnsealOpener(FileOpener(*in), identity)
	schemaNS, h, err := schemaNamespaces(open)
	if err != nil {
		return err
	}
	if opt.NSMap, err = namespaceMap(h, schemaNS, *nsSpec); err != nil {
		return err
	}
	c, err := connect(*api, *bearer, *author, identity)
	if err != nil {
		return err
	}
	if !*asJSON {
		opt.Progress = func(b *BatchReport) {
			fmt.Fprintf(stderr, "batch %d/%d into %s: %d items, %d steps -> %s\n", b.Part, b.Parts, b.NS, len(b.Resources), b.Steps, b.NSID)
		}
	}
	rep, err := Import(ctx, c, open, opt)
	if rep != nil {
		if *asJSON {
			writeJSON(stdout, rep)
		} else {
			printReport(stdout, rep)
		}
	}
	return err
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
		fmt.Fprintf(w, "  undeclared pinned string in %s at %s: %s (not rewritten)\n", u.Doc, u.Pointer, u.Value)
	}
	for _, ns := range r.Create {
		fmt.Fprintf(w, "  create namespace %s\n", ns)
	}
	for _, b := range r.Batches {
		fmt.Fprintf(w, "  batch %d/%d into %s: %d items, %d steps, %d bytes, dry run %s", b.Part, b.Parts, b.NS, len(b.Resources), b.Steps, b.Size, b.DryRun)
		if b.NSID != "" {
			fmt.Fprintf(w, ", committed %s", b.NSID)
		}
		fmt.Fprintln(w)
		for _, f := range b.Failures {
			fmt.Fprintf(w, "      %s\n", f)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
	if u := r.Unresolved(); len(u) > 0 {
		fmt.Fprintf(w, "%d unresolved conflicts: resolve each with -resolve ns/name=skip|take|replay\n", len(u))
	}
}

func cliVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bundle verify", flag.ContinueOnError)
	in := fs.String("i", "", "bundle file")
	asJSON := fs.Bool("json", false, "print JSON")
	idFile := fs.String("identity", "", "private key (JWK) that opens a sealed bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("bundle verify: -i is required")
	}
	identity, err := loadIdentity(*idFile)
	if err != nil {
		return err
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	plain, sealed, err := Unseal(f, identity)
	if err != nil {
		return err
	}
	s, err := Verify(plain)
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
	if *asJSON {
		writeJSON(stdout, map[string]any{"ok": true, "digest": s.Digest, "origin": s.Header.Origin, "created": s.Header.Created,
			"at": s.Header.At, "full": full, "snapshot": snap, "lines": s.Lines, "external": s.Header.External, "requires": s.Header.Requires,
			"access": s.Header.Access, "sealed": sealed})
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
	fmt.Fprintln(stdout, "  snapshot lines and the header are only as trustworthy as the channel that delivered the bundle (§G.4.1)")
	return nil
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
		return nil, fmt.Errorf("-identity %s: %w", path, err)
	}
	return id, nil
}

// cliKeygen writes a new X25519 identity (private JWK, mode 0600) and
// prints its public JWK.
func cliKeygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bundle keygen", flag.ContinueOnError)
	out := fs.String("o", "", "file for the private key (JWK); must not exist")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("bundle keygen: -o is required")
	}
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
