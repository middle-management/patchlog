package bundle

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/verify"
)

// Target is a dependency: a resource, pinned to a revision if Rev is set.
type Target struct {
	NS, Name string
	Rev      string // "" = live: the head as of the export's at
}

// Resolver is an application resolver (§G.4.2, level 3): a tool plug-in for
// relationships no schema expresses. It is called with every exported
// document's head (nil if the document is deleted) and returns the
// resources it depends on.
type Resolver interface {
	Resolve(ctx context.Context, src *client.Client, ns, name string, doc any) ([]Target, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, src *client.Client, ns, name string, doc any) ([]Target, error)

// Resolve calls f.
func (f ResolverFunc) Resolve(ctx context.Context, src *client.Client, ns, name string, doc any) ([]Target, error) {
	return f(ctx, src, ns, name, doc)
}

// ExportOptions configure an export.
type ExportOptions struct {
	// Select lists namespaces ("ns": every resource at its at) and
	// resources ("ns/name").
	Select []string
	// Mode is the mode of selected documents and their dependencies, Full
	// (default) or Snapshot. Schemas are always Full, and modes close
	// downward (§G.4.3).
	Mode string
	// External leaves dependencies out on purpose: "ns" or "ns/name". They
	// are listed in the header's external, and the importer checks that
	// they exist in the target.
	External []string
	// Resolvers are application resolvers (level 3 of §G.4.2).
	Resolvers []Resolver
	// UntypedRefs treats any string of an untyped document that has the
	// form of a reference (/r/…) as a reference (opt-in, §G.4.2).
	UntypedRefs bool
	// Authors includes authors, creation times and author signatures.
	Authors bool
	// Requires makes an incremental bundle: "ns/name" → an id already in
	// the target. Full documents then start right after it; a document
	// whose required id is its head is left out.
	Requires map[string]string
	// ForeignParents changes how resources of a branch namespace (§7.6)
	// are bundled. By default their chains include the base's entries back
	// to genesis (§G.4.1), under the branch's name, so the bundle stands
	// alone. With ForeignParents, a chain starts after its foreign parent
	// (the base's head as of the branch's at), which goes in requires, and
	// a read-through resource (no entries of its own) is not bundled but
	// listed in external as "{branch}/{name}/rev/{head}": the target must
	// already hold the base, e.g. by importing with the branch mapped onto
	// the base namespace.
	ForeignParents bool
	// Recipients seal the bundle to their X25519 public keys (§G.5.1.1).
	Recipients []*ecdh.PublicKey
	// Plaintext allows writing lines of private and sealed namespaces
	// unsealed; without it or Recipients, Write refuses (§G.5.1).
	Plaintext bool
	// Now overrides the clock for the header's created.
	Now func() time.Time
}

// keyringName is the reserved keyring resource of an e2e namespace
// (§E.3.2).
const keyringName = "keyring"

// PlannedDoc is one document of an export plan.
type PlannedDoc struct {
	Key      string   `json:"doc"`
	NS       string   `json:"ns"`
	Name     string   `json:"resource"`
	Mode     string   `json:"history"`
	Head     string   `json:"head"`
	Deleted  bool     `json:"deleted,omitempty"`
	Requires string   `json:"requires,omitempty"`
	Selected bool     `json:"selected,omitempty"`
	Reasons  []string `json:"reasons,omitempty"` // why it is included, and why full
	Blobs    []string `json:"blobs,omitempty"`   // the blob lines it gets (§G.4.1)

	needRevs map[string]string // pinned revisions needed → by whom
	done     string            // the mode it was processed in
	chain    map[string]bool   // full: every id from genesis to head
	skip     bool              // requires names the head: already in the target
	blobs    []plannedBlob     // its blob lines, in order
}

// plannedBlob is a blob line of a document: written right before the line
// whose id is before, the first whose document references it (§G.4.1).
type plannedBlob struct {
	blobRef
	before string
}

// addBlobs plans blob lines for the blobs refs that seen doesn't have yet,
// before the line before.
func (d *PlannedDoc) addBlobs(seen map[string]bool, refs []blobRef, before string) {
	for _, r := range refs {
		if seen[r.bid] {
			continue
		}
		seen[r.bid] = true
		d.blobs = append(d.blobs, plannedBlob{blobRef: r, before: before})
		d.Blobs = append(d.Blobs, r.bid)
	}
}

// ExportPlan is a selection closed over its dependencies.
type ExportPlan struct {
	Origin   string                 `json:"origin"`
	At       map[string]string      `json:"at"`
	Docs     map[string]*PlannedDoc `json:"docs"`
	External []string               `json:"external,omitempty"`
	Access   map[string]string      `json:"access"` // namespace → access level (§G.5.1)

	c       *client.Client
	opt     ExportOptions
	heads   map[string]map[string]client.HeadItem
	ext     map[string]bool
	queue   []string
	schemas map[string]any                        // schema revision path → document
	bases   map[string]map[string]client.HeadItem // branch ns → its base's heads as of at (nil: not a branch)
}

func (p *ExportPlan) reason(d *PlannedDoc, format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	for _, r := range d.Reasons {
		if r == s {
			return
		}
	}
	d.Reasons = append(d.Reasons, s)
}

// PlanExport resolves the selection and builds the dependency closure
// (§G.4.2) with modes closed downward (§G.4.3). Each namespace's at is
// taken when it is first needed: the selected namespaces up front, and
// namespaces reached only through dependencies when they are reached.
func PlanExport(ctx context.Context, c *client.Client, opt ExportOptions) (*ExportPlan, error) {
	if opt.Mode == "" {
		opt.Mode = Full
	}
	if opt.Mode != Full && opt.Mode != Snapshot {
		return nil, fmt.Errorf("export: mode must be %q or %q", Full, Snapshot)
	}
	origin, err := c.Origin(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: origin: %w", err)
	}
	p := &ExportPlan{Origin: origin, At: map[string]string{}, Docs: map[string]*PlannedDoc{}, Access: map[string]string{}, c: c, opt: opt,
		heads: map[string]map[string]client.HeadItem{}, bases: map[string]map[string]client.HeadItem{}, ext: map[string]bool{}, schemas: map[string]any{}}

	// Take the selected namespaces' at first (§G.4.1 consistency).
	var sel []string
	for _, s := range opt.Select {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ns := s
		if i := strings.IndexByte(s, '/'); i >= 0 {
			ns = s[:i]
		}
		if !client.ValidNSName(ns) {
			return nil, fmt.Errorf("export: invalid selection %q", s)
		}
		if err := p.loadNS(ctx, ns); err != nil {
			return nil, err
		}
		sel = append(sel, s)
	}
	if len(sel) == 0 {
		return nil, fmt.Errorf("export: nothing selected")
	}
	for _, s := range sel {
		if !strings.Contains(s, "/") {
			names := make([]string, 0, len(p.heads[s]))
			for n, h := range p.heads[s] {
				if h.Kind != "purge" {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			for _, n := range names {
				if err := p.add(ctx, s, n, true, "selected ("+s+")"); err != nil {
					return nil, err
				}
			}
			continue
		}
		ns, name, ok := SplitKey(s)
		if !ok {
			return nil, fmt.Errorf("export: invalid selection %q", s)
		}
		if err := p.add(ctx, ns, name, true, "selected"); err != nil {
			return nil, err
		}
	}
	for len(p.queue) > 0 {
		for len(p.queue) > 0 {
			k := p.queue[0]
			p.queue = p.queue[1:]
			if err := p.process(ctx, p.Docs[k]); err != nil {
				return nil, fmt.Errorf("export: %s: %w", k, err)
			}
		}
		// Keys travel via the keyring (§G.5): an e2e namespace's comes along.
		for _, ns := range sortedAccess(p.Access, AccessE2E) {
			hi, ok := p.heads[ns][keyringName]
			if !ok || hi.Kind == "purge" || p.isExternal(ns, keyringName) || p.Docs[Key(ns, keyringName)] != nil {
				continue
			}
			if err := p.add(ctx, ns, keyringName, false, "the keyring of an e2e namespace (§E.3.2, §G.5)"); err != nil {
				return nil, err
			}
		}
	}
	// Pinned revisions must be in what is exported (or already required).
	for _, d := range p.Docs {
		for rev, by := range d.needRevs {
			if d.Mode == Snapshot && rev != d.Head {
				return nil, fmt.Errorf("export: %s: pinned revision %s (from %s) is not the head", d.Key, rev, by)
			}
			if d.Mode == Full && !d.chain[rev] {
				return nil, fmt.Errorf("export: %s: pinned revision %s (from %s) is not in its chain as of at %s; export again", d.Key, rev, by, p.At[d.NS])
			}
		}
	}
	for e := range p.ext {
		p.External = append(p.External, e)
	}
	sort.Strings(p.External)
	return p, nil
}

func (p *ExportPlan) loadNS(ctx context.Context, ns string) error {
	if _, ok := p.heads[ns]; ok {
		return nil
	}
	h, err := p.c.NSHead(ctx, ns)
	if err != nil {
		return fmt.Errorf("export: namespace %s: %w", ns, err)
	}
	access, err := p.accessOf(ctx, ns, h.ID)
	if err != nil {
		return err
	}
	if access == AccessE2E && p.opt.Mode == Snapshot {
		// §G.5.1: a snapshot of an e2e namespace is a sealed genesis made
		// by a client holding its keys, which this exporter isn't.
		return fmt.Errorf("export: namespace %s is e2e (Addendum E.3): a snapshot needs a client holding its keys to seal a new genesis (§G.5.1); export its full history, which carries the ciphertext", ns)
	}
	p.Access[ns] = access
	items, err := p.c.Heads(ctx, ns, h.ID)
	if err != nil {
		return fmt.Errorf("export: namespace %s heads: %w", ns, err)
	}
	m := make(map[string]client.HeadItem, len(items))
	for _, it := range items {
		m[it.Resource] = it
	}
	p.At[ns], p.heads[ns] = h.ID, m
	return nil
}

// accessOf is a namespace's access level (§G.5.1). A sealed namespace's
// document is read with the client's keys: without them the export can't
// read its content either.
func (p *ExportPlan) accessOf(ctx context.Context, ns, nsID string) (string, error) {
	lv, err := p.c.EncryptionLevel(ctx, ns)
	if err != nil {
		return "", fmt.Errorf("export: namespace %s: %w", ns, err)
	}
	if lv == "e2e" {
		return AccessE2E, nil
	}
	doc, err := p.c.NSDoc(ctx, ns, nsID)
	if err != nil {
		if errors.Is(err, client.ErrNoKeys) {
			return "", fmt.Errorf("export: namespace %s is sealed (Addendum E.2) and the exporter has no keys for it: it needs a read grant, and the identity the grant's enc names if the keys are wrapped (§E.2.3, §G.5): %w", ns, err)
		}
		return "", fmt.Errorf("export: namespace %s: %w", ns, err)
	}
	switch {
	case lv == "sealed":
		return AccessSealed, nil
	case doc.Value["read"] == "public":
		return AccessPublic, nil
	}
	return AccessPrivate, nil
}

func sortedAccess(m map[string]string, level string) []string {
	var out []string
	for ns, a := range m {
		if a == level {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

func (p *ExportPlan) isExternal(ns, name string) bool {
	for _, e := range p.opt.External {
		if e == ns || e == ns+"/"+name {
			return true
		}
	}
	return false
}

// add includes a document (or finds it) and queues it.
func (p *ExportPlan) add(ctx context.Context, ns, name string, selected bool, why string) error {
	k := Key(ns, name)
	if d, ok := p.Docs[k]; ok {
		d.Selected = d.Selected || selected
		p.reason(d, "%s", why)
		return nil
	}
	if err := p.loadNS(ctx, ns); err != nil {
		return err
	}
	hi, ok := p.heads[ns][name]
	if !ok || hi.Kind == "purge" {
		// Purged content is never exported (§G.4.1).
		return fmt.Errorf("export: %s is not in %s as of %s (never existed or purged); %s — leave it out with external", k, ns, p.At[ns], why)
	}
	if p.opt.ForeignParents && p.opt.Requires[k] == "" {
		bh, err := p.baseHeads(ctx, ns)
		if err != nil {
			return err
		}
		if b, ok := bh[name]; ok && b.Kind != "purge" {
			if b.Target == hi.Target {
				// Read-through: the base's content as of at.
				p.ext[External{NS: ns, Name: name, Rev: hi.Target}.String()] = true
				return nil
			}
			if p.opt.Requires == nil {
				p.opt.Requires = map[string]string{}
			}
			p.opt.Requires[k] = b.Target // the foreign parent
		}
	}
	d := &PlannedDoc{Key: k, NS: ns, Name: name, Mode: p.opt.Mode, Head: hi.Target, Deleted: hi.Kind == "tombstone",
		Selected: selected, needRevs: map[string]string{}}
	if r := p.opt.Requires[k]; r != "" {
		d.Requires = r
		if r == d.Head {
			d.skip = true
		}
	}
	p.reason(d, "%s", why)
	p.Docs[k] = d
	p.queue = append(p.queue, k)
	return nil
}

// need records a dependency found while processing from.
func (p *ExportPlan) need(ctx context.Context, from *PlannedDoc, t Target, forceFull bool, why string) error {
	if t.NS == from.NS && t.Name == from.Name && (t.Rev == "" || t.Rev == from.Head) {
		return nil // a document referring to itself (an older revision of itself forces full below)
	}
	if p.isExternal(t.NS, t.Name) {
		p.ext[External{NS: t.NS, Name: t.Name, Rev: t.Rev}.String()] = true
		return nil
	}
	if err := p.add(ctx, t.NS, t.Name, false, why+" from "+from.Key); err != nil {
		return err
	}
	d := p.Docs[Key(t.NS, t.Name)]
	if d == nil {
		if t.Rev != "" {
			// A read-through resource declared external: a pin must name
			// the revision the target is checked for.
			p.ext[External{NS: t.NS, Name: t.Name, Rev: t.Rev}.String()] = true
		}
		return nil
	}
	if t.Rev != "" {
		d.needRevs[t.Rev] = from.Key
		if t.Rev != d.Head {
			forceFull = true
			why = "pinned to " + t.Rev + ", not its head"
		}
	}
	if forceFull && d.Mode != Full {
		d.Mode = Full
		p.reason(d, "full: %s (from %s)", why, from.Key)
		p.queue = append(p.queue, d.Key)
	}
	return nil
}

// baseHeads returns the heads of ns's base as of the branch's at, or nil
// if ns isn't a branch.
func (p *ExportPlan) baseHeads(ctx context.Context, ns string) (map[string]client.HeadItem, error) {
	if m, ok := p.bases[ns]; ok {
		return m, nil
	}
	doc, err := p.c.NSDoc(ctx, ns, p.At[ns])
	if err != nil {
		return nil, fmt.Errorf("export: namespace %s: %w", ns, err)
	}
	var m map[string]client.HeadItem
	if b, ok := doc.Value["base"].(map[string]any); ok {
		bns, _ := b["ns"].(string)
		at, _ := b["at"].(string)
		items, err := p.c.Heads(ctx, bns, at)
		if err != nil {
			return nil, fmt.Errorf("export: base %s of %s: %w", bns, ns, err)
		}
		m = map[string]client.HeadItem{}
		for _, it := range items {
			m[it.Resource] = it
		}
	}
	p.bases[ns] = m
	return m, nil
}

// loader loads schema documents from the source for x-ref walks.
func (p *ExportPlan) loader(ctx context.Context) schema.Loader {
	return func(ref schema.Ref) (any, error) {
		if d, ok := p.schemas[ref.Path()]; ok {
			return d, nil
		}
		doc, err := p.c.Doc(ctx, ref.NS, ref.Name, ref.Rev)
		if err != nil && (client.IsNotFound(err) || client.IsGone(err)) && p.isExternal(ref.NS, ref.Name) {
			// Left out on purpose: a draft in a branch has the same
			// content (§3.3), enough to walk x-refs; the importer checks
			// the target holds it (§G.4.2).
			if r, rerr := p.c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true}); rerr == nil {
				doc, err = r.Doc, nil
			}
		}
		if err != nil {
			if client.IsNotFound(err) || client.IsGone(err) {
				return nil, &schema.UnavailableError{Ref: ref.Path()}
			}
			return nil, err
		}
		p.schemas[ref.Path()] = doc.Value
		return doc.Value, nil
	}
}

// revisionDeps adds the core references of one exported revision (§G.4.2
// level 1): its $schema, and $ref inside it if it is itself a schema.
func (p *ExportPlan) revisionDeps(ctx context.Context, d *PlannedDoc, rev string, doc any) (isSchema bool, err error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return false, nil
	}
	s, ok := obj["$schema"].(string)
	if !ok {
		return false, nil
	}
	if schema.IsDialect(s) {
		for _, r := range schema.Refs(doc) {
			if err := p.notDraft(ctx, d, r, "$ref in "+rev); err != nil {
				return true, err
			}
			if err := p.need(ctx, d, Target{r.NS, r.Name, r.Rev}, true, "$ref in "+rev); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	if r, ok := schema.ParseRef(s); ok {
		if err := p.notDraft(ctx, d, r, "$schema of "+rev); err != nil {
			return false, err
		}
		return false, p.need(ctx, d, Target{r.NS, r.Name, r.Rev}, true, "$schema of "+rev)
	}
	return false, nil
}

// ErrSchemaUnavailable is the error an export answers for a document that
// references a schema revision existing only in a branch (§6.1 drafts,
// §G.4.2), unless that schema's namespace is declared external.
var ErrSchemaUnavailable = errors.New("schema_unavailable")

// notDraft refuses a schema reference that resolves only in a branch of
// its namespace (§6.1 drafts): the bundle couldn't carry it under its path,
// so the document can't be exported until that branch is merged (§G.4.2).
func (p *ExportPlan) notDraft(ctx context.Context, d *PlannedDoc, r schema.Ref, why string) error {
	if p.isExternal(r.NS, r.Name) {
		return nil
	}
	_, err := p.loader(ctx)(r)
	var ue *schema.UnavailableError
	if err == nil || !errors.As(err, &ue) {
		return nil // available, or a failure reported where it is needed
	}
	b, ferr := p.c.FindDraft(ctx, r)
	if ferr != nil {
		return ferr
	}
	if b != "" {
		return fmt.Errorf("export: %w: %s: the %s, %s, exists only in branch %s (a draft schema revision, §6.1); merge that branch's schemas into %s before exporting, or declare %s external (§G.4.2)",
			ErrSchemaUnavailable, d.Key, why, r.Path(), b, r.NS, r.NS)
	}
	return nil // reported as unavailable where it is needed
}

func (p *ExportPlan) process(ctx context.Context, d *PlannedDoc) error {
	if d.done == Full || d.done == d.Mode || d.skip {
		return nil
	}
	d.done = d.Mode
	d.blobs, d.Blobs = nil, nil
	// Blobs referenced up to requires are in the target (§G.4.1): seen.
	seen := map[string]bool{}
	if p.Access[d.NS] == AccessE2E {
		// Ciphertext (§G.5): the chain is verified over it and bundled
		// verbatim. Nothing can be folded, so it brings no dependencies.
		entries, _, err := verify.Resource(ctx, p.c, d.NS, d.Name, d.Head, "")
		if err != nil {
			if client.IsPruned(err) {
				return fmt.Errorf("e2e history below the pruning horizon %s: a full export needs the archive (§8.6)", client.Horizon(err))
			}
			return err
		}
		d.chain = make(map[string]bool, len(entries))
		exporting := d.Requires == ""
		for _, e := range entries {
			d.chain[e.ID] = true
			// The blobs the sealed ops declare (§E.3.1).
			if e.Kind == "rev" {
				refs := revisionBlobs(true, e.Patches, nil)
				if exporting {
					d.addBlobs(seen, refs, e.ID)
				} else {
					for _, r := range refs {
						seen[r.bid] = true
					}
				}
			}
			if e.ID == d.Requires {
				exporting = true
			}
		}
		if d.Requires != "" && !d.chain[d.Requires] {
			return fmt.Errorf("requires %s is not in its chain", d.Requires)
		}
		return nil
	}
	var head any // the live head document, nil if deleted
	if d.Mode == Full {
		// Every revision from genesis is folded, so every exported
		// revision's $schema is known; the log is verified on the way.
		entries, _, err := verify.Resource(ctx, p.c, d.NS, d.Name, d.Head, "")
		if err != nil {
			if client.IsPruned(err) {
				return fmt.Errorf("history below the pruning horizon %s: a full export needs the archive (§8.6); use snapshot mode", client.Horizon(err))
			}
			return err
		}
		d.chain = make(map[string]bool, len(entries))
		exporting := d.Requires == ""
		var doc any
		live := false
		// The first exported line whose patch set writes a reference to
		// each blob: its blob line goes before that one if it comes before
		// the first document referencing it, as importers check it.
		mentioned := map[string]string{}
		for _, e := range entries {
			d.chain[e.ID] = true
			doc, live, err = verify.Replay(doc, live, []client.LogEntry{e})
			if err != nil {
				return err
			}
			if e.Kind == "rev" {
				// Core references (§G.4.2): its $schema and blobs.
				refs := revisionBlobs(false, nil, doc)
				if exporting {
					if _, err := p.revisionDeps(ctx, d, e.ID, doc); err != nil {
						return err
					}
					for _, b := range mentions(client.PatchStep(e.Patches)) {
						if _, ok := mentioned[b]; !ok {
							mentioned[b] = e.ID
						}
					}
					for _, r := range refs {
						before := e.ID
						if m, ok := mentioned[r.bid]; ok {
							before = m
						}
						d.addBlobs(seen, []blobRef{r}, before)
					}
				} else {
					for _, r := range refs {
						seen[r.bid] = true
					}
				}
			}
			if e.ID == d.Requires {
				exporting = true
			}
		}
		if d.Requires != "" && !d.chain[d.Requires] {
			return fmt.Errorf("requires %s is not in its chain", d.Requires)
		}
		if live {
			head = doc
		}
	} else if !d.Deleted {
		doc, err := p.c.Doc(ctx, d.NS, d.Name, d.Head)
		if err != nil {
			return err
		}
		head = doc.Value
		isSchema, err := p.revisionDeps(ctx, d, d.Head, head)
		if err != nil {
			return err
		}
		if isSchema {
			// Schemas are always full (§G.4.3).
			d.Mode = Full
			p.reason(d, "full: it is a schema")
			d.done = ""
			return p.process(ctx, d)
		}
		d.addBlobs(seen, revisionBlobs(false, nil, head), d.Head)
	}
	if head == nil {
		return p.resolvers(ctx, d, nil)
	}

	// Declared references (level 2): x-ref, found by a static walk.
	obj, _ := head.(map[string]any)
	_, typed := obj["$schema"]
	if typed {
		refs, err := annot.FindRefs(head, p.loader(ctx))
		if err != nil {
			return fmt.Errorf("x-ref walk: %w", err)
		}
		for _, r := range refs {
			// A string with /rev/ is pinned whatever the declaration says;
			// §6.5 reports mismatches as found.
			if r.Rev != "" {
				if err := p.need(ctx, d, Target{r.NS, r.Name, r.Rev}, d.Mode == Full, "pinned x-ref at "+r.Pointer); err != nil {
					return err
				}
			} else if err := p.need(ctx, d, Target{r.NS, r.Name, ""}, false, "live x-ref at "+r.Pointer); err != nil {
				return err
			}
		}
	} else if p.opt.UntypedRefs {
		var ferr error
		walkStrings(head, "", func(ptr, s string) {
			if ferr != nil {
				return
			}
			if r, ok := annot.ParseRefString(s); ok {
				ferr = p.need(ctx, d, Target{r.NS, r.Name, r.Rev}, r.Rev != "" && d.Mode == Full, "untyped reference at "+ptr)
			}
		})
		if ferr != nil {
			return ferr
		}
	}
	return p.resolvers(ctx, d, head)
}

func (p *ExportPlan) resolvers(ctx context.Context, d *PlannedDoc, head any) error {
	for _, r := range p.opt.Resolvers {
		ts, err := r.Resolve(ctx, p.c, d.NS, d.Name, head)
		if err != nil {
			return fmt.Errorf("resolver: %w", err)
		}
		for _, t := range ts {
			if err := p.need(ctx, d, t, t.Rev != "" && d.Mode == Full, "resolver"); err != nil {
				return err
			}
		}
	}
	return nil
}

// Header is the bundle header the plan writes.
func (p *ExportPlan) Header() Header {
	h := Header{Origin: p.Origin, At: map[string]string{}, Docs: map[string]DocInfo{}, Requires: map[string]string{},
		External: p.External, Authors: p.opt.Authors, Access: map[string]string{}}
	now := time.Now
	if p.opt.Now != nil {
		now = p.opt.Now
	}
	h.Created = now().UTC().Format(time.RFC3339)
	for k, d := range p.Docs {
		if d.skip {
			continue
		}
		h.Docs[k] = DocInfo{History: d.Mode, Head: d.Head}
		h.At[d.NS] = p.At[d.NS]
		h.Access[d.NS] = p.Access[d.NS]
		if d.Mode == Full && d.Requires != "" {
			h.Requires[k] = d.Requires
		}
	}
	return h
}

// Protected lists the namespaces whose lines hold plaintext of private or
// sealed content (§G.5.1).
func (p *ExportPlan) Protected() []string {
	h := p.Header()
	var out []string
	for ns, a := range h.Access {
		if a == AccessPrivate || a == AccessSealed {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

// Write streams the bundle: the header, then every document's lines, one
// document at a time (full documents' logs are fetched and verified again,
// so nothing is held in memory across documents). With Recipients it is
// written as a sealed bundle (§G.5.1.1); plaintext of private or sealed
// namespaces isn't written unsealed unless Plaintext is set.
func (p *ExportPlan) Write(ctx context.Context, w io.Writer) (*Summary, error) {
	if prot := p.Protected(); len(prot) > 0 && len(p.opt.Recipients) == 0 && !p.opt.Plaintext {
		return nil, fmt.Errorf("export: %s hold private or sealed content, which a bundle carries in plaintext: "+
			"seal the bundle to its recipients, or ask for plaintext explicitly (§G.5.1)", strings.Join(prot, ", "))
	}
	var sw *SealedWriter
	if len(p.opt.Recipients) > 0 {
		var err error
		if sw, err = NewSealedWriter(w, p.opt.Recipients); err != nil {
			return nil, err
		}
		w = sw
	}
	bw, err := NewWriter(w, p.Header())
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(p.Docs))
	for k, d := range p.Docs {
		if !d.skip {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	n := 0
	for _, k := range keys {
		d := p.Docs[k]
		// Blob lines, each right before the first line that references it.
		blobs := func(before string) error {
			for _, b := range d.blobs {
				if b.before != before {
					continue
				}
				if err := p.writeBlob(ctx, bw, d, b); err != nil {
					return fmt.Errorf("export: %s: %w", k, err)
				}
				n++
			}
			return nil
		}
		if d.Mode == Full {
			entries, _, err := verify.Resource(ctx, p.c, d.NS, d.Name, d.Head, d.Requires)
			if err != nil {
				return nil, fmt.Errorf("export: %s: %w", k, err)
			}
			for _, e := range entries {
				if err := blobs(e.ID); err != nil {
					return nil, err
				}
				if err := bw.History(d.NS, d.Name, e); err != nil {
					return nil, err
				}
				n++
			}
			continue
		}
		if err := blobs(d.Head); err != nil {
			return nil, err
		}
		if d.Deleted {
			err = bw.SnapshotDoc(d.NS, d.Name, d.Head, nil, true)
		} else {
			var doc *client.Doc
			doc, err = p.c.Doc(ctx, d.NS, d.Name, d.Head)
			if err != nil {
				return nil, fmt.Errorf("export: %s: %w", k, err)
			}
			err = bw.SnapshotDoc(d.NS, d.Name, d.Head, doc.Value, false)
		}
		if err != nil {
			return nil, err
		}
		n++
	}
	digest, err := bw.Close()
	if err != nil {
		return nil, err
	}
	if sw != nil {
		if err := sw.Close(); err != nil {
			return nil, err
		}
	}
	return &Summary{Header: bw.Header(), Digest: digest, Lines: n}, nil
}

// writeBlob reads a blob of d from the source, checked against its id with
// the reference's type and nonce, and writes its blob line. A sealed (E2)
// source's blob is fetched through its epoch's URL and opened with the
// client's keys, and checked against the reference (§E.2.2), so the line
// carries the plaintext.
func (p *ExportPlan) writeBlob(ctx context.Context, bw *Writer, d *PlannedDoc, b plannedBlob) error {
	var blob *client.Blob
	var err error
	if p.Access[d.NS] == AccessSealed {
		blob, err = p.c.GetBlobRef(ctx, d.NS, d.Name, client.BlobRef(b.bid, b.typ, b.size, b.nonce))
	} else {
		blob, err = p.c.GetBlob(ctx, d.NS, d.Name, b.bid, b.nonce)
	}
	if err != nil {
		return fmt.Errorf("blob %s: %w", b.bid, err)
	}
	return bw.Line(Line{NS: d.NS, Resource: d.Name, Blob: b.bid, Type: b.typ, Nonce: b.nonce, Data: blob.Data})
}

// Export plans and writes a bundle.
func Export(ctx context.Context, c *client.Client, w io.Writer, opt ExportOptions) (*ExportPlan, *Summary, error) {
	p, err := PlanExport(ctx, c, opt)
	if err != nil {
		return nil, nil, err
	}
	s, err := p.Write(ctx, w)
	return p, s, err
}

// walkStrings calls fn for every string in v with its JSON Pointer.
func walkStrings(v any, ptr string, fn func(ptr, s string)) {
	switch x := v.(type) {
	case string:
		fn(ptr, x)
	case []any:
		for i, e := range x {
			walkStrings(e, fmt.Sprintf("%s/%d", ptr, i), fn)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkStrings(x[k], ptr+"/"+escapePtr(k), fn)
		}
	}
}

func escapePtr(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
