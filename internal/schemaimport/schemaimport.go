// Package schemaimport brings external JSON Schemas (from http(s) URLs or
// local files) into a namespace as schema resources, so documents can use
// them under §6.1: every reference between them is rewritten to the immutable
// revision path of its target, /r/{ns}/{name}/rev/{id}#/json/pointer.
//
// The steps are:
//
//  1. Fetch the given documents and, transitively, every document they
//     $ref, resolving references against the base URI of their location
//     ($id, or draft-04 id, in the document and its subschemas).
//  2. Resolve every $ref to a document and a JSON Pointer in it. Plain-name
//     fragments ($anchor, $dynamicAnchor, draft ≤ 7 "$id": "#foo") become
//     pointers, since §6.1 resolves no anchors across revisions.
//  3. Merge each cycle of documents (a strongly connected component of the
//     reference graph) into one bundled document, the others under $defs,
//     since a revision can reference only revisions that already exist.
//  4. In dependency order (leaves first), convert each document to draft
//     2020-12 as the server accepts it, rewrite its references, and predict
//     the id the write will get (§3.3), so dependents can pin it.
//  5. Compile every converted schema as the server will (package schema),
//     and write them in one atomic batch (§7.5) when within batch limits.
//
// A resource whose head already holds the converted content is reused as is,
// so a re-run with unchanged sources writes nothing.
package schemaimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// Options configure an import.
type Options struct {
	NS   string // target namespace (required)
	Name string // resource name of the root; only with a single source
	// Limits: total documents, total bytes and the timeout of each fetch.
	// Zero means DefaultMaxDocs, DefaultMaxBytes and DefaultTimeout.
	MaxDocs  int
	MaxBytes int64
	Timeout  time.Duration
	// HTTPClient fetches http(s) sources (default: a client using the
	// environment's proxy settings).
	HTTPClient *http.Client
	// Files supplies documents in memory, by name: sources and the targets
	// of relative references between them are looked up here, at the
	// virtual location FileURL(name). Use FileURL(name).String() as the source.
	Files map[string][]byte
	// NoDisk refuses local files that aren't in Files (a server must not
	// read its own disk for a caller).
	NoDisk bool
	// DeclareSchema gives a schema that is closed at the instance root a
	// "$schema" property, for servers before spec v0.36, which validated a
	// document's $schema member. Since v0.36 validation leaves it out
	// (§6.2 step 5), so closed schemas type documents as they are.
	DeclareSchema bool
}

// Actions of a Resource.
const (
	Create    = "create"    // the resource doesn't exist
	Append    = "append"    // its head has other content: a new revision replaces it
	Restore   = "restore"   // it is tombstoned: restored with the new content
	Unchanged = "unchanged" // its head already holds this content
)

// Resource is one schema resource to write (or reuse).
type Resource struct {
	Name    string
	Sources []string // source URLs, the primary first; more than one for a bundled cycle
	Action  string
	Parent  string // head (Append) or tombstone (Restore) the write is based on
	ID      string // the revision the resource will be at
	Content any    // the converted schema document
	Patches []any  // the patch set to write (nil when Unchanged)
}

// Path is the revision path of the resource (§6.1).
func (r *Resource) Path(ns string) string { return "/r/" + ns + "/" + r.Name + "/rev/" + r.ID }

// Entry maps one source document to where it lands.
type Entry struct {
	Source   string `json:"source"`
	Resource string `json:"resource"`
	Path     string `json:"path"` // revision path, with a fragment for a bundled document
	Action   string `json:"action"`
	Root     bool   `json:"root,omitempty"`
}

// Result is an import plan, and after Write its outcome.
type Result struct {
	NS        string
	Resources []*Resource // dependency order: every resource after those it references
	Entries   []Entry     // one per source document; the roots last, in argument order
	Bundled   [][]string  // source URLs of each cycle merged into one resource
	Warnings  []string
	NSIDs     []string // namespace entries of the batches written
}

// Changed reports whether Write has anything to write.
func (r *Result) Changed() bool {
	for _, res := range r.Resources {
		if res.Action != Unchanged {
			return true
		}
	}
	return false
}

type loc struct {
	d   *doc
	ptr pointer.Pointer
}

type rawRef struct {
	at   pointer.Pointer
	val  string
	base *url.URL
}

type target struct {
	d    *doc
	ptr  pointer.Pointer
	meta string // a meta-schema URL instead of a document
}

type doc struct {
	key     string
	url     *url.URL
	raw     any
	root    bool
	rootIdx int
	refs    []rawRef
	targets map[string]target // by the referencing schema's source pointer
	b       *bundle
	prefix  pointer.Pointer // where the document sits in its bundle
	idx     int             // Tarjan
	low     int
	onStack bool
}

type bundle struct {
	members []*doc // the primary first
	res     *Resource
}

type planner struct {
	opt       Options
	f         *fetcher
	docs      map[string]*doc
	order     []*doc
	resources map[string]loc // absolute URL (no fragment) → schema resource root
	anchors   map[string]loc // absolute URL + "#" + anchor name
	fetchErr  map[string]error
	warnings  map[string]*warning
	warnOrder []string
	notes     []string // conversion lines that aren't per-location warnings
}

type warning struct {
	first string
	n     int
}

func (p *planner) warn(kind, where string) {
	w := p.warnings[kind]
	if w == nil {
		w = &warning{first: where}
		p.warnings[kind] = w
		p.warnOrder = append(p.warnOrder, kind)
	}
	w.n++
}

// Plan fetches, resolves and converts the sources and predicts the writes.
// It reads heads through c to decide each resource's action; with c nil
// every resource is planned as a create. Nothing is written.
func Plan(ctx context.Context, c *client.Client, sources []string, opt Options) (*Result, error) {
	if !client.ValidNSName(opt.NS) {
		return nil, fmt.Errorf("invalid namespace name %q", opt.NS)
	}
	if len(sources) == 0 {
		return nil, errors.New("no sources given")
	}
	if opt.Name != "" {
		if len(sources) != 1 {
			return nil, errors.New("-name needs exactly one source")
		}
		if !client.ValidResourceName(opt.Name) {
			return nil, fmt.Errorf("invalid resource name %q (§3.6)", opt.Name)
		}
	}
	p := &planner{opt: opt, f: newFetcher(opt), docs: map[string]*doc{}, resources: map[string]loc{},
		anchors: map[string]loc{}, fetchErr: map[string]error{}, warnings: map[string]*warning{}}
	if err := p.fetchAll(ctx, sources); err != nil {
		return nil, err
	}
	if err := p.resolve(); err != nil {
		return nil, err
	}
	bundles := p.bundles()
	res := &Result{NS: opt.NS}
	if err := p.build(ctx, c, bundles, res); err != nil {
		return nil, err
	}
	if err := compile(res); err != nil {
		return nil, err
	}
	res.Warnings = append(res.Warnings, p.notes...)
	for _, k := range p.warnOrder {
		w := p.warnings[k]
		msg := k + " (at " + w.first
		if w.n > 1 {
			msg += fmt.Sprintf(" and %d more", w.n-1)
		}
		res.Warnings = append(res.Warnings, msg+")")
	}
	return res, nil
}

// --- fetching and analysis ----------------------------------------------

func (p *planner) fetchAll(ctx context.Context, sources []string) error {
	var queue []*url.URL
	roots := map[string]int{}
	for i, s := range sources {
		u, err := sourceURL(s)
		if err != nil {
			return err
		}
		if _, dup := roots[u.String()]; !dup {
			roots[u.String()] = i
			queue = append(queue, u)
		}
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		key := u.String()
		_, isRoot := roots[key]
		if p.docs[key] != nil || (!isRoot && p.resources[key].d != nil) || p.fetchErr[key] != nil {
			continue
		}
		raw, final, err := p.f.fetch(ctx, u)
		if err != nil {
			if _, limit := err.(limitError); isRoot || limit {
				return err
			}
			p.fetchErr[key] = err // fatal only if still unresolved at the end
			continue
		}
		d := &doc{key: key, url: u, raw: raw, targets: map[string]target{}}
		if i, ok := roots[key]; ok {
			d.root, d.rootIdx = true, i
		}
		p.docs[key] = d
		p.order = append(p.order, d)
		if err := p.addResource(key, loc{d, pointer.Pointer{}}); err != nil {
			return err
		}
		if fk := final.String(); fk != key && p.resources[fk].d == nil {
			p.resources[fk] = loc{d, pointer.Pointer{}}
		}
		if err := p.analyse(d); err != nil {
			return err
		}
		for _, r := range d.refs {
			tu, err := r.base.Parse(r.val)
			if err != nil {
				return fmt.Errorf("%s#%s: invalid $ref %q", d.key, r.at.String(), r.val)
			}
			tu.Fragment, tu.RawFragment = "", ""
			tk := tu.String()
			if isMeta(tk) || p.resources[tk].d != nil || p.docs[tk] != nil {
				continue
			}
			switch tu.Scheme {
			case "http", "https":
			case "file":
				if d.url.Scheme != "file" {
					return fmt.Errorf("%s#%s: $ref %q names a local file from a remote document; refusing", d.key, r.at.String(), r.val)
				}
			default:
				continue // reported at resolution unless an $id defines it
			}
			queue = append(queue, tu)
		}
	}
	return nil
}

func (p *planner) addResource(key string, l loc) error {
	if prev, ok := p.resources[key]; ok && (prev.d != l.d || prev.ptr.String() != l.ptr.String()) {
		if prev.ptr.String() == "" && prev.d.key == key {
			return nil // the retrieval URL wins over an $id naming another document's URL
		}
		return fmt.Errorf("%s is the identifier of both %s#%s and %s#%s", key, prev.d.key, prev.ptr.String(), l.d.key, l.ptr.String())
	}
	p.resources[key] = l
	return nil
}

func (p *planner) addAnchor(base, name string, l loc) error {
	k := base + "#" + name
	if prev, ok := p.anchors[k]; ok && (prev.d != l.d || prev.ptr.String() != l.ptr.String()) {
		return fmt.Errorf("anchor %q is defined twice in %s (at %s and %s)", name, base, prev.ptr.String(), l.ptr.String())
	}
	p.anchors[k] = l
	return nil
}

// analyse walks a document's schemas, registering embedded resources ($id)
// and anchors, and collecting its $refs with their base URIs.
func (p *planner) analyse(d *doc) error {
	if obj, ok := d.raw.(map[string]any); ok {
		if s, ok := obj["$schema"].(string); ok && draftOf(s) == draftUnknown && !schema.IsDialect(s) {
			p.warn("custom meta-schema "+s+" is not imported; the document is stored as a draft 2020-12 schema", d.key)
		}
	}
	var walk func(node any, at pointer.Pointer, base *url.URL, draft int) error
	walk = func(node any, at pointer.Pointer, base *url.URL, draft int) error {
		obj, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		draft = draftAt(obj, draft)
		here := loc{d, at}
		idKey := "$id"
		if draft == draft4 || draft == draft3 {
			idKey = "id"
		}
		if s, ok := obj[idKey].(string); ok && s != "" {
			u, err := base.Parse(s)
			if err != nil {
				p.warn("ignored invalid "+idKey, d.key+"#"+at.String())
			} else {
				frag := u.Fragment
				u.Fragment, u.RawFragment = "", ""
				if u.String() != base.String() {
					if err := p.addResource(u.String(), here); err != nil {
						return err
					}
					base = u
				}
				if frag != "" && !strings.HasPrefix(frag, "/") {
					if err := p.addAnchor(base.String(), frag, here); err != nil {
						return err
					}
				}
			}
		}
		for _, k := range []string{"$anchor", "$dynamicAnchor"} {
			if s, ok := obj[k].(string); ok {
				if err := p.addAnchor(base.String(), s, here); err != nil {
					return err
				}
			}
		}
		if s, ok := obj["$ref"].(string); ok {
			d.refs = append(d.refs, rawRef{at: at, val: s, base: base})
		}
		for _, ch := range children(obj, draft) {
			if err := walk(ch.node, append(append(pointer.Pointer{}, at...), ch.toks...), base, draft); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(d.raw, pointer.Pointer{}, d.url, draftUnknown)
}

// resolve finds every $ref's target document and JSON Pointer.
func (p *planner) resolve() error {
	for _, d := range p.order {
		for _, r := range d.refs {
			where := fmt.Sprintf("%s#%s: $ref %q", d.key, r.at.String(), r.val)
			tu, err := r.base.Parse(r.val)
			if err != nil {
				return fmt.Errorf("%s: %v", where, err)
			}
			frag := tu.Fragment
			tu.Fragment, tu.RawFragment = "", ""
			tk := tu.String()
			if isMeta(tk) && p.resources[tk].d == nil {
				m := tk
				if frag != "" {
					m += "#" + tu.EscapedFragment()
				}
				d.targets[r.at.String()] = target{meta: m}
				continue
			}
			l, ok := p.resources[tk]
			if !ok {
				if err := p.fetchErr[tk]; err != nil {
					return fmt.Errorf("%s: %v", where, err)
				}
				return fmt.Errorf("%s: %s can't be fetched (only http(s) and local files are)", where, tk)
			}
			var t target
			switch {
			case frag == "":
				t = target{d: l.d, ptr: l.ptr}
			case strings.HasPrefix(frag, "/"):
				fp, err := pointer.Parse(frag)
				if err != nil {
					return fmt.Errorf("%s: malformed JSON Pointer fragment", where)
				}
				t = target{d: l.d, ptr: append(append(pointer.Pointer{}, l.ptr...), fp...)}
			default:
				a, ok := p.anchors[tk+"#"+frag]
				if !ok {
					return fmt.Errorf("%s: no anchor %q in %s", where, frag, tk)
				}
				t = target{d: a.d, ptr: a.ptr}
			}
			if _, err := translate(t.d.raw, draftUnknown, t.ptr); err != nil {
				return fmt.Errorf("%s: in %s: %v", where, t.d.key, err)
			}
			d.targets[r.at.String()] = t
		}
	}
	return nil
}

// --- cycles and bundles ---------------------------------------------------

func (d *doc) deps() []*doc {
	seen := map[*doc]bool{}
	var out []*doc
	for _, t := range d.targets {
		if t.d != nil && t.d != d && !seen[t.d] {
			seen[t.d] = true
			out = append(out, t.d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// bundles groups the documents into strongly connected components (Tarjan),
// returned in dependency order: each after every component it references.
func (p *planner) bundles() []*bundle {
	docs := append([]*doc(nil), p.order...)
	sort.Slice(docs, func(i, j int) bool { return docs[i].key < docs[j].key })
	for _, d := range docs {
		d.idx = -1
	}
	var (
		index int
		stack []*doc
		out   []*bundle
	)
	var strong func(d *doc)
	strong = func(d *doc) {
		d.idx, d.low = index, index
		index++
		stack = append(stack, d)
		d.onStack = true
		for _, w := range d.deps() {
			if w.idx < 0 {
				strong(w)
				d.low = min(d.low, w.low)
			} else if w.onStack {
				d.low = min(d.low, w.idx)
			}
		}
		if d.low != d.idx {
			return
		}
		var comp []*doc
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			w.onStack = false
			comp = append(comp, w)
			if w == d {
				break
			}
		}
		sort.Slice(comp, func(i, j int) bool {
			a, b := comp[i], comp[j]
			if a.root != b.root {
				return a.root
			}
			if a.root {
				return a.rootIdx < b.rootIdx
			}
			return a.key < b.key
		})
		b := &bundle{members: comp}
		for _, m := range comp {
			m.b = b
		}
		out = append(out, b)
	}
	for _, d := range docs {
		if d.idx < 0 {
			strong(d)
		}
	}
	return out
}

var invalidName = regexp.MustCompile(`[^a-z0-9._-]+`)

// baseName derives a resource name (§3.6) from a URL: its last path segment
// without a .json extension, lowercased, other characters replaced by "-".
func baseName(u *url.URL) string {
	p := strings.TrimRight(u.Path, "/")
	seg := path.Base(p)
	if seg == "." || seg == "/" || seg == "" {
		seg = u.Hostname()
	}
	seg = strings.ToLower(seg)
	seg = strings.TrimSuffix(seg, ".json")
	seg = invalidName.ReplaceAllString(seg, "-")
	seg = strings.TrimLeft(seg, "._-")
	if len(seg) > 110 {
		seg = seg[:110]
	}
	seg = strings.TrimRight(seg, "._-")
	if seg == "" {
		seg = "schema"
	}
	return seg
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:4])
}

// names gives each bundle a resource name: -name for the root, else the
// primary's URL. Colliding names keep the base name for the first root (in
// argument order), else the smallest URL; the others get a hash of their URL.
func (p *planner) names(bundles []*bundle) map[*bundle]string {
	out := map[*bundle]string{}
	groups := map[string][]*bundle{}
	fixed := map[string]bool{}
	for _, b := range bundles {
		pr := b.members[0]
		if p.opt.Name != "" && pr.root {
			out[b] = p.opt.Name
			fixed[p.opt.Name] = true
			continue
		}
		n := baseName(pr.url)
		groups[n] = append(groups[n], b)
	}
	used := map[string]bool{}
	for n := range fixed {
		used[n] = true
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, n := range keys {
		g := groups[n]
		sort.Slice(g, func(i, j int) bool {
			a, b := g[i].members[0], g[j].members[0]
			if a.root != b.root {
				return a.root
			}
			if a.root {
				return a.rootIdx < b.rootIdx
			}
			return a.key < b.key
		})
		for i, b := range g {
			name := n
			if i > 0 || fixed[n] {
				name = n + "-" + shortHash(b.members[0].key)
			}
			for used[name] {
				name += "-" + shortHash(name)
			}
			used[name] = true
			out[b] = name
		}
	}
	return out
}

// --- conversion and planning ---------------------------------------------

func (p *planner) build(ctx context.Context, c *client.Client, bundles []*bundle, res *Result) error {
	names := p.names(bundles)
	for _, b := range bundles {
		b.res = &Resource{Name: names[b]}
		for _, m := range b.members {
			b.res.Sources = append(b.res.Sources, m.key)
		}
		if len(b.members) > 1 {
			res.Bundled = append(res.Bundled, b.res.Sources)
		}
		// Places in the bundle: the primary at the root, the others under
		// $defs, by name, clear of the primary's own definitions.
		taken := map[string]bool{}
		if obj, ok := b.members[0].raw.(map[string]any); ok {
			for _, k := range []string{"$defs", "definitions"} {
				if m, ok := obj[k].(map[string]any); ok {
					for n := range m {
						taken[n] = true
					}
				}
			}
		}
		b.members[0].prefix = pointer.Pointer{}
		for _, m := range b.members[1:] {
			k := baseName(m.url)
			for i := 2; taken[k]; i++ {
				k = fmt.Sprintf("%s-%d", baseName(m.url), i)
			}
			taken[k] = true
			m.prefix = pointer.Pointer{"$defs", k}
		}
	}
	var patch map[string][]pointer.Pointer
	if p.opt.DeclareSchema {
		// Dry run: convert with stub references (a dependency's revision id
		// isn't known before its content is final) and find what to patch.
		docs := map[string]any{}
		for _, b := range bundles {
			content, err := p.convertBundle(b, func(d *doc) refRewriter { return p.rewriterFor(d, res.NS, true) }, func(string, string) {})
			if err != nil {
				return err
			}
			docs[b.res.Name] = content
		}
		var refused map[string]string
		var shared []nodeRef
		patch, refused, shared = declareSchema(docs)
		p.noteDeclaration(patch, refused, shared)
	}
	for _, b := range bundles {
		content, err := p.convertBundle(b, func(d *doc) refRewriter { return p.rewriterFor(d, res.NS, false) }, p.warn)
		if err != nil {
			return err
		}
		applyDeclaration(content, patch[b.res.Name])
		r := b.res
		r.Content = content
		if err := plan(ctx, c, res.NS, r); err != nil {
			return err
		}
		res.Resources = append(res.Resources, r)
	}
	// Entries: non-roots in dependency order, then the roots.
	var roots []Entry
	rootIdx := map[string]int{}
	for _, b := range bundles {
		for _, m := range b.members {
			e := Entry{Source: m.key, Resource: b.res.Name, Path: b.res.Path(res.NS), Action: b.res.Action, Root: m.root}
			if len(m.prefix) > 0 {
				e.Path += "#" + fragment(m.prefix)
			}
			if m.root {
				rootIdx[m.key] = m.rootIdx
				roots = append(roots, e)
			} else {
				res.Entries = append(res.Entries, e)
			}
		}
	}
	sort.SliceStable(roots, func(i, j int) bool { return rootIdx[roots[i].Source] < rootIdx[roots[j].Source] })
	res.Entries = append(res.Entries, roots...)
	return nil
}

// convertBundle converts the members of a bundle and merges them into one
// document: the primary at the root, the others under $defs. Each document
// keeps where it came from in x-source (and its own identifier in
// x-source-id, when that differs), as $id itself can't be kept (§6.1).
func (p *planner) convertBundle(b *bundle, rw func(*doc) refRewriter, warn func(kind, detail string)) (any, error) {
	var content any
	for i, m := range b.members {
		cv := &converter{where: m.key, warn: warn, rewrite: rw(m)}
		out, err := cv.schema(m.raw, pointer.Pointer{}, draftUnknown)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			if bv, ok := out.(bool); ok && len(b.members) > 1 {
				out = map[string]any{}
				if !bv {
					out = map[string]any{"not": map[string]any{}}
				}
			}
		}
		if obj, ok := out.(map[string]any); ok {
			if _, taken := obj["x-source"]; !taken {
				obj["x-source"] = strings.TrimPrefix(m.key, "file:///upload/")
				if id := sourceID(m); id != "" {
					obj["x-source-id"] = id
				}
			}
			if i == 0 {
				obj["$schema"] = schema.Dialect2020
			}
		}
		if i == 0 {
			content = out
			continue
		}
		obj := content.(map[string]any)
		defs, _ := obj["$defs"].(map[string]any)
		if defs == nil {
			defs = map[string]any{}
			obj["$defs"] = defs
		}
		defs[m.prefix[1]] = out
	}
	return content, nil
}

// sourceID returns the identifier a document declared for itself ($id, or
// id in draft 3 and 4) when it isn't the URL it was fetched from.
func sourceID(m *doc) string {
	obj, ok := m.raw.(map[string]any)
	if !ok {
		return ""
	}
	k := "$id"
	if d := draftAt(obj, draftUnknown); d == draft3 || d == draft4 {
		k = "id"
	}
	s, _ := obj[k].(string)
	if s == "" {
		return ""
	}
	u, err := m.url.Parse(s)
	if err != nil {
		return s
	}
	u.Fragment, u.RawFragment = "", ""
	if u.String() == "" || u.String() == m.url.String() || u.String() == m.key {
		return ""
	}
	return s
}

// rewriter rewrites the $refs of document d: into its own bundle as a
// same-document fragment, into another as that bundle's revision path.
func (p *planner) rewriter(d *doc, ns string) refRewriter { return p.rewriterFor(d, ns, false) }

// rewriterFor is rewriter, or with stub set, one that refers to other
// bundles as "@name#fragment" so that no revision id is needed.
func (p *planner) rewriterFor(d *doc, ns string, stub bool) refRewriter {
	return func(at pointer.Pointer) (string, string, error) {
		t, ok := d.targets[at.String()]
		if !ok {
			return "", "", fmt.Errorf("%s#%s: unresolved $ref", d.key, at.String())
		}
		if t.meta != "" {
			return "", t.meta, nil
		}
		tp, err := translate(t.d.raw, draftUnknown, t.ptr)
		if err != nil {
			return "", "", fmt.Errorf("%s#%s: %v", d.key, at.String(), err)
		}
		np := append(append(pointer.Pointer{}, t.d.prefix...), tp...)
		if t.d.b == d.b {
			return "#" + fragment(np), "", nil
		}
		if stub {
			return stubPrefix + t.d.b.res.Name + "#" + fragment(np), "", nil
		}
		if t.d.b.res.ID == "" {
			return "", "", fmt.Errorf("internal error: %s referenced before it is planned", t.d.key)
		}
		ref := t.d.b.res.Path(ns)
		if len(np) > 0 {
			ref += "#" + fragment(np)
		}
		return ref, "", nil
	}
}

// plan decides a resource's action from its head and predicts its id.
func plan(ctx context.Context, c *client.Client, ns string, r *Resource) error {
	r.Action = Create
	if c != nil {
		h, err := c.Head(ctx, ns, r.Name)
		if err != nil {
			return fmt.Errorf("reading %s/%s: %w", ns, r.Name, err)
		}
		switch h.State {
		case client.Live:
			d, err := c.Doc(ctx, ns, r.Name, h.ID)
			if err != nil {
				return fmt.Errorf("reading %s/%s: %w", ns, r.Name, err)
			}
			if jsonv.Equal(d.Value, r.Content) {
				r.Action, r.ID = Unchanged, h.ID
				return nil
			}
			r.Action, r.Parent = Append, h.ID
		case client.Tombstoned:
			r.Action, r.Parent = Restore, h.ID
		case client.Purged:
			return fmt.Errorf("%s/%s was purged; choose another name with -name or remove the source", ns, r.Name)
		}
	}
	if r.Action == Create {
		r.Patches = client.GenesisPatches(r.Content)
	} else {
		r.Patches = []any{map[string]any{"op": "replace", "path": "", "value": r.Content}}
	}
	id, err := client.ExpectedRevision(r.Parent, r.Patches)
	if err != nil {
		return err
	}
	r.ID = id
	return nil
}

// compile checks every converted schema as the server will on write
// (§6.2 step 5), resolving references among the planned revisions.
func compile(res *Result) error {
	planned := map[string]any{}
	for _, r := range res.Resources {
		planned[r.Path(res.NS)] = r.Content
	}
	load := func(ref schema.Ref) (any, error) {
		if d, ok := planned[ref.Path()]; ok {
			return d, nil
		}
		return nil, schema.ErrUnavailable
	}
	v := schema.NewValidator()
	for _, r := range res.Resources {
		if err := v.Validate(r.Content, load); err != nil {
			return fmt.Errorf("%s (from %s) is not a schema the server accepts: %v", r.Name, strings.Join(r.Sources, ", "), err)
		}
	}
	return nil
}

// --- writing ----------------------------------------------------------------

// Chunks splits the resources that need writing into dependency-ordered
// groups that each fit one batch of at most maxItems items and about
// maxBytes bytes (§6.6). A plan within the limits is one group, one atomic
// batch (§7.5).
func (r *Result) Chunks(maxItems, maxBytes int) [][]*Resource {
	var chunks [][]*Resource
	var cur []*Resource
	var size int
	for _, res := range r.Resources {
		if res.Action == Unchanged {
			continue
		}
		n := len(jsonv.Canonical(jsonv.FromGo(res.Patches))) + 256
		if len(cur) > 0 && (len(cur)+1 > maxItems || size+n > maxBytes) {
			chunks = append(chunks, cur)
			cur, size = nil, 0
		}
		cur = append(cur, res)
		size += n
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// Item is the batch item that writes the resource.
func (res *Resource) Item() client.BatchItem {
	it := client.BatchItem{Resource: res.Name, Steps: []client.Step{client.PatchStep(res.Patches)}}
	if res.Action == Create {
		it.IfNoneMatch = true
	} else {
		it.IfMatch = res.Parent
	}
	return it
}

// WireItem is the item as it goes in the body of POST /ns/{ns}/batch (§7.5).
func (res *Resource) WireItem() map[string]any {
	m := map[string]any{"resource": res.Name, "steps": []any{res.Patches}}
	if res.Action == Create {
		m["ifNoneMatch"] = "*"
	} else {
		m["ifMatch"] = res.Parent
	}
	return m
}

// Write writes the planned resources: in one atomic batch (§7.5) when within
// the namespace's batch limits, else in dependency-ordered batches. It checks
// that every revision got the predicted id.
func (r *Result) Write(ctx context.Context, c *client.Client) error {
	maxItems, maxBytes := BatchLimits(ctx, c, r.NS)
	for _, ch := range r.Chunks(maxItems, maxBytes) {
		var b client.BatchRequest
		for _, res := range ch {
			b.Items = append(b.Items, res.Item())
		}
		out, err := c.Batch(ctx, r.NS, b, false)
		if err != nil {
			return fmt.Errorf("writing to %s: %w", r.NS, describe(err))
		}
		for i, it := range out.Items {
			if i < len(ch) && (len(it.IDs) != 1 || it.IDs[0] != ch[i].ID) {
				return fmt.Errorf("%s: the server assigned %v, expected %s", ch[i].Name, it.IDs, ch[i].ID)
			}
		}
		r.NSIDs = append(r.NSIDs, out.NSID)
	}
	return nil
}

// describe adds the failing items of a batch error to its message.
func describe(err error) error {
	ae, ok := client.AsAPIError(err)
	if !ok || len(ae.Items()) == 0 {
		return err
	}
	var parts []string
	for _, it := range ae.Items() {
		parts = append(parts, fmt.Sprintf("%v", it))
	}
	return fmt.Errorf("%w: %s", err, strings.Join(parts, "; "))
}

// BatchLimits reads the namespace's itemsPerBatch and batchSize (§6.6),
// falling back to the defaults.
func BatchLimits(ctx context.Context, c *client.Client, ns string) (items, bytes int) {
	items, bytes = 1000, 16<<20
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return
	}
	d, err := c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return
	}
	if l, ok := d.Value["limits"].(map[string]any); ok {
		if n, ok := l["itemsPerBatch"].(float64); ok && n > 0 {
			items = int(n)
		}
		if n, ok := l["batchSize"].(float64); ok && n > 0 {
			bytes = int(n)
		}
	}
	return
}
