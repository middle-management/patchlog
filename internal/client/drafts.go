package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/schema"
)

// Draft schema revisions (§6.1, §F.9).
//
// A schema path /r/N/R/rev/X never names a branch, but in a branch it may
// resolve to a revision drafted in a branch of N. Clients and consumers
// that validate such documents find drafts as the server does: they try N,
// then the branches it lists (GET /ns/{N}/branches, recursively), trying
// first the branches a release document names (§F.9). An id determines its
// document (§3.3), so any branch that serves X serves the right schema.
//
// With ResolveOptions.For, the namespace of the document being validated,
// the resolver also applies drafts.for where it can see it (the branch
// listing shows each branch's drafts, §7.4): a candidate serves For if For
// is the candidate or one of its branches, or For or one of its bases is
// listed in the candidate's own drafts.for (§6.1). This is best effort: a
// client may not see every candidate or every rule (For's base chain may be
// unreadable, and then nothing is filtered), and only the server's check
// decides whether a write is accepted. Resolved schemas may be cached by
// path across namespaces, since a path that resolves always means the same
// schema.

// ResolvedSchema is a schema revision found by ResolveSchema.
type ResolvedSchema struct {
	Doc *Doc
	// NS is the namespace it was read from: the path's own, or a branch
	// of it holding the draft.
	NS string
}

// Draft reports whether the revision was found in a branch, not in the
// path's own namespace.
func (r *ResolvedSchema) Draft(path schema.Ref) bool { return r.NS != path.NS }

// ResolveOptions tune ResolveSchema.
type ResolveOptions struct {
	// Drafts also looks among the branches of the path's namespace when
	// the namespace itself doesn't resolve the revision.
	Drafts bool
	// Prefer lists branches tried first, in order, before the others: the
	// branches named in a release document (§F.9).
	Prefer []string
	// MaxBranches bounds how many branches are tried (0: 256).
	MaxBranches int
	// For is the namespace whose document refers to the path: candidates
	// whose visible drafts.for doesn't serve it are skipped (§6.1). ""
	// applies no drafts.for.
	For string
}

// ResolveSchema fetches the schema revision ref: in ref.NS, then, with
// opt.Drafts, in the branches of ref.NS (§6.1). If it is found nowhere, the
// error is the one ref.NS answered (IsNotFound, IsGone, IsAuth). Other
// failures (network, 5xx) are returned as they happen.
func (c *Client) ResolveSchema(ctx context.Context, ref schema.Ref, opt ResolveOptions) (*ResolvedSchema, error) {
	d, err := c.Doc(ctx, ref.NS, ref.Name, ref.Rev)
	if err == nil {
		return &ResolvedSchema{Doc: d, NS: ref.NS}, nil
	}
	if !opt.Drafts || !unresolved(err) {
		return nil, err
	}
	max := opt.MaxBranches
	if max <= 0 {
		max = 256
	}
	tried := map[string]bool{ref.NS: true}
	// For and its bases, nearest first; nil if they can't be read.
	var forChain []string
	if opt.For != "" {
		forChain = c.baseChain(ctx, opt.For)
	}
	// serves applies a candidate's drafts.for (known: it could be seen).
	serves := func(ns string, drafts []string, known bool) bool {
		if forChain == nil || !known {
			return true
		}
		for _, x := range forChain {
			if x == ns || DraftsMatch(drafts, x) {
				return true
			}
		}
		return false
	}
	try := func(ns string) (*ResolvedSchema, bool, error) {
		if tried[ns] || !ValidNSName(ns) {
			return nil, false, nil
		}
		tried[ns] = true
		max--
		bd, berr := c.Doc(ctx, ns, ref.Name, ref.Rev)
		if berr == nil {
			return &ResolvedSchema{Doc: bd, NS: ns}, true, nil
		}
		if unresolved(berr) || errors.Is(berr, ErrNoKeys) {
			return nil, false, nil
		}
		return nil, false, berr
	}
	for _, ns := range opt.Prefer {
		if max <= 0 {
			break
		}
		if forChain != nil {
			if d, known := c.draftsOf(ctx, ns); !serves(ns, d, known) {
				continue
			}
		}
		r, ok, terr := try(ns)
		if terr != nil {
			return nil, terr
		}
		if ok {
			return r, nil
		}
	}
	// Breadth first through the branches, branches of branches included.
	queue := []string{ref.NS}
	listed := map[string]bool{}
	for len(queue) > 0 && max > 0 {
		ns := queue[0]
		queue = queue[1:]
		if listed[ns] {
			continue
		}
		listed[ns] = true
		bs, lerr := c.Branches(ctx, ns)
		if lerr != nil {
			if unresolved(lerr) {
				continue // a namespace the caller can't list
			}
			return nil, lerr
		}
		for _, b := range bs {
			if b.Purged || b.Remote != nil || b.Name == "" {
				continue
			}
			queue = append(queue, b.Name)
			if max <= 0 {
				break
			}
			if !serves(b.Name, b.Drafts, true) {
				continue
			}
			r, ok, terr := try(b.Name)
			if terr != nil {
				return nil, terr
			}
			if ok {
				return r, nil
			}
		}
	}
	return nil, err
}

// baseChain returns ns and its bases, nearest first, from their namespace
// documents; nil if one can't be read (best effort, §6.1).
func (c *Client) baseChain(ctx context.Context, ns string) []string {
	out := []string{}
	for i := 0; i < 64 && ns != ""; i++ {
		out = append(out, ns)
		h, err := c.NSHead(ctx, ns)
		if err != nil || h.ID == "" {
			return nil
		}
		d, err := c.NSDoc(ctx, ns, h.ID)
		if err != nil {
			return nil
		}
		b, _ := d.Value["base"].(map[string]any)
		if b == nil {
			return out
		}
		if _, remote := b["origin"]; remote {
			return out
		}
		ns, _ = b["ns"].(string)
	}
	return out
}

// draftsOf reads a namespace's drafts.for from its document; known is
// false if it can't be read.
func (c *Client) draftsOf(ctx context.Context, ns string) (drafts []string, known bool) {
	h, err := c.NSHead(ctx, ns)
	if err != nil || h.ID == "" {
		return nil, false
	}
	d, err := c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return nil, false
	}
	return draftsFor(d.Value["drafts"]), true
}

// draftsFor parses a drafts member, { "for": [ … ] } (§7.4).
func draftsFor(v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	arr, _ := m["for"].([]any)
	out := []string{}
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// DraftsMatch reports whether a drafts.for list names a namespace, by name
// or by a prefix ending in "*"; a bare "*" names every namespace (§7.4).
func DraftsMatch(list []string, ns string) bool {
	for _, p := range list {
		if pre, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(ns, pre) {
				return true
			}
		} else if p == ns {
			return true
		}
	}
	return false
}

// unresolved reports an answer meaning "not here for this caller".
func unresolved(err error) bool { return IsNotFound(err) || IsGone(err) || IsAuth(err) }

// IsBranch reports whether ns is a branch: its current namespace document
// has a base (§7.6).
func (c *Client) IsBranch(ctx context.Context, ns string) (bool, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return false, err
	}
	if h.ID == "" {
		return false, fmt.Errorf("client: namespace %s has no head", ns)
	}
	d, err := c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return false, err
	}
	_, ok := d.Value["base"]
	return ok, nil
}

// SchemaResolver loads schema revisions for validating consumers and
// caches them forever (an id determines its document, §3.3). With Drafts it
// finds drafts in branches as ResolveSchema does. It is safe for concurrent
// use.
type SchemaResolver struct {
	c   *Client
	opt ResolveOptions
	mu  sync.Mutex
	m   map[string]any
}

// NewSchemaResolver returns a resolver reading through c.
func NewSchemaResolver(c *Client, opt ResolveOptions) *SchemaResolver {
	return &SchemaResolver{c: c, opt: opt, m: map[string]any{}}
}

// Resolve returns the document of a schema revision. A revision found
// nowhere is schema.ErrUnavailable; other failures are returned as they are.
func (s *SchemaResolver) Resolve(ctx context.Context, ref schema.Ref) (any, error) {
	p := ref.Path()
	s.mu.Lock()
	v, ok := s.m[p]
	s.mu.Unlock()
	if ok {
		return v, nil
	}
	r, err := s.c.ResolveSchema(ctx, ref, s.opt)
	if err != nil {
		if unresolved(err) {
			return nil, schema.ErrUnavailable
		}
		return nil, err
	}
	s.mu.Lock()
	s.m[p] = r.Doc.Value
	s.mu.Unlock()
	return r.Doc.Value, nil
}

// Loader returns a schema.Loader over Resolve.
func (s *SchemaResolver) Loader(ctx context.Context) schema.Loader {
	return func(ref schema.Ref) (any, error) { return s.Resolve(ctx, ref) }
}

// FindDraft reports where a schema revision that its own namespace doesn't
// resolve is drafted: the branch holding it, or "" if none the caller can
// read does (or ref.NS resolves it). Exports use it to refuse documents
// referencing drafts with a clear error (§G.4).
func (c *Client) FindDraft(ctx context.Context, ref schema.Ref, prefer ...string) (string, error) {
	r, err := c.ResolveSchema(ctx, ref, ResolveOptions{Drafts: true, Prefer: prefer})
	if err != nil {
		if unresolved(err) {
			return "", nil
		}
		return "", err
	}
	if r.NS == ref.NS {
		return "", nil
	}
	return r.NS, nil
}
