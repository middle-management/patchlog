package client

import (
	"context"
	"fmt"
	"net/url"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// State is a resource's state as seen through its head pointer (§7.1).
type State int

const (
	// NotFound: never existed, or not readable by the caller.
	NotFound State = iota
	// Live: the head is a revision.
	Live
	// Tombstoned: the head is a tombstone; Head.Last is the last live revision.
	Tombstoned
	// Purged: the resource (or its namespace) was purged.
	Purged
)

func (s State) String() string {
	return [...]string{"notfound", "live", "tombstoned", "purged"}[s]
}

// Head is the answer of GET /r/{ns}/{name}.
type Head struct {
	State State
	ID    string // head revision (Live) or tombstone (Tombstoned) id
	Last  string // Tombstoned: last live revision id
}

// Head reads a resource's head pointer without following the redirect.
// NotFound and Purged are states, not errors.
func (c *Client) Head(ctx context.Context, ns, name string) (*Head, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/r/"+ns+"/"+name, nil, nil)
	if err != nil {
		return nil, err
	}
	switch r.status {
	case 302:
		return &Head{State: Live, ID: r.etag()}, nil
	case 404:
		return &Head{State: NotFound}, nil
	case 410:
		m := r.obj()
		if t := str(m, "tombstone"); t != "" {
			return &Head{State: Tombstoned, ID: t, Last: str(m, "last")}, nil
		}
		return &Head{State: Purged}, nil
	}
	return nil, r.apiError()
}

// Doc is a document at a revision.
type Doc struct {
	ID    string
	Raw   []byte // canonical bytes as served
	Value any    // parsed (jsonv model)
}

// Doc fetches the document at revision id (immutable). A tombstone id, a
// purge or a pruned revision is a 410 *APIError (IsGone / IsPruned).
func (c *Client) Doc(ctx context.Context, ns, name, id string) (*Doc, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("revision", id); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+id, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	v, err := jsonv.Parse(r.body)
	if err != nil {
		return nil, fmt.Errorf("client: document %s/%s@%s: %w", ns, name, id, err)
	}
	return &Doc{ID: id, Raw: r.body, Value: v}, nil
}

// Load reads the head and, if live, the document at it (§11 load).
// For a resource that is not live, doc is nil.
func (c *Client) Load(ctx context.Context, ns, name string) (*Head, *Doc, error) {
	h, err := c.Head(ctx, ns, name)
	if err != nil || h.State != Live {
		return h, nil, err
	}
	d, err := c.Doc(ctx, ns, name, h.ID)
	return h, d, err
}

// LogEntry is one entry of a resource log (§7.1).
type LogEntry struct {
	ID      string
	Parent  string // "" for genesis
	Kind    string // "rev" or "tombstone"
	Patches any    // canonical patch set (jsonv model); nil if absent
	// HasPatches is false for a tombstone, or a revision whose patch set is
	// absent (pruned or purged).
	HasPatches bool
	Author     string
	Created    string
	Signature  string         // author signature (§C.3), if served
	Raw        map[string]any // the entry as served
}

func parseLogEntry(v any) (LogEntry, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return LogEntry{}, fmt.Errorf("client: log entry is not an object")
	}
	e := LogEntry{
		ID: str(m, "id"), Parent: str(m, "parent"), Kind: str(m, "kind"),
		Author: str(m, "author"), Created: str(m, "created"), Signature: str(m, "signature"), Raw: m,
	}
	if p, has := m["patches"]; has {
		e.Patches, e.HasPatches = p, true
	}
	return e, nil
}

func parseLog(r *response) ([]LogEntry, error) {
	arr, ok := r.value().([]any)
	if !ok {
		return nil, fmt.Errorf("client: %s: log is not an array", r.path)
	}
	out := make([]LogEntry, 0, len(arr))
	for _, x := range arr {
		e, err := parseLogEntry(x)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// Log fetches the resource log after since (exclusive; "" = from genesis)
// up to id (inclusive), oldest first. With id "" it resolves the current
// head (a revision or tombstone) first. A range crossing the pruning horizon
// is a 410 pruned *APIError; a since that is not an ancestor is a 404.
func (c *Client) Log(ctx context.Context, ns, name, id, since string) ([]LogEntry, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, err
	}
	if id == "" {
		h, err := c.Head(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		switch h.State {
		case NotFound:
			return nil, &APIError{Status: 404, Code: "not_found", Method: "GET", Path: "/r/" + ns + "/" + name}
		case Purged:
			return nil, &APIError{Status: 410, Code: "gone", Method: "GET", Path: "/r/" + ns + "/" + name}
		}
		id = h.ID
	}
	if err := checkID("revision", id); err != nil {
		return nil, err
	}
	var q url.Values
	if since != "" {
		q = url.Values{"since": {since}}
	}
	r, err := c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+id+"/log", q, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	return parseLog(r)
}

// --- writes ------------------------------------------------------------

// WriteResult is the outcome of a resource write.
type WriteResult struct {
	Status int    // 201 created, or 200 for an idempotent retry (§7.2)
	ID     string // the new revision or tombstone id (ETag)
	NSID   string // X-Namespace-Revision: the namespace entry of the write
	Entry  *LogEntry
}

// Replayed reports an idempotent retry answered with the existing entry.
func (w *WriteResult) Replayed() bool { return w.Status == 200 }

// WriteOption adjusts one write request.
type WriteOption func(*request)

// WithSignature sends an author signature header (§C.3), "alg:kid:sig".
func WithSignature(sig string) WriteOption {
	return func(r *request) { r.header["Signature"] = sig }
}

func (c *Client) patchResource(ctx context.Context, ns, name string, precond map[string]string, patches any, opts []WriteOption) (*WriteResult, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	b, err := encodeJSON(patches)
	if err != nil {
		return nil, err
	}
	rq := &request{header: precond, body: b, ct: "application/json-patch+json"}
	for _, o := range opts {
		o(rq)
	}
	r, err := c.do(ctx, "PATCH", "/r/"+ns+"/"+name, nil, rq)
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 201 {
		return nil, r.apiError()
	}
	res := &WriteResult{Status: r.status, ID: r.etag(), NSID: r.header.Get("X-Namespace-Revision")}
	if m := r.obj(); m != nil {
		if e, err := parseLogEntry(m); err == nil {
			res.Entry = &e
		}
	}
	return res, nil
}

// Create creates a resource with its genesis patch set (If-None-Match: *).
func (c *Client) Create(ctx context.Context, ns, name string, patches any, opts ...WriteOption) (*WriteResult, error) {
	return c.patchResource(ctx, ns, name, map[string]string{"If-None-Match": "*"}, patches, opts)
}

// CreateDoc creates a resource whose genesis is [{op:add, path:"", value:doc}].
func (c *Client) CreateDoc(ctx context.Context, ns, name string, doc any, opts ...WriteOption) (*WriteResult, error) {
	return c.Create(ctx, ns, name, GenesisPatches(doc), opts...)
}

// Append appends a patch set on parent (If-Match). A 412 names the current
// head (APIError.Head).
func (c *Client) Append(ctx context.Context, ns, name, parent string, patches any, opts ...WriteOption) (*WriteResult, error) {
	if err := checkID("parent", parent); err != nil {
		return nil, err
	}
	return c.patchResource(ctx, ns, name, map[string]string{"If-Match": quote(parent)}, patches, opts)
}

// Restore restores a tombstoned resource: patches apply to the last live
// document ([] restores it unchanged, §8.2).
func (c *Client) Restore(ctx context.Context, ns, name, tombstone string, patches any, opts ...WriteOption) (*WriteResult, error) {
	return c.Append(ctx, ns, name, tombstone, patches, opts...)
}

// Delete tombstones a resource whose head is head. The result's ID is the
// tombstone id.
func (c *Client) Delete(ctx context.Context, ns, name, head string) (*WriteResult, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("head", head); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "DELETE", "/r/"+ns+"/"+name, nil, &request{header: map[string]string{"If-Match": quote(head)}})
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	id := str(r.obj(), "tombstone")
	if id == "" {
		id = r.etag()
	}
	return &WriteResult{Status: r.status, ID: id, NSID: r.header.Get("X-Namespace-Revision")}, nil
}

// Purge purges a resource whose head (revision or tombstone) is head
// (§8.3). force purges a referenced schema (needs a * key). It returns the
// purge entry's ns_id.
func (c *Client) Purge(ctx context.Context, ns, name, head string, force bool) (string, error) {
	if err := checkRes(ns, name); err != nil {
		return "", err
	}
	if err := checkID("head", head); err != nil {
		return "", err
	}
	var q url.Values
	if force {
		q = url.Values{"force": {"1"}}
	}
	r, err := c.do(ctx, "POST", "/r/"+ns+"/"+name+"/purge", q, &request{header: map[string]string{"If-Match": quote(head)}})
	if err != nil {
		return "", err
	}
	if r.status != 204 {
		return "", r.apiError()
	}
	return r.header.Get("X-Namespace-Revision"), nil
}

// PruneRequest is the body of POST /r/{ns}/{name}/prune (§8.6).
type PruneRequest struct {
	Horizon string
	Keep    []string // replaces the resource's earlier keep set; nil = none
}

// PruneResult is the outcome of a prune.
type PruneResult struct {
	Horizon string // the effective horizon (may be lower than requested)
	NSID    string // the prune entry, "" if the horizon did not move
}

// Prune prunes a resource's history below a horizon (§8.6). It takes no
// precondition.
func (c *Client) Prune(ctx context.Context, ns, name string, p PruneRequest) (*PruneResult, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	body := map[string]any{"horizon": p.Horizon}
	if p.Keep != nil {
		body["keep"] = p.Keep
	}
	b, err := encodeJSON(body)
	if err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "POST", "/r/"+ns+"/"+name+"/prune", nil, &request{body: b, ct: "application/json"})
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	return &PruneResult{Horizon: str(r.obj(), "horizon"), NSID: r.header.Get("X-Namespace-Revision")}, nil
}

// GenesisPatches is the patch set that creates doc: [{op:add, path:"", value:doc}].
func GenesisPatches(doc any) []any {
	return []any{map[string]any{"op": "add", "path": "", "value": doc}}
}
