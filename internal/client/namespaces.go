package client

import (
	"context"
	"fmt"
	"net/url"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// NSHead is the answer of GET /ns/{ns}.
type NSHead struct {
	ID     string // the current ns_id (ETag)
	Config string // the config revision in force (X-Config-Revision)
}

// NSHead reads the namespace head pointer (§7.4).
func (c *Client) NSHead(ctx context.Context, ns string) (*NSHead, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 302 {
		return nil, r.apiError()
	}
	return &NSHead{ID: r.etag(), Config: r.header.Get("X-Config-Revision")}, nil
}

// NSDoc is the namespace document in force at an ns_id.
type NSDoc struct {
	ID     string // the ns_id it was read at
	Config string // the config revision in force there
	Raw    []byte
	Value  map[string]any
}

// NSDoc fetches the namespace document in force at nsID (immutable).
func (c *Client) NSDoc(ctx context.Context, ns, nsID string) (*NSDoc, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if err := checkID("namespace revision", nsID); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/rev/"+nsID, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	body := r.body
	if isJOSE(r) {
		if body, err = c.open(ctx, ns, "", string(r.body), fixedPL(seal.NamespaceDocPL(ns, nsID))); err != nil {
			return nil, fmt.Errorf("client: namespace document %s@%s: %w", ns, nsID, err)
		}
	}
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("client: namespace document %s@%s: %w", ns, nsID, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("client: namespace document %s@%s is not an object", ns, nsID)
	}
	return &NSDoc{ID: nsID, Config: r.header.Get("X-Config-Revision"), Raw: body, Value: m}, nil
}

// NSEntry is one entry of a namespace log (§7.4), with the fields of §3.5.
// Sub-entries of a batch are NSEntry values with only Resource/Kind/Target
// set (and Raw).
type NSEntry struct {
	ID        string
	Prev      string // "" for the first entry
	Kind      string // head, tombstone, purge, config, batch, branch, purge-ns, prune
	Resource  string
	Name      string         // branch: the branch's name
	At        string         // branch: the base's ns_id it starts at
	Target    string         // revision, tombstone, config revision or horizon id
	Remote    map[string]any // branch: a remote branch registration (§G.3)
	Entries   []NSEntry      // batch: config entry first, then resource entries
	Source    map[string]any // batch: optional provenance
	HasSource bool
	Author    string
	// Kid is the root key id of the grant the entry was written under, as
	// the server exposes it (not part of the hashed entry, like Author and
	// Created). "" with authentication disabled, or for entries written
	// before servers recorded it.
	Kid     string
	Created string
	Raw     map[string]any // the entry as served
}

// IsResource reports whether the entry concerns one resource (head,
// tombstone, purge or prune).
func (e NSEntry) IsResource() bool {
	switch e.Kind {
	case "head", "tombstone", "purge", "prune":
		return true
	}
	return false
}

// ParseNSEntry converts a served entry (jsonv model) to an NSEntry.
func ParseNSEntry(v any) (NSEntry, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return NSEntry{}, fmt.Errorf("client: namespace entry is not an object")
	}
	e := NSEntry{
		ID: str(m, "id"), Prev: str(m, "prev"), Kind: str(m, "kind"), Resource: str(m, "resource"),
		Name: str(m, "name"), At: str(m, "at"), Target: str(m, "target"),
		Author: str(m, "author"), Kid: str(m, "kid"), Created: str(m, "created"), Raw: m,
	}
	e.Remote, _ = m["remote"].(map[string]any)
	if s, has := m["source"]; has {
		e.Source, _ = s.(map[string]any)
		e.HasSource = true
	}
	if arr, ok := m["entries"].([]any); ok {
		for _, x := range arr {
			sub, err := ParseNSEntry(x)
			if err != nil {
				return NSEntry{}, err
			}
			e.Entries = append(e.Entries, sub)
		}
	}
	return e, nil
}

func parseNSLog(body any, path string) ([]NSEntry, error) {
	arr, ok := body.([]any)
	if !ok {
		return nil, fmt.Errorf("client: %s: log is not an array", path)
	}
	out := make([]NSEntry, 0, len(arr))
	for _, x := range arr {
		e, err := ParseNSEntry(x)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// NSLog fetches the namespace log after since (exclusive; "" = from the
// first entry) up to nsID (inclusive), oldest first (immutable). A since
// not in the chain is a 404.
func (c *Client) NSLog(ctx context.Context, ns, nsID, since string) ([]NSEntry, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if err := checkID("namespace revision", nsID); err != nil {
		return nil, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, err
	}
	var q url.Values
	if since != "" {
		q = url.Values{"since": {since}}
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/rev/"+nsID+"/log", q, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	if isJOSE(r) {
		v, err := c.openRange(ctx, ns, since, nsID, string(r.body))
		if err != nil {
			return nil, fmt.Errorf("client: namespace log %s: %w", ns, err)
		}
		return parseNSLog(v, r.path)
	}
	return parseNSLog(r.value(), r.path)
}

// HeadItem is one resource of a /heads listing.
type HeadItem struct {
	Resource string
	Kind     string // head, tombstone or purge
	Target   string
}

// HeadsPage fetches one page of GET /ns/{ns}/rev/{nsID}/heads after the
// resource name after ("" = first page). next is "" on the last page.
func (c *Client) HeadsPage(ctx context.Context, ns, nsID, after string) (items []HeadItem, next string, err error) {
	if err := checkNS(ns); err != nil {
		return nil, "", err
	}
	if err := checkID("namespace revision", nsID); err != nil {
		return nil, "", err
	}
	var q url.Values
	if after != "" {
		q = url.Values{"after": {after}}
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/rev/"+nsID+"/heads", q, nil)
	if err != nil {
		return nil, "", err
	}
	if r.status != 200 {
		return nil, "", r.apiError()
	}
	m := r.obj()
	arr, _ := m["items"].([]any)
	for _, x := range arr {
		o, _ := x.(map[string]any)
		items = append(items, HeadItem{Resource: str(o, "resource"), Kind: str(o, "kind"), Target: str(o, "target")})
	}
	return items, str(m, "next"), nil
}

// Heads lists every resource as of nsID (including read-through ones in a
// branch), iterating all pages.
func (c *Client) Heads(ctx context.Context, ns, nsID string) ([]HeadItem, error) {
	var all []HeadItem
	after := ""
	for {
		items, next, err := c.HeadsPage(ctx, ns, nsID, after)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == "" {
			return all, nil
		}
		after = next
	}
}

// Branch is one entry of GET /ns/{ns}/branches.
type Branch struct {
	Name      string
	At        string
	Frozen    bool
	Purged    bool
	Successor string
	Remote    map[string]any // remote branch registrations (§G.3)
	Raw       map[string]any
}

// Branches lists a namespace's direct branches (§7.4).
func (c *Client) Branches(ctx context.Context, ns string) ([]Branch, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/branches", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	arr, _ := r.value().([]any)
	out := make([]Branch, 0, len(arr))
	for _, x := range arr {
		m, _ := x.(map[string]any)
		b := Branch{Name: str(m, "name"), At: str(m, "at"), Successor: str(m, "successor"), Raw: m}
		b.Frozen, _ = m["frozen"].(bool)
		b.Purged, _ = m["purged"].(bool)
		b.Remote, _ = m["remote"].(map[string]any)
		out = append(out, b)
	}
	return out, nil
}

// ConfigResult is the outcome of a namespace-document write.
type ConfigResult struct {
	Status int    // 201, or 200 for an idempotent retry
	Config string // the new config revision id
	NSID   string // the config entry's ns_id
}

func (c *Client) patchNS(ctx context.Context, ns string, precond map[string]string, patches any) (*ConfigResult, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	b, err := encodeJSON(patches)
	if err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "PATCH", "/ns/"+ns, nil, &request{header: precond, body: b, ct: "application/json-patch+json"})
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 201 {
		return nil, r.apiError()
	}
	m := r.obj()
	res := &ConfigResult{Status: r.status, Config: r.header.Get("X-Config-Revision"), NSID: r.header.Get("X-Namespace-Revision")}
	if res.Config == "" {
		res.Config = str(m, "config")
	}
	if res.NSID == "" {
		res.NSID = str(m, "ns_id")
	}
	return res, nil
}

// CreateNamespace creates a namespace whose document is doc (the genesis
// patch set [{op:add, path:"", value:doc}], If-None-Match: *). It needs an
// operator grant with authentication on (§C.4).
func (c *Client) CreateNamespace(ctx context.Context, ns string, doc any) (*ConfigResult, error) {
	return c.patchNS(ctx, ns, map[string]string{"If-None-Match": "*"}, GenesisPatches(doc))
}

// PatchConfig changes the namespace document. configID is the current
// config revision (X-Config-Revision), not the ns_id (§7.4).
func (c *Client) PatchConfig(ctx context.Context, ns, configID string, patches any) (*ConfigResult, error) {
	if err := checkID("config", configID); err != nil {
		return nil, err
	}
	return c.patchNS(ctx, ns, map[string]string{"If-Match": quote(configID)}, patches)
}

// BranchRequest creates a branch (§7.6).
type BranchRequest struct {
	Name    string
	At      string // "" = the base's current head
	Patches any    // optional changes to the copied document
}

// BranchResult is the outcome of creating a branch.
type BranchResult struct {
	Status int
	Name   string
	Config string // the branch's config genesis id
	NSID   string // the branch entry in the base's log
}

// CreateBranch creates a branch of base.
func (c *Client) CreateBranch(ctx context.Context, base string, br BranchRequest) (*BranchResult, error) {
	if err := checkNS(base); err != nil {
		return nil, err
	}
	body := map[string]any{"name": br.Name}
	if br.At != "" {
		body["at"] = br.At
	}
	if br.Patches != nil {
		p, err := ToValue(br.Patches)
		if err != nil {
			return nil, err
		}
		body["patches"] = p
	}
	b, err := encodeJSON(body)
	if err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "POST", "/ns/"+base+"/branches", nil, &request{header: map[string]string{"If-None-Match": "*"}, body: b, ct: "application/json"})
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 201 {
		return nil, r.apiError()
	}
	m := r.obj()
	res := &BranchResult{Status: r.status, Name: str(m, "name"), Config: str(m, "config"), NSID: r.header.Get("X-Namespace-Revision")}
	if res.NSID == "" {
		res.NSID = str(m, "ns_id")
	}
	return res, nil
}

// Step is one step of a batch item: a patch set or a delete.
type Step struct {
	Delete  bool
	Patches any
}

// PatchStep is a step appending (or restoring with) a patch set.
func PatchStep(patches any) Step { return Step{Patches: patches} }

// DeleteStep is a step appending a tombstone.
func DeleteStep() Step { return Step{Delete: true} }

// BatchItem writes one resource in a batch. Exactly one of IfMatch and
// IfNoneMatch must be set.
type BatchItem struct {
	Resource    string
	IfMatch     string
	IfNoneMatch bool
	Steps       []Step
}

// BatchConfig is an optional config change in a batch.
type BatchConfig struct {
	IfMatch string // current config id
	Patches any
}

// BatchRequest is the body of POST /ns/{ns}/batch (§7.5).
type BatchRequest struct {
	Items  []BatchItem
	Config *BatchConfig
	Source map[string]any // optional provenance { origin?, ns, at, bundle?, ids? }
	// SourceAuthorization, if set, is the grant sent as
	// Source-Authorization: it reads a local source, whose blobs the items
	// may then reference (§7.5, §7.8).
	SourceAuthorization string
	// SourceAuthorizations are further grants sent as repeated
	// Source-Authorization headers: any that verifies for a namespace
	// serves for it, e.g. one per branch holding draft schema revisions
	// the items resolve (§6.1).
	SourceAuthorizations []string
}

// BatchItemResult lists the ids an item produced (or, for a dry run, would).
type BatchItemResult struct {
	Resource string
	IDs      []string
	Raw      map[string]any
}

// BatchResult is the outcome of a batch.
type BatchResult struct {
	Status int    // 201, or 200 for a dry run or an idempotent retry
	NSID   string // the batch entry ("" for a dry run)
	Config string // the new config id, if the batch changed it
	Items  []BatchItemResult
}

func (b BatchRequest) body() (map[string]any, error) {
	out := map[string]any{}
	if b.Items != nil {
		items := make([]any, 0, len(b.Items))
		for _, it := range b.Items {
			m := map[string]any{"resource": it.Resource}
			if it.IfMatch != "" {
				m["ifMatch"] = it.IfMatch
			}
			if it.IfNoneMatch {
				m["ifNoneMatch"] = "*"
			}
			steps := make([]any, 0, len(it.Steps))
			for _, s := range it.Steps {
				if s.Delete {
					steps = append(steps, "delete")
					continue
				}
				p, err := ToValue(s.Patches)
				if err != nil {
					return nil, fmt.Errorf("client: batch item %s: %w", it.Resource, err)
				}
				steps = append(steps, p)
			}
			m["steps"] = steps
			items = append(items, m)
		}
		out["items"] = items
	}
	if b.Config != nil {
		p, err := ToValue(b.Config.Patches)
		if err != nil {
			return nil, fmt.Errorf("client: batch config: %w", err)
		}
		cm := map[string]any{"patches": p}
		if b.Config.IfMatch != "" {
			cm["ifMatch"] = b.Config.IfMatch
		}
		out["config"] = cm
	}
	if b.Source != nil {
		out["source"] = b.Source
	}
	return out, nil
}

// Batch applies writes to several resources of one namespace atomically
// (§7.5). With dryRun, nothing is written and the result reports the ids a
// submit would produce. A failure is an *APIError with code "batch" whose
// Items() list the failing items.
func (c *Client) Batch(ctx context.Context, ns string, b BatchRequest, dryRun bool) (*BatchResult, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	body, err := b.body()
	if err != nil {
		return nil, err
	}
	raw, err := encodeJSON(body)
	if err != nil {
		return nil, err
	}
	var q url.Values
	if dryRun {
		q = url.Values{"dry-run": {"1"}}
	}
	rq := &request{body: raw, ct: "application/json"}
	if b.SourceAuthorization != "" {
		rq.sourceAuth = append(rq.sourceAuth, b.SourceAuthorization)
	}
	rq.sourceAuth = append(rq.sourceAuth, b.SourceAuthorizations...)
	r, err := c.do(ctx, "POST", "/ns/"+ns+"/batch", q, rq)
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 201 {
		return nil, r.apiError()
	}
	m := r.obj()
	res := &BatchResult{Status: r.status, NSID: r.header.Get("X-Namespace-Revision"), Config: str(m, "config")}
	if res.NSID == "" {
		res.NSID = str(m, "ns_id")
	}
	arr, _ := m["items"].([]any)
	for _, x := range arr {
		o, _ := x.(map[string]any)
		res.Items = append(res.Items, BatchItemResult{Resource: str(o, "resource"), IDs: strList(o["ids"]), Raw: o})
	}
	return res, nil
}

// PurgeNamespace purges a frozen namespace (§8.5). head is its current
// ns_id. It returns the purge-ns entry's ns_id.
func (c *Client) PurgeNamespace(ctx context.Context, ns, head string) (string, error) {
	return c.PurgeNamespaceForce(ctx, ns, head, false)
}

// PurgeNamespaceForce is PurgeNamespace; with force (a grant chained to a *
// key), it goes ahead even if the namespace holds the last copy of a
// referenced schema revision (§6.1).
func (c *Client) PurgeNamespaceForce(ctx context.Context, ns, head string, force bool) (string, error) {
	if err := checkNS(ns); err != nil {
		return "", err
	}
	if err := checkID("namespace head", head); err != nil {
		return "", err
	}
	var q url.Values
	if force {
		q = url.Values{"force": {"1"}}
	}
	r, err := c.do(ctx, "POST", "/ns/"+ns+"/purge", q, &request{header: map[string]string{"If-Match": quote(head)}})
	if err != nil {
		return "", err
	}
	if r.status != 204 {
		return "", r.apiError()
	}
	return r.header.Get("X-Namespace-Revision"), nil
}
