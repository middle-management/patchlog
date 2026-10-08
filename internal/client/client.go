// Package client is a typed client for the Patch Log public HTTP API (§7).
//
// It is the base for namespace consumers (§10, package follow), integrity
// checks (§G.2, package verify) and grant checks (Addendum C, package
// grantcheck), and for services such as indexers, tree services, merge tools
// and export/import that talk to a deployment only through its public API.
//
// Conventions:
//
//   - Ids are text ids (§3.2). An empty id means "none" (genesis parent,
//     empty checkpoint).
//   - Redirects are never followed automatically: head pointers (302) are
//     returned as typed values read from Location / ETag.
//   - JSON bodies are parsed with jsonv (I-JSON, §3.1), so values use the
//     jsonv model (float64 numbers, map[string]any, []any) and can be
//     canonicalised and hashed exactly as the server does.
//   - Failures are *APIError, parsed from the §12 error body; see IsStale,
//     IsGone, IsPruned, IsNotFound and friends.
//   - Patch sets and documents passed to write methods may be any value that
//     encoding/json can marshal, or raw JSON as []byte / json.RawMessage.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// Client talks to one deployment. It is safe for concurrent use.
type Client struct {
	base   string // scheme://host[:port][/prefix], no trailing slash
	hc     *http.Client
	bearer string
	author string
	keys   *Keys // sealed namespaces (sealed.go)
	// sourceAuth are grants sent as Source-Authorization on every write
	// (WithSourceAuthorization).
	sourceAuth []string
	// signer signs resource writes and batch steps (WithSigner, §C.3.1).
	signer *sig.Key

	rootMu sync.Mutex
	root   *Root // GET /, once fetched
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient uses hc for requests. The client is copied and its
// CheckRedirect replaced, so redirects are never followed.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		cp := *hc
		c.hc = &cp
	}
}

// WithIdleConns keeps up to n idle connections per host, for a client that
// sends n requests at once (http.DefaultTransport keeps 2, so it would
// close the others after each burst and dial them again for the next). It
// replaces the transport, also one from an earlier WithHTTPClient, with a
// clone of http.DefaultTransport (same proxy, TLS and timeouts), traced as
// the default one is. n at or below the default's 2 changes nothing.
func WithIdleConns(n int) Option {
	return func(c *Client) {
		if n <= http.DefaultMaxIdleConnsPerHost {
			return
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConnsPerHost = n
		t.MaxIdleConns = max(t.MaxIdleConns, n)
		cp := *c.hc
		cp.Transport = telemetry.Transport(t)
		c.hc = &cp
	}
}

// WithBearer sends Authorization: Bearer <token> (Addendum C) on every request.
func WithBearer(token string) Option { return func(c *Client) { c.bearer = token } }

// WithSourceAuthorization sends each grant as a Source-Authorization header
// on every write: resource writes, batches and blob copies (§6.1, §7.8).
// Any of them that verifies for a namespace serves for it: to read a
// batch's local source, a copy's source, or a branch holding draft schema
// revisions the written documents resolve (§6.1). Requests that pass their
// own Source-Authorization grants send those too.
func WithSourceAuthorization(grants ...string) Option {
	return func(c *Client) { c.sourceAuth = append([]string(nil), grants...) }
}

// WithAuthor sends X-Author on every request (development mode only, §7.2).
func WithAuthor(name string) Option { return func(c *Client) { c.author = name } }

// New returns a client for the deployment at baseURL (e.g.
// "https://cms.example"). The origin (§G.1) is fetched lazily by Origin.
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("client: invalid base URL %q", baseURL)
	}
	c := &Client{base: strings.TrimRight(baseURL, "/"), hc: &http.Client{Transport: telemetry.Transport(nil)}}
	for _, o := range opts {
		o(c)
	}
	c.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, nil
}

// With returns a copy of the client with further options applied, e.g. a
// different bearer grant. The copy shares the HTTP client.
func (c *Client) With(opts ...Option) *Client {
	n := &Client{base: c.base, hc: c.hc, bearer: c.bearer, author: c.author, keys: c.keys, sourceAuth: c.sourceAuth, signer: c.signer}
	c.rootMu.Lock()
	n.root = c.root
	c.rootMu.Unlock()
	for _, o := range opts {
		o(n)
	}
	n.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return n
}

// BaseURL is the base URL the client was created with.
func (c *Client) BaseURL() string { return c.base }

// Root is the answer of GET /.
type Root struct {
	// Spec is the version of the spec the deployment implements (§7),
	// dotted decimal, e.g. "0.38"; "" for deployments from before v0.37,
	// which didn't publish it.
	Spec string
	// Auth is "grants" when the deployment authenticates requests with
	// grants and "disabled" when it runs with authentication disabled
	// (§1); "" for deployments from before v0.38, which didn't publish it.
	Auth string
	// Origin is the deployment's canonical origin (§G.1).
	Origin string
	// JWKSURI is where the deployment publishes its operator key history
	// (§C.4); "" for deployments from before v0.41.
	JWKSURI string
}

// AuthDisabled reports whether Auth is "disabled" (§1).
func (r Root) AuthDisabled() bool { return r.Auth == "disabled" }

// Root fetches GET / (§7, §G.1). It is fetched once and cached;
// AuthDisabled fetches it again.
func (c *Client) Root(ctx context.Context) (Root, error) {
	c.rootMu.Lock()
	cached := c.root
	c.rootMu.Unlock()
	if cached != nil {
		return *cached, nil
	}
	return c.fetchRoot(ctx)
}

func (c *Client) fetchRoot(ctx context.Context) (Root, error) {
	r, err := c.do(ctx, "GET", "/", nil, nil)
	if err != nil {
		return Root{}, err
	}
	if r.status != 200 {
		return Root{}, r.apiError()
	}
	m, _ := r.value().(map[string]any)
	root := Root{Spec: str(m, "spec"), Auth: str(m, "auth"), Origin: str(m, "origin"), JWKSURI: str(m, "jwks_uri")}
	c.rootMu.Lock()
	c.root = &root
	c.rootMu.Unlock()
	return root, nil
}

// AuthDisabled reports whether the deployment says, at GET /, that it runs
// with authentication disabled (§1, §7). Only then do checks that match
// merge.authors (§F.3, §F.6) match an entry with "grant": null on its
// author alone; under "grants", and for a deployment that doesn't say
// (before v0.38), such entries count for no one. Unlike Root, it asks
// every time, so a long-running tool such as the janitor notices when a
// deployment is restarted with authentication on.
func (c *Client) AuthDisabled(ctx context.Context) (bool, error) {
	root, err := c.fetchRoot(ctx)
	if err != nil {
		return false, err
	}
	return root.AuthDisabled(), nil
}

// Origin returns the deployment's canonical origin from GET / (§G.1). It is
// fetched once and cached.
func (c *Client) Origin(ctx context.Context) (string, error) {
	root, err := c.Root(ctx)
	if err != nil {
		return "", err
	}
	if root.Origin == "" {
		return "", fmt.Errorf("client: GET / returned no origin")
	}
	return root.Origin, nil
}

// --- names -------------------------------------------------------------

var (
	nsNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	resNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	idRe      = regexp.MustCompile(`^1[a-z2-7]{32}$`)
)

// ValidNSName reports whether s is a namespace name (§3.6).
func ValidNSName(s string) bool { return nsNameRe.MatchString(s) }

// ValidResourceName reports whether s is a resource name (§3.6).
func ValidResourceName(s string) bool { return resNameRe.MatchString(s) }

func checkNS(ns string) error {
	if !ValidNSName(ns) {
		return fmt.Errorf("client: invalid namespace name %q", ns)
	}
	return nil
}

func checkRes(ns, name string) error {
	if err := checkNS(ns); err != nil {
		return err
	}
	if !ValidResourceName(name) {
		return fmt.Errorf("client: invalid resource name %q", name)
	}
	return nil
}

func checkID(what, id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("client: invalid %s id %q", what, id)
	}
	return nil
}

// checkOptID accepts "" (none) or an id.
func checkOptID(what, id string) error {
	if id == "" {
		return nil
	}
	return checkID(what, id)
}

// --- transport ---------------------------------------------------------

type response struct {
	status int
	header http.Header
	body   []byte
	method string
	path   string
}

func (r *response) value() any {
	if len(r.body) == 0 {
		return nil
	}
	v, err := jsonv.Parse(r.body)
	if err != nil {
		return nil
	}
	return v
}

func (r *response) obj() map[string]any {
	m, _ := r.value().(map[string]any)
	return m
}

// etag returns the unquoted strong ETag.
func (r *response) etag() string { return strings.Trim(r.header.Get("ETag"), `"`) }

// request describes one call.
type request struct {
	header map[string]string
	body   []byte
	ct     string
	// sourceAuth are grants sent as repeated Source-Authorization headers
	// (§6.1, §7.8), after the client's own.
	sourceAuth []string
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, rq *request) (*response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if rq != nil && rq.body != nil {
		body = bytes.NewReader(rq.body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	c.setAuth(hr)
	if rq != nil {
		if rq.ct != "" {
			hr.Header.Set("Content-Type", rq.ct)
		}
		for k, v := range rq.header {
			hr.Header.Set(k, v)
		}
	}
	if method != "GET" && method != "HEAD" {
		var grants []string
		grants = append(grants, c.sourceAuth...)
		if rq != nil {
			grants = append(grants, rq.sourceAuth...)
		}
		for _, g := range grants {
			if g != "" {
				hr.Header.Add("Source-Authorization", "Bearer "+g)
			}
		}
	}
	res, err := c.hc.Do(hr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return &response{status: res.StatusCode, header: res.Header, body: b, method: method, path: path}, nil
}

func (c *Client) setAuth(hr *http.Request) {
	if c.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.author != "" {
		hr.Header.Set("X-Author", c.author)
	}
}

// encodeJSON marshals v, passing raw JSON through.
func encodeJSON(v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case json.RawMessage:
		return x, nil
	case nil:
		return nil, errors.New("client: nil body")
	}
	return json.Marshal(v)
}

// ToValue converts v (anything encoding/json marshals, or raw JSON bytes) to
// the jsonv value model, rejecting non-I-JSON input as the server would.
func ToValue(v any) (any, error) {
	b, err := encodeJSON(v)
	if err != nil {
		return nil, err
	}
	return jsonv.Parse(b)
}

func quote(id string) string { return `"` + id + `"` }

// --- small value helpers -----------------------------------------------

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func strList(v any) []string {
	a, _ := v.([]any)
	out := make([]string, 0, len(a))
	for _, x := range a {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
