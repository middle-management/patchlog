package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// clock is an injectable clock (Options.Now).
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// tenv is one server under test.
type tenv struct {
	t      *testing.T
	e      *core.Engine
	srv    *httptest.Server
	clock  *clock
	opPriv ed25519.PrivateKey // operator key (auth enabled only)
	auth   bool
}

type envOpt func(*core.Options)

func withAuth(priv *ed25519.PrivateKey) envOpt {
	return func(o *core.Options) {
		pub, p := grant.GenerateKey()
		*priv = p
		ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": pub, "can": []any{"*"}}}))
		if err != nil {
			panic(err)
		}
		o.OperatorKeys = ks
		o.AuthDisabled = false
	}
}

func withLongPoll(d time.Duration) envOpt {
	return func(o *core.Options) { o.LongPollInterval = d }
}

func withFileDB(t *testing.T) envOpt {
	return func(o *core.Options) { o.Path = filepath.Join(t.TempDir(), "test.db") }
}

func newEnv(t *testing.T, opts ...envOpt) *tenv {
	t.Helper()
	c := &clock{t: t0}
	o := core.Options{Path: ":memory:", Origin: "https://cms.example", AuthDisabled: true, Now: c.Now, Purger: nopPurger{}}
	for _, f := range opts {
		f(&o)
	}
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(e))
	env := &tenv{t: t, e: e, srv: srv, clock: c, auth: !o.AuthDisabled}
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		e.Close()
	})
	return env
}

func newAuthEnv(t *testing.T, opts ...envOpt) *tenv {
	var priv ed25519.PrivateKey
	env := newEnv(t, append([]envOpt{withAuth(&priv)}, opts...)...)
	env.opPriv = priv
	return env
}

type nopPurger struct{}

func (nopPurger) PurgeTags([]string) {}

// req describes one request.
type req struct {
	method, path string
	body         any    // JSON-encoded unless raw is set
	raw          string // raw body
	hasRaw       bool
	ct           string
	ifMatch      string // unquoted id; quoted on send
	ifNoneMatch  string
	author       string
	bearer       string
	hdr          map[string]string
}

type resp struct {
	Code int
	H    http.Header
	Body []byte
}

func (r *resp) JSON() any {
	if len(r.Body) == 0 {
		return nil
	}
	v, err := jsonv.Parse(r.Body)
	if err != nil {
		panic("bad JSON response: " + string(r.Body))
	}
	return v
}

func (r *resp) Obj() map[string]any {
	m, _ := r.JSON().(map[string]any)
	return m
}

func (r *resp) Arr() []any {
	a, _ := r.JSON().([]any)
	return a
}

func (r *resp) Str(k string) string { s, _ := r.Obj()[k].(string); return s }

func (r *resp) String() string { return string(r.Body) }

var client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *tenv) do(q req) *resp {
	e.t.Helper()
	var body io.Reader
	switch {
	case q.hasRaw || q.raw != "":
		body = strings.NewReader(q.raw)
	case q.body != nil:
		b, err := json.Marshal(q.body)
		if err != nil {
			e.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequest(q.method, e.srv.URL+q.path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if q.ct != "" {
		hr.Header.Set("Content-Type", q.ct)
	} else if body != nil {
		if q.method == "PATCH" {
			hr.Header.Set("Content-Type", "application/json-patch+json")
		} else {
			hr.Header.Set("Content-Type", "application/json")
		}
	}
	if q.ifMatch != "" {
		hr.Header.Set("If-Match", `"`+q.ifMatch+`"`)
	}
	if q.ifNoneMatch != "" {
		hr.Header.Set("If-None-Match", q.ifNoneMatch)
	}
	if q.author != "" {
		hr.Header.Set("X-Author", q.author)
	}
	if q.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+q.bearer)
	}
	for k, v := range q.hdr {
		hr.Header.Set(k, v)
	}
	r, err := client.Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return &resp{Code: r.StatusCode, H: r.Header, Body: b}
}

// rawGet sends a request line verbatim (no URL normalisation by the client).
func (e *tenv) rawGet(path string) int {
	e.t.Helper()
	hr, _ := http.NewRequest("GET", e.srv.URL+"/", nil)
	hr.URL.Opaque = path
	r, err := client.Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	r.Body.Close()
	return r.StatusCode
}

func (e *tenv) get(path string, bearer ...string) *resp {
	e.t.Helper()
	q := req{method: "GET", path: path}
	if len(bearer) > 0 {
		q.bearer = bearer[0]
	}
	return e.do(q)
}

func expect(t *testing.T, r *resp, code int) {
	t.Helper()
	if r.Code != code {
		t.Fatalf("status %d, want %d: %s", r.Code, code, r.Body)
	}
}

func expectCode(t *testing.T, r *resp, status int, code string) {
	t.Helper()
	expect(t, r, status)
	if got := r.Str("code"); got != code {
		t.Fatalf("code %q, want %q: %s", got, code, r.Body)
	}
}

// --- dev-mode (auth disabled) shortcuts ----------------------------------

func addRoot(doc any) []any { return []any{map[string]any{"op": "add", "path": "", "value": doc}} }

func op(o, path string, v ...any) map[string]any {
	m := map[string]any{"op": o, "path": path}
	if len(v) > 0 {
		m["value"] = v[0]
	}
	return m
}

func ops(o ...map[string]any) []any {
	out := make([]any, len(o))
	for i, x := range o {
		out[i] = x
	}
	return out
}

// mkNS creates a namespace (dev mode or with the operator key).
func (e *tenv) mkNS(ns string, doc map[string]any) string {
	e.t.Helper()
	q := req{method: "PATCH", path: "/ns/" + ns, ifNoneMatch: "*", body: addRoot(doc), author: "admin"}
	if e.auth {
		q.bearer = e.operatorGrant(ns)
	}
	r := e.do(q)
	expect(e.t, r, 201)
	return r.H.Get("X-Config-Revision")
}

func (e *tenv) configID(ns string, bearer ...string) string {
	e.t.Helper()
	r := e.get("/ns/"+ns, bearer...)
	expect(e.t, r, 302)
	return r.H.Get("X-Config-Revision")
}

func (e *tenv) nsHead(ns string, bearer ...string) string {
	e.t.Helper()
	r := e.get("/ns/"+ns, bearer...)
	expect(e.t, r, 302)
	return strings.Trim(r.H.Get("ETag"), `"`)
}

// patchNS changes the namespace document with the current config id.
func (e *tenv) patchNS(ns string, patches []any, bearer string) *resp {
	e.t.Helper()
	return e.do(req{method: "PATCH", path: "/ns/" + ns, ifMatch: e.configID(ns, bearer), body: patches, bearer: bearer, author: "admin"})
}

// create creates a resource and returns its revision id.
func (e *tenv) create(ns, name string, doc any, who ...string) string {
	e.t.Helper()
	r := e.write("PATCH", ns, name, "", addRoot(doc), who...)
	expect(e.t, r, 201)
	return etagOf(r)
}

func (e *tenv) appendRev(ns, name, parent string, patches []any, who ...string) string {
	e.t.Helper()
	r := e.write("PATCH", ns, name, parent, patches, who...)
	expect(e.t, r, 201)
	return etagOf(r)
}

func (e *tenv) del(ns, name, head string, who ...string) string {
	e.t.Helper()
	r := e.write("DELETE", ns, name, head, nil, who...)
	expect(e.t, r, 200)
	return r.Str("tombstone")
}

// write sends a PATCH (parent "" = create) or DELETE. who is an author name
// in dev mode, or a bearer grant with auth enabled.
func (e *tenv) write(method, ns, name, parent string, patches []any, who ...string) *resp {
	e.t.Helper()
	q := req{method: method, path: "/r/" + ns + "/" + name, ifMatch: parent}
	if parent == "" {
		q.ifNoneMatch = "*"
	}
	if patches != nil {
		q.body = patches
	}
	if len(who) > 0 {
		if e.auth {
			q.bearer = who[0]
		} else {
			q.author = who[0]
		}
	} else {
		q.author = "alice"
	}
	return e.do(q)
}

func etagOf(r *resp) string { return strings.Trim(r.H.Get("ETag"), `"`) }

// doc fetches the document at the head.
func (e *tenv) doc(ns, name string, bearer ...string) map[string]any {
	e.t.Helper()
	r := e.get("/r/"+ns+"/"+name, bearer...)
	expect(e.t, r, 302)
	r = e.get(r.H.Get("Location"), bearer...)
	expect(e.t, r, 200)
	return r.Obj()
}

func (e *tenv) head(ns, name string, bearer ...string) string {
	e.t.Helper()
	r := e.get("/r/"+ns+"/"+name, bearer...)
	expect(e.t, r, 302)
	return etagOf(r)
}

// --- grants ---------------------------------------------------------------

func (e *tenv) operatorGrant(ns string) string {
	return mint(e.t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
}

func mint(t *testing.T, priv ed25519.PrivateKey, root map[string]any) string {
	t.Helper()
	g, err := grant.Mint(root, priv)
	if err != nil {
		t.Fatal(err)
	}
	return g.Encode()
}

type keyPair struct {
	kid  string
	pub  string
	priv ed25519.PrivateKey
}

func newKey(kid string) keyPair {
	pub, priv := grant.GenerateKey()
	return keyPair{kid, pub, priv}
}

func (k keyPair) entry(can ...string) map[string]any {
	c := make([]any, len(can))
	for i, x := range can {
		c[i] = x
	}
	return map[string]any{"kid": k.kid, "alg": "ed25519", "pub": k.pub, "can": c}
}

// grant mints a root block signed by k for sub in ns with verbs can.
func (e *tenv) grant(k keyPair, sub string, ns []string, can []string, extra ...map[string]any) string {
	e.t.Helper()
	root := map[string]any{"kid": k.kid, "sub": sub, "ns": strs(ns), "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}
	if can != nil {
		root["can"] = strs(can)
	}
	for _, x := range extra {
		for k, v := range x {
			root[k] = v
		}
	}
	return mint(e.t, k.priv, root)
}

func strs(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// --- independent id computation (§3) --------------------------------------

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func idBytes(t *testing.T, s string) []byte {
	t.Helper()
	if len(s) != 33 || s[0] != '1' {
		t.Fatalf("malformed id %q", s)
	}
	b, err := b32.DecodeString(s[1:])
	if err != nil || len(b) != 20 {
		t.Fatalf("malformed id %q", s)
	}
	return b
}

// hashID computes text(trunc160(sha256(parent ‖ 0x0A ‖ body))).
func hashID(t *testing.T, parent string, body []byte) string {
	t.Helper()
	h := sha256.New()
	if parent != "" {
		h.Write(idBytes(t, parent))
	}
	h.Write([]byte{0x0A})
	h.Write(body)
	return "1" + b32.EncodeToString(h.Sum(nil)[:20])
}

// canonical re-encodes a value with JCS.
func canonical(v any) []byte { return jsonv.Canonical(jsonv.FromGo(v)) }
