// Package grantcheck lets a service verify a reader's grant locally
// (§A.6, §C.1 "consumers verify grants too", §C.6), with keys and
// revocations as of the namespace head (§10), mirroring the origin's checks
// in internal/core:
//
//   - the root signature by a key of the namespace document at its head;
//   - in a branch, keys follow the base (§C.4): a key the branch copied from
//     its base is accepted only while the base's current document still has
//     it with the same pub, recursively;
//   - revocations of the namespace and, for a branch, of every base;
//   - the order of §C.2: a grant not naming the namespace is 403 before
//     anything else; no usable grant (malformed, unknown key, bad
//     signature, revoked, expired, not yet valid) is 401;
//   - key scopes, including attrs (validated with internal/rules as the
//     core does) and requireAt/maxLag (checked against the named chain,
//     relative to the grant's issuance, default maxLag 60 seconds);
//   - read decisions: the grant allows read and its key-scope, block and
//     role rules pass against a read envelope
//     { action: "read", resource?, principal, now } (§C.2 item 5).
//
// The Checker fetches namespace documents with its own client (which needs
// read on the namespaces checked) and caches them for a TTL; after the TTL
// it re-reads the head pointers and refetches only if a head moved. A
// follower can call Observe to invalidate as soon as it sees a new entry.
package grantcheck

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/rules"
)

// Checker verifies grants against namespace documents fetched through a
// client. It is safe for concurrent use.
type Checker struct {
	c        *client.Client
	ttl      time.Duration
	now      func() time.Time
	maxGrant int

	mu     sync.Mutex
	states map[string]*nsState
	copied map[string]map[string]grant.Key // branch -> keys copied from its base at creation (immutable)
	rules  sync.Map                        // canonical rule -> *rules.Rule
}

// Option configures a Checker.
type Option func(*Checker)

// WithTTL sets how long fetched documents are used before the head pointers
// are re-read (default 30s). Zero re-reads the heads on every check.
func WithTTL(d time.Duration) Option { return func(ch *Checker) { ch.ttl = d } }

// WithClock sets the clock used for grant times and the envelope's now.
func WithClock(now func() time.Time) Option { return func(ch *Checker) { ch.now = now } }

// WithMaxGrantSize rejects bearer tokens longer than n bytes (default 8 KiB,
// the §6.6 default).
func WithMaxGrantSize(n int) Option { return func(ch *Checker) { ch.maxGrant = n } }

// New returns a Checker that reads namespace documents with c.
func New(c *client.Client, opts ...Option) *Checker {
	ch := &Checker{c: c, ttl: 30 * time.Second, now: time.Now, maxGrant: 8 << 10,
		states: map[string]*nsState{}, copied: map[string]map[string]grant.Key{}}
	for _, o := range opts {
		o(ch)
	}
	return ch
}

// Config is the part of a namespace document that grant checks use.
type Config struct {
	NS      string
	Head    string // the ns_id the document was read at
	Read    string // "public" or "grant"
	Keys    []grant.Key
	Roles   grant.Roles
	Revoked map[string]bool
	MaxLag  *time.Duration
	Base    string // the base namespace of a branch, "" otherwise
	BaseAt  string
	Doc     map[string]any
}

// ParseConfig extracts the grant-relevant fields of a namespace document.
func ParseConfig(ns, head string, doc map[string]any) (*Config, error) {
	cfg := &Config{NS: ns, Head: head, Read: "grant", Revoked: map[string]bool{}, Doc: doc}
	if r, ok := doc["read"].(string); ok {
		cfg.Read = r
	}
	var err error
	if cfg.Keys, err = grant.ParseKeys(doc["keys"]); err != nil {
		return nil, fmt.Errorf("grantcheck: %s /keys: %w", ns, err)
	}
	if cfg.Roles, err = grant.ParseRoles(doc["roles"]); err != nil {
		return nil, fmt.Errorf("grantcheck: %s /roles: %w", ns, err)
	}
	if rv, ok := doc["revoked"].([]any); ok {
		for _, x := range rv {
			if s, ok := x.(string); ok {
				cfg.Revoked[s] = true
			}
		}
	}
	if s, ok := doc["maxLag"].(string); ok {
		if d, err := grant.ParseDuration(s); err == nil {
			cfg.MaxLag = &d
		}
	}
	if b, ok := doc["base"].(map[string]any); ok {
		cfg.Base, _ = b["ns"].(string)
		cfg.BaseAt, _ = b["at"].(string)
	}
	return cfg, nil
}

// nsState is a cached namespace document with its effective keys and
// revocations (which depend on the bases' documents).
type nsState struct {
	cfg       *Config
	chain     []*Config // cfg, then its base, the base's base, …
	keys      []grant.Key
	revoked   map[string]bool
	checkedAt time.Time
}

// Observe tells the checker that ns has reached nsID (e.g. from a follower
// or an X-Namespace-Revision header). A cached state at another head is
// dropped, so the next check refetches.
func (ch *Checker) Observe(ns, nsID string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	for name, st := range ch.states {
		for _, c := range st.chain {
			if c.NS == ns && c.Head != nsID {
				delete(ch.states, name)
				break
			}
		}
	}
}

// Invalidate drops every cached state (all namespaces).
func (ch *Checker) Invalidate() {
	ch.mu.Lock()
	ch.states = map[string]*nsState{}
	ch.mu.Unlock()
}

// Config returns the namespace document at the head (cached), with the
// effective keys of §C.4 applied to Keys and revocations of every base
// merged into Revoked.
func (ch *Checker) Config(ctx context.Context, ns string) (*Config, error) {
	st, err := ch.state(ctx, ns)
	if err != nil {
		return nil, err
	}
	cfg := *st.cfg
	cfg.Keys, cfg.Revoked = st.keys, st.revoked
	return &cfg, nil
}

func (ch *Checker) state(ctx context.Context, ns string) (*nsState, error) {
	now := time.Now()
	ch.mu.Lock()
	st := ch.states[ns]
	var checkedAt time.Time
	if st != nil {
		checkedAt = st.checkedAt
	}
	ch.mu.Unlock()
	if st != nil && now.Sub(checkedAt) < ch.ttl {
		return st, nil
	}
	if st != nil {
		// Refresh only if a head in the chain moved.
		same := true
		for _, c := range st.chain {
			h, err := ch.c.NSHead(ctx, c.NS)
			if err != nil {
				return nil, err
			}
			if h.ID != c.Head {
				same = false
				break
			}
		}
		if same {
			ch.mu.Lock()
			st.checkedAt = now
			ch.mu.Unlock()
			return st, nil
		}
	}
	st, err := ch.load(ctx, ns, 0)
	if err != nil {
		return nil, err
	}
	st.checkedAt = now
	ch.mu.Lock()
	ch.states[ns] = st
	ch.mu.Unlock()
	return st, nil
}

// maxDepth bounds base chains (the deployment's branch depth is 8 by default).
const maxDepth = 32

func (ch *Checker) load(ctx context.Context, ns string, depth int) (*nsState, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("grantcheck: base chain of %s too deep", ns)
	}
	h, err := ch.c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	doc, err := ch.c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(ns, h.ID, doc.Value)
	if err != nil {
		return nil, err
	}
	st := &nsState{cfg: cfg, chain: []*Config{cfg}, keys: cfg.Keys, revoked: cfg.Revoked}
	if cfg.Base == "" {
		return st, nil
	}
	base, err := ch.load(ctx, cfg.Base, depth+1)
	if err != nil {
		return nil, fmt.Errorf("grantcheck: base %s of %s: %w", cfg.Base, ns, err)
	}
	st.chain = append(st.chain, base.chain...)
	copied, err := ch.copiedKeys(ctx, ns, cfg)
	if err != nil {
		return nil, err
	}
	// Keys follow the base (core effectiveKeys): the base's current keys,
	// whose entries win over the branch's for a shared kid, then the
	// branch's own, less those it copied and the base has since removed.
	st.keys = append([]grant.Key(nil), base.keys...)
	for _, k := range cfg.Keys {
		if _, inBase := findKey(base.keys, k.Kid); inBase {
			continue
		}
		if _, shared := copied[k.Kid]; shared {
			continue
		}
		st.keys = append(st.keys, k)
	}
	// Revocations of every base (core effectiveRevoked).
	st.revoked = map[string]bool{}
	for _, c := range st.chain {
		for r := range c.Revoked {
			st.revoked[r] = true
		}
	}
	return st, nil
}

// copiedKeys returns the keys a branch copied from its base at creation:
// those of the base's document in force at the base's branch entry, found
// in the base's log after the branch's at. It is immutable, so cached.
func (ch *Checker) copiedKeys(ctx context.Context, ns string, cfg *Config) (map[string]grant.Key, error) {
	ch.mu.Lock()
	m, ok := ch.copied[ns]
	ch.mu.Unlock()
	if ok {
		return m, nil
	}
	bh, err := ch.c.NSHead(ctx, cfg.Base)
	if err != nil {
		return nil, err
	}
	entries, err := ch.c.NSLog(ctx, cfg.Base, bh.ID, cfg.BaseAt)
	if err != nil {
		return nil, fmt.Errorf("grantcheck: log of base %s: %w", cfg.Base, err)
	}
	entryID := ""
	for _, e := range entries {
		if e.Kind == "branch" && e.Name == ns && e.Remote == nil {
			entryID = e.ID
			break
		}
	}
	if entryID == "" {
		return nil, fmt.Errorf("grantcheck: no branch entry for %s in %s", ns, cfg.Base)
	}
	doc, err := ch.c.NSDoc(ctx, cfg.Base, entryID)
	if err != nil {
		return nil, err
	}
	bc, err := ParseConfig(cfg.Base, entryID, doc.Value)
	if err != nil {
		return nil, err
	}
	m = map[string]grant.Key{}
	for _, k := range bc.Keys {
		m[k.Kid] = k
	}
	ch.mu.Lock()
	ch.copied[ns] = m
	ch.mu.Unlock()
	return m, nil
}

func findKey(ks []grant.Key, kid string) (grant.Key, bool) {
	for _, k := range ks {
		if k.Kid == kid {
			return k, true
		}
	}
	return grant.Key{}, false
}

// Verify decodes and verifies a bearer token for namespace ns against its
// configuration at the head, in the core's order (§C.2, §7): a grant that
// doesn't name ns is 403 before the namespace is consulted; then 401 when
// there is no usable grant (malformed, unknown key, bad signature, revoked,
// expired or not yet valid, or a namespace that doesn't exist); 403 when a
// valid grant's key scope refuses it. Grant failures are *grant.AuthError;
// other errors are fetch failures.
func (ch *Checker) Verify(ctx context.Context, ns, token string) (*grant.Verified, error) {
	if token == "" {
		return nil, &grant.AuthError{Status: 401, Msg: "missing grant"}
	}
	g, err := grant.Decode(token, ch.maxGrant)
	if errors.Is(err, grant.ErrTooLarge) {
		return nil, &grant.AuthError{Status: 401, Msg: "grant too large"}
	}
	if err != nil {
		return nil, err
	}
	if !g.NamesNS(ns) {
		return nil, &grant.AuthError{Status: 403, Msg: fmt.Sprintf("the grant does not apply to namespace %q", ns)}
	}
	st, err := ch.state(ctx, ns)
	if unreadable(err) {
		return nil, &grant.AuthError{Status: 401, Msg: "no key can verify the grant"}
	}
	if err != nil {
		return nil, err
	}
	now := ch.now()
	env := grant.Env{
		Now:           now,
		NS:            ns,
		Keys:          st.keys,
		Revoked:       st.revoked,
		Roles:         st.cfg.Roles,
		ValidateAttrs: ValidateAttrs,
		CheckAt:       ch.checkAt(ctx, ns),
	}
	return grant.Verify(g, env)
}

// Decode decodes a bearer token as Verify does, without verifying it, so a
// caller checking many namespaces can see which ones it names first.
func (ch *Checker) Decode(token string) (*grant.Grant, error) {
	return grant.Decode(token, ch.maxGrant)
}

// unreadable reports a namespace document the checker can't fetch because
// the namespace doesn't exist or the origin refuses the checker (§7 answers
// both alike), so no key can verify a grant for it.
func unreadable(err error) bool { return client.IsNotFound(err) || client.IsAuth(err) }

// ValidateAttrs checks asserted attrs against a key scope's attrs schema,
// as the core does: by evaluating a rule { op: test, path: /attrs, schema }.
func ValidateAttrs(schema any, attrs map[string]any) error {
	r, err := rules.Compile(map[string]any{"op": "test", "path": "/attrs", "schema": schema})
	if err != nil {
		return fmt.Errorf("invalid attrs schema: %v", err)
	}
	var a any = map[string]any{}
	if attrs != nil {
		a = attrs
	}
	if !r.Eval(map[string]any{"attrs": a}) {
		return fmt.Errorf("attrs do not match the key scope")
	}
	return nil
}

// checkAt resolves a key's requireAt (§C.4) against the public API, as the
// core does: at must be an ns_id in the named chain (ns itself for
// requireAt true), and must have been its head at some point within maxLag
// before the grant was issued: its successor, if any, was written no
// earlier than issued − maxLag. maxLag is the target namespace's (default
// 60 seconds), or the key's when stricter.
func (ch *Checker) checkAt(ctx context.Context, ns string) func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error {
	return func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error {
		target := ns
		if s, ok := requireAt.(string); ok {
			target = s
		}
		var idText string
		switch x := at.(type) {
		case string:
			idText = x
		case map[string]any:
			if n, _ := x["ns"].(string); n != target {
				return fmt.Errorf("at names another namespace")
			}
			idText, _ = x["id"].(string)
		}
		if _, err := ids.Parse(idText); err != nil {
			return fmt.Errorf("malformed at")
		}
		tst, err := ch.state(ctx, target)
		if err != nil {
			return fmt.Errorf("namespace %s: %v", target, err)
		}
		if idText == tst.cfg.Head {
			return nil
		}
		entries, err := ch.c.NSLog(ctx, target, tst.cfg.Head, idText)
		if err != nil {
			if client.IsNotFound(err) {
				return fmt.Errorf("at is not in the chain of %s", target)
			}
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		next, err := time.Parse(time.RFC3339Nano, entries[0].Created)
		if err != nil {
			return fmt.Errorf("namespace %s: bad log entry time", target)
		}
		lag := grant.EffectiveMaxLag(tst.cfg.MaxLag, keyMaxLag)
		if !grant.HeadWithin(&next, issued, lag) {
			return fmt.Errorf("at was not the head of %s within maxLag (%s) before the grant was issued", target, lag)
		}
		return nil
	}
}

// Decision is the outcome of a read check.
type Decision struct {
	Allowed  bool
	Public   bool            // the namespace is public: anyone may read
	Verified *grant.Verified // nil for an anonymous read of a public namespace
	Reason   string          // why not, when !Allowed
}

// CheckRead decides whether the bearer of token may read resource in ns
// ("" = the namespace as a whole, which only grants whose rules don't fix
// /resource pass). Public namespaces allow everyone; a token presented to a
// public namespace is still verified (an invalid one is an error), matching
// services that attribute reads. Grant failures are returned as a Decision
// with Allowed false and the *grant.AuthError as the error.
func (ch *Checker) CheckRead(ctx context.Context, ns, token, resource string) (*Decision, error) {
	st, err := ch.state(ctx, ns)
	if token != "" {
		// A grant not naming ns is refused (§7), as the core does, unless
		// ns is public: then it is ignored and the read is anonymous.
		if g, derr := grant.Decode(token, ch.maxGrant); derr == nil && !g.NamesNS(ns) {
			if err == nil && st.cfg.Read == "public" {
				return &Decision{Allowed: true, Public: true}, nil
			}
			msg := fmt.Sprintf("the grant does not apply to namespace %q", ns)
			return &Decision{Reason: msg}, &grant.AuthError{Status: 403, Msg: msg}
		}
	}
	if unreadable(err) {
		// An unknown namespace is like one that isn't public (§7).
		return &Decision{Reason: "no usable grant"}, &grant.AuthError{Status: 401, Msg: "no usable grant"}
	}
	if err != nil {
		return nil, err
	}
	public := st.cfg.Read == "public"
	if token == "" {
		if public {
			return &Decision{Allowed: true, Public: true}, nil
		}
		return &Decision{Reason: "missing grant"}, &grant.AuthError{Status: 401, Msg: "missing grant"}
	}
	v, err := ch.Verify(ctx, ns, token)
	if err != nil {
		var ae *grant.AuthError
		if errors.As(err, &ae) {
			return &Decision{Public: public, Reason: ae.Msg}, err
		}
		return nil, err
	}
	d := &Decision{Public: public, Verified: v}
	if public {
		d.Allowed = true
		return d, nil
	}
	if ok, why := ch.allowsRead(v, resource); !ok {
		d.Reason = why
		return d, nil
	}
	d.Allowed = true
	return d, nil
}

// ReadEnvelope is the read envelope of §6.4.1 evaluated for reads.
func ReadEnvelope(v *grant.Verified, resource string, now time.Time) map[string]any {
	env := map[string]any{"action": "read", "now": now.UTC().Format("2006-01-02T15:04:05.000Z")}
	if resource != "" {
		env["resource"] = resource
	}
	if v != nil {
		env["principal"] = v.Principal.Envelope()
	}
	return env
}

// AllowsRead reports whether a verified grant may read resource ("" = the
// whole namespace): the grant allows read and its key-scope, block and role
// rules pass against the read envelope at the checker's now.
func (ch *Checker) AllowsRead(v *grant.Verified, resource string) bool {
	ok, _ := ch.allowsRead(v, resource)
	return ok
}

func (ch *Checker) allowsRead(v *grant.Verified, resource string) (bool, string) {
	ok, roles := v.Allows("read")
	if !ok {
		return false, "the grant does not allow read"
	}
	env := ReadEnvelope(v, resource, ch.now())
	for _, src := range [][]any{v.KeyRules, v.BlockRules} {
		for _, rv := range src {
			r, err := ch.compile(rv)
			if err != nil {
				return false, "invalid grant rule"
			}
			if !r.Eval(env) {
				return false, "a grant or key rule refuses the read"
			}
		}
	}
	if v.HasRoles() {
		for _, role := range roles {
			pass := true
			for _, rv := range v.RoleRules(role) {
				r, err := ch.compile(rv)
				if err != nil || !r.Eval(env) {
					pass = false
					break
				}
			}
			if pass {
				return true, ""
			}
		}
		return false, "no role allows the read"
	}
	return true, ""
}

// ReadsAll reports whether a verified grant may read every resource of the
// namespace: no rule of its blocks, key scope or effective roles refers to
// /resource, and its key has no readScope (as the core decides for
// branching, §7.6). Such readers can share namespace-wide caches.
func (ch *Checker) ReadsAll(v *grant.Verified) bool {
	if v.Key.ReadScopeResource {
		return false
	}
	lists := [][]any{v.KeyRules, v.BlockRules}
	for _, r := range v.EffectiveRoles {
		lists = append(lists, v.RoleRules(r))
	}
	for _, l := range lists {
		for _, rv := range l {
			r, err := ch.compile(rv)
			if err != nil || r.Refs()["resource"] || r.Refs()["*"] {
				return false
			}
		}
	}
	return true
}

// ReadsUnrestricted reports whether a verified grant reads the namespace
// unrestricted (§C.5) and may read it now: its key has no readScope, no
// rule of its blocks or key scope refers to /resource, they pass, and, if
// it carries roles, so does some role that lists read and has no rule
// referring to /resource. Unlike ReadsAll, its other roles don't count:
// roles are alternatives (§C.1.1).
func (ch *Checker) ReadsUnrestricted(v *grant.Verified) bool {
	ok, roles := v.Allows("read")
	if !ok || v.Key.ReadScopeResource {
		return false
	}
	env := ReadEnvelope(v, "", ch.now())
	if !ch.passWhole(v.KeyRules, env) || !ch.passWhole(v.BlockRules, env) {
		return false
	}
	if !v.HasRoles() {
		return true
	}
	for _, role := range roles {
		if ch.passWhole(v.RoleRules(role), env) {
			return true
		}
	}
	return false
}

// passWhole reports whether rules rs pass against env without referring to
// /resource (or the whole envelope).
func (ch *Checker) passWhole(rs []any, env map[string]any) bool {
	for _, rv := range rs {
		r, err := ch.compile(rv)
		if err != nil || r.Refs()["resource"] || r.Refs()["*"] || !r.Eval(env) {
			return false
		}
	}
	return true
}

func (ch *Checker) compile(v any) (*rules.Rule, error) {
	k := string(jsonv.Canonical(v))
	if r, ok := ch.rules.Load(k); ok {
		return r.(*rules.Rule), nil
	}
	r, err := rules.Compile(v)
	if err != nil {
		return nil, err
	}
	ch.rules.Store(k, r)
	return r, nil
}

// --- subject sets (§B.11.5) ----------------------------------------------

// GroupPrefix marks group subjects.
const GroupPrefix = "group:"

// SubjectSet returns the sorted, de-duplicated subjects of a verified
// grant, for per-subject-set caching of private results (§B.11.5, §C.6):
//
//   - every root group g as "group:"+g (a group already written with the
//     "group:" prefix is kept as is);
//   - the root sub verbatim (grants carry principal ids such as
//     "user:bob"), only if includeSub. §B.11.5 includes the user only when
//     the service has direct entries for that user, so users without them
//     share caches with everyone in the same groups.
//
// Sorting is by byte order (equal to UTF-16 order for ASCII subjects).
func SubjectSet(v *grant.Verified, includeSub bool) []string {
	set := map[string]bool{}
	for _, g := range v.Principal.Groups {
		if !strings.HasPrefix(g, GroupPrefix) {
			g = GroupPrefix + g
		}
		set[g] = true
	}
	if includeSub && v.Principal.ID != "" {
		set[v.Principal.ID] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SubjectSetID is gs = text(trunc160(sha256(canonical(sorted subjects))))
// (§B.11.5). subjects are sorted and de-duplicated first.
func SubjectSetID(subjects []string) string {
	set := map[string]bool{}
	for _, s := range subjects {
		set[s] = true
	}
	sorted := make([]string, 0, len(set))
	for s := range set {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	arr := make([]any, len(sorted))
	for i, s := range sorted {
		arr[i] = s
	}
	sum := sha256.Sum256(jsonv.Canonical(arr))
	return ids.FromBytes(sum[:ids.Size]).String()
}
