// Package grantcheck lets a service verify a reader's grant locally
// (§A.6, §C.1 "consumers verify grants too", §C.6), with keys and
// revocations as of the namespace head (§10), mirroring the origin's checks
// in internal/core:
//
//   - the root signature by a key of the namespace document at its head;
//   - in a branch, keys follow the base (§C.4): a key the branch copied from
//     its base is accepted only while the base's current document still has
//     it with the same pub, recursively;
//   - revocations of the namespace and, for a branch, of every local base;
//   - the order of §C.2 and §C.8: a token that can't be decoded, whose
//     rules don't compile, or over grantSize or rulesPerGrant is 401
//     first (the origin answers the limits 413); then a grant not naming
//     the namespace is 403 before anything else; no usable grant (unknown
//     key, bad signature, revoked, expired, not yet valid, "*" outside an
//     operator grant) is 401;
//   - key scopes, including attrs (validated with internal/rules as the
//     core does) and readScope (a read grant that doesn't fix /resource
//     is 403, §2.1);
//   - read decisions: the grant allows read and its key-scope, block and
//     role rules pass against a read envelope
//     { action: "read", resource?, principal }, which has no now: a rule
//     that refers to /now fails a read as a whole (§C.2 item 5).
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
	maxRules int
	steps    int // validationSteps for each check; 0: the default

	mu     sync.Mutex
	states map[string]*nsState
	copied map[string]map[string]grant.Key // branch -> keys copied from its base at creation (immutable)
	rules  sync.Map                        // canonical rule -> *rules.Rule

	// seq counts Observe and Invalidate calls; observed is the seq of the
	// last Observe of each namespace, invalidated that of the last
	// Invalidate. A state loaded by a read that began before one that
	// concerns its chain is not stored (stateWithin): it may hold what the
	// Observe said is gone, fresh for the TTL.
	seq         uint64
	observed    map[string]uint64
	invalidated uint64
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

// WithMaxGrantRules rejects bearer tokens whose blocks carry more than n
// rule forms, nested ones included (default 32, the §12.2 default of
// rulesPerGrant).
func WithMaxGrantRules(n int) Option { return func(ch *Checker) { ch.maxRules = n } }

// WithValidationSteps sets the validation steps each read check, each
// attrs check and each item filtered by a grant may take in its rules'
// schema tests (§6.6 Validation work): one that needs more fails, or the
// item is left out. validationSteps is a limit of the origin's deployment
// that no namespace document carries, so a service is told it here; the
// default, and what a value that isn't positive means, is §12.2's
// 5,000,000 (rules.DefaultValidationSteps). No check is unbounded.
func WithValidationSteps(n int) Option { return func(ch *Checker) { ch.steps = n } }

// ValidationSteps is the budget WithValidationSteps set, 0 for the
// default: what a ReadFilter of this checker's service takes as Steps.
func (ch *Checker) ValidationSteps() int { return ch.steps }

// New returns a Checker that reads namespace documents with c.
func New(c *client.Client, opts ...Option) *Checker {
	ch := &Checker{c: c, ttl: 30 * time.Second, now: time.Now, maxGrant: 8 << 10, maxRules: 32,
		states: map[string]*nsState{}, copied: map[string]map[string]grant.Key{}, observed: map[string]uint64{}}
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
	// Base is the base namespace of a branch, "" otherwise (§C.4, §10).
	Base   string
	BaseAt string
	Doc    map[string]any
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
	ch.seq++
	ch.observed[ns] = ch.seq
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
	ch.seq++
	ch.invalidated = ch.seq
	ch.mu.Unlock()
}

// overtaken reports whether an Observe of a namespace in chain, or an
// Invalidate, came since seq start. ch.mu is held.
func (ch *Checker) overtaken(chain []*Config, start uint64) bool {
	if ch.invalidated > start {
		return true
	}
	for _, c := range chain {
		if ch.observed[c.NS] > start {
			return true
		}
	}
	return false
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
	st, _, err := ch.stateWithin(ctx, ns, ch.ttl)
	return st, err
}

// stateWithin is state with ttl for the checker's: a ttl of zero re-reads
// the heads now. checked is when the heads of the state returned were
// last read.
func (ch *Checker) stateWithin(ctx context.Context, ns string, ttl time.Duration) (st *nsState, checked time.Time, err error) {
	now := time.Now()
	ch.mu.Lock()
	start := ch.seq
	st = ch.states[ns]
	var checkedAt time.Time
	if st != nil {
		checkedAt = st.checkedAt
	}
	ch.mu.Unlock()
	if st != nil && now.Sub(checkedAt) < ttl {
		return st, checkedAt, nil
	}
	if st != nil {
		// Refresh only if a head in the chain moved.
		same := true
		for _, c := range st.chain {
			h, err := ch.c.NSHead(ctx, c.NS)
			if err != nil {
				return nil, time.Time{}, err
			}
			if h.ID != c.Head {
				same = false
				break
			}
		}
		if same {
			ch.mu.Lock()
			if !ch.overtaken(st.chain, start) {
				st.checkedAt = now
			}
			ch.mu.Unlock()
			return st, now, nil
		}
	}
	st, err = ch.load(ctx, ns, 0)
	if err != nil {
		return nil, time.Time{}, err
	}
	st.checkedAt = now
	ch.mu.Lock()
	if !ch.overtaken(st.chain, start) {
		// Not one an Observe since it began overtook: that one holds
		// for this call, which began before it, and the next reads again.
		ch.states[ns] = st
	}
	ch.mu.Unlock()
	return st, now, nil
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
	entries, _, err := ch.c.Unfiltered().NSLog(ctx, cfg.Base, bh.ID, cfg.BaseAt)
	if err != nil {
		return nil, fmt.Errorf("grantcheck: log of base %s: %w", cfg.Base, err)
	}
	entryID := ""
	for _, e := range entries {
		if e.Kind == "branch" && e.Name == ns {
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
	g, err := ch.Decode(token)
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
		ValidateAttrs: func(schema any, attrs map[string]any) error { return validateAttrs(schema, attrs, ch.steps) },
	}
	return grant.Verify(g, env)
}

// Decode decodes a bearer token as Verify does, without verifying it, so a
// caller checking many namespaces can see which ones it names first. As
// the origin does, it refuses a token over grantSize or rulesPerGrant
// before its ns check (§C.8, §6.6), as a *LimitError, and one whose rules
// don't compile as a *grant.AuthError with status 401.
func (ch *Checker) Decode(token string) (*grant.Grant, error) {
	g, err := grant.DecodeLimited(token, grant.Limits{Size: ch.maxGrant, Rules: ch.maxRules})
	var tl *grant.TooLargeError
	var tr *grant.TooManyRulesError
	switch {
	case errors.As(err, &tl):
		return nil, &LimitError{Limit: "grantSize", Measured: tl.Size, Max: tl.Max}
	case errors.As(err, &tr):
		return nil, &LimitError{Limit: "rulesPerGrant", Measured: tr.Count, Max: tr.Max}
	case errors.Is(err, grant.ErrTooLarge):
		return nil, &LimitError{Limit: "grantSize", Measured: ch.maxGrant + 1, Max: ch.maxGrant}
	}
	return g, err
}

// LimitError is a bearer token over grantSize or rulesPerGrant (§C.8,
// §6.6), Measured against Max. Services verify as the origin does (§C.6),
// which answers it 413, code limit, naming the limit, so a service that
// answers grant failures itself answers it so too (internal/tree). It
// unwraps to the 401 *grant.AuthError that callers answering only
// grant.AuthError give it.
type LimitError struct {
	Limit         string // "grantSize" or "rulesPerGrant"
	Measured, Max int
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("grant over %s: %d, at most %d", e.Limit, e.Measured, e.Max)
}

// Unwrap is the 401 a caller answering only *grant.AuthError gives.
func (e *LimitError) Unwrap() error {
	if e.Limit == "rulesPerGrant" {
		return &grant.AuthError{Status: 401, Msg: "too many rules in the grant's blocks"}
	}
	return &grant.AuthError{Status: 401, Msg: "grant too large"}
}

// unreadable reports a namespace document the checker can't fetch because
// the namespace doesn't exist or the origin refuses the checker (§7 answers
// both alike), so no key can verify a grant for it.
func unreadable(err error) bool { return client.IsNotFound(err) || client.IsAuth(err) }

// ValidateAttrs checks asserted attrs against a key scope's attrs schema,
// as the core does: by evaluating a rule { op: test, path: /attrs, schema }.
func ValidateAttrs(schema any, attrs map[string]any) error {
	return validateAttrs(schema, attrs, 0)
}

// validateAttrs is ValidateAttrs within a budget of steps validation
// steps (0: the default): attrs whose check takes more don't match.
func validateAttrs(schema any, attrs map[string]any, steps int) error {
	r, err := rules.Compile(map[string]any{"op": "test", "path": "/attrs", "schema": schema})
	if err != nil {
		return fmt.Errorf("invalid attrs schema: %v", err)
	}
	var a any = map[string]any{}
	if attrs != nil {
		a = attrs
	}
	if !r.Passes(map[string]any{"attrs": a}, rules.Budget(steps)) {
		return fmt.Errorf("attrs do not match the key scope")
	}
	return nil
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
// with Allowed false and the *grant.AuthError as the error; a fetch
// failure with a nil Decision.
func (ch *Checker) CheckRead(ctx context.Context, ns, token, resource string) (*Decision, error) {
	st, err := ch.state(ctx, ns)
	if token != "" {
		// A grant not naming ns is refused (§7), as the core does, unless
		// ns is public: then it is ignored and the read is anonymous.
		if g, derr := ch.Decode(token); derr == nil && !g.NamesNS(ns) {
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
	if ok, why := ch.allowsRead(v, resource, nil, false); !ok {
		d.Reason = why
		return d, nil
	}
	d.Allowed = true
	return d, nil
}

// ReadEnvelope is the read envelope of §6.4.1 evaluated for reads. It
// has no now, whatever now is (§C.2 item 5): a rule that refers to /now
// fails a read as a whole (FailsRead), and a read's time window is its
// grant's nbf and exp. now is kept for callers' signatures only.
func ReadEnvelope(v *grant.Verified, resource string, now time.Time) map[string]any {
	_ = now
	env := map[string]any{"action": "read"}
	if resource != "" {
		env["resource"] = resource
	}
	if v != nil {
		env["principal"] = v.Principal.Envelope()
	}
	return env
}

// FailsRead reports whether r fails as a whole wherever it is evaluated
// for a read (§C.2 item 5): it refers to /now, at any depth, which a read
// envelope doesn't carry, or to the whole envelope (path ""), which holds
// /now as far as a rule can tell (the conservative reading). It fails
// before Eval, so that a not or any around it can't make it pass.
func FailsRead(r *rules.Rule) bool {
	refs := r.Refs()
	return refs["now"] || refs["*"]
}

// AllowsRead reports whether a verified grant may read resource ("" = the
// whole namespace) where the read concerns no stored document (doc null,
// §6.4.1): the grant allows read, its key-scope and block rules pass
// against the read envelope, none failing for a read (FailsRead: such a
// grant is refused every read, §C.2 item 5) nor referring to /doc, and,
// if it carries roles, so do the rules of one that lists read, a role
// with a rule that fails for a read not counting.
func (ch *Checker) AllowsRead(v *grant.Verified, resource string) bool {
	ok, _ := ch.allowsRead(v, resource, nil, false)
	return ok
}

// AllowsReadDoc is AllowsRead for a revision of resource whose document
// is doc (§C.2 item 5: reads are judged per revision).
func (ch *Checker) AllowsReadDoc(v *grant.Verified, resource string, doc any) bool {
	ok, _ := ch.allowsRead(v, resource, doc, true)
	return ok
}

func (ch *Checker) allowsRead(v *grant.Verified, resource string, doc any, hasDoc bool) (bool, string) {
	ok, roles := v.Allows("read")
	if !ok {
		return false, "the grant does not allow read"
	}
	env := ReadEnvelope(v, resource, ch.now())
	if hasDoc {
		env["doc"] = doc
	}
	// The check's budget of validationSteps: a rule whose schema test
	// runs out fails it, whatever role might have passed (§6.6).
	m := rules.Budget(ch.steps)
	passes := func(r *rules.Rule) bool {
		return (hasDoc || !RefersToDoc(r)) && r.Passes(env, m)
	}
	for _, src := range [][]any{v.KeyRules, v.BlockRules} {
		for _, rv := range src {
			r, err := ch.compile(rv)
			if err != nil {
				return false, "invalid grant rule"
			}
			if FailsRead(r) {
				return false, "a grant or key rule refers to /now, which no read passes (§C.2 item 5)"
			}
			if !passes(r) {
				return false, "a grant or key rule refuses the read"
			}
		}
	}
	if v.HasRoles() {
		for _, role := range roles {
			pass := true
			for _, rv := range v.RoleRules(role) {
				r, err := ch.compile(rv)
				if err != nil || FailsRead(r) || !passes(r) {
					pass = false
					break
				}
			}
			if m.Over {
				// Not a role that doesn't pass: the check's steps ran
				// out, which no other role makes up for (§6.6).
				return false, "the grant's rules take more than validationSteps steps for this read"
			}
			if pass {
				return true, ""
			}
		}
		return false, "no role allows the read"
	}
	return true, ""
}

// ReadsPerResource reports whether a verified grant's reads may differ
// between resources of a namespace: its key has a readScope, or a rule of
// its key scope, its blocks or a role that counts for read (readRoles: a
// role with a rule on /now doesn't, §C.2 item 5) refers to /resource (or
// to the whole envelope). A grant whose reads can't differ reads every
// resource or none, so one that doesn't read the namespace unrestricted
// (ReadsUnrestricted) reads none of it.
func (ch *Checker) ReadsPerResource(v *grant.Verified) bool {
	if v.Key.ReadScopeResource {
		return true
	}
	roles := readRoles(v)
	lists := [][]any{v.KeyRules, v.BlockRules}
	for _, r := range roles {
		lists = append(lists, v.RoleRules(r))
	}
	for _, l := range lists {
		for _, rv := range l {
			r, err := ch.compile(rv)
			if err != nil || r.Refs()["resource"] || r.Refs()["doc"] || r.Refs()["*"] {
				return true
			}
		}
	}
	return false
}

// ReadsUnrestricted reports whether a verified grant reads the namespace
// unrestricted (§2.1) and may read it now: its key has no readScope, no
// rule of its blocks or key scope refers to /resource or fails for a read
// (FailsRead: such a grant is refused every read, §C.2 item 5), they
// pass, and, if it carries roles, so does some role that lists read and
// has no rule referring to /resource or failing for a read. Its other
// roles don't count: roles are alternatives (§C.1.1), and one with a rule
// on /now doesn't count for read. Such readers read every resource, so
// they can share namespace-wide caches.
func (ch *Checker) ReadsUnrestricted(v *grant.Verified) bool {
	ok, roles := v.Allows("read")
	if !ok || v.Key.ReadScopeResource {
		return false
	}
	env := ReadEnvelope(v, "", ch.now())
	m := rules.Budget(ch.steps) // the check's validationSteps (§6.6)
	if !ch.passWhole(v.KeyRules, env, m) || !ch.passWhole(v.BlockRules, env, m) {
		return false
	}
	if !v.HasRoles() {
		return true
	}
	for _, role := range roles {
		pass := ch.passWhole(v.RoleRules(role), env, m)
		if m.Over {
			// The check's steps ran out, which no other role makes up
			// for: the whole check fails, as at the origin (§6.6).
			return false
		}
		if pass {
			return true
		}
	}
	return false
}

// passWhole reports whether rules rs pass against env without referring to
// /resource or /doc (§2.1 Unrestricted read), or to /now (or the whole
// envelope), which fails any read.
func (ch *Checker) passWhole(rs []any, env map[string]any, m *rules.Meter) bool {
	return ch.passWholeRefs(rs, env, m, "resource", "doc", "now")
}

// passWholeRefs reports whether rules rs pass against env, within what m
// has left of the check's validation steps, without referring to any of
// refs or to the whole envelope.
func (ch *Checker) passWholeRefs(rs []any, env map[string]any, m *rules.Meter, refs ...string) bool {
	for _, rv := range rs {
		r, err := ch.compile(rv)
		if err != nil || r.Refs()["*"] || !r.Passes(env, m) {
			return false
		}
		for _, ref := range refs {
			if r.Refs()[ref] {
				return false
			}
		}
	}
	return true
}

// NamespaceWide reports whether a verified grant would be issued a
// namespace-wide edge grant in its namespace (§C.5.2), as far as its rules
// decide: it reads the namespace unrestricted (§2.1), no rule of its
// blocks or key scope refers to /now or the whole envelope, they pass now
// against a read envelope, and, if it carries roles, it has a qualifying
// role (§2.1): one listing read whose rules refer to neither /resource
// nor /now, and pass now. It is ReadsUnrestricted less the rules an edge
// can't evaluate: a reader whose access depends on the clock is decided
// on each request, never by a namespace-wide view such as g/all (§B.11.5).
// Whether the namespace exists, is purged or public is the caller's.
func (ch *Checker) NamespaceWide(v *grant.Verified) bool {
	ok, roles := v.Allows("read")
	if !ok || v.Key.ReadScopeResource {
		return false
	}
	env := ReadEnvelope(v, "", ch.now())
	m := rules.Budget(ch.steps) // the check's validationSteps (§6.6)
	if !ch.passWholeRefs(v.KeyRules, env, m, "resource", "doc", "now") || !ch.passWholeRefs(v.BlockRules, env, m, "resource", "doc", "now") {
		return false
	}
	if !v.HasRoles() {
		return true
	}
	for _, role := range roles {
		pass := ch.passWholeRefs(v.RoleRules(role), env, m, "resource", "doc", "now")
		if m.Over {
			// As ReadsUnrestricted: a spent budget fails the whole check.
			return false
		}
		if pass {
			return true
		}
	}
	return false
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

// ViewID is view = text(trunc160(sha256(canonical(sorted subjects))))
// (§7.9 view, §A.4). subjects are sorted and de-duplicated first.
func ViewID(subjects []string) string {
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
