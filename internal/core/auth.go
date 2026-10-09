package core

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/rules"
)

// Credentials are what a request presents: a bearer grant, or with
// authentication disabled an X-Author name.
type Credentials struct {
	Bearer string
	Author string
	// Edge is a verified edge grant (§C.5), for GET and HEAD under its
	// prefix only: the server sets it from a cookie, never for writes.
	Edge *EdgeGrant
}

// actor is the authenticated principal of a request in one namespace.
type actor struct {
	principal grant.Principal
	verified  *grant.Verified // nil with auth disabled
	star      bool
	bucketKey string
	keyRate   *grant.Rate
	grant     *grant.Grant
	// noAuth: a request made while authentication is disabled (§1). The
	// namespace entries written for it record "grant": null (§7.4).
	noAuth bool
}

func (a *actor) id() string { return a.principal.ID }

func (a *actor) envelope() any {
	if a.verified == nil {
		return nil
	}
	return a.principal.Envelope()
}

// authenticate verifies credentials against the configuration in force in
// namespace n (§C.2 item 1). keysOverride replaces the namespace's keys, for
// namespace creation with operator keys (then n and cfg may be nil).
func (t *tx) authenticate(nsName string, n *nsRow, cfg *Config, cred Credentials, keysOverride []grant.Key) (*actor, *Error) {
	if t.e.opt.AuthDisabled {
		name := cred.Author
		if name == "" {
			name = "anonymous"
		}
		return &actor{principal: grant.Principal{ID: name}, star: true, bucketKey: name, noAuth: true}, nil
	}
	g, err := t.decodeGrant(nsName, cred)
	if err != nil {
		return nil, err
	}
	a, err := t.verifyGrant(g, nsName, n, cfg, keysOverride)
	if err != nil {
		return nil, err
	}
	t.e.bearers.put(cred.Bearer, g)
	return a, nil
}

// decodeGrant decodes a bearer grant and checks, before anything is
// verified or looked up, that every block carrying ns names the namespace
// (§C.2, §7): 401 without a parseable grant, 403 when it doesn't name the
// namespace, whether or not the namespace exists.
func (t *tx) decodeGrant(nsName string, cred Credentials) (*grant.Grant, *Error) {
	if cred.Bearer == "" {
		return nil, apiErr(401, "unauthenticated", "message", "missing grant")
	}
	g := t.e.bearers.get(cred.Bearer)
	if g == nil {
		var err error
		g, err = grant.Decode(cred.Bearer, t.e.opt.Maximums.GrantSize)
		if errors.Is(err, grant.ErrTooLarge) {
			return nil, limitErr(413, "grant too large")
		}
		if err != nil {
			return nil, authErr(err)
		}
	}
	if !g.NamesNS(nsName) {
		return nil, nsNotNamed(nsName)
	}
	return g, nil
}

// grantCache keeps bearer grants by their token once they have verified,
// so a grant presented again is neither decoded nor its signatures checked
// again (grant.Verify remembers the chain's root key). Verification still
// runs on every request against the configuration in force: times,
// revocation, key scope and rules are never cached.
//
// Only a grant that verified is stored (put, after verifyGrant): one that
// doesn't, such as a well-formed token signed by a key nobody configured,
// costs a decode on each request, as without the cache, and holds no
// memory. A decoded grant can be several times larger than its token (an
// 8 KiB token of empty JSON arrays decodes to about 100 KB), so the cache
// is bounded by the total length of its tokens as well as by their number.
type grantCache struct {
	mu    sync.Mutex
	m     map[string]*grant.Grant
	bytes int // the total length of the tokens in m
}

// Past either bound the cache starts over.
const (
	maxGrantCacheEntries = 1024
	maxGrantCacheBytes   = 1 << 20
)

// get returns the verified grant of token, or nil.
func (c *grantCache) get(token string) *grant.Grant {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[token]
}

// put keeps g, decoded from token, if its signature chain has verified.
func (c *grantCache) put(token string, g *grant.Grant) {
	if !g.ChainVerified() || len(token) > maxGrantCacheBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[token]; ok {
		return
	}
	if c.m == nil || len(c.m) >= maxGrantCacheEntries || c.bytes+len(token) > maxGrantCacheBytes {
		c.m, c.bytes = map[string]*grant.Grant{}, 0
	}
	c.m[token] = g
	c.bytes += len(token)
}

func nsNotNamed(ns string) *Error {
	return forbidden(fmt.Sprintf("the grant does not apply to namespace %q", ns))
}

// verifyGrant verifies a decoded grant against namespace n's configuration
// in force, or against keysOverride (operator keys).
func (t *tx) verifyGrant(g *grant.Grant, nsName string, n *nsRow, cfg *Config, keysOverride []grant.Key) (*actor, *Error) {
	env := grant.Env{
		Now:           t.now,
		NS:            nsName,
		ValidateAttrs: validateAttrs,
	}
	if keysOverride != nil {
		// Operator grants (§C.4 bootstrapping) name the namespace, which
		// may not exist yet, or "*".
		env.Keys = keysOverride
		env.Operator = true
		env.Revoked = map[string]bool{}
	} else {
		env.Keys = t.effectiveKeys(n, cfg)
		env.Revoked = t.effectiveRevoked(n, cfg)
		env.Roles = cfg.Roles
		env.CheckAt = t.checkAt(n)
	}
	v, err := grant.Verify(g, env)
	if err != nil {
		return nil, authErr(err)
	}
	if len(v.BlockRules)+len(v.KeyRules) > t.e.opt.Maximums.RulesPerGrant {
		return nil, limitErr(422, "too many rules in the grant chain")
	}
	a := &actor{principal: v.Principal, verified: v, star: v.StarKey, grant: g, keyRate: v.Key.Rate}
	a.bucketKey = v.Principal.ID + "\x00" + v.Key.Kid
	return a, nil
}

// absentNS answers a request to a namespace that doesn't exist exactly as
// one to an existing namespace whose read isn't public (§7), so existence
// is not revealed: 401 without a usable grant, 403 for a grant that
// doesn't name the namespace, and 401 for any other grant naming it, since
// no key of the namespace can verify it. Operator grants authorise only
// creating namespaces and forcing purges (§C.4): any other request under
// one is 401, as for an existing namespace whose keys don't list it.
func (t *tx) absentNS(nsName string, cred Credentials) *Error {
	return t.absentNSOp(nsName, cred, false)
}

// absentNSOp is absentNS for a request an operator grant may authorise
// (operator: a forced purge): a usable operator grant then gets 404.
func (t *tx) absentNSOp(nsName string, cred Credentials, operator bool) *Error {
	if t.e.opt.AuthDisabled {
		return notFound()
	}
	g, err := t.decodeGrant(nsName, cred)
	if err != nil {
		return err
	}
	if _, ok := findKey(t.operatorKeys(), g.Blocks[0].Kid); !ok || !operator {
		return apiErr(401, "unauthenticated", "message", "no key can verify the grant")
	}
	if _, err := t.verifyGrant(g, nsName, nil, nil, t.operatorKeys()); err != nil {
		return err
	}
	t.e.bearers.put(cred.Bearer, g)
	return notFound()
}

func authErr(err error) *Error {
	var ae *grant.AuthError
	if errors.As(err, &ae) {
		if ae.Status == 401 {
			return apiErr(401, "unauthenticated", "message", ae.Msg)
		}
		return forbidden(ae.Msg)
	}
	return apiErr(401, "unauthenticated", "message", err.Error())
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// validateAttrs checks key-scope attrs against a JSON Schema by evaluating a
// rule with that schema.
func validateAttrs(schema any, attrs map[string]any) error {
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

// effectiveKeys applies "keys follow the base" (§C.4): a branch accepts its
// base's current keys, recursively through every local base, as well as
// its own. A kid the base has is the base's: only the base's entry is
// accepted, whatever the branch's entry says. A key the branch copied from
// its base at creation that the base has since removed stops working. Keys
// added only to the branch are its own.
//
// Keys don't follow a base in another deployment (§7.6, §G.3): a remote
// branch's keys are its own.
func (t *tx) effectiveKeys(n *nsRow, cfg *Config) []grant.Key {
	if !n.isBranch() || t.remoteShadow(n) != nil {
		return cfg.Keys
	}
	base := t.nsByID(n.base.Int64)
	copied := t.config(n.baseConfigSeq.Int64)
	baseKeys := t.effectiveKeys(base, t.config(base.configSeq))
	out := append([]grant.Key(nil), baseKeys...)
	for _, k := range cfg.Keys {
		if hasKid(baseKeys, k.Kid) || hasKid(copied.Keys, k.Kid) {
			continue
		}
		out = append(out, k)
	}
	return out
}

func hasKid(ks []grant.Key, kid string) bool { _, ok := findKey(ks, kid); return ok }

func findKey(ks []grant.Key, kid string) (grant.Key, bool) {
	for _, k := range ks {
		if k.Kid == kid {
			return k, true
		}
	}
	return grant.Key{}, false
}

// effectiveRevoked merges the revocations of the namespace and all its
// bases in this deployment; they stop at a remote base (§7.6, §G.3).
func (t *tx) effectiveRevoked(n *nsRow, cfg *Config) map[string]bool {
	if !n.isBranch() || t.remoteShadow(n) != nil {
		return cfg.Revoked
	}
	out := map[string]bool{}
	for k := range cfg.Revoked {
		out[k] = true
	}
	for b := n; b.isBranch() && t.remoteShadow(b) == nil; {
		b = t.nsByID(b.base.Int64)
		for k := range t.config(b.configSeq).Revoked {
			out[k] = true
		}
	}
	return out
}

// checkAt resolves a key's requireAt (§C.4): the grant's at must be an
// ns_id in the named chain, and must have been that namespace's head at
// some point within maxLag before the grant was issued (or later). maxLag
// is the target namespace's (default 60 seconds), or the key's when that
// is stricter.
func (t *tx) checkAt(n *nsRow) func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error {
	return func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error {
		target := n
		if s, ok := requireAt.(string); ok {
			target = t.nsByName(s)
			if target == nil {
				return fmt.Errorf("unknown namespace %q", s)
			}
		}
		var idText string
		switch x := at.(type) {
		case string:
			idText = x
		case map[string]any:
			ns, _ := x["ns"].(string)
			if ns != target.name {
				return fmt.Errorf("at names another namespace")
			}
			idText, _ = x["id"].(string)
		}
		id, err := ids.Parse(idText)
		if err != nil {
			return fmt.Errorf("malformed at")
		}
		seq, ok := t.nsLogSeq(target.id, id)
		if !ok {
			return fmt.Errorf("at is not in the chain of %s", target.name)
		}
		var nextMs int64
		if err := t.QueryRow(`SELECT created FROM ns_log WHERE ns = ? AND prev_seq = ?`, target.id, seq).Scan(&nextMs); err != nil {
			return nil // at is still the head
		}
		next := time.UnixMilli(nextMs)
		lag := grant.EffectiveMaxLag(t.config(target.configSeq).MaxLag, keyMaxLag)
		if !grant.HeadWithin(&next, issued, lag) {
			return fmt.Errorf("at was not the head of %s within maxLag (%s) before the grant was issued", target.name, lag)
		}
		return nil
	}
}

// basicEnvelope is the envelope of step 1 and of reads.
func (t *tx) basicEnvelope(action, resource string, a *actor) map[string]any {
	env := map[string]any{"action": action, "now": t.now.Format("2006-01-02T15:04:05.000Z")}
	if resource != "" {
		env["resource"] = resource
	}
	if p := a.envelope(); p != nil {
		env["principal"] = p
	}
	return env
}

var stepOneRefs = []string{"action", "resource", "principal", "now"}

// authorize is step 1 of §6.2 for one verb: verbs, and the grant, key and
// role rules that refer only to the request. It does not rate-limit.
func (t *tx) authorize(a *actor, verb, resource string) *Error {
	if a.verified == nil {
		return nil
	}
	ok, roles := a.verified.Allows(verb)
	if !ok {
		return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
	}
	env := t.basicEnvelope(verb, resource, a)
	return t.grantRules(a, verb, roles, env, true)
}

// grantRules evaluates key-scope, block and role rules. With stepOne, only
// rules that refer solely to action, resource, principal and now are
// evaluated.
func (t *tx) grantRules(a *actor, verb string, roles []string, env map[string]any, stepOne bool) *Error {
	return t.grantRulesMode(a, verb, roles, env, stepOne, false)
}

// grantRulesMode is grantRules; with blind, a rule reading writes or /doc
// fails (sealed writes of e2e namespaces, §6.2): a key-scope or block rule
// refuses the request, and a role with one doesn't allow it.
func (t *tx) grantRulesMode(a *actor, verb string, roles []string, env map[string]any, stepOne, blind bool) *Error {
	if a.verified == nil {
		return nil
	}
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil {
				return forbidden("invalid grant rule")
			}
			if stepOne && !r.OnlyRefs(stepOneRefs...) {
				continue
			}
			if _, b := blindRule(r); blind && b {
				return forbidden("a grant or key rule reads writes or /doc, which the server can't see in an e2e namespace (§6.2, §E.3.2)")
			}
			if !r.Eval(env) {
				return forbidden("a grant or key rule refuses the request")
			}
		}
	}
	if a.verified.HasRoles() {
		if roles == nil {
			_, roles = a.verified.Allows(verb)
		}
		passed := false
		for _, role := range roles {
			ok := true
			for _, rv := range a.verified.RoleRules(role) {
				r, err := compileCached(rv)
				if err != nil {
					ok = false
					break
				}
				if stepOne && !r.OnlyRefs(stepOneRefs...) {
					continue
				}
				if _, b := blindRule(r); (blind && b) || !r.Eval(env) {
					ok = false
					break
				}
			}
			if ok {
				passed = true
				break
			}
		}
		if !passed {
			return forbidden("no role allows the request")
		}
	}
	return nil
}

var ruleCache sync.Map // canonical rule -> *rules.Rule

func compileCached(v any) (*rules.Rule, error) {
	k := string(jsonv.Canonical(v))
	if r, ok := ruleCache.Load(k); ok {
		return r.(*rules.Rule), nil
	}
	r, err := rules.Compile(v)
	if err != nil {
		return nil, err
	}
	ruleCache.Store(k, r)
	return r, nil
}

// checkRules is step 6 of §6.2: namespace rules, then grant, key and role
// rules, against the full envelope.
func (t *tx) checkRules(cfg *Config, a *actor, env map[string]any, isConfig bool) *Error {
	verb := env["action"].(string)
	if a.verified != nil {
		if ok, _ := a.verified.Allows(verb); !ok {
			return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
		}
	}
	if !(isConfig && a.star) {
		if i, path, ok := rules.EvalList(cfg.Rules, env); !ok {
			return apiErr(422, "rule", "rule", i, "path", path)
		}
	}
	return t.grantRules(a, verb, nil, env, false)
}

// canRead decides read access to a namespace, optionally for one resource
// (§C.2 item 5, §C.5).
func (t *tx) canRead(n *nsRow, cfg *Config, a *actor, resource string) bool {
	if cfg.Read == "public" || t.e.opt.AuthDisabled {
		return true
	}
	if a == nil || a.verified == nil {
		return false
	}
	if !a.verified.Can["read"] {
		return false
	}
	return t.grantRules(a, "read", nil, t.basicEnvelope("read", resource, a), false) == nil
}

// reader authenticates a read request, if it carries credentials, and
// decides access. A grant that doesn't name the namespace is 403 (§7), as
// for a namespace that doesn't exist, except that public namespaces ignore
// it and answer as to an unauthenticated request; other refusals answer
// 404 rather than 403 so existence is not revealed.
func (t *tx) reader(n *nsRow, cred Credentials, resource string) (*actor, *Error) {
	cfg := t.config(n.configSeq)
	if cred.Edge != nil && cfg.Read != "public" && !t.e.opt.AuthDisabled {
		return t.edgeReader(n, cred.Edge, resource)
	}
	return t.readerCheck(n, cred, func(a *actor) bool { return t.canRead(n, cfg, a, resource) })
}

// nsReader is reader for /ns/{ns} and the URLs under it, but the gestures
// listing (anyReader): they need unrestricted read (readsNS, §C.5). A
// grant that may read only some resources gets the answer of any read it
// may not make.
func (t *tx) nsReader(n *nsRow, cred Credentials) (*actor, *Error) {
	cfg := t.config(n.configSeq)
	if cred.Edge != nil && cfg.Read != "public" && !t.e.opt.AuthDisabled {
		return t.edgeReader(n, cred.Edge, "")
	}
	return t.readerCheck(n, cred, func(a *actor) bool { return t.readsNS(n, cfg, a, false) })
}

// anyReader is reader for a request that answers any reader of the
// namespace, filtered to what it may read (the gestures listing, §7.4):
// a grant with read, whatever its rules say about resources.
func (t *tx) anyReader(n *nsRow, cred Credentials) (*actor, *Error) {
	cfg := t.config(n.configSeq)
	if cred.Edge != nil && cfg.Read != "public" && !t.e.opt.AuthDisabled {
		return t.edgeReader(n, cred.Edge, "")
	}
	return t.readerCheck(n, cred, func(a *actor) bool {
		if cfg.Read == "public" || t.e.opt.AuthDisabled {
			return true
		}
		return a != nil && a.verified != nil && a.verified.Can["read"]
	})
}

func (t *tx) readerCheck(n *nsRow, cred Credentials, may func(*actor) bool) (*actor, *Error) {
	cfg := t.config(n.configSeq)
	var a *actor
	if t.e.opt.AuthDisabled {
		a, _ = t.authenticate(n.name, n, cfg, cred, nil)
	} else if cred.Bearer != "" {
		g, err := t.decodeGrant(n.name, cred)
		if err == nil {
			a, err = t.verifyGrant(g, n.name, n, cfg, nil)
		}
		switch {
		case err == nil:
			t.e.bearers.put(cred.Bearer, g)
		case cfg.Read == "public":
			// Public content doesn't need the grant: one that is unusable,
			// or doesn't name the namespace, is ignored.
			a = nil
		case g == nil && err.Status == 403:
			return nil, err // not named
		case err.Status == 401 || err.Status == 413:
			return nil, err
		default:
			return nil, notFound()
		}
	}
	if !may(a) {
		if a == nil {
			return nil, apiErr(401, "unauthenticated", "message", "missing grant")
		}
		return nil, notFound()
	}
	return a, nil
}

// readsNS reports whether a reads namespace n unrestricted (§C.5 "The
// stream is metadata"): anyone does in a public namespace or with
// authentication disabled, and otherwise a grant that may read there
// through rules none of which refers to /resource (unrestrictedRoles).
// /ns/{ns} and everything under it but the gestures listing need it, as
// do a batch's source check (§7.5), branching (§7.6) and remote branch
// registration (§G.3): a grant whose rules hide some resources could
// otherwise list their names and heads, or read them through a branch.
// Branching and registration check it as step 1 checks verbs (stepOne,
// §6.2, §C.5), in a public namespace too: the grant must read n
// unrestricted and allow read, and its rules that refer only to /action,
// /principal or /now must pass with /action read; rules over the rest of
// the envelope apply to their own write at step 6.
func (t *tx) readsNS(n *nsRow, cfg *Config, a *actor, stepOne bool) bool {
	if cfg.Read == "public" && !stepOne || t.e.opt.AuthDisabled {
		return true
	}
	if a == nil {
		return false
	}
	if a.verified == nil {
		return true // a namespace's edge grant (edgeReader)
	}
	roles, ok := a.unrestrictedRoles()
	return ok && t.grantRules(a, "read", roles, t.basicEnvelope("read", "", a), stepOne) == nil
}

// unrestrictedRoles reports whether a grant's rules leave every resource
// readable (§C.5): its key has no readScope, no rule of its blocks or key
// scope refers to /resource, and, if it carries roles, some role listing
// read has no rule that does. Those roles are returned, nil for a grant
// without roles; roles are alternatives (§C.1.1), so one is enough.
func (a *actor) unrestrictedRoles() ([]string, bool) {
	v := a.verified
	if v.Key.ReadScopeResource || refersToResource(v.KeyRules) || refersToResource(v.BlockRules) {
		return nil, false
	}
	ok, roles := v.Allows("read")
	if !ok || !v.HasRoles() {
		return nil, ok
	}
	var out []string
	for _, r := range roles {
		if !refersToResource(v.RoleRules(r)) {
			out = append(out, r)
		}
	}
	return out, len(out) > 0
}

// refersToResource reports whether a rule of rs refers to /resource, or
// to the whole envelope. A rule that doesn't compile counts.
func refersToResource(rs []any) bool {
	for _, rv := range rs {
		r, err := compileCached(rv)
		if err != nil || r.Refs()["resource"] || r.Refs()["*"] {
			return true
		}
	}
	return false
}

// rateLimiter holds the token buckets of §6.6.
type rateLimiter struct {
	mu sync.Mutex
	b  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// refill adds what a bucket refilled since it was last drawn on, up to its
// burst. A request that read the clock before another drew on the bucket
// finds it there already: time doesn't run backwards for a bucket.
func (b *bucket) refill(now time.Time, r Rate) {
	if el := now.Sub(b.last); el > 0 {
		b.tokens = math.Min(r.Burst, b.tokens+el.Seconds()*r.Rate)
		b.last = now
	}
}

func newRateLimiter() *rateLimiter { return &rateLimiter{b: map[string]*bucket{}} }

type draw struct {
	key  string
	rate Rate
	cost float64
	name string // the limit of §6.6, reported in a 429
}

// admit checks every bucket holds a token, then deducts each cost (§6.6).
// It returns the wait until the first empty bucket refills, and the limit
// that has the longest wait.
func (rl *rateLimiter) admit(now time.Time, draws []draw) (time.Duration, string, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	var wait time.Duration
	var hit string
	bs := make([]*bucket, len(draws))
	for i, d := range draws {
		b := rl.b[d.key]
		if b == nil {
			b = &bucket{tokens: d.rate.Burst, last: now}
			rl.b[d.key] = b
		}
		b.refill(now, d.rate)
		bs[i] = b
		if b.tokens < 1 {
			w := time.Duration((1 - b.tokens) / d.rate.Rate * float64(time.Second))
			if w > wait {
				wait, hit = w, d.name
			}
		}
	}
	if wait > 0 {
		return wait, hit, false
	}
	for i, d := range draws {
		bs[i].tokens -= d.cost
	}
	return 0, "", true
}

// rateLimit draws a request's tokens: one per resource from each
// per-resource bucket, and items from the principal and namespace buckets.
func (t *tx) rateLimit(n *nsRow, cfg *Config, a *actor, resources []string, items int) *Error {
	return t.admit(t.writeDraws(n, cfg, a, resources, items))
}

// writeDraws are the draws of a write (rateLimit).
func (t *tx) writeDraws(n *nsRow, cfg *Config, a *actor, resources []string, items int) []draw {
	l := cfg.Limits
	var draws []draw
	if al := t.allowanceOf(cfg, a); al != nil && al.Rate.Rate > 0 {
		// An allowance's own bucket replaces the principal and namespace
		// buckets; per-resource buckets still apply (§6.6).
		draws = append(draws, draw{"a\x00" + n.name + "\x00" + al.Sub + "\x00" + al.Kid, al.Rate, float64(items), "allowance"})
	} else {
		pr := l.RatePerPrincipal
		if a.keyRate != nil && a.keyRate.Rate < pr.Rate {
			pr = Rate{a.keyRate.Rate, math.Min(a.keyRate.Burst, pr.Burst)}
		}
		draws = append(draws,
			draw{"p\x00" + a.bucketKey, pr, float64(items), "ratePerPrincipal"},
			draw{"n\x00" + n.name, l.RatePerNamespace, float64(items), "ratePerNamespace"})
	}
	for _, r := range resources {
		draws = append(draws, draw{"r\x00" + n.name + "\x00" + r + "\x00" + a.bucketKey, l.RatePerResource, 1, "ratePerResource"})
	}
	return draws
}

// blobDraw is the draw of an upload's bytes from the principal's blobRate
// bucket, or its allowance's (§6.6, §7.8).
func (t *tx) blobDraw(n *nsRow, cfg *Config, a *actor, size int64) draw {
	if al := t.allowanceOf(cfg, a); al != nil && al.BlobRate.Rate > 0 {
		return draw{"ab\x00" + n.name + "\x00" + al.Sub + "\x00" + al.Kid, al.BlobRate, float64(size), "allowance.blobRate"}
	}
	return draw{"b\x00" + a.bucketKey, cfg.Limits.BlobRate, float64(size), "blobRate"}
}

// admit draws tokens, or answers 429 (§6.6): Retry-After in whole seconds,
// rounded up, and in the body retryAfter, the wait in seconds as a decimal
// (rounded up to the millisecond), which a client under a fast allowance
// waits by instead.
func (t *tx) admit(draws []draw) *Error {
	wait, hit, ok := t.e.rate.admit(t.now, draws)
	if !ok {
		secs := int(math.Ceil(wait.Seconds()))
		if secs < 1 {
			secs = 1
		}
		e := apiErr(429, "rate", "message", "rate limit exceeded", "limit", hit, "retryAfter", math.Ceil(wait.Seconds()*1000)/1000)
		e.Header = map[string][]string{"Retry-After": {fmt.Sprint(secs)}}
		return e
	}
	return nil
}

// charge deducts more from a bucket an admitted request drew on: an
// upload's bytes beyond what it declared (§7.8).
func (rl *rateLimiter) charge(now time.Time, d draw) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.b[d.key]
	if b == nil {
		b = &bucket{tokens: d.rate.Burst, last: now}
		rl.b[d.key] = b
	}
	b.refill(now, d.rate)
	b.tokens -= d.cost
}

// allowanceOf returns the actor's allowance in a configuration, if any.
func (t *tx) allowanceOf(cfg *Config, a *actor) *Allowance {
	kid := ""
	if a.verified != nil {
		kid = a.verified.Key.Kid
	}
	al := cfg.allowance(a.principal.ID, kid, a.verified == nil)
	if al != nil && !al.Until.IsZero() && !t.now.Before(al.Until) {
		return nil // ended: ignored from `until` on (§6.6)
	}
	return al
}

// guardedPaths need a grant chained to a * key (§7.4).
var guardedPaths = []string{"/keys", "/roles", "/revoked", "/limits", "/allowances", "/merge", "/retention", "/encryption", "/signatures", "/nonce", "/schemaReads"}

func touchesGuarded(writes []string) bool {
	for _, w := range writes {
		for _, g := range guardedPaths {
			if pointerOverlaps(w, g) {
				return true
			}
		}
	}
	return false
}

func pointerOverlaps(a, b string) bool {
	return a == b || strings.HasPrefix(b, a+"/") || strings.HasPrefix(a, b+"/") || a == ""
}
