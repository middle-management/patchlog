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
}

// actor is the authenticated principal of a request in one namespace.
type actor struct {
	principal grant.Principal
	verified  *grant.Verified // nil with auth disabled
	star      bool
	bucketKey string
	keyRate   *grant.Rate
	grant     *grant.Grant
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
// namespace creation with operator keys.
func (t *tx) authenticate(nsName string, n *nsRow, cfg *Config, cred Credentials, keysOverride []grant.Key) (*actor, *Error) {
	if t.e.opt.AuthDisabled {
		name := cred.Author
		if name == "" {
			name = "anonymous"
		}
		return &actor{principal: grant.Principal{ID: name}, star: true, bucketKey: name}, nil
	}
	if cred.Bearer == "" {
		return nil, apiErr(401, "unauthenticated", "message", "missing grant")
	}
	g, err := grant.Decode(cred.Bearer, t.e.opt.Limits.GrantSize)
	if errors.Is(err, grant.ErrTooLarge) {
		return nil, limitErr(413, "grant too large")
	}
	if err != nil {
		return nil, authErr(err)
	}
	env := grant.Env{
		Now:           t.now,
		ValidateAttrs: validateAttrs,
	}
	if keysOverride != nil {
		// Operator grants (§C.4 bootstrapping) name the namespace they
		// create, or "*".
		env.NS = "*"
		if contains(g.Blocks[0].NS, nsName) {
			env.NS = nsName
		}
		env.Keys = keysOverride
		env.Revoked = map[string]bool{}
	} else {
		env.NS = n.name
		env.Keys = t.effectiveKeys(n, cfg)
		env.Revoked = t.effectiveRevoked(n, cfg)
		env.Roles = cfg.Roles
		env.CheckAt = t.checkAt(n)
	}
	v, err := grant.Verify(g, env)
	if err != nil {
		return nil, authErr(err)
	}
	if len(v.BlockRules)+len(v.KeyRules) > t.e.opt.Limits.RulesPerGrant {
		return nil, limitErr(422, "too many rules in the grant chain")
	}
	a := &actor{principal: v.Principal, verified: v, star: v.StarKey, grant: g, keyRate: v.Key.Rate}
	a.bucketKey = v.Principal.ID + "\x00" + v.Key.Kid
	return a, nil
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

// effectiveKeys applies "keys follow the base" (§C.4): a key a branch shares
// with a base is accepted only while the base's current configuration still
// has it with the same pub.
func (t *tx) effectiveKeys(n *nsRow, cfg *Config) []grant.Key {
	if !n.isBranch() {
		return cfg.Keys
	}
	base := t.nsByID(n.base.Int64)
	copied := t.config(n.baseConfigSeq.Int64)
	baseKeys := t.effectiveKeys(base, t.config(base.configSeq))
	var out []grant.Key
	for _, k := range cfg.Keys {
		if hasKid(copied.Keys, k.Kid) {
			bk, ok := findKey(baseKeys, k.Kid)
			if !ok || string(bk.Pub) != string(k.Pub) {
				continue
			}
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

// effectiveRevoked merges the revocations of the namespace and all its bases.
func (t *tx) effectiveRevoked(n *nsRow, cfg *Config) map[string]bool {
	if !n.isBranch() {
		return cfg.Revoked
	}
	out := map[string]bool{}
	for k := range cfg.Revoked {
		out[k] = true
	}
	for b := n; b.isBranch(); {
		b = t.nsByID(b.base.Int64)
		for k := range t.config(b.configSeq).Revoked {
			out[k] = true
		}
	}
	return out
}

// checkAt resolves a key's requireAt (§C.4): the grant's at must be an ns_id
// in the named chain; the lag is how long it has not been the head.
func (t *tx) checkAt(n *nsRow) func(requireAt any, at any) (time.Duration, error) {
	return func(requireAt any, at any) (time.Duration, error) {
		target := n
		if s, ok := requireAt.(string); ok {
			target = t.nsByName(s)
			if target == nil {
				return 0, fmt.Errorf("unknown namespace %q", s)
			}
		}
		var idText string
		switch x := at.(type) {
		case string:
			idText = x
		case map[string]any:
			ns, _ := x["ns"].(string)
			if ns != target.name {
				return 0, fmt.Errorf("at names another namespace")
			}
			idText, _ = x["id"].(string)
		}
		id, err := ids.Parse(idText)
		if err != nil {
			return 0, fmt.Errorf("malformed at")
		}
		seq, ok := t.nsLogSeq(target.id, id)
		if !ok {
			return 0, fmt.Errorf("at is not in the chain of %s", target.name)
		}
		var lag time.Duration
		var next int64
		if err := t.QueryRow(`SELECT created FROM ns_log WHERE ns = ? AND prev_seq = ?`, target.id, seq).Scan(&next); err == nil {
			lag = t.now.Sub(time.UnixMilli(next)) // how long at has not been the head
		}
		// The namespace named by requireAt bounds the lag with its own
		// maxLag (§C.4, §B.11.3). A key-level maxLag is a stricter override.
		if ml := t.config(target.configSeq).MaxLag; ml != nil && lag > *ml {
			return lag, fmt.Errorf("at is older than %s's maxLag", target.name)
		}
		return lag, nil
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
				if !r.Eval(env) {
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
// decides access. It answers 404 rather than 403 so existence is not
// revealed (§7).
func (t *tx) reader(n *nsRow, cred Credentials, resource string) (*actor, *Error) {
	cfg := t.config(n.configSeq)
	var a *actor
	if cred.Bearer != "" || t.e.opt.AuthDisabled {
		var err *Error
		a, err = t.authenticate(n.name, n, cfg, cred, nil)
		if err != nil && cfg.Read != "public" {
			if err.Status == 401 {
				return nil, err
			}
			return nil, notFound()
		}
	}
	if !t.canRead(n, cfg, a, resource) {
		if a == nil {
			return nil, apiErr(401, "unauthenticated", "message", "missing grant")
		}
		return nil, notFound()
	}
	return a, nil
}

// unrestrictedRead reports whether an actor may read every resource of a
// namespace: no rule of its blocks, key scope or roles refers to /resource,
// and the key has no readScope (§7.6).
func (a *actor) unrestrictedRead() bool {
	if a.verified == nil {
		return true
	}
	if a.verified.Key.ReadScopeResource {
		return false
	}
	lists := [][]any{a.verified.KeyRules, a.verified.BlockRules}
	for _, r := range a.verified.EffectiveRoles {
		lists = append(lists, a.verified.RoleRules(r))
	}
	for _, l := range lists {
		for _, rv := range l {
			r, err := compileCached(rv)
			if err != nil || r.Refs()["resource"] || r.Refs()["*"] {
				return false
			}
		}
	}
	return true
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
		b.tokens = math.Min(d.rate.Burst, b.tokens+now.Sub(b.last).Seconds()*d.rate.Rate)
		b.last = now
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
	l := cfg.Limits
	pr := l.RatePerPrincipal
	if a.keyRate != nil && a.keyRate.Rate < pr.Rate {
		pr = Rate{a.keyRate.Rate, math.Min(a.keyRate.Burst, pr.Burst)}
	}
	draws := []draw{
		{"p\x00" + a.bucketKey, pr, float64(items), "ratePerPrincipal"},
		{"n\x00" + n.name, l.RatePerNamespace, float64(items), "ratePerNamespace"},
	}
	for _, r := range resources {
		draws = append(draws, draw{"r\x00" + n.name + "\x00" + r + "\x00" + a.bucketKey, l.RatePerResource, 1, "ratePerResource"})
	}
	wait, hit, ok := t.e.rate.admit(t.now, draws)
	if !ok {
		secs := int(math.Ceil(wait.Seconds()))
		if secs < 1 {
			secs = 1
		}
		e := apiErr(429, "rate", "message", "rate limit exceeded", "limit", hit, "retryAfter", secs)
		e.Header = map[string][]string{"Retry-After": {fmt.Sprint(secs)}}
		return e
	}
	return nil
}

// guardedPaths need a grant chained to a * key (§7.4).
var guardedPaths = []string{"/keys", "/roles", "/revoked", "/limits", "/retention", "/encryption"}

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
