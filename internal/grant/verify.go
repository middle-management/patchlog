package grant

import (
	"crypto/ed25519"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Principal is the effective principal of a verified grant (§C.2, §6.4.1).
type Principal struct {
	ID            string
	Groups, Roles []string
	Attrs         map[string]any
	Via           []string
	Grant         string
}

func strsToAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// Envelope is the principal member of a change envelope, as jsonv values.
func (p Principal) Envelope() map[string]any {
	attrs, _ := jsonv.Clone(p.Attrs).(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	return map[string]any{
		"id":     p.ID,
		"groups": strsToAny(p.Groups),
		"roles":  strsToAny(p.Roles),
		"attrs":  attrs,
		"via":    strsToAny(p.Via),
		"grant":  p.Grant,
	}
}

// Env is the configuration in force for a verification.
type Env struct {
	Now     time.Time
	NS      string
	Keys    []Key
	Revoked map[string]bool
	Roles   Roles
	// Operator says Keys are the deployment's operator keys (§C.4
	// bootstrapping). Only grants they sign may name "*" in ns.
	Operator      bool
	ValidateAttrs func(schema any, attrs map[string]any) error
	// CheckAt checks a key's requireAt (§C.4): at must be an ns_id in the
	// chain requireAt names (true: this namespace), and must have been that
	// namespace's head at some point within maxLag before issued, the
	// grant's issuance (see Issued). maxLag is the namespace document's
	// (DefaultMaxLag when absent), or keyMaxLag when that is stricter (see
	// EffectiveMaxLag). A non-nil error refuses the grant (403).
	CheckAt func(requireAt, at any, issued time.Time, keyMaxLag *time.Duration) error
}

// DefaultMaxLag is a namespace's maxLag when its document sets none (§C.4).
const DefaultMaxLag = 60 * time.Second

// EffectiveMaxLag is the maxLag that applies to at: the namespace's
// (DefaultMaxLag if nil) or the key's, whichever is smaller (§C.4).
func EffectiveMaxLag(nsMaxLag, keyMaxLag *time.Duration) time.Duration {
	lag := DefaultMaxLag
	if nsMaxLag != nil {
		lag = *nsMaxLag
	}
	if keyMaxLag != nil && *keyMaxLag < lag {
		lag = *keyMaxLag
	}
	return lag
}

// Issued is when a grant counts as issued for requireAt (§C.4): the later
// of the root block's nbf and exp − maxTtl, of those that exist (exp −
// maxTtl only when the key sets maxTtl). ok is false when neither exists:
// the grant then fails the key scope, since nothing bounds how long ago it
// was issued.
func Issued(root Block, key *Key) (issued time.Time, ok bool) {
	if root.Nbf != nil {
		issued, ok = *root.Nbf, true
	}
	if key != nil && key.MaxTTL != nil && root.Exp != nil {
		if s := root.Exp.Add(-*key.MaxTTL); !ok || s.After(issued) {
			issued, ok = s, true
		}
	}
	return issued, ok
}

// HeadWithin reports whether a revision was its namespace's head at some
// point within lag before issued, or later: next is when its successor was
// written (nil while it is still the head).
func HeadWithin(next *time.Time, issued time.Time, lag time.Duration) bool {
	return next == nil || !next.Before(issued.Add(-lag))
}

// Verified is the result of a successful verification.
type Verified struct {
	Grant     *Grant
	Key       *Key
	Principal Principal
	// Can are the verbs the grant allows (§C.2 item 2): those the
	// intersection of its blocks' can allows (the root's roles' verbs for
	// a root without can), within its key's can for a namespace key, and,
	// if it carries roles, listed by an effective role.
	Can map[string]bool
	// EffectiveRoles are its effective roles (§2.1): nil if it carries
	// none, and empty, allowing no verb, if it carries roles but none is
	// effective.
	EffectiveRoles []string
	StarKey        bool
	// Operator: an operator key verified it (Env.Operator, §C.4).
	Operator   bool
	BlockRules []any
	KeyRules   []any

	roles Roles
}

// Verify checks a decoded grant against the configuration in force (§C.2,
// §C.4), in the order of §C.2: first that every block carrying ns names
// env.NS (403, before anything is verified), then the signature chain,
// times, revocation and "*" in ns outside an operator grant (401: no usable
// grant), then the key scope (403), readScope included, so the core and the
// services that verify grants (grantcheck) refuse the same grants.
func Verify(g *Grant, env Env) (*Verified, error) {
	if g == nil || len(g.Blocks) == 0 {
		return nil, unauth("missing grant")
	}
	if !g.NamesNS(env.NS) {
		return nil, forbid("grant does not apply to namespace %q", env.NS)
	}
	root := g.Blocks[0]
	var key *Key
	for i := range env.Keys {
		if env.Keys[i].Kid == root.Kid {
			key = &env.Keys[i]
			break
		}
	}
	if key == nil {
		return nil, unauth("no key can verify the grant")
	}
	if len(key.Pub) != ed25519.PublicKeySize {
		return nil, unauth("bad root signature")
	}
	if err := g.verifyChain(key.Pub); err != nil {
		return nil, unauth("%v", err)
	}

	// Time window: nbf <= now < exp for every block.
	now := env.Now
	for i, b := range g.Blocks {
		if b.Nbf != nil && now.Before(*b.Nbf) {
			return nil, unauth("grant block %d not yet valid", i)
		}
		if b.Exp != nil && !now.Before(*b.Exp) {
			return nil, unauth("grant block %d expired", i)
		}
	}

	// Revocation (§C.4). The root block's revocation id is its grant id;
	// the text id of its signature, which named it before v0.71, still
	// revokes it, so a revoked list written then keeps revoking.
	for i, r := range g.RevocationIDs() {
		if env.Revoked[r] || i == 0 && env.Revoked[g.rootSigID()] {
			return nil, unauth("grant block %d revoked", i)
		}
	}

	// "*" in ns: only grants an operator key signs may name it (§C.4); in
	// any other the grant is invalid.
	if g.usesStar() && !env.Operator {
		return nil, unauth(`only operator grants may name "*" in ns`)
	}

	// Key scope. Only the root block's can is the issuer's (§C.4): a
	// narrowing block's verbs outside the key's can narrow nothing more,
	// since verbs are intersected below (§C.1).
	star := key.IsStar()
	if !star {
		for _, c := range root.Can {
			if !contains(key.Can, c) {
				return nil, forbid("key %q may not grant %q", key.Kid, c)
			}
		}
	}
	if key.MaxTTL != nil {
		// The root block's remaining lifetime, exp − max(now, nbf): a
		// narrowing block's earlier exp doesn't shorten what the issuer
		// signed (§C.4).
		start := now
		if root.Nbf != nil && root.Nbf.After(start) {
			start = *root.Nbf
		}
		if root.Exp.Sub(start) > *key.MaxTTL {
			return nil, forbid("grant lifetime exceeds key maxTtl")
		}
	}
	if key.SubPattern != nil && !key.SubPattern.MatchString(root.Sub) {
		return nil, forbid("sub %q not allowed by key %q", root.Sub, key.Kid)
	}
	if ok, v := key.Groups.Permits(root.Groups); !ok {
		return nil, forbid("group %q not allowed by key %q", v, key.Kid)
	}
	if ok, v := key.Roles.Permits(root.Roles); !ok {
		return nil, forbid("role %q not allowed by key %q", v, key.Kid)
	}
	if key.AttrsSchema != nil {
		if env.ValidateAttrs == nil {
			return nil, forbid("cannot check attrs against key scope")
		}
		if err := env.ValidateAttrs(key.AttrsSchema, root.Attrs); err != nil {
			return nil, forbid("attrs not allowed by key %q: %v", key.Kid, err)
		}
	}
	if key.RequireAt != nil {
		if root.At == nil {
			return nil, forbid("key %q requires at", key.Kid)
		}
		issued, ok := Issued(root, key)
		if !ok {
			return nil, forbid("key %q requires at, and the grant has neither nbf nor a key maxTtl to date its issuance (§C.4)", key.Kid)
		}
		if env.CheckAt == nil {
			return nil, forbid("cannot check at")
		}
		if err := env.CheckAt(key.RequireAt, root.At, issued, key.MaxLag); err != nil {
			return nil, forbid("at rejected: %v", err)
		}
	}

	// Effective roles (§2.1), for a grant that carries roles, one with a
	// block listing roles: the root block's (none if it lists none) that
	// every narrowing block listing roles keeps and the configuration
	// defines.
	var effRoles []string
	if g.carriesRoles() {
		effRoles = []string{}
		for _, r := range root.Roles {
			if _, ok := env.Roles[r]; !ok || contains(effRoles, r) {
				continue
			}
			kept := true
			for _, b := range g.Blocks[1:] {
				if b.HasRoles && !contains(b.Roles, r) {
					kept = false
					break
				}
			}
			if kept {
				effRoles = append(effRoles, r)
			}
		}
	}

	// Effective verbs.
	can := map[string]bool{}
	if root.HasCan {
		for _, c := range root.Can {
			can[c] = true
		}
	} else {
		for _, r := range effRoles {
			for _, c := range env.Roles[r].Can {
				can[c] = true
			}
		}
	}
	for _, b := range g.Blocks[1:] {
		if b.HasCan {
			for c := range can {
				if !contains(b.Can, c) {
					delete(can, c)
				}
			}
		}
	}
	for c := range can {
		if !star && !contains(key.Can, c) || effRoles != nil && !listedBy(env.Roles, effRoles, c) {
			delete(can, c)
		}
	}

	var blockRules []any
	var via []string
	for _, b := range g.Blocks {
		blockRules = append(blockRules, b.Rules...)
		if b.Via != "" {
			via = append(via, b.Via)
		}
	}
	principalRoles := effRoles
	if principalRoles == nil {
		principalRoles = []string{}
	}
	if via == nil {
		via = []string{}
	}
	v := &Verified{
		Grant: g,
		Key:   key,
		Principal: Principal{
			ID:     root.Sub,
			Groups: root.Groups,
			Roles:  principalRoles,
			Attrs:  root.Attrs,
			Via:    via,
			Grant:  g.ID().String(),
		},
		Can:            can,
		EffectiveRoles: effRoles,
		StarKey:        star,
		Operator:       env.Operator,
		BlockRules:     blockRules,
		KeyRules:       key.Rules,
		roles:          env.Roles,
	}
	if key.ReadScopeResource {
		// The key's scope (§C.2 item 1, §C.4): every read grant it signs
		// fixes /resource (§2.1), whatever the request.
		if ok, _ := v.Allows("read"); ok && !v.FixesResource() {
			return nil, forbid(`key %q has readScope "resource": a read grant it signs must fix /resource (§2.1, §C.4)`, key.Kid)
		}
	}
	return v, nil
}

// listedBy reports whether one of roles, defined in defs, lists verb.
func listedBy(defs Roles, roles []string, verb string) bool {
	for _, r := range roles {
		if contains(defs[r].Can, verb) {
			return true
		}
	}
	return false
}

// HasRoles reports whether the grant carries roles (§2.1): a block of it,
// the root or a narrowing one, lists roles. Its verbs then need an
// effective role listing them (Allows).
func (v *Verified) HasRoles() bool { return v.Grant.carriesRoles() }

// carriesRoles reports whether a block of g lists roles (§2.1).
func (g *Grant) carriesRoles() bool {
	for _, b := range g.Blocks {
		if b.HasRoles {
			return true
		}
	}
	return false
}

// Allows reports whether verb is allowed at step 1 of §6.2: the blocks (and
// key) allow it and, if the grant carries roles, at least one effective role
// lists it. roles are the effective roles listing the verb, whose rules the
// caller must evaluate (at least one must pass).
func (v *Verified) Allows(verb string) (ok bool, roles []string) {
	if !v.Can[verb] {
		return false, nil
	}
	if !v.HasRoles() {
		return true, nil
	}
	for _, r := range v.EffectiveRoles {
		if contains(v.roles[r].Can, verb) {
			roles = append(roles, r)
		}
	}
	return len(roles) > 0, roles
}

// RoleRules returns the rules of an effective role.
func (v *Verified) RoleRules(role string) []any { return v.roles[role].Rules }
