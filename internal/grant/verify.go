package grant

import (
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
	Now           time.Time
	NS            string
	Keys          []Key
	Revoked       map[string]bool
	Roles         Roles
	ValidateAttrs func(schema any, attrs map[string]any) error
	CheckAt       func(requireAt any, at any) (lag time.Duration, err error)
}

// Verified is the result of a successful verification.
type Verified struct {
	Grant          *Grant
	Key            *Key
	Principal      Principal
	Can            map[string]bool
	EffectiveRoles []string
	StarKey        bool
	BlockRules     []any
	KeyRules       []any

	roles Roles
}

// Verify checks a decoded grant against the configuration in force (§C.2,
// §C.4). Failures are *AuthError: 401 for an unknown kid or bad root
// signature, 403 otherwise.
func Verify(g *Grant, env Env) (*Verified, error) {
	if g == nil || len(g.Blocks) == 0 {
		return nil, unauth("missing grant")
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
		return nil, unauth("unknown key %q", root.Kid)
	}
	if len(key.Pub) != 32 || !g.verifyRoot(key.Pub) {
		return nil, unauth("bad root signature")
	}

	// Time window: nbf <= now < exp for every block.
	now := env.Now
	var effExp, effNbf *time.Time
	for i, b := range g.Blocks {
		if b.Nbf != nil {
			if now.Before(*b.Nbf) {
				return nil, forbid("grant block %d not yet valid", i)
			}
			if effNbf == nil || b.Nbf.After(*effNbf) {
				effNbf = b.Nbf
			}
		}
		if b.Exp != nil {
			if !now.Before(*b.Exp) {
				return nil, forbid("grant block %d expired", i)
			}
			if effExp == nil || b.Exp.Before(*effExp) {
				effExp = b.Exp
			}
		}
	}

	// Revocation.
	for i, r := range g.RevocationIDs() {
		if env.Revoked[r] {
			return nil, forbid("grant block %d revoked", i)
		}
	}

	// Namespace.
	for _, b := range g.Blocks {
		if b.HasNS && !contains(b.NS, env.NS) {
			return nil, forbid("grant does not apply to namespace %q", env.NS)
		}
	}

	// Key scope.
	star := key.IsStar()
	if !star {
		for i, b := range g.Blocks {
			for _, c := range b.Can {
				if !contains(key.Can, c) {
					return nil, forbid("key %q may not grant %q (block %d)", key.Kid, c, i)
				}
			}
		}
	}
	if key.MaxTTL != nil {
		start := now
		if effNbf != nil && effNbf.After(start) {
			start = *effNbf
		}
		if effExp.Sub(start) > *key.MaxTTL {
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
		if env.CheckAt == nil {
			return nil, forbid("cannot check at")
		}
		lag, err := env.CheckAt(key.RequireAt, root.At)
		if err != nil {
			return nil, forbid("at rejected: %v", err)
		}
		if key.MaxLag != nil && lag > *key.MaxLag {
			return nil, forbid("at is older than maxLag")
		}
	}

	// Effective roles: root roles kept by every narrowing block and defined.
	var effRoles []string
	if root.HasRoles {
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
	if !star {
		for c := range can {
			if !contains(key.Can, c) {
				delete(can, c)
			}
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
	return &Verified{
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
		BlockRules:     blockRules,
		KeyRules:       key.Rules,
		roles:          env.Roles,
	}, nil
}

// HasRoles reports whether the grant carries roles (its root lists roles).
func (v *Verified) HasRoles() bool { return v.Grant.Blocks[0].HasRoles }

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
