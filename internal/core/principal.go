package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// PrincipalAnswer is the answer of GET /ns/{ns}/principal (§7.4): Body is
// { principal, kid, key, operator, can, roles, writer, catalog? }, Config
// the X-Config-Revision.
type PrincipalAnswer struct {
	Body   map[string]any
	Config string
}

// Principal is GET /ns/{ns}/principal (§7.4): what the grant in
// Authorization is in namespace ns, and what a writer needs from the
// namespace document, which a grant limited to some resources can't read
// (§2.1, §C.7). Only the ns check (§7) and verification (§C.2 item 1)
// apply, with no verb check, no rule and no rate limit, so a grant without
// read learns these settings too. The grant is the question: one that
// can't be used, or none, is 401 even in a public namespace (§7), and an
// edge grant (§C.5) is none. A grant whose root kid names an operator key
// verifies against those keys (§C.4), and learns whether the namespace
// exists: 404 if it doesn't. A purged namespace is 410 once the grant
// verifies (§8.5). The answer is never cached (no-store). With
// authentication disabled (§1) there is no grant: principal and kid are
// left out, as from envelopes (§6.4.1), and every verb is allowed.
func (e *Engine) Principal(ctx context.Context, ns string, cred Credentials) (*PrincipalAnswer, error) {
	cred.Edge = nil
	var ans *PrincipalAnswer
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNSOp(ns, cred, true)
		}
		cfg := t.config(n.configSeq)
		var a *actor
		if !t.e.opt.AuthDisabled {
			g, err := t.decodeGrant(n.name, cred)
			if err != nil {
				return err
			}
			a, err = t.verifyGrant(g, n.name, n, cfg, nil)
			if err != nil {
				if a, err = t.operatorPrincipal(g, n, cfg, err); err != nil {
					return err
				}
			}
			t.e.bearers.put(cred.Bearer, g)
		}
		if n.purged {
			return t.purgedNS(n)
		}
		var v *grant.Verified
		if a != nil {
			v = a.verified
		}
		body := t.principalBody(v, cfg)
		// A catalog namespace's catalog member (§7.4, §B.6, §H.2), whole
		// to a grant with unrestricted read, a public namespace's or one
		// while authentication is disabled included (readsNS).
		if c := principalCatalog(cfg.Doc, t.readsNS(n, cfg, a, false)); c != nil {
			body["catalog"] = c
		}
		ans = &PrincipalAnswer{Body: body, Config: t.configID(n.configSeq).String()}
		return nil
	})
	return ans, err
}

// operatorPrincipal verifies g against the deployment operator keys when
// its root kid names one (§C.4), once the namespace's keys refused it with
// nerr. The operator's refusal wins for a kid the namespace doesn't list.
func (t *tx) operatorPrincipal(g *grant.Grant, n *nsRow, cfg *Config, nerr *Error) (*actor, *Error) {
	kid := g.Blocks[0].Kid
	if _, ok := findKey(t.operatorKeys(), kid); !ok {
		return nil, nerr
	}
	a, err := t.verifyGrant(g, n.name, nil, nil, t.operatorKeys())
	if err != nil {
		if _, listed := findKey(t.effectiveKeys(n, cfg), kid); listed {
			return nil, nerr
		}
		return nil, err
	}
	return a, nil
}

// principalBody is the §7.4 answer for a verified grant v (nil with
// authentication disabled) under the configuration cfg.
func (t *tx) principalBody(v *grant.Verified, cfg *Config) map[string]any {
	can, roles := []any{}, []any{}
	// operator: verified by a deployment operator key (§C.4), whose can is
	// its blocks' verbs and roles []; false while authentication is
	// disabled, which has no principal, kid or key.
	out := map[string]any{"operator": v != nil && v.Operator}
	if v == nil {
		for _, verb := range grant.Verbs {
			can = append(can, verb)
		}
	} else {
		out["principal"], out["kid"] = v.Principal.Envelope(), v.Key.Kid
		out["key"] = keyThumbprint(v.Key.Pub)
		// The verbs its blocks allow, and with roles only those an
		// effective role lists (§C.2 item 2).
		for _, verb := range grant.Verbs {
			if ok, _ := v.Allows(verb); ok {
				can = append(can, verb)
			}
		}
		for _, r := range v.EffectiveRoles {
			roles = append(roles, r)
		}
	}
	sort.Slice(can, func(i, j int) bool { return can[i].(string) < can[j].(string) })
	out["can"], out["roles"] = can, roles
	w := map[string]any{"frozen": cfg.Frozen, "nonce": "optional", "signatures": "optional", "limits": t.limitsInForce(cfg)}
	if cfg.Successor != "" {
		w["successor"] = cfg.Successor
	}
	// Sealed namespaces need a fresh $nonce in every patch set whatever
	// the document says (§C.7, §E.2.5); e2e ids need none.
	if cfg.NonceRequired || cfg.level == levelSealed {
		w["nonce"] = "required"
	}
	if cfg.SignaturesRequired {
		w["signatures"] = "required"
	}
	if cfg.Encryption != "" {
		w["level"] = cfg.Encryption
	}
	out["writer"] = w
	return out
}

// keyThumbprint is /principal's key (§7.4, §H.7): the RFC 7638 SHA-256
// thumbprint, base64url without padding, of an Ed25519 verifying key as
// the JWK {"crv":"Ed25519","kty":"OKP","x":<pub>}, its required members in
// lexicographic order. An operator key's published JWK (JWKS) has the same
// required members, so a key means the same in every namespace, unlike
// its kid.
func keyThumbprint(pub ed25519.PublicKey) string {
	jwk := map[string]any{"crv": "Ed25519", "kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(pub)}
	sum := sha256.Sum256(jsonv.Canonical(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// principalCatalog is /principal's catalog member for a namespace whose
// document has catalog (§7.4, §B.6, §H.2), nil for any other: trust ([]
// when absent) and files, if set. A grant without unrestricted read of
// the catalog (whole) gets files without its x- members, and in place of
// trust only trusted, whether files.ns is one of the trusted namespaces:
// false without files, which names no namespace.
func principalCatalog(doc map[string]any, whole bool) map[string]any {
	c, ok := doc["catalog"].(map[string]any)
	if !ok {
		return nil
	}
	trust := []any{}
	if tr, ok := c["trust"].([]any); ok {
		trust = jsonv.Clone(tr).([]any)
	}
	files, hasFiles := c["files"].(map[string]any)
	out := map[string]any{}
	if whole {
		out["trust"] = trust
		if hasFiles {
			out["files"] = jsonv.Clone(files)
		}
		return out
	}
	trusted := false
	if hasFiles {
		f := map[string]any{}
		for k, v := range files {
			if !strings.HasPrefix(k, "x-") {
				f[k] = jsonv.Clone(v)
			}
		}
		out["files"] = f
		ns, _ := files["ns"].(string)
		trusted = ns != "" && slices.Contains(trust, any(ns))
	}
	out["trusted"] = trusted
	return out
}

// limitsInForce are the limits of §6.6 as the server applies them in a
// namespace whose configuration is cfg: the document's, over the
// deployment's defaults and within its maximums, which hold alone for the
// deployment-only limits, grantSize and rulesPerGrant among them (§12.2).
func (t *tx) limitsInForce(cfg *Config) map[string]any {
	l, max := cfg.Limits, t.e.opt.Maximums
	l.LogPageSize, l.LogPageBytes, l.BranchDepth, l.ExchangeRate = max.LogPageSize, max.LogPageBytes, max.BranchDepth, max.ExchangeRate
	l.RulesPerGrant, l.GrantSize = max.RulesPerGrant, max.GrantSize
	return l.Doc()
}
