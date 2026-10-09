package core

import (
	"context"
	"errors"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// Edge grants (§C.5 "Issuing them", §9).
//
// POST /edge-grants exchanges a grant with read for edge grants, one per
// namespace the grant's ns names, each scoped to the smallest prefix the
// grant allows: /r/{ns}/{name} when its read rules fix /resource, else
// /r/{ns} and /ns/{ns}. The edge evaluates no rules, so the grant's blocks
// and its key's scope may refer to /resource only to fix it, and never to
// /now. A grant with roles needs a role that lists read and qualifies: its
// rules refer to neither /resource nor /now. Roles are alternatives, so
// one is enough; a role whose rules test /resource doesn't qualify, even
// when the blocks fix it. The rules that remain, over /principal and
// /action, are constant for the edge grant's reads, and must pass here.
// Anything else is 403, as are "*" and a grant without read in a
// namespace it names. The answer is all or nothing: a namespace that
// doesn't exist, is purged or refuses the grant refuses the request, 401
// if any would be 401, else 403 if any would be 403, so it doesn't reveal
// which exist, and 410 purged only when every one refused is purged and
// the grant verifies and may read there. With authentication disabled it
// is 404 not_offered (§12).
//
// The server turns them into cookies (internal/edge); a read under one
// comes back as Credentials.Edge, which reader honours for that namespace
// and, if fixed, that resource only.

// EdgeGrant is one namespace's edge grant: reads of NS, fixed to Resource
// if set, for Sub.
type EdgeGrant struct {
	NS       string
	Resource string
	Sub      string
	// Exp is when a verified edge grant expires (zero when issuing).
	Exp time.Time
}

// Prefixes are the URL prefixes the edge grant covers (§C.5).
func (g EdgeGrant) Prefixes() []string {
	if g.Resource != "" {
		return []string{"/r/" + g.NS + "/" + g.Resource}
	}
	return []string{"/r/" + g.NS, "/ns/" + g.NS}
}

// EdgeGrants is the answer of POST /edge-grants before the server sets the
// cookies: the grants, and the exchanged grant's exp (zero if none), which
// no edge grant outlives.
type EdgeGrants struct {
	Grants []EdgeGrant
	Exp    time.Time
	Now    time.Time
}

// IssueEdgeGrants decides POST /edge-grants for cred (§C.5).
func (e *Engine) IssueEdgeGrants(ctx context.Context, cred Credentials) (*EdgeGrants, error) {
	if e.opt.AuthDisabled {
		return nil, apiErr(404, "not_offered", "message", "edge grants need authentication (§1)")
	}
	if cred.Bearer == "" {
		return nil, apiErr(401, "unauthenticated", "message", "missing grant")
	}
	g, err := grant.Decode(cred.Bearer, e.opt.Maximums.GrantSize)
	if errors.Is(err, grant.ErrTooLarge) {
		return nil, limitErr(413, "grant too large")
	}
	if err != nil {
		return nil, authErr(err)
	}
	root := g.Blocks[0]
	for _, ns := range root.NS {
		if ns == "*" {
			return nil, forbidden(`edge grants are issued per namespace; a grant naming "*" gets none (§C.5)`)
		}
	}
	out := &EdgeGrants{Now: e.now()}
	for _, b := range g.Blocks {
		if b.Exp != nil && (out.Exp.IsZero() || b.Exp.Before(out.Exp)) {
			out.Exp = *b.Exp
		}
	}
	err = e.read(ctx, func(t *tx) error {
		var refused *Error
		for _, ns := range root.NS {
			if !g.NamesNS(ns) {
				continue // a narrowing block leaves it out
			}
			eg, err := t.edgeGrant(g, ns, cred)
			if err != nil {
				if refused == nil || refusalRank(err) < refusalRank(refused) {
					refused = err
				}
				continue
			}
			out.Grants = append(out.Grants, *eg)
		}
		if refused != nil {
			return refused
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out.Grants) == 0 {
		return nil, forbidden("the grant names no namespace an edge grant can be issued for")
	}
	return out, nil
}

// refusalRank orders the refusals of an all-or-nothing answer (§C.5): 401
// if any namespace's is, then 403, then the rest, and 410 for a purged one
// only when every refusal is.
func refusalRank(err *Error) int {
	switch err.Status {
	case 401:
		return 0
	case 403:
		return 1
	case 410:
		return 3
	}
	return 2
}

// edgeGrant decides g's edge grant in namespace ns (§C.5).
func (t *tx) edgeGrant(g *grant.Grant, ns string, cred Credentials) (*EdgeGrant, *Error) {
	n := t.nsByName(ns)
	if n == nil {
		return nil, t.absentNS(ns, cred)
	}
	a, err := t.verifyGrant(g, ns, n, t.config(n.configSeq), nil)
	if err != nil {
		return nil, err
	}
	ok, roles := a.verified.Allows("read")
	if !ok {
		return nil, forbidden("the grant does not allow read in " + ns)
	}
	res, safe := edgeReadScope(a)
	if !safe {
		return nil, forbidden("the grant's read rules refer to /resource without fixing it, or to /now, which an edge can't evaluate (§C.5): " + ns)
	}
	if a.verified.Key.ReadScopeResource && res == "" {
		return nil, forbidden("the key's readScope needs a grant fixing /resource (§C.4)")
	}
	if a.verified.HasRoles() {
		var q []string
		for _, r := range roles {
			if edgeRole(a.verified.RoleRules(r)) {
				q = append(q, r)
			}
		}
		if len(q) == 0 {
			return nil, forbidden("no role of the grant that allows read qualifies for an edge grant: each has a rule referring to /resource or /now (§C.5): " + ns)
		}
		roles = q
	}
	// The blocks, the key scope and one qualifying role must pass now, for
	// the principal: they decide every read under the prefix alike.
	if t.grantRules(a, "read", roles, t.basicEnvelope("read", res, a), false) != nil {
		return nil, forbidden("the grant's rules refuse reading " + ns)
	}
	// A purged namespace is decided last, once the grant verifies and may
	// read there, as its URLs answer 410 after the read check (§8.5).
	if n.purged {
		return nil, purgedNS()
	}
	return &EdgeGrant{NS: ns, Resource: res, Sub: a.principal.ID}, nil
}

// edgeRole reports whether a role's rules qualify it for an edge grant
// (§C.5): none refers to /resource, /now or the whole envelope.
func edgeRole(rules []any) bool {
	for _, rv := range rules {
		r, err := compileCached(rv)
		if err != nil {
			return false
		}
		if refs := r.Refs(); refs["resource"] || refs["now"] || refs["*"] {
			return false
		}
	}
	return true
}

// edgeReadScope classifies the rules of a's blocks and key scope, which
// apply on top of its roles. It returns the resource they fix, "" for
// none, and false if a rule refers to /resource without fixing it, to
// /now or to the whole envelope, or if rules fix different resources.
func edgeReadScope(a *actor) (string, bool) {
	fixed := ""
	for _, l := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range l {
			r, err := compileCached(rv)
			if err != nil {
				return "", false
			}
			refs := r.Refs()
			if refs["now"] || refs["*"] {
				return "", false
			}
			if !refs["resource"] {
				continue
			}
			name, ok := fixesResource(rv)
			if !ok || (fixed != "" && fixed != name) {
				return "", false
			}
			fixed = name
		}
	}
	return fixed, true
}

// fixesResource reports whether a rule is exactly
// { "op": "test", "path": "/resource", "value": name } for a valid name.
func fixesResource(rv any) (string, bool) {
	m, ok := rv.(map[string]any)
	if !ok || len(m) != 3 || m["op"] != "test" || m["path"] != "/resource" {
		return "", false
	}
	name, ok := m["value"].(string)
	if !ok || !ValidResourceName(name) {
		return "", false
	}
	return name, true
}

// edgeReader decides a read under an edge grant (§C.5): of its namespace,
// and if fixed of its resource only. The edge grant was issued for a grant
// with unrestricted read there, or read of that resource, so the actor
// stands for it without rules. Each read checks its exp, so an event
// stream opened under it ends there, as under the grant.
func (t *tx) edgeReader(n *nsRow, eg *EdgeGrant, resource string) (*actor, *Error) {
	if !eg.Exp.IsZero() && !t.now.Before(eg.Exp) {
		return nil, apiErr(401, "unauthenticated", "message", "the edge grant has expired")
	}
	if eg.NS != n.name {
		return nil, nsNotNamed(n.name)
	}
	if eg.Resource != "" && eg.Resource != resource {
		return nil, notFound()
	}
	return &actor{principal: grant.Principal{ID: eg.Sub}, bucketKey: eg.Sub}, nil
}
