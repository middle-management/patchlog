package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// Edge grants (§C.5 "Issuing them", §9).
//
// POST /edge-grants exchanges grants with read for edge grants: the grant
// in Authorization, or up to MaxEdgeGrants of them in the body. Each gets
// one per namespace its ns names, scoped to the smallest prefix it
// allows: /r/{ns}/{name}, one per name, when its read rules fix /resource
// to a finite set of names, else /r/{ns} and /ns/{ns}. The edge evaluates
// no rules, so the grant's blocks and its key's scope may refer to
// /resource only to fix it, and never to /now. A grant with roles needs a
// role that lists read and qualifies: its rules refer to neither
// /resource nor /now. Roles are alternatives, so one is enough; a role
// whose rules test /resource doesn't qualify, even when the blocks fix
// it. The rules that remain, over /principal and /action, are constant
// for the edge grant's reads, and must pass here, for each name fixed.
// Anything else is 403, as are "*", a grant without read in a namespace
// it names, and more than maxEdgeNames names over all the grants.
//
// The answer is all or nothing across every grant: a namespace that
// doesn't exist, is purged or refuses a grant refuses the request, 401 if
// any would be 401, else 403 if any would be 403, so it doesn't reveal
// which exist, and 410 purged only when every one refused is purged and
// the grant verifies and may read there, naming in ns and head the first
// refused in the order of the grants and their root blocks. Only then
// does each grant draw a token from its principal's rate limits (§6.6),
// all at once. With authentication disabled it is 404 not_offered (§12).
//
// The server turns them into cookies (internal/edge); a read under one
// comes back as Credentials.Edge, which reader honours for that namespace
// and, if fixed, that resource only.

// MaxEdgeGrants is how many grants one POST /edge-grants may exchange
// (§C.5).
const MaxEdgeGrants = 50

// maxEdgeNames is how many names the grants of one request may fix
// /resource to, summed over the grants (§C.5).
const maxEdgeNames = 100

// EdgeGrant is one namespace's edge grant: reads of NS, fixed to Resource
// if set. It names no principal (§C.5 "Format").
type EdgeGrant struct {
	NS       string
	Resource string
	// Prefix is a verified edge grant's prefix (empty when issuing).
	Prefix string
	// Exp is a verified edge grant's expiry, or when issuing the
	// exchanged grant's exp (zero if none), which no edge grant outlives.
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
// cookies: the edge grants of every grant exchanged, in the order of the
// grants and their root blocks, each with its grant's exp.
type EdgeGrants struct {
	Grants []EdgeGrant
	Now    time.Time
}

// IssueEdgeGrants decides POST /edge-grants for bearers, the grants
// exchanged, as they would follow "Bearer " (§C.5). None is 401; the
// server keeps their number within MaxEdgeGrants.
func (e *Engine) IssueEdgeGrants(ctx context.Context, bearers []string) (*EdgeGrants, error) {
	if e.opt.AuthDisabled {
		return nil, apiErr(404, "not_offered", "message", "edge grants need authentication (§1)")
	}
	if len(bearers) == 0 {
		return nil, apiErr(401, "unauthenticated", "message", "missing grant")
	}
	gs := make([]*grant.Grant, len(bearers))
	bad := make([]*Error, len(bearers))
	for i, b := range bearers {
		g, err := grant.Decode(b, e.opt.Maximums.GrantSize)
		if errors.Is(err, grant.ErrTooLarge) {
			return nil, limitErr(413, "grant too large")
		}
		if err != nil {
			bad[i] = authErr(err) // ranked with the rest, in its place
			continue
		}
		gs[i] = g
	}
	out := &EdgeGrants{Now: e.now()}
	err := e.read(ctx, func(t *tx) error {
		var refused *Error
		refuse := func(err *Error) {
			if refused == nil || refusalRank(err) < refusalRank(refused) {
				refused = err
			}
		}
		var draws []draw
		names := 0
		for i, g := range gs {
			if g == nil {
				refuse(bad[i])
				continue
			}
			egs, n, d, err := t.edgeGrantsOf(g, Credentials{Bearer: bearers[i]})
			if err != nil {
				refuse(err)
			}
			if names += n; n > 0 && names > maxEdgeNames {
				refuse(forbidden(fmt.Sprintf("the grants fix /resource to more than %d names in all, so none fixes it (§C.5)", maxEdgeNames)))
			}
			if err == nil {
				out.Grants = append(out.Grants, egs...)
				draws = append(draws, d)
			}
		}
		if refused != nil {
			return refused
		}
		// Nothing is drawn unless every grant is issued, and then all at
		// once: one 429 for the request (§6.6).
		if err := t.admit(mergeDraws(draws)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// edgeGrantsOf decides the edge grants of g, presented as cred, in the
// order its root block names namespaces (§C.5). It returns them, each
// with g's exp; the number of names g's rules fix /resource to, counted
// once however many namespaces fix them, refused ones included; the draw
// g makes on its principal's rate limits, under the limits of the first
// namespace issued; and the first refusal of the lowest rank.
func (t *tx) edgeGrantsOf(g *grant.Grant, cred Credentials) ([]EdgeGrant, int, draw, *Error) {
	var exp time.Time
	for _, b := range g.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	var out []EdgeGrant
	var d draw
	var refused *Error
	names := map[string]bool{}
	for _, ns := range g.Blocks[0].NS {
		var err *Error
		var iss *edgeIssue
		switch {
		case ns == "*":
			err = forbidden(`edge grants are issued per namespace; a grant naming "*" gets none (§C.5)`)
		case !g.NamesNS(ns):
			continue // a narrowing block leaves it out
		default:
			iss, err = t.edgeGrant(g, ns, cred)
		}
		if iss != nil {
			for _, name := range iss.names {
				names[name] = true
			}
		}
		if err != nil {
			if refused == nil || refusalRank(err) < refusalRank(refused) {
				refused = err
			}
			continue
		}
		if len(out) == 0 {
			d = iss.draw
		}
		for _, eg := range iss.grants {
			eg.Exp = exp
			out = append(out, eg)
		}
	}
	if refused == nil && len(out) == 0 {
		refused = forbidden("the grant names no namespace an edge grant can be issued for")
	}
	return out, len(names), d, refused
}

// mergeDraws merges draws on the same bucket into one, summing their
// costs, as a write draws its items at once: several grants of one
// principal draw together.
func mergeDraws(ds []draw) []draw {
	var out []draw
	at := map[string]int{}
	for _, d := range ds {
		if i, ok := at[d.key]; ok {
			out[i].cost += d.cost
			continue
		}
		at[d.key] = len(out)
		out = append(out, d)
	}
	return out
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

// edgeIssue is a grant's edge grants in one namespace: one per name its
// rules fix /resource to, else one namespace-wide; the names; and the
// draw the grant makes on its principal's rate limits there.
type edgeIssue struct {
	grants []EdgeGrant
	names  []string
	draw   draw
}

// edgeGrant decides g's edge grants in namespace ns (§C.5). Refused as
// purged, it still returns the names g fixes there, which count toward
// the request's maxEdgeNames.
func (t *tx) edgeGrant(g *grant.Grant, ns string, cred Credentials) (*edgeIssue, *Error) {
	n := t.nsByName(ns)
	if n == nil {
		return nil, t.absentNS(ns, cred)
	}
	cfg := t.config(n.configSeq)
	a, err := t.verifyGrant(g, ns, n, cfg, nil)
	if err != nil {
		return nil, err
	}
	ok, roles := a.verified.Allows("read")
	if !ok {
		return nil, forbidden("the grant does not allow read in " + ns)
	}
	names, safe := edgeReadScope(a)
	if !safe {
		return nil, forbidden("the grant's read rules refer to /resource without fixing it to a finite set of valid names, or to /now, which an edge can't evaluate (§C.5): " + ns)
	}
	if len(names) > maxEdgeNames {
		return nil, forbidden(fmt.Sprintf("the grant's rules fix /resource to more than %d names, so they don't fix it (§C.5): %s", maxEdgeNames, ns))
	}
	if a.verified.Key.ReadScopeResource && names == nil {
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
	// the principal and each name fixed: they decide every read under the
	// prefix alike.
	iss := &edgeIssue{names: names, draw: t.principalDraw(n, cfg, a, 1)}
	if names == nil {
		iss.grants = []EdgeGrant{{NS: ns}}
	}
	for _, name := range names {
		iss.grants = append(iss.grants, EdgeGrant{NS: ns, Resource: name})
	}
	for _, eg := range iss.grants {
		if t.grantRules(a, "read", roles, t.basicEnvelope("read", eg.Resource, a), false) != nil {
			return nil, forbidden("the grant's rules refuse reading " + ns)
		}
	}
	// A purged namespace is decided last, once the grant verifies and may
	// read there, as its URLs answer 410 after the read check (§8.5). Its
	// 410 names the namespace, since a request may name several (§12).
	if n.purged {
		pe := t.purgedNS(n)
		pe.Body["ns"] = ns
		return &edgeIssue{names: names}, pe
	}
	return iss, nil
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
// apply on top of its roles (§C.5). It returns the names they fix
// /resource to, those every fixing rule allows, in the order of the first
// fixing rule, or nil if none fixes it; and false if a rule refers to /now
// or to the whole envelope, or to /resource other than by fixing it, at
// top level or inside all, or if the names are none or one isn't valid
// (§3.6).
func edgeReadScope(a *actor) ([]string, bool) {
	var names []string
	fixed := false
	var walk func(rules []any) bool
	walk = func(rules []any) bool {
		for _, rv := range rules {
			r, err := compileCached(rv)
			if err != nil {
				return false
			}
			refs := r.Refs()
			if refs["now"] || refs["*"] {
				return false
			}
			if !refs["resource"] {
				continue
			}
			if m, ok := rv.(map[string]any); ok && len(m) == 1 {
				if all, ok := m["all"].([]any); ok {
					if !walk(all) {
						return false
					}
					continue
				}
			}
			set, ok := fixesResource(rv)
			if !ok {
				return false
			}
			if !fixed {
				names, fixed = set, true
				continue
			}
			in := make(map[string]bool, len(set))
			for _, n := range set {
				in[n] = true
			}
			names = slices.DeleteFunc(names, func(n string) bool { return !in[n] })
		}
		return true
	}
	if !walk(a.verified.KeyRules) || !walk(a.verified.BlockRules) {
		return nil, false
	}
	if fixed && len(names) == 0 {
		return nil, false
	}
	return names, true
}

// fixesResource returns the names a rule fixes /resource to (§C.5),
// without duplicates: one for { "op": "test", "path": "/resource",
// "value": name } or a compare with eq and { "value": name }; a finite
// set for a test whose schema has only enum, or a compare with in and a
// literal array. It reports false for any other rule, or a name that
// isn't valid (§3.6).
func fixesResource(rv any) ([]string, bool) {
	m, ok := rv.(map[string]any)
	if !ok || len(m) != 3 || m["path"] != "/resource" {
		return nil, false
	}
	var lits []any
	literal := func(k string) (any, bool) {
		o, ok := m[k].(map[string]any)
		if !ok || len(o) != 1 {
			return nil, false
		}
		v, ok := o["value"]
		return v, ok
	}
	switch m["op"] {
	case "test":
		if v, ok := m["value"]; ok {
			lits = []any{v}
		} else if sch, ok := m["schema"].(map[string]any); ok && len(sch) == 1 {
			if lits, ok = sch["enum"].([]any); !ok {
				return nil, false
			}
		} else {
			return nil, false
		}
	case "compare":
		if v, ok := literal("eq"); ok {
			lits = []any{v}
		} else if v, ok := literal("in"); ok {
			if lits, ok = v.([]any); !ok {
				return nil, false
			}
		} else {
			return nil, false
		}
	default:
		return nil, false
	}
	names := []string{}
	seen := make(map[string]bool, len(lits))
	for _, l := range lits {
		name, ok := l.(string)
		if !ok || !ValidResourceName(name) {
			return nil, false
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names, true
}

// edgeReader decides a read under an edge grant (§C.5): of its namespace,
// and if fixed of its resource only. The edge grant was issued for a grant
// with unrestricted read there, or read of that resource, so the actor
// stands for it without rules. It carries no subject, so the actor is
// named, and its bucket keyed, by the prefix. Each read checks its exp, so
// an event stream opened under it ends there, as under the grant.
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
	return &actor{principal: grant.Principal{ID: "edge:" + eg.Prefix}, bucketKey: "edge:" + eg.Prefix}, nil
}
