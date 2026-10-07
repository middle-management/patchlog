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
// /r/{ns} and /ns/{ns}. The edge evaluates no rules, so a grant whose
// read rules (its blocks', its key scope's, and those of the roles that
// allow read) refer to /resource without fixing it, or to /now, gets none
// (403), as does "*" and a grant without read in a namespace it names.
// Rules over /principal and /action are constant for the edge grant's
// reads, and are evaluated here.
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
		for _, ns := range root.NS {
			if !g.NamesNS(ns) {
				continue // a narrowing block leaves it out
			}
			n := t.nsByName(ns)
			if n == nil {
				return t.absentNS(ns, cred)
			}
			cfg := t.config(n.configSeq)
			a, aerr := t.verifyGrant(g, ns, n, cfg, nil)
			if aerr != nil {
				return aerr
			}
			if n.purged {
				return gone()
			}
			ok, roles := a.verified.Allows("read")
			if !ok {
				return forbidden("the grant does not allow read in " + ns)
			}
			res, safe := edgeReadScope(a, roles)
			if !safe {
				return forbidden("the grant's read rules refer to /resource without fixing it, or to /now, which an edge can't evaluate (§C.5): " + ns)
			}
			if a.verified.Key.ReadScopeResource && res == "" {
				return forbidden("the key's readScope needs a grant fixing /resource (§C.4)")
			}
			if !t.canRead(n, cfg, a, res) {
				return forbidden("the grant's rules refuse reading " + ns)
			}
			out.Grants = append(out.Grants, EdgeGrant{NS: ns, Resource: res, Sub: a.principal.ID})
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

// edgeReadScope classifies the rules that decide a's reads: its blocks',
// its key scope's and those of roles (the roles allowing read). It
// returns the resource they fix, "" for none, and false if a rule refers
// to /resource without fixing it, to /now or to the whole envelope, or if
// rules fix different resources.
func edgeReadScope(a *actor, roles []string) (string, bool) {
	lists := [][]any{a.verified.KeyRules, a.verified.BlockRules}
	for _, r := range roles {
		lists = append(lists, a.verified.RoleRules(r))
	}
	fixed := ""
	for _, l := range lists {
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
// stands for it without rules.
func (t *tx) edgeReader(n *nsRow, eg *EdgeGrant, resource string) (*actor, *Error) {
	if eg.NS != n.name {
		return nil, nsNotNamed(n.name)
	}
	if eg.Resource != "" && eg.Resource != resource {
		return nil, notFound()
	}
	return &actor{principal: grant.Principal{ID: eg.Sub}, bucketKey: eg.Sub}, nil
}
