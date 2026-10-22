package core

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/rules"
)

// Edge grants (§C.5.2, §9).
//
// POST /edge-grants exchanges grants with read for edge grants: the grant
// in Authorization, or up to MaxEdgeGrants of them in the body. Each gets
// one per namespace its ns names, scoped to the smallest prefix it
// allows: /r/{ns}/{name}, one per name, when its read rules fix /resource
// to a finite set of names, else /r/{ns} and /ns/{ns}. The edge evaluates
// no rules, so the grant's blocks and its key's scope may refer to
// /resource only to fix it, and never to /now. A grant with roles needs a
// qualifying role (§2.1): one that lists read, whose rules don't refer to
// /now, refer to /resource only if the grant fixes it, and pass now for
// each name fixed, or once if none is. Roles are alternatives, so one is
// enough. The rules that remain, over /principal and /action, are
// constant for the edge grant's reads, and must pass here, for each name
// fixed. Anything else is 403, as is a grant without read in a namespace
// it names. A grant naming "*" is 401: from a namespace key it is
// invalid, and an operator grant authorises nothing here (§C.4).
//
// The answer is all or nothing across every grant: a namespace that
// doesn't exist, is purged or refuses a grant refuses the request, 401 if
// any would be 401, else 403 if any would be 403, so it doesn't reveal
// which exist, and 410 purged only when every one refused is purged and
// the grant verifies and may read there, naming in ns and head the first
// refused in the order of the grants and their root blocks. Only then is
// an exchange of more than maxEdgePrefixes distinct prefixes 400, and
// only then does the request draw one token, however many grants it
// carries, from the exchangeRate bucket of each distinct principal among
// them, and from no write bucket (§6.6), so a reader's exchanges and
// writes never wait on each other. The 400 is a refusal too and draws
// nothing: a token would save no work, since a 429 is decided only once
// every grant has verified, and the prefixes are counted only up to the
// cap, so an exchange over it costs no more than its grants'
// verification. With authentication disabled it is 404 not_offered
// (§12).
//
// The server turns them into cookies (internal/edge); a read under one
// comes back as Credentials.Edge, which reader honours for that namespace
// and, if fixed, that resource only.

// MaxEdgeGrants is how many grants one POST /edge-grants may exchange
// (§C.5.2).
const MaxEdgeGrants = 50

// maxEdgePrefixes is how many distinct prefixes one POST /edge-grants may
// issue (§C.5.2): a namespace-wide edge grant gives two, /r/{ns} and
// /ns/{ns}.
const maxEdgePrefixes = 100

// EdgeGrant is one namespace's edge grant: reads of NS, fixed to Resource
// if set. It names no principal (§C.5.3).
type EdgeGrant struct {
	NS       string
	Resource string
	// Prefix is a verified edge grant's prefix (empty when issuing).
	Prefix string
	// Exp is a verified edge grant's expiry, or when issuing the
	// exchanged grant's exp (zero if none), which no edge grant outlives.
	Exp time.Time
}

// Prefixes are the URL prefixes the edge grant covers (edge prefixes,
// §2.1).
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

// EdgeGrantsOffered is nil unless authentication is disabled, where
// issuance is 404 not_offered whatever the request (§C.5.2, §12): the
// server asks it before reading a body.
func (e *Engine) EdgeGrantsOffered() error {
	if e.opt.AuthDisabled {
		return apiErr(404, "not_offered", "message", "edge grants need authentication (§1)")
	}
	return nil
}

// IssueEdgeGrants decides POST /edge-grants for bearers, the grants
// exchanged, as they would follow "Bearer " (§C.5.2). None is 401; the
// server keeps their number within MaxEdgeGrants.
func (e *Engine) IssueEdgeGrants(ctx context.Context, bearers []string) (*EdgeGrants, error) {
	if err := e.EdgeGrantsOffered(); err != nil {
		return nil, err
	}
	if len(bearers) == 0 {
		return nil, apiErr(401, "unauthenticated", "message", "missing grant")
	}
	gs := make([]*grant.Grant, len(bearers))
	bad := make([]*Error, len(bearers))
	for i, b := range bearers {
		g, err := grant.DecodeLimited(b, e.grantLimits())
		if e := grantLimit(err); e != nil {
			return nil, e
		}
		if err != nil {
			bad[i] = authErr(err) // ranked with the rest, in its place
			continue
		}
		gs[i] = g
	}
	out := &EdgeGrants{Now: e.now()}
	col := &edgeCollect{seen: map[string]bool{}}
	err := e.read(ctx, func(t *tx) error {
		t.decoded = map[string]*grant.Grant{}
		for i, g := range gs {
			if g != nil {
				t.decoded[bearers[i]] = g
			}
		}
		var refused *Error
		refuse := func(err *Error) {
			if refused == nil || refusalRank(err) < refusalRank(refused) {
				refused = err
			}
		}
		var buckets []string // each principal's, once
		seen := map[string]bool{}
		for i, g := range gs {
			if refused != nil && refusalRank(refused) == 0 {
				break // 401 ranks first, so nothing after it changes the answer
			}
			if g == nil {
				refuse(bad[i])
				continue
			}
			bucket, err := t.edgeGrantsOf(g, Credentials{Bearer: bearers[i]}, col)
			if err != nil {
				refuse(err)
				continue
			}
			if !seen[bucket] {
				seen[bucket] = true
				buckets = append(buckets, bucket)
			}
		}
		if refused != nil {
			return refused
		}
		// The cap counts distinct prefixes once the grants have verified, so
		// a refusal outranks it (§C.5.2); it draws nothing.
		if col.over {
			return badInput(fmt.Sprintf("the grants would issue more than %d distinct prefixes (§C.5.2)", maxEdgePrefixes))
		}
		out.Grants = col.grants
		// One token for the request from each principal's exchangeRate
		// bucket, all at once: one 429 for the request (§6.6, §C.5).
		draws := make([]draw, len(buckets))
		for i, b := range buckets {
			draws[i] = draw{"e\x00" + b, e.opt.Maximums.ExchangeRate, 1, "exchangeRate"}
		}
		if err := t.admit(draws); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// edgeCollect gathers an exchange's edge grants, in the order of the
// grants and their root blocks, while they give at most maxEdgePrefixes
// distinct prefixes (§C.5.2). Past that it only records that the cap is
// exceeded: a grant naming many namespaces and fixing /resource to many
// names gives their product, which the 400 needs no more of.
type edgeCollect struct {
	grants []EdgeGrant
	seen   map[string]bool // the prefixes of grants
	over   bool
}

// add adds eg, unless its prefixes would exceed the cap; it reports
// whether c is still within it.
func (c *edgeCollect) add(eg EdgeGrant) bool {
	if c.over {
		return false
	}
	for _, p := range eg.Prefixes() {
		if !c.seen[p] {
			if len(c.seen) == maxEdgePrefixes {
				c.over = true
				return false
			}
			c.seen[p] = true
		}
	}
	c.grants = append(c.grants, eg)
	return true
}

// edgeGrantsOf decides the edge grants of g, presented as cred, in the
// order its root block names namespaces (§C.5.2), and adds them to col,
// each with g's exp. It returns the key of g's principal's buckets, as a
// write's are keyed (§6.6), and the first refusal of the lowest rank.
func (t *tx) edgeGrantsOf(g *grant.Grant, cred Credentials, col *edgeCollect) (string, *Error) {
	var exp time.Time
	for _, b := range g.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	var bucket string
	var refused *Error
	issued := false
	for _, ns := range g.Blocks[0].NS {
		var err *Error
		var iss *edgeIssue
		switch {
		case ns == "*":
			// Valid only from an operator key, whose grants authorise no
			// read: 401 either way (§C.4).
			err = apiErr(401, "unauthenticated", "message", `a grant naming "*" is an operator grant or invalid, and authorises no edge grant (§C.4, §C.5.2)`)
		case !g.NamesNS(ns):
			continue // a narrowing block leaves it out
		default:
			iss, err = t.edgeGrant(g, ns, cred)
		}
		if err != nil {
			if refused == nil || refusalRank(err) < refusalRank(refused) {
				refused = err
			}
			if refusalRank(refused) == 0 {
				break // 401 ranks first: the request is refused whatever follows
			}
			continue
		}
		bucket, issued = iss.bucket, true
		if iss.names == nil {
			col.add(EdgeGrant{NS: ns, Exp: exp})
		}
		for _, name := range iss.names {
			if !col.add(EdgeGrant{NS: ns, Resource: name, Exp: exp}) {
				break
			}
		}
	}
	if refused == nil && !issued {
		refused = forbidden("the grant names no namespace an edge grant can be issued for")
	}
	return bucket, refused
}

// refusalRank orders the refusals of an all-or-nothing answer (§C.5.2): 401
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
// rules fix /resource to, else (names nil) one namespace-wide; and the
// key of its principal's buckets (actor.bucketKey).
type edgeIssue struct {
	names  []string
	bucket string
}

// edgeGrant decides g's edge grants in namespace ns (§C.5.2).
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
		return nil, forbidden("the grant's read rules refer to /resource without fixing it to a finite set of valid names, or to /now, which an edge can't evaluate (§2.1, §C.5.2): " + ns)
	}
	if a.verified.Key.ReadScopeResource && names == nil {
		return nil, forbidden("the key's readScope needs a grant fixing /resource (§C.4)")
	}
	if a.verified.HasRoles() {
		var q []string
		for _, r := range roles {
			if t.qualifies(a, a.verified.RoleRules(r), names) {
				q = append(q, r)
			}
		}
		if len(q) == 0 {
			return nil, forbidden("no role of the grant that allows read qualifies for an edge grant: each has a rule referring to /now, or to /resource without the grant fixing it, or failing now for a name it fixes (§2.1): " + ns)
		}
		roles = q
	}
	// The blocks, the key scope and one qualifying role must pass now, for
	// the principal and each name fixed: they decide every read under the
	// prefix alike. The roles in roles passed for every name (qualifies).
	// Of the blocks and key scope, only the rules fixing /resource refer
	// to it, and each name fixed passes every one of them, so the first
	// stands for all: testing each would cost the square of their number,
	// which the cap, coming after, no longer bounds (§C.5).
	first := ""
	if names != nil {
		first = names[0]
	}
	if t.grantRules(a, "read", roles, t.basicEnvelope("read", first, a), false) != nil {
		return nil, forbidden("the grant's rules refuse reading " + ns)
	}
	// A purged namespace is decided last, once the grant verifies and may
	// read there, as its URLs answer 410 after the read check (§8.5). Its
	// 410 names the namespace, since a request may name several (§12).
	if n.purged {
		pe := t.purgedNS(n)
		pe.Body["ns"] = ns
		return nil, pe
	}
	return &edgeIssue{names: names, bucket: a.bucketKey}, nil
}

// qualifies reports whether an effective role listing read, with rules
// rs, is a qualifying role of a's grant (§2.1, §C.5.2, v0.65, v0.71): none
// of its rules refers to /now or the whole envelope, one refers to
// /resource only if the grant fixes it (names, nil for none), and they
// pass now against a read envelope for the principal with /resource set
// to each name fixed, or once if none is. A rule that doesn't refer to
// /resource gives the same for every name, so only those that do are
// evaluated per name.
func (t *tx) qualifies(a *actor, rs []any, names []string) bool {
	var once, each []*rules.Rule
	for _, rv := range rs {
		r, err := compileCached(rv)
		if err != nil {
			return false
		}
		switch refs := r.Refs(); {
		case refs["now"] || refs["*"] || refs["resource"] && names == nil:
			return false
		case refs["resource"]:
			each = append(each, r)
		default:
			once = append(once, r)
		}
	}
	first := ""
	if names != nil {
		first = names[0]
	}
	for i, name := range append([]string{first}, names...) {
		env := t.basicEnvelope("read", name, a)
		list := each
		if i == 0 {
			list = once
		}
		for _, r := range list {
			if !r.Eval(env) {
				return false
			}
		}
	}
	return true
}

// edgeReadScope classifies the rules of a's blocks and key scope, which
// apply on top of its roles (§C.5.2). It returns the names they fix
// /resource to (§2.1), those every fixing rule allows, in the order of the first
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

// fixesResource returns the names a rule fixes /resource to (§2.1),
// without duplicates: one for { "op": "test", "path": "/resource",
// "value": name } or a compare with eq and { "value": name }; a finite
// set for a test whose schema has only enum, or a compare with in and a
// literal array. It reports false for any other rule, or a name that
// isn't valid (§3.6).
func fixesResource(rv any) ([]string, bool) {
	lits, ok := grant.ResourceLiterals(rv)
	if !ok {
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
