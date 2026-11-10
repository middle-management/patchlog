package catvis

import (
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/tree"
)

// Profile holds what of a caller a catalog's subject sets depend on at one
// checkpoint, beyond its groups, all of which always count (§B.11.5
// Listing URLs carry the subject set: "every group: entry of the caller's
// subject set"; v0.78 dropped deciding groups): whether its sub does.
type Profile struct {
	// KeepAll is always true: every group of the caller is in its subject
	// sets (§B.11.5, §B.11.9 gs), so none leaves a group out, and a stored
	// set that holds Partial, from an earlier draft, is refused wherever
	// it is presented. It is kept for callers that still test it.
	KeepAll bool
	// Users are the user: subjects with direct $access entries, deleted
	// nodes' included (NewCatalogDeleted: a tombstone is judged by its own
	// $access, §B.11.9 Deleted resources).
	Users map[string]bool
	// SubScoped: some catalog key in a trusted content namespace has a
	// sub scope, so the caller's sub decides.
	SubScoped bool
}

// Profile is c's Profile, computed once.
func (c *Catalog) Profile() Profile {
	c.profileOnce.Do(func() { c.profile = c.computeProfile() })
	return c.profile
}

func (c *Catalog) computeProfile() Profile {
	p := Profile{KeepAll: true, Users: map[string]bool{}}
	nodes := make([]*tree.Node, 0, len(c.deleted))
	for _, name := range c.G.Names() {
		if c.G.Explicit(name) {
			nodes = append(nodes, c.G.Node(name))
		}
	}
	for _, n := range c.deleted {
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		if n == nil || n.Self {
			continue
		}
		for subj := range n.Access {
			if strings.HasPrefix(subj, userPrefix) {
				p.Users[subj] = true
			}
		}
	}
	for _, ct := range c.contents {
		if ct.Cfg == nil {
			continue
		}
		// The sub decides only where the catalog's own key has a sub
		// scope ("the catalog's key ... has a sub scope", §B.11.5).
		for _, kid := range ct.Kids {
			if k := findKey(ct.Cfg.Keys, kid); k != nil && k.SubPattern != nil {
				p.SubScoped = true
			}
		}
	}
	return p
}

// Deciding is a caller's subjects under p (§B.11.5): every one of its
// group: subjects, without duplicates, plus its user: subject if p has
// direct entries for it or SubScoped. dropped is always false: no group
// is left out (v0.78). The result is sorted and never holds "partial".
func (p Profile) Deciding(pr grant.Principal) (subjects []string, dropped bool) {
	for _, g := range dedupe(pr.Groups) {
		subjects = append(subjects, grantcheck.GroupPrefix+g)
	}
	if u := UserSubject(pr.ID); u != "" && (p.Users[u] || p.SubScoped) {
		subjects = append(subjects, u)
	}
	subjects = dedupe(subjects)
	sort.Strings(subjects)
	return subjects, false
}

// ListingSubjects are the tree service's listing subjects for a caller
// (§B.11.5): Deciding, every group of the caller and its sub where the
// catalog has direct entries for it or a sub-scoped key.
func ListingSubjects(p Profile, pr grant.Principal) []string {
	subs, _ := p.Deciding(pr)
	return subs
}

// Partial is the subject that marked, before v0.78, a subject set leaving
// out some of the caller's groups. No set holds it any more: it is kept
// only to recognise sets stored under an earlier draft, which are refused
// (403, exchange again) wherever they are presented, never served as a
// set missing groups (§B.11.5, §B.11.9 gs).
const Partial = "partial"

// ScopePrefix prefixes §B.11.9's scope subject, scope:{digest}.
const ScopePrefix = "scope:"

// FilteredSubjects are §B.11.9's subjects for a gs: every group of the
// caller (callerGroups, as the grant has them), as group: subjects
// without duplicates; the user: subjects of deciding (one list per
// catalog {ns} trusts, each Profile.Deciding's), which hold the caller's
// sub where §B.11.5 would add it for that catalog; and
// scope:{scopeDigest}, §A.4's marker digest (ScopeKeyDigest of ReadsScope's
// digest and the grant's key). deciding's groups, and any "partial" in
// it, are ignored: every group counts (v0.78). Its gs is
// grantcheck.SubjectSetID of the result.
func FilteredSubjects(deciding [][]string, callerGroups []string, scopeDigest string) []string {
	set := map[string]bool{}
	for _, g := range callerGroups {
		set[grantcheck.GroupPrefix+g] = true
	}
	for _, l := range deciding {
		for _, s := range l {
			if strings.HasPrefix(s, userPrefix) {
				set[s] = true
			}
		}
	}
	out := make([]string, 0, len(set)+1)
	for s := range set {
		out = append(out, s)
	}
	out = append(out, ScopePrefix+scopeDigest)
	sort.Strings(out)
	return out
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
