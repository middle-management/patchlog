package catvis

import (
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/rules"
)

// Profile holds a catalog's deciding inputs at one checkpoint (§B.11.5
// Listing URLs carry the subject set): what of a caller its visibility
// can depend on.
type Profile struct {
	// Groups are the groups (without the group: prefix) named in $access
	// of every explicit, non-implicit node, and by the rules of every role
	// and every catalog key (Kids) of every trusted content namespace.
	// Taking every role, not only those that list read, is a superset,
	// which is always safe. A key's groups allow or deny scope names no
	// group.
	Groups map[string]bool
	// KeepAll: some such rule refers to /principal/groups otherwise than
	// by positive tests of named groups (rules.GroupTests), so every
	// group of the caller decides.
	KeepAll bool
	// Users are the user: subjects with direct $access entries.
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
	p := Profile{Groups: map[string]bool{}, Users: map[string]bool{}}
	for _, name := range c.G.Names() {
		if !c.G.Explicit(name) {
			continue
		}
		n := c.G.Node(name)
		if n == nil || n.Self {
			continue
		}
		for subj := range n.Access {
			if g, ok := strings.CutPrefix(subj, grantcheck.GroupPrefix); ok {
				p.Groups[g] = true
			} else if strings.HasPrefix(subj, userPrefix) {
				p.Users[subj] = true
			}
		}
	}
	addRules := func(rs []any) {
		named, ok := rules.GroupTestsList(rs)
		if !ok {
			p.KeepAll = true
		}
		for _, g := range named {
			p.Groups[g] = true
		}
	}
	for _, ct := range c.contents {
		if ct.Cfg == nil {
			continue
		}
		for _, def := range ct.Cfg.Roles {
			addRules(def.Rules)
		}
		for _, kid := range ct.Kids {
			if k := findKey(ct.Cfg.Keys, kid); k != nil {
				addRules(k.Rules)
				if k.SubPattern != nil {
					p.SubScoped = true
				}
			}
		}
	}
	return p
}

// Deciding is a caller's deciding subjects under p (§B.11.5): its group:
// subjects that p.Groups names, or all of them with KeepAll, plus its
// user: subject if p has direct entries for it or SubScoped. dropped
// reports that a group was left out. The result is sorted and never holds
// "partial".
func (p Profile) Deciding(pr grant.Principal) (subjects []string, dropped bool) {
	for _, g := range dedupe(pr.Groups) {
		if p.KeepAll || p.Groups[g] {
			subjects = append(subjects, grantcheck.GroupPrefix+g)
		} else {
			dropped = true
		}
	}
	if u := UserSubject(pr.ID); u != "" && (p.Users[u] || p.SubScoped) {
		subjects = append(subjects, u)
	}
	sort.Strings(subjects)
	return subjects, dropped
}

// ListingSubjects are the tree service's listing subjects for a caller
// (§B.11.5): Deciding, plus "partial" when a group was left out.
func ListingSubjects(p Profile, pr grant.Principal) []string {
	subs, dropped := p.Deciding(pr)
	if dropped {
		subs = append(subs, Partial)
		sort.Strings(subs)
	}
	return subs
}

// Partial is the subject that marks a subject set leaving out some of the
// caller's groups (§B.11.5).
const Partial = "partial"

// ScopePrefix prefixes §B.11.9's scope subject, scope:{digest}.
const ScopePrefix = "scope:"

// FilteredSubjects are §B.11.9's subjects for a gs: the union of the
// deciding subjects of every catalog (deciding, one list per catalog);
// "partial" if some of the caller's groups (callerGroups, as the grant
// has them) is missing from it; and scope:{scopeDigest}, ReadsScope's
// digest. Its gs is grantcheck.SubjectSetID of the result.
func FilteredSubjects(deciding [][]string, callerGroups []string, scopeDigest string) []string {
	set := map[string]bool{}
	for _, l := range deciding {
		for _, s := range l {
			set[s] = true
		}
	}
	partial := false
	for _, g := range callerGroups {
		if !set[grantcheck.GroupPrefix+g] {
			partial = true
		}
	}
	out := make([]string, 0, len(set)+2)
	for s := range set {
		out = append(out, s)
	}
	if partial {
		out = append(out, Partial)
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
