package merge

import (
	"github.com/middle-management/patchlog/internal/client"
)

// Author is one principal of a base's merge.authors (§F.3): the root sub
// and kid of the grant a merge batch was written under.
type Author struct {
	Sub string `json:"sub"`
	Kid string `json:"kid,omitempty"`
}

// MergeAuthors reads "merge": { "authors": [{ "sub", "kid" }] } from a
// namespace document. declared is false when the document has no
// merge.authors; the core validates the shape, so malformed entries are
// skipped.
func MergeAuthors(doc map[string]any) (authors []Author, declared bool) {
	m, ok := doc["merge"].(map[string]any)
	if !ok {
		return nil, false
	}
	arr, ok := m["authors"].([]any)
	if !ok {
		return nil, false
	}
	for _, x := range arr {
		o, _ := x.(map[string]any)
		sub, _ := o["sub"].(string)
		kid, _ := o["kid"].(string)
		if sub != "" {
			authors = append(authors, Author{Sub: sub, Kid: kid})
		}
	}
	return authors, true
}

// Listed reports whether the principal (sub, kid) is in authors.
//
// Matching is on both sub and kid. A kid of "" matches on sub alone: that
// is how an entry written while authentication is disabled is matched
// (EntryListed), and a development server's -author has no key either,
// the same way the core matches allowances without keys. (merge.authors
// entries always have a kid: the core requires one.)
func Listed(authors []Author, sub, kid string) bool {
	if sub == "" {
		return false
	}
	for _, a := range authors {
		if a.Sub == sub && (a.Kid == kid || kid == "") {
			return true
		}
	}
	return false
}

// EntryPrincipal is who a namespace entry counts as for merge.authors
// (§F.3): the root sub and kid of the grant it records (§7.4), or, for an
// entry without one, its author and no kid.
func EntryPrincipal(e client.NSEntry) (sub, kid string) {
	if e.Grant != nil {
		return e.Grant.Sub, e.Grant.Kid
	}
	return e.Author, ""
}

// EntryListed reports whether a namespace entry counts as written by one
// of authors (§1, §F.3, §F.6):
//
//   - An entry recording a grant counts when the grant's root sub and kid
//     are listed.
//   - An entry recording "grant": null, written while authentication was
//     disabled, counts on its author's sub alone while the deployment runs
//     with authentication disabled (disabled: GET / says "auth":
//     "disabled", client.AuthDisabled). Under "grants" it counts for no
//     one, so nothing written without authentication is trusted in
//     production.
//   - An entry without "grant" at all, one the server wrote itself or one
//     from before v0.37, counts for no one.
func EntryListed(authors []Author, e client.NSEntry, disabled bool) bool {
	switch {
	case e.Grant != nil:
		return e.Grant.Kid != "" && Listed(authors, e.Grant.Sub, e.Grant.Kid)
	case e.GrantNull && disabled:
		return Listed(authors, e.Author, "")
	}
	return false
}

// Unlisted explains why EntryListed is false for an entry by no listed
// principal, for status and dry-run output.
func Unlisted(e client.NSEntry, disabled bool) string {
	switch {
	case e.Grant != nil:
		return "its author " + principal(e.Grant.Sub, e.Grant.Kid) + " is not in the target's merge.authors"
	case e.GrantNull && disabled:
		return "its author " + e.Author + " is not in the target's merge.authors"
	case e.GrantNull:
		return "it was written while authentication was disabled (grant: null, §1), and the deployment now runs with grants, so it counts for no one"
	}
	return "it records no grant (§7.4), so its author " + e.Author + " can't be matched against the target's merge.authors"
}

// IsTrustedMergeOf reports whether e is a merge batch of branch that
// counts for §F.3 (common ancestors) and §F.6 (the janitor's merged
// check): a batch without origin whose source.ns is branch, written under
// a grant whose root sub and kid are listed in the base's merge.authors
// (EntryListed, disabled as there).
func IsTrustedMergeOf(e client.NSEntry, branch string, authors []Author, disabled bool) bool {
	return IsMergeOf(e, branch) && EntryListed(authors, e, disabled)
}

// String describes where the pair came from, for dry-run and status
// output: "merge batch <ns_id> by <sub>/<kid>".
func (p Pair) String() string {
	s := "pair from merge batch " + p.Batch + " by " + principal(p.Author, p.Kid) + " (branch " + p.Branch + " as of " + p.At + " = target " + p.Target + ")"
	if !p.Used {
		s += ", not used: the common ancestor by ids is later"
	}
	return s
}
