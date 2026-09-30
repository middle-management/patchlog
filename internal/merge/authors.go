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
// Matching is on both sub and kid. The one exception is development mode:
// with authentication disabled the server records no kid on log entries
// (and a merger has no grant), so a kid of "" matches on sub alone, the
// same way the core matches allowances without keys. With authentication
// on, every entry written under a grant carries its root kid, so the
// exception never applies there. (merge.authors entries always have a kid:
// the core requires one.)
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

// IsTrustedMergeOf reports whether e is a merge batch of branch that
// counts for §F.3 (common ancestors) and §F.6 (the janitor's merged
// check): a batch without origin whose source.ns is branch, written by a
// principal listed in the base's merge.authors.
func IsTrustedMergeOf(e client.NSEntry, branch string, authors []Author) bool {
	return IsMergeOf(e, branch) && Listed(authors, e.Author, e.Kid)
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
