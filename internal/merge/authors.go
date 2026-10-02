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
// with authentication disabled the server records no grants (§1) and a
// tool has none, so a kid of "" matches on sub alone, the same way the
// core matches allowances without keys. (merge.authors entries always have
// a kid: the core requires one.)
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

// EntryListed reports whether a namespace entry was written under a grant
// whose root sub and kid are in authors (§F.3). An entry without a grant
// reference is matched on its author alone only in development mode (dev):
// for a tool without a grant of its own, against a server with
// authentication disabled, where no entry records a grant (§1). Otherwise
// such an entry, one the server wrote itself or one from before servers
// recorded grants, is no one's.
func EntryListed(authors []Author, e client.NSEntry, dev bool) bool {
	if e.Grant == nil && !dev {
		return false
	}
	sub, kid := EntryPrincipal(e)
	return Listed(authors, sub, kid)
}

// IsTrustedMergeOf reports whether e is a merge batch of branch that
// counts for §F.3 (common ancestors) and §F.6 (the janitor's merged
// check): a batch without origin whose source.ns is branch, written under
// a grant whose root sub and kid are listed in the base's merge.authors
// (EntryListed, dev as there).
func IsTrustedMergeOf(e client.NSEntry, branch string, authors []Author, dev bool) bool {
	return IsMergeOf(e, branch) && EntryListed(authors, e, dev)
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
