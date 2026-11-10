package client

import "github.com/middle-management/patchlog/internal/seal"

// Kid is the kid of the epoch revision d.ID is served under at E3, as a
// derived view takes it (§E.2.6, §E.3.1): that of the sealed op of the
// newest revision of the range folded that isn't a tombstone and whose
// patch set isn't [] (a restore with [] keeps the last live document),
// else, for a fold that starts at a pruning horizon, its snapshot's kid;
// "" where the fold has neither, or the document was served in the clear
// (Plain). The op is this namespace's own only where its pl.ns names it
// (§E.3.1): one a branch reads through from a base, whose epoch is not
// this namespace's, gives "", as does an own op whose kid names another
// namespace, so EpochOf is 0 for both (not known: the epoch in force,
// judged where the view is first sealed). A snapshot's pl.ns is its
// kid's namespace (openSnapshotJWE), so the same rule goes by its kid.
func (d *E2EDoc) Kid() string {
	for i := len(d.log) - 1; i >= 0; i-- {
		e := d.log[i]
		if e.Kind != "rev" || !e.HasPatches {
			continue
		}
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			continue
		}
		kid, plNS, ok := opKid(e.Patches)
		if !ok || plNS != d.ns || !kidNames(kid, d.ns) {
			return ""
		}
		return kid
	}
	if !kidNames(d.sinceKid, d.ns) {
		return ""
	}
	return d.sinceKid
}

// opKid returns the kid and pl.ns of the sealed op a revision's patch set
// is (§E.3.1); ok is false where it is none or its header doesn't parse.
func opKid(patches any) (kid, plNS string, ok bool) {
	jwe, ok := seal.SealedJWE(patches)
	if !ok {
		return "", "", false
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return "", "", false
	}
	plNS, _ = h.PL["ns"].(string)
	return h.Kid, plNS, true
}

// kidNames reports whether kid parses and names namespace ns.
func kidNames(kid, ns string) bool {
	kns, _, err := seal.ParseKid(kid)
	return err == nil && kns == ns
}
