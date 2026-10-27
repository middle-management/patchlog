package client

import "github.com/middle-management/patchlog/internal/seal"

// Kid is the kid of the epoch revision d.ID is served under at E3, as a
// derived view takes it (§E.2.6, §E.3.1): that of the sealed op of the
// newest revision of the range folded that isn't a tombstone and whose
// patch set isn't [] (a restore with [] keeps the last live document),
// else, for a fold that starts at a pruning horizon, its snapshot's kid;
// "" where the fold has neither, or the document was served in the clear
// (Plain). The kid may name a base's namespace, for content a branch reads
// through (§F.8).
func (d *E2EDoc) Kid() string {
	for i := len(d.log) - 1; i >= 0; i-- {
		e := d.log[i]
		if e.Kind != "rev" || !e.HasPatches {
			continue
		}
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			continue
		}
		jwe, ok := seal.SealedJWE(e.Patches)
		if !ok {
			return ""
		}
		h, err := seal.ParseHeader(jwe)
		if err != nil {
			return ""
		}
		return h.Kid
	}
	return d.sinceKid
}
