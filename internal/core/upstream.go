package core

// upstreamRefusal is the 502 upstream of §1 for a write, other than a
// purge, to resource name of n: a remote branch whose source was raised to
// a level this server lacks, or a branch whose base chain reaches one,
// answers 502 { code: "upstream", origin } for every resource its source
// had at `at`, read through or written since and not purged since (§1,
// §6.2 step 2.1, §12.1). It comes at step 2.1, after the purged-namespace
// check and before a purged resource's 410 and the idempotent-retry
// lookup. nil while no source is followed past a raise: every write goes
// on to the rest of the gate.
func (t *tx) upstreamRefusal(n *nsRow, name string) *Error {
	return nil
}
