package core

// Filtered namespace reads (§7.9), an origin MAY that this one
// implements unless Options.NoFilteredReads. A partial reader, one whose
// grant verifies in a namespace and allows read there without reading it
// unrestricted (§2.1), reads a covered namespace's /heads, log ranges,
// long-poll and events filtered to what it may see, at URLs under
// /ns/{ns}/view/{view}, where view is its view: scope:{digest} of its
// read rules (§A.4) and a subject binding it to its grant's key
// (grantcheck.KeySubject; ViewSubjects). A resource is visible to it where
// its grant's blocks, key scope and roles allow reading it.
//
// The files of this feature, each read inside one read transaction:
//
//   - filtered_scope.go: which namespaces are covered (fscope, §7.9
//     Where);
//   - filtered_state.go: the checkpoint a filtered answer is at (fcp, at),
//     and the stored views (filtered_views);
//   - filtered_visible.go: whether a name is visible (fview);
//   - filtered_admit.go: a request's view, from a grant
//     (grantView) or a cookie (filteredAdmit);
//   - filtered_exchange.go: POST /edge-grants for a partial reader, whose
//     edge grant covers /ns/{ns}/view/{view} alone.
//
// Every path here is reached only through filteredScope. Branches are
// never covered: their filtered URLs answer as any uncovered namespace's
// (§7.9 Where).

// fscope is a covered namespace (§7.9 Where), as of the read snapshot.
type fscope struct {
	n *nsRow
}

// filteredScope is n's coverage by §7.9, nil if it isn't covered: a
// namespace, not a branch, neither public nor end-to-end, sealed ones
// included (nsLevel below e2e, v0.89). Nothing is covered with authentication
// disabled, where every reader reads unrestricted (§1), or with
// Options.NoFilteredReads.
func (t *tx) filteredScope(n *nsRow) *fscope {
	if n == nil || t.e.opt.NoFilteredReads || t.e.opt.AuthDisabled || n.isBranch() {
		return nil
	}
	if !t.fsOpen(n, t.config(n.configSeq)) {
		return nil
	}
	return &fscope{n: n}
}

// fsOpen reports whether a namespace with document cfg can be covered:
// not public, not e2e (§7.9 Where; sealed ones since v0.89).
func (t *tx) fsOpen(n *nsRow, cfg *Config) bool {
	return cfg.Read != "public" && cfg.level < levelE2E && t.nsLevel(n) < levelE2E
}

// fconfigAt is the namespace document in force after the ns_log entry seq.
func (t *tx) fconfigAt(seq int64) *Config { return t.config(t.fconfigSeqAt(seq)) }

// fconfigSeqAt is the ns_config seq of the namespace document in force
// after the ns_log entry seq.
func (t *tx) fconfigSeqAt(seq int64) int64 {
	var cseq int64
	t.must(t.QueryRow(`SELECT config_seq FROM ns_log WHERE seq = ?`, seq).Scan(&cseq))
	return cseq
}
