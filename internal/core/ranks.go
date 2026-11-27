package core

// Protection ranks (§2.1): public < private = sealed < e2e.
const (
	rankPublic = iota
	rankPrivate
	rankE2E
)

// targetRank is the protection of a namespace of this deployment as a
// target (§2.1): as a source (localSourceRank), except that a sealed one
// whose read is public is public.
func targetRank(cfg *Config) int {
	switch {
	case cfg.level == levelE2E:
		return rankE2E
	case cfg.Read == "public":
		return rankPublic
	}
	return rankPrivate
}

// samePrincipal reports whether namespace entry seq was written by the
// principal of a, whose author id is author: the same root sub and kid,
// or, while authentication is disabled, the same author (§7.2, §6.6).
// Under grants, an entry that records no grant, written while
// authentication was disabled or before grants were recorded (v0.37),
// matches no one (sameRoot).
func (t *tx) samePrincipal(seq int64, a *actor, author int64) bool {
	var au int64
	var gid []byte
	t.must(t.QueryRow(`SELECT l.author, `+t.grantIDOf("l")+` FROM ns_log l WHERE l.seq = ?`, seq).Scan(&au, &gid))
	if au != author {
		return false
	}
	return t.sameRoot(gid, a)
}
