package core

// Key windows: what content moved out of a sealed namespace must open
// under (§2.1 Protection, §6.1 Read permission, §7.8, §E.2.3).
//
// Moving content never makes it readable to anyone who couldn't read it at
// its source, and reading a sealed source, public or not, takes keys that
// open the content. So a blob copy from a sealed namespace, a batch's
// local source there and the resolution of a schema revision stored there
// (in the namespace written too) each take only content that opens, under
// an epoch it is served under there, with keys POST /ns/{ns}/keys would
// give the request's own grant or one in Source-Authorization:
//
//   - which keys (keysOpenResource): K_r of the resource, for a grant whose
//     rules fix /resource to it and that may read it, or K_e, for one that
//     reads the namespace unrestricted; any other gets none;
//   - which epochs (grantEpochsOf): the grant's §E.2.3 window, from the
//     epoch in force at its latest nbf (the current one without nbf) up to
//     the current one, capped by historyEpochs;
//   - against which epochs: those the content is served under, fixed as a
//     request for it would fix one (§E.2.2): a revision's own (revEpoch),
//     a blob's those of its referencing revisions (blobKeyEpochs), and for
//     content no stored sealing has fixed yet, the current epoch, under
//     which a read would fix it now. The check doesn't store that sealing:
//     the request that next reads the content does.
//
// With authentication disabled every request gets every epoch's K_e, as
// far as historyEpochs allows, as /keys gives them. The check draws no
// exchangeRate token: no keys are handed out.

// keysOpen reports whether any of creds gets from n's /keys (§E.2.3) a key
// opening resource name's content sealed under one of epochs.
func (t *tx) keysOpen(n *nsRow, name string, epochs map[int]bool, creds []Credentials) bool {
	if len(epochs) == 0 || n.purged {
		return false
	}
	cfg := t.config(n.configSeq)
	all := t.epochStarts(`epoch_keys`, n.id, cfg.Epoch)
	within := func(a *actor) bool {
		for _, e := range t.grantEpochsOf(all, cfg, a) {
			if epochs[e] {
				return true
			}
		}
		return false
	}
	if t.e.opt.AuthDisabled {
		return within(nil)
	}
	for _, c := range creds {
		if c.Bearer == "" {
			continue
		}
		// As /keys authenticates (keysReader): the grant must name n,
		// verify under its keys and may read, in a public namespace too.
		a, err := t.keysReader(n, c, func(a *actor) bool { return a != nil && a.verified.Can["read"] })
		if err != nil || !t.keysOpenResource(a, name) {
			continue
		}
		if within(a) {
			return true
		}
	}
	return false
}

// keysOpenResource reports whether a gets, at E2, a key that opens
// resource name (keysScope): K_r of name, if a's rules fix /resource to
// it and a may read it, or K_e, if they don't fix it and a reads the
// namespace unrestricted (§2.1, §E.2.3).
func (t *tx) keysOpenResource(a *actor, name string) bool {
	fixed, fixes := fixedNames(a)
	if !fixes {
		return t.readsUnrestricted(a)
	}
	for _, f := range fixed {
		if f == name {
			return t.grantRules(a, "read", nil, t.basicEnvelope("read", name, a), false) == nil
		}
	}
	return false
}

// revKeyOpen reports whether any of creds gets keys opening revision row
// of resource name as sealed namespace n serves it, under the epoch it is
// served under there (revEpoch, §6.1 Read permission).
func (t *tx) revKeyOpen(n *nsRow, name string, row *revRow, creds []Credentials) bool {
	return t.keysOpen(n, name, map[int]bool{t.revEpoch(n, row): true}, creds)
}
