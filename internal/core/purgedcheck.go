package core

// purgedReadable is the read check of a purged resource's 410, or of a
// purged namespace's, at a resource's URL (§8.3 Responses, §8.5, §6.4.1
// read, v0.88): a's rules with those that refer to /doc set aside, alls
// flattened (judge.byNameOnly), since doc is null there and would
// otherwise fail every such rule. A reader whose rules fail only for want
// of doc so gets the 410; one whose other rules refuse the name gets the
// answer of any read it may not make.
func (t *tx) purgedReadable(a *actor, n *nsRow, name string) bool {
	j, all := t.rowJudge(n, a)
	switch {
	case all:
		return true
	case j == nil:
		return false
	case !j.doc && a.view == "":
		// Decided by its admission (reader), which judged the name.
		return true
	}
	return j.byNameOnly(name)
}

// tagFilteredRanges adds the tag a filtered range of n carries, ns:{ns}
// (§7.9 URLs, §12.8), to those this write purges at the CDN, once a view
// of n has been served (§8.3 CDN, v0.90; filtered_served, markServed):
// ranges are immutable but for purges (§7.9), since a revision the purge
// removes is judged anew. An archive restore clears it too, which v0.90
// allows but no longer needs (§7.9 Cost). A namespace no view of which
// was served has no filtered range cached, nor has a branch, which
// filtered reads don't cover (§7.9 Where): a purge's statements don't
// grow with the branches it reaches. Until v0.90 the tag was cleared
// only while a filtered_views row was kept, which an exchange writes
// and a sweep removes a minute after its cookies expire, and a bearer's
// read at a view URL never wrote, though its ranges stay cached.
func (t *tx) tagFilteredRanges(n *nsRow) {
	if n.isBranch() {
		return
	}
	var any bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM filtered_served WHERE ns = ?) OR EXISTS (SELECT 1 FROM filtered_views WHERE ns = ?)`, n.name, n.name).Scan(&any))
	if any {
		t.tags = append(t.tags, "ns:"+n.name)
	}
}

// headReadable is the read check of the head URL of name in n for a
// reader judged per revision (readsByDoc): the head's own read envelope
// (§C.2 item 5), or, for a purged resource or namespace, purgedReadable.
func (t *tx) headReadable(a *actor, n *nsRow, name string) bool {
	if n.purged {
		return t.purgedReadable(a, n, name)
	}
	v := t.resolve(n, name, nil)
	if v.state == Purged {
		return t.purgedReadable(a, n, name)
	}
	return t.mayReadRow(a, n, name, v.head)
}

// sealedBlobReadable is the read check of a sealed blob's epoch URL for a
// reader judged per revision: a purged namespace's or resource's with its
// rules on /doc set aside (purgedReadable), a sealed namespace's by the
// revisions of the epoch asked (v0.89), any other with a null document.
func (t *tx) sealedBlobReadable(a *actor, n *nsRow, name string) bool {
	if n.purged || t.resolve(n, name, nil).state == Purged {
		return t.purgedReadable(a, n, name)
	}
	if t.isSealedNS(n) {
		return true // judged per revision of the epoch asked (v0.89)
	}
	return t.mayReadRow(a, n, name, nil)
}
