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
