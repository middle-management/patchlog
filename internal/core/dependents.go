package core

import "sort"

// A refusal's dependents (§6.1 Refusals, §7.4, §8.5 item 4, v0.88): an
// in_use answer lists them as it lists referencing, the dependents in
// which the caller may read anything, judged as for reading other
// namespaces (§7.5), with the request's grant or any in
// Source-Authorization (credsReadAny): the first logPageSize in byte
// order of name, with "more": true where it may read others. So more
// never tells a caller that dependents it can't read exist, and one who
// may read none gets [] without it, though the write is still refused.
// The list's judgments share one budget of validationSteps (§6.6
// Validation work): where it runs out the list ends there, without more.

// dependentsInUse is the 409 in_use for the dependents names lists, nil
// if there are none; msg, if not "", is its message.
func (t *tx) dependentsInUse(names []string, msg string) *Error {
	if len(names) == 0 {
		return nil
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	i := 0
	return t.dependentsRefusal(func() (*nsRow, bool) {
		for i < len(sorted) {
			b := t.nsByName(sorted[i])
			i++
			if b != nil {
				return b, true
			}
		}
		return nil, false
	}, msg)
}

// dependentsRefusal is dependentsInUse over next, which yields the
// dependents in byte order of name, at least one.
func (t *tx) dependentsRefusal(next func() (*nsRow, bool), msg string) *Error {
	defer t.readScope()()
	limit := t.e.opt.Maximums.LogPageSize
	listed := []string{}
	more := false
	for {
		b, ok := next()
		if !ok || t.readSpent() {
			break
		}
		if !t.credsReadAny(b, t.reqCreds) {
			continue
		}
		if t.readSpent() {
			// The judgment ran out: the list ends before it (§6.6).
			break
		}
		if len(listed) == limit {
			more = true
			break
		}
		listed = append(listed, b.name)
	}
	e := apiErr(409, "in_use", "dependents", anyStrings(listed))
	if msg != "" {
		e.Body["message"] = msg
	}
	if more {
		e.Body["more"] = true
	}
	return e
}

// branchDependents yields n's direct branches that aren't purged, in
// byte order of name, a page at a time (branchesAfter), for
// dependentsRefusal.
func (t *tx) branchDependents(n *nsRow) func() (*nsRow, bool) {
	var page []*nsRow
	after, done := "", false
	return func() (*nsRow, bool) {
		if len(page) == 0 && !done {
			page = t.branchesAfter(n, after, true, 256)
			done = len(page) < 256
			if len(page) > 0 {
				after = page[len(page)-1].name
			}
		}
		if len(page) == 0 {
			return nil, false
		}
		b := page[0]
		page = page[1:]
		return b, true
	}
}
