package core

// Step 6 for resource writes in end-to-end namespaces (§6.2, §E.3.2).

// sealedUnknown are the envelope members the server can't see for a
// sealed create, append or restore at E3: its writes, which the envelope
// gives as [], and the resulting document, given as null (§6.2, §6.4.1).
var sealedUnknown = []string{"writes", "doc"}

// e2eDeleteUnknown is what it can't see for a delete there: the document
// deleted, given as null. A delete's writes are [] at every level, so
// rules on them are decided as usual (§6.2, §6.4.1).
var e2eDeleteUnknown = []string{"doc"}

// stepUnknown is the envelope members step 6 can't see for a step of a
// resource write checked against cfg, nil for none: a namespace, grant,
// key or role rule whose outcome depends on them fails as a whole, 422 or
// 403, and one that passes, or fails, whatever they hold is decided as
// usual (§6.2 End-to-end namespaces, rules.EvalTri). The keyring is
// plaintext and checked as usual (§E.3.2), and so are config, branch and
// prune writes, which don't come here.
func stepUnknown(cfg *Config, s *itemState, step *stepState) []string {
	switch {
	case step.sealed:
		return sealedUnknown
	case step.del && cfg.level == levelE2E && s.Resource != KeyringName:
		return e2eDeleteUnknown
	}
	return nil
}

const blindMsg = "the rule's outcome depends on writes or /doc, which the server can't see for this write in an e2e namespace, so it fails as a whole (§6.2, §E.3.2)"
