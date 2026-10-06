package core

// Author signatures at the gate (§C.3, §C.3.1).
//
// A write's revisions and tombstones may carry author signatures: the
// Signature header of a single write, a step object's "signature" in a
// batch (§7.5). Each is stored with its revision or tombstone (outside its
// id) and served in resource logs. A malformed one is 400, a request-shape
// error checked before step 1 (checkSignatureShapes).
//
// They are checked at §6.2 step 2.3: after authentication, authorisation
// and rate limits (step 1), after the idempotent-retry lookup, so a retry
// is answered with the entry as first recorded whatever well-formed
// signature it carries or lacks, even after "required" was turned on, and
// after the verb is settled, so authorisation failures (including a 403
// from settling the verb) are reported first. Then a signature whose kid
// the grant's root block lists in "signers" is verified, and a bad one is
// 422 "signature"; one with any other kid is stored unverified. A
// namespace whose configuration (the one the gate checks the write
// against: for a batch item, after the batch's config change) says
// "signatures": "required" refuses every revision and tombstone without a
// valid signature by a signer of its grant, with the same 422. A batch
// whose config change fails fails with it, so its items are never judged
// under another configuration.
//
// The signing input binds the revision's parent (§C.3). It needs no head:
// the precondition only passes when If-Match names the resource's head as
// the writer sees it (§7.2), which in a branch may be a revision its base
// wrote, so the parent a revision is written on is the If-Match id, a
// create's is nil, and each later step's is the id the step before it
// produces (§3.3, §3.4), exactly as expectedIDs computes them. Verifying
// with the If-Match id before the precondition comparison therefore checks
// the same input a successful write is stored with: a bad signature on a
// write whose precondition is stale is 422, not 412.
//
// A write without a usable precondition (no If-Match or If-None-Match, or
// a malformed If-Match) has no parent to bind, so its signatures can't be
// checked: they aren't, "required" included, and it gets the
// precondition's own error (428, or 400) at step 2.5 (§C.3.1 "The parent").

import (
	"fmt"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/sig"
)

// checkSignatureShapes answers 400 for a Signature header on a batch and
// for a signature that isn't "<alg>:<kid>:<sig>" with the sig in base64url
// without padding: request-shape errors, which come before step 1 (§6.2).
// It moves a single write's header onto its one step.
func checkSignatureShapes(req Request, items []Item, isBatch bool) *Error {
	if isBatch && req.Signature != "" {
		return badInput("a batch carries signatures in its step objects, not in a Signature header (§C.3.1)")
	}
	if !isBatch && req.Signature != "" && len(items) == 1 && len(items[0].Steps) == 1 {
		items[0].Steps[0].Signature = req.Signature
	}
	for i, it := range items {
		for j, st := range it.Steps {
			if st.Signature == "" {
				continue
			}
			if _, err := sig.Parse(st.Signature); err != nil {
				if !isBatch {
					return badInput("malformed Signature: " + err.Error())
				}
				return badInput(fmt.Sprintf("item %d, step %d: malformed signature: %v", i, j, err))
			}
		}
	}
	return nil
}

// signatureErr is the 422 of §C.3.1.
func signatureErr(msg string) *Error {
	return apiErr(422, "signature", "message", msg)
}

// checkSignatures is the signature check of §6.2 step 2.3 for the items
// still standing, against cfg, the configuration the write is checked
// against.
func (t *tx) checkSignatures(n *nsRow, cfg *Config, a *actor, st []*itemState) []itemErr {
	var signers []sig.Signer
	if a != nil && a.grant != nil && len(a.grant.Blocks) > 0 {
		signers = a.grant.Blocks[0].Signers
	}
	required := cfg.SignaturesRequired
	if !required && len(signers) == 0 {
		// Nothing to verify: every signature is stored unverified.
		return nil
	}
	var fs []itemErr
	for _, s := range st {
		if err := t.checkItemSignatures(n, s, signers, required); err != nil {
			fs = append(fs, itemErr{s.index, err})
		}
	}
	return fs
}

func (t *tx) checkItemSignatures(n *nsRow, s *itemState, signers []sig.Signer, required bool) *Error {
	where := func(j int) string {
		if len(s.Steps) == 1 {
			return ""
		}
		return fmt.Sprintf("step %d: ", j)
	}
	// The parent of the first step (see the package comment above).
	var parent *ids.ID
	switch {
	case s.IfMatch != "" && !s.IfNoneMatch:
		p, err := ids.Parse(s.IfMatch)
		if err != nil {
			return nil // malformed: step 2.5 answers it
		}
		parent = &p
	case s.IfNoneMatch && s.IfMatch == "":
	default:
		// No usable precondition: nothing to bind, and step 2.5
		// answers it (see the package comment above).
		return nil
	}
	origin := t.e.Origin()
	for j, step := range s.Steps {
		if step.Signature == "" {
			if required {
				return signatureErr(where(j) + "this namespace requires author signatures (§C.3.1)")
			}
		} else {
			sg, _ := sig.Parse(step.Signature) // shape checked before step 1 (§6.2)
			signer, listed := sig.Find(signers, sg.Kid)
			switch {
			case !listed && required:
				return signatureErr(where(j) + fmt.Sprintf("the grant lists no signer %q, and this namespace requires author signatures (§C.3.1)", sg.Kid))
			case listed:
				var body []byte // nil: a tombstone's input
				if !step.Delete {
					body = s.canon(j)
				}
				if step.Delete && parent == nil {
					// A delete of nothing: step 2 or 3 answers it.
					return nil
				}
				if !sig.Verify(signer, sg, sig.Digest(origin, n.name, s.Resource, parent, body)) {
					return signatureErr(where(j) + fmt.Sprintf("the signature by %q does not verify (§C.3.1)", sg.Kid))
				}
			}
		}
		var id ids.ID
		if step.Delete {
			if parent == nil {
				return nil
			}
			id = ids.Tombstone(*parent)
		} else {
			id = ids.Revision(parent, s.canon(j))
		}
		parent = &id
	}
	return nil
}
