package core

// Author signatures at the gate (§C.3, §C.3.1).
//
// A write's revisions and tombstones may carry author signatures: the
// Signature header of a single write, a step object's "signature" in a
// batch (§7.5). Each is stored with its revision or tombstone (outside its
// id) and served in resource logs. At the end of §6.2 step 1, after
// authentication and authorisation and before rate limits, every write
// that passed is checked: a signature whose kid the grant's root block
// lists in "signers" is verified, and a bad one is 422 "signature"; one
// with any other kid is stored unverified. A namespace whose configuration
// (the one the gate checks the write against: for a batch item, after the
// batch's config change) says "signatures": "required" refuses every
// revision and tombstone without a valid signature by a signer of its
// grant, with the same 422.
//
// The signing input binds the revision's parent (§C.3). It is known from
// the request: the step 2 precondition only passes when If-Match names the
// resource's head as the writer sees it (§7.2), which in a branch may be a
// revision its base wrote, so the parent a revision is written on is the
// If-Match id, a create's is nil, and each later step's is the id the step
// before it produces (§3.3, §3.4), exactly as expectedIDs computes them.
// Verifying with the If-Match id at step 1 therefore checks the same input
// a successful write is stored with, and keeps the order of §6.2: a bad
// signature on a write whose precondition is stale is 422, not 412.
//
// Deviations, where step 1 can't know the parent:
//
//   - A write without If-Match or If-None-Match is 428 at step 2. Its
//     signatures can't be verified (there is no parent to bind), so they
//     aren't, and it fails with 428; a missing signature where one is
//     required is still 422 here.
//   - A malformed If-Match is a request-shape error (400) that this
//     implementation answers at step 2; its signatures aren't verified
//     here either, so it gets that 400.

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

// checkSignatures is the signature check at the end of §6.2 step 1 for
// the items that passed authorisation, against cfg, the configuration the
// write is checked against. honourRequired false skips the "required" rule
// (verifying listed kids only), for the replay lookup of a batch whose
// config change no longer applies.
func (t *tx) checkSignatures(n *nsRow, cfg *Config, a *actor, st []*itemState, honourRequired bool) []itemErr {
	var signers []sig.Signer
	if a != nil && a.grant != nil && len(a.grant.Blocks) > 0 {
		signers = a.grant.Blocks[0].Signers
	}
	required := honourRequired && cfg.SignaturesRequired
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
	known := true
	switch {
	case s.IfMatch != "" && !s.IfNoneMatch:
		p, err := ids.Parse(s.IfMatch)
		if err != nil {
			known = false
		} else {
			parent = &p
		}
	case s.IfNoneMatch && s.IfMatch == "":
	default:
		known = false
	}
	origin := t.e.Origin()
	for j, step := range s.Steps {
		if step.Signature == "" {
			if required {
				return signatureErr(where(j) + "this namespace requires author signatures (§C.3.1)")
			}
		} else {
			sg, _ := sig.Parse(step.Signature) // shape checked before step 1
			signer, listed := sig.Find(signers, sg.Kid)
			switch {
			case !listed && required:
				return signatureErr(where(j) + fmt.Sprintf("the grant lists no signer %q, and this namespace requires author signatures (§C.3.1)", sg.Kid))
			case listed && known:
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
		if !known {
			continue
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
