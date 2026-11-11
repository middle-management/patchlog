package grant

import (
	"errors"
	"strings"
	"testing"
)

// v081Fact is a Block's one fact grant_block(<symbol str>), the predicate
// named by symbol name.
func v081Fact(name, str uint64) []byte {
	pred := pbBytes(pbUint(nil, 1, name), 2, pbUint(nil, 3, str))
	return pbBytes(nil, 4, pbBytes(nil, 1, pred))
}

// BYTES (§C.8, v0.81 "a Biscuit symbol is unused per block"): a symbol a
// block adds to the table must be used by that block's own fact, judged
// per block: one an earlier block adds and only a later block uses is
// refused at the block that adds it, as §I.21's (v0.81's P.7) token with
// the narrowing block's string added by the authority block. A symbol an
// earlier block adds and uses itself may be used again by a later one
// (grant_block, in every token).
func TestV081SymbolUnusedPerBlock(t *testing.T) {
	root := `{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}`
	narrow := `{"can":["read"],"via":"svc:reader"}`

	// The control: each block adds the symbols its own fact uses.
	b0, syms := encodeBlockData(root, nil)
	b1, _ := encodeBlockData(narrow, syms)
	c := &container{blocks: []signedBlock{{data: b0}, {data: b1}}}
	if got, _, err := c.blockStrings(); err != nil || len(got) != 2 || got[1] != narrow {
		t.Fatalf("the control: %q %v", got, err)
	}

	// The authority block adds narrow as symbol 1026, which only the
	// narrowing block's fact uses; that block adds no symbol.
	b0 = nil
	for _, s := range []string{factName, root, narrow} {
		b0 = pbBytes(b0, 1, []byte(s))
	}
	b0 = append(pbUint(b0, 3, blockVersion), v081Fact(symbolOffset, symbolOffset+1)...)
	b1 = append(pbUint(nil, 3, blockVersion), v081Fact(symbolOffset, symbolOffset+2)...)
	c = &container{blocks: []signedBlock{{data: b0}, {data: b1}}}
	if got, _, err := c.blockStrings(); err == nil || !strings.Contains(err.Error(), "block 0: unused symbol") {
		t.Fatalf("a symbol the authority block adds for a later block: %q %v, want block 0 refused (unused symbol)", got, err)
	}

	// The same through a bearer (§I.21, v0.81's P.7): 401.
	const tok = "ErwCCs8BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91" +
		"cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9" +
		"CiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIEIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2h" +
		"QE7hBmypVZ0aQNLkziAVYiQ9Kse5KI3wTLTk0O9IqxEkkhj9-2QHU9jXtI9A0cT45WdWauYECQwPCzvRBwIoL7ThM9ai-xXOYAQoARp6Cg4Y" +
		"AyIKCggIgAgSAxiCCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5W31DpjSCmT_VGkD073dRSsrJFv-DLYHazlyPesuHGJFEdxAHBaIV" +
		"06Hmnpl9XshSYxTVZk1dqUF9DfIZns-MgOJZ5I6NqFMOLrENKAEiIgogYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8"
	_, err := DecodeLimited(tok, Limits{})
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != 401 || !strings.Contains(err.Error(), "unused symbol") {
		t.Fatalf("P.7's token: %v, want 401 unused symbol", err)
	}
}
