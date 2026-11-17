package vectors_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
)

// VECTORS-PROPOSED.md C.5 (§G.4.1, v0.85; SPEC-FEEDBACK v0.82 Open 75): two
// changes to §I.20's bundle, each matched to the candidate's sha-256 and
// then rejected whole by the bundle Reader at the grant line, for the rule
// the candidate names: a grant line whose key has a kid other than
// root.kid, and one whose key doesn't verify the stored block (the pub of
// §I.21's ops-2027, seed 20 21 … 3f). Every other check of the two bundles
// still holds: only the key object changes.
func TestV085C5GrantLineKey(t *testing.T) {
	t.Parallel()
	ai := loadAddendumI(t)
	b := ai.I20.Bundle
	if d, err := readBundle(b); err != nil || d != ai.I20.Digest {
		t.Fatalf("§I.20's bundle, the control: %s %v", d, err)
	}
	const (
		key     = `"key":{"alg":"Ed25519","kid":"ops-2026","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}`
		kid2027 = `"key":{"alg":"Ed25519","kid":"ops-2027","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}`
		pub2027 = `"key":{"alg":"Ed25519","kid":"ops-2026","pub":"Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc"}`
	)
	ls := strings.SplitAfter(b, "\n")
	if strings.Count(b, key) != 1 || strings.Count(ls[1], key) != 1 {
		t.Fatalf("§I.20's grant line doesn't carry I.14's key once: %s", ls[1])
	}
	for _, c := range []struct {
		change, with, sha string
		msg               []string
	}{
		{"the grant line's key.kid is ops-2027", kid2027,
			"59dd09cd7d6913eaf8bfc58025bb02f5b27468b757ee351b64d90457ded62920", []string{`"ops-2027"`, "not its root's"}},
		{"the grant line's key.pub is that of §I.21's ops-2027", pub2027,
			"44e7aa12dfb273be81818819f8f53cefb404d031da212971847afd8bdd8b0910", []string{"doesn't verify its stored block"}},
	} {
		changed := strings.Replace(b, key, c.with, 1)
		if got := sha256Hex([]byte(changed)); got != c.sha {
			t.Errorf("%s: the bundle is sha-256 %s, want %s", c.change, got, c.sha)
			continue
		}
		d, err := readBundle(changed)
		var be *bundle.Error
		if err == nil || !errors.As(err, &be) {
			t.Errorf("%s: read with digest %s, %v; want rejected", c.change, d, err)
			continue
		}
		if be.Line != 2 {
			t.Errorf("%s: rejected at line %d (%v), want line 2", c.change, be.Line, err)
		}
		for _, m := range c.msg {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("%s: rejected with %q, which doesn't say %q", c.change, err, m)
			}
		}
	}
}
