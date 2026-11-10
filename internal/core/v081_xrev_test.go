package core

import (
	"strings"
	"testing"
)

// The start gate's refusal and the raise's 422 don't send an operator down
// an import no reference tool performs: the bundle importer takes an e2e
// namespace only under its own name and no plaintext into one (§G.5.1's
// re-sealing import is a key holder's MAY). They say so, and name what is
// left: a key holder re-sealing the content into a new e2e namespace, or
// -purge-raised-e2e, which destroys it.
func TestV081XrevLegacyE2EAdvice(t *testing.T) {
	t.Parallel()
	gate := errLegacyE2E(&legacyE2E{raised: []string{"e"}}).Error()
	raise := (&tx{e: &Engine{}}).checkNoE2ERaise(&Config{level: levelSealed}, &Config{level: levelE2E})
	if raise == nil {
		t.Fatal("a raise to e2e was accepted")
	}
	msg, _ := raise.Body["message"].(string)
	for what, s := range map[string]string{"start gate": gate, "raise": msg} {
		if strings.Contains(s, "import it into a new e2e namespace") || strings.Contains(s, "have a key holder import it") {
			t.Errorf("%s names an import no reference tool performs: %s", what, s)
		}
		if !strings.Contains(s, "no reference") {
			t.Errorf("%s doesn't say no reference tool does it: %s", what, s)
		}
	}
	if !strings.Contains(gate, "-purge-raised-e2e") || !strings.Contains(gate, "content") {
		t.Errorf("start gate: %s", gate)
	}
}
