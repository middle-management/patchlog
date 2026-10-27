package core

import (
	"testing"

	"github.com/middle-management/patchlog/internal/keystore"
)

// v0.73 Addendum E, Branches and dependents (ENC-48): a branch is at least
// at its base's level, and e2e only over an e2e base, which its creation
// and a raise to e2e are checked against; other config writes don't check
// it. The refusals are 422 invalid with errors at /encryption (§7.4).
func TestV073P16BaseLevelAtCreationAndE2E(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	tx := &gate{checkState: &checkState{e: &Engine{opt: Options{KeyStore: ks}}}}
	cfg := func(s string) *Config {
		t.Helper()
		c, err := parseConfig(v073Doc(s), DefaultLimits(), DefaultMaximums())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	none, atRest, e2e := cfg(`{}`), cfg(`{"encryption": {"level": "at-rest"}}`), cfg(`{"encryption": {"level": "e2e"}}`)
	refused := func(name string, err *Error) {
		t.Helper()
		if err == nil || err.Status != 422 || err.Body["code"] != "invalid" {
			t.Fatalf("%s: %v, want 422 invalid", name, err)
		}
		errs, _ := err.Body["errors"].([]any)
		if len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/encryption" {
			t.Fatalf("%s: errors %v, want one at /encryption", name, err.Body)
		}
	}
	refused("creation below the base", tx.checkEncryption(nil, atRest, levelSealed))
	refused("e2e creation over a sealed base", tx.checkEncryption(nil, e2e, levelSealed))
	refused("a raise to e2e over a sealed base", tx.checkEncryption(atRest, e2e, levelSealed))
	for name, c := range map[string][2]*Config{
		"a config write below the base": {atRest, atRest},
		"a raise that stays below it":   {none, atRest},
	} {
		if err := tx.checkEncryption(c[0], c[1], levelSealed); err != nil {
			t.Errorf("%s: %v", name, err.Body)
		}
	}
	if err := tx.checkEncryption(nil, e2e, levelE2E); err != nil {
		t.Errorf("e2e creation over an e2e base: %v", err.Body)
	}
}
