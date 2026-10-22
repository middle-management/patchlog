package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
)

// CIS-21 (§6.4.2, F-S3 default): rules written in a namespace document, in
// rules, roles and key scopes, hold their schema fragments to the fragment
// rules (422 invalid); a stored document compiles them as stored, and a
// write that keeps such a rule unchanged, such as a freeze, isn't refused
// for it.
func TestV073P20NamespaceRuleFragments(t *testing.T) {
	t.Parallel()
	pub, _ := grant.GenerateKey()
	frag := `{"op": "test", "path": "/doc/v", "schema": {"format": "semver"}}`
	docs := map[string]string{
		"rules": `{"rules": [{"if": [{"op": "test", "path": "/action", "value": "create"}], "then": [` + frag + `]}]}`,
		"roles": `{"roles": {"ed": {"can": ["read"], "rules": [` + frag + `]}}}`,
		"keys":  `{"keys": [{"kid": "k", "alg": "Ed25519", "pub": "` + pub + `", "can": ["read"], "rules": [` + frag + `]}]}`,
	}
	for name, s := range docs {
		doc := v073Doc(s)
		_, err := parseConfigIn(doc, DefaultLimits(), DefaultMaximums(), configMode{})
		if err == nil || !strings.HasPrefix(err.Error(), "/"+name) || !strings.Contains(err.Error(), "semver") {
			t.Errorf("%s: a written fragment with format semver: %v", name, err)
		} else if e := configErr(err); e.Status != 422 || e.Body["code"] != "invalid" {
			t.Errorf("%s: %d %v", name, e.Status, e.Body)
		}
		if _, err := parseConfigIn(doc, DefaultLimits(), DefaultMaximums(), configMode{stored: true}); err != nil {
			t.Errorf("%s: stored: %v", name, err)
		}
		// A write keeping it: here a freeze.
		frozen := v073Doc(s)
		frozen["frozen"] = true
		if _, err := parseConfigIn(frozen, DefaultLimits(), DefaultMaximums(), configMode{prev: doc}); err != nil {
			t.Errorf("%s: a freeze keeping the rule: %v", name, err)
		}
	}
	// A kept rule moved between rules, roles and key scopes is still one
	// the document held; a changed rule is written now.
	moved := v073Doc(`{"roles": {"ed": {"can": ["read"], "rules": [` + frag + `]}}}`)
	if _, err := parseConfigIn(moved, DefaultLimits(), DefaultMaximums(), configMode{prev: v073Doc(`{"rules": [` + frag + `]}`)}); err != nil {
		t.Errorf("a kept rule moved into a role: %v", err)
	}
	changed := v073Doc(`{"rules": [{"op": "test", "path": "/doc/w", "schema": {"format": "semver"}}]}`)
	if _, err := parseConfigIn(changed, DefaultLimits(), DefaultMaximums(), configMode{prev: v073Doc(`{"rules": [` + frag + `]}`)}); err == nil {
		t.Error("a changed rule was compiled as stored")
	}
	// Each refused form of §6.4.2, and accepted ones.
	for _, s := range []string{`{"$id": "x"}`, `{"$schema": "https://json-schema.org/draft/2020-12/schema"}`,
		`{"foo": 1}`, `{"format": "nope"}`, `{"$ref": "/r/s/t/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, `{"pattern": "\\ud800"}`} {
		doc := v073Doc(`{"rules": [{"op": "test", "path": "/doc", "schema": ` + s + `}]}`)
		if _, err := parseConfigIn(doc, DefaultLimits(), DefaultMaximums(), configMode{}); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
	for _, s := range []string{`{"pattern": "^\\u00e9"}`, `{"definitions": {"a": {}}, "$ref": "#/definitions/a"}`, `{"format": "idn-hostname"}`} {
		doc := v073Doc(`{"rules": [{"op": "test", "path": "/doc", "schema": ` + s + `}]}`)
		if _, err := parseConfigIn(doc, DefaultLimits(), DefaultMaximums(), configMode{}); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// CIS-16, CIS-21 (§C.4, §6.6): a key entry a write sets holds its sub to
// RE2 as §6.6 reads it and its attrs to the fragment rules (422 invalid
// at the field); an entry the write keeps unchanged is kept.
func TestV073P20KeyEntryFields(t *testing.T) {
	t.Parallel()
	pub, _ := grant.GenerateKey()
	entry := func(field string) string {
		return `{"keys": [{"kid": "k", "alg": "Ed25519", "pub": "` + pub + `", "can": ["read"], ` + field + `}]}`
	}
	// A lone \u surrogate RE2 never took: invalid wherever it is.
	lone := v073Doc(entry(`"sub": "user:\\ud800"`))
	if _, err := parseConfigIn(lone, DefaultLimits(), DefaultMaximums(), configMode{stored: true}); err == nil || !strings.Contains(err.Error(), "sub") {
		t.Errorf("a sub with \\ud800: %v", err)
	}
	// RE2 took these as written: a stored document keeps them, a write
	// that sets them is refused at the field.
	for _, x := range []struct{ field, ptr string }{
		{`"sub": "user:\\x{D800}"`, "/keys/0/sub"},
		{`"sub": "[\\x{DC00}-\\x{DFFF}]"`, "/keys/0/sub"},
		{`"attrs": {"$id": "x"}`, "/keys/0/attrs"},
		{`"attrs": {"properties": {"r": {"format": "semver"}}}`, "/keys/0/attrs"},
	} {
		doc := v073Doc(entry(x.field))
		if _, err := parseConfigIn(doc, DefaultLimits(), DefaultMaximums(), configMode{}); err != nil {
			t.Errorf("%s: stored keys parse: %v", x.field, err)
			continue
		}
		err := checkMembers(doc, nil)
		var me *memberError
		if !errors.As(err, &me) || me.pointer != x.ptr {
			t.Errorf("%s: %v, want an error at %s", x.field, err, x.ptr)
		}
		if err := checkMembers(doc, doc); err != nil {
			t.Errorf("%s: kept: %v", x.field, err)
		}
	}
	doc := v073Doc(entry(`"sub": "user:\\u00e9.*", "attrs": {"properties": {"r": {"pattern": "^\\u00e9"}}}`))
	if err := checkMembers(doc, nil); err != nil {
		t.Fatal(err)
	}
	c, err := parseConfigIn(doc, DefaultLimits(), DefaultMaximums(), configMode{})
	if err != nil {
		t.Fatal(err)
	}
	if re := c.Keys[0].SubPattern; !re.MatchString("user:éva") || re.MatchString("user:eva") {
		t.Errorf("sub %s", re)
	}
}
