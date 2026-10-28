package schema

import (
	"errors"
	"testing"
)

// markedStore holds a revision stored before the upgrade (legacyPath,
// Legacy) and one written since (writtenPath, V073) that $refs it, and a
// Legacy root that $refs the V073 one, each naming only formats draft
// 2020-12 defines, and the markers their rows carry (§6.1). Since v0.74
// the markers select nothing: every schema compiles under this version.
type markedStore struct {
	*store
	rules map[string]Rules
	asked int // times rulesOf was called
}

var (
	legacyPath  = "/r/schemas/old/rev/" + rev('l')
	writtenPath = "/r/schemas/new/rev/" + rev('w')
	// A Legacy revision that $refs a V073 one, as a revision mirrored
	// from a deployment (no marker known) may.
	legacyRootPath = "/r/schemas/oldroot/rev/" + rev('o')
)

const markedProps = `"e":{"format":"idn-email"},"h":{"format":"idn-hostname"},"r":{"format":"regex"}`

func newMarkedStore() *markedStore {
	s := newStore()
	s.docs[legacyPath] = j(`{` + d073 + `,"type":"object","properties":{` + markedProps + `}}`)
	s.docs[writtenPath] = j(`{` + d073 + `,"type":"object","properties":{"old":{"$ref":"` + legacyPath + `"},` + markedProps + `}}`)
	s.docs[legacyRootPath] = j(`{` + d073 + `,"type":"object","properties":{"new":{"$ref":"` + writtenPath + `"},` + markedProps + `}}`)
	return &markedStore{store: s, rules: map[string]Rules{legacyPath: Legacy, writtenPath: V073, legacyRootPath: Legacy}}
}

func (s *markedStore) rulesOf(r Ref) Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	return s.rules[r.Path()]
}

// Values v0.73 read differently under the two markers: Legacy ignored
// idn-* and compiled a lone surrogate escape in a regex; V073 refuses
// them all, as every revision now does (§6.1, §6.6).
var markedBad = map[string]string{
	"e": "not an email",
	"h": "ex ample.com",
	"r": `^a\x{D800}$`,
}

// CIS-17 as v0.74 has it (§6.1: every schema compiles under this
// version): each revision of a typed document's $ref closure compiles
// under today's rules, wherever it is reached from and whatever marker
// its row carries, so a Legacy revision asserts idn-* and reads regex as
// §6.6 says, named directly or through a V073 schema. ValidateMarked
// never asks for markers.
func TestV073MarkedClosureFormats(t *testing.T) {
	s := newMarkedStore()
	v := NewValidator()
	check := func(root string, path []string, member string) {
		t.Helper()
		var inst any = map[string]any{member: markedBad[member]}
		for i := len(path) - 1; i >= 0; i-- {
			inst = map[string]any{path[i]: inst}
		}
		doc := inst.(map[string]any)
		doc["$schema"] = root
		for _, rules := range []Rules{Legacy, V073} {
			err := v.ValidateMarked(doc, s.load, rules, s.rulesOf)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("%s %v %s %q (%v): got %v, want a refusal", root, path, member, markedBad[member], rules, err)
			}
			if err := v.ValidateRules(doc, s.load, rules); !errors.As(err, &ve) {
				t.Errorf("ValidateRules %s %v %s (%v): got %v, want a refusal", root, path, member, rules, err)
			}
		}
	}
	for member := range markedBad {
		check(legacyPath, nil, member)
		check(writtenPath, []string{"old"}, member)
		check(writtenPath, nil, member)
		check(legacyRootPath, []string{"new"}, member)
		check(legacyRootPath, []string{"new", "old"}, member)
		check(legacyRootPath, nil, member)
	}
	if s.asked != 0 {
		t.Errorf("rulesOf asked %d times", s.asked)
	}
}

// A schema written now that $refs a revision stored with a pattern RE2
// took as written though §6.6's translation refuses it is invalid, and so
// is every document typed by a schema whose closure holds it: the stored
// revision compiles under this version too (§6.1, §6.6).
func TestV073MarkedClosureStoredPattern(t *testing.T) {
	s := newMarkedStore()
	s.docs[legacyPath] = j(`{` + d073 + `,"type":"object","properties":{"pat":{"pattern":"^a\\x{D800}?$"}}}`)
	v := NewValidator()
	if err := v.Validate(s.docs[writtenPath], s.load); !isInvalid(err) {
		t.Errorf("the V073 schema's write: got %v, want invalid", err)
	}
	for _, doc := range []map[string]any{
		{"$schema": writtenPath, "old": map[string]any{"pat": "a"}},
		{"$schema": legacyRootPath, "new": map[string]any{"old": map[string]any{"pat": "a"}}},
		{"$schema": legacyPath, "pat": "a"},
	} {
		if err := v.ValidateMarked(doc, s.load, V073, s.rulesOf); !isSchemaErr(err) {
			t.Errorf("%v: got %v, want SchemaError", doc, err)
		}
	}
}

// A compiled schema is kept by path alone, whatever markers rulesOf gives
// (§6.1 "Validator cache"): a change of marker compiles nothing again.
func TestV073MarkedCacheFollowsMarkers(t *testing.T) {
	s := newMarkedStore()
	v := NewValidator()
	doc := map[string]any{"$schema": writtenPath, "old": map[string]any{"e": "a@example.com"}}
	if err := v.ValidateMarked(doc, s.load, V073, s.rulesOf); err != nil {
		t.Fatal(err)
	}
	a, ok := v.compiled.Get(writtenPath)
	if !ok {
		t.Fatal("not cached by path")
	}
	s.mu.Lock()
	s.rules[legacyPath] = V073
	s.mu.Unlock()
	if err := v.ValidateMarked(doc, s.load, Legacy, s.rulesOf); err != nil {
		t.Fatal(err)
	}
	if b, _ := v.compiled.Get(writtenPath); b != a {
		t.Error("compiled again for another marker")
	}
	if s.calls[legacyPath] != 1 || s.calls[writtenPath] != 1 {
		t.Errorf("loaded %v", s.calls)
	}
}
