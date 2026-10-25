package schema

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// markedStore holds a revision stored before the upgrade (legacyPath,
// Legacy) and one written since (writtenPath, V073) that $refs it, naming
// the formats the markers read differently (§6.1, §6.2 step 5): the five,
// in the Legacy revisions; idn-email, idn-hostname and regex in the V073
// one, as semver and period make a schema written now invalid. And their
// markers.
type markedStore struct {
	*store
	rules map[string]Rules
}

var (
	legacyPath  = "/r/schemas/old/rev/" + rev('l')
	writtenPath = "/r/schemas/new/rev/" + rev('w')
	// A Legacy revision that $refs a V073 one, as a revision mirrored
	// from a deployment (no marker known) may.
	legacyRootPath = "/r/schemas/oldroot/rev/" + rev('o')
)

const (
	writtenProps = `"e":{"format":"idn-email"},"h":{"format":"idn-hostname"},"r":{"format":"regex"}`
	markedProps  = `"v":{"format":"semver"},"p":{"format":"period"},` + writtenProps
)

func newMarkedStore() *markedStore {
	s := newStore()
	s.docs[legacyPath] = j(`{` + d073 + `,"type":"object","properties":{` + markedProps + `,"pat":{"pattern":"^a\\x{D800}?$"}}}`)
	s.docs[writtenPath] = j(`{` + d073 + `,"type":"object","properties":{"old":{"$ref":"` + legacyPath + `"},` + writtenProps + `}}`)
	s.docs[legacyRootPath] = j(`{` + d073 + `,"type":"object","properties":{"new":{"$ref":"` + writtenPath + `"},` + markedProps + `}}`)
	return &markedStore{store: s, rules: map[string]Rules{legacyPath: Legacy, writtenPath: V073, legacyRootPath: Legacy}}
}

func (s *markedStore) rulesOf(r Ref) Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rules[r.Path()]
}

// Values each marker reads differently: Legacy asserts semver and period
// and reads regex as v0.55 did (a lone surrogate escape compiles), and
// ignores idn-*; V073 the reverse (§6.1, §6.6).
var markedBad = map[string]string{
	"v": "not a version",
	"p": "not a period",
	"e": "not an email",
	"h": "ex ample.com",
	"r": `^a\x{D800}$`,
}

func legacyRefuses(member string) bool { return member == "v" || member == "p" }

// CIS-17, §6.1 "A schema stored under an earlier version is compiled as
// that version did": each revision of a typed document's $ref closure
// compiles under its own marker, wherever it is reached from. A Legacy
// revision reached through the $ref of a V073 schema asserts semver and
// period and ignores idn-*, as it does when named directly; the V073
// schema's own formats are V073's; and the converse.
func TestV073MarkedClosureFormats(t *testing.T) {
	s := newMarkedStore()
	v := NewValidator()
	check := func(root string, path []string, member string, wantOK bool) {
		t.Helper()
		var inst any = map[string]any{member: markedBad[member]}
		for i := len(path) - 1; i >= 0; i-- {
			inst = map[string]any{path[i]: inst}
		}
		doc := inst.(map[string]any)
		doc["$schema"] = root
		err := v.ValidateMarked(doc, s.load, V073, s.rulesOf)
		var ve *ValidationError
		if wantOK && err != nil || !wantOK && !errors.As(err, &ve) {
			t.Errorf("%s %v %s %q: got %v, want ok %v", root, path, member, markedBad[member], err, wantOK)
		}
	}
	for member := range markedBad {
		legacyOK := !legacyRefuses(member)
		// The Legacy revision, named directly and through the V073 one.
		check(legacyPath, nil, member, legacyOK)
		check(writtenPath, []string{"old"}, member, legacyOK)
		// The V073 revision's own, named directly and through the Legacy
		// root.
		if !legacyRefuses(member) {
			check(writtenPath, nil, member, false)
			check(legacyRootPath, []string{"new"}, member, false)
		}
		// And back again: the Legacy revision through both.
		check(legacyRootPath, []string{"new", "old"}, member, legacyOK)
		check(legacyRootPath, nil, member, legacyOK)
	}
	// ValidateRules still compiles a whole closure under one marker: under
	// Legacy, the V073 revision's idn-email too.
	if err := v.ValidateRules(map[string]any{"$schema": writtenPath, "e": "not an email"}, s.load, Legacy); err != nil {
		t.Errorf("ValidateRules Legacy: %v", err)
	}
}

// CIS-17 regression (P03's TestV073WriteRefsStoredPattern): a schema
// written now may $ref a revision stored before the upgrade with a pattern
// RE2 took as written though §6.6's translation refuses it, and documents
// typed by that schema validate, the stored pattern applied as v0.55 did.
// Compiled under the root's V073 marker, every one was refused ("lone
// surrogate").
func TestV073MarkedClosureStoredPattern(t *testing.T) {
	s := newMarkedStore()
	v := NewValidator()
	if err := v.Validate(s.docs[writtenPath], s.load); err != nil {
		t.Fatalf("the V073 schema's write: %v", err)
	}
	for _, c := range []struct {
		doc map[string]any
		ok  bool
	}{
		{map[string]any{"$schema": writtenPath, "old": map[string]any{"pat": "a"}}, true},
		{map[string]any{"$schema": writtenPath, "old": map[string]any{"pat": "b"}}, false},
		{map[string]any{"$schema": legacyRootPath, "new": map[string]any{"old": map[string]any{"pat": "a"}}}, true},
		{map[string]any{"$schema": legacyPath, "pat": "a"}, true},
	} {
		err := v.ValidateMarked(c.doc, s.load, V073, s.rulesOf)
		var ve *ValidationError
		if c.ok && err != nil || !c.ok && !errors.As(err, &ve) {
			t.Errorf("%v: got %v, want ok %v", c.doc, err, c.ok)
		}
	}
}

// A compiled schema is kept by path while each revision of its closure
// keeps the marker it compiled under, and compiles again when one changes
// (a namespace purged and made again, resolving the path to another row).
func TestV073MarkedCacheFollowsMarkers(t *testing.T) {
	s := newMarkedStore()
	v := NewValidator()
	ref, _ := ParseRef(writtenPath)
	a, err := v.compileMarked(ref, s.load, s.rulesOf)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := v.compileMarked(ref, s.load, s.rulesOf); err != nil || b != a {
		t.Errorf("same markers: compiled again (%v)", err)
	}
	m, _ := v.marked.Get(writtenPath)
	if got, want := len(m.closure), 2; got != want {
		t.Errorf("closure %v, want %d revisions", m.closure, want)
	}
	doc := map[string]any{"$schema": writtenPath, "old": map[string]any{"v": "not a version"}}
	if err := v.ValidateMarked(doc, s.load, V073, s.rulesOf); err == nil {
		t.Fatal("Legacy revision: semver not asserted")
	}
	s.mu.Lock()
	s.rules[legacyPath] = V073
	s.mu.Unlock()
	if c, err := v.compileMarked(ref, s.load, s.rulesOf); err != nil || c == a {
		t.Errorf("marker changed: not compiled again (%v)", err)
	}
	if err := v.ValidateMarked(doc, s.load, V073, s.rulesOf); err != nil {
		t.Errorf("revision now V073: %v", err)
	}
}

// markFormats renames only format keywords of subschemas, never instance
// data or names, and leaves the document it is given as it was; messages
// name the format as the schema writes it. A member named format whose
// value is an object is a subschema like any other member's object.
func TestV073MarkFormatsScope(t *testing.T) {
	doc := j(`{` + d073 + `,
		"properties":{"format":{"format":"semver"},"x":{"const":{"format":"semver"},"enum":[{"format":"period"}],
			"default":{"format":"semver"},"examples":[{"format":"semver"}]}},
		"$defs":{"d":{"items":{"format":"idn-email"}}},
		"allOf":[{"format":"regex"}],
		"x-defs":{"format":{"format":"period"}},
		"format":"date-time"}`)
	before := jsonv.Clone(doc)
	out := markFormats(doc, Legacy).(map[string]any)
	if !reflect.DeepEqual(doc, before) {
		t.Fatal("markFormats modified its input")
	}
	props := out["properties"].(map[string]any)
	if _, ok := props["format"]; !ok {
		t.Error("a property named format was renamed")
	}
	if got := props["format"].(map[string]any)["format"]; got != markedFormatName(Legacy, "semver") {
		t.Errorf("properties/format/format = %q", got)
	}
	if !reflect.DeepEqual(props["x"], before.(map[string]any)["properties"].(map[string]any)["x"]) {
		t.Errorf("instance data renamed: %v", props["x"])
	}
	if got := out["$defs"].(map[string]any)["d"].(map[string]any)["items"].(map[string]any)["format"]; got != markedFormatName(Legacy, "idn-email") {
		t.Errorf("$defs/d/items/format = %q", got)
	}
	if got := out["allOf"].([]any)[0].(map[string]any)["format"]; got != markedFormatName(Legacy, "regex") {
		t.Errorf("allOf/0/format = %q", got)
	}
	// A member named format holding an object, as in a map of subschemas
	// a JSON Pointer may reach, is a subschema too.
	if got := out["x-defs"].(map[string]any)["format"].(map[string]any)["format"]; got != markedFormatName(Legacy, "period") {
		t.Errorf("x-defs/format/format = %q", got)
	}
	if out["format"] != "date-time" {
		t.Errorf("a format both markers read alike was renamed: %q", out["format"])
	}
	for _, r := range []Rules{Legacy, V073} {
		for f := range markerFormats {
			if got := writtenFormat(markedFormatName(r, f)); got != f {
				t.Errorf("writtenFormat(%v, %s) = %q", r, f, got)
			}
		}
	}

	s := newMarkedStore()
	err := NewValidator().ValidateMarked(map[string]any{"$schema": legacyPath, "v": "not a version"}, s.load, V073, s.rulesOf)
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Errors) != 1 {
		t.Fatalf("got %v", err)
	}
	if msg := ve.Errors[0].Message; !strings.Contains(msg, "valid semver") || strings.Contains(msg, markedPrefix) {
		t.Errorf("message %q doesn't name the format as written", msg)
	}
}
