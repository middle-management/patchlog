package server

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// changeSchemaDoc has, above the members a patch changes, constraints that
// are no conjunction over members: a patch that is fine where it lands
// can break each of them.
func changeSchemaDoc() map[string]any {
	j := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	return j("$schema", "https://json-schema.org/draft/2020-12/schema",
		"type", "object",
		"required", []any{"title", "items"},
		"maxProperties", 6,
		"properties", j(
			"title", j("type", "string", "maxLength", 8),
			"items", j("type", "array", "uniqueItems", true, "maxItems", 5, "items", j("type", "integer", "minimum", 0)),
			"shape", j("oneOf", []any{
				j("type", "object", "required", []any{"circle"}, "properties", j("circle", j("type", "number"))),
				j("type", "object", "required", []any{"rect"}, "properties", j("rect", j("type", "number")))}),
			"meta", j("type", "object", "properties", j("a", j("type", "integer")), "unevaluatedProperties", false),
			"list", j("type", "array", "items", j("type", "object", "required", []any{"id"},
				"properties", j("id", j("type", "integer"), "tags", j("type", "array", "contains", j("const", "x")))))),
		"additionalProperties", j("type", "string"))
}

// validationPair is the same deployment twice: one validating patches by
// their changes, as by default, and one always in full. What the first
// answers must be what the second does.
type validationPair struct {
	t          *testing.T
	fast, full *tenv
	head       [2]string
}

func newValidationPair(t *testing.T, doc map[string]any) *validationPair {
	p := &validationPair{t: t, fast: newEnv(t), full: newEnv(t, func(o *core.Options) { o.FullValidation = true })}
	for i, e := range []*tenv{p.fast, p.full} {
		e.mkNS("s", map[string]any{})
		rev := e.create("s", "schema", changeSchemaDoc())
		typed := map[string]any{"$schema": "/r/s/schema/rev/" + rev}
		for k, v := range doc {
			typed[k] = v
		}
		p.head[i] = e.create("s", "doc", typed)
	}
	return p
}

// patch sends the patch to both and returns the status, having checked
// that the two answer alike: the same status and, for an invalid
// document, the same list of failures.
func (p *validationPair) patch(patches []any) int {
	p.t.Helper()
	var rs [2]*resp
	for i, e := range []*tenv{p.fast, p.full} {
		e.clock.Advance(1e9) // a second: past the per-resource rate
		rs[i] = e.write("PATCH", "s", "doc", p.head[i], patches)
		if rs[i].Code == 201 {
			p.head[i] = etagOf(rs[i])
		}
	}
	if rs[0].Code != rs[1].Code {
		p.t.Fatalf("patch %v: by changes %d %s, in full %d %s", patches, rs[0].Code, rs[0].Body, rs[1].Code, rs[1].Body)
	}
	if rs[0].Code != 201 && !reflect.DeepEqual(rs[0].Obj()["errors"], rs[1].Obj()["errors"]) {
		p.t.Fatalf("patch %v: failures differ:\n  by changes: %s\n  in full:    %s", patches, rs[0].Body, rs[1].Body)
	}
	return rs[0].Code
}

func (p *validationPair) counts() (full, change int64) { return p.fast.e.ValidationCounts() }

func baseDoc() map[string]any {
	return map[string]any{"title": "t", "items": []any{1, 2}, "shape": map[string]any{"circle": 1}, "meta": map[string]any{"a": 1},
		"list": []any{map[string]any{"id": 1, "tags": []any{"x"}}, map[string]any{"id": 2}}}
}

// A patch that is valid where it lands and breaks a constraint above it is
// refused, though only its changes are validated.
func TestValidationByChanges(t *testing.T) {
	t.Parallel()
	p := newValidationPair(t, baseDoc())
	f0, c0 := p.counts()
	for _, tc := range []struct {
		name    string
		patches []any
		want    int
	}{
		{"a valid replace", ops(op("replace", "/title", "u")), 201},
		{"deep in a list", ops(op("replace", "/list/1/id", 3)), 201},
		{"wrong where it lands", ops(op("replace", "/list/1/id", "three")), 422},
		{"maxProperties", ops(op("add", "/extra", "s"), op("add", "/more", "s")), 422},
		{"required", ops(op("remove", "/title")), 422},
		{"uniqueItems", ops(op("add", "/items/-", 2)), 422},
		{"maxItems", ops(op("add", "/items/0", 7), op("add", "/items/0", 8), op("add", "/items/0", 9), op("add", "/items/0", 10)), 422},
		{"oneOf above", ops(op("add", "/shape/rect", 2)), 422},
		{"unevaluatedProperties above", ops(op("add", "/meta/b", 1)), 422},
		{"contains above", ops(op("replace", "/list/0/tags/0", "y")), 422},
		{"required in a list item", ops(op("remove", "/list/0/id")), 422},
		{"an array shift", ops(op("remove", "/list/0")), 201},
		{"additionalProperties", ops(op("add", "/note", 5)), 422},
		{"a member added", ops(op("add", "/note", "n")), 201},
		{"a move away", []any{map[string]any{"op": "move", "from": "/shape/circle", "path": "/note"}}, 422},
		{"move the tag", []any{map[string]any{"op": "move", "from": "/shape/circle", "path": "/shape/rect"}}, 201},
	} {
		if got := p.patch(tc.patches); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
	f1, c1 := p.counts()
	// All by their changes but the removal of a top-level member, which
	// is a change to the root.
	if f1-f0 != 1 || c1-c0 != 15 {
		t.Errorf("validated %d in full and %d by changes, want 1 and 15", f1-f0, c1-c0)
	}
	if f, c := p.full.e.ValidationCounts(); c != 0 || f < 16 {
		t.Errorf("with FullValidation: %d in full, %d by changes", f, c)
	}
}

// Where the proof is missing, validation is in full: a create, a change
// of $schema, a restore, and the first patch after a restart, since what
// was validated is remembered in memory only.
func TestValidationInFull(t *testing.T) {
	t.Parallel()
	if pgtest.Enabled() {
		t.Skip("reopens a SQLite file")
	}
	path := filepath.Join(t.TempDir(), "v.db")
	open := func() *tenv { return newEnv(t, func(o *core.Options) { o.Path = path }) }
	e := open()
	e.mkNS("s", map[string]any{})
	s1 := e.create("s", "schema", changeSchemaDoc())
	loose := e.create("s", "loose", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})
	doc := baseDoc()
	doc["$schema"] = "/r/s/loose/rev/" + loose
	doc["title"] = "far too long a title" // valid against loose only
	head := e.create("s", "doc", doc)
	step := func(want int, wantFull, wantChange int64, patches []any) {
		t.Helper()
		f0, c0 := e.e.ValidationCounts()
		e.clock.Advance(1e9)
		r := e.write("PATCH", "s", "doc", head, patches)
		if r.Code != want {
			t.Fatalf("%v: status %d, want %d: %s", patches, r.Code, want, r.Body)
		}
		if r.Code == 201 {
			head = etagOf(r)
		}
		if f, c := e.e.ValidationCounts(); f-f0 != wantFull || c-c0 != wantChange {
			t.Fatalf("%v: validated %d in full and %d by changes, want %d and %d", patches, f-f0, c-c0, wantFull, wantChange)
		}
	}
	step(201, 0, 1, ops(op("replace", "/items/0", 5)))
	// Another schema: the whole document is held to it, and the title,
	// which the patch does not touch, fails.
	strict := "/r/s/schema/rev/" + s1
	step(422, 1, 0, ops(op("replace", "/$schema", strict)))
	step(201, 1, 0, ops(op("replace", "/$schema", strict), op("replace", "/title", "ok")))
	step(201, 0, 1, ops(op("replace", "/items/0", 6)))
	// The same $schema written again still touches it.
	step(201, 1, 0, ops(op("replace", "/$schema", strict)))
	// A root replace.
	next := baseDoc()
	next["$schema"] = strict
	step(201, 1, 0, ops(op("replace", "", next)))
	step(201, 0, 1, ops(op("replace", "/items/0", 7)))

	// After a restart nothing is remembered: in full once, then by changes.
	e.srv.Close()
	e.e.Close()
	e = open()
	step(201, 1, 0, ops(op("replace", "/items/0", 8)))
	step(201, 0, 1, ops(op("replace", "/items/0", 9)))
	step(422, 0, 1, ops(op("add", "/items/-", 9)))

	// A delete and a restore: the restore is a document from scratch.
	e.clock.Advance(1e9)
	r := e.write("DELETE", "s", "doc", head, nil)
	expect(t, r, 200)
	head, _ = r.Obj()["tombstone"].(string)
	next["title"] = "back"
	step(201, 1, 0, addRoot(next))
	step(201, 0, 1, ops(op("replace", "/title", "again")))
}

// The steps of a batch item: each is validated by its changes on the step
// before it, which this write validated, and a step that breaks a
// constraint above its change refuses the batch.
func TestValidationByChangesBatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("s", map[string]any{})
	rev := e.create("s", "schema", changeSchemaDoc())
	doc := baseDoc()
	doc["$schema"] = "/r/s/schema/rev/" + rev
	batch := func(items ...map[string]any) *resp {
		e.clock.Advance(1e9)
		list := make([]any, len(items))
		for i, it := range items {
			list[i] = it
		}
		return e.do(req{method: "POST", path: "/ns/s/batch", author: "alice", body: map[string]any{"items": list}})
	}
	f0, c0 := e.e.ValidationCounts()
	// A create and two appends in one item: in full, then twice by changes.
	expect(t, batch(map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{
		addRoot(doc), ops(op("add", "/items/-", 3)), ops(op("replace", "/title", "second"))}}), 201)
	if f, c := e.e.ValidationCounts(); f-f0 != 1 || c-c0 != 2 {
		t.Fatalf("validated %d in full and %d by changes, want 1 and 2", f-f0, c-c0)
	}
	head := etagOf(e.get("/r/s/a"))
	// The second step repeats an item the first added.
	r := batch(map[string]any{"resource": "a", "ifMatch": head, "steps": []any{
		ops(op("add", "/items/-", 4)), ops(op("add", "/items/-", 4))}})
	expectCode(t, r, 422, "batch")
	// And valid steps after it are not reached; the document is as it was.
	expect(t, batch(map[string]any{"resource": "a", "ifMatch": head, "steps": []any{
		ops(op("add", "/items/-", 4)), ops(op("replace", "/items/3", 5))}}), 201)
}

// Random patches, valid and not, to both deployments of a pair.
func TestValidationByChangesRandom(t *testing.T) {
	t.Parallel()
	p := newValidationPair(t, baseDoc())
	r := rand.New(rand.NewSource(11))
	n := func() int { return r.Intn(8) }
	likely := []func() map[string]any{
		func() map[string]any { return op("replace", "/title", fmt.Sprint("t", n())) },
		func() map[string]any { return op("add", "/items/-", n()) },
		func() map[string]any { return op("add", "/items/0", n()) },
		func() map[string]any { return op("remove", "/items/0") },
		func() map[string]any { return op("replace", "/items/0", n()) },
		func() map[string]any { return op("replace", "/meta/a", n()) },
		func() map[string]any { return op("add", "/note", "n") },
		func() map[string]any { return op("remove", "/note") },
		func() map[string]any { return op("replace", "/shape", map[string]any{"circle": n()}) },
		func() map[string]any { return op("replace", "/shape", map[string]any{"rect": n()}) },
		func() map[string]any { return op("add", "/list/-", map[string]any{"id": n()}) },
		func() map[string]any { return op("add", "/list/0", map[string]any{"id": n(), "tags": []any{"x", "y"}}) },
		func() map[string]any { return op("replace", "/list/0/id", n()) },
		func() map[string]any { return op("add", "/list/0/tags", []any{"x"}) },
		func() map[string]any { return op("add", "/list/0/tags/-", "z") },
		func() map[string]any { return map[string]any{"op": "copy", "from": "/list/0", "path": "/list/-"} },
		func() map[string]any { return map[string]any{"op": "move", "from": "/list/0", "path": "/list/-"} },
		func() map[string]any {
			return op("add", "/$nonce", fmt.Sprintf("abcdefghijklmnopqrstuvwxy%c", 'a'+rune(n())))
		},
	}
	unlikely := []func() map[string]any{
		func() map[string]any { return op("replace", "/title", "a much longer title") },
		func() map[string]any { return op("remove", "/title") },
		func() map[string]any { return op("add", "/items/-", -1) },
		func() map[string]any { return op("add", "/meta/b", 1) },
		func() map[string]any { return op("add", "/shape/rect", 1) },
		func() map[string]any { return op("add", "/shape/circle", 1) },
		func() map[string]any { return op("remove", "/shape/circle") },
		func() map[string]any { return op("add", "/note", 5) },
		func() map[string]any { return op("add", "/extra", "e") },
		func() map[string]any { return op("remove", "/list/0/id") },
		func() map[string]any { return op("remove", "/list/0/tags/0") },
		func() map[string]any { return op("replace", "/list/0/tags/0", "q") },
		func() map[string]any { return op("replace", "/list", "none") },
		func() map[string]any { return map[string]any{"op": "move", "from": "/meta/a", "path": "/note"} },
		func() map[string]any { return op("add", "/$nonce", "not of the fresh form") },
		func() map[string]any { return op("remove", "/$nonce") },
	}
	ok, refused := 0, 0
	for i := 0; i < 500; i++ {
		var patches []any
		for k := 1 + r.Intn(2); k > 0; k-- {
			if r.Intn(5) == 0 {
				patches = append(patches, unlikely[r.Intn(len(unlikely))]())
			} else {
				patches = append(patches, likely[r.Intn(len(likely))]())
			}
		}
		if p.patch(patches) == 201 {
			ok++
		} else {
			refused++
		}
	}
	full, change := p.counts()
	t.Logf("%d patches applied, %d refused; validated %d in full, %d by changes", ok, refused, full, change)
	if ok < 100 || refused < 100 || change < 300 {
		t.Errorf("the patches exercise too little: %d applied, %d refused, %d validated by changes", ok, refused, change)
	}
}

// A remote branch mirrors typed revisions another deployment validated
// (§G.3): this one stored them and never validated them, so the first
// patch to one is validated in full, and the next by its changes.
func TestValidationMirroredInFull(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	f0, c0 := b.e.ValidationCounts()
	head := b.appendRev("rel", "derby", f.d2, ops(op("replace", "/score", "2-0")))
	if full, change := b.e.ValidationCounts(); full-f0 != 1 || change != c0 {
		t.Fatalf("a patch to a mirrored revision: validated %d in full, %d by changes; want 1 and 0", full-f0, change-c0)
	}
	b.clock.Advance(1e9)
	b.appendRev("rel", "derby", head, ops(op("replace", "/score", "3-0")))
	if full, change := b.e.ValidationCounts(); full-f0 != 1 || change-c0 != 1 {
		t.Fatalf("the next patch: validated %d in full, %d by changes; want 1 and 1", full-f0, change-c0)
	}
}
