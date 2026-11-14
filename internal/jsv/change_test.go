package jsv

import (
	"errors"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/patch"
)

func TestChangedPaths(t *testing.T) {
	doc := mustJSON(`{"a": {"0": 1, "b": [1, 2]}, "list": [1, 2, 3]}`)
	for _, tc := range []struct {
		ops     string
		want    []string
		wantDoc []string // ChangedPathsIn(doc), if it differs
	}{
		{`[{"op": "replace", "path": "/a/b/1", "value": 5}]`, []string{"/a/b/1"}, nil},
		{`[{"op": "replace", "path": "", "value": 5}]`, []string{""}, nil},
		{`[{"op": "add", "path": "/a/c", "value": 5}]`, []string{"/a/c"}, nil},
		{`[{"op": "add", "path": "/list/1", "value": 5}]`, []string{"/list"}, nil},
		{`[{"op": "add", "path": "/list/-", "value": 5}]`, []string{"/list"}, nil},
		{`[{"op": "add", "path": "/a/0", "value": 5}]`, []string{"/a"}, []string{"/a/0"}},
		{`[{"op": "add", "path": "", "value": 5}]`, []string{""}, nil},
		{`[{"op": "remove", "path": "/a/b"}]`, []string{"/a"}, nil},
		{`[{"op": "remove", "path": "/list/0"}]`, []string{"/list"}, nil},
		{`[{"op": "remove", "path": "/a"}]`, []string{""}, nil},
		{`[{"op": "move", "from": "/a/b", "path": "/c"}]`, []string{"/a", "/c"}, nil},
		{`[{"op": "move", "from": "/list/0", "path": "/a/b/-"}]`, []string{"/list", "/a/b"}, nil},
		{`[{"op": "copy", "from": "/a/b", "path": "/a/z~1y"}]`, []string{"/a/z~1y"}, nil},
		{`[{"op": "test", "path": "/a/b", "value": 1}]`, nil, nil},
		{`[{"op": "replace", "path": "/a/b/0", "value": 1}, {"op": "replace", "path": "/a/b/0", "value": 2}, {"op": "remove", "path": "/a/0"}]`,
			[]string{"/a/b/0", "/a"}, nil},
	} {
		ops := mustJSON(tc.ops).([]any)
		got, err := ChangedPaths(ops)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ChangedPaths(%s) = %q, %v; want %q", tc.ops, got, err, tc.want)
		}
		want := tc.wantDoc
		if want == nil {
			want = tc.want
		}
		got, err = ChangedPathsIn(doc, ops)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ChangedPathsIn(%s) = %q, %v; want %q", tc.ops, got, err, want)
		}
	}
	for _, bad := range []string{`[5]`, `[{"op": "replace"}]`, `[{"op": "replace", "path": "a"}]`, `[{"op": "move", "path": "/a"}]`, `[{"op": "frob", "path": "/a"}]`} {
		if _, err := ChangedPaths(mustJSON(bad).([]any)); err == nil {
			t.Errorf("ChangedPaths(%s): no error", bad)
		}
	}
}

func TestValidateChangeEdges(t *testing.T) {
	sch, err := Compile(mustJSON(`{"type": "object", "required": ["a"], "properties": {"a": {"type": "object", "properties": {"n": {"type": "integer"}}}, "b": {"type": "string"}}}`), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	invalidB := mustJSON(`{"a": {"n": 1}, "b": 5}`)
	var st Stats
	// Nothing changed: nothing is looked at, whatever the document.
	if err := sch.ValidateChange(invalidB, nil, ValidateOptions{Stats: &st}); err != nil || st.Steps != 0 {
		t.Errorf("no changes: %v, %d steps", err, st.Steps)
	}
	// A change elsewhere does not look at /b.
	if err := sch.ValidateChange(invalidB, []string{"/a/n"}, ValidateOptions{}); err != nil {
		t.Errorf("change at /a/n: %v", err)
	}
	// The root pointer is a full validation.
	var ve *ValidationError
	if err := sch.ValidateChange(invalidB, []string{"/a/n", ""}, ValidateOptions{}); !errors.As(err, &ve) || ve.InstancePath != "/b" {
		t.Errorf("change at root: %v", err)
	}
	if err := sch.ValidateChange(invalidB, []string{"/b"}, ValidateOptions{}); !errors.As(err, &ve) || ve.InstancePath != "/b" || ve.KeywordPath != "/properties/b/type" {
		t.Errorf("change at /b: %#v", err)
	}
	// A location that is not there stands for its deepest ancestor that is.
	if err := sch.ValidateChange(mustJSON(`{"a": {"n": "x"}}`), []string{"/a/gone/deeper"}, ValidateOptions{}); !errors.As(err, &ve) || ve.InstancePath != "/a/n" {
		t.Errorf("change at a missing location: %v", err)
	}
	// A removed required member is seen from its parent.
	if err := sch.ValidateChange(mustJSON(`{"b": "x"}`), []string{"/a/n"}, ValidateOptions{}); !errors.As(err, &ve) || ve.KeywordPath != "/required" {
		t.Errorf("removed member: %v", err)
	}
	if err := sch.ValidateChange(invalidB, []string{"b"}, ValidateOptions{}); err == nil || errors.As(err, &ve) {
		t.Errorf("malformed pointer: %v", err)
	}
}

// covered reports whether every location where old and new differ is at
// or under one of paths, as ValidateChange requires of them: this checks
// ChangedPaths against the patch's effect, whatever the schema.
func covered(old, new any, ptr string, paths []string) bool {
	for _, p := range paths {
		if p == ptr || strings.HasPrefix(ptr, p+"/") {
			return true
		}
	}
	switch o := old.(type) {
	case map[string]any:
		n, ok := new.(map[string]any)
		if !ok {
			return false
		}
		for k := range o {
			if _, ok := n[k]; !ok {
				return false // a removal must be reported at ptr or above
			}
		}
		for k, nv := range n {
			child := ptr + "/" + escapeToken(k)
			ov, ok := o[k]
			if !ok {
				ov = nv
				if !covered(nil, map[string]any{}, child, paths) { // an addition must be reported
					return false
				}
			}
			if !covered(ov, nv, child, paths) {
				return false
			}
		}
		return true
	case []any:
		n, ok := new.([]any)
		if !ok || len(n) != len(o) {
			return false
		}
		for i := range o {
			if !covered(o[i], n[i], ptr+"/"+strconv.Itoa(i), paths) {
				return false
			}
		}
		return true
	}
	return equal(old, new)
}

// patchGen makes random patches aimed at what schemas constrain: members
// come and go, arrays grow, shrink and repeat items, values change type.
type patchGen struct {
	r    *rand.Rand
	keys []string // member names worth adding
}

func schemaKeys(schema any, into map[string]bool) {
	switch x := schema.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "properties" {
				if props, ok := v.(map[string]any); ok {
					for name := range props {
						into[name] = true
					}
				}
			}
			schemaKeys(v, into)
		}
	case []any:
		for _, v := range x {
			schemaKeys(v, into)
		}
	}
}

func newPatchGen(r *rand.Rand, schema any) *patchGen {
	set := map[string]bool{"bad": true, "x-n": true, "q": true, "0": true, "Zed": true}
	schemaKeys(schema, set)
	g := &patchGen{r: r}
	for k := range set {
		g.keys = append(g.keys, k)
	}
	// Map order is random: sort for a repeatable run.
	for i := 1; i < len(g.keys); i++ {
		for j := i; j > 0 && g.keys[j] < g.keys[j-1]; j-- {
			g.keys[j], g.keys[j-1] = g.keys[j-1], g.keys[j]
		}
	}
	return g
}

// value returns something to write: junk, or a copy of a value from doc,
// which tends to be valid somewhere.
func (g *patchGen) value(doc any, ptrs []string) any {
	if g.r.Intn(3) == 0 {
		return cloneJSON(junk[g.r.Intn(len(junk))])
	}
	v, _ := lookup(doc, ptrs[g.r.Intn(len(ptrs))])
	if f, ok := v.(float64); ok && g.r.Intn(2) == 0 {
		return f + float64(g.r.Intn(3)-1)
	}
	return cloneJSON(v)
}

// dest returns a path to add at: a member of an object or an index of an
// array of doc.
func (g *patchGen) dest(doc any, ptrs []string) (string, bool) {
	for try := 0; try < 20; try++ {
		p := ptrs[g.r.Intn(len(ptrs))]
		v, _ := lookup(doc, p)
		switch x := v.(type) {
		case map[string]any:
			return p + "/" + escapeToken(g.keys[g.r.Intn(len(g.keys))]), true
		case []any:
			if g.r.Intn(3) == 0 {
				return p + "/-", true
			}
			return p + "/" + strconv.Itoa(g.r.Intn(len(x)+1)), true
		}
	}
	return "", false
}

func (g *patchGen) op(doc any) map[string]any {
	ptrs := pointers(doc)
	any1 := func() string { return ptrs[g.r.Intn(len(ptrs))] }
	notRoot := func() (string, bool) {
		if len(ptrs) < 2 {
			return "", false
		}
		return ptrs[1+g.r.Intn(len(ptrs)-1)], true
	}
	switch g.r.Intn(10) {
	case 0, 1, 2: // replace, most often a scalar
		p := any1()
		for try := 0; try < 5; try++ {
			if v, _ := lookup(doc, p); !isContainer(v) {
				break
			}
			p = any1()
		}
		return map[string]any{"op": "replace", "path": p, "value": g.value(doc, ptrs)}
	case 3, 4: // add a member or insert an item
		if p, ok := g.dest(doc, ptrs); ok {
			return map[string]any{"op": "add", "path": p, "value": g.value(doc, ptrs)}
		}
	case 5, 6: // remove a member or an item
		if p, ok := notRoot(); ok {
			return map[string]any{"op": "remove", "path": p}
		}
	case 7: // move
		from, ok1 := notRoot()
		to, ok2 := g.dest(doc, ptrs)
		if ok1 && ok2 {
			return map[string]any{"op": "move", "from": from, "path": to}
		}
	case 8: // copy
		if to, ok := g.dest(doc, ptrs); ok {
			return map[string]any{"op": "copy", "from": any1(), "path": to}
		}
	}
	p := any1()
	v, _ := lookup(doc, p)
	return map[string]any{"op": "test", "path": p, "value": cloneJSON(v)}
}

func applyPatch(doc any, ops []any) (any, error) {
	parsed, err := patch.Parse(ops)
	if err != nil {
		return nil, err
	}
	out, _, err := patch.Apply(doc, true, parsed, patch.Options{})
	return out, err
}

// patch returns a patch of one to three operations that applies to doc,
// and the document it results in.
func (g *patchGen) patch(doc any) (ops []any, result any) {
	for {
		ops, result = nil, doc
		n := 1 + g.r.Intn(3)
		if g.r.Intn(2) == 0 {
			n = 1
		}
		for len(ops) < n {
			op := g.op(result)
			next, err := applyPatch(result, []any{op})
			if err != nil {
				continue // a move into itself, say
			}
			ops, result = append(ops, op), next
		}
		// The patch as a whole, applied by the server's own code.
		if whole, err := applyPatch(doc, ops); err == nil && equal(whole, result) {
			return ops, result
		}
	}
}

// TestValidateChangeProperty: for a valid document and any patch,
// ValidateChange given the patch's changed paths agrees with Validate on
// the patched document.
func TestValidateChangeProperty(t *testing.T) {
	const docs, patchesPerDoc = 600, 8
	for _, ts := range testSchemas {
		t.Run(ts.name, func(t *testing.T) {
			raw := mustJSON(ts.schema)
			sch, err := Compile(raw, "", Options{AssertFormat: true})
			if err != nil {
				t.Fatal(err)
			}
			r := rand.New(rand.NewSource(20261114))
			pg := newPatchGen(r, raw)
			var valid, invalid, cheaper, same, stepsFull, stepsChange int
			for d := 0; d < docs; d++ {
				var doc any
				for {
					doc = (&generator{r: r, root: raw}).gen(raw, 0)
					if sch.Validate(doc, ValidateOptions{}) == nil {
						break
					}
				}
				for i := 0; i < patchesPerDoc; i++ {
					ops, next := pg.patch(doc)
					var full, part Stats
					want := sch.Validate(next, ValidateOptions{Stats: &full})
					if want == nil {
						valid++
					} else {
						invalid++
					}
					blind, err := ChangedPaths(ops)
					if err != nil {
						t.Fatal(err)
					}
					seeing, err := ChangedPathsIn(next, ops)
					if err != nil {
						t.Fatal(err)
					}
					for _, paths := range [][]string{blind, seeing} {
						if !covered(doc, next, "", paths) {
							t.Fatalf("paths %q do not cover the changes\n  doc:   %s\n  patch: %s\n  after: %s", paths, jsonFull(doc), jsonFull(ops), jsonFull(next))
						}
						got := sch.ValidateChange(next, paths, ValidateOptions{Stats: &part})
						if got != nil && !errors.As(got, new(*ValidationError)) {
							t.Fatalf("ValidateChange: %v", got)
						}
						if (got == nil) != (want == nil) {
							t.Fatalf("verdicts differ\n  doc:   %s\n  patch: %s\n  after: %s\n  paths: %q\n  Validate:       %v\n  ValidateChange: %v",
								jsonFull(doc), jsonFull(ops), jsonFull(next), paths, want, got)
						}
					}
					// part is now the cost with ChangedPathsIn.
					if want == nil {
						stepsFull += full.Steps
						stepsChange += part.Steps
						switch {
						case part.Steps < full.Steps:
							cheaper++
						case part.Steps == full.Steps:
							same++
						}
					}
					if want == nil && r.Intn(2) == 0 {
						doc = next // walk on from the patched document
					}
				}
			}
			total := valid + invalid
			t.Logf("%d patches: %d leave the document valid, %d invalid; on the valid ones ValidateChange took %d steps against %d (fewer in %d, as many in %d)",
				total, valid, invalid, stepsChange, stepsFull, cheaper, same)
			if valid < total/10 || invalid < total/10 {
				t.Errorf("the patches do not exercise both verdicts: %d valid, %d invalid", valid, invalid)
			}
			// Many documents are a few values, and many changes are at the
			// root, so not every one can be cheaper; the sum must be.
			if ts.local && stepsChange*10 > stepsFull*7 {
				t.Errorf("ValidateChange took %d steps where Validate took %d", stepsChange, stepsFull)
			}
		})
	}
}

func jsonFull(v any) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v any) {
	switch x := v.(type) {
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		b.WriteByte('{')
		first := true
		for _, k := range sortedKeys(x) {
			if !first {
				b.WriteByte(',')
			}
			first = false
			b.WriteString(strconv.Quote(k))
			b.WriteByte(':')
			writeJSON(b, x[k])
		}
		b.WriteByte('}')
	case string:
		b.WriteString(strconv.Quote(x))
	case nil:
		b.WriteString("null")
	case float64:
		b.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case bool:
		b.WriteString(strconv.FormatBool(x))
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
