package core

import (
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §6.6: at E3 every create and restore may be as large as documentSize.
func TestCheckLimitsFromScratch(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	l.PatchSetSize, l.DocumentSize = 100, 1000
	big := make([]byte, 500)
	root := []any{map[string]any{"op": "replace", "path": "", "value": 1.0}}
	add := []any{map[string]any{"op": "add", "path": "/a", "value": 1.0}}
	for _, c := range []struct {
		name string
		s    stepState
		ok   bool
	}{
		{"create", stepState{action: "create"}, true},
		{"e2e create", stepState{action: "create", sealed: true}, true},
		{"e2e restore", stepState{action: "restore", sealed: true}, true},
		{"e2e append", stepState{action: "append", sealed: true}, false},
		{"restore from scratch", stepState{action: "restore", raw: root}, true},
		{"restore with add", stepState{action: "restore", raw: add}, false},
		{"empty restore", stepState{action: "restore", raw: []any{}}, false},
		{"append", stepState{action: "append", raw: root}, false},
	} {
		c.s.canon = big
		err := checkLimits(l, &itemState{steps: []*stepState{&c.s}})
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestCanonStringLen(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]int{"": 2, "abc": 5, `a"b`: 6, "\n\x01": 2 + 2 + 6, "é": 4} {
		if got := canonStringLen(s); got != want {
			t.Errorf("%q: %d, want %d", s, got, want)
		}
	}
}

// canonStringLen is the length of s as canonical JSON, quotes included.
func canonStringLen(s string) int {
	n := 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"', c == '\\', c == '\b', c == '\f', c == '\n', c == '\r', c == '\t':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
	}
	return n
}

// walkValuesAndPaths is the walk that enforced valueSize and pathSize
// (§6.6) on the document itself before shapeOf, members visited in
// canonical order rather than the map's: what shapeOf reads from the
// canonical form.
func walkValuesAndPaths(l Limits, doc any) *Error {
	var bad *Error
	var walk func(v any, path int)
	// path is the canonical JSON length of the pointer to v, without quotes.
	walk = func(v any, path int) {
		if bad != nil {
			return
		}
		if path+2 > l.PathSize {
			bad = limitErr(413, fmt.Sprintf("a path is longer than %d bytes", l.PathSize))
			return
		}
		switch x := v.(type) {
		case string:
			if canonStringLen(x) > l.ValueSize {
				bad = limitErr(413, fmt.Sprintf("a string is longer than %d bytes", l.ValueSize))
			}
		case []any:
			for i, e := range x {
				walk(e, path+1+len(strconv.Itoa(i)))
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
				for k := 0; k < len(a) && k < len(b); k++ {
					if a[k] != b[k] {
						return a[k] < b[k]
					}
				}
				return len(a) < len(b)
			})
			for _, k := range keys {
				n := canonStringLen(k)
				if n > l.ValueSize {
					bad = limitErr(413, fmt.Sprintf("a member name is longer than %d bytes", l.ValueSize))
					return
				}
				// "~" and "/" are escaped as two characters in a pointer.
				walk(x[k], path+1+n-2+strings.Count(k, "~")+strings.Count(k, "/"))
			}
		}
	}
	walk(doc, 0)
	return bad
}

// shapeOf reads from a document's canonical form what walking the document
// finds: its depth, the first string, member name or pointer over the
// limits, and whether it has a $blob member.
func TestShapeOf(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(1))
	pieces := []string{"a", "bc", "~", "/", `"`, `\`, "\n", "\x01", "\x1f", "é", "€", "😀", "$blob", " ", "0"}
	str := func() string {
		var b strings.Builder
		for n := r.Intn(6); n > 0; n-- {
			b.WriteString(pieces[r.Intn(len(pieces))])
		}
		return b.String()
	}
	var gen func(depth int) any
	gen = func(depth int) any {
		switch k := r.Intn(10); {
		case depth > 4 || k < 3:
			switch r.Intn(6) {
			case 0:
				return nil
			case 1:
				return r.Intn(2) == 0
			case 2:
				return float64(r.Intn(2000) - 1000)
			case 3:
				return r.Float64() * 1e300
			}
			return str()
		case k < 6:
			a := make([]any, r.Intn(12))
			for i := range a {
				a[i] = gen(depth + 1)
			}
			return a
		default:
			m := map[string]any{}
			for n := r.Intn(5); n > 0; n-- {
				k := str()
				if r.Intn(8) == 0 {
					k = "$blob"
				}
				m[k] = gen(depth + 1)
			}
			return m
		}
	}
	found := map[string]bool{}
	for i := 0; i < 5000; i++ {
		doc := gen(0)
		l := Limits{ValueSize: 2 + r.Intn(16), PathSize: 2 + r.Intn(24)}
		if i%4 == 0 {
			l.ValueSize, l.PathSize = 1<<20, 1<<20
		}
		got := shapeOf(l, jsonv.Canonical(doc))
		want := walkValuesAndPaths(l, doc)
		if got.depth != jsonv.Depth(doc) || got.blobs != hasBlobMember(doc) || fmt.Sprint(got.bad) != fmt.Sprint(want) {
			t.Fatalf("%s under %d/%d: depth %d blobs %v %v, want %d %v %v", jsonv.Canonical(doc), l.ValueSize, l.PathSize,
				got.depth, got.blobs, got.bad, jsonv.Depth(doc), hasBlobMember(doc), want)
		}
		if want != nil {
			found[strings.Fields(want.Body["message"].(string))[1]] = true
		}
	}
	if len(found) != 3 {
		t.Errorf("only %v over the limits", found)
	}
}
