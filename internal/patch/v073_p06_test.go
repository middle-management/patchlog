package patch

import (
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §6.4.1 (v0.67): an add, copy or move into an array at an index below its
// length, and a remove or move of an element that isn't its last, shift the
// elements after it, so they also write the array itself, once per op.
func TestV073ArrayShiftWritesArray(t *testing.T) {
	cases := []struct {
		name, doc, patch string
		want             []string
	}{
		{"add below length", `{"a":[1,2,3]}`, `[{"op":"add","path":"/a/0","value":0}]`, []string{"/a/0", "/a"}},
		{"add at length appends", `{"a":[1,2,3]}`, `[{"op":"add","path":"/a/3","value":4}]`, []string{"/a/3"}},
		{"add dash appends", `{"a":[1,2,3]}`, `[{"op":"add","path":"/a/-","value":4}]`, []string{"/a/3"}},
		{"add into empty array", `{"a":[]}`, `[{"op":"add","path":"/a/0","value":4}]`, []string{"/a/0"}},
		{"add nested", `{"a":[[1,2]]}`, `[{"op":"add","path":"/a/0/1","value":9}]`, []string{"/a/0/1", "/a/0"}},
		{"add object member", `{"a":{"x":1}}`, `[{"op":"add","path":"/a/x","value":2}]`, []string{"/a/x"}},
		{"remove last", `{"a":[1,2,3]}`, `[{"op":"remove","path":"/a/2"}]`, []string{"/a/2"}},
		{"remove not last", `{"a":[1,2,3]}`, `[{"op":"remove","path":"/a/1"}]`, []string{"/a/1", "/a"}},
		{"remove only element", `{"a":[1]}`, `[{"op":"remove","path":"/a/0"}]`, []string{"/a/0"}},
		{"replace element in place", `{"a":[1,2,3]}`, `[{"op":"replace","path":"/a/0","value":9}]`, []string{"/a/0"}},
		{"copy below length", `{"a":[1,2,3]}`, `[{"op":"copy","from":"/a/2","path":"/a/0"}]`, []string{"/a/0", "/a"}},
		{"copy append", `{"a":[1]}`, `[{"op":"copy","from":"/a/0","path":"/a/-"}]`, []string{"/a/1"}},
		{"move out of array", `{"a":[1,2,3],"b":{}}`, `[{"op":"move","from":"/a/0","path":"/b/x"}]`, []string{"/a/0", "/a", "/b/x"}},
		{"move last out", `{"a":[1,2,3],"b":{}}`, `[{"op":"move","from":"/a/2","path":"/b/x"}]`, []string{"/a/2", "/b/x"}},
		{"move into array", `{"a":[1,2],"b":{"x":0}}`, `[{"op":"move","from":"/b/x","path":"/a/0"}]`, []string{"/b/x", "/a/0", "/a"}},
		{"move within array once", `{"a":[1,2,3]}`, `[{"op":"move","from":"/a/0","path":"/a/1"}]`, []string{"/a/0", "/a", "/a/1"}},
		{"move last to front", `{"a":[1,2,3]}`, `[{"op":"move","from":"/a/2","path":"/a/0"}]`, []string{"/a/2", "/a/0", "/a"}},
		{"move first to end", `{"a":[1,2,3]}`, `[{"op":"move","from":"/a/0","path":"/a/-"}]`, []string{"/a/0", "/a", "/a/2"}},
		{"move between arrays", `{"a":[1,2],"b":[7,8]}`, `[{"op":"move","from":"/b/0","path":"/a/0"}]`, []string{"/b/0", "/b", "/a/0", "/a"}},
		{"move same element not last", `{"a":[1,2,3]}`, `[{"op":"move","from":"/a/0","path":"/a/0"}]`, []string{"/a/0", "/a", "/a/0"}},
		{"move same element last", `{"a":[1,2,3]}`, `[{"op":"move","from":"/a/2","path":"/a/2"}]`, []string{"/a/2", "/a/2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, w, err := run(t, c.doc, c.patch, true, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(w, c.want) {
				t.Fatalf("writes %q want %q", w, c.want)
			}
		})
	}
}

// §6.2 step 3 (v0.65): a create applies to the document null, which exists:
// test "" null, root replace, copy and move work, and the result may be
// null itself (nil with a nil error); the caller decides whether that is
// allowed. Without a document at all, only a root add starts one.
func TestV073CreateAppliesToNull(t *testing.T) {
	cases := []struct {
		name, patch string
		want        string // canonical result
		writes      []string
	}{
		{"test null then add", `[{"op":"test","path":"","value":null},{"op":"add","path":"","value":{"a":1}}]`, `{"a":1}`, []string{""}},
		{"root replace", `[{"op":"replace","path":"","value":{"a":1}}]`, `{"a":1}`, []string{""}},
		{"root copy", `[{"op":"copy","from":"","path":""},{"op":"add","path":"","value":[]}]`, `[]`, []string{"", ""}},
		{"root move", `[{"op":"move","from":"","path":""},{"op":"replace","path":"","value":"x"}]`, `"x"`, []string{"", "", ""}},
		{"empty set is null", `[]`, `null`, nil},
		{"test only is null", `[{"op":"test","path":"","value":null}]`, `null`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops, err := Parse(jsonv.MustParse([]byte(c.patch)))
			if err != nil {
				t.Fatal(err)
			}
			for _, opt := range []Options{{}, {InPlace: true}, {ResourceEnvelope: true, ShareLast: true}} {
				got, w, err := Apply(nil, true, ops, opt)
				if err != nil {
					t.Fatalf("%+v: %v", opt, err)
				}
				if g := string(jsonv.Canonical(got)); g != c.want {
					t.Fatalf("%+v: got %s want %s", opt, g, c.want)
				}
				if ws := WritesStrings(w); len(ws)+len(c.writes) > 0 && !reflect.DeepEqual(ws, c.writes) {
					t.Fatalf("%+v: writes %q want %q", opt, ws, c.writes)
				}
			}
		})
	}
	// A member of null doesn't exist; null isn't "true".
	for _, p := range []string{
		`[{"op":"add","path":"/a","value":1}]`,
		`[{"op":"test","path":"","value":{}}]`,
		`[{"op":"remove","path":""}]`,
		`[{"op":"copy","from":"/a","path":"/b"}]`,
	} {
		ops, _ := Parse(jsonv.MustParse([]byte(p)))
		if _, _, err := Apply(nil, true, ops, Options{}); err == nil {
			t.Errorf("%s on null succeeded", p)
		}
	}
	// No document at all: test and replace fail, an empty set is no document.
	for _, p := range []string{`[{"op":"test","path":"","value":null}]`, `[{"op":"replace","path":"","value":{}}]`, `[]`} {
		ops, _ := Parse(jsonv.MustParse([]byte(p)))
		if _, _, err := Apply(nil, false, ops, Options{}); err == nil {
			t.Errorf("%s without a document succeeded", p)
		}
	}
}
