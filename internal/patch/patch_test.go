package patch

import (
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func run(t *testing.T, doc, patch string, exists bool, opt Options) (any, []string, error) {
	t.Helper()
	pv, err := jsonv.Parse([]byte(patch))
	if err != nil {
		t.Fatal(err)
	}
	ops, err := Parse(pv)
	if err != nil {
		return nil, nil, err
	}
	var d any
	if exists {
		d = jsonv.MustParse([]byte(doc))
	}
	res, w, err := Apply(d, exists, ops, opt)
	return res, WritesStrings(w), err
}

func TestRFC6902AppendixA(t *testing.T) {
	cases := []struct {
		name, doc, patch, want string // want "" = error
	}{
		{"A.1 add object member", `{"foo":"bar"}`, `[{"op":"add","path":"/baz","value":"qux"}]`, `{"baz":"qux","foo":"bar"}`},
		{"A.2 add array element", `{"foo":["bar","baz"]}`, `[{"op":"add","path":"/foo/1","value":"qux"}]`, `{"foo":["bar","qux","baz"]}`},
		{"A.3 remove member", `{"baz":"qux","foo":"bar"}`, `[{"op":"remove","path":"/baz"}]`, `{"foo":"bar"}`},
		{"A.4 remove element", `{"foo":["bar","qux","baz"]}`, `[{"op":"remove","path":"/foo/1"}]`, `{"foo":["bar","baz"]}`},
		{"A.5 replace", `{"baz":"qux","foo":"bar"}`, `[{"op":"replace","path":"/baz","value":"boo"}]`, `{"baz":"boo","foo":"bar"}`},
		{"A.6 move value", `{"foo":{"bar":"baz","waldo":"fred"},"qux":{"corge":"grault"}}`, `[{"op":"move","from":"/foo/waldo","path":"/qux/thud"}]`, `{"foo":{"bar":"baz"},"qux":{"corge":"grault","thud":"fred"}}`},
		{"A.7 move element", `{"foo":["all","grass","cows","eat"]}`, `[{"op":"move","from":"/foo/1","path":"/foo/3"}]`, `{"foo":["all","cows","eat","grass"]}`},
		{"A.8 test success", `{"baz":"qux","foo":["a",2,"c"]}`, `[{"op":"test","path":"/baz","value":"qux"},{"op":"test","path":"/foo/1","value":2}]`, `{"baz":"qux","foo":["a",2,"c"]}`},
		{"A.9 test error", `{"baz":"qux"}`, `[{"op":"test","path":"/baz","value":"bar"}]`, ``},
		{"A.10 add nested member", `{"foo":"bar"}`, `[{"op":"add","path":"/child","value":{"grandchild":{}}}]`, `{"foo":"bar","child":{"grandchild":{}}}`},
		{"A.11 ignore unrecognized", `{"foo":"bar"}`, `[{"op":"add","path":"/baz","value":"qux","xyz":123}]`, `{"foo":"bar","baz":"qux"}`},
		{"A.12 add missing parent", `{"foo":"bar"}`, `[{"op":"add","path":"/baz/bat","value":"qux"}]`, ``},
		{"A.14 ~ escape ordering", `{"/":9,"~1":10}`, `[{"op":"test","path":"/~01","value":10}]`, `{"/":9,"~1":10}`},
		{"A.15 compare string and number", `{"/":9,"~1":10}`, `[{"op":"test","path":"/~01","value":"10"}]`, ``},
		{"A.16 add array value", `{"foo":["bar"]}`, `[{"op":"add","path":"/foo/-","value":["abc","def"]}]`, `{"foo":["bar",["abc","def"]]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, _, err := run(t, c.doc, c.patch, true, Options{})
			if c.want == "" {
				var pe *Error
				if err == nil {
					t.Fatalf("want error, got %s", jsonv.Canonical(res))
				}
				if e, ok := err.(*Error); ok {
					pe = e
				}
				if pe == nil {
					t.Fatalf("error type %T", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !jsonv.Equal(res, jsonv.MustParse([]byte(c.want))) {
				t.Fatalf("got %s want %s", jsonv.Canonical(res), c.want)
			}
		})
	}
}

func TestOpSemantics(t *testing.T) {
	cases := []struct {
		name, doc, patch string
		ok               bool
		want             string
	}{
		{"copy", `{"a":{"x":1},"b":[]}`, `[{"op":"copy","from":"/a","path":"/b/0"},{"op":"add","path":"/b/0/x","value":2}]`, true, `{"a":{"x":1},"b":[{"x":2}]}`},
		{"copy missing from", `{}`, `[{"op":"copy","from":"/a","path":"/b"}]`, false, ""},
		{"move missing from", `{}`, `[{"op":"move","from":"/a","path":"/b"}]`, false, ""},
		{"move into own child", `{"a":{"b":1}}`, `[{"op":"move","from":"/a","path":"/a/b/c"}]`, false, ""},
		{"move same location", `{"a":1}`, `[{"op":"move","from":"/a","path":"/a"}]`, true, `{"a":1}`},
		{"remove missing", `{}`, `[{"op":"remove","path":"/a"}]`, false, ""},
		{"remove dash", `{"a":[1]}`, `[{"op":"remove","path":"/a/-"}]`, false, ""},
		{"remove out of range", `{"a":[1]}`, `[{"op":"remove","path":"/a/1"}]`, false, ""},
		{"replace missing", `{}`, `[{"op":"replace","path":"/a","value":1}]`, false, ""},
		{"replace root", `{"a":1}`, `[{"op":"replace","path":"","value":[1]}]`, true, `[1]`},
		{"add root", `{"a":1}`, `[{"op":"add","path":"","value":null}]`, true, `null`},
		{"remove root", `{"a":1}`, `[{"op":"remove","path":""}]`, false, ""},
		{"add index past len", `{"a":[1]}`, `[{"op":"add","path":"/a/2","value":1}]`, false, ""},
		{"add at len", `{"a":[1]}`, `[{"op":"add","path":"/a/1","value":2}]`, true, `{"a":[1,2]}`},
		{"leading zero index", `{"a":[1,2]}`, `[{"op":"add","path":"/a/01","value":2}]`, false, ""},
		{"non numeric index", `{"a":[1,2]}`, `[{"op":"add","path":"/a/x","value":2}]`, false, ""},
		{"numeric key on object", `{"a":{}}`, `[{"op":"add","path":"/a/01","value":2}]`, true, `{"a":{"01":2}}`},
		{"add through scalar", `{"a":1}`, `[{"op":"add","path":"/a/b","value":2}]`, false, ""},
		{"test null", `{"a":null}`, `[{"op":"test","path":"/a","value":null}]`, true, `{"a":null}`},
		{"test missing", `{}`, `[{"op":"test","path":"/a","value":null}]`, false, ""},
		{"test number equality", `{"a":1}`, `[{"op":"test","path":"/a","value":1.0}]`, true, `{"a":1}`},
		{"escaped keys", `{"a/b":1,"m~n":2}`, `[{"op":"replace","path":"/a~1b","value":3},{"op":"remove","path":"/m~0n"}]`, true, `{"a/b":3}`},
		{"empty patch", `{"a":1}`, `[]`, true, `{"a":1}`},
		{"atomic", `{"a":1}`, `[{"op":"add","path":"/b","value":1},{"op":"remove","path":"/zz"}]`, false, ""},
		{"empty key", `{"":1}`, `[{"op":"replace","path":"/","value":2}]`, true, `{"":2}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, _, err := run(t, c.doc, c.patch, true, Options{})
			if !c.ok {
				if _, isP := err.(*Error); !isP {
					t.Fatalf("want *Error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !jsonv.Equal(res, jsonv.MustParse([]byte(c.want))) {
				t.Fatalf("got %s want %s", jsonv.Canonical(res), c.want)
			}
		})
	}
}

func TestErrorFields(t *testing.T) {
	_, _, err := run(t, `{"a":1}`, `[{"op":"add","path":"/b","value":1},{"op":"test","path":"/a","value":2}]`, true, Options{})
	e, ok := err.(*Error)
	if !ok || e.Index != 1 || e.Pointer != "/a" || !strings.Contains(e.Message, "test failed") {
		t.Fatalf("got %#v", err)
	}
	_, _, err = run(t, `{}`, `[{"op":"copy","from":"/x","path":"/y"}]`, true, Options{})
	if e, ok := err.(*Error); !ok || e.Index != 0 || e.Pointer != "/x" {
		t.Fatalf("got %#v", err)
	}
}

const nonce = "abcdefghijklmnopqrstuvwxy2"

func TestWrites(t *testing.T) {
	if len(nonce) != 26 {
		t.Fatal("bad nonce const")
	}
	cases := []struct {
		name, doc, patch string
		opt              Options
		want             []string
	}{
		{"add replace remove", `{"a":1,"b":2}`, `[{"op":"add","path":"/c","value":1},{"op":"replace","path":"/a","value":2},{"op":"remove","path":"/b"}]`, Options{}, []string{"/c", "/a", "/b"}},
		{"copy writes path only", `{"a":1}`, `[{"op":"copy","from":"/a","path":"/b"}]`, Options{}, []string{"/b"}},
		{"move writes from and path", `{"a":1}`, `[{"op":"move","from":"/a","path":"/b"}]`, Options{}, []string{"/a", "/b"}},
		{"move same location", `{"a":1}`, `[{"op":"move","from":"/a","path":"/a"}]`, Options{}, []string{"/a", "/a"}},
		{"append index", `{"a":[1,2,3]}`, `[{"op":"add","path":"/a/-","value":4},{"op":"add","path":"/a/-","value":5}]`, Options{}, []string{"/a/3", "/a/4"}},
		{"move append", `{"a":[1],"b":[7,8]}`, `[{"op":"move","from":"/b/0","path":"/a/-"}]`, Options{}, []string{"/b/0", "/a/1"}},
		{"copy append", `{"a":[1]}`, `[{"op":"copy","from":"/a/0","path":"/a/-"}]`, Options{}, []string{"/a/1"}},
		{"root", `{"a":1}`, `[{"op":"replace","path":"","value":{}}]`, Options{}, []string{""}},
		{"test writes nothing", `{"a":1}`, `[{"op":"test","path":"/a","value":1}]`, Options{}, nil},
		{"escaping", `{"a/b":1,"m~n":1}`, `[{"op":"replace","path":"/a~1b","value":2},{"op":"remove","path":"/m~0n"}]`, Options{}, []string{"/a~1b", "/m~0n"}},
		{"nonce excluded add", `{}`, `[{"op":"add","path":"/$nonce","value":"` + nonce + `"}]`, Options{ResourceEnvelope: true}, nil},
		{"nonce excluded replace", `{"$nonce":"x"}`, `[{"op":"replace","path":"/$nonce","value":"` + nonce + `"},{"op":"add","path":"/t","value":1}]`, Options{ResourceEnvelope: true}, []string{"/t"}},
		{"nonce not excluded without envelope", `{}`, `[{"op":"add","path":"/$nonce","value":"` + nonce + `"}]`, Options{}, []string{"/$nonce"}},
		{"nonce wrong value", `{}`, `[{"op":"add","path":"/$nonce","value":"short"}]`, Options{ResourceEnvelope: true}, []string{"/$nonce"}},
		{"nonce bad alphabet", `{}`, `[{"op":"add","path":"/$nonce","value":"ABCDEFGHIJKLMNOPQRSTUVWXY2"}]`, Options{ResourceEnvelope: true}, []string{"/$nonce"}},
		{"nonce non-string", `{}`, `[{"op":"add","path":"/$nonce","value":1}]`, Options{ResourceEnvelope: true}, []string{"/$nonce"}},
		{"nonce deeper path", `{"$nonce":{}}`, `[{"op":"add","path":"/$nonce/x","value":"` + nonce + `"}]`, Options{ResourceEnvelope: true}, []string{"/$nonce/x"}},
		{"nonce remove", `{"$nonce":"x"}`, `[{"op":"remove","path":"/$nonce"}]`, Options{ResourceEnvelope: true}, []string{"/$nonce"}},
		{"nonce copy", `{"a":"` + nonce + `"}`, `[{"op":"copy","from":"/a","path":"/$nonce"}]`, Options{ResourceEnvelope: true}, []string{"/$nonce"}},
		{"nonce move to and from", `{"a":"` + nonce + `"}`, `[{"op":"move","from":"/a","path":"/$nonce"},{"op":"move","from":"/$nonce","path":"/b"}]`, Options{ResourceEnvelope: true}, []string{"/a", "/$nonce", "/$nonce", "/b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, w, err := run(t, c.doc, c.patch, true, c.opt)
			if err != nil {
				t.Fatal(err)
			}
			if len(w) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(w, c.want) {
				t.Fatalf("writes %v want %v", w, c.want)
			}
		})
	}
}

func TestNoMutation(t *testing.T) {
	src := `{"a":[1,2,3],"b":{"c":[{"d":1}]}}`
	doc := jsonv.MustParse([]byte(src))
	pv, _ := jsonv.Parse([]byte(`[
	 {"op":"add","path":"/a/0","value":9},
	 {"op":"remove","path":"/a/2"},
	 {"op":"copy","from":"/b","path":"/e"},
	 {"op":"add","path":"/e/c/0/d","value":5},
	 {"op":"move","from":"/a/0","path":"/b/c/-"},
	 {"op":"replace","path":"/b/c/0/d","value":7}]`))
	ops, err := Parse(pv)
	if err != nil {
		t.Fatal(err)
	}
	opsBefore := jsonv.Clone(pv)
	res, _, err := Apply(doc, true, ops, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(jsonv.Canonical(doc)) != string(jsonv.Canonical(jsonv.MustParse([]byte(src)))) {
		t.Fatalf("input mutated: %s", jsonv.Canonical(doc))
	}
	if !jsonv.Equal(pv, opsBefore) {
		t.Fatal("patch mutated")
	}
	want := `{"a":[2],"b":{"c":[{"d":7},9]},"e":{"c":[{"d":5}]}}`
	_ = want
	// mutate the result; ops values must not alias it
	res.(map[string]any)["a"] = nil
	if !jsonv.Equal(pv, opsBefore) {
		t.Fatal("patch aliased")
	}
	// a failing apply must leave doc intact too
	ops2, _ := Parse(jsonv.MustParse([]byte(`[{"op":"add","path":"/a/0","value":1},{"op":"remove","path":"/zz"}]`)))
	if _, _, err := Apply(doc, true, ops2, Options{}); err == nil {
		t.Fatal("want error")
	}
	if string(jsonv.Canonical(doc)) != string(jsonv.Canonical(jsonv.MustParse([]byte(src)))) {
		t.Fatal("input mutated by failed apply")
	}
}

func TestCreateFromNothing(t *testing.T) {
	res, w, err := run(t, ``, `[{"op":"add","path":"","value":{"a":1}},{"op":"add","path":"/b","value":2}]`, false, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonv.Equal(res, jsonv.MustParse([]byte(`{"a":1,"b":2}`))) || !reflect.DeepEqual(w, []string{"", "/b"}) {
		t.Fatalf("got %s %v", jsonv.Canonical(res), w)
	}
	res, w, err = run(t, ``, `[{"op":"add","path":"","value":null}]`, false, Options{})
	if err != nil || res != nil || !reflect.DeepEqual(w, []string{""}) {
		t.Fatalf("null genesis: %v %v %v", res, w, err)
	}
	for _, p := range []string{
		`[{"op":"test","path":"","value":null}]`,
		`[{"op":"replace","path":"","value":1}]`,
		`[{"op":"remove","path":""}]`,
		`[{"op":"add","path":"/a","value":1}]`,
		`[{"op":"copy","from":"","path":"/a"}]`,
		`[{"op":"move","from":"","path":"/a"}]`,
		`[]`,
	} {
		if _, _, err := run(t, ``, p, false, Options{}); err == nil {
			t.Errorf("want error for %s", p)
		} else if _, ok := err.(*Error); !ok {
			t.Errorf("%s: type %T", p, err)
		}
	}
}

func TestParse(t *testing.T) {
	bad := []string{
		`{}`, `"x"`, `null`, `[1]`, `[null]`, `[{}]`, `[{"op":1,"path":""}]`,
		`[{"op":"bogus","path":""}]`, `[{"op":"add"}]`, `[{"op":"add","path":1,"value":1}]`,
		`[{"op":"add","path":"a","value":1}]`, `[{"op":"add","path":"/a~2","value":1}]`,
		`[{"op":"add","path":"/a"}]`, `[{"op":"replace","path":"/a"}]`, `[{"op":"test","path":"/a"}]`,
		`[{"op":"move","path":"/a"}]`, `[{"op":"copy","path":"/a"}]`,
		`[{"op":"move","from":1,"path":"/a"}]`, `[{"op":"copy","from":"x","path":"/a"}]`,
	}
	for _, b := range bad {
		pv, err := jsonv.Parse([]byte(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(pv); err == nil {
			t.Errorf("want error for %s", b)
		} else if _, ok := err.(*Error); !ok {
			t.Errorf("%s: type %T", b, err)
		}
	}
	pv := jsonv.MustParse([]byte(`[
	 {"op":"add","path":"/a~1b","value":null,"extra":1},
	 {"op":"remove","path":"/x","value":1},
	 {"op":"move","from":"/m~0n","path":"/y"},
	 {"op":"test","path":"","value":false}]`))
	ops, err := Parse(pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 4 || ops[0].Value != nil || ops[0].PathText != "/a~1b" || ops[0].Path[0] != "a/b" ||
		ops[2].From[0] != "m~n" || ops[3].Value != false || len(ops[3].Path) != 0 {
		t.Fatalf("unexpected %#v", ops)
	}
	if ops, err := Parse([]any{}); err != nil || len(ops) != 0 {
		t.Fatal("empty patch set should parse")
	}
}

// replace on an array element replaces it in place (RFC 6902 §4.3).
func TestReplaceArrayElement(t *testing.T) {
	doc := jsonv.MustParse([]byte(`{"k":[1,2,3],"o":{"a":[{"x":1},{"x":2}]}}`))
	ops, err := Parse(jsonv.MustParse([]byte(`[{"op":"replace","path":"/k/1","value":9},{"op":"replace","path":"/o/a/0","value":{"y":0}},{"op":"replace","path":"/k/2","value":7}]`)))
	if err != nil {
		t.Fatal(err)
	}
	got, writes, err := Apply(doc, true, ops, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := jsonv.MustParse([]byte(`{"k":[1,9,7],"o":{"a":[{"y":0},{"x":2}]}}`))
	if !jsonv.Equal(got, want) {
		t.Fatalf("got %s", jsonv.Canonical(got))
	}
	if w := WritesStrings(writes); len(w) != 3 || w[0] != "/k/1" || w[1] != "/o/a/0" || w[2] != "/k/2" {
		t.Fatalf("writes %v", w)
	}
	// Out of range and "-" still fail.
	for _, p := range []string{`/k/3`, `/k/-`} {
		ops, _ := Parse(jsonv.MustParse([]byte(`[{"op":"replace","path":"` + p + `","value":0}]`)))
		if _, _, err := Apply(doc, true, ops, Options{}); err == nil {
			t.Errorf("replace %s succeeded", p)
		}
	}
}
