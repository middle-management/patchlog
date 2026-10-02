package rules

import (
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func c(t *testing.T, s string) *Rule {
	t.Helper()
	r, err := Compile(jsonv.MustParse([]byte(s)))
	if err != nil {
		t.Fatalf("compile %s: %v", s, err)
	}
	return r
}

func env(s string) map[string]any { return jsonv.MustParse([]byte(s)).(map[string]any) }

type tc struct {
	rule string
	env  string
	want bool
}

func run(t *testing.T, cases []tc) {
	t.Helper()
	for i, x := range cases {
		if got := c(t, x.rule).Eval(env(x.env)); got != x.want {
			t.Errorf("case %d: %s on %s = %v, want %v", i, x.rule, x.env, got, x.want)
		}
	}
}

func TestTest(t *testing.T) {
	run(t, []tc{
		{`{"op":"test","path":"/a","value":1}`, `{"a":1}`, true},
		{`{"op":"test","path":"/a","value":1}`, `{"a":2}`, false},
		{`{"op":"test","path":"/a","value":1}`, `{}`, false},
		{`{"op":"test","path":"/a","value":null}`, `{"a":null}`, true},
		{`{"op":"test","path":"/a","value":null}`, `{}`, false},
		{`{"op":"test","path":"","value":{"a":[1,2]}}`, `{"a":[1,2]}`, true},
		{`{"op":"test","path":"/a","exists":true}`, `{"a":null}`, true},
		{`{"op":"test","path":"/a","exists":true}`, `{}`, false},
		{`{"op":"test","path":"/a","exists":false}`, `{}`, true},
		{`{"op":"test","path":"/a","exists":false}`, `{"a":1}`, false},
		{`{"op":"test","path":"/a/b","exists":false}`, `{"a":5}`, true},
		{`{"op":"test","path":"/a","schema":{"type":"string","pattern":"^x"}}`, `{"a":"xy"}`, true},
		{`{"op":"test","path":"/a","schema":{"type":"string","pattern":"^x"}}`, `{"a":"y"}`, false},
		{`{"op":"test","path":"/a","schema":{"type":"string"}}`, `{}`, false},
		{`{"op":"test","path":"/a","schema":true}`, `{"a":1}`, true},
		{`{"op":"test","path":"/a","schema":false}`, `{"a":1}`, false},
		{`{"op":"test","path":"/a","schema":{"format":"email"}}`, `{"a":"nope"}`, false},
		{`{"op":"test","path":"/a","schema":{"format":"email"}}`, `{"a":"x@y.se"}`, true},
		{`{"op":"test","path":"/a","schema":{"$defs":{"s":{"type":"integer"}},"$ref":"#/$defs/s"}}`, `{"a":3}`, true},
	})
}

func TestWrites(t *testing.T) {
	run(t, []tc{
		{`{"op":"writes","covers":"/a/b"}`, `{"writes":["/a"]}`, true},
		{`{"op":"writes","covers":"/a/b"}`, `{"writes":["/a/b"]}`, true},
		{`{"op":"writes","covers":"/a/b"}`, `{"writes":["/a/b/c"]}`, false},
		{`{"op":"writes","covers":"/a"}`, `{"writes":["/ab"]}`, false},
		{`{"op":"writes","covers":"/a/b"}`, `{"writes":[]}`, false},
		{`{"op":"writes","covers":"/a/b"}`, `{}`, false},
		{`{"op":"writes","covers":"/a~1b"}`, `{"writes":["/a~1b"]}`, true},
		{`{"op":"writes","covers":"/a~1b"}`, `{"writes":["/a/b"]}`, false},
		{`{"op":"writes","covers":"/a/b"}`, `{"writes":["/a~1b"]}`, false},
		{`{"op":"writes","covers":"/x/y/z"}`, `{"writes":[""]}`, true},
		{`{"op":"writes","covers":""}`, `{"writes":["/a"]}`, false},
		{`{"op":"writes","covers":""}`, `{"writes":[""]}`, true},
		{`{"op":"writes","overlaps":"/a"}`, `{"writes":["/a/b"]}`, true},
		{`{"op":"writes","overlaps":"/a/b"}`, `{"writes":["/a"]}`, true},
		{`{"op":"writes","overlaps":"/a"}`, `{"writes":["/a"]}`, true},
		{`{"op":"writes","overlaps":"/a"}`, `{"writes":["/b","/ab"]}`, false},
		{`{"op":"writes","overlaps":"/a"}`, `{"writes":[""]}`, true},
		{`{"op":"writes","overlaps":"/a"}`, `{"writes":[]}`, false},
		{`{"op":"writes","within":["/i18n/sv"]}`, `{"writes":["/i18n/sv","/i18n/sv/x"]}`, true},
		{`{"op":"writes","within":["/i18n/sv"]}`, `{"writes":["/i18n"]}`, false},
		{`{"op":"writes","within":["/i18n/sv"]}`, `{"writes":["/i18n/sv","/other"]}`, false},
		{`{"op":"writes","within":["/a","/b"]}`, `{"writes":["/a/x","/b"]}`, true},
		{`{"op":"writes","within":["/a"]}`, `{"writes":[]}`, true},
		{`{"op":"writes","within":["/a"]}`, `{}`, true},
		{`{"op":"writes","within":[]}`, `{"writes":["/a"]}`, false},
		{`{"op":"writes","within":[""]}`, `{"writes":["/a",""]}`, true},
		{`{"op":"writes","within":["/a~1b"]}`, `{"writes":["/a~1b/c"]}`, true},
		{`{"op":"writes","within":["/a~1b"]}`, `{"writes":["/a/b"]}`, false},
	})
}

func TestCompare(t *testing.T) {
	run(t, []tc{
		{`{"op":"compare","path":"/a","eq":{"value":1}}`, `{"a":1}`, true},
		{`{"op":"compare","path":"/a","eq":{"value":1}}`, `{"a":"1"}`, false},
		{`{"op":"compare","path":"/a","eq":{"path":"/b"}}`, `{"a":{"x":1},"b":{"x":1}}`, true},
		{`{"op":"compare","path":"/a","eq":{"path":"/b"}}`, `{"a":1}`, false},
		{`{"op":"compare","path":"/a","eq":{"path":"/b"}}`, `{"b":1}`, false},
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":"se","b":["se","no"]}`, true},
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":"dk","b":["se","no"]}`, false},
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":"dk","b":"dk"}`, false},
		{`{"op":"compare","path":"/a","in":{"value":[1,2]}}`, `{"a":2}`, true},
		{`{"op":"compare","path":"/a","lt":{"value":2}}`, `{"a":1}`, true},
		{`{"op":"compare","path":"/a","lt":{"value":1}}`, `{"a":1}`, false},
		{`{"op":"compare","path":"/a","le":{"value":1}}`, `{"a":1}`, true},
		{`{"op":"compare","path":"/a","gt":{"value":1}}`, `{"a":1}`, false},
		{`{"op":"compare","path":"/a","ge":{"value":1}}`, `{"a":1}`, true},
		{`{"op":"compare","path":"/a","lt":{"value":"x"}}`, `{"a":1}`, false},
		{`{"op":"compare","path":"/a","lt":{"value":"b"}}`, `{"a":"a"}`, false}, // plain strings unsupported
		{`{"op":"compare","path":"/a","lt":{"value":true}}`, `{"a":false}`, false},
		{`{"op":"compare","path":"/a","lt":{"path":"/b"}}`, `{"a":"2026-01-01T10:00:00+02:00","b":"2026-01-01T09:00:00Z"}`, true}, // 08:00Z < 09:00Z
		{`{"op":"compare","path":"/a","gt":{"path":"/b"}}`, `{"a":"2026-01-01T10:00:00+02:00","b":"2026-01-01T09:00:00Z"}`, false},
		{`{"op":"compare","path":"/a","eq":{"path":"/b"}}`, `{"a":"2026-01-01T10:00:00+02:00","b":"2026-01-01T08:00:00Z"}`, false}, // eq is JSON equality
		{`{"op":"compare","path":"/a","le":{"path":"/b"}}`, `{"a":"2026-01-01T10:00:00+02:00","b":"2026-01-01T08:00:00Z"}`, true},
		{`{"op":"compare","path":"/a","ge":{"path":"/b"}}`, `{"a":"2026-01-01T10:00:00+02:00","b":"2026-01-01T08:00:00.000Z"}`, true},
		{`{"op":"compare","path":"/now","lt":{"path":"/doc/lockAt"}}`, `{"now":"2026-10-04T18:02:11.482Z","doc":{"lockAt":"2026-10-04T18:02:11.483Z"}}`, true},
		{`{"op":"compare","path":"/a","lt":{"path":"/b"}}`, `{"a":"2026-01-01T00:00:00Z","b":"garbage"}`, false},
	})
}

func TestCombinators(t *testing.T) {
	tr := `{"op":"test","path":"/a","exists":true}`
	fl := `{"op":"test","path":"/a","exists":false}`
	e := `{"a":1}`
	run(t, []tc{
		{`{"all":[]}`, e, true},
		{`{"any":[]}`, e, false},
		{`{"all":[` + tr + `,` + tr + `]}`, e, true},
		{`{"all":[` + tr + `,` + fl + `]}`, e, false},
		{`{"any":[` + fl + `,` + tr + `]}`, e, true},
		{`{"any":[` + fl + `,` + fl + `]}`, e, false},
		{`{"not":` + fl + `}`, e, true},
		{`{"not":` + tr + `}`, e, false},
		{`{"if":[` + tr + `],"then":[` + tr + `]}`, e, true},
		{`{"if":[` + tr + `],"then":[` + fl + `]}`, e, false},
		{`{"if":[` + fl + `],"then":[` + fl + `]}`, e, true},
		{`{"if":[],"then":[` + fl + `]}`, e, false},
		{`{"if":[` + tr + `],"then":[]}`, e, true},
	})
}

const examples = `[
  { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } }],
    "then": [{ "op": "test", "path": "/doc/$schema", "schema": { "type": "string", "pattern": "^/r/schemas/match/rev/" } }] },
  { "if":   [{ "not": { "op": "test", "path": "/action", "value": "create" } },
             { "op": "writes", "overlaps": "/$schema" }],
    "then": [{ "op": "test", "path": "/doc/$schema", "exists": true }] },
  { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["delete", "purge"] } }],
    "then": [{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "ops" } } }] },
  { "if":   [{ "op": "test", "path": "/action", "value": "append" }],
    "then": [{ "not": { "op": "writes", "covers": "" } }] }
]`

func TestSpecExamples(t *testing.T) {
	rs, err := CompileList(jsonv.MustParse([]byte(examples)))
	if err != nil || len(rs) != 4 {
		t.Fatal(err, len(rs))
	}
	cases := []struct {
		env  string
		idx  int
		path string
	}{
		{`{"action":"create","writes":[""],"doc":{"$schema":"/r/schemas/match/rev/1"}}`, -1, ""},
		{`{"action":"create","writes":[""],"doc":{"$schema":"/x"}}`, 0, "/doc/$schema"},
		{`{"action":"create","writes":[""],"doc":{}}`, 0, "/doc/$schema"},
		{`{"action":"append","writes":["/title"],"doc":{"$schema":"/r/schemas/match/rev/2"}}`, -1, ""},
		{`{"action":"append","writes":["/$schema"],"doc":{"$schema":"/r/schemas/match/rev/2"}}`, -1, ""},
		{`{"action":"delete","writes":[],"doc":null,"principal":{"groups":["ops"]}}`, -1, ""},
		{`{"action":"delete","writes":[],"doc":null,"principal":{"groups":["dev"]}}`, 2, "/principal/groups"},
		{`{"action":"purge","writes":[],"doc":null}`, 2, "/principal/groups"},
		{`{"action":"config","writes":[],"doc":{}}`, -1, ""},
		{`{"action":"append","writes":[""],"doc":{"$schema":"/r/schemas/match/rev/2"}}`, 3, ""},
		{`{"action":"restore","writes":["/a"],"doc":{"$schema":"/r/schemas/match/rev/2"}}`, -1, ""},
	}
	for i, x := range cases {
		idx, p, ok := EvalList(rs, env(x.env))
		if idx != x.idx || p != x.path || ok != (x.idx == -1) {
			t.Errorf("case %d: got (%d,%q,%v), want (%d,%q)", i, idx, p, ok, x.idx, x.path)
		}
	}
	// $schema removal on non-create (rule 1)
	_ = rs
	r := c(t, `{"if":[{"not":{"op":"test","path":"/action","value":"create"}},{"op":"writes","overlaps":"/$schema"}],"then":[{"op":"test","path":"/doc/$schema","exists":true}]}`)
	if r.Eval(env(`{"action":"append","writes":[""],"doc":{}}`)) {
		t.Error("removing $schema by root replace must fail")
	}
}

const ownership = `{ "if":   [{ "not": { "op": "test", "path": "/principal/roles", "schema": { "contains": { "const": "editor" } } } },
           { "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } }],
  "then": [{ "op": "compare", "path": "/doc/owner",  "eq": { "path": "/principal/id" } },
           { "op": "compare", "path": "/doc/region", "in": { "path": "/principal/attrs/regions" } },
           { "if":   [{ "not": { "op": "test", "path": "/action", "value": "create" } }],
             "then": [{ "not": { "op": "writes", "overlaps": "/owner" } },
                      { "not": { "op": "writes", "overlaps": "/lockAt" } }] },
           { "if":   [{ "op": "test", "path": "/doc/lockAt", "exists": true }],
             "then": [{ "op": "compare", "path": "/now", "lt": { "path": "/doc/lockAt" } }] }] }`

func TestOwnershipExample(t *testing.T) {
	r := c(t, ownership)
	p := `"principal":{"id":"u1","roles":["desk"],"attrs":{"regions":["se","no"]}}`
	cases := []tc{
		{"", `{"action":"create","writes":[""],` + p + `,"now":"2026-01-01T00:00:00Z","doc":{"owner":"u1","region":"se"}}`, true},
		{"", `{"action":"create","writes":[""],` + p + `,"now":"2026-01-01T00:00:00Z","doc":{"owner":"u2","region":"se"}}`, false},
		{"", `{"action":"create","writes":[""],` + p + `,"now":"2026-01-01T00:00:00Z","doc":{"owner":"u1","region":"dk"}}`, false},
		{"", `{"action":"append","writes":["/x"],` + p + `,"now":"2026-01-01T00:00:00Z","doc":{"owner":"u1","region":"no","lockAt":"2026-02-01T00:00:00Z"}}`, true},
		{"", `{"action":"append","writes":["/x"],` + p + `,"now":"2026-03-01T00:00:00Z","doc":{"owner":"u1","region":"no","lockAt":"2026-02-01T00:00:00Z"}}`, false},
		{"", `{"action":"append","writes":["/lockAt"],` + p + `,"now":"2026-01-01T00:00:00Z","doc":{"owner":"u1","region":"no"}}`, false},
		{"", `{"action":"append","writes":[""],` + p + `,"now":"2026-01-01T00:00:00Z","doc":{"owner":"u1","region":"no"}}`, false},
		{"", `{"action":"delete","writes":[""],` + p + `,"now":"2026-01-01T00:00:00Z","doc":null}`, true},
		{"", `{"action":"append","writes":["/owner"],"principal":{"id":"u9","roles":["editor"]},"doc":{"owner":"x"}}`, true},
	}
	for i, x := range cases {
		if got := r.Eval(env(x.env)); got != x.want {
			t.Errorf("case %d: got %v want %v", i, got, x.want)
		}
	}
	if !r.OnlyRefs("action", "principal", "writes", "doc", "now") {
		t.Errorf("refs: %v", r.Refs())
	}
}

func TestRefs(t *testing.T) {
	cases := []struct {
		rule string
		want map[string]bool
	}{
		{`{"op":"test","path":"/action","value":"x"}`, map[string]bool{"action": true}},
		{`{"op":"writes","covers":"/a"}`, map[string]bool{"writes": true}},
		{`{"op":"test","path":"","exists":true}`, map[string]bool{"*": true}},
		{`{"op":"compare","path":"/doc/a","eq":{"path":"/principal/id"}}`, map[string]bool{"doc": true, "principal": true}},
		{`{"op":"compare","path":"/now","lt":{"value":"2026-01-01T00:00:00Z"}}`, map[string]bool{"now": true}},
		{`{"not":{"all":[{"op":"test","path":"/resource","exists":true},{"if":[{"op":"writes","within":[]}],"then":[{"op":"test","path":"/patches/0","exists":true}]}]}}`,
			map[string]bool{"resource": true, "writes": true, "patches": true}},
		{`{"any":[]}`, map[string]bool{}},
	}
	for _, x := range cases {
		if got := c(t, x.rule).Refs(); !reflect.DeepEqual(got, x.want) {
			t.Errorf("%s: refs %v, want %v", x.rule, got, x.want)
		}
	}
	r := c(t, `{"op":"compare","path":"/action","eq":{"path":"/principal/id"}}`)
	if !r.OnlyRefs("action", "principal", "now") || r.OnlyRefs("action") {
		t.Error("OnlyRefs")
	}
	if c(t, `{"op":"test","path":"","exists":true}`).OnlyRefs("action", "doc") {
		t.Error("whole envelope must not be allowed")
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		`1`, `[]`, `null`, `{}`,
		`{"op":"nope"}`, `{"op":1}`,
		`{"op":"test","path":"/a"}`,
		`{"op":"test","path":"/a","value":1,"exists":true}`,
		`{"op":"test","path":"/a","exists":"yes"}`,
		`{"op":"test","path":"a","value":1}`,
		`{"op":"test","path":"/a~2","value":1}`,
		`{"op":"test","path":5,"value":1}`,
		`{"op":"test","value":1}`,
		`{"op":"test","path":"/a","value":1,"extra":1}`,
		`{"op":"test","path":"/a","schema":5}`,
		`{"op":"test","path":"/a","schema":{"type":"nonsense"}}`,
		`{"op":"test","path":"/a","schema":{"pattern":"(?=a)"}}`,
		`{"op":"test","path":"/a","schema":{"pattern":"(a)\\1"}}`,
		`{"op":"test","path":"/a","schema":{"patternProperties":{"(?!x)":{}}}}`,
		`{"op":"test","path":"/a","schema":{"format":"regex"}}`[:0] + `{"op":"test","path":"/a","schema":{"$ref":"https://example.com/s.json"}}`,
		`{"op":"writes"}`,
		`{"op":"writes","covers":"/a","overlaps":"/b"}`,
		`{"op":"writes","covers":"a"}`,
		`{"op":"writes","covers":1}`,
		`{"op":"writes","within":"/a"}`,
		`{"op":"writes","within":["/a",1]}`,
		`{"op":"writes","within":["x"]}`,
		`{"op":"writes","covers":"/a","path":"/a"}`,
		`{"op":"compare","path":"/a"}`,
		`{"op":"compare","path":"/a","eq":{"value":1},"lt":{"value":1}}`,
		`{"op":"compare","path":"/a","eq":{}}`,
		`{"op":"compare","path":"/a","eq":{"value":1,"path":"/b"}}`,
		`{"op":"compare","path":"/a","eq":{"path":"b"}}`,
		`{"op":"compare","path":"/a","eq":1}`,
		`{"op":"compare","path":"/a","eq":{"value":1,"x":1}}`,
		`{"op":"compare","path":"/a","in":{"value":3}}`,
		`{"op":"compare","path":"/a","zz":{"value":3}}`,
		`{"all":{}}`, `{"all":[1]}`, `{"all":[],"any":[]}`,
		`{"any":[{"op":"x"}]}`,
		`{"not":[]}`, `{"not":{"op":"x"}}`,
		`{"if":[]}`, `{"then":[]}`, `{"if":[],"then":[],"x":1}`, `{"if":{},"then":[]}`,
	}
	for _, s := range bad {
		if _, err := Compile(jsonv.MustParse([]byte(s))); err == nil {
			t.Errorf("expected error for %s", s)
		}
	}
	// lookahead message
	_, err := Compile(jsonv.MustParse([]byte(`{"op":"test","path":"/a","schema":{"pattern":"(?=a)"}}`)))
	if err == nil || !strings.Contains(err.Error(), "schema") {
		t.Errorf("lookahead err: %v", err)
	}
}

func TestCompileList(t *testing.T) {
	rs, err := CompileList(nil)
	if err != nil || len(rs) != 0 {
		t.Fatal(rs, err)
	}
	_, err = CompileList(jsonv.MustParse([]byte(`[{"all":[]},{"op":"bogus"}]`)))
	if err == nil || !strings.Contains(err.Error(), "1") {
		t.Errorf("want index in error: %v", err)
	}
	if _, err := CompileList("x"); err == nil {
		t.Error("non-array")
	}
	if i, p, ok := EvalList(nil, env(`{}`)); i != -1 || p != "" || !ok {
		t.Error("empty list passes")
	}
}

func TestFailPath(t *testing.T) {
	rs, _ := CompileList(jsonv.MustParse([]byte(`[
	 {"op":"test","path":"/a","exists":false},
	 {"all":[{"op":"test","path":"/a","exists":true},{"op":"compare","path":"/b","eq":{"value":1}}]},
	 {"not":{"op":"writes","covers":"/z"}},
	 {"op":"writes","within":["/ok"]},
	 {"any":[{"op":"test","path":"/q","exists":true}]}]`)))
	e := env(`{"a":1,"b":2,"writes":["/z"]}`)
	want := []string{"/a", "/b", "/z", "/z", ""}
	for i, r := range rs {
		if r.Eval(e) {
			t.Fatalf("rule %d should fail", i)
		}
		if got := r.n.failPath(e); got != want[i] {
			t.Errorf("rule %d failPath %q want %q", i, got, want[i])
		}
	}
	if i, _, ok := EvalList(rs, env(`{}`)); i != 1 || ok {
		t.Error("first failing index")
	}
}

func TestRefPaths(t *testing.T) {
	cases := []struct{ rule, want string }{
		{`{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"x"}}}`, "/principal/groups"},
		{`{"op":"test","path":"","exists":true}`, ""},
		{`{"op":"compare","path":"/doc/a","eq":{"path":"/principal/id"}}`, "/doc/a /principal/id"},
		{`{"not":{"all":[{"op":"test","path":"/resource","exists":true},{"if":[{"op":"writes","within":[]}],"then":[{"op":"test","path":"/patches/0","exists":true}]}]}}`,
			"/resource /writes /patches/0"},
		{`{"any":[]}`, ""},
	}
	for _, x := range cases {
		var got []string
		for _, p := range c(t, x.rule).RefPaths() {
			got = append(got, p.String())
		}
		if strings.Join(got, " ") != x.want {
			t.Errorf("%s: paths %q, want %q", x.rule, got, x.want)
		}
	}
}
