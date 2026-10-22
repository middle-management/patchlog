package rules

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// GB-9 (§6.4.3): a failing namespace rule's path points at the failing rule
// form in the namespace document: /rules/{i}, descending only through the
// first failing member of an all (/all/{k}) or a then (/then/{k}); any,
// not, test, writes and compare stop at themselves.
func TestV073P20RuleFormPath(t *testing.T) {
	t.Parallel()
	pass := `{"op":"test","path":"/a","exists":true}`
	fail := `{"op":"test","path":"/a","exists":false}`
	rs, err := CompileList(jsonv.MustParse([]byte(`[
	 ` + pass + `,
	 {"all":[` + pass + `,{"if":[` + pass + `],"then":[` + pass + `,` + fail + `]}]},
	 {"all":[` + fail + `,` + fail + `]},
	 {"any":[` + fail + `,{"all":[` + fail + `]}]},
	 {"not":{"all":[` + pass + `]}},
	 {"if":[` + pass + `],"then":[{"not":` + pass + `},` + fail + `]},
	 {"op":"writes","within":["/ok"]},
	 {"op":"compare","path":"/a","eq":{"value":2}},
	 ` + fail + `]`)))
	if err != nil {
		t.Fatal(err)
	}
	e := env(`{"a":1,"writes":["/z"]}`)
	want := []string{"", "/rules/1/all/1/then/1", "/rules/2/all/0", "/rules/3", "/rules/4",
		"/rules/5/then/0", "/rules/6", "/rules/7", "/rules/8"}
	for i := 1; i < len(rs); i++ {
		idx, path, ok := EvalList(rs[i:], e)
		if ok || idx != 0 || path != want[i] {
			t.Errorf("rule %d: EvalList = (%d, %q, %v), want (0, %q, false)", i, idx, path, ok, want[i])
		}
		// A rule CompileList compiled keeps its index when evaluated
		// alone, as step 6 of a sealed write does rule by rule.
		if _, path, _ := EvalList([]*Rule{rs[i]}, e); path != want[i] {
			t.Errorf("rule %d alone: path %q, want %q", i, path, want[i])
		}
	}
	if idx, path, ok := EvalList(rs, e); idx != 1 || path != want[1] || ok {
		t.Errorf("EvalList = (%d, %q, %v)", idx, path, ok)
	}
	// Rules compiled one by one are numbered by their place in the list.
	lone := []*Rule{c(t, pass), c(t, `{"all":[`+fail+`]}`)}
	if idx, path, _ := EvalList(lone, e); idx != 1 || path != "/rules/1/all/0" {
		t.Errorf("Compile'd rules: (%d, %q)", idx, path)
	}
}

// GB-10 (§6.4.2): in is false when the right-hand side isn't an array,
// a literal or a path alike; the rule is valid.
func TestV073P20CompareInNotArray(t *testing.T) {
	t.Parallel()
	run(t, []tc{
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":"x","b":"x"}`, false},
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":{"x":1},"b":{"x":1}}`, false},
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":null,"b":null}`, false},
		{`{"op":"compare","path":"/a","in":{"value":"x"}}`, `{"a":"x"}`, false},
		{`{"op":"compare","path":"/a","in":{"path":"/b"}}`, `{"a":"x","b":["y","x"]}`, true},
	})
}

// GB-11 (§6.4.2): lt, le, gt and ge compare RFC 3339 date-times as
// instants at the full precision of their fractional seconds; a leap
// second is of an unsupported type, so is a lowercase t or z (F-G5).
func TestV073P20CompareDateTimes(t *testing.T) {
	t.Parallel()
	cmp := func(op, a, b string) string {
		return `{"op":"compare","path":"/a","` + op + `":{"value":"` + b + `"}}`
	}
	a := func(s string) string { return `{"a":"` + s + `"}` }
	run(t, []tc{
		// Beyond nanoseconds.
		{cmp("lt", "", "2026-01-01T00:00:00.0000000002Z"), a("2026-01-01T00:00:00.0000000001Z"), true},
		{cmp("gt", "", "2026-01-01T00:00:00.0000000002Z"), a("2026-01-01T00:00:00.0000000001Z"), false},
		{cmp("lt", "", "2026-01-01T00:00:00.000000000000000000000000000002Z"), a("2026-01-01T00:00:00.000000000000000000000000000001Z"), true},
		{cmp("lt", "", "2026-01-01T00:00:00.12Z"), a("2026-01-01T00:00:00.119999999999999999Z"), true},
		// Trailing zeros and an absent fraction are the same instant.
		{cmp("le", "", "2026-01-01T00:00:00Z"), a("2026-01-01T00:00:00.000000000000Z"), true},
		{cmp("ge", "", "2026-01-01T00:00:00Z"), a("2026-01-01T00:00:00.000000000000Z"), true},
		{cmp("lt", "", "2026-01-01T00:00:00.5Z"), a("2026-01-01T00:00:00.50000000000Z"), false},
		// Offsets name the same instant in UTC, across a day and a year.
		{cmp("le", "", "2026-01-01T11:00:00Z"), a("2026-01-01T12:00:00+01:00"), true},
		{cmp("ge", "", "2026-01-01T11:00:00Z"), a("2026-01-01T12:00:00+01:00"), true},
		{cmp("lt", "", "2026-01-01T00:30:00+01:00"), a("2025-12-31T23:59:59.999999999999-00:01"), false},
		{cmp("gt", "", "2026-01-01T00:00:00Z"), a("2025-12-31T23:30:00.000000000001-00:30"), true},
		{cmp("lt", "", "2024-02-29T00:00:00Z"), a("2024-02-28T23:59:59Z"), true},
		// A leap second is unsupported, on either side.
		{cmp("lt", "", "2017-01-01T00:00:00Z"), a("2016-12-31T23:59:60Z"), false},
		{cmp("ge", "", "2017-01-01T00:00:00Z"), a("2016-12-31T23:59:60Z"), false},
		{cmp("gt", "", "2016-12-31T23:59:60Z"), a("2017-01-01T00:00:00Z"), false},
		{cmp("le", "", "2016-12-31T23:59:60Z"), a("2017-01-01T00:00:00Z"), false},
		// Lowercase t and z, and a space, are unsupported (F-G5).
		{cmp("lt", "", "2026-01-02T00:00:00Z"), a("2026-01-01t00:00:00Z"), false},
		{cmp("lt", "", "2026-01-02T00:00:00Z"), a("2026-01-01T00:00:00z"), false},
		{cmp("lt", "", "2026-01-02T00:00:00Z"), a("2026-01-01 00:00:00Z"), false},
		// Not date-times: dates that don't exist, missing parts.
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-29T00:00:00Z"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-30T00:00:00Z"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-01T24:00:00Z"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-01T00:00:00."), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-01T00:00:00"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-01T00:00:00+0100"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-01T00:00:00+24:00"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("2026-02-01"), false},
		{cmp("lt", "", "2026-03-01T00:00:00Z"), a("+2026-02-01T00:00:00Z"), false},
	})
}

// GB-15 (§6.2 End-to-end namespaces): EvalTri leaves writes predicates and
// /writes and /doc paths unknown, and combines all, any, not and if in
// Kleene logic, so only a rule whose outcome depends on them is Unknown.
func TestV073P20EvalTri(t *testing.T) {
	t.Parallel()
	create := `{"action":"create","resource":"r","principal":{"id":"u1","groups":["ops"]},"now":"2026-01-01T00:00:00Z","writes":[],"doc":null,"patches":[]}`
	cases := []struct {
		rule string
		want Tri
	}{
		{`{"if":[{"op":"test","path":"/action","value":"delete"}],"then":[{"op":"test","path":"/doc/x","exists":true}]}`, True},
		{`{"if":[{"op":"test","path":"/action","value":"create"}],"then":[{"op":"test","path":"/doc/x","exists":true}]}`, Unknown},
		{`{"op":"test","path":"/doc/x","exists":true}`, Unknown},
		{`{"op":"test","path":"/doc/x","exists":false}`, Unknown},
		{`{"op":"test","path":"/doc","value":null}`, Unknown},
		{`{"op":"test","path":"/writes/0","exists":false}`, Unknown},
		// The members themselves are there whatever they hold.
		{`{"op":"test","path":"/doc","exists":true}`, True},
		{`{"op":"test","path":"/writes","exists":false}`, False},
		{`{"op":"test","path":"","exists":true}`, True},
		{`{"op":"test","path":"","schema":{"type":"object"}}`, Unknown},
		{`{"op":"writes","within":["/a"]}`, Unknown},
		{`{"op":"writes","covers":""}`, Unknown},
		{`{"any":[{"op":"test","path":"/action","value":"create"},{"op":"writes","within":["/a"]}]}`, True},
		{`{"any":[{"op":"test","path":"/action","value":"append"},{"op":"writes","within":["/a"]}]}`, Unknown},
		{`{"all":[{"op":"test","path":"/principal/id","value":"u1"},{"op":"writes","within":["/a"]}]}`, Unknown},
		{`{"all":[{"op":"test","path":"/principal/id","value":"u2"},{"op":"writes","within":["/a"]}]}`, False},
		{`{"all":[{"op":"writes","within":["/a"]},{"op":"test","path":"/principal/id","value":"u2"}]}`, False},
		{`{"not":{"op":"writes","overlaps":"/owner"}}`, Unknown},
		{`{"not":{"op":"test","path":"/action","value":"create"}}`, False},
		{`{"if":[{"op":"writes","overlaps":"/a"}],"then":[{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"ops"}}}]}`, True},
		{`{"if":[{"op":"writes","overlaps":"/a"}],"then":[{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"dev"}}}]}`, Unknown},
		{`{"if":[{"op":"test","path":"/action","value":"create"}],"then":[{"op":"writes","within":["/a"]},{"op":"test","path":"/resource","value":"s"}]}`, False},
		{`{"if":[],"then":[]}`, True},
		// A compare is decided by a known operand that makes it false
		// whatever the other holds, and is otherwise unknown.
		{`{"op":"compare","path":"/doc/region","in":{"value":"se"}}`, False},
		{`{"op":"compare","path":"/doc/region","in":{"path":"/resource"}}`, False},
		{`{"op":"compare","path":"/doc/region","in":{"path":"/principal/groups"}}`, Unknown},
		{`{"op":"compare","path":"/doc/n","lt":{"value":true}}`, False},
		{`{"op":"compare","path":"/doc/n","lt":{"value":"tomorrow"}}`, False},
		{`{"op":"compare","path":"/doc/n","lt":{"value":3}}`, Unknown},
		{`{"op":"compare","path":"/now","lt":{"path":"/doc/lockAt"}}`, Unknown},
		{`{"op":"compare","path":"/principal","lt":{"path":"/doc/lockAt"}}`, False},
		{`{"op":"compare","path":"/missing","eq":{"path":"/doc/owner"}}`, False},
		{`{"op":"compare","path":"/doc/owner","eq":{"path":"/principal/id"}}`, Unknown},
		{`{"op":"compare","path":"/principal/id","eq":{"value":"u1"}}`, True},
	}
	for i, x := range cases {
		r := c(t, x.rule)
		if got := r.EvalTri(env(create), "writes", "doc"); got != x.want {
			t.Errorf("case %d: %s = %v, want %v", i, x.rule, got, x.want)
		}
	}
	// A delete's writes are known ([]); only its doc is hidden.
	del := env(`{"action":"delete","resource":"r","writes":[],"doc":null}`)
	if got := c(t, `{"op":"writes","within":["/a"]}`).EvalTri(del, "doc"); got != True {
		t.Errorf("writes within on a delete with doc hidden: %v", got)
	}
	if got := c(t, `{"op":"test","path":"/doc/x","exists":false}`).EvalTri(del, "doc"); got != Unknown {
		t.Errorf("a /doc test on a delete with doc hidden: %v", got)
	}

	// The list form: the first rule that isn't True, the failing form's
	// path for False, the rule's own for Unknown (it fails as a whole).
	rs, err := CompileList(jsonv.MustParse([]byte(`[
	  {"if":[{"op":"test","path":"/action","value":"delete"}],"then":[{"op":"test","path":"/doc/x","exists":true}]},
	  {"all":[{"op":"writes","within":["/a"]},{"if":[{"op":"test","path":"/action","value":"create"}],"then":[{"op":"test","path":"/resource","value":"s"}]}]},
	  {"op":"test","path":"/doc/x","exists":true}]`)))
	if err != nil {
		t.Fatal(err)
	}
	if i, path, v := EvalTri(rs, env(create), "writes", "doc"); i != 1 || path != "/rules/1/all/1/then/0" || v != False {
		t.Errorf("EvalTri = (%d, %q, %v), want (1, /rules/1/all/1/then/0, false)", i, path, v)
	}
	if i, path, v := EvalTri(rs[2:], env(create), "writes", "doc"); i != 0 || path != "/rules/2" || v != Unknown {
		t.Errorf("EvalTri unknown = (%d, %q, %v), want (0, /rules/2, unknown)", i, path, v)
	}
	if i, path, v := EvalTri(rs[:1], env(create), "writes", "doc"); i != -1 || path != "" || v != True {
		t.Errorf("EvalTri pass = (%d, %q, %v)", i, path, v)
	}
}

// With nothing unknown, EvalTri is Eval, and EvalTri's list form is
// EvalList.
func TestV073P20EvalTriKnown(t *testing.T) {
	t.Parallel()
	e := env(`{"action":"append","principal":{"id":"u1","roles":["desk"],"attrs":{"regions":["se"]}},"now":"2026-01-01T00:00:00Z","writes":["/x"],"doc":{"owner":"u1","region":"se","lockAt":"2025-01-01T00:00:00Z"}}`)
	for _, s := range []string{ownership, `{"op":"writes","within":["/x"]}`, `{"not":{"op":"writes","covers":""}}`,
		`{"any":[{"op":"test","path":"/doc/owner","value":"u2"}]}`, `{"if":[],"then":[{"op":"test","path":"/doc","exists":false}]}`} {
		r := c(t, s)
		if got, want := r.EvalTri(e), tri(r.Eval(e)); got != want {
			t.Errorf("%s: EvalTri %v, Eval %v", s, got, want)
		}
	}
	rs, _ := CompileList(jsonv.MustParse([]byte(examples)))
	for _, s := range []string{
		`{"action":"create","writes":[""],"doc":{}}`,
		`{"action":"delete","writes":[],"doc":null,"principal":{"groups":["dev"]}}`,
		`{"action":"append","writes":[""],"doc":{"$schema":"/r/schemas/match/rev/2"}}`,
		`{"action":"append","writes":["/title"],"doc":{"$schema":"/r/schemas/match/rev/2"}}`,
	} {
		i, p, ok := EvalList(rs, env(s))
		j, q, v := EvalTri(rs, env(s))
		if i != j || p != q || tri(ok) != v {
			t.Errorf("%s: EvalList (%d, %q, %v), EvalTri (%d, %q, %v)", s, i, p, ok, j, q, v)
		}
	}
}
