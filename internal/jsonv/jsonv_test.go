package jsonv

import (
	"math"
	"testing"
)

func TestFormatNumber(t *testing.T) {
	cases := map[float64]string{
		0:                       "0",
		math.Copysign(0, -1):    "0",
		1:                       "1",
		-1:                      "-1",
		1.5:                     "1.5",
		100:                     "100",
		1e21:                    "1e+21",
		1e20:                    "100000000000000000000",
		123e-20:                 "1.23e-18",
		0.000001:                "0.000001",
		0.0000001:               "1e-7",
		9007199254740991:        "9007199254740991",
		4.50:                    "4.5",
		2e-3:                    "0.002",
		1.7976931348623157e308:  "1.7976931348623157e+308",
		5e-324:                  "5e-324",
		333333333.3333333:       "333333333.3333333",
		-1.2345678901234568e-10: "-1.2345678901234568e-10",
	}
	for f, want := range cases {
		if got := FormatNumber(f); got != want {
			t.Errorf("FormatNumber(%v) = %q, want %q", f, got, want)
		}
	}
}

func TestCanonical(t *testing.T) {
	// RFC 8785 §3.2.2 example (subset).
	in := `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(Canonical(v)); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	// Key ordering by UTF-16 code units.
	v, _ = Parse([]byte(`{"€":1,"😀":2,"a":3,"\u0080":4}`))
	if got, want := string(Canonical(v)), "{\"a\":3,\"\u0080\":4,\"\u20ac\":1,\"\U0001F600\":2}"; got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,
		`"\ud800"`,
		`"\udc00"`,
		`"\ud800A"`,
		"\"\xff\"",
		`1e400`,
		`9007199254740992`,
		`-9007199254740992`,
		`NaN`,
		`[1,]`,
		`01`,
		`1 2`,
		"\"a\x01\"",
		``,
	}
	for _, s := range bad {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
	good := []string{`9007199254740991`, `1e300`, `-0`, `"😀"`, ` {"a":[1,{"b":null}]} `}
	for _, s := range good {
		if _, err := Parse([]byte(s)); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
}

func TestEqual(t *testing.T) {
	a := MustParse([]byte(`{"a":[1,2,{"b":1.0}],"c":null}`))
	b := MustParse([]byte(`{"c":null,"a":[1,2,{"b":1}]}`))
	if !Equal(a, b) {
		t.Error("expected equal")
	}
	if Equal(MustParse([]byte(`[1,2]`)), MustParse([]byte(`[2,1]`))) {
		t.Error("arrays are ordered")
	}
}
