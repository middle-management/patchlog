package release

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

const id1 = "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func parse(t *testing.T, s string) (*Doc, error) {
	t.Helper()
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return Parse(v)
}

func TestParse(t *testing.T) {
	d, err := parse(t, `{ "name": "release-7", "at": "`+id1+`",
	  "branches": { "matches": { "ns": "matches-r7", "at": "`+id1+`" },
	                "cat-season": { "ns": "cat-season-r7" },
	                "schemas": { "ns": "schemas-r7", "at": "`+id1+`" } },
	  "on": "/r/releases/release-6/rev/`+id1+`",
	  "owners": ["user:anna"], "x-note": "kept" }`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Keys(), ",") != "cat-season,matches,schemas" || strings.Join(d.BranchNames(), ",") != "cat-season-r7,matches-r7,schemas-r7" {
		t.Fatalf("keys %v %v", d.Keys(), d.BranchNames())
	}
	if d.KeyOf("matches-r7") != "matches" || d.KeyOf("nope") != "" || d.Aliases()["schemas"] != "schemas-r7" {
		t.Fatal("lookups")
	}
	// Round trip, unknown fields kept.
	b, _ := json.Marshal(d)
	v, _ := jsonv.Parse(b)
	d2, err := Parse(v)
	if err != nil || d2.Extra["x-note"] != "kept" || d2.On != d.On || len(d2.Branches) != 3 {
		t.Fatalf("round trip: %v %+v", err, d2)
	}

	for _, bad := range []string{
		`{ "name": "r", "branches": {} }`,
		`{ "name": "R 7", "branches": { "a": { "ns": "a-r" } } }`,
		`{ "name": "r", "branches": { "a": { "ns": "a" } } }`,
		`{ "name": "r", "branches": { "a": { "ns": "x" }, "b": { "ns": "x" } } }`,
		`{ "name": "r", "branches": { "a": { "ns": "a-r", "at": "nope" } } }`,
		`{ "name": "r", "branches": { "a": "a-r" } }`,
		`{ "name": "r", "branches": { "a": { "ns": "a-r" } }, "on": "release-6" }`,
		`{ "name": "r", "branches": { "a": { "ns": "a-r" } }, "owners": [1] }`,
		`[]`,
	} {
		if _, err := parse(t, bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseRef(t *testing.T) {
	for in, want := range map[string]Ref{
		"/r/releases/release-7":                       {NS: "releases", Name: "release-7"},
		"/r/releases/release-7/rev/" + id1:            {NS: "releases", Name: "release-7", Rev: id1},
		"https://cms.example/r/releases/release-7":    {NS: "releases", Name: "release-7"},
		"https://cms.example/r/releases/r/rev/" + id1: {NS: "releases", Name: "r", Rev: id1},
	} {
		got, err := ParseRef(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"releases/release-7", "/r/Releases/x", "/r/releases/x/rev/abc", "https://h"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	r := Ref{NS: "releases", Name: "r", Rev: id1}
	if r.String() != "/r/releases/r/rev/"+id1 || r.Live() != "/r/releases/r" {
		t.Fatal(r.String())
	}
}
