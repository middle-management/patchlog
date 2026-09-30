package annot

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

var pathRefs = "/r/s/refs/rev/" + rev('d')

func init() {
	store[pathRefs] = `{` + d2020 + `,
		"type": "object",
		"properties": {
			"$schema": {"type": "string"},
			"hero":    { "type": "string", "x-ref": { "pinned": true } },
			"related": { "type": "array", "items": { "type": "string", "x-ref": {} } },
			"trigger": { "type": "string", "x-ref": { "key": "/triggers" } }
		}
	}`
}

func shortRefs(rs []Ref) []string {
	var out []string
	for _, r := range rs {
		out = append(out, fmt.Sprintf("%s %s/%s rev=%q entry=%q key=%q pinned=%v", r.Pointer, r.NS, r.Name, r.Rev, r.Entry, r.Key, r.Pinned))
	}
	return out
}

func TestFindRefsSpecExamples(t *testing.T) {
	photo := "/r/media/photo-12/rev/" + rev('q')
	frag := url.PathEscape("t 42/x") // "t%2042%2Fx"
	doc := j(`{"$schema":"` + pathRefs + `","hero":"` + photo + `",
		"related":["/r/matches/cup","not a ref","/r/matches/final"],
		"trigger":"/r/doors/layout-7#` + frag + `"}`)
	got, err := FindRefs(doc, loader)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`/hero media/photo-12 rev="` + rev('q') + `" entry="" key="" pinned=true`,
		`/related/0 matches/cup rev="" entry="" key="" pinned=false`,
		`/related/2 matches/final rev="" entry="" key="" pinned=false`,
		`/trigger doors/layout-7 rev="" entry="t 42/x" key="/triggers" pinned=false`,
	}
	if g, w := strings.Join(shortRefs(got), "\n"), strings.Join(want, "\n"); g != w {
		t.Fatalf("got:\n%s\nwant:\n%s", g, w)
	}
	if got[3].Raw != "/r/doors/layout-7#"+frag || got[3].SchemaPath != pathRefs+"#/properties/trigger" {
		t.Errorf("trigger: %+v", got[3])
	}
	// The trigger resolves by id in the target document.
	layout := j(`{"triggers":[{"id":"t 41"},{"id":"t 42/x","at":3}]}`)
	if e, ok := ResolveEntry(layout, got[3].Key, got[3].Entry); !ok || !jsonv.Equal(e, j(`{"id":"t 42/x","at":3}`)) {
		t.Errorf("resolve: %v %v", e, ok)
	}
}

func TestFindRefsWith(t *testing.T) {
	cases := []struct {
		name, schema, doc string
		want              []string
	}{
		{
			name: "failing anyOf branch still counts",
			schema: `{"properties":{"v":{"anyOf":[
				{"type":"number"},
				{"type":"string","minLength":1000,"x-ref":{}}]}}}`,
			doc:  `{"v":"/r/a/b"}`,
			want: []string{`/v a/b rev="" entry="" key="" pinned=false`},
		},
		{
			name:   "invalid document still walked",
			schema: `{"type":"object","required":["missing"],"properties":{"v":{"type":"number","x-ref":{"pinned":true}}}}`,
			doc:    `{"v":"/r/a/b"}`,
			want:   []string{`/v a/b rev="" entry="" key="" pinned=true`},
		},
		{
			name: "recursive schema",
			schema: `{"$ref":"#/$defs/node","$defs":{"node":{"properties":{
				"link":{"x-ref":{}},"kids":{"items":{"$ref":"#/$defs/node"}}}}}}`,
			doc: `{"link":"/r/n/root","kids":[{"link":"/r/n/c1","kids":[{"link":"/r/n/g"}]},{"link":"nope"}]}`,
			want: []string{
				`/kids/0/kids/0/link n/g rev="" entry="" key="" pinned=false`,
				`/kids/0/link n/c1 rev="" entry="" key="" pinned=false`,
				`/link n/root rev="" entry="" key="" pinned=false`,
			},
		},
		{
			name: "every if/then/else and oneOf branch",
			schema: `{"if":{"properties":{"a":{"x-ref":{}}}},"then":{"properties":{"b":{"x-ref":{}}}},
				"else":{"properties":{"c":{"x-ref":{}}}},
				"oneOf":[{"properties":{"d":{"x-ref":{"key":"/k"}}}},{"properties":{"d":{"x-ref":{}}}}]}`,
			doc: `{"a":"/r/x/a","b":"/r/x/b","c":"/r/x/c","d":"/r/x/d#e"}`,
			want: []string{
				`/a x/a rev="" entry="" key="" pinned=false`,
				`/b x/b rev="" entry="" key="" pinned=false`,
				`/c x/c rev="" entry="" key="" pinned=false`,
				`/d x/d rev="" entry="e" key="/k" pinned=false`,
				`/d x/d rev="" entry="e" key="" pinned=false`,
			},
		},
		{
			name:   "non-string and non-ref values ignored",
			schema: `{"additionalProperties":{"x-ref":{}}}`,
			doc:    `{"a":1,"b":"/r/UP/x","c":{"x":"/r/a/b"},"d":"/r/a/b"}`,
			want:   []string{`/d a/b rev="" entry="" key="" pinned=false`},
		},
		{
			name:   "cycle without instance progress",
			schema: `{"$defs":{"a":{"$ref":"#/$defs/b","x-ref":{}},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`,
			doc:    `"/r/a/b"`,
			want:   []string{` a/b rev="" entry="" key="" pinned=false`},
		},
		{
			name:   "contains and patternProperties",
			schema: `{"patternProperties":{"^l":{"contains":{"x-ref":{}}}}}`,
			doc:    `{"list":[1,"/r/a/b"]}`,
			want:   []string{`/list/1 a/b rev="" entry="" key="" pinned=false`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FindRefsWith(j(tc.schema), "", j(tc.doc), loader)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := strings.Join(shortRefs(got), "\n"), strings.Join(tc.want, "\n"); g != w {
				t.Errorf("got:\n%s\nwant:\n%s", g, w)
			}
		})
	}
}

func TestFindRefsUntyped(t *testing.T) {
	for _, d := range []string{`{"a":"/r/a/b"}`, `"x"`, `{` + d2020 + `}`} {
		got, err := FindRefs(j(d), loader)
		if err != nil || got != nil {
			t.Errorf("%s: %v %v", d, got, err)
		}
	}
}

func TestParseRefString(t *testing.T) {
	id := rev('k')
	cases := []struct {
		in                  string
		ok                  bool
		ns, name, rv, entry string
	}{
		{"/r/a/b", true, "a", "b", "", ""},
		{"/r/my-ns/name.v2_x", true, "my-ns", "name.v2_x", "", ""},
		{"/r/a/b/rev/" + id, true, "a", "b", id, ""},
		{"/r/a/b/rev/" + id + "#t-42", true, "a", "b", id, "t-42"},
		{"/r/a/b#t%2042%2Fx", true, "a", "b", "", "t 42/x"},
		{"/r/a/b#t%2042/x", true, "a", "b", "", "t 42/x"},
		{"/r/a/b#%C3%A9", true, "a", "b", "", "é"},
		{"/r/a/b#", false, "", "", "", ""},
		{"/r/a/b#t 42", false, "", "", "", ""},
		{"/r/a/b#a#b", false, "", "", "", ""},
		{"/r/a/b#%zz", false, "", "", "", ""},
		{"/r/a/b#%2", false, "", "", "", ""},
		{"/r/A/b", false, "", "", "", ""},
		{"/r/a.b/c", false, "", "", "", ""},
		{"/r/-a/b", false, "", "", "", ""},
		{"/r/a/.b", false, "", "", "", ""},
		{"/r/a/b/c", false, "", "", "", ""},
		{"/r/a/b/", false, "", "", "", ""},
		{"/r/a", false, "", "", "", ""},
		{"/r/a/b/rev/" + id[:32], false, "", "", "", ""},
		{"/r/a/b/rev/2" + id[1:], false, "", "", "", ""},
		{"/r/a/b/rev/" + strings.ToUpper(id), false, "", "", "", ""},
		{"/r/a/b/log", false, "", "", "", ""},
		{"/r/a/" + strings.Repeat("n", 129), false, "", "", "", ""},
		{"/r/" + strings.Repeat("n", 65) + "/b", false, "", "", "", ""},
		{"https://x/r/a/b", false, "", "", "", ""},
		{" /r/a/b", false, "", "", "", ""},
	}
	for _, tc := range cases {
		r, ok := ParseRefString(tc.in)
		if ok != tc.ok {
			t.Errorf("%q: ok=%v", tc.in, ok)
			continue
		}
		if ok && (r.NS != tc.ns || r.Name != tc.name || r.Rev != tc.rv || r.Entry != tc.entry || r.Raw != tc.in) {
			t.Errorf("%q: %+v", tc.in, r)
		}
	}
}

func TestResolveEntry(t *testing.T) {
	arr := j(`{"triggers":[{"id":"a","v":1},{"id":7},"x",{"id":"b","v":2}]}`)
	obj := j(`{"m":{"by":{"a":{"v":1},"b/c":{"v":2}}}}`)
	cases := []struct {
		target  any
		key, id string
		ok      bool
		want    string
	}{
		{arr, "/triggers", "b", true, `{"id":"b","v":2}`},
		{arr, "/triggers", "a", true, `{"id":"a","v":1}`},
		{arr, "/triggers", "7", false, ``},  // non-string id
		{arr, "/triggers", "1", false, ``},  // never by position
		{arr, "/triggers", "zz", false, ``}, // dangling
		{arr, "/missing", "a", false, ``},
		{arr, "bad", "a", false, ``},
		{obj, "/m/by", "b/c", true, `{"v":2}`},
		{obj, "/m/by", "a", true, `{"v":1}`},
		{obj, "/m/by", "c", false, ``},
		{obj, "/m/by/a/v", "x", false, ``}, // not a container
		{j(`{"a":1}`), "", "a", true, `1`},
	}
	for _, tc := range cases {
		e, ok := ResolveEntry(tc.target, tc.key, tc.id)
		if ok != tc.ok || (ok && !jsonv.Equal(e, j(tc.want))) {
			t.Errorf("%s %q: %v %v", tc.key, tc.id, e, ok)
		}
	}
}
