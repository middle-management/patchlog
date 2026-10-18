package files

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func render(t *testing.T, text string) string {
	t.Helper()
	v, err := jsonv.Parse([]byte(text))
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return string(Rendering(v))
}

// §H.1: the rendering lays out the canonical text as JSON.stringify(v,
// null, 2) does, with JCS's tokens and member order.
func TestRendering(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		// Keys that look like array indices keep JCS's order (UTF-16 code
		// units), where JSON.stringify of a parsed object would put "2"
		// and "10" first, as integers.
		`{"b":1,"a":2,"10":3,"2":4,"-1":5,"01":6}`: "{\n  \"-1\": 5,\n  \"01\": 6,\n  \"10\": 3,\n  \"2\": 4,\n  \"a\": 2,\n  \"b\": 1\n}\n",
		// Escapes as JCS writes them: control characters as \u00xx, the
		// short forms, and everything else, U+2028 and astral characters
		// included, as itself; structural characters inside strings and
		// escaped quotes and backslashes don't lay anything out.
		`{"s":"\u001f\n\"\\\u00e9\u2028😀","t":"{[,:]}","u":"a\\","v":"\\\""}`: "{\n  \"s\": \"\\u001f\\n\\\"\\\\é\u2028😀\",\n  \"t\": \"{[,:]}\",\n  \"u\": \"a\\\\\",\n  \"v\": \"\\\\\\\"\"\n}\n",
		// Numbers as ECMAScript writes them.
		`[1e21,0.1,-0,1.5e-7,100,1E2,123456789012345,-2.5]`: "[\n  1e+21,\n  0.1,\n  0,\n  1.5e-7,\n  100,\n  100,\n  123456789012345,\n  -2.5\n]\n",
		// Empty containers stay {} and [].
		`{"a":{},"b":[],"c":[{}],"d":[[]],"e":{"f":{}}}`: "{\n  \"a\": {},\n  \"b\": [],\n  \"c\": [\n    {}\n  ],\n  \"d\": [\n    []\n  ],\n  \"e\": {\n    \"f\": {}\n  }\n}\n",
		`[[1,[2,[]]],[],[[[true]]]]`:                     "[\n  [\n    1,\n    [\n      2,\n      []\n    ]\n  ],\n  [],\n  [\n    [\n      [\n        true\n      ]\n    ]\n  ]\n]\n",
		`{}`:                                             "{}\n",
		`[]`:                                             "[]\n",
		`"text"`:                                         "\"text\"\n",
		`5`:                                              "5\n",
		`null`:                                           "null\n",
		`[null,false,"x"]`:                               "[\n  null,\n  false,\n  \"x\"\n]\n",
	} {
		if got := render(t, in); got != want {
			t.Errorf("%s:\n got %q\nwant %q", in, got, want)
		}
	}
}

// §H.1: a top-level fresh $nonce and a $successor of §8.1's form are left
// out; $schema, any other $nonce or $successor, and nested ones stay.
func TestRenderingLeavesOut(t *testing.T) {
	t.Parallel()
	nonce := strings.Repeat("a", 26)
	for in, want := range map[string]string{
		`{"$nonce":"` + nonce + `","n":1}`:                        "{\n  \"n\": 1\n}\n",
		`{"$successor":"next","n":1}`:                             "{\n  \"n\": 1\n}\n",
		`{"$successor":"/r/other/next","$nonce":"` + nonce + `"}`: "{}\n",
		`{"$schema":"/r/s/x/rev/1a","$nonce":"` + nonce + `"}`:    "{\n  \"$schema\": \"/r/s/x/rev/1a\"\n}\n",
		`{"$nonce":"short","n":1}`:                                "{\n  \"$nonce\": \"short\",\n  \"n\": 1\n}\n",
		`{"$nonce":7}`:                                            "{\n  \"$nonce\": 7\n}\n",
		`{"$successor":"Not A Name"}`:                             "{\n  \"$successor\": \"Not A Name\"\n}\n",
		`{"$successor":"/r/Bad/x"}`:                               "{\n  \"$successor\": \"/r/Bad/x\"\n}\n",
		`{"a":{"$nonce":"` + nonce + `","$successor":"next"}}`:    "{\n  \"a\": {\n    \"$nonce\": \"" + nonce + "\",\n    \"$successor\": \"next\"\n  }\n}\n",
		`["` + nonce + `"]`:                                       "[\n  \"" + nonce + "\"\n]\n",
	} {
		if got := render(t, in); got != want {
			t.Errorf("%s:\n got %q\nwant %q", in, got, want)
		}
	}
	// The document itself is untouched.
	doc := jsonv.MustParse([]byte(`{"$nonce":"` + nonce + `","n":1}`)).(map[string]any)
	Rendering(doc)
	if _, ok := doc["$nonce"]; !ok {
		t.Fatal("Rendering modified the document")
	}
}

// Layout lays out canonical text as encoding/json's Indent does, an
// independent implementation that copies tokens too, with a final LF.
func TestLayoutMatchesIndent(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(1))
	var gen func(depth int) any
	gen = func(depth int) any {
		switch k := r.Intn(8); {
		case depth > 4 || k < 2:
			switch r.Intn(5) {
			case 0:
				return float64(r.Intn(2000) - 1000)
			case 1:
				return r.Float64() * 1e6
			case 2:
				return strings.Repeat(string(rune("a\"\\{}[],: \n\u001fé😀"[r.Intn(16)%14])), r.Intn(3))
			case 3:
				return r.Intn(2) == 0
			default:
				return nil
			}
		case k < 5:
			n := r.Intn(4)
			a := make([]any, n)
			for i := range a {
				a[i] = gen(depth + 1)
			}
			return a
		default:
			n := r.Intn(4)
			m := map[string]any{}
			for i := 0; i < n; i++ {
				m[strconv.Itoa(r.Intn(20))+string(rune('a'+r.Intn(3)))] = gen(depth + 1)
			}
			return m
		}
	}
	for i := 0; i < 2000; i++ {
		canon := jsonv.Canonical(jsonv.FromGo(gen(0)))
		var want bytes.Buffer
		if err := json.Indent(&want, canon, "", "  "); err != nil {
			t.Fatalf("%s: %v", canon, err)
		}
		want.WriteByte('\n')
		if got := Layout(canon); !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("%s:\n got %q\nwant %q", canon, got, want.Bytes())
		}
	}
}

// §H.3: a raw file's metadata is its reference's; any other document's is
// its rendering's length and application/json.
func TestMetaOf(t *testing.T) {
	t.Parallel()
	bid := "1" + strings.Repeat("a", 32)
	nonce := strings.Repeat("b", 26)
	raw := jsonv.MustParse([]byte(`{"$blob":"` + bid + `","type":"text/markdown","size":1234,"$nonce":"` + nonce + `","$successor":"next"}`))
	if m := MetaOf(raw); m != (Meta{1234, "text/markdown"}) {
		t.Fatalf("raw %+v", m)
	}
	doc := jsonv.MustParse([]byte(`{"$nonce":"` + nonce + `","title":"Hi","n":[1,2]}`))
	if m, want := MetaOf(doc), int64(len("{\n  \"n\": [\n    1,\n    2\n  ],\n  \"title\": \"Hi\"\n}\n")); m != (Meta{want, JSONType}) {
		t.Fatalf("json %+v, want size %d", m, want)
	}
	// A blob reference with another member is a JSON file.
	other := jsonv.MustParse([]byte(`{"$blob":"` + bid + `","type":"text/plain","size":3,"note":"x"}`))
	if m := MetaOf(other); m.Type != JSONType {
		t.Fatalf("not raw %+v", m)
	}
}
