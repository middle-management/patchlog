package jsonv

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A Raw value serialises as the value it holds, inside other values too,
// through Canonical, CanonicalOf and encoding/json; IsValue accepts it;
// Equal, Depth and FromGo read it as that value; Clone shares it; and
// Expand turns it back into that value without modifying its argument.
func TestRaw(t *testing.T) {
	t.Parallel()
	doc := MustParse([]byte(`{"b":[1,"x",{"$blob":"y"}],"a":null,"é":" <&> \u2028"}`))
	raw := Raw(Canonical(doc))
	wrapped := []any{map[string]any{"op": "add", "path": "", "value": raw}}
	plain := []any{map[string]any{"op": "add", "path": "", "value": doc}}
	if got, want := Canonical(wrapped), Canonical(plain); !bytes.Equal(got, want) {
		t.Fatalf("Canonical: %s, want %s", got, want)
	}
	got, ok := CanonicalOf(wrapped)
	if !ok || !bytes.Equal(got, Canonical(plain)) {
		t.Fatalf("CanonicalOf: %s %v", got, ok)
	}
	if _, ok := CanonicalOf([]any{Raw(nil)}); ok {
		t.Fatal("CanonicalOf accepted a nil Raw")
	}
	if !IsValue(wrapped) || !IsValue(raw) || IsValue(Raw(nil)) || IsValue([]any{Raw(nil)}) {
		t.Fatal("IsValue")
	}

	// encoding/json, which a client falls back to for a body with values
	// outside the model (here an int), writes the value, not base64.
	j, err := json.Marshal(map[string]any{"n": 1, "value": raw})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(j, &back); err != nil {
		t.Fatal(err)
	}
	if v := FromGo(map[string]any{"v": back["value"]}).(map[string]any)["v"]; !Equal(v, doc) {
		t.Fatalf("encoding/json wrote %s", j)
	}
	if _, err := json.Marshal(Raw(nil)); err == nil {
		t.Fatal("encoding/json wrote a nil Raw")
	}

	if !Equal(raw, doc) || !Equal(doc, raw) || !Equal(wrapped, plain) || !Equal(raw, Raw(Canonical(doc))) || Equal(raw, Raw(`{"a":null}`)) {
		t.Fatal("Equal")
	}
	if Depth(raw) != Depth(doc) || Depth(wrapped) != Depth(plain) {
		t.Fatalf("Depth %d, want %d", Depth(wrapped), Depth(plain))
	}
	if n := FromGo(map[string]any{"v": raw}); !Equal(n, map[string]any{"v": doc}) {
		t.Fatalf("FromGo: %v", n)
	} else if _, isRaw := n.(map[string]any)["v"].(Raw); isRaw {
		t.Fatal("FromGo kept the Raw")
	}
	if c := Clone(wrapped).([]any)[0].(map[string]any)["value"].(Raw); &c[0] != &raw[0] {
		t.Fatal("Clone copied a Raw")
	}

	ex, err := Expand(wrapped)
	if err != nil || !Equal(ex, plain) {
		t.Fatalf("Expand: %v %v", ex, err)
	}
	if _, isRaw := ex.([]any)[0].(map[string]any)["value"].(Raw); isRaw {
		t.Fatal("Expand left the Raw")
	}
	if m := wrapped[0].(map[string]any); !bytes.Equal(m["value"].(Raw), raw) {
		t.Fatal("Expand modified its argument")
	}
	if same, _ := Expand(plain); &same.([]any)[0] != &plain[0] {
		t.Fatal("Expand copied a value without Raw")
	}
	if _, err := Expand([]any{Raw(`{"a":`)}); err == nil {
		t.Fatal("Expand of a Raw that isn't a value: no error")
	}
}

// constructsRaw matches a conversion to a Raw or a Raw literal.
var constructsRaw = regexp.MustCompile(`jsonv\.Raw\s*[({]`)

// Raw is the bundle importer's: no other package constructs one (its
// contract, Raw), so code elsewhere that meets values never sees one.
func TestRawConfined(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	allowed := map[string]bool{filepath.Join("internal", "jsonv"): true, filepath.Join("internal", "bundle"): true}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if n := e.Name(); n != ".." && (strings.HasPrefix(n, ".") || n == "testdata" || n == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil || allowed[rel] {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if loc := constructsRaw.FindIndex(b); loc != nil {
			t.Errorf("%s constructs a jsonv.Raw (%s), which is the bundle importer's (see its contract)", p, b[loc[0]:loc[1]])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
