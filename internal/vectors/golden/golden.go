// Package golden keeps the test vectors the reference proposes for the
// spec's Addendum I (I.11 and the writer's list) in
// internal/vectors/testdata, one JSON file per group. The tests that
// compute them, through production code only, live beside the code they
// need: internal/vectors for the exported APIs, and internal tests of
// grant, merge and core for vectors only their unexported encoders can
// produce (a Biscuit token breaking §C.8, a plan's steps as its digest
// renders them, a resource's archive key).
//
// A test computes its group and calls Check, which compares it with the
// stored file byte for byte; with -update it writes the file instead:
//
//	go test ./internal/vectors/ ./internal/grant/ ./internal/merge/ ./internal/core/ -run Vector -update
//
// Every vector names the production function that produced it ("fn"), so
// the writer can tell what the reference computed from what it was given.
package golden

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite internal/vectors/testdata from the reference")

// Updating reports whether the test run rewrites the stored vectors.
func Updating() bool { return *update }

// Obj is a JSON object whose members keep their order, so a vector reads
// name, fn, inputs, then outputs.
type Obj []Member

// Member is one member of an Obj.
type Member struct {
	Key   string
	Value any
}

// MarshalJSON writes the members in order.
func (o Obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := marshal(m.Key)
		if err != nil {
			return nil, err
		}
		v, err := marshal(m.Value)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// marshal is json.Marshal without HTML escaping, so strings read as they
// are ("<", "&" and "\u2028" included).
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Hex is the lowercase hex of b, as Addendum I writes byte strings.
func Hex(b []byte) string { return hex.EncodeToString(b) }

// Dir is internal/vectors/testdata, found from the test's working
// directory (its package's) by walking up to go.mod.
func Dir(t testing.TB) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(d, "internal", "vectors", "testdata")
		}
		up := filepath.Dir(d)
		if up == d {
			t.Fatal("golden: no go.mod above the test's directory")
		}
		d = up
	}
}

// Encode renders a group as its stored file: indented JSON, ending in one
// line feed.
func Encode(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := json.Indent(&b, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	b.WriteByte('\n')
	return b.Bytes()
}

// Check compares the group v, as Encode renders it, with the stored file
// testdata/name.json, or with -update writes it.
func Check(t testing.TB, name string, v any) {
	t.Helper()
	got := Encode(t, v)
	path := filepath.Join(Dir(t), name+".json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write the vectors)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s.json differs from what the reference computes now; first difference at line %d:\n got  %s\n want %s\n(if the change is intended, run with -update and send the new values to the spec writer)",
			name, diffLine(got, want), line(got, diffLine(got, want)), line(want, diffLine(got, want)))
	}
}

// Load reads the stored file testdata/name.json into v; it reports false,
// leaving v alone, when the file doesn't exist yet.
func Load(t testing.TB, name string, v any) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(Dir(t), name+".json"))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s.json: %v", name, err)
	}
	return true
}

// diffLine is the 1-based number of the first line where a and b differ.
func diffLine(a, b []byte) int {
	la, lb := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := range min(len(la), len(lb)) {
		if la[i] != lb[i] {
			return i + 1
		}
	}
	return min(len(la), len(lb)) + 1
}

func line(b []byte, n int) string {
	ls := strings.Split(string(b), "\n")
	if n-1 < len(ls) {
		return ls[n-1]
	}
	return "(end of file)"
}
