package bundle

import (
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// withAt copies the containers on the way to what it replaces and shares
// the rest, so a rewritten patch set never changes the bundle's line it
// shares its values with (renameStep).
func TestWithAt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, ptr string
		want      any
		err       bool
	}{
		{"root", "", "x", false},
		{"member", "/a", map[string]any{"a": "x", "b": map[string]any{"c": "/r/s/c"}, "l": []any{"/r/s/l", "k"}}, false},
		{"nested", "/b/c", map[string]any{"a": "/r/s/a", "b": map[string]any{"c": "x"}, "l": []any{"/r/s/l", "k"}}, false},
		{"array", "/l/0", map[string]any{"a": "/r/s/a", "b": map[string]any{"c": "/r/s/c"}, "l": []any{"x", "k"}}, false},
		{"missing", "/b/d", nil, true},
		{"out of range", "/l/2", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := map[string]any{"a": "/r/s/a", "b": map[string]any{"c": "/r/s/c"}, "l": []any{"/r/s/l", "k"}}
			before := jsonv.Clone(v)
			got, err := withAt(v, tc.ptr, "x")
			if tc.err != (err != nil) {
				t.Fatalf("err %v", err)
			}
			if !jsonv.Equal(v, before) {
				t.Fatalf("v changed: %v", v)
			}
			if err == nil && !jsonv.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			// What it doesn't replace is shared, not copied.
			if m, ok := got.(map[string]any); ok && tc.ptr != "/b/c" {
				if reflect.ValueOf(m["b"]).UnsafePointer() != reflect.ValueOf(v["b"]).UnsafePointer() {
					t.Fatal("/b copied")
				}
			}
		})
	}
}

// fixTests replaces the test ops it changes by copies, leaving the source's
// patch set, whose other ops the rewritten one shares, as it was.
func TestFixTestsShares(t *testing.T) {
	t.Parallel()
	src := map[string]any{"pin": "/r/s/b/rev/1"}
	dst := map[string]any{"pin": "/r/c/b/rev/2"}
	srcOps := []any{
		map[string]any{"op": "test", "path": "/pin", "value": "/r/s/b/rev/1"},
		map[string]any{"op": "add", "path": "/t", "value": "x"},
	}
	before := jsonv.Clone(srcOps)
	ops := append([]any(nil), srcOps...)
	if err := fixTests(src, true, dst, true, srcOps, ops); err != nil {
		t.Fatal(err)
	}
	if !jsonv.Equal(srcOps, before) {
		t.Fatalf("the source's patch set changed: %v", srcOps)
	}
	if got := ops[0].(map[string]any)["value"]; got != "/r/c/b/rev/2" {
		t.Fatalf("test op %v", got)
	}
	if ops[1].(map[string]any)["value"] != "x" {
		t.Fatalf("other op %v", ops[1])
	}
}

// The report says which undeclared references a later revision rewrites
// after all, where its schema declares their position.
func TestPrintUndeclaredRenamed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		u    UndeclaredRef
		want string
	}{
		{"never declared", UndeclaredRef{Doc: "x/d", Pointer: "/note", Value: "/r/x/o", Renamed: true, Rev: "r1"},
			"undeclared reference in x/d at /note, written by r1: /r/x/o (renamed, not rewritten)\n"},
		{"declared later", UndeclaredRef{Doc: "x/d", Pointer: "/note", Value: "/r/x/o", Renamed: true, Rev: "r1", RewrittenFrom: "r2"},
			"undeclared reference in x/d at /note, written by r1: /r/x/o (renamed, not rewritten before r2, which declares it)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			printReport(&b, &Report{Undeclared: []UndeclaredRef{tc.u}})
			if !strings.Contains(b.String(), tc.want) {
				t.Fatalf("report:\n%s\nwant %q", b.String(), tc.want)
			}
		})
	}
}
