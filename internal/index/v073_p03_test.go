package index

import (
	"bytes"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// CIS-13: a $ref into another revision whose fragment is a plain name
// marks through the anchor it names (§6.1), never through the revision's
// root.
func TestV073MarksThroughRevisionAnchor(t *testing.T) {
	t.Parallel()
	rev := func(name string, b byte) string {
		return "/r/schemas/" + name + "/rev/" + ids.FromBytes(bytes.Repeat([]byte{b}, ids.Size)).String()
	}
	root, other := rev("root", 1), rev("other", 2)
	ds := map[string]any{other: parse(t, `{"x-index": "text", "$defs": {"m": {"$anchor": "m", "x-index": "facet"}, "u": {"$anchor": "u"}}}`)}
	for _, c := range []struct {
		schema string
		want   bool
	}{
		{`{"properties": {"a": {"$ref": "OTHER#m"}}}`, true},
		{`{"properties": {"a": {"$ref": "OTHER#u"}}}`, false},
		{`{"properties": {"a": {"$ref": "OTHER#nope"}}}`, false},
	} {
		ds[root] = parse(t, strings.ReplaceAll(c.schema, "OTHER", other))
		w := &markWalk{docs: map[string]any{}, seen: map[string]bool{}, path: pointer.MustParse("/a"), load: func(ref schema.Ref) (any, error) {
			if d, ok := ds[ref.Path()]; ok {
				return d, nil
			}
			return nil, schema.ErrUnavailable
		}}
		if got := w.marked(root, nil, 0); got != c.want {
			t.Errorf("%s marks /a: %v, want %v", c.schema, got, c.want)
		}
	}
}
