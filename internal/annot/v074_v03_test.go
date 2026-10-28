package annot

import (
	"testing"

	"github.com/middle-management/patchlog/internal/schema"
)

// CORE-3 (§6.5, §6.1): finding references is a static walk, not
// validation. A document stored against a schema revision an earlier
// version accepted, which no longer compiles under this version (a format
// outside 2020-12, a root $id equal to its own path, a nested dialect
// $schema, a pattern only raw RE2 takes), still declares its references:
// bundle export, import and rename and the index's /_refs walk it.
func TestV074V03FindRefsStoredSchema(t *testing.T) {
	t.Parallel()
	const p = "/r/s/legacy/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	xref := map[string]any{"type": "string", "x-ref": map[string]any{}}
	for name, sch := range map[string]map[string]any{
		"format semver": {"properties": map[string]any{
			"v": map[string]any{"type": "string", "format": "semver"}, "rel": xref}},
		"own $id": {"$id": p, "properties": map[string]any{"rel": xref}},
		"nested $schema": {"properties": map[string]any{
			"v": map[string]any{"$schema": schema.Dialect2020, "type": "string"}, "rel": xref}},
		"pattern raw RE2 takes": {"patternProperties": map[string]any{
			`^re[\x{D800}l]`: xref}},
	} {
		sch["$schema"] = schema.Dialect2020
		load := func(r schema.Ref) (any, error) {
			if r.Path() == p {
				return sch, nil
			}
			return nil, schema.ErrUnavailable
		}
		refs, err := FindRefs(map[string]any{"$schema": p, "v": "1.0.0", "rel": "/r/n/x"}, load)
		if err != nil || len(refs) != 1 || refs[0].Pointer != "/rel" {
			t.Errorf("%s: FindRefs = %+v, %v; want the one x-ref at /rel", name, refs, err)
		}
	}
	// What no version accepted is still refused.
	for name, sch := range map[string]map[string]any{
		"unknown keyword": {"frobnicate": true, "properties": map[string]any{"rel": xref}},
		"other $id":       {"$id": "/r/s/other/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "properties": map[string]any{"rel": xref}},
		"nested $id":      {"properties": map[string]any{"rel": map[string]any{"$id": p, "x-ref": map[string]any{}}}},
	} {
		sch["$schema"] = schema.Dialect2020
		load := func(r schema.Ref) (any, error) { return sch, nil }
		if refs, err := FindRefs(map[string]any{"$schema": p, "rel": "/r/n/x"}, load); err == nil {
			t.Errorf("%s: FindRefs = %+v, want a schema error", name, refs)
		}
	}
}
