package jsonv

import (
	"errors"
	"fmt"
)

// Raw is a value of the model held as its canonical serialisation: the
// bytes Canonical writes for one value, or a part of its output that is one
// whole value. The bundle importer keeps the snapshot documents it only
// sends on this way (internal/bundle, snapDoc), at a fraction of the
// memory of their trees; nothing else constructs one (TestRawConfined).
//
// The contract:
//
//   - The bytes are canonical (RFC 8785) and are never modified: Canonical,
//     CanonicalOf and MarshalJSON write them as they are, unchecked, into
//     request bodies and the patch sets whose ids are hashed from them, and
//     Clone shares them.
//   - IsValue accepts a non-nil Raw: it is a value of the model, the one
//     Parse(r) returns, though not a Go value Parse returns. A Raw may
//     stand anywhere a value may, inside []any and map[string]any too.
//   - Equal, Depth and FromGo parse it, and merge.Diff expands it. Any
//     other code that reads a value's structure (a type switch on []any
//     and map[string]any, such as the readers of a patch set's ops) would
//     see an opaque leaf: it must Expand the value first, or refuse a Raw.
//   - A patch set is never a Raw itself: one is a value inside a patch set
//     (client.GenesisPatches), whose ops stay readable, and the importer's
//     readers of ops refuse one (internal/bundle, errRawPatchSet).
type Raw []byte

// MarshalJSON returns r's bytes, so that encoding/json, which a client
// falls back to for a body that isn't all values of the model, writes the
// value r holds, not a base64 string of its bytes.
func (r Raw) MarshalJSON() ([]byte, error) {
	if r == nil {
		return nil, errors.New("jsonv: nil Raw")
	}
	return r, nil
}

// Expand returns v with every Raw in it parsed, the containers on the way
// to one copied; v itself if it holds none. v is not modified.
func Expand(v any) (any, error) {
	if !hasRaw(v) {
		return v, nil
	}
	switch x := v.(type) {
	case Raw:
		return Parse(x)
	case []any:
		c := make([]any, len(x))
		for i, e := range x {
			var err error
			if c[i], err = Expand(e); err != nil {
				return nil, err
			}
		}
		return c, nil
	case map[string]any:
		c := make(map[string]any, len(x))
		for k, e := range x {
			var err error
			if c[k], err = Expand(e); err != nil {
				return nil, err
			}
		}
		return c, nil
	}
	return v, nil
}

// hasRaw reports whether v holds a Raw.
func hasRaw(v any) bool {
	switch x := v.(type) {
	case Raw:
		return true
	case []any:
		for _, e := range x {
			if hasRaw(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if hasRaw(e) {
				return true
			}
		}
	}
	return false
}

// parsed is the value r holds, for the readers of structure that take a
// Raw (Equal, Depth, FromGo). A Raw that doesn't parse breaks its
// contract.
func (r Raw) parsed() any {
	v, err := Parse(r)
	if err != nil {
		panic(fmt.Sprintf("jsonv: a Raw that is not a value: %v", err))
	}
	return v
}
