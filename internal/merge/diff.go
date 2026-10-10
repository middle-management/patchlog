package merge

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
)

// Diff returns a JSON Patch (RFC 6902) that turns document a into document
// b, using only add, replace and remove. Applying it to a gives a document
// equal to b (jsonv.Equal). Equal documents give an empty patch set.
//
// Objects are compared key by key (in sorted key order, so the output is
// deterministic). Arrays keep their common prefix and suffix, pair up the
// elements in between (recursing into each pair), then remove the surplus
// elements of a or add the extra elements of b. Anything else that differs,
// including a change of type, is a replace.
//
// A value held as its canonical form (jsonv.Raw) is diffed as the value it
// holds: Diff expands it first, so that it compares its members and
// elements rather than replacing it whole.
func Diff(a, b any) []any {
	var out []any
	diffRec(pointer.Pointer{}, expanded(a), expanded(b), &out)
	return out
}

// expanded is v with every jsonv.Raw in it parsed; one that doesn't parse
// breaks Raw's contract.
func expanded(v any) any {
	x, err := jsonv.Expand(v)
	if err != nil {
		panic(fmt.Sprintf("merge: Diff of a jsonv.Raw that is not a value: %v", err))
	}
	return x
}

func diffOp(op string, p pointer.Pointer, v any, withValue bool) map[string]any {
	m := map[string]any{"op": op, "path": p.String()}
	if withValue {
		m["value"] = jsonv.Clone(v)
	}
	return m
}

func child(p pointer.Pointer, tok string) pointer.Pointer {
	out := make(pointer.Pointer, len(p)+1)
	copy(out, p)
	out[len(p)] = tok
	return out
}

func diffRec(p pointer.Pointer, a, b any, out *[]any) {
	if jsonv.Equal(a, b) {
		return
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			break
		}
		keys := make([]string, 0, len(x)+len(y))
		for k := range x {
			keys = append(keys, k)
		}
		for k := range y {
			if _, ok := x[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			av, inA := x[k]
			bv, inB := y[k]
			switch {
			case inA && !inB:
				*out = append(*out, diffOp("remove", child(p, k), nil, false))
			case !inA && inB:
				*out = append(*out, diffOp("add", child(p, k), bv, true))
			default:
				diffRec(child(p, k), av, bv, out)
			}
		}
		return
	case []any:
		y, ok := b.([]any)
		if !ok {
			break
		}
		diffArray(p, x, y, out)
		return
	}
	*out = append(*out, diffOp("replace", p, b, true))
}

func diffArray(p pointer.Pointer, a, b []any, out *[]any) {
	pre := 0
	for pre < len(a) && pre < len(b) && jsonv.Equal(a[pre], b[pre]) {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && jsonv.Equal(a[len(a)-1-suf], b[len(b)-1-suf]) {
		suf++
	}
	am := a[pre : len(a)-suf]
	bm := b[pre : len(b)-suf]
	k := len(am)
	if len(bm) < k {
		k = len(bm)
	}
	for i := 0; i < k; i++ {
		diffRec(child(p, strconv.Itoa(pre+i)), am[i], bm[i], out)
	}
	// Surplus elements of a: remove them at the same index (each removal
	// shifts the next one into place).
	for i := k; i < len(am); i++ {
		*out = append(*out, diffOp("remove", child(p, strconv.Itoa(pre+k)), nil, false))
	}
	// Extra elements of b: insert them in order.
	for i := k; i < len(bm); i++ {
		*out = append(*out, diffOp("add", child(p, strconv.Itoa(pre+i)), bm[i], true))
	}
}
