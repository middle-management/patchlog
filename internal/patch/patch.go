// Package patch implements RFC 6902 JSON Patch with the write-set
// computation of the change envelope (spec §6.4.1).
package patch

import (
	"fmt"
	"strconv"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
)

// Op is one parsed patch operation.
type Op struct {
	Op       string // add, remove, replace, move, copy, test
	Path     pointer.Pointer
	From     pointer.Pointer // move/copy only
	Value    any             // add/replace/test
	PathText string          // original text of path
}

// Error is a patch-application or structure error; the server maps it to 422 code "invalid".
type Error struct {
	Index   int
	Pointer string
	Message string
}

func (e *Error) Error() string {
	if e.Pointer != "" {
		return fmt.Sprintf("patch op %d (%s): %s", e.Index, e.Pointer, e.Message)
	}
	return fmt.Sprintf("patch op %d: %s", e.Index, e.Message)
}

// Options control Apply.
type Options struct {
	// ResourceEnvelope enables the $nonce exclusion of §6.4.1.
	ResourceEnvelope bool
	// InPlace applies the ops to doc itself instead of a copy, for callers
	// that own it (folding a log). On an error doc may be half changed.
	InPlace bool
}

// Parse validates the structure of a patch set.
func Parse(v any) ([]Op, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, &Error{Index: 0, Message: "a patch set must be an array"}
	}
	ops := make([]Op, 0, len(arr))
	for i, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, &Error{Index: i, Message: "operation must be an object"}
		}
		name, ok := m["op"].(string)
		if !ok {
			return nil, &Error{Index: i, Message: `missing or non-string "op"`}
		}
		switch name {
		case "add", "remove", "replace", "move", "copy", "test":
		default:
			return nil, &Error{Index: i, Message: fmt.Sprintf("unknown op %q", name)}
		}
		ptxt, ok := m["path"].(string)
		if !ok {
			return nil, &Error{Index: i, Message: `missing or non-string "path"`}
		}
		p, err := pointer.Parse(ptxt)
		if err != nil {
			return nil, &Error{Index: i, Pointer: ptxt, Message: "invalid path pointer"}
		}
		op := Op{Op: name, Path: p, PathText: ptxt}
		switch name {
		case "move", "copy":
			ftxt, ok := m["from"].(string)
			if !ok {
				return nil, &Error{Index: i, Pointer: ptxt, Message: `missing or non-string "from"`}
			}
			f, err := pointer.Parse(ftxt)
			if err != nil {
				return nil, &Error{Index: i, Pointer: ftxt, Message: `invalid "from" pointer`}
			}
			op.From = f
		case "add", "replace", "test":
			val, present := m["value"]
			if !present {
				return nil, &Error{Index: i, Pointer: ptxt, Message: `missing "value"`}
			}
			op.Value = val
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// WritesStrings formats writes as pointer strings.
func WritesStrings(w []pointer.Pointer) []string {
	out := make([]string, len(w))
	for i, p := range w {
		out[i] = p.String()
	}
	return out
}

// Apply applies ops to doc without mutating it (unless opt.InPlace).
func Apply(doc any, exists bool, ops []Op, opt Options) (any, []pointer.Pointer, error) {
	cur := doc
	if !opt.InPlace {
		cur = jsonv.Clone(doc)
	}
	have := exists
	if !exists {
		cur = nil
	}
	var writes []pointer.Pointer

	for i, op := range ops {
		fail := func(ptr, msg string) error { return &Error{Index: i, Pointer: ptr, Message: msg} }
		switch op.Op {
		case "add", "replace", "copy", "move", "remove", "test":
		default:
			return nil, nil, fail(op.PathText, fmt.Sprintf("unknown op %q", op.Op))
		}

		switch op.Op {
		case "add":
			nd, w, err := addAt(cur, have, op.Path, jsonv.Clone(op.Value))
			if err != nil {
				return nil, nil, fail(op.PathText, err.Error())
			}
			cur, have = nd, true
			if !(opt.ResourceEnvelope && isNonce(op.Path, op.Value)) {
				writes = append(writes, w)
			}
		case "replace":
			if !have {
				return nil, nil, fail(op.PathText, "the document does not exist")
			}
			if _, ok := pointer.Get(cur, op.Path); !ok {
				return nil, nil, fail(op.PathText, "replace target does not exist")
			}
			// Replace = remove, then add at the same location, so an array
			// element is replaced in place rather than inserted before.
			base := cur
			if len(op.Path) > 0 {
				var err error
				if base, _, err = removeAt(cur, op.Path); err != nil {
					return nil, nil, fail(op.PathText, err.Error())
				}
			}
			nd, w, err := addAt(base, have, op.Path, jsonv.Clone(op.Value))
			if err != nil {
				return nil, nil, fail(op.PathText, err.Error())
			}
			cur = nd
			if !(opt.ResourceEnvelope && isNonce(op.Path, op.Value)) {
				writes = append(writes, w)
			}
		case "remove":
			if !have {
				return nil, nil, fail(op.PathText, "the document does not exist")
			}
			nd, _, err := removeAt(cur, op.Path)
			if err != nil {
				return nil, nil, fail(op.PathText, err.Error())
			}
			cur = nd
			writes = append(writes, clonePtr(op.Path))
		case "copy":
			if !have {
				return nil, nil, fail(op.From.String(), "the document does not exist")
			}
			v, ok := pointer.Get(cur, op.From)
			if !ok {
				return nil, nil, fail(op.From.String(), "copy source does not exist")
			}
			nd, w, err := addAt(cur, have, op.Path, jsonv.Clone(v))
			if err != nil {
				return nil, nil, fail(op.PathText, err.Error())
			}
			cur = nd
			writes = append(writes, w)
		case "move":
			if !have {
				return nil, nil, fail(op.From.String(), "the document does not exist")
			}
			v, ok := pointer.Get(cur, op.From)
			if !ok {
				return nil, nil, fail(op.From.String(), "move source does not exist")
			}
			if len(op.Path) > len(op.From) && op.Path.HasPrefix(op.From) {
				return nil, nil, fail(op.PathText, "cannot move a value into one of its own children")
			}
			if samePtr(op.From, op.Path) {
				writes = append(writes, clonePtr(op.From), clonePtr(op.Path))
				continue
			}
			nd, _, err := removeAt(cur, op.From)
			if err != nil {
				return nil, nil, fail(op.From.String(), err.Error())
			}
			nd, w, err := addAt(nd, true, op.Path, v)
			if err != nil {
				return nil, nil, fail(op.PathText, err.Error())
			}
			cur = nd
			writes = append(writes, clonePtr(op.From), w)
		case "test":
			if !have {
				return nil, nil, fail(op.PathText, "test failed: the document does not exist")
			}
			v, ok := pointer.Get(cur, op.Path)
			if !ok {
				return nil, nil, fail(op.PathText, "test failed: path does not exist")
			}
			if !jsonv.Equal(v, op.Value) {
				return nil, nil, fail(op.PathText, "test failed")
			}
		}
	}
	if !have {
		return nil, nil, &Error{Index: len(ops), Message: "no document"}
	}
	return cur, writes, nil
}

func isNonce(p pointer.Pointer, v any) bool {
	if len(p) != 1 || p[0] != "$nonce" {
		return false
	}
	s, ok := v.(string)
	if !ok || len(s) != 26 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func clonePtr(p pointer.Pointer) pointer.Pointer {
	out := make(pointer.Pointer, len(p))
	copy(out, p)
	return out
}

func samePtr(a, b pointer.Pointer) bool {
	return len(a) == len(b) && a.HasPrefix(b)
}

// addAt inserts val at p and returns the new node and the resolved pointer
// (with `-` replaced by the index it landed at).
func addAt(node any, have bool, p pointer.Pointer, val any) (any, pointer.Pointer, error) {
	if len(p) == 0 {
		return val, pointer.Pointer{}, nil
	}
	if !have {
		return nil, nil, fmt.Errorf("the document does not exist")
	}
	resolved := clonePtr(p)
	nd, err := addRec(node, p, resolved, 0, val)
	if err != nil {
		return nil, nil, err
	}
	return nd, resolved, nil
}

func addRec(node any, p, resolved pointer.Pointer, depth int, val any) (any, error) {
	tok := p[depth]
	last := depth == len(p)-1
	switch c := node.(type) {
	case map[string]any:
		if last {
			c[tok] = val
			return c, nil
		}
		child, ok := c[tok]
		if !ok {
			return nil, fmt.Errorf("path does not exist")
		}
		nc, err := addRec(child, p, resolved, depth+1, val)
		if err != nil {
			return nil, err
		}
		c[tok] = nc
		return c, nil
	case []any:
		if last {
			var idx int
			if tok == "-" {
				idx = len(c)
			} else {
				n, ok := pointer.ArrayIndex(tok)
				if !ok {
					return nil, fmt.Errorf("invalid array index %q", tok)
				}
				if n > len(c) {
					return nil, fmt.Errorf("array index %d out of range", n)
				}
				idx = n
			}
			resolved[depth] = strconv.Itoa(idx)
			c = append(c, nil)
			copy(c[idx+1:], c[idx:])
			c[idx] = val
			return c, nil
		}
		n, ok := pointer.ArrayIndex(tok)
		if !ok || n >= len(c) {
			return nil, fmt.Errorf("path does not exist")
		}
		nc, err := addRec(c[n], p, resolved, depth+1, val)
		if err != nil {
			return nil, err
		}
		c[n] = nc
		return c, nil
	default:
		return nil, fmt.Errorf("path does not exist")
	}
}

// removeAt removes the value at p (non-root) and returns the new node.
func removeAt(node any, p pointer.Pointer) (any, any, error) {
	if len(p) == 0 {
		return nil, nil, fmt.Errorf("the document cannot be removed")
	}
	return removeRec(node, p, 0)
}

func removeRec(node any, p pointer.Pointer, depth int) (any, any, error) {
	tok := p[depth]
	last := depth == len(p)-1
	switch c := node.(type) {
	case map[string]any:
		child, ok := c[tok]
		if !ok {
			return nil, nil, fmt.Errorf("path does not exist")
		}
		if last {
			delete(c, tok)
			return c, child, nil
		}
		nc, old, err := removeRec(child, p, depth+1)
		if err != nil {
			return nil, nil, err
		}
		c[tok] = nc
		return c, old, nil
	case []any:
		n, ok := pointer.ArrayIndex(tok)
		if !ok || n >= len(c) {
			return nil, nil, fmt.Errorf("path does not exist")
		}
		if last {
			old := c[n]
			c = append(c[:n], c[n+1:]...)
			return c, old, nil
		}
		nc, old, err := removeRec(c[n], p, depth+1)
		if err != nil {
			return nil, nil, err
		}
		c[n] = nc
		return c, old, nil
	default:
		return nil, nil, fmt.Errorf("path does not exist")
	}
}
