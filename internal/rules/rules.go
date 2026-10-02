// Package rules implements the namespace rule language (SPEC §6.4.2).
package rules

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Rule is a compiled rule.
type Rule struct{ n node }

type node interface {
	eval(env map[string]any) bool
	// failPath describes the innermost failing leaf; called only after eval returned false.
	failPath(env map[string]any) string
	// refs calls add with every envelope pointer the node can read.
	refs(add func(pointer.Pointer))
}

// Compile validates and compiles one rule.
func Compile(v any) (*Rule, error) {
	n, err := compileNode(v)
	if err != nil {
		return nil, err
	}
	return &Rule{n: n}, nil
}

// CompileList compiles an array of rules; nil => empty list.
func CompileList(v any) ([]*Rule, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("rules must be an array")
	}
	out := make([]*Rule, 0, len(arr))
	for i, x := range arr {
		r, err := Compile(x)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Eval evaluates the rule against a change envelope.
func (r *Rule) Eval(env map[string]any) bool { return r.n.eval(env) }

// EvalList runs rules in order; returns (-1, "", true) if all pass.
func EvalList(rs []*Rule, env map[string]any) (int, string, bool) {
	for i, r := range rs {
		if !r.n.eval(env) {
			return i, r.n.failPath(env), false
		}
	}
	return -1, "", true
}

// Refs reports every top-level envelope member the rule can read ("*" for the whole envelope).
func (r *Rule) Refs() map[string]bool {
	m := map[string]bool{}
	r.n.refs(func(p pointer.Pointer) {
		if len(p) == 0 {
			m["*"] = true
			return
		}
		m[p[0]] = true
	})
	return m
}

// RefPaths reports every envelope pointer the rule can read: the paths of
// test and compare operands (the empty pointer for the whole envelope),
// and /writes for a writes op. A rule reads only what lies at or below
// these pointers.
func (r *Rule) RefPaths() []pointer.Pointer {
	var out []pointer.Pointer
	r.n.refs(func(p pointer.Pointer) { out = append(out, p) })
	return out
}

// OnlyRefs reports whether every member in Refs() is in allowed.
func (r *Rule) OnlyRefs(allowed ...string) bool {
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	for k := range r.Refs() {
		if !set[k] {
			return false
		}
	}
	return true
}

// ---- compilation helpers ----

func asObject(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("rule must be an object")
	}
	return m, nil
}

func checkKeys(m map[string]any, allowed ...string) error {
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	var bad []string
	for k := range m {
		if !set[k] {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("unknown member %q", bad[0])
	}
	return nil
}

func ptrField(m map[string]any, key string) (pointer.Pointer, string, error) {
	v, ok := m[key]
	if !ok {
		return nil, "", fmt.Errorf("missing %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return nil, "", fmt.Errorf("%q must be a string pointer", key)
	}
	p, err := pointer.Parse(s)
	if err != nil {
		return nil, "", fmt.Errorf("%q: invalid JSON pointer %q", key, s)
	}
	return p, s, nil
}

func compileNode(v any) (node, error) {
	m, err := asObject(v)
	if err != nil {
		return nil, err
	}
	if _, ok := m["op"]; ok {
		return compileOp(m)
	}
	switch {
	case has(m, "all"):
		return compileGroup(m, "all")
	case has(m, "any"):
		return compileGroup(m, "any")
	case has(m, "not"):
		if err := checkKeys(m, "not"); err != nil {
			return nil, err
		}
		in, err := compileNode(m["not"])
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		return &notNode{in}, nil
	case has(m, "if"), has(m, "then"):
		if err := checkKeys(m, "if", "then"); err != nil {
			return nil, err
		}
		if !has(m, "if") || !has(m, "then") {
			return nil, errors.New(`"if" and "then" must appear together`)
		}
		c, err := compileArr(m["if"], "if")
		if err != nil {
			return nil, err
		}
		t, err := compileArr(m["then"], "then")
		if err != nil {
			return nil, err
		}
		return &ifNode{c, t}, nil
	}
	return nil, errors.New(`rule needs "op", "all", "any", "not" or "if"`)
}

func has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func compileArr(v any, name string) ([]node, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%q must be an array of rules", name)
	}
	out := make([]node, 0, len(arr))
	for i, x := range arr {
		n, err := compileNode(x)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func compileGroup(m map[string]any, key string) (node, error) {
	if err := checkKeys(m, key); err != nil {
		return nil, err
	}
	ns, err := compileArr(m[key], key)
	if err != nil {
		return nil, err
	}
	if key == "all" {
		return &allNode{ns}, nil
	}
	return &anyNode{ns}, nil
}

func compileOp(m map[string]any) (node, error) {
	op, ok := m["op"].(string)
	if !ok {
		return nil, errors.New(`"op" must be a string`)
	}
	switch op {
	case "test":
		return compileTest(m)
	case "writes":
		return compileWrites(m)
	case "compare":
		return compileCompare(m)
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

// ---- test ----

type testNode struct {
	path   pointer.Pointer
	raw    string
	kind   string // value, exists, schema
	value  any
	exists bool
	schema *jsonschema.Schema
}

func compileTest(m map[string]any) (node, error) {
	if err := checkKeys(m, "op", "path", "value", "exists", "schema"); err != nil {
		return nil, err
	}
	p, raw, err := ptrField(m, "path")
	if err != nil {
		return nil, err
	}
	n := &testNode{path: p, raw: raw}
	count := 0
	for _, k := range []string{"value", "exists", "schema"} {
		if has(m, k) {
			count++
			n.kind = k
		}
	}
	if count != 1 {
		return nil, errors.New(`test needs exactly one of "value", "exists", "schema"`)
	}
	switch n.kind {
	case "value":
		n.value = jsonv.Clone(m["value"])
	case "exists":
		b, ok := m["exists"].(bool)
		if !ok {
			return nil, errors.New(`"exists" must be a boolean`)
		}
		n.exists = b
	case "schema":
		s, err := compileSchema(m["schema"])
		if err != nil {
			return nil, err
		}
		n.schema = s
	}
	return n, nil
}

type refuseLoader struct{}

func (refuseLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("remote schema references are not allowed (%s)", url)
}

const schemaURL = "urn:patchlog:rule"

func compileSchema(v any) (*jsonschema.Schema, error) {
	switch v.(type) {
	case map[string]any, bool:
	default:
		return nil, errors.New(`"schema" must be an object or boolean`)
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(refuseLoader{})
	c.AssertFormat()
	if err := c.AddResource(schemaURL, jsonv.Clone(v)); err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}
	s, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}
	return s, nil
}

func (n *testNode) eval(env map[string]any) bool {
	v, ok := pointer.Get(env, n.path)
	switch n.kind {
	case "value":
		return ok && jsonv.Equal(v, n.value)
	case "exists":
		return ok == n.exists
	default:
		if !ok {
			return false
		}
		return n.schema.Validate(v) == nil
	}
}
func (n *testNode) failPath(map[string]any) string { return n.raw }
func (n *testNode) refs(add func(pointer.Pointer)) { add(n.path) }

// ---- writes ----

type writesNode struct {
	kind   string // covers, overlaps, within
	target pointer.Pointer
	within []pointer.Pointer
	raw    string
}

func compileWrites(m map[string]any) (node, error) {
	if err := checkKeys(m, "op", "covers", "overlaps", "within"); err != nil {
		return nil, err
	}
	n := &writesNode{}
	count := 0
	for _, k := range []string{"covers", "overlaps", "within"} {
		if has(m, k) {
			count++
			n.kind = k
		}
	}
	if count != 1 {
		return nil, errors.New(`writes needs exactly one of "covers", "overlaps", "within"`)
	}
	if n.kind == "within" {
		arr, ok := m["within"].([]any)
		if !ok {
			return nil, errors.New(`"within" must be an array of pointers`)
		}
		for i, x := range arr {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("within[%d] must be a string pointer", i)
			}
			p, err := pointer.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("within[%d]: invalid JSON pointer %q", i, s)
			}
			n.within = append(n.within, p)
		}
		if len(arr) > 0 {
			n.raw, _ = arr[0].(string)
		}
		return n, nil
	}
	p, raw, err := ptrField(m, n.kind)
	if err != nil {
		return nil, err
	}
	n.target, n.raw = p, raw
	return n, nil
}

// writesOf returns parsed writes; ok=false entries (invalid) are reported via bad.
func writesOf(env map[string]any) (ps []pointer.Pointer, bad int) {
	arr, _ := env["writes"].([]any)
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			bad++
			continue
		}
		p, err := pointer.Parse(s)
		if err != nil {
			bad++
			continue
		}
		ps = append(ps, p)
	}
	return
}

func (n *writesNode) eval(env map[string]any) bool {
	ws, bad := writesOf(env)
	switch n.kind {
	case "covers":
		for _, w := range ws {
			if n.target.HasPrefix(w) {
				return true
			}
		}
		return false
	case "overlaps":
		for _, w := range ws {
			if n.target.Overlaps(w) {
				return true
			}
		}
		return false
	}
	if bad > 0 {
		return false
	}
	for _, w := range ws {
		ok := false
		for _, p := range n.within {
			if w.HasPrefix(p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func (n *writesNode) failPath(env map[string]any) string {
	if n.kind == "within" {
		// report the first offending write
		ws, _ := writesOf(env)
		for _, w := range ws {
			ok := false
			for _, p := range n.within {
				if w.HasPrefix(p) {
					ok = true
				}
			}
			if !ok {
				return w.String()
			}
		}
		return ""
	}
	return n.raw
}
func (n *writesNode) refs(add func(pointer.Pointer)) { add(pointer.Pointer{"writes"}) }

// ---- compare ----

type operand struct {
	isPath bool
	path   pointer.Pointer
	value  any
	raw    string
}

type compareNode struct {
	path  pointer.Pointer
	raw   string
	op    string
	right operand
}

func compileCompare(m map[string]any) (node, error) {
	if err := checkKeys(m, "op", "path", "eq", "lt", "le", "gt", "ge", "in"); err != nil {
		return nil, err
	}
	p, raw, err := ptrField(m, "path")
	if err != nil {
		return nil, err
	}
	n := &compareNode{path: p, raw: raw}
	count := 0
	for _, k := range []string{"eq", "lt", "le", "gt", "ge", "in"} {
		if has(m, k) {
			count++
			n.op = k
		}
	}
	if count != 1 {
		return nil, errors.New(`compare needs exactly one of eq, lt, le, gt, ge, in`)
	}
	o, err := asObject(m[n.op])
	if err != nil {
		return nil, fmt.Errorf("%s: operand must be an object with \"value\" or \"path\"", n.op)
	}
	if err := checkKeys(o, "value", "path"); err != nil {
		return nil, fmt.Errorf("%s: %w", n.op, err)
	}
	hv, hp := has(o, "value"), has(o, "path")
	if hv == hp {
		return nil, fmt.Errorf(`%s: operand needs exactly one of "value", "path"`, n.op)
	}
	if hv {
		n.right.value = jsonv.Clone(o["value"])
		if n.op == "in" {
			if _, ok := n.right.value.([]any); !ok {
				return nil, errors.New(`in: "value" must be an array`)
			}
		}
	} else {
		q, qraw, err := ptrField(o, "path")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n.op, err)
		}
		n.right = operand{isPath: true, path: q, raw: qraw}
	}
	return n, nil
}

func (n *compareNode) eval(env map[string]any) bool {
	l, ok := pointer.Get(env, n.path)
	if !ok {
		return false
	}
	r := n.right.value
	if n.right.isPath {
		r, ok = pointer.Get(env, n.right.path)
		if !ok {
			return false
		}
	}
	switch n.op {
	case "eq":
		return jsonv.Equal(l, r)
	case "in":
		arr, ok := r.([]any)
		if !ok {
			return false
		}
		for _, e := range arr {
			if jsonv.Equal(l, e) {
				return true
			}
		}
		return false
	}
	c, ok := order(l, r)
	if !ok {
		return false
	}
	switch n.op {
	case "lt":
		return c < 0
	case "le":
		return c <= 0
	case "gt":
		return c > 0
	default:
		return c >= 0
	}
}

func order(a, b any) (int, bool) {
	switch x := a.(type) {
	case float64:
		y, ok := b.(float64)
		if !ok {
			return 0, false
		}
		switch {
		case x < y:
			return -1, true
		case x > y:
			return 1, true
		case x == y:
			return 0, true
		}
		return 0, false
	case string:
		y, ok := b.(string)
		if !ok {
			return 0, false
		}
		tx, err1 := time.Parse(time.RFC3339Nano, x)
		ty, err2 := time.Parse(time.RFC3339Nano, y)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return tx.Compare(ty), true
	}
	return 0, false
}

func (n *compareNode) failPath(map[string]any) string { return n.raw }
func (n *compareNode) refs(add func(pointer.Pointer)) {
	add(n.path)
	if n.right.isPath {
		add(n.right.path)
	}
}

// ---- combinators ----

type allNode struct{ ns []node }
type anyNode struct{ ns []node }
type notNode struct{ n node }
type ifNode struct{ cond, then []node }

func (a *allNode) eval(env map[string]any) bool {
	for _, n := range a.ns {
		if !n.eval(env) {
			return false
		}
	}
	return true
}
func (a *allNode) failPath(env map[string]any) string {
	for _, n := range a.ns {
		if !n.eval(env) {
			return n.failPath(env)
		}
	}
	return ""
}
func (a *allNode) refs(add func(pointer.Pointer)) {
	for _, n := range a.ns {
		n.refs(add)
	}
}

func (a *anyNode) eval(env map[string]any) bool {
	for _, n := range a.ns {
		if n.eval(env) {
			return true
		}
	}
	return false
}
func (a *anyNode) failPath(env map[string]any) string { return "" }
func (a *anyNode) refs(add func(pointer.Pointer)) {
	for _, n := range a.ns {
		n.refs(add)
	}
}

func (n *notNode) eval(env map[string]any) bool { return !n.n.eval(env) }
func (n *notNode) failPath(env map[string]any) string {
	return leafPath(n.n)
}
func (n *notNode) refs(add func(pointer.Pointer)) { n.n.refs(add) }

// leafPath returns the operand pointer of a leaf node without needing a failure.
func leafPath(n node) string {
	switch x := n.(type) {
	case *testNode:
		return x.raw
	case *compareNode:
		return x.raw
	case *writesNode:
		return x.raw
	case *notNode:
		return leafPath(x.n)
	}
	return ""
}

func (n *ifNode) eval(env map[string]any) bool {
	for _, c := range n.cond {
		if !c.eval(env) {
			return true
		}
	}
	for _, t := range n.then {
		if !t.eval(env) {
			return false
		}
	}
	return true
}
func (n *ifNode) failPath(env map[string]any) string {
	for _, t := range n.then {
		if !t.eval(env) {
			return t.failPath(env)
		}
	}
	return ""
}
func (n *ifNode) refs(add func(pointer.Pointer)) {
	for _, c := range n.cond {
		c.refs(add)
	}
	for _, t := range n.then {
		t.refs(add)
	}
}
