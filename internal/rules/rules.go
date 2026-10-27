// Package rules implements the namespace rule language (SPEC §6.4.2).
package rules

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Rule is a compiled rule.
type Rule struct {
	n node
	// at is the rule's index in the list CompileList compiled it from,
	// which the path of a failure names (§6.4.3); -1 for Compile.
	at int
}

// Tri is a truth value of Kleene's three-valued logic: what EvalTri gives
// a rule some of whose envelope members the server can't see (§6.2
// End-to-end namespaces).
type Tri int8

const (
	False Tri = iota
	True
	// Unknown is the value of a rule whose outcome depends on what the
	// server can't see.
	Unknown
)

func (t Tri) String() string {
	switch t {
	case True:
		return "true"
	case False:
		return "false"
	}
	return "unknown"
}

func not3(t Tri) Tri {
	switch t {
	case True:
		return False
	case False:
		return True
	}
	return Unknown
}

// blind is the set of top-level envelope members whose values are
// unknown (EvalTri); nil for none.
type blind map[string]bool

// hides reports whether p reads what b makes unknown: a value at or below
// an unknown member, or the whole envelope, which holds them. Presence
// (an exists test) is known at the member and above it, since the
// envelope holds the member whatever its value, and unknown below it.
func (b blind) hides(p pointer.Pointer, presence bool) bool {
	if len(b) == 0 {
		return false
	}
	if len(p) == 0 {
		return !presence
	}
	return b[p[0]] && !(presence && len(p) == 1)
}

type node interface {
	// eval is the node's value in env, Unknown only where it depends on
	// a member unk makes unknown, combined in Kleene logic.
	eval(env map[string]any, unk blind) Tri
	// failPath is the pointer, relative to this node, to the rule form
	// that makes it False (§6.4.3): "", or /all/{k} or /then/{k} and
	// that member's own. Called only after eval returned False.
	failPath(env map[string]any, unk blind) string
	// refs calls add with every envelope pointer the node can read.
	refs(add func(pointer.Pointer))
}

// Compile validates and compiles one rule as stored: its schema fragments
// compile as v0.55 compiled them, held to none of the rules §6.4.2 now
// has for fragments (F-S3): the library's formats asserted, semver and
// period included, and patterns read as §6.6 says, a pattern RE2 took as
// written included (schema.Legacy). But a fragment is applied with
// draft 2020-12's format assertions whenever it was written (§6.4.2), so
// idn-email and idn-hostname, which v0.55 ignored, are asserted too. A
// rule CompileStrict accepts evaluates the same compiled so, which is how
// rules from stored namespace documents, and those of a grant decoded
// under CompileStrict, are evaluated.
func Compile(v any) (*Rule, error) { return compile(v, false) }

// CompileStrict compiles one rule written now, in a namespace document
// (§7.4) or a grant (§C.8): each schema fragment must pass
// schema.CheckFragment (§6.1's $id ban, §6.5 and §6.6 as for a schema
// document, no $schema in any subschema, same-document $ref and
// $dynamicRef only) and is asserted with draft 2020-12's format set and
// RE2 as §6.6 reads it (schema.V073), so one that breaks them makes the
// namespace document invalid (422), or the grant (401).
func CompileStrict(v any) (*Rule, error) { return compile(v, true) }

func compile(v any, strict bool) (*Rule, error) {
	n, err := compileNode(v, strict)
	if err != nil {
		return nil, err
	}
	return &Rule{n: n, at: -1}, nil
}

// CompileList compiles an array of rules as stored (Compile); nil =>
// empty list. Each rule remembers its index, which EvalList and EvalTri
// report in a failure's path (§6.4.3).
func CompileList(v any) ([]*Rule, error) { return compileList(v, nil) }

// CompileListStrict is CompileList for rules written now: each rule is
// compiled by CompileStrict, unless kept reports it (as JSON) is one the
// write keeps unchanged from a stored document, which compiles as stored
// (Compile). kept may be nil.
func CompileListStrict(v any, kept func(rule any) bool) ([]*Rule, error) {
	return compileList(v, func(x any) bool { return kept == nil || !kept(x) })
}

func compileList(v any, strict func(any) bool) ([]*Rule, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("rules must be an array")
	}
	out := make([]*Rule, 0, len(arr))
	for i, x := range arr {
		r, err := compile(x, strict != nil && strict(x))
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		r.at = i
		out = append(out, r)
	}
	return out, nil
}

// Eval evaluates the rule against a change envelope.
func (r *Rule) Eval(env map[string]any) bool { return r.n.eval(env, nil) == True }

// EvalTri evaluates the rule against a change envelope in which the
// top-level members unknown name are hidden from the server, as writes
// and doc are for a sealed write at E3 (§6.2 End-to-end namespaces):
// every writes predicate, a test or compare of a path at or below one of
// them, or of the whole envelope, is Unknown, unless it is decided
// whatever they hold (a compare that is false for its other operand, the
// presence of the member itself); all, any, not and if combine in Kleene
// logic. With no unknown members it is Eval.
func (r *Rule) EvalTri(env map[string]any, unknown ...string) Tri {
	return r.n.eval(env, blindOf(unknown))
}

func blindOf(unknown []string) blind {
	if len(unknown) == 0 {
		return nil
	}
	b := blind{}
	for _, m := range unknown {
		b[m] = true
	}
	return b
}

// EvalList runs rules in order; returns (-1, "", true) if all pass. On the
// first failing rule it returns its index in rs and the JSON Pointer to
// the failing rule form in the namespace document (§6.4.3): /rules/{i},
// i the rule's index in the list CompileList compiled it from (its index
// in rs for Compile's), descending only through the first failing member
// of an all (/all/{k}) or a then (/then/{k}); any, not, test, writes and
// compare stop at themselves.
func EvalList(rs []*Rule, env map[string]any) (int, string, bool) {
	i, path, t := evalList(rs, env, nil)
	return i, path, t == True
}

// EvalTri is EvalList in three-valued logic, with the top-level members
// unknown names hidden (Rule.EvalTri): it returns the index of the first
// rule that isn't True, its value and path, the failing rule form's for
// False, as EvalList's, and the rule's own, /rules/{i}, for Unknown,
// whose rule fails as a whole (§6.2); (-1, "", True) if all pass.
func EvalTri(rs []*Rule, env map[string]any, unknown ...string) (int, string, Tri) {
	return evalList(rs, env, blindOf(unknown))
}

func evalList(rs []*Rule, env map[string]any, unk blind) (int, string, Tri) {
	for i, r := range rs {
		t := r.n.eval(env, unk)
		if t == True {
			continue
		}
		at := r.at
		if at < 0 {
			at = i
		}
		path := "/rules/" + strconv.Itoa(at)
		if t == False {
			path += r.n.failPath(env, unk)
		}
		return i, path, t
	}
	return -1, "", True
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

func ptrField(m map[string]any, key string) (pointer.Pointer, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("missing %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%q must be a string pointer", key)
	}
	p, err := pointer.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%q: invalid JSON pointer %q", key, s)
	}
	return p, nil
}

func compileNode(v any, strict bool) (node, error) {
	m, err := asObject(v)
	if err != nil {
		return nil, err
	}
	if _, ok := m["op"]; ok {
		return compileOp(m, strict)
	}
	switch {
	case has(m, "all"):
		return compileGroup(m, "all", strict)
	case has(m, "any"):
		return compileGroup(m, "any", strict)
	case has(m, "not"):
		if err := checkKeys(m, "not"); err != nil {
			return nil, err
		}
		in, err := compileNode(m["not"], strict)
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
		c, err := compileArr(m["if"], "if", strict)
		if err != nil {
			return nil, err
		}
		t, err := compileArr(m["then"], "then", strict)
		if err != nil {
			return nil, err
		}
		return &ifNode{c, t}, nil
	}
	return nil, errors.New(`rule needs "op", "all", "any", "not" or "if"`)
}

func has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func compileArr(v any, name string, strict bool) ([]node, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%q must be an array of rules", name)
	}
	out := make([]node, 0, len(arr))
	for i, x := range arr {
		n, err := compileNode(x, strict)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func compileGroup(m map[string]any, key string, strict bool) (node, error) {
	if err := checkKeys(m, key); err != nil {
		return nil, err
	}
	ns, err := compileArr(m[key], key, strict)
	if err != nil {
		return nil, err
	}
	if key == "all" {
		return &allNode{ns}, nil
	}
	return &anyNode{ns}, nil
}

func compileOp(m map[string]any, strict bool) (node, error) {
	op, ok := m["op"].(string)
	if !ok {
		return nil, errors.New(`"op" must be a string`)
	}
	switch op {
	case "test":
		return compileTest(m, strict)
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
	kind   string // value, exists, schema
	value  any
	exists bool
	schema *jsonschema.Schema
}

func compileTest(m map[string]any, strict bool) (node, error) {
	if err := checkKeys(m, "op", "path", "value", "exists", "schema"); err != nil {
		return nil, err
	}
	p, err := ptrField(m, "path")
	if err != nil {
		return nil, err
	}
	n := &testNode{path: p}
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
		s, err := compileSchema(m["schema"], strict)
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

// compileSchema compiles a test's schema fragment with format assertions
// (§6.4.2). strict holds it to the rules of a fragment written now and
// compiles it under schema.V073 (CompileStrict); otherwise it compiles
// as stored, under schema.Legacy, as v0.55 did, but for patterns with
// \uXXXX, which RE2 refused then, and idn-email and idn-hostname, which
// it didn't assert (schema.Rules.ConfigureFragment).
func compileSchema(v any, strict bool) (*jsonschema.Schema, error) {
	switch v.(type) {
	case map[string]any, bool:
	default:
		return nil, errors.New(`"schema" must be an object or boolean`)
	}
	rs := schema.Legacy
	if strict {
		if err := schema.CheckFragment(v); err != nil {
			return nil, err
		}
		rs = schema.V073
	}
	c := jsonschema.NewCompiler()
	rs.ConfigureFragment(c)
	c.UseLoader(refuseLoader{})
	if err := c.AddResource(schemaURL, jsonv.Clone(v)); err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}
	s, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}
	return s, nil
}

func (n *testNode) eval(env map[string]any, unk blind) Tri {
	if unk.hides(n.path, n.kind == "exists") {
		return Unknown
	}
	v, ok := pointer.Get(env, n.path)
	switch n.kind {
	case "value":
		return tri(ok && jsonv.Equal(v, n.value))
	case "exists":
		return tri(ok == n.exists)
	default:
		if !ok {
			return False
		}
		return tri(n.schema.Validate(v) == nil)
	}
}
func (n *testNode) failPath(map[string]any, blind) string { return "" }
func (n *testNode) refs(add func(pointer.Pointer))        { add(n.path) }

func tri(b bool) Tri {
	if b {
		return True
	}
	return False
}

// ---- writes ----

type writesNode struct {
	kind   string // covers, overlaps, within
	target pointer.Pointer
	within []pointer.Pointer
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
		return n, nil
	}
	p, err := ptrField(m, n.kind)
	if err != nil {
		return nil, err
	}
	n.target = p
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

func (n *writesNode) eval(env map[string]any, unk blind) Tri {
	if unk["writes"] {
		return Unknown
	}
	ws, bad := writesOf(env)
	switch n.kind {
	case "covers":
		for _, w := range ws {
			if n.target.HasPrefix(w) {
				return True
			}
		}
		return False
	case "overlaps":
		for _, w := range ws {
			if n.target.Overlaps(w) {
				return True
			}
		}
		return False
	}
	if bad > 0 {
		return False
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
			return False
		}
	}
	return True
}
func (n *writesNode) failPath(map[string]any, blind) string { return "" }
func (n *writesNode) refs(add func(pointer.Pointer))        { add(pointer.Pointer{"writes"}) }

// ---- compare ----

type operand struct {
	isPath bool
	path   pointer.Pointer
	value  any
}

type compareNode struct {
	path  pointer.Pointer
	op    string
	right operand
}

func compileCompare(m map[string]any) (node, error) {
	if err := checkKeys(m, "op", "path", "eq", "lt", "le", "gt", "ge", "in"); err != nil {
		return nil, err
	}
	p, err := ptrField(m, "path")
	if err != nil {
		return nil, err
	}
	n := &compareNode{path: p}
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
		// A literal that isn't an array makes in false, as a path to one
		// does, not the rule invalid (§6.4.2).
		n.right.value = jsonv.Clone(o["value"])
	} else {
		q, err := ptrField(o, "path")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n.op, err)
		}
		n.right = operand{isPath: true, path: q}
	}
	return n, nil
}

func (n *compareNode) eval(env map[string]any, unk blind) Tri {
	// Each operand is missing (false whatever the other holds), known,
	// or hidden by unk; a known one can decide alone (decides), and so
	// can the whole envelope, an object whatever it holds.
	unknown := false
	get := func(p pointer.Pointer, right bool) (any, bool) {
		if unk.hides(p, false) {
			unknown = true
			return nil, len(p) != 0 || !n.decides(env, right)
		}
		v, ok := pointer.Get(env, p)
		return v, ok && !n.decides(v, right)
	}
	l, ok := get(n.path, false)
	if !ok {
		return False
	}
	r := n.right.value
	if n.right.isPath {
		r, ok = get(n.right.path, true)
	} else {
		ok = !n.decides(r, true)
	}
	if !ok {
		return False
	}
	if unknown {
		return Unknown
	}
	switch n.op {
	case "eq":
		return tri(jsonv.Equal(l, r))
	case "in":
		for _, e := range r.([]any) {
			if jsonv.Equal(l, e) {
				return True
			}
		}
		return False
	}
	c, ok := order(l, r)
	if !ok {
		return False
	}
	switch n.op {
	case "lt":
		return tri(c < 0)
	case "le":
		return tri(c <= 0)
	case "gt":
		return tri(c > 0)
	default:
		return tri(c >= 0)
	}
}

// decides reports whether operand v makes the compare false whatever the
// other holds (§6.4.2): a right-hand side of in that isn't an array, or
// an operand of lt, le, gt or ge of an unsupported type.
func (n *compareNode) decides(v any, right bool) bool {
	switch n.op {
	case "eq":
		return false
	case "in":
		_, arr := v.([]any)
		return right && !arr
	}
	switch x := v.(type) {
	case float64:
		return false
	case string:
		_, ok := parseDateTime(x)
		return !ok
	}
	return true
}

// order compares two numbers, or two RFC 3339 date-times as instants
// (§6.4.2); ok is false for operands of different or unsupported types.
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
		tx, ok1 := parseDateTime(x)
		ty, ok2 := parseDateTime(y)
		if !ok1 || !ok2 {
			return 0, false
		}
		return tx.compare(ty), true
	}
	return 0, false
}

// instant is an RFC 3339 date-time as a UTC instant: whole seconds since
// the Unix epoch, and the digits of its fractional second without
// trailing zeros, kept at whatever precision it was written.
type instant struct {
	sec  int64
	frac string
}

// compare orders two instants. Fractions without trailing zeros order as
// their digit strings do.
func (a instant) compare(b instant) int {
	switch {
	case a.sec < b.sec:
		return -1
	case a.sec > b.sec:
		return 1
	}
	return strings.Compare(a.frac, b.frac)
}

// parseDateTime parses an RFC 3339 date-time (§5.6):
// YYYY-MM-DDTHH:MM:SS[.digits](Z|±HH:MM), with any number of fractional
// digits. A leap second (:60) is of an unsupported type (§6.4.2), and so
// are a lowercase t or z (the ABNF's case-insensitivity is left
// unsupported, F-G5) and a space for the T.
func parseDateTime(s string) (instant, bool) {
	if len(s) < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return instant{}, false
	}
	num := func(i, n int) (int, bool) {
		v := 0
		for _, c := range []byte(s[i : i+n]) {
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int(c-'0')
		}
		return v, true
	}
	y, ok1 := num(0, 4)
	mo, ok2 := num(5, 2)
	d, ok3 := num(8, 2)
	h, ok4 := num(11, 2)
	mi, ok5 := num(14, 2)
	sec, ok6 := num(17, 2)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || sec > 59 {
		return instant{}, false
	}
	if d > time.Date(y, time.Month(mo)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return instant{}, false
	}
	rest := s[19:]
	var frac string
	if rest != "" && rest[0] == '.' {
		k := 1
		for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
			k++
		}
		if k == 1 {
			return instant{}, false
		}
		frac = strings.TrimRight(rest[1:k], "0")
		rest = rest[k:]
	}
	off := 0
	switch {
	case rest == "Z":
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-') && rest[3] == ':':
		oh, ok1 := num(len(s)-5, 2)
		om, ok2 := num(len(s)-2, 2)
		if !ok1 || !ok2 || oh > 23 || om > 59 {
			return instant{}, false
		}
		off = oh*3600 + om*60
		if rest[0] == '-' {
			off = -off
		}
	default:
		return instant{}, false
	}
	t := time.Date(y, time.Month(mo), d, h, mi, sec, 0, time.UTC).Unix() - int64(off)
	return instant{sec: t, frac: frac}, true
}

func (n *compareNode) failPath(map[string]any, blind) string { return "" }
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

func (a *allNode) eval(env map[string]any, unk blind) Tri {
	return all3(a.ns, env, unk)
}

// all3 is the Kleene conjunction of ns: False if any is, else Unknown if
// any is, else True.
func all3(ns []node, env map[string]any, unk blind) Tri {
	out := True
	for _, n := range ns {
		switch n.eval(env, unk) {
		case False:
			return False
		case Unknown:
			out = Unknown
		}
	}
	return out
}

// firstFalse is the path through the first of ns that is False, under
// the member name key (§6.4.3).
func firstFalse(key string, ns []node, env map[string]any, unk blind) string {
	for k, n := range ns {
		if n.eval(env, unk) == False {
			return "/" + key + "/" + strconv.Itoa(k) + n.failPath(env, unk)
		}
	}
	return ""
}

func (a *allNode) failPath(env map[string]any, unk blind) string {
	return firstFalse("all", a.ns, env, unk)
}
func (a *allNode) refs(add func(pointer.Pointer)) {
	for _, n := range a.ns {
		n.refs(add)
	}
}

func (a *anyNode) eval(env map[string]any, unk blind) Tri {
	out := False
	for _, n := range a.ns {
		switch n.eval(env, unk) {
		case True:
			return True
		case Unknown:
			out = Unknown
		}
	}
	return out
}
func (a *anyNode) failPath(map[string]any, blind) string { return "" }
func (a *anyNode) refs(add func(pointer.Pointer)) {
	for _, n := range a.ns {
		n.refs(add)
	}
}

func (n *notNode) eval(env map[string]any, unk blind) Tri { return not3(n.n.eval(env, unk)) }
func (n *notNode) failPath(map[string]any, blind) string  { return "" }
func (n *notNode) refs(add func(pointer.Pointer))         { n.n.refs(add) }

// eval is "not all of if, or all of then" in Kleene logic.
func (n *ifNode) eval(env map[string]any, unk blind) Tri {
	c := all3(n.cond, env, unk)
	if c == False {
		return True
	}
	t := all3(n.then, env, unk)
	if t == True || c == True {
		return t
	}
	return Unknown
}
func (n *ifNode) failPath(env map[string]any, unk blind) string {
	return firstFalse("then", n.then, env, unk)
}
func (n *ifNode) refs(add func(pointer.Pointer)) {
	for _, c := range n.cond {
		c.refs(add)
	}
	for _, t := range n.then {
		t.refs(add)
	}
}
