package jsv

import (
	"errors"
	"math"
	"math/bits"
	"slices"
	"strconv"
	"sync"
	"unicode/utf8"
)

// ErrBudget reports that validation used up ValidateOptions.Budget before
// reaching a verdict.
var ErrBudget = errors.New("jsv: validation step budget exhausted")

// ValidateOptions bound and observe one validation.
type ValidateOptions struct {
	// Budget is the number of steps validation may take, 0 for no limit.
	// A step is one evaluation of a schema node against an instance value;
	// uniqueItems also counts one per item it compares.
	Budget int
	// Stats, if set, receives what the validation cost, whatever its
	// outcome.
	Stats *Stats
}

// Stats is the cost of one validation.
type Stats struct {
	Steps int
}

// ValidationError is the first failure validation found.
type ValidationError struct {
	InstancePath string // JSON Pointer to the failing value
	KeywordPath  string // the keywords walked from the root schema, as a JSON Pointer, through references
	Message      string
}

func (e *ValidationError) Error() string {
	p := e.InstancePath
	if p == "" {
		p = "(root)"
	}
	return "jsv: " + p + ": " + e.Message
}

// tok is one token of a path being built: a key, or an index if i >= 0.
type tok struct {
	s string
	i int
}

// state is one validation run. It is pooled: a run on a valid document
// allocates nothing.
type state struct {
	sch    *Schema
	steps  int
	budget int
	over   bool // budget exhausted: every evaluation now fails
	quiet  int  // > 0 inside a branch whose failure is not the verdict

	// The schemas being evaluated against the current instance, from base
	// on; kept only if sch.cyclic. A schema met again there fails.
	chain []*node
	base  int

	failed  bool // a failure is recorded, and being unwound
	errNode *node
	errKw   string
	errVal  any
	errArg  string
	errNum  int
	ipath   []tok // innermost first
	kpath   []tok

	regexp func(string) (Matcher, error) // for the regex format
	scope  []*resource                   // dynamic scope, outermost first; only if sch.dynamic
	evFree []*evals
	hashes []hashed // scratch for uniqueItems
}

var statePool = sync.Pool{New: func() any { return new(state) }}

func (sc *Schema) newState(o ValidateOptions) *state {
	s := statePool.Get().(*state)
	s.sch, s.regexp = sc, sc.regexp
	s.steps, s.budget = 0, o.Budget
	s.over, s.failed = false, false
	s.quiet, s.base = 0, 0
	s.ipath, s.kpath, s.scope, s.chain = s.ipath[:0], s.kpath[:0], s.scope[:0], s.chain[:0]
	return s
}

// finish turns the run into its result and returns the state to the pool.
func (s *state) finish(ok bool, o ValidateOptions) error {
	if o.Stats != nil {
		o.Stats.Steps = s.steps
	}
	var err error
	switch {
	case s.over:
		err = ErrBudget
	case !ok:
		err = s.validationError()
	}
	s.errNode, s.errVal, s.sch, s.regexp = nil, nil, nil, nil
	clear(s.ipath)
	clear(s.kpath)
	clear(s.scope)
	clear(s.chain[:cap(s.chain)])
	statePool.Put(s)
	return err
}

// Validate reports whether v is valid against the schema: nil, or a
// *ValidationError for the first failure found, or ErrBudget.
func (sc *Schema) Validate(v any, o ValidateOptions) error {
	s := sc.newState(o)
	return s.finish(s.eval(sc.root, v, nil), o)
}

// fail records the failure of keyword kw of n on v, unless a branch is
// being tried, and returns false.
func (s *state) fail(n *node, kw string, v any) bool {
	if s.quiet == 0 && !s.failed && !s.over {
		s.failed, s.errNode, s.errKw, s.errVal, s.errArg = true, n, kw, v, ""
	}
	return false
}

func (s *state) failArg(n *node, kw string, v any, arg string, num int) bool {
	if s.quiet == 0 && !s.failed && !s.over {
		s.failed, s.errNode, s.errKw, s.errVal, s.errArg, s.errNum = true, n, kw, v, arg, num
	}
	return false
}

// The up functions add to the paths of a recorded failure as it unwinds
// through the keyword that applied the failing schema. They return false.

func (s *state) upKw(kw string) bool {
	if s.failed {
		s.kpath = append(s.kpath, tok{kw, -1})
	}
	return false
}

func (s *state) upKwAt(kw string, i int) bool {
	if s.failed {
		s.kpath = append(s.kpath, tok{"", i}, tok{kw, -1})
	}
	return false
}

func (s *state) upKwKey(kw, key string) bool {
	if s.failed {
		s.kpath = append(s.kpath, tok{key, -1}, tok{kw, -1})
	}
	return false
}

func (s *state) upProp(key, kw, kwKey string) bool {
	if s.failed {
		s.ipath = append(s.ipath, tok{key, -1})
		if kwKey != "" {
			s.kpath = append(s.kpath, tok{kwKey, -1})
		}
		s.kpath = append(s.kpath, tok{kw, -1})
	}
	return false
}

func (s *state) upItem(i int, kw string, kwIdx int) bool {
	if s.failed {
		s.ipath = append(s.ipath, tok{"", i})
		if kwIdx >= 0 {
			s.kpath = append(s.kpath, tok{"", kwIdx})
		}
		s.kpath = append(s.kpath, tok{kw, -1})
	}
	return false
}

// eval evaluates n against v: one step. ev, if not nil, collects which
// properties and items of v were evaluated, for an unevaluated* keyword of
// a schema applied to the same instance.
func (s *state) eval(n *node, v any, ev *evals) bool {
	if s.over {
		return false // the count stays where the budget ran out
	}
	s.steps++
	if s.budget > 0 && s.steps > s.budget {
		s.over = true
		return false
	}
	if n.boolean != 0 {
		if n.boolean > 0 {
			return true
		}
		return s.fail(n, "false", v)
	}
	if s.sch.cyclic {
		// A schema that comes back to itself on the same instance fails
		// there, as a reference cycle does in the library this package
		// replaced: {"$ref": "#"} admits nothing.
		for _, on := range s.chain[s.base:] {
			if on == n {
				return s.fail(n, "cycle", v)
			}
		}
		s.chain = append(s.chain, n)
	}
	ok := s.scoped(n, v, ev)
	if s.sch.cyclic {
		s.chain = s.chain[:len(s.chain)-1]
	}
	return ok
}

// scoped evaluates n with its resource in the dynamic scope.
func (s *state) scoped(n *node, v any, ev *evals) bool {
	if s.sch.dynamic && (len(s.scope) == 0 || s.scope[len(s.scope)-1] != n.res) {
		s.scope = append(s.scope, n.res)
		ok := s.evalNode(n, v, ev)
		s.scope = s.scope[:len(s.scope)-1]
		return ok
	}
	return s.evalNode(n, v, ev)
}

// child evaluates n against a child of the current instance.
func (s *state) child(n *node, v any) bool {
	b := s.base
	s.base = len(s.chain)
	ok := s.eval(n, v, nil)
	s.base = b
	return ok
}

func (s *state) evalNode(n *node, v any, ev *evals) bool {
	if !n.uneval {
		return s.evalBody(n, v, ev)
	}
	// unevaluated* sees what this schema's own keywords and in-place
	// subschemas evaluated, not what its siblings under a parent did.
	local := s.getEvals()
	ok := s.evalBody(n, v, local) && s.unevaluated(n, v, local)
	if ok && ev != nil {
		ev.merge(local)
	}
	s.putEvals(local)
	return ok
}

// evalBody evaluates every keyword of n but unevaluated*, cheapest first:
// assertions on the value itself, then scalar children, then container
// children, then in-place applicators. A branch of a oneOf whose
// discriminator fails is so rejected before anything is recursed into.
func (s *state) evalBody(n *node, v any, ev *evals) bool {
	switch x := v.(type) {
	case map[string]any:
		// Going by the declared properties (unless far more are declared
		// than present) finds a missing required one in passing.
		bySchema := len(n.props) > 0 && len(n.props) <= 2*len(x)+4
		if !s.assert(n, v, bySchema) {
			return false
		}
		if n.propNames != nil && !s.propertyNames(n, x) {
			return false
		}
		if n.hasProps && !s.properties(n, x, ev, bySchema) {
			return false
		}
		return !n.hasInPlace || s.inPlace(n, v, ev)
	}
	if !s.assert(n, v, false) {
		return false
	}
	switch x := v.(type) {
	case []any:
		if n.hasItems && !s.items(n, x, ev) {
			return false
		}
		if n.contains != nil && !s.containsOK(n, x, v, ev) {
			return false
		}
	}
	return !n.hasInPlace || s.inPlace(n, v, ev)
}

// inPlace applies the applicators that apply subschemas to v itself.
func (s *state) inPlace(n *node, v any, ev *evals) bool {
	if n.ref != nil && !s.eval(n.ref, v, ev) {
		return s.upKw("$ref")
	}
	for i, sub := range n.allOf {
		if !s.eval(sub, v, ev) {
			return s.upKwAt("allOf", i)
		}
	}
	return !n.hasRest || s.inPlaceRest(n, v, ev)
}

// assert checks the keywords of n that look at v itself and apply no
// subschema. With bySchema, the presence of required members that
// properties declares is left to properties.
func (s *state) assert(n *node, v any, bySchema bool) bool {
	switch x := v.(type) {
	case string:
		if n.types != 0 && n.types&tString == 0 {
			return s.fail(n, "type", v)
		}
		if n.hasValue && !s.value(n, v) {
			return false
		}
		if n.hasStr {
			return s.str(n, x, v)
		}
	case float64:
		if n.types != 0 && n.types&tNumber == 0 && (n.types&tInteger == 0 || x != math.Trunc(x)) {
			return s.fail(n, "type", v)
		}
		if n.hasValue && !s.value(n, v) {
			return false
		}
		if n.hasNum {
			return s.num(n, x, v)
		}
	case map[string]any:
		if n.types != 0 && n.types&tObject == 0 {
			return s.fail(n, "type", v)
		}
		if n.hasValue && !s.value(n, v) {
			return false
		}
		if n.hasObj {
			return s.obj(n, x, v, bySchema)
		}
	case []any:
		if n.types != 0 && n.types&tArray == 0 {
			return s.fail(n, "type", v)
		}
		if n.hasValue && !s.value(n, v) {
			return false
		}
		if n.hasArr {
			return s.arr(n, x, v)
		}
	case bool:
		if n.types != 0 && n.types&tBool == 0 {
			return s.fail(n, "type", v)
		}
		if n.hasValue {
			return s.value(n, v)
		}
	case nil:
		if n.types != 0 && n.types&tNull == 0 {
			return s.fail(n, "type", v)
		}
		if n.hasValue {
			return s.value(n, v)
		}
	default:
		return s.fail(n, "value", v)
	}
	return true
}

func (s *state) value(n *node, v any) bool {
	if n.hasConst && !equal(n.constVal, v) {
		return s.fail(n, "const", v)
	}
	if n.enum != nil && !n.enum.has(v) {
		return s.fail(n, "enum", v)
	}
	return true
}

func (s *state) num(n *node, x float64, v any) bool {
	switch {
	case n.hasMin && x < n.min:
		return s.fail(n, "minimum", v)
	case n.hasMax && x > n.max:
		return s.fail(n, "maximum", v)
	case n.hasXMin && x <= n.xmin:
		return s.fail(n, "exclusiveMinimum", v)
	case n.hasXMax && x >= n.xmax:
		return s.fail(n, "exclusiveMaximum", v)
	case n.multipleOf != nil && !n.multipleOf.divides(x):
		return s.fail(n, "multipleOf", v)
	}
	return true
}

func (s *state) str(n *node, x string, v any) bool {
	// A string has at most as many characters as bytes, and at least a
	// quarter as many.
	if n.minLen > 0 && (len(x) < n.minLen || len(x) < 4*n.minLen && utf8.RuneCountInString(x) < n.minLen) {
		return s.fail(n, "minLength", v)
	}
	if n.maxLen >= 0 && len(x) > n.maxLen && utf8.RuneCountInString(x) > n.maxLen {
		return s.fail(n, "maxLength", v)
	}
	if n.pattern != nil && !n.pattern.MatchString(x) {
		return s.fail(n, "pattern", v)
	}
	if n.format != nil && !n.format(x) {
		return s.fail(n, "format", v)
	}
	if n.formatRegex {
		if _, err := s.regexp(x); err != nil {
			return s.fail(n, "format", v)
		}
	}
	return true
}

func (s *state) obj(n *node, x map[string]any, v any, bySchema bool) bool {
	if n.minProps >= 0 && len(x) < n.minProps {
		return s.fail(n, "minProperties", v)
	}
	if n.maxProps >= 0 && len(x) > n.maxProps {
		return s.fail(n, "maxProperties", v)
	}
	required := n.required
	if bySchema {
		required = n.requiredOther
	}
	for _, k := range required {
		if _, ok := x[k]; !ok {
			return s.failArg(n, "required", v, k, 0)
		}
	}
	for i := range n.depRequired {
		d := &n.depRequired[i]
		if _, ok := x[d.key]; !ok {
			continue
		}
		for _, k := range d.need {
			if _, ok := x[k]; !ok {
				return s.failArg(n, "dependentRequired", v, k, 0)
			}
		}
	}
	return true
}

func (s *state) arr(n *node, x []any, v any) bool {
	if n.minItems >= 0 && len(x) < n.minItems {
		return s.fail(n, "minItems", v)
	}
	if n.maxItems >= 0 && len(x) > n.maxItems {
		return s.fail(n, "maxItems", v)
	}
	if n.unique && len(x) > 1 {
		return s.uniqueItems(n, x, v)
	}
	return true
}

func isContainer(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

// properties applies properties, patternProperties and
// additionalProperties.
func (s *state) properties(n *node, x map[string]any, ev *evals, bySchema bool) bool {
	matched := 0
	if len(n.props) > 0 {
		// Scalar members first: they are cheap, and a discriminator is one.
		containers := false
		if bySchema {
			for i := range n.props {
				p := &n.props[i]
				pv, ok := x[p.key]
				if !ok {
					if p.required {
						return s.failArg(n, "required", x, p.key, 0)
					}
					continue
				}
				matched++
				if ev != nil {
					ev.addProp(p.key)
				}
				if isContainer(pv) {
					containers = true
				} else if !s.child(p.n, pv) {
					return s.upProp(p.key, "properties", p.key)
				}
			}
			if containers {
				for i := range n.props {
					p := &n.props[i]
					if pv, ok := x[p.key]; ok && isContainer(pv) && !s.child(p.n, pv) {
						return s.upProp(p.key, "properties", p.key)
					}
				}
			}
		} else {
			// Far more declared than present: go by the instance.
			for k, pv := range x {
				pn := n.propMap[k]
				if pn == nil {
					continue
				}
				matched++
				if ev != nil {
					ev.addProp(k)
				}
				if isContainer(pv) {
					containers = true
				} else if !s.child(pn, pv) {
					return s.upProp(k, "properties", k)
				}
			}
			if containers {
				for k, pv := range x {
					if !isContainer(pv) {
						continue
					}
					if pn := n.propMap[k]; pn != nil && !s.child(pn, pv) {
						return s.upProp(k, "properties", k)
					}
				}
			}
		}
	}
	if len(n.patProps) == 0 && (n.addProps == nil || matched == len(x)) {
		if n.addProps != nil && ev != nil {
			ev.allProps = true
		}
		return true
	}
	for k, pv := range x {
		hit := n.propMap != nil && n.propMap[k] != nil
		for i := range n.patProps {
			p := &n.patProps[i]
			if !p.re.MatchString(k) {
				continue
			}
			hit = true
			if ev != nil {
				ev.addProp(k)
			}
			if !s.child(p.n, pv) {
				return s.upProp(k, "patternProperties", p.src)
			}
		}
		if !hit && n.addProps != nil {
			if n.addProps.boolean < 0 {
				s.steps++
				return s.failArg(n, "additionalProperties", x, k, 0)
			}
			if !s.child(n.addProps, pv) {
				return s.upProp(k, "additionalProperties", "")
			}
		}
	}
	if n.addProps != nil && ev != nil {
		ev.allProps = true
	}
	return true
}

func (s *state) propertyNames(n *node, x map[string]any) bool {
	for k := range x {
		if !s.child(n.propNames, k) {
			// The failing value is the name, which no pointer names: the
			// instance path stays at the object.
			return s.upKw("propertyNames")
		}
	}
	return true
}

// items applies prefixItems and items.
func (s *state) items(n *node, x []any, ev *evals) bool {
	np := min(len(n.prefix), len(x))
	for i := 0; i < np; i++ {
		if !s.child(n.prefix[i], x[i]) {
			return s.upItem(i, "prefixItems", i)
		}
	}
	if ev != nil && np > ev.nItems {
		ev.nItems = np
	}
	if n.items != nil {
		it := n.items
		for i := np; i < len(x); i++ {
			if !s.child(it, x[i]) {
				return s.upItem(i, "items", -1)
			}
		}
		if ev != nil {
			ev.allItems = true
		}
	}
	return true
}

// containsOK applies contains, minContains and maxContains.
func (s *state) containsOK(n *node, x []any, v any, ev *evals) bool {
	count := 0
	s.quiet++
	for i, e := range x {
		if !s.child(n.contains, e) {
			continue
		}
		count++
		if ev != nil {
			ev.addItem(i)
			continue
		}
		if n.maxContains < 0 && count >= n.minContains || n.maxContains >= 0 && count > n.maxContains {
			break
		}
	}
	s.quiet--
	if count < n.minContains {
		if n.minContains == 1 {
			return s.fail(n, "contains", v)
		}
		return s.failArg(n, "minContains", v, "", count)
	}
	if n.maxContains >= 0 && count > n.maxContains {
		return s.failArg(n, "maxContains", v, "", count)
	}
	return true
}

// inPlaceRest applies the in-place applicators other than $ref and allOf.
func (s *state) inPlaceRest(n *node, v any, ev *evals) bool {
	if n.dynRef != nil && !s.eval(s.dynTarget(n), v, ev) {
		return s.upKw("$dynamicRef")
	}
	if n.anyOf != nil && !s.anyOfOK(n, v, ev, 0) {
		return false
	}
	if n.oneOf != nil && !s.oneOfOK(n, v, ev, 0) {
		return false
	}
	return s.conditionals(n, v, ev)
}

// dynTarget returns the schema the $dynamicRef of n names here: the
// outermost $dynamicAnchor of its name in the dynamic scope, if the
// reference resolves to one at all.
func (s *state) dynTarget(n *node) *node {
	if n.dynName != "" {
		for _, r := range s.scope {
			if t := r.dynNodes[n.dynName]; t != nil {
				return t
			}
		}
	}
	return n.dynRef
}

// anyOfOK applies anyOf. The branches in the bit set skip are known to
// fail and are not evaluated.
func (s *state) anyOfOK(n *node, v any, ev *evals, skip uint64) bool {
	found := false
	s.quiet++
	if ev == nil {
		for i, sub := range n.anyOf {
			if i < 64 && skip&(1<<i) != 0 {
				continue
			}
			if s.eval(sub, v, nil) {
				found = true
				break
			}
		}
	} else {
		// Every branch that holds contributes what it evaluated.
		tmp := s.getEvals()
		for _, sub := range n.anyOf {
			tmp.reset()
			if s.eval(sub, v, tmp) {
				found = true
				ev.merge(tmp)
			}
		}
		s.putEvals(tmp)
	}
	s.quiet--
	if !found {
		return s.fail(n, "anyOf", v)
	}
	return true
}

// oneOfOK applies oneOf, skip as for anyOfOK.
func (s *state) oneOfOK(n *node, v any, ev *evals, skip uint64) bool {
	count := 0
	var tmp *evals
	if ev != nil {
		tmp = s.getEvals()
	}
	s.quiet++
	for i, sub := range n.oneOf {
		if i < 64 && skip&(1<<i) != 0 {
			continue
		}
		if tmp != nil {
			tmp.reset()
		}
		if s.eval(sub, v, tmp) {
			count++
			if count > 1 {
				break
			}
			if tmp != nil {
				ev.merge(tmp)
			}
		}
	}
	s.quiet--
	if tmp != nil {
		s.putEvals(tmp)
	}
	if count != 1 {
		return s.failArg(n, "oneOf", v, "", count)
	}
	return true
}

// conditionals applies not, if/then/else and dependentSchemas.
func (s *state) conditionals(n *node, v any, ev *evals) bool {
	if n.not != nil {
		s.quiet++
		ok := s.eval(n.not, v, nil)
		s.quiet--
		if ok {
			return s.fail(n, "not", v)
		}
	}
	if n.ifN != nil {
		var tmp *evals
		if ev != nil {
			tmp = s.getEvals()
		}
		s.quiet++
		cond := s.eval(n.ifN, v, tmp)
		s.quiet--
		if tmp != nil {
			if cond {
				ev.merge(tmp)
			}
			s.putEvals(tmp)
		}
		if cond {
			if n.thenN != nil && !s.eval(n.thenN, v, ev) {
				return s.upKw("then")
			}
		} else if n.elseN != nil && !s.eval(n.elseN, v, ev) {
			return s.upKw("else")
		}
	}
	if len(n.depSchemas) > 0 {
		if x, ok := v.(map[string]any); ok {
			for i := range n.depSchemas {
				d := &n.depSchemas[i]
				if _, ok := x[d.key]; ok && !s.eval(d.n, v, ev) {
					return s.upKwKey("dependentSchemas", d.key)
				}
			}
		}
	}
	return true
}

// unevaluated applies unevaluatedProperties and unevaluatedItems, given
// what the rest of n evaluated.
func (s *state) unevaluated(n *node, v any, ev *evals) bool {
	switch x := v.(type) {
	case map[string]any:
		if n.unevalProps == nil {
			return true
		}
		if !ev.allProps {
			for k, pv := range x {
				if ev.hasProp(k) {
					continue
				}
				if !s.child(n.unevalProps, pv) {
					return s.upProp(k, "unevaluatedProperties", "")
				}
			}
		}
		ev.allProps = true
	case []any:
		if n.unevalItems == nil {
			return true
		}
		if !ev.allItems {
			for i := ev.nItems; i < len(x); i++ {
				if ev.hasItem(i) {
					continue
				}
				if !s.child(n.unevalItems, x[i]) {
					return s.upItem(i, "unevaluatedItems", -1)
				}
			}
		}
		ev.allItems = true
	}
	return true
}

// evals is what was evaluated of one object or array.
type evals struct {
	allProps bool
	allItems bool
	nItems   int // items [0, nItems) are evaluated
	props    map[string]struct{}
	items    map[int]struct{} // beyond nItems, by contains
}

func (e *evals) reset() {
	e.allProps, e.allItems, e.nItems = false, false, 0
	clear(e.props)
	clear(e.items)
}

func (e *evals) addProp(k string) {
	if e.props == nil {
		e.props = map[string]struct{}{}
	}
	e.props[k] = struct{}{}
}

func (e *evals) hasProp(k string) bool {
	_, ok := e.props[k]
	return ok
}

func (e *evals) addItem(i int) {
	if e.items == nil {
		e.items = map[int]struct{}{}
	}
	e.items[i] = struct{}{}
}

func (e *evals) hasItem(i int) bool {
	_, ok := e.items[i]
	return ok
}

func (e *evals) merge(o *evals) {
	e.allProps = e.allProps || o.allProps
	e.allItems = e.allItems || o.allItems
	e.nItems = max(e.nItems, o.nItems)
	for k := range o.props {
		e.addProp(k)
	}
	for i := range o.items {
		e.addItem(i)
	}
}

func (s *state) getEvals() *evals {
	if n := len(s.evFree); n > 0 {
		e := s.evFree[n-1]
		s.evFree = s.evFree[:n-1]
		e.reset()
		return e
	}
	return new(evals)
}

func (s *state) putEvals(e *evals) { s.evFree = append(s.evFree, e) }

// equal is JSON equality: numbers by value, objects regardless of order.
func equal(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !equal(xv, yv) {
				return false
			}
		}
		return true
	}
	return false
}

type hashed struct {
	h uint64
	i int
}

const (
	hashSeed  = 0x9E3779B97F4A7C15
	hashPrime = 0x100000001B3
)

func mix(h, x uint64) uint64 {
	h ^= x
	h *= hashSeed
	return h ^ h>>29
}

func hashString(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * hashPrime
	}
	return mix(h, uint64(len(s)))
}

// hashValue hashes v so that equal values hash alike.
func hashValue(v any) uint64 {
	switch x := v.(type) {
	case nil:
		return 1
	case bool:
		if x {
			return 2
		}
		return 3
	case float64:
		if x == 0 {
			x = 0 // -0 equals 0
		}
		return mix(4, math.Float64bits(x))
	case string:
		return hashString(5, x)
	case []any:
		h := uint64(6)
		for _, e := range x {
			h = mix(h, hashValue(e))
		}
		return h
	case map[string]any:
		var sum uint64
		for k, e := range x {
			sum += mix(hashString(7, k), hashValue(e))
		}
		return mix(8, sum)
	}
	return 0
}

// uniqueItems compares items by hash, so it costs the size of the array,
// not its square. It counts one step per item.
func (s *state) uniqueItems(n *node, x []any, v any) bool {
	s.steps += len(x)
	if s.budget > 0 && s.steps > s.budget {
		s.over = true
		return false
	}
	hs := s.hashes[:0]
	for i, e := range x {
		hs = append(hs, hashed{hashValue(e), i})
	}
	s.hashes = hs
	slices.SortFunc(hs, func(a, b hashed) int {
		switch {
		case a.h < b.h:
			return -1
		case a.h > b.h:
			return 1
		}
		return a.i - b.i
	})
	for i := 1; i < len(hs); i++ {
		for j := i - 1; j >= 0 && hs[j].h == hs[i].h; j-- {
			if equal(x[hs[j].i], x[hs[i].i]) {
				return s.failArg(n, "uniqueItems", v, strconv.Itoa(hs[j].i), hs[i].i)
			}
		}
	}
	return true
}

// multiple is a multipleOf divisor. The verdict is that of exact decimal
// arithmetic on the shortest decimal that reads back as each float64,
// which is what a JSON text says: 0.0075 is a multiple of 0.0001.
type multiple struct {
	f       float64
	integer bool // f is an integer below 2^53
	m       uint64
	e       int
}

func newMultiple(f float64) *multiple {
	m, e := decimal(f)
	return &multiple{f: f, integer: f == math.Trunc(f) && f < 1<<53, m: m, e: e}
}

// decimal returns m and e with |f| = m * 10^e, m not a multiple of ten,
// for the shortest decimal that reads back as f.
func decimal(f float64) (m uint64, e int) {
	var buf [32]byte
	b := strconv.AppendFloat(buf[:0], math.Abs(f), 'e', -1, 64)
	i, frac := 0, 0
	for ; i < len(b) && b[i] != 'e'; i++ {
		if b[i] == '.' {
			frac = len(b) // marks that digits from here are fractional
			continue
		}
		m = m*10 + uint64(b[i]-'0')
		if frac != 0 {
			e--
		}
	}
	exp, neg := 0, false
	for i++; i < len(b); i++ {
		switch b[i] {
		case '-':
			neg = true
		case '+':
		default:
			exp = exp*10 + int(b[i]-'0')
		}
	}
	if neg {
		exp = -exp
	}
	e += exp
	if m == 0 {
		return 0, 0
	}
	for m%10 == 0 {
		m /= 10
		e++
	}
	return m, e
}

func (d *multiple) divides(x float64) bool {
	if x == 0 {
		return true
	}
	if d.integer && x == math.Trunc(x) && math.Abs(x) < 1<<53 {
		return math.Mod(x, d.f) == 0
	}
	m, e := decimal(x)
	k := e - d.e
	if k < 0 {
		// x/d = m / (d.m * 10^-k), and m is not a multiple of ten.
		return false
	}
	r := m % d.m
	for ; k > 0 && r != 0; k-- {
		hi, lo := bits.Mul64(r, 10)
		_, r = bits.Div64(hi, lo, d.m)
	}
	return r == 0
}
