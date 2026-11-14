package jsv

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// Failure is one failed keyword on one value.
type Failure struct {
	InstancePath string // JSON Pointer to the value
	Message      string
	// Cycle is the absolute location of the schema, if the failure is that
	// the schema applies itself to the same value without end: a defect of
	// the schema, not of the instance.
	Cycle string
}

// Collect returns every failure of v against the schema, sorted by
// instance path and message and without repeats; none if v is valid. It
// is the slow way to learn what Validate learns fast: call it after
// Validate has found v invalid, to say all that is wrong.
//
// What it reports of a schema that fails:
//
//   - a failed type, const or enum alone: the other keywords would only
//     repeat it;
//   - otherwise every failed assertion, and the failures of every member
//     and item under properties, items and the like, of $ref, allOf,
//     then/else and dependentSchemas;
//   - of an anyOf or oneOf that nothing matches, the failures of the
//     branches whose tag fits (the value's type, and the const or enum of
//     itself and of its scalar members), since a branch for another tag
//     says nothing useful; if no tag fits, what refutes each branch
//     without looking into members that are objects or arrays;
//   - of not, contains, propertyNames and a oneOf matched twice, the
//     keyword itself.
//
// The budget is counted as for Validate; with ErrBudget nothing is
// returned.
func (sc *Schema) Collect(v any, o ValidateOptions) ([]Failure, error) {
	s := sc.newState(o)
	c := &collector{s: s}
	// Everything the collector asks of the fast evaluator is a question,
	// not the verdict.
	s.quiet = 1
	c.node(sc.root, v, false)
	out := c.out
	err := s.finish(true, o)
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].InstancePath != out[j].InstancePath {
			return out[i].InstancePath < out[j].InstancePath
		}
		return out[i].Message < out[j].Message
	})
	dedup := out[:0]
	for i, f := range out {
		if i == 0 || f != out[i-1] {
			dedup = append(dedup, f)
		}
	}
	return dedup, nil
}

type collector struct {
	s    *state
	path []tok // outermost first
	out  []Failure
}

func (c *collector) pointer() string {
	var b strings.Builder
	for _, t := range c.path {
		b.WriteByte('/')
		if t.i >= 0 {
			b.WriteString(strconv.Itoa(t.i))
		} else {
			b.WriteString(escapeToken(t.s))
		}
	}
	return b.String()
}

func (c *collector) emit(n *node, kw string, v any, arg string, num int) {
	f := Failure{InstancePath: c.pointer(), Message: describe(n, kw, v, arg, num)}
	if kw == "cycle" {
		f.Cycle = n.loc
	}
	c.out = append(c.out, f)
}

// ok asks the fast evaluator whether v is valid against n.
func (c *collector) ok(n *node, v any) bool { return c.s.eval(n, v, nil) }

// child collects the failures of a member or item against n.
func (c *collector) child(n *node, v any, t tok) {
	s := c.s
	c.path = append(c.path, t)
	b := s.base
	s.base = len(s.chain)
	c.node(n, v, false)
	s.base = b
	c.path = c.path[:len(c.path)-1]
}

// node collects the failures of v against n. shallow leaves out members
// and items that are containers, and the in-place applicators but $ref and
// allOf: what refutes a branch at a glance.
func (c *collector) node(n *node, v any, shallow bool) {
	s := c.s
	s.steps++
	if s.budget > 0 && s.steps > s.budget {
		s.over = true
	}
	if s.over {
		return
	}
	if n.boolean != 0 {
		if n.boolean < 0 {
			c.emit(n, "false", v, "", 0)
		}
		return
	}
	if s.sch.cyclic {
		for _, on := range s.chain[s.base:] {
			if on == n {
				c.emit(n, "cycle", v, "", 0)
				return
			}
		}
		s.chain = append(s.chain, n)
		defer func() { s.chain = s.chain[:len(s.chain)-1] }()
	}
	if s.sch.dynamic && (len(s.scope) == 0 || s.scope[len(s.scope)-1] != n.res) {
		s.scope = append(s.scope, n.res)
		defer func() { s.scope = s.scope[:len(s.scope)-1] }()
	}
	before := len(c.out)
	c.body(n, v, shallow)
	if n.uneval && !shallow && len(c.out) == before {
		c.unevaluated(n, v)
	}
}

func (c *collector) body(n *node, v any, shallow bool) {
	s := c.s
	// The value itself.
	t := tNull
	switch x := v.(type) {
	case nil:
	case bool:
		t = tBool
	case float64:
		t = tNumber
		if x == math.Trunc(x) {
			t |= tInteger
		}
	case string:
		t = tString
	case []any:
		t = tArray
	case map[string]any:
		t = tObject
	default:
		c.emit(n, "value", v, "", 0)
		return
	}
	if n.types != 0 && n.types&t == 0 {
		c.emit(n, "type", v, "", 0)
		return
	}
	if n.hasConst && !equal(n.constVal, v) {
		c.emit(n, "const", v, "", 0)
		return
	}
	if n.enum != nil && !n.enum.has(v) {
		c.emit(n, "enum", v, "", 0)
		return
	}
	switch x := v.(type) {
	case float64:
		if n.hasMin && x < n.min {
			c.emit(n, "minimum", v, "", 0)
		}
		if n.hasMax && x > n.max {
			c.emit(n, "maximum", v, "", 0)
		}
		if n.hasXMin && x <= n.xmin {
			c.emit(n, "exclusiveMinimum", v, "", 0)
		}
		if n.hasXMax && x >= n.xmax {
			c.emit(n, "exclusiveMaximum", v, "", 0)
		}
		if n.multipleOf != nil && !n.multipleOf.divides(x) {
			c.emit(n, "multipleOf", v, "", 0)
		}
	case string:
		if n.hasStr {
			// The fast checks, one keyword at a time.
			for _, kw := range [...]string{"minLength", "maxLength", "pattern", "format"} {
				if !strKeyword(s, n, kw, x) {
					c.emit(n, kw, v, "", 0)
				}
			}
		}
	case map[string]any:
		c.object(n, x, v, shallow)
	case []any:
		c.array(n, x, v, shallow)
	}
	// The same value, by other schemas.
	if n.ref != nil {
		c.node(n.ref, v, shallow)
	}
	for _, sub := range n.allOf {
		c.node(sub, v, shallow)
	}
	if shallow || !n.hasRest {
		return
	}
	if n.dynRef != nil {
		c.node(s.dynTarget(n), v, false)
	}
	if n.anyOf != nil && !s.anyOfOK(n, v, nil, 0) {
		c.branches(n, n.anyOf, "anyOf", v)
	}
	if n.oneOf != nil {
		var matched []string
		for i, sub := range n.oneOf {
			if c.ok(sub, v) {
				if matched = append(matched, strconv.Itoa(i)); len(matched) == 2 {
					break
				}
			}
		}
		switch len(matched) {
		case 0:
			c.branches(n, n.oneOf, "oneOf", v)
		case 2:
			c.emit(n, "oneOf", v, strings.Join(matched, ", "), 2)
		}
	}
	if n.not != nil && c.ok(n.not, v) {
		c.emit(n, "not", v, "", 0)
	}
	if n.ifN != nil {
		if c.ok(n.ifN, v) {
			if n.thenN != nil {
				c.node(n.thenN, v, false)
			}
		} else if n.elseN != nil {
			c.node(n.elseN, v, false)
		}
	}
	if x, ok := v.(map[string]any); ok {
		for i := range n.depSchemas {
			if _, ok := x[n.depSchemas[i].key]; ok {
				c.node(n.depSchemas[i].n, v, false)
			}
		}
	}
}

// strKeyword reports whether string x passes keyword kw of n.
func strKeyword(s *state, n *node, kw, x string) bool {
	switch kw {
	case "minLength":
		return n.minLen < 0 || len([]rune(x)) >= n.minLen
	case "maxLength":
		return n.maxLen < 0 || len([]rune(x)) <= n.maxLen
	case "pattern":
		return n.pattern == nil || n.pattern.MatchString(x)
	}
	if n.format != nil && !n.format(x) {
		return false
	}
	if n.formatRegex {
		if _, err := s.regexp(x); err != nil {
			return false
		}
	}
	return true
}

func (c *collector) object(n *node, x map[string]any, v any, shallow bool) {
	if n.minProps >= 0 && len(x) < n.minProps {
		c.emit(n, "minProperties", v, "", 0)
	}
	if n.maxProps >= 0 && len(x) > n.maxProps {
		c.emit(n, "maxProperties", v, "", 0)
	}
	var missing []string
	for _, k := range n.required {
		if _, ok := x[k]; !ok {
			missing = append(missing, k)
		}
	}
	switch len(missing) {
	case 0:
	case 1:
		c.emit(n, "required", v, missing[0], 0)
	default:
		c.emit(n, "required", v, "\x00"+quoteAll(missing), 0)
	}
	for i := range n.depRequired {
		d := &n.depRequired[i]
		if _, ok := x[d.key]; !ok {
			continue
		}
		missing = missing[:0]
		for _, k := range d.need {
			if _, ok := x[k]; !ok {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			c.emit(n, "dependentRequired", v, "\x00"+quoteAll(missing)+" required, if "+quote(d.key)+" exists", 0)
		}
	}
	keys := make([]string, 0, len(x))
	for k := range x {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if n.propNames != nil {
		for _, k := range keys {
			if !c.ok(n.propNames, k) {
				c.emit(n, "propertyNames", v, k, 0)
			}
		}
	}
	if !n.hasProps {
		return
	}
	var additional []string
	for _, k := range keys {
		pv := x[k]
		deep := isContainer(pv)
		hit := false
		if pn := n.propMap[k]; pn != nil {
			hit = true
			if !shallow || !deep {
				c.child(pn, pv, tok{k, -1})
			}
		}
		for i := range n.patProps {
			if n.patProps[i].re.MatchString(k) {
				hit = true
				if !shallow {
					c.child(n.patProps[i].n, pv, tok{k, -1})
				}
			}
		}
		if !hit && n.addProps != nil {
			if n.addProps.boolean < 0 {
				additional = append(additional, k)
			} else if !shallow {
				c.child(n.addProps, pv, tok{k, -1})
			}
		}
	}
	if len(additional) > 0 {
		c.emit(n, "additionalProperties", v, "\x00"+quoteAll(additional), 0)
	}
}

func (c *collector) array(n *node, x []any, v any, shallow bool) {
	s := c.s
	if n.minItems >= 0 && len(x) < n.minItems {
		c.emit(n, "minItems", v, "", 0)
	}
	if n.maxItems >= 0 && len(x) > n.maxItems {
		c.emit(n, "maxItems", v, "", 0)
	}
	if shallow {
		return
	}
	if n.unique && len(x) > 1 {
		// Ask the fast check, which records what it finds when not quiet.
		s.quiet, s.failed = 0, false
		if !s.uniqueItems(n, x, v) && s.failed {
			c.emit(n, "uniqueItems", v, s.errArg, s.errNum)
		}
		s.quiet, s.failed, s.errNode, s.errVal = 1, false, nil, nil
	}
	for i, e := range x {
		switch {
		case i < len(n.prefix):
			c.child(n.prefix[i], e, tok{"", i})
		case n.items != nil:
			c.child(n.items, e, tok{"", i})
		}
	}
	if n.contains != nil {
		count := 0
		for _, e := range x {
			if s.child(n.contains, e) {
				count++
			}
		}
		switch {
		case count < n.minContains && n.minContains == 1:
			c.emit(n, "contains", v, "", 0)
		case count < n.minContains:
			c.emit(n, "minContains", v, "", count)
		case n.maxContains >= 0 && count > n.maxContains:
			c.emit(n, "maxContains", v, "", count)
		}
	}
}

// branches reports an anyOf or oneOf of n that no branch matches.
func (c *collector) branches(n *node, branches []*node, kw string, v any) {
	start := len(c.out)
	// The branches whose tag fits are the ones the value was meant for:
	// what is wrong is within them.
	fits := 0
	for _, b := range branches {
		if c.tagFits(b, v, 0) {
			fits++
			c.node(b, v, false)
		}
	}
	if fits == 0 {
		// None: what refutes each branch at a glance.
		for _, b := range branches {
			c.node(b, v, true)
		}
	}
	if len(c.out) == start {
		c.emit(n, kw, v, "", 0)
	}
}

// tagFits reports whether v is not ruled out of n by what tells the
// branches of a union apart: its type, its const or enum, or the const or
// enum of a scalar member, n's own or through $ref and allOf.
func (c *collector) tagFits(n *node, v any, depth int) bool {
	if n.boolean != 0 || depth > c.s.sch.nodes {
		return n.boolean >= 0
	}
	t := tNull
	switch x := v.(type) {
	case bool:
		t = tBool
	case float64:
		t = tNumber
		if x == math.Trunc(x) {
			t |= tInteger
		}
	case string:
		t = tString
	case []any:
		t = tArray
	case map[string]any:
		t = tObject
		for i := range n.props {
			p := &n.props[i]
			pv, ok := x[p.key]
			if ok && !isContainer(pv) && p.n.hasValue && (p.n.hasConst && !equal(p.n.constVal, pv) || p.n.enum != nil && !p.n.enum.has(pv)) {
				return false
			}
		}
	}
	if n.types != 0 && n.types&t == 0 {
		return false
	}
	if n.hasConst && !equal(n.constVal, v) || n.enum != nil && !n.enum.has(v) {
		return false
	}
	if n.ref != nil && !c.tagFits(n.ref, v, depth+1) {
		return false
	}
	for _, sub := range n.allOf {
		if !c.tagFits(sub, v, depth+1) {
			return false
		}
	}
	return true
}

// unevaluated reports unevaluatedProperties and unevaluatedItems of n,
// whose other keywords v passes.
func (c *collector) unevaluated(n *node, v any) {
	s := c.s
	ev := s.getEvals()
	defer s.putEvals(ev)
	if !s.evalBody(n, v, ev) {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		if n.unevalProps == nil || ev.allProps {
			return
		}
		var keys, refused []string
		for k := range x {
			if !ev.hasProp(k) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			if n.unevalProps.boolean < 0 {
				refused = append(refused, k)
			} else {
				c.child(n.unevalProps, x[k], tok{k, -1})
			}
		}
		if len(refused) > 0 {
			c.emit(n, "unevaluatedProperties", v, quoteAll(refused), 0)
		}
	case []any:
		if n.unevalItems == nil || ev.allItems {
			return
		}
		for i := ev.nItems; i < len(x); i++ {
			if ev.hasItem(i) {
				continue
			}
			if n.unevalItems.boolean < 0 {
				c.path = append(c.path, tok{"", i})
				c.emit(n, "unevaluatedItems", v, "", 0)
				c.path = c.path[:len(c.path)-1]
			} else {
				c.child(n.unevalItems, x[i], tok{"", i})
			}
		}
	}
}
