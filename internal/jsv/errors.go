package jsv

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// validationError builds the error of the recorded failure. It runs once
// per failed validation, so it may allocate.
func (s *state) validationError() *ValidationError {
	e := &ValidationError{InstancePath: pathString(s.ipath, "")}
	if !s.failed {
		// Not reachable: a failure outside a branch is always recorded.
		e.Message = "invalid"
		return e
	}
	kw := s.errKw
	switch kw {
	case "false", "value", "cycle":
		kw = ""
	}
	e.KeywordPath = pathString(s.kpath, kw)
	e.Message = s.message()
	return e
}

// pathString writes toks, kept innermost first, as a JSON Pointer, with
// last appended if not empty.
func pathString(toks []tok, last string) string {
	var b strings.Builder
	for i := len(toks) - 1; i >= 0; i-- {
		b.WriteByte('/')
		if toks[i].i >= 0 {
			b.WriteString(strconv.Itoa(toks[i].i))
		} else {
			b.WriteString(escapeToken(toks[i].s))
		}
	}
	if last != "" {
		b.WriteByte('/')
		b.WriteString(last)
	}
	return b.String()
}

func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(b) > 80 {
		return string(b[:77]) + "..."
	}
	return string(b)
}

// quote writes s between single quotes, as messages name members,
// patterns and strings.
func quote(s string) string {
	q := strconv.Quote(s)
	q = strings.ReplaceAll(q[1:len(q)-1], `\"`, `"`)
	return "'" + strings.ReplaceAll(q, "'", `\'`) + "'"
}

func quoteAll(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = quote(s)
	}
	return strings.Join(out, ", ")
}

// display writes a scalar for a message.
func display(v any) string {
	if s, ok := v.(string); ok {
		return quote(s)
	}
	return jsonText(v)
}

func (s *state) message() string {
	return describe(s.errNode, s.errKw, s.errVal, s.errArg, s.errNum)
}

// describe is the message of the failure of keyword kw of n on v. arg and
// num are what the keyword adds: the member missing, the items equal, the
// count of matches.
func describe(n *node, kw string, v any, arg string, num int) string {
	switch kw {
	case "false":
		return "false schema"
	case "value":
		return fmt.Sprintf("not a JSON value: %T", v)
	case "cycle":
		return "reference cycle: the schema at " + n.loc + " applies itself to the same value"
	case "type":
		return fmt.Sprintf("got %s, want %s", kindOf(v), typeSetString(n.types))
	case "const":
		if isContainer(n.constVal) {
			return "value must be " + jsonText(n.constVal)
		}
		return "value must be " + display(n.constVal)
	case "enum":
		parts := make([]string, len(n.enum.all))
		for i, m := range n.enum.all {
			parts[i] = display(m)
		}
		if len(parts) == 1 {
			return "value must be " + parts[0]
		}
		return "value must be one of " + strings.Join(parts, ", ")
	case "minimum":
		return fmt.Sprintf("minimum: got %v, want %v", v, n.min)
	case "maximum":
		return fmt.Sprintf("maximum: got %v, want %v", v, n.max)
	case "exclusiveMinimum":
		return fmt.Sprintf("exclusiveMinimum: got %v, want %v", v, n.xmin)
	case "exclusiveMaximum":
		return fmt.Sprintf("exclusiveMaximum: got %v, want %v", v, n.xmax)
	case "multipleOf":
		return fmt.Sprintf("multipleOf: got %v, want %v", v, n.multipleOf.f)
	case "minLength":
		return fmt.Sprintf("minLength: got %d, want %d", len([]rune(v.(string))), n.minLen)
	case "maxLength":
		return fmt.Sprintf("maxLength: got %d, want %d", len([]rune(v.(string))), n.maxLen)
	case "pattern":
		return fmt.Sprintf("%s does not match pattern %s", display(v), quote(n.patternSrc))
	case "format":
		return fmt.Sprintf("%s is not valid %s", display(v), n.formatName)
	case "minProperties":
		return fmt.Sprintf("minProperties: got %d, want %d", len(v.(map[string]any)), n.minProps)
	case "maxProperties":
		return fmt.Sprintf("maxProperties: got %d, want %d", len(v.(map[string]any)), n.maxProps)
	case "required":
		if strings.HasPrefix(arg, "\x00") {
			return "missing properties " + arg[1:]
		}
		return "missing property " + quote(arg)
	case "dependentRequired":
		if strings.HasPrefix(arg, "\x00") {
			return "properties " + arg[1:]
		}
		return "missing property " + quote(arg) + ", required by another that is present"
	case "additionalProperties":
		if strings.HasPrefix(arg, "\x00") {
			return "additional properties " + arg[1:] + " not allowed"
		}
		return "additional properties " + quote(arg) + " not allowed"
	case "unevaluatedProperties":
		return "unevaluated properties " + arg + " not allowed"
	case "unevaluatedItems":
		return fmt.Sprintf("unevaluated item not allowed")
	case "propertyNames":
		return "invalid propertyName " + quote(arg)
	case "minItems":
		return fmt.Sprintf("minItems: got %d, want %d", len(v.([]any)), n.minItems)
	case "maxItems":
		return fmt.Sprintf("maxItems: got %d, want %d", len(v.([]any)), n.maxItems)
	case "uniqueItems":
		return fmt.Sprintf("items at %s and %d are equal", arg, num)
	case "contains":
		return "no items match contains schema"
	case "minContains":
		return fmt.Sprintf("min %d items required to match contains schema, but %d matched", n.minContains, num)
	case "maxContains":
		return fmt.Sprintf("max %d items may match contains schema, but more matched", n.maxContains)
	case "anyOf":
		return "'anyOf' failed, none matched"
	case "oneOf":
		switch {
		case arg != "":
			return "'oneOf' failed, subschemas " + arg + " matched"
		case num == 0:
			return "'oneOf' failed, none matched"
		}
		return "'oneOf' failed, more than one subschema matched"
	case "not":
		return "'not' failed"
	}
	return kw + " failed"
}
