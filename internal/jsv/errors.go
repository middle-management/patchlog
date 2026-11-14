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
	case "false", "value":
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

func (s *state) message() string {
	n, v := s.errNode, s.errVal
	switch s.errKw {
	case "false":
		return "false schema"
	case "value":
		return fmt.Sprintf("not a JSON value: %T", v)
	case "type":
		return fmt.Sprintf("got %s, want %s", kindOf(v), typeSetString(n.types))
	case "const":
		return "value must be " + jsonText(n.constVal)
	case "enum":
		parts := make([]string, len(n.enum.all))
		for i, m := range n.enum.all {
			parts[i] = jsonText(m)
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
		return fmt.Sprintf("%s does not match pattern %q", jsonText(v), n.patternSrc)
	case "format":
		return fmt.Sprintf("%s is not valid %s", jsonText(v), n.formatName)
	case "minProperties":
		return fmt.Sprintf("minProperties: got %d, want %d", len(v.(map[string]any)), n.minProps)
	case "maxProperties":
		return fmt.Sprintf("maxProperties: got %d, want %d", len(v.(map[string]any)), n.maxProps)
	case "required":
		return fmt.Sprintf("missing property %q", s.errArg)
	case "dependentRequired":
		return fmt.Sprintf("missing property %q, which a property present requires", s.errArg)
	case "additionalProperties":
		return fmt.Sprintf("additional property %q not allowed", s.errArg)
	case "minItems":
		return fmt.Sprintf("minItems: got %d, want %d", len(v.([]any)), n.minItems)
	case "maxItems":
		return fmt.Sprintf("maxItems: got %d, want %d", len(v.([]any)), n.maxItems)
	case "uniqueItems":
		return fmt.Sprintf("items at %s and %d are equal", s.errArg, s.errNum)
	case "contains":
		return "no items match contains schema"
	case "minContains":
		return fmt.Sprintf("minContains: %d items match contains schema, want at least %d", s.errNum, n.minContains)
	case "maxContains":
		return fmt.Sprintf("maxContains: more than %d items match contains schema", n.maxContains)
	case "anyOf":
		return "anyOf failed, none matched"
	case "oneOf":
		if s.errNum == 0 {
			return "oneOf failed, none matched"
		}
		return "oneOf failed, more than one subschema matched"
	case "not":
		return "not failed"
	}
	return s.errKw + " failed"
}
