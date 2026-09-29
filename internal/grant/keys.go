package grant

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Key is a signing key entry of the namespace document with its scope (§C.4).
type Key struct {
	Kid, Alg          string
	Pub               ed25519.PublicKey
	Can               []string
	MaxTTL            *time.Duration
	SubPattern        *regexp.Regexp // anchored: matches the whole sub
	Groups, Roles     *AllowDeny
	AttrsSchema       any
	Rules             []any
	ReadScopeResource bool
	Rate              *Rate
	RequireAt         any // nil, true or a namespace name
	MaxLag            *time.Duration
	Raw               map[string]any
}

// AllowDeny is an allow list (IsAllow) or a deny list.
type AllowDeny struct {
	Allow, Deny []string
	IsAllow     bool
}

// Permits reports whether every value is allowed.
func (a *AllowDeny) Permits(values []string) (bool, string) {
	if a == nil {
		return true, ""
	}
	if a.IsAllow {
		for _, v := range values {
			if !contains(a.Allow, v) {
				return false, v
			}
		}
		return true, ""
	}
	for _, v := range values {
		if contains(a.Deny, v) {
			return false, v
		}
	}
	return true, ""
}

// Rate is a token bucket: refill per second and size.
type Rate struct{ Rate, Burst float64 }

// IsStar reports whether the key's can contains "*".
func (k Key) IsStar() bool { return contains(k.Can, "*") }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var keyFields = map[string]bool{"kid": true, "alg": true, "pub": true, "can": true, "maxTtl": true, "sub": true, "groups": true, "roles": true, "attrs": true, "rules": true, "readScope": true, "rate": true, "requireAt": true, "maxLag": true}

// ParseKeys parses and validates the namespace document's "keys" value.
// nil (absent) yields no keys.
func ParseKeys(v any) ([]Key, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("keys must be an array")
	}
	seen := map[string]bool{}
	out := make([]Key, 0, len(arr))
	for i, e := range arr {
		k, err := parseKey(e)
		if err != nil {
			return nil, fmt.Errorf("keys/%d: %w", i, err)
		}
		if seen[k.Kid] {
			return nil, fmt.Errorf("keys/%d: duplicate kid %q", i, k.Kid)
		}
		seen[k.Kid] = true
		out = append(out, k)
	}
	return out, nil
}

func parseKey(e any) (Key, error) {
	var k Key
	m, ok := e.(map[string]any)
	if !ok {
		return k, errors.New("key must be an object")
	}
	k.Raw = m
	for f := range m {
		if !keyFields[f] && !strings.HasPrefix(f, "x-") {
			return k, fmt.Errorf("unknown key field %q", f)
		}
	}
	var err error
	if k.Kid, ok = m["kid"].(string); !ok || k.Kid == "" {
		return k, errors.New("kid must be a non-empty string")
	}
	if k.Alg, ok = m["alg"].(string); !ok || !strings.EqualFold(k.Alg, "ed25519") {
		return k, errors.New(`alg must be "ed25519"`)
	}
	ps, ok := m["pub"].(string)
	if !ok {
		return k, errors.New("pub is required")
	}
	pub, err := b64.DecodeString(ps)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return k, errors.New("pub must be a b64url 32-byte ed25519 public key")
	}
	k.Pub = ed25519.PublicKey(pub)
	var has bool
	if k.Can, has, err = strList(m, "can"); err != nil {
		return k, err
	}
	if !has {
		return k, errors.New("can is required")
	}
	for _, c := range k.Can {
		if c != "*" && !verbSet[c] {
			return k, fmt.Errorf("unknown verb %q", c)
		}
	}
	if k.MaxTTL, err = durField(m, "maxTtl"); err != nil {
		return k, err
	}
	if k.MaxLag, err = durField(m, "maxLag"); err != nil {
		return k, err
	}
	if v, ok := m["sub"]; ok {
		s, ok := v.(string)
		if !ok {
			return k, errors.New("sub must be a regular expression string")
		}
		re, err := regexp.Compile(`^(?:` + s + `)$`)
		if err != nil {
			return k, fmt.Errorf("sub: %v", err)
		}
		k.SubPattern = re
	}
	if k.Groups, err = allowDeny(m, "groups"); err != nil {
		return k, err
	}
	if k.Roles, err = allowDeny(m, "roles"); err != nil {
		return k, err
	}
	if v, ok := m["attrs"]; ok {
		switch v.(type) {
		case map[string]any, bool:
		default:
			return k, errors.New("attrs must be a JSON Schema")
		}
		k.AttrsSchema = v
	}
	if v, ok := m["rules"]; ok {
		r, ok := v.([]any)
		if !ok {
			return k, errors.New("rules must be an array")
		}
		k.Rules = r
	}
	if v, ok := m["readScope"]; ok {
		if v != "resource" {
			return k, errors.New(`readScope must be "resource"`)
		}
		k.ReadScopeResource = true
	}
	if v, ok := m["rate"]; ok {
		rm, ok := v.(map[string]any)
		if !ok {
			return k, errors.New("rate must be an object")
		}
		for f := range rm {
			if f != "rate" && f != "burst" {
				return k, fmt.Errorf("unknown rate field %q", f)
			}
		}
		r, ok1 := rm["rate"].(float64)
		b, ok2 := rm["burst"].(float64)
		if !ok1 || !ok2 || r <= 0 || b < 1 {
			return k, errors.New("rate needs rate > 0 and burst >= 1")
		}
		k.Rate = &Rate{Rate: r, Burst: b}
	}
	if v, ok := m["requireAt"]; ok {
		switch x := v.(type) {
		case bool:
			if x {
				k.RequireAt = true
			}
		case string:
			if x == "" {
				return k, errors.New("requireAt must be true or a namespace name")
			}
			k.RequireAt = x
		default:
			return k, errors.New("requireAt must be true or a namespace name")
		}
	}
	return k, nil
}

func allowDeny(m map[string]any, f string) (*AllowDeny, error) {
	v, ok := m[f]
	if !ok {
		return nil, nil
	}
	o, ok := v.(map[string]any)
	if !ok || len(o) != 1 {
		return nil, fmt.Errorf(`%s must be {"allow": [...]} or {"deny": [...]}`, f)
	}
	if _, ok := o["allow"]; ok {
		l, _, err := strList(o, "allow")
		if err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		return &AllowDeny{Allow: l, IsAllow: true}, nil
	}
	if _, ok := o["deny"]; ok {
		l, _, err := strList(o, "deny")
		if err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		return &AllowDeny{Deny: l}, nil
	}
	return nil, fmt.Errorf(`%s must be {"allow": [...]} or {"deny": [...]}`, f)
}

func durField(m map[string]any, f string) (*time.Duration, error) {
	v, ok := m[f]
	if !ok {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be an ISO 8601 duration", f)
	}
	d, err := ParseDuration(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", f, err)
	}
	return &d, nil
}

// ParseDuration parses an ISO 8601 duration of the form PnWnDTnHnMn.nS
// (weeks and days are 7×24h and 24h; years and months are rejected).
func ParseDuration(s string) (time.Duration, error) {
	bad := fmt.Errorf("invalid ISO 8601 duration %q", s)
	if len(s) < 3 || s[0] != 'P' {
		return 0, bad
	}
	rest := s[1:]
	inTime := false
	units := 0
	var total float64
	order := ""
	for len(rest) > 0 {
		if rest[0] == 'T' {
			if inTime {
				return 0, bad
			}
			inTime = true
			rest = rest[1:]
			if rest == "" {
				return 0, bad
			}
			continue
		}
		i := 0
		for i < len(rest) && (rest[i] >= '0' && rest[i] <= '9' || rest[i] == '.') {
			i++
		}
		if i == 0 || i == len(rest) {
			return 0, bad
		}
		n, err := strconv.ParseFloat(rest[:i], 64)
		if err != nil || n < 0 {
			return 0, bad
		}
		u := rest[i]
		var sec float64
		switch {
		case !inTime && u == 'W':
			sec = 7 * 86400
		case !inTime && u == 'D':
			sec = 86400
		case inTime && u == 'H':
			sec = 3600
		case inTime && u == 'M':
			sec = 60
		case inTime && u == 'S':
			sec = 1
		default:
			return 0, bad
		}
		key := string(u)
		if inTime {
			key = "T" + key
		}
		if strings.Contains(order, key) {
			return 0, bad
		}
		order += key
		if strings.Contains(rest[:i], ".") && u != 'S' {
			return 0, bad
		}
		total += n * sec
		units++
		rest = rest[i+1:]
	}
	if units == 0 || total*float64(time.Second) > float64(1<<62) {
		return 0, bad
	}
	return time.Duration(total * float64(time.Second)), nil
}

// Roles are the namespace document's role definitions (§C.1.1).
type Roles map[string]RoleDef

// RoleDef is one role. Other fields of a role entry are ignored.
type RoleDef struct {
	Can   []string
	Rules []any
}

// ParseRoles parses the namespace document's "roles" value.
func ParseRoles(v any) (Roles, error) {
	out := Roles{}
	if v == nil {
		return out, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("roles must be an object")
	}
	for name, e := range m {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("roles/%s must be an object", name)
		}
		var d RoleDef
		var err error
		if d.Can, _, err = strList(o, "can"); err != nil {
			return nil, fmt.Errorf("roles/%s: %v", name, err)
		}
		for _, c := range d.Can {
			if !verbSet[c] {
				return nil, fmt.Errorf("roles/%s: unknown verb %q", name, c)
			}
		}
		if r, ok := o["rules"]; ok {
			if d.Rules, ok = r.([]any); !ok {
				return nil, fmt.Errorf("roles/%s: rules must be an array", name)
			}
		}
		out[name] = d
	}
	return out, nil
}
