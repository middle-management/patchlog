package core

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/rules"
)

// Limits are the configurable limits of §6.6. Sizes are bytes; rates are
// tokens per second with a burst.
type Limits struct {
	PatchSetSize     int
	OpsPerSet        int
	DocumentSize     int
	NestingDepth     int
	RulesPerNS       int
	RulesPerGrant    int
	GrantSize        int
	ItemsPerBatch    int
	LogPageSize      int // deployment only
	BatchSize        int
	BranchDepth      int // deployment only
	LiveBranches     int
	RatePerResource  Rate
	RatePerPrincipal Rate
	RatePerNamespace Rate
	RetryWindow      time.Duration
	RetryWindowMin   time.Duration // deployment only
	KeepPerResource  int
	RemoteBranchLife time.Duration
}

// Rate is a token bucket: Rate tokens per second, Burst the bucket size.
type Rate struct{ Rate, Burst float64 }

// DefaultLimits are the defaults of §6.6, also used as deployment maximums.
func DefaultLimits() Limits {
	return Limits{
		PatchSetSize:     256 << 10,
		OpsPerSet:        1000,
		DocumentSize:     4 << 20,
		NestingDepth:     64,
		RulesPerNS:       256,
		RulesPerGrant:    32,
		GrantSize:        8 << 10,
		ItemsPerBatch:    1000,
		LogPageSize:      1000,
		BatchSize:        16 << 20,
		BranchDepth:      8,
		LiveBranches:     100,
		RatePerResource:  Rate{10, 20},
		RatePerPrincipal: Rate{50, 100},
		RatePerNamespace: Rate{500, 1000},
		RetryWindow:      5 * time.Minute,
		RetryWindowMin:   5 * time.Minute,
		KeepPerResource:  100,
		RemoteBranchLife: 30 * 24 * time.Hour,
	}
}

// limitFields maps namespace-document names under "limits" to fields.
// Integer limits can only be lowered; the retry window can be raised up to
// the deployment maximum.
var limitFields = map[string]func(*Limits) *int{
	"patchSetSize":      func(l *Limits) *int { return &l.PatchSetSize },
	"opsPerSet":         func(l *Limits) *int { return &l.OpsPerSet },
	"documentSize":      func(l *Limits) *int { return &l.DocumentSize },
	"nestingDepth":      func(l *Limits) *int { return &l.NestingDepth },
	"rulesPerNamespace": func(l *Limits) *int { return &l.RulesPerNS },
	"rulesPerGrant":     func(l *Limits) *int { return &l.RulesPerGrant },
	"grantSize":         func(l *Limits) *int { return &l.GrantSize },
	"itemsPerBatch":     func(l *Limits) *int { return &l.ItemsPerBatch },
	"batchSize":         func(l *Limits) *int { return &l.BatchSize },
	"liveBranches":      func(l *Limits) *int { return &l.LiveBranches },
	"keepPerResource":   func(l *Limits) *int { return &l.KeepPerResource },
}

var rateFields = map[string]func(*Limits) *Rate{
	"ratePerResource":  func(l *Limits) *Rate { return &l.RatePerResource },
	"ratePerPrincipal": func(l *Limits) *Rate { return &l.RatePerPrincipal },
	"ratePerNamespace": func(l *Limits) *Rate { return &l.RatePerNamespace },
}

// Config is a parsed namespace document (§2, §7.4).
type Config struct {
	Doc        map[string]any
	Read       string // "public" or "grant"
	Rules      []*rules.Rule
	Keys       []grant.Key
	Roles      grant.Roles
	Revoked    map[string]bool
	Limits     Limits
	Retention  []RetentionRule
	MaxLag     *time.Duration // §C.4: how old a grant's `at` in this namespace may be
	Allowances []Allowance
	Frozen     bool
	Successor  string
	Base       *BaseRef
}

// Allowance gives a named principal its own rate and batch limits (§6.6).
// Zero fields mean the namespace's own limit.
type Allowance struct {
	Sub, Kid      string
	Rate          Rate
	ItemsPerBatch int
	BatchSize     int
}

// allowance returns the allowance of a principal, or nil. With
// authentication disabled there is no signing key, so only sub is matched.
func (c *Config) allowance(sub, kid string, noKeys bool) *Allowance {
	for i := range c.Allowances {
		a := &c.Allowances[i]
		if a.Sub == sub && (a.Kid == kid || noKeys) {
			return a
		}
	}
	return nil
}

// BaseRef is a branch's `+"`base`"+`. Origin is set for a remote branch,
// whose base lives in another deployment (§7.6, §G.3).
type BaseRef struct {
	Origin string
	NS     string
	At     string
}

// Remote reports whether the base is in another deployment.
func (b *BaseRef) Remote() bool { return b != nil && b.Origin != "" }

// ValidRemoteOrigin reports whether s is an origin another deployment may
// have, in the RFC 6454 ASCII serialisation of §C.3 (scheme://host[:port],
// lowercase, default port omitted). It must be https, except that plain
// http is accepted for loopback hosts, so two local deployments can try
// remote branches.
func ValidRemoteOrigin(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		if u.Port() == "443" {
			return false
		}
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" || u.Port() == "80" {
			return false
		}
	default:
		return false
	}
	if strings.ToLower(u.Host) != u.Host || strings.HasSuffix(u.Host, ":") {
		return false
	}
	return s == u.Scheme+"://"+u.Host
}

var nsNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var resNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ValidNSName and ValidResourceName check the grammar of §3.6.
func ValidNSName(s string) bool       { return nsNameRe.MatchString(s) }
func ValidResourceName(s string) bool { return resNameRe.MatchString(s) }

// parseConfig validates a namespace document against the built-in
// namespace-document schema and the deployment maximums.
// defaults are the namespace defaults; max the deployment maximums.
func parseConfig(doc any, defaults, max Limits) (*Config, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the namespace document must be an object")
	}
	c := &Config{Doc: m, Read: "grant", Limits: defaults, Revoked: map[string]bool{}}
	for k, v := range m {
		switch k {
		case "read":
			s, ok := v.(string)
			if !ok || (s != "public" && s != "grant") {
				return nil, fmt.Errorf(`/read must be "public" or "grant"`)
			}
			c.Read = s
		case "rules":
			rs, err := rules.CompileList(v)
			if err != nil {
				return nil, fmt.Errorf("/rules: %v", err)
			}
			if len(rs) > max.RulesPerNS {
				return nil, &limitError{fmt.Sprintf("more than %d rules", max.RulesPerNS)}
			}
			c.Rules = rs
		case "keys":
			ks, err := grant.ParseKeys(v)
			if err != nil {
				return nil, fmt.Errorf("/keys: %v", err)
			}
			for _, k := range ks {
				if _, err := rules.CompileList(anySlice(k.Rules)); err != nil {
					return nil, fmt.Errorf("/keys %s rules: %v", k.Kid, err)
				}
			}
			c.Keys = ks
		case "roles":
			rs, err := grant.ParseRoles(v)
			if err != nil {
				return nil, fmt.Errorf("/roles: %v", err)
			}
			for name, r := range rs {
				if _, err := rules.CompileList(anySlice(r.Rules)); err != nil {
					return nil, fmt.Errorf("/roles/%s rules: %v", name, err)
				}
			}
			c.Roles = rs
		case "revoked":
			a, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("/revoked must be an array of revocation ids")
			}
			for _, e := range a {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("/revoked must be an array of revocation ids")
				}
				c.Revoked[s] = true
			}
		case "limits":
			if err := parseLimits(v, &c.Limits, max); err != nil {
				return nil, err
			}
		case "allowances":
			as, err := parseAllowances(v, max)
			if err != nil {
				return nil, err
			}
			c.Allowances = as
		case "maxLag":
			str, ok := v.(string)
			d, err := ParseDuration(str)
			if !ok || err != nil || d <= 0 {
				return nil, fmt.Errorf("/maxLag must be a positive ISO 8601 duration")
			}
			c.MaxLag = &d
		case "retention":
			rs, err := parseRetention(v)
			if err != nil {
				return nil, err
			}
			c.Retention = rs
		case "frozen":
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("/frozen must be a boolean")
			}
			c.Frozen = b
		case "successor":
			s, ok := v.(string)
			if !ok || !ValidNSName(s) {
				return nil, fmt.Errorf("/successor must be a namespace name")
			}
			c.Successor = s
		case "base":
			b, ok := v.(map[string]any)
			ns, _ := b["ns"].(string)
			at, _ := b["at"].(string)
			if _, remote := b["origin"]; ok && remote {
				// A remote branch (§7.6, §G.3): { origin, ns, at }.
				origin, _ := b["origin"].(string)
				if len(b) != 3 || !ValidRemoteOrigin(origin) || !ValidNSName(ns) {
					return nil, fmt.Errorf("/base must be { origin, ns, at } with an https origin")
				}
				if _, err := ids.Parse(at); err != nil {
					return nil, fmt.Errorf("/base/at must be an ns_id")
				}
				c.Base = &BaseRef{Origin: origin, NS: ns, At: at}
				continue
			}
			if !ok || ns == "" || at == "" || len(b) != 2 {
				return nil, fmt.Errorf("/base must be { ns, at } or { origin, ns, at }")
			}
			c.Base = &BaseRef{NS: ns, At: at}
		case "encryption":
			return nil, fmt.Errorf("/encryption: encryption (Addendum E) is not supported by this server")
		}
	}
	return c, nil
}

func anySlice(a []any) any {
	if a == nil {
		return []any{}
	}
	return a
}

func parseLimits(v any, l *Limits, max Limits) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("/limits must be an object")
	}
	for k, x := range m {
		if f, ok := limitFields[k]; ok {
			n, ok := x.(float64)
			if s, isStr := x.(string); isStr && sizeFields[k] {
				b, err := ParseSize(s)
				n, ok = float64(b), err == nil
			}
			if !ok || n < 0 || n != float64(int(n)) {
				return fmt.Errorf("/limits/%s must be a non-negative integer", k)
			}
			if int(n) > *f(&max) {
				return &limitError{fmt.Sprintf("/limits/%s exceeds the deployment maximum %d", k, *f(&max))}
			}
			*f(l) = int(n)
			continue
		}
		if f, ok := rateFields[k]; ok {
			o, ok := x.(map[string]any)
			r, _ := o["rate"].(float64)
			b, _ := o["burst"].(float64)
			if !ok || r <= 0 || b < 1 {
				return fmt.Errorf("/limits/%s must be { rate, burst }", k)
			}
			if r > f(&max).Rate || b > f(&max).Burst {
				return &limitError{fmt.Sprintf("/limits/%s exceeds the deployment maximum", k)}
			}
			*f(l) = Rate{r, b}
			continue
		}
		if k == "remoteBranchLife" {
			s, ok := x.(string)
			d, err := ParseDuration(s)
			if !ok || err != nil || d <= 0 {
				return fmt.Errorf("/limits/remoteBranchLife must be a positive ISO 8601 duration")
			}
			if d > max.RemoteBranchLife {
				return &limitError{"/limits/remoteBranchLife exceeds the deployment maximum"}
			}
			l.RemoteBranchLife = d
			continue
		}
		if k == "retryWindow" {
			s, ok := x.(string)
			d, err := ParseDuration(s)
			if !ok || err != nil {
				return fmt.Errorf("/limits/retryWindow must be an ISO 8601 duration")
			}
			if d < max.RetryWindowMin || d > max.RetryWindow {
				return &limitError{"/limits/retryWindow is outside the deployment's range"}
			}
			l.RetryWindow = d
			continue
		}
		return fmt.Errorf("/limits/%s is not a known limit", k)
	}
	return nil
}

// sizeFields are limits in bytes, which may also be written as "64 MiB".
var sizeFields = map[string]bool{"patchSetSize": true, "documentSize": true, "grantSize": true, "batchSize": true}

var sizeRe = regexp.MustCompile(`^(\d+)\s*(B|KiB|MiB|GiB)?$`)

// ParseSize parses a byte size: an integer, optionally followed by B, KiB,
// MiB or GiB.
func ParseSize(s string) (int, error) {
	m := sizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	var n int
	fmt.Sscan(m[1], &n)
	switch m[2] {
	case "KiB":
		n <<= 10
	case "MiB":
		n <<= 20
	case "GiB":
		n <<= 30
	}
	return n, nil
}

func parseAllowances(v any, max Limits) ([]Allowance, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("/allowances must be an array")
	}
	var out []Allowance
	seen := map[string]bool{}
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("/allowances/%d must be an object", i)
		}
		a := Allowance{} // unset fields fall back to the namespace's limits
		for k, x := range m {
			switch k {
			case "sub", "kid":
				s, ok := x.(string)
				if !ok || s == "" {
					return nil, fmt.Errorf("/allowances/%d/%s must be a string", i, k)
				}
				if k == "sub" {
					a.Sub = s
				} else {
					a.Kid = s
				}
			case "rate", "burst":
				n, ok := x.(float64)
				if !ok || n <= 0 {
					return nil, fmt.Errorf("/allowances/%d/%s must be a positive number", i, k)
				}
				if k == "rate" {
					a.Rate.Rate = n
				} else {
					a.Rate.Burst = n
				}
			case "itemsPerBatch":
				n, ok := x.(float64)
				if !ok || n < 1 || n != float64(int(n)) {
					return nil, fmt.Errorf("/allowances/%d/itemsPerBatch must be a positive integer", i)
				}
				if int(n) > max.ItemsPerBatch {
					return nil, &limitError{fmt.Sprintf("/allowances/%d/itemsPerBatch exceeds the deployment maximum %d", i, max.ItemsPerBatch)}
				}
				a.ItemsPerBatch = int(n)
			case "batchSize":
				var n int
				switch y := x.(type) {
				case float64:
					n = int(y)
					if y != float64(n) || n < 1 {
						return nil, fmt.Errorf("/allowances/%d/batchSize must be a size", i)
					}
				case string:
					var err error
					if n, err = ParseSize(y); err != nil {
						return nil, fmt.Errorf("/allowances/%d/batchSize: %v", i, err)
					}
				default:
					return nil, fmt.Errorf("/allowances/%d/batchSize must be a size", i)
				}
				if n > max.BatchSize {
					return nil, &limitError{fmt.Sprintf("/allowances/%d/batchSize exceeds the deployment maximum %d", i, max.BatchSize)}
				}
				a.BatchSize = n
			default:
				return nil, fmt.Errorf("/allowances/%d/%s is not a known field", i, k)
			}
		}
		if a.Sub == "" || a.Kid == "" {
			return nil, fmt.Errorf("/allowances/%d needs sub and kid", i)
		}
		if (a.Rate.Rate == 0) != (a.Rate.Burst == 0) || (a.Rate.Burst > 0 && a.Rate.Burst < 1) {
			return nil, fmt.Errorf("/allowances/%d needs both rate and burst, burst at least 1", i)
		}
		if seen[a.Sub+"\x00"+a.Kid] {
			return nil, fmt.Errorf("/allowances/%d duplicates an earlier sub and kid", i)
		}
		seen[a.Sub+"\x00"+a.Kid] = true
		out = append(out, a)
	}
	return out, nil
}

type limitError struct{ msg string }

func (e *limitError) Error() string { return e.msg }

var durRe = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// ParseDuration parses an ISO 8601 duration (years as 365 days, months as 30).
func ParseDuration(s string) (time.Duration, error) {
	m := durRe.FindStringSubmatch(s)
	if m == nil || s == "P" || s[len(s)-1] == 'T' {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	var d time.Duration
	units := []time.Duration{365 * 24 * time.Hour, 30 * 24 * time.Hour, 7 * 24 * time.Hour, 24 * time.Hour, time.Hour, time.Minute}
	for i, u := range units {
		if m[i+1] != "" {
			var n int64
			fmt.Sscan(m[i+1], &n)
			d += time.Duration(n) * u
		}
	}
	if m[7] != "" {
		var f float64
		fmt.Sscan(m[7], &f)
		d += time.Duration(f * float64(time.Second))
	}
	return d, nil
}

// starKids returns the kids of keys with can ["*"].
func (c *Config) starKeys() map[string]grant.Key {
	out := map[string]grant.Key{}
	for _, k := range c.Keys {
		if k.IsStar() {
			out[k.Kid] = k
		}
	}
	return out
}

func cloneDoc(m map[string]any) map[string]any { return jsonv.Clone(m).(map[string]any) }
