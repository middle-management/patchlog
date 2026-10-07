package core

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/rules"
)

// Limits are the configurable limits of §6.6. Sizes are bytes; rates are
// tokens per second with a burst.
type Limits struct {
	PatchSetSize         int
	OpsPerSet            int
	DocumentSize         int
	ValueSize            int
	PathSize             int
	NestingDepth         int
	RulesPerNS           int
	RulesPerGrant        int
	GrantSize            int
	ItemsPerBatch        int
	LogPageSize          int // deployment only
	BatchSize            int
	BranchDepth          int // deployment only
	BranchesPerNamespace int
	RatePerResource      Rate
	RatePerPrincipal     Rate
	RatePerNamespace     Rate
	RetryWindow          time.Duration
	RetryWindowMin       time.Duration // deployment only
	KeepPerResource      int
	BlobsPerDocument     int
	RemoteRegistration   time.Duration
	// Blobs (§7.8): the largest blob, the bytes of pending blobs per
	// uploader and namespace, the age at which a pending blob is deleted,
	// and the bytes a principal may upload (a token bucket in bytes).
	BlobSize    int
	BlobPending int
	BlobGrace   time.Duration
	BlobRate    Rate
}

// Rate is a token bucket: Rate tokens per second, Burst the bucket size.
type Rate struct{ Rate, Burst float64 }

// DefaultLimits are the defaults of §6.6, also used as deployment maximums.
func DefaultLimits() Limits {
	return Limits{
		PatchSetSize:         256 << 10,
		OpsPerSet:            1000,
		DocumentSize:         4 << 20,
		ValueSize:            64 << 10,
		PathSize:             2 << 10,
		NestingDepth:         64,
		RulesPerNS:           256,
		RulesPerGrant:        32,
		GrantSize:            8 << 10,
		ItemsPerBatch:        1000,
		LogPageSize:          1000,
		BatchSize:            16 << 20,
		BranchDepth:          8,
		BranchesPerNamespace: 100,
		RatePerResource:      Rate{10, 20},
		RatePerPrincipal:     Rate{50, 100},
		RatePerNamespace:     Rate{500, 1000},
		RetryWindow:          5 * time.Minute,
		RetryWindowMin:       5 * time.Minute,
		KeepPerResource:      100,
		BlobsPerDocument:     1000,
		RemoteRegistration:   30 * 24 * time.Hour,
		BlobSize:             64 << 20,
		BlobPending:          256 << 20,
		BlobGrace:            24 * time.Hour,
		BlobRate:             Rate{8 << 20, 256 << 20},
	}
}

// limitFields maps namespace-document names under "limits" to fields.
// Integer limits can only be lowered; the retry window can be raised up to
// the deployment maximum.
var limitFields = map[string]func(*Limits) *int{
	"patchSetSize":         func(l *Limits) *int { return &l.PatchSetSize },
	"opsPerSet":            func(l *Limits) *int { return &l.OpsPerSet },
	"documentSize":         func(l *Limits) *int { return &l.DocumentSize },
	"valueSize":            func(l *Limits) *int { return &l.ValueSize },
	"pathSize":             func(l *Limits) *int { return &l.PathSize },
	"nestingDepth":         func(l *Limits) *int { return &l.NestingDepth },
	"rulesPerNamespace":    func(l *Limits) *int { return &l.RulesPerNS },
	"rulesPerGrant":        func(l *Limits) *int { return &l.RulesPerGrant },
	"grantSize":            func(l *Limits) *int { return &l.GrantSize },
	"itemsPerBatch":        func(l *Limits) *int { return &l.ItemsPerBatch },
	"batchSize":            func(l *Limits) *int { return &l.BatchSize },
	"branchesPerNamespace": func(l *Limits) *int { return &l.BranchesPerNamespace },
	"keepPerResource":      func(l *Limits) *int { return &l.KeepPerResource },
	"blobsPerDocument":     func(l *Limits) *int { return &l.BlobsPerDocument },
	"blobSize":             func(l *Limits) *int { return &l.BlobSize },
	"blobPending":          func(l *Limits) *int { return &l.BlobPending },
}

// deploymentOnlyLimits are limits of §6.6 that only a deployment sets.
var deploymentOnlyLimits = map[string]bool{"logPageSize": true, "branchDepth": true}

var rateFields = map[string]func(*Limits) *Rate{
	"ratePerResource":  func(l *Limits) *Rate { return &l.RatePerResource },
	"ratePerPrincipal": func(l *Limits) *Rate { return &l.RatePerPrincipal },
	"ratePerNamespace": func(l *Limits) *Rate { return &l.RatePerNamespace },
	"blobRate":         func(l *Limits) *Rate { return &l.BlobRate },
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
	// MergeAuthors are merge.authors (§F.3): the principals (root sub and
	// signing kid) whose merge batches merge tools and the janitor trust.
	MergeAuthors []MergeAuthor
	Frozen       bool
	Successor    string
	Base         *BaseRef
	// Encryption is encryption.level (Addendum E), "" if none.
	Encryption string
	// Epoch is encryption.epoch of a sealed or e2e namespace (§E.2.1,
	// §E.3.2): 1 if absent, 0 otherwise. HistoryEpochs is encryption.historyEpochs,
	// 0 if absent (no cap).
	Epoch         int
	HistoryEpochs int
	// Pad is encryption.pad of a sealed or e2e namespace: sealed payloads
	// are padded to size buckets (§E.2.2, seal.PadLen).
	Pad bool
	// DraftsFor is drafts.for of a branch (§7.4): the other namespaces,
	// names or prefixes ending in "*", whose writes (and their branches')
	// may resolve schema paths into this branch's own revisions (§6.1).
	// Nil when absent: the drafts serve only the branch and its branches.
	DraftsFor []string
	// SchemaReadsFor is schemaReads.for (§6.1): the namespaces, names or
	// prefixes ending in "*", for whose writes and readers this
	// namespace's schema revisions resolve without read here. Nil when
	// absent. The namespace itself always counts (schemaReadsOpen).
	SchemaReadsFor []string
	// SignaturesRequired is "signatures": "required" (§C.3.1): every
	// resource revision and tombstone needs a valid author signature by a
	// signer of its grant. False for "optional", the default.
	SignaturesRequired bool
	level              int
}

// Allowance gives a named principal its own rate and batch limits (§6.6).
// Zero fields mean the namespace's own limit.
type Allowance struct {
	Sub, Kid      string
	Rate          Rate // the allowance's "bucket"
	ItemsPerBatch int
	BatchSize     int
	// BlobRate and BlobPending replace the namespace's blob limits for
	// this principal (§6.6, §7.8); zero means the namespace's.
	BlobRate    Rate
	BlobPending int
	// Until is when the allowance ends (§6.6); zero if it doesn't.
	Until time.Time
}

// MergeAuthor is one entry of merge.authors (§F.3).
type MergeAuthor struct{ Sub, Kid string }

func parseMerge(v any) ([]MergeAuthor, error) {
	const shape = `/merge must be { "authors": [{ "sub", "kid" }, …] }`
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf(shape)
	}
	for _, k := range sortedKeys(m) {
		// Other members must start with "x-" (§7.4).
		if k != "authors" && !strings.HasPrefix(k, "x-") {
			return nil, badAt(pointer.Pointer{"merge", k}, `is not a known field; other members must start with "x-" (§F.3, §7.4)`)
		}
	}
	arr, ok := m["authors"].([]any)
	if !ok {
		return nil, fmt.Errorf(shape)
	}
	out := []MergeAuthor{}
	for i, e := range arr {
		o, ok := e.(map[string]any)
		sub, _ := o["sub"].(string)
		kid, _ := o["kid"].(string)
		if !ok || len(o) != 2 || sub == "" || kid == "" {
			return nil, fmt.Errorf("/merge/authors/%d must be { sub, kid } with non-empty strings", i)
		}
		out = append(out, MergeAuthor{sub, kid})
	}
	return out, nil
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
	// Chain is a remote base's namespace and its bases as of At, as the
	// branch's deployment followed them (§G.3); nil for a local base.
	Chain []string
}

// Remote reports whether the base is in another deployment.
func (b *BaseRef) Remote() bool { return b != nil && b.Origin != "" }

// isLoopbackHost reports whether host is a loopback host: "localhost", an
// address in 127.0.0.0/8, or "::1" (§G.3).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		// 127.0.0.0/8 for IPv4, exactly ::1 for IPv6.
		return ip.IsLoopback()
	}
	return false
}

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
		// http is for loopback hosts: localhost, the whole 127.0.0.0/8
		// range, or [::1] (§G.3).
		if !isLoopbackHost(u.Hostname()) || u.Port() == "80" {
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

// nsMembers are the namespace-document members this version of the spec
// defines (§7.4): the core's, then Addendum B's and Addendum F's. Any other
// member must start with "x-" and is stored as data.
var nsMembers = map[string]bool{
	"read": true, "keys": true, "roles": true, "revoked": true, "rules": true, "limits": true,
	"allowances": true, "retention": true, "encryption": true, "maxLag": true, "base": true,
	"frozen": true, "successor": true, "drafts": true, "signatures": true, "schemaReads": true,
	"catalog": true, "catalogs": true, // Addendum B
	"merge": true, "merged": true, "cleanup": true, "abandoned": true, // Addendum F
}

// memberError is a namespace document that fails the strict part of the
// namespace-document schema (§7.4): the JSON Pointer of the offending
// value, and why. Its 422 is code "invalid" with
// errors: [{ "pointer", "message" }], as for schema validation
// (configErr). member is set for a top-level member this version doesn't
// define and that doesn't start with "x-"; inherited, when a new branch's
// document holds it because its base's does (stored under an earlier
// version): the message then says how the branch's patches can rename it.
type memberError struct {
	pointer   string
	msg       string
	member    string
	inherited bool
}

func (e *memberError) Error() string {
	if e.member == "" {
		return e.msg
	}
	x := pointer.Pointer{"x-" + e.member}
	if e.inherited {
		return fmt.Sprintf(`%s, which the base's document holds, is not a namespace-document member of the spec version this server implements, and a new namespace can't hold it; other members must start with "x-": the branch's patches can rename it, {"op":"move","from":%q,"path":%q} (§7.4)`,
			e.pointer, e.pointer, x.String())
	}
	return fmt.Sprintf(`%s is not a namespace-document member of the spec version this server implements; other members must start with "x-", e.g. %s (§7.4)`,
		e.pointer, x)
}

// badAt is a memberError at the value p; the message starts with p.
func badAt(p pointer.Pointer, format string, args ...any) *memberError {
	s := p.String()
	return &memberError{pointer: s, msg: s + " " + fmt.Sprintf(format, args...)}
}

// unknownMember is the memberError of a top-level member k this version
// doesn't define.
func unknownMember(k string) *memberError {
	return &memberError{pointer: pointer.Pointer{k}.String(), member: k}
}

// isX reports an "x-" member, stored as data (§7.4). The prefix is
// case-sensitive.
func isX(k string) bool { return strings.HasPrefix(k, "x-") }

// checkMembers is the strict part of the namespace-document schema (§7.4),
// for a document a write produces, after parseConfig accepted it: every
// top-level member is one the spec defines, in its shape, or starts with
// "x-" and is stored as data, so a typo or a setting from a newer version
// is refused rather than ignored. So may members inside the addenda's
// objects (catalog, each catalogs entry, merge, merged, cleanup), except
// as keys of catalogs, which are catalog names; role entries are open
// (grant.ParseRoles reads can and rules and ignores the rest); key entries
// and other nested objects are strict. parseConfig checks the core's
// members, and reads stored documents too; this checks the rest, which
// only services read, and revocation ids and key entries.
//
// prev is what the write keeps: for a config write the namespace's current
// document, so a member it holds with the same value, stored under an
// earlier version, is kept as data until a write changes or removes it,
// and a namespace written before an upgrade can still be frozen, rotated
// or merged; for a new branch only the members its base's document holds
// that this version defines (definedMembers), since a new namespace holds
// no others. Within revoked and keys, entries prev holds are kept the
// same way, so a revocation can be added next to one an older version
// stored. A new namespace has no prev. Removing a member is always
// accepted: only what the document holds is checked.
func checkMembers(doc, prev map[string]any) error {
	for _, k := range sortedKeys(doc) {
		v := doc[k]
		if isX(k) {
			continue
		}
		if pv, ok := prev[k]; ok && jsonv.Equal(pv, v) {
			continue
		}
		var err *memberError
		switch k {
		case "revoked":
			// parseConfig, which reads stored documents too, checks only
			// that they are strings, as older versions did; entries prev
			// holds are kept.
			kept := map[string]bool{}
			pa, _ := prev[k].([]any)
			for _, e := range pa {
				if s, ok := e.(string); ok {
					kept[s] = true
				}
			}
			arr, _ := v.([]any)
			for i, e := range arr {
				s, _ := e.(string)
				if _, perr := ids.Parse(s); perr != nil && !kept[s] {
					err = badAt(pointer.Pointer{"revoked", strconv.Itoa(i)}, "must be a revocation id, the text id of a block's signature (§C.4)")
					break
				}
			}
		case "keys":
			err = checkKeyFields(v, prev[k])
		case "catalog":
			err = checkCatalog(v)
		case "catalogs":
			err = checkCatalogs(v)
		case "merge":
			// parseConfig checked its shape; x- members are data.
		case "merged":
			err = checkMerged(v)
		case "cleanup":
			err = checkCleanup(v)
		case "abandoned":
			if _, ok := v.(bool); !ok {
				err = badAt(pointer.Pointer{"abandoned"}, "must be a boolean (§F.6)")
			}
		default:
			if !nsMembers[k] {
				err = unknownMember(k)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// definedMembers is what a new branch keeps of its base's document as
// stored (checkMembers): the members this version defines.
func definedMembers(doc map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range doc {
		if nsMembers[k] {
			out[k] = v
		}
	}
	return out
}

// checkKeyFields refuses fields a key entry doesn't define (§C.4), which
// grant.ParseKeys accepts when they start with "x-", as stored documents
// may hold them: key entries are strict (§7.4). An entry prev holds
// unchanged is kept.
func checkKeyFields(v, prev any) *memberError {
	pa, _ := prev.([]any)
	arr, _ := v.([]any)
	for i, e := range arr {
		m, _ := e.(map[string]any)
		kept := false
		for _, p := range pa {
			if jsonv.Equal(p, e) {
				kept = true
				break
			}
		}
		if kept {
			continue
		}
		for _, f := range sortedKeys(m) {
			if isX(f) {
				return badAt(pointer.Pointer{"keys", strconv.Itoa(i), f}, "is not a key field; a key entry holds only the fields of §C.4")
			}
		}
	}
	return nil
}

// checkCatalog checks a catalog namespace's "catalog" (§B.6):
// { "trust"?: [namespace names], "mode"?: "tree" | "dag", "title"?: pointer },
// and x- members.
func checkCatalog(v any) *memberError {
	m, ok := v.(map[string]any)
	if !ok {
		return badAt(pointer.Pointer{"catalog"}, `must be { "trust"?: [namespace names], "mode"?: "tree" | "dag", "title"?: pointer } (§B.6)`)
	}
	for _, k := range sortedKeys(m) {
		switch x := m[k]; {
		case k == "trust":
			arr, ok := x.([]any)
			if !ok {
				return badAt(pointer.Pointer{"catalog", "trust"}, "must be an array of namespace names (§B.6)")
			}
			for i, e := range arr {
				if s, ok := e.(string); !ok || !ValidNSName(s) {
					return badAt(pointer.Pointer{"catalog", "trust", strconv.Itoa(i)}, "must be a namespace name (§3.6)")
				}
			}
		case k == "mode":
			if x != "tree" && x != "dag" {
				return badAt(pointer.Pointer{"catalog", "mode"}, `must be "tree" or "dag" (§B.6)`)
			}
		case k == "title":
			if t, ok := x.(string); !ok {
				return badAt(pointer.Pointer{"catalog", "title"}, "must be a JSON Pointer (§B.5)")
			} else if _, err := pointer.Parse(t); err != nil {
				return badAt(pointer.Pointer{"catalog", "title"}, "must be a JSON Pointer (§B.5)")
			}
		case isX(k):
		default:
			return badAt(pointer.Pointer{"catalog", k}, `is not a known field; other members must start with "x-" (§B.6, §7.4)`)
		}
	}
	return nil
}

// subjectRe is a catalog subject (§B.11.1): a group or a user.
var subjectRe = regexp.MustCompile(`^(group|user):.+$`)

// checkCatalogs checks a content namespace's "catalogs" (§B.11.3):
// { catalog namespace: { "place"?: [subjects] } }. Its keys are catalog
// names, never x- members; each entry may hold x- members.
func checkCatalogs(v any) *memberError {
	m, ok := v.(map[string]any)
	if !ok {
		return badAt(pointer.Pointer{"catalogs"}, `must be { catalog namespace: { "place": ["group:…" or "user:…", …] } } (§B.11.3)`)
	}
	for _, cat := range sortedKeys(m) {
		if !ValidNSName(cat) {
			return badAt(pointer.Pointer{"catalogs", cat}, "is not a catalog namespace name: the keys of /catalogs must be catalog namespace names (§B.11.3)")
		}
		o, ok := m[cat].(map[string]any)
		if !ok {
			return badAt(pointer.Pointer{"catalogs", cat}, `must be { "place": ["group:…" or "user:…", …] } (§B.11.3)`)
		}
		for _, k := range sortedKeys(o) {
			if isX(k) {
				continue
			}
			if k != "place" {
				return badAt(pointer.Pointer{"catalogs", cat, k}, `is not a known field; other members must start with "x-" (§B.11.3, §7.4)`)
			}
			arr, ok := o[k].([]any)
			if !ok {
				return badAt(pointer.Pointer{"catalogs", cat, "place"}, `must be an array of subjects, "group:…" or "user:…" (§B.11.3)`)
			}
			for i, e := range arr {
				if s, ok := e.(string); !ok || !subjectRe.MatchString(s) {
					return badAt(pointer.Pointer{"catalogs", cat, "place", strconv.Itoa(i)}, `must be a subject, "group:…" or "user:…" (§B.11.1)`)
				}
			}
		}
	}
	return nil
}

// checkMerged checks a merged branch's "merged" (§F.3): { "at": the base's
// ns_id after the merge }, and x- members.
func checkMerged(v any) *memberError {
	m, ok := v.(map[string]any)
	at, _ := m["at"].(string)
	if _, perr := ids.Parse(at); !ok || perr != nil {
		return badAt(pointer.Pointer{"merged"}, `must be { "at": the base's ns_id after the merge } (§F.3)`)
	}
	for _, k := range sortedKeys(m) {
		if k != "at" && !isX(k) {
			return badAt(pointer.Pointer{"merged", k}, `is not a known field; other members must start with "x-" (§F.3, §7.4)`)
		}
	}
	return nil
}

// checkCleanup checks a branch's "cleanup" (§F.6), which the janitor reads,
// and a base's minimums in the same shape: { "merged"?, "superseded"?,
// "abandoned"? }, each an ISO 8601 duration, and x- members.
func checkCleanup(v any) *memberError {
	m, ok := v.(map[string]any)
	if !ok {
		return badAt(pointer.Pointer{"cleanup"}, `must be { "merged"?, "superseded"?, "abandoned"? }, each an ISO 8601 duration (§F.6)`)
	}
	for _, k := range sortedKeys(m) {
		switch {
		case k == "merged" || k == "superseded" || k == "abandoned":
			s, ok := m[k].(string)
			if _, err := ParseDuration(s); !ok || err != nil {
				return badAt(pointer.Pointer{"cleanup", k}, "must be an ISO 8601 duration, e.g. P7D (§F.6)")
			}
		case isX(k):
		default:
			return badAt(pointer.Pointer{"cleanup", k}, `is not a known field; other members must start with "x-" (§F.6, §7.4)`)
		}
	}
	return nil
}

var nsNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var resNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ValidNSName and ValidResourceName check the grammar of §3.6.
func ValidNSName(s string) bool       { return nsNameRe.MatchString(s) }
func ValidResourceName(s string) bool { return resNameRe.MatchString(s) }

// parseConfig validates a namespace document against the built-in
// namespace-document schema and the deployment maximums: the members the
// core reads. It also reads stored documents, so it leaves other members
// alone; writes check them with checkMembers (§7.4).
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
		case "merge":
			ma, err := parseMerge(v)
			if err != nil {
				return nil, err
			}
			c.MergeAuthors = ma
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
				// A remote branch (§7.6, §G.3): { origin, ns, at, chain? }.
				origin, _ := b["origin"].(string)
				_, hasChain := b["chain"]
				n := 3
				if hasChain {
					n = 4
				}
				if len(b) != n || !ValidRemoteOrigin(origin) || !ValidNSName(ns) {
					return nil, fmt.Errorf("/base must be { origin, ns, at, chain? } with an https origin")
				}
				if _, err := ids.Parse(at); err != nil {
					return nil, fmt.Errorf("/base/at must be an ns_id")
				}
				c.Base = &BaseRef{Origin: origin, NS: ns, At: at}
				if hasChain {
					// The base's namespace and its bases, as of at (§G.3).
					arr, _ := b["chain"].([]any)
					for _, x := range arr {
						s, _ := x.(string)
						if !ValidNSName(s) {
							return nil, fmt.Errorf("/base/chain must list namespace names")
						}
						c.Base.Chain = append(c.Base.Chain, s)
					}
					if len(c.Base.Chain) == 0 || c.Base.Chain[0] != ns {
						return nil, fmt.Errorf("/base/chain must start with /base/ns")
					}
				}
				continue
			}
			if !ok || ns == "" || at == "" || len(b) != 2 {
				return nil, fmt.Errorf("/base must be { ns, at } or { origin, ns, at }")
			}
			c.Base = &BaseRef{NS: ns, At: at}
		case "signatures":
			switch v {
			case "optional":
			case "required":
				c.SignaturesRequired = true
			default:
				return nil, fmt.Errorf(`/signatures must be "optional" or "required"`)
			}
		case "drafts":
			df, err := parseDrafts(v)
			if err != nil {
				return nil, err
			}
			c.DraftsFor = df
		case "schemaReads":
			sr, err := parseSchemaReads(v)
			if err != nil {
				return nil, err
			}
			c.SchemaReadsFor = sr
		case "encryption":
			e, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf(`/encryption must be { "level": "at-rest" | "sealed" | "e2e", "epoch"?, "historyEpochs"?, "pad"? }`)
			}
			for k := range e {
				if k != "level" && k != "epoch" && k != "historyEpochs" && k != "pad" {
					return nil, fmt.Errorf("/encryption/%s is not supported by this server", k)
				}
			}
			lv, _ := e["level"].(string)
			switch lv {
			case "at-rest", "sealed", "e2e":
			default:
				return nil, fmt.Errorf(`/encryption/level must be "at-rest", "sealed" or "e2e"`)
			}
			if lv == "at-rest" {
				if _, has := e["epoch"]; has {
					return nil, fmt.Errorf("/encryption/epoch is only for sealed and e2e namespaces")
				}
				if _, has := e["historyEpochs"]; has {
					return nil, fmt.Errorf("/encryption/historyEpochs is only for sealed and e2e namespaces")
				}
				if _, has := e["pad"]; has {
					return nil, fmt.Errorf("/encryption/pad is only for sealed and e2e namespaces")
				}
			} else {
				// Epochs count from 1; an absent epoch is 1 (§E.2.1).
				c.Epoch = 1
				if x, has := e["epoch"]; has {
					f, ok := x.(float64)
					if !ok || f < 1 || f != float64(int(f)) || f > 1<<31 {
						return nil, fmt.Errorf("/encryption/epoch must be a positive integer")
					}
					c.Epoch = int(f)
				}
				if x, has := e["historyEpochs"]; has {
					f, ok := x.(float64)
					if !ok || f < 1 || f != float64(int(f)) || f > 1<<31 {
						return nil, fmt.Errorf("/encryption/historyEpochs must be a positive integer")
					}
					c.HistoryEpochs = int(f)
				}
				if x, has := e["pad"]; has {
					b, ok := x.(bool)
					if !ok {
						return nil, fmt.Errorf("/encryption/pad must be a boolean")
					}
					c.Pad = b
				}
			}
			c.Encryption, c.level = lv, levelOf(lv)
		}
	}
	if c.DraftsFor != nil && c.Base == nil {
		return nil, fmt.Errorf("/drafts is only for local branches (§7.4)")
	}
	if c.DraftsFor != nil && (c.Base.Remote() || c.level == levelE2E) {
		// It could have no effect there (§6.1, §7.4).
		return nil, fmt.Errorf("/drafts is only for local branches that aren't end-to-end encrypted (§7.4)")
	}
	if c.SchemaReadsFor != nil && c.level >= levelSealed {
		// Their readers need keys that a pinning document doesn't give
		// them (§6.1).
		return nil, fmt.Errorf("/schemaReads is not allowed in sealed and end-to-end namespaces (§6.1)")
	}
	if c.level == levelE2E {
		// Sealing grows a patch set by half, and it carries the declared
		// blob list (§6.6, Values).
		l := c.Limits
		if 3*(l.ValueSize+l.PathSize)+(1<<10)+36*l.BlobsPerDocument > l.PatchSetSize {
			return nil, &limitError{"an e2e namespace needs 3 × (valueSize + pathSize) + 1 KiB + 36 B × blobsPerDocument ≤ patchSetSize (§6.6)"}
		}
		for i, r := range c.Retention {
			if r.NoArchive {
				return nil, fmt.Errorf(`/retention/%d/archive: "archive": false is not allowed in an e2e namespace, where pruning needs an archive (§8.6)`, i)
			}
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
		if deploymentOnlyLimits[k] {
			return fmt.Errorf("/limits/%s is set by the deployment only (§6.6)", k)
		}
		if f, ok := limitFields[k]; ok {
			n, ok := x.(float64)
			if !ok || n < 0 || n != float64(int(n)) {
				if sizeFields[k] {
					return fmt.Errorf("/limits/%s must be a non-negative integer, in bytes (§6.6)", k)
				}
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
		if k == "remoteRegistration" {
			s, ok := x.(string)
			d, err := ParseDuration(s)
			if !ok || err != nil || d <= 0 {
				return fmt.Errorf("/limits/remoteRegistration must be a positive ISO 8601 duration")
			}
			if d > max.RemoteRegistration {
				return &limitError{"/limits/remoteRegistration exceeds the deployment maximum"}
			}
			l.RemoteRegistration = d
			continue
		}
		if k == "blobGrace" {
			s, ok := x.(string)
			d, err := ParseDuration(s)
			if !ok || err != nil || d <= 0 {
				return fmt.Errorf("/limits/blobGrace must be a positive ISO 8601 duration")
			}
			if d > max.BlobGrace {
				return &limitError{"/limits/blobGrace exceeds the deployment maximum"}
			}
			l.BlobGrace = d
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
	// A pending blob lives at least as long as a retry may come (§6.6).
	if l.BlobGrace < l.RetryWindow {
		return &limitError{"/limits/blobGrace must be at least retryWindow (§6.6)"}
	}
	return nil
}

// sizeFields are limits in bytes. A namespace document writes them as
// integers (§6.6); ParseSize's "64 MiB" form is for deployment flags only.
var sizeFields = map[string]bool{"patchSetSize": true, "documentSize": true, "valueSize": true, "pathSize": true, "grantSize": true, "batchSize": true, "blobSize": true, "blobPending": true}

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
			case "bucket":
				o, ok := x.(map[string]any)
				r, rok := o["rate"].(float64)
				b, bok := o["burst"].(float64)
				if !ok || len(o) != 2 || !rok || !bok || r <= 0 || b < 1 {
					return nil, fmt.Errorf("/allowances/%d/bucket must be { rate, burst }, rate positive and burst at least 1", i)
				}
				a.Rate = Rate{r, b}
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
				y, ok := x.(float64)
				n := int(y)
				if !ok || y != float64(n) || n < 1 {
					return nil, fmt.Errorf("/allowances/%d/batchSize must be a positive integer, in bytes (§6.6)", i)
				}
				if n > max.BatchSize {
					return nil, &limitError{fmt.Sprintf("/allowances/%d/batchSize exceeds the deployment maximum %d", i, max.BatchSize)}
				}
				a.BatchSize = n
			case "blobRate":
				o, ok := x.(map[string]any)
				r, rok := o["rate"].(float64)
				b, bok := o["burst"].(float64)
				if !ok || len(o) != 2 || !rok || !bok || r <= 0 || b < 1 {
					return nil, fmt.Errorf("/allowances/%d/blobRate must be { rate, burst } in bytes, rate positive and burst at least 1", i)
				}
				if r > max.BlobRate.Rate || b > max.BlobRate.Burst {
					return nil, &limitError{fmt.Sprintf("/allowances/%d/blobRate exceeds the deployment maximum", i)}
				}
				a.BlobRate = Rate{r, b}
			case "blobPending":
				y, ok := x.(float64)
				n := int(y)
				if !ok || y != float64(n) || n < 1 {
					return nil, fmt.Errorf("/allowances/%d/blobPending must be a positive integer, in bytes (§6.6)", i)
				}
				if n > max.BlobPending {
					return nil, &limitError{fmt.Sprintf("/allowances/%d/blobPending exceeds the deployment maximum %d", i, max.BlobPending)}
				}
				a.BlobPending = n
			case "until":
				str, ok := x.(string)
				u, err := time.Parse(time.RFC3339, str)
				if !ok || err != nil {
					return nil, fmt.Errorf("/allowances/%d/until must be an RFC 3339 time with an offset, e.g. 2026-12-31T23:59:59Z", i)
				}
				a.Until = u
			default:
				return nil, fmt.Errorf("/allowances/%d/%s is not a known field", i, k)
			}
		}
		if a.Sub == "" || a.Kid == "" {
			return nil, fmt.Errorf("/allowances/%d needs sub and kid", i)
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
