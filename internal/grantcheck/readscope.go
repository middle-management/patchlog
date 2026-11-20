package grantcheck

import (
	"crypto/sha256"
	"errors"
	"slices"
	"sync"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/rules"
)

// What a grant that reads a namespace only in part reads there, shared by
// the index (§A.4's scope marker) and the origin's filtered reads
// (§7.9's scope:{digest} subject and item 2).

// ScopeInput is what §A.4's scope marker digests: the rules a grant's
// reads in a namespace are judged by, those of its key's scope, its blocks
// and its effective roles that list read, by name, and its /principal
// envelope, of which only the values those rules refer to are digested.
type ScopeInput struct {
	ReadScopeResource bool
	KeyRules          []any
	BlockRules        []any
	Roles             map[string][]any
	Principal         map[string]any
}

// ScopeInputOf is the ScopeInput of v's reads. Its roles are those that
// count for read: each effective role that lists read, less those with a
// rule that fails for a read (FailsRead, §C.2 item 5), as FilterOf's.
func ScopeInputOf(v *grant.Verified) ScopeInput {
	in := ScopeInput{ReadScopeResource: v.Key.ReadScopeResource, KeyRules: v.KeyRules, BlockRules: v.BlockRules,
		Roles: map[string][]any{}, Principal: v.Principal.Envelope()}
	for _, role := range readRoles(v) {
		in.Roles[role] = v.RoleRules(role)
	}
	return in
}

// readRoles are v's effective roles that count for read: those that list
// read and have no rule failing for a read (FailsRead; §C.2 item 5: "a
// role with such a rule doesn't count for read"). A rule that doesn't
// compile leaves its role in, where it refuses every read it judges.
func readRoles(v *grant.Verified) []string {
	_, readers := v.Allows("read")
	var out []string
	for _, role := range readers {
		if !failsRead(v.RoleRules(role)) {
			out = append(out, role)
		}
	}
	return out
}

// failsRead reports whether some rule of rs fails for a read (FailsRead).
func failsRead(rs []any) bool {
	for _, rv := range rs {
		if r, err := rules.Compile(rv); err == nil && FailsRead(r) {
			return true
		}
	}
	return false
}

// ReadsScope digests what the reads of a grant that reads a namespace only
// in part depend on (§A.4, §7.9): the rules they are judged by there
// (its key's scope, its blocks' and those of its roles that grant read,
// §C.5) and the /principal values those refer to, so readers with the same
// rules and values share answers. It reports false if a rule refers to
// /now (or the whole envelope): the namespace then counts as unreadable,
// since an answer at a given at can't change. The digest is the index's
// marker reads:{ns}:scope:{digest}, byte for byte. A grant that carries
// roles, none of which counts for read (each refers to /now, ScopeInputOf),
// reads nothing: false, so that it never shares a digest with a grant
// without roles.
func ReadsScope(v *grant.Verified) (digest string, ok bool) {
	in := ScopeInputOf(v)
	if v.HasRoles() && len(in.Roles) == 0 {
		return "", false
	}
	return ScopeDigest(in)
}

// ScopeDigest is ReadsScope over its inputs, so that the origin can digest
// a stored gs's rules again as of another checkpoint (§7.9: a gs cookie
// is 403 at an at where those rules differ). It reports false where any
// rule, a role's included, refers to /now or the whole envelope: a stored
// role that has gained one since doesn't count for read any more (§C.2
// item 5), so the cookie ends.
func ScopeDigest(in ScopeInput) (string, bool) {
	lists := [][]any{in.KeyRules, in.BlockRules}
	roles := map[string]any{}
	names := make([]string, 0, len(in.Roles))
	for role := range in.Roles {
		names = append(names, role)
	}
	slices.Sort(names)
	for _, role := range names {
		roles[role] = in.Roles[role]
		lists = append(lists, in.Roles[role])
	}
	env := map[string]any{"principal": in.Principal}
	principal := map[string]any{}
	for _, l := range lists {
		for _, rv := range l {
			r, err := rules.Compile(rv)
			if err != nil {
				return "", false // it refuses every read anyway
			}
			for _, p := range r.RefPaths() {
				switch {
				case len(p) == 0 || p[0] == "now":
					return "", false
				case p[0] == "principal":
					if x, ok := pointer.Get(env, p); ok {
						principal[p.String()] = x
					}
				}
			}
		}
	}
	x := map[string]any{
		"readScope": in.ReadScopeResource, "keyRules": in.KeyRules, "blockRules": in.BlockRules,
		"roles": roles, "principal": principal,
	}
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(x)))
	return ids.FromBytes(sum[:ids.Size]).String(), true
}

// CombinedAt is the combined checkpoint of §B.5 over cps (ns → ns_id
// text): the same bytes as the tree service's and the index's.
func CombinedAt(cps map[string]string) string {
	m := make(map[string]any, len(cps))
	for ns, id := range cps {
		m[ns] = id
	}
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(m)))
	return ids.FromBytes(sum[:ids.Size]).String()
}

// ReadFilter is what a view (§7.9) or a scope marker (§A.4) stands for:
// the rules a grant's reads in a namespace are judged by, those of its
// key's scope, its blocks and, if it carries roles, each effective role
// that counts for read (any one passing), and its /principal envelope. A
// key-scope or block rule referring to /now gives no view (ReadsScope),
// and a role with one doesn't count (FilterOf), so the filter judges a
// read as the grant's read check does, without a clock; one decoded with
// such a rule (DecodeReadFilter) refuses every read, or doesn't count the
// role, as that check does (FailsRead). Reads are judged per revision
// (§C.2 item 5): the read envelope carries the revision's doc, and where
// it is null every rule that refers to /doc fails as a whole (§6.4.1).
// Fields must not change once a method has been called.
type ReadFilter struct {
	KeyRules, BlockRules []any
	Roles                [][]any // nil: the grant carries no roles
	Principal            map[string]any
	// Steps is the validation steps each judgement may take in the rules'
	// schema tests (§6.6 Validation work: each item a service filters by
	// a grant has its own budget). One that needs more doesn't allow. It
	// isn't part of what Encode keeps: 0, as a decoded filter has, is
	// §12.2's default, and a service sets its own
	// (Checker.ValidationSteps).
	Steps int

	once     sync.Once
	compiled [][]*rules.Rule // KeyRules, BlockRules, then each role's
	docRefs  bool            // some rule refers to /doc
	err      error
}

// FilterOf is the ReadFilter of v's reads: its roles are those that count
// for read (ScopeInputOf), so a grant that carries roles, none of which
// counts, reads nothing.
func FilterOf(v *grant.Verified) *ReadFilter {
	f := &ReadFilter{KeyRules: v.KeyRules, BlockRules: v.BlockRules, Principal: v.Principal.Envelope()}
	if v.HasRoles() {
		f.Roles = [][]any{}
		for _, role := range readRoles(v) {
			f.Roles = append(f.Roles, v.RoleRules(role))
		}
	}
	return f
}

// Encode is f as it is kept (the index's edge_filters, the origin's
// filtered_views): canonical JSON.
func (f *ReadFilter) Encode() string {
	m := map[string]any{"keyRules": f.KeyRules, "blockRules": f.BlockRules, "principal": f.Principal}
	if f.Roles != nil {
		roles := make([]any, len(f.Roles))
		for i, r := range f.Roles {
			roles[i] = r
		}
		m["roles"] = roles
	}
	return string(jsonv.Canonical(jsonv.FromGo(m)))
}

// DecodeReadFilter reads what Encode wrote.
func DecodeReadFilter(s string) (*ReadFilter, error) {
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	f := &ReadFilter{}
	f.KeyRules, _ = m["keyRules"].([]any)
	f.BlockRules, _ = m["blockRules"].([]any)
	f.Principal, _ = m["principal"].(map[string]any)
	if roles, ok := m["roles"].([]any); ok {
		f.Roles = [][]any{}
		for _, r := range roles {
			l, _ := r.([]any)
			f.Roles = append(f.Roles, l)
		}
	}
	return f, nil
}

// errFailsRead is a filter with a key-scope or block rule that fails for
// a read (FailsRead): it allows nothing.
var errFailsRead = errors.New("a key-scope or block rule refers to /now, which no read passes")

// failRule stands for a role's rule that fails for a read (FailsRead):
// a test no read envelope passes, so the role never counts.
var failRule = func() *rules.Rule {
	r, err := rules.Compile(map[string]any{"op": "test", "path": "/action", "value": "never"})
	if err != nil {
		panic(err)
	}
	return r
}()

// RefersToDoc reports whether r refers to /doc (§2.1 Refers to): such a
// rule fails as a whole for a read whose doc is null (§6.4.1).
func RefersToDoc(r *rules.Rule) bool {
	refs := r.Refs()
	return refs["doc"] || refs["*"]
}

func (f *ReadFilter) compile() {
	f.once.Do(func() {
		lists := append([][]any{f.KeyRules, f.BlockRules}, f.Roles...)
		for i, l := range lists {
			var rs []*rules.Rule
			for _, rv := range l {
				r, err := rules.Compile(rv)
				if err != nil {
					f.err = err
					return
				}
				if FailsRead(r) {
					// It fails every read (§C.2 item 5): a key-scope or
					// block rule refuses them all, and a role with it
					// doesn't count.
					if i < 2 {
						f.err = errFailsRead
						return
					}
					rs = append(rs, failRule)
					continue
				}
				if RefersToDoc(r) {
					f.docRefs = true
				}
				rs = append(rs, r)
			}
			f.compiled = append(f.compiled, rs)
		}
	})
}

// RefersToDoc reports whether a rule of f refers to /doc: only then does
// a read's answer depend on the revision it concerns rather than on the
// resource's name alone.
func (f *ReadFilter) RefersToDoc() bool {
	f.compile()
	return f.docRefs
}

// Allows reports whether the reads f stands for may read resource where
// the read concerns no stored document (doc null, §6.4.1): every rule
// that refers to /doc fails.
func (f *ReadFilter) Allows(resource string) bool { return f.AllowsDoc(resource, nil, false) }

// AllowsDoc reports whether the reads f stands for may read a revision of
// resource whose document is doc (§C.2 item 5): every key-scope and block
// rule passes against the read envelope (§6.4.1) and, with roles, every
// rule of some role does (§C.1.1). hasDoc false is a null doc, against
// which every rule that refers to /doc fails as a whole.
func (f *ReadFilter) AllowsDoc(resource string, doc any, hasDoc bool) bool {
	f.compile()
	if f.err != nil {
		return false
	}
	env := map[string]any{"action": "read", "resource": resource, "principal": f.Principal}
	if hasDoc {
		env["doc"] = doc
	}
	m := rules.Budget(f.Steps)
	pass := func(rs []*rules.Rule) bool {
		for _, r := range rs {
			if !hasDoc && RefersToDoc(r) {
				return false
			}
			if !r.Passes(env, m) {
				return false
			}
		}
		// A role without rules doesn't make up for one before it that
		// ran out of steps: that fails the whole check (§6.6).
		return !m.Over
	}
	if !pass(f.compiled[0]) || !pass(f.compiled[1]) {
		return false
	}
	if f.Roles == nil {
		return true
	}
	for _, rs := range f.compiled[2:] {
		if pass(rs) {
			return true
		}
	}
	return false
}

// WithoutDoc is f with only its rules that don't refer to /doc, each
// top-level all flattened into the rules it holds first (§7.9 Log
// entries: a purge is shown where these allow read of its resource).
func (f *ReadFilter) WithoutDoc() *ReadFilter {
	keep := func(rs []any) []any {
		out := []any{}
		var walk func(rs []any)
		walk = func(rs []any) {
			for _, rv := range rs {
				if m, ok := rv.(map[string]any); ok && len(m) == 1 {
					if all, ok := m["all"].([]any); ok {
						walk(all)
						continue
					}
				}
				if r, err := rules.Compile(rv); err == nil && RefersToDoc(r) && !FailsRead(r) {
					continue
				}
				out = append(out, rv)
			}
		}
		walk(rs)
		return out
	}
	g := &ReadFilter{KeyRules: keep(f.KeyRules), BlockRules: keep(f.BlockRules), Principal: f.Principal, Steps: f.Steps}
	if f.Roles != nil {
		g.Roles = [][]any{}
		for _, rs := range f.Roles {
			g.Roles = append(g.Roles, keep(rs))
		}
	}
	return g
}

// KeyPrefix prefixes a view's key subject (KeySubject).
const KeyPrefix = "key:"

// ScopePrefix prefixes a view's scope subject, scope:{digest}.
const ScopePrefix = "scope:"

// KeySubject is the subject that binds a view (§7.9) to the key that
// verified its grant's root block, by kid and pub, the pub member string
// as the key's entry has it: key:{text(trunc160(sha256(canonical([kid,
// pub]))))}. Without it readers through two keys with the same scope rules
// would share a view, and so one stored record, whose kid and pub, those
// of its last exchange, would judge both keys' cookies.
func KeySubject(kid, pub string) string {
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo([]any{kid, pub})))
	return KeyPrefix + ids.FromBytes(sum[:ids.Size]).String()
}

// ScopeKeyDigest is the digest of §A.4's scope marker
// reads:{ns}:scope:{digest}, which covers the rules that limit a reader's
// reads, d (ReadsScope), and its key's key: string (KeySubject): the
// digest of canonical([d, key:…]). A view carries the same as its
// scope:{digest} subject (ViewSubjects); implementations needn't agree
// on it (§7.9 view).
func ScopeKeyDigest(d, kid, pub string) string {
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo([]any{d, KeySubject(kid, pub)})))
	return ids.FromBytes(sum[:ids.Size]).String()
}

// ViewSubjects are a view's subjects (§7.9 view), sorted: for a reader
// whose reads are limited (scoped), scope:{ScopeKeyDigest(d, kid, pub)},
// and always KeySubject(kid, pub). A grant §C.5.2 would give /ns/{ns}
// has no scope: subject. Its view is ViewID of the result.
func ViewSubjects(d, kid, pub string, scoped bool) []string {
	out := []string{KeySubject(kid, pub)}
	if scoped {
		out = append(out, ScopePrefix+ScopeKeyDigest(d, kid, pub))
	}
	slices.Sort(out)
	return out
}
