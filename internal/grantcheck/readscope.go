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
// (§B.11.9's scope:{digest} subject and item 2).

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

// RefusedByNow reports whether rules on /now refuse v every read (§C.2
// item 5): a key-scope or block rule fails for a read (FailsRead), or v
// carries roles, some listing read, and every one of those has a rule
// that fails for a read, so none counts. A grant that allows no read at
// all is not this case.
func RefusedByNow(v *grant.Verified) bool {
	if RefusedByNowRule(v) {
		return true
	}
	ok, readers := v.Allows("read")
	return ok && v.HasRoles() && len(readers) > 0 && len(readRoles(v)) == 0
}

// RefusedByNowRule is the first half of RefusedByNow: a key-scope or
// block rule of v fails for a read (FailsRead), referring to /now or the
// whole envelope. The catalog's POST /grants and POST /read-grants refuse
// such a grant whatever it wants (§B.11.4 The caller's grant, §C.2 item
// 5); its roles' rules are judged per want there (ReadsNothing).
func RefusedByNowRule(v *grant.Verified) bool {
	return failsRead(v.KeyRules) || failsRead(v.BlockRules)
}

// ReadsNothing reports whether v allows read nowhere it verifies in
// (§B.11.4 The caller's grant, §C.2 item 2): its blocks or key don't
// allow read, or it carries roles and none counts for read, each either
// not listing read or having a rule that fails for a read (readRoles,
// §C.2 item 5: such a role "doesn't count for read"). v is a grant as
// verified in one namespace, the one this is judged in.
func ReadsNothing(v *grant.Verified) bool {
	if ok, _ := v.Allows("read"); !ok {
		return true
	}
	return v.HasRoles() && len(readRoles(v)) == 0
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
// in part depend on (§A.4, §B.11.9): the rules they are judged by there
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
// a stored gs's rules again as of another checkpoint (§B.11.9: a gs cookie
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

// ReadFilter is what a scope marker, or a filtered-read gs (§B.11.9 item
// 2), stands for: the rules a grant's reads in a namespace are judged by,
// those of its key's scope, its blocks and, if it carries roles, each
// effective role that counts for read (any one passing), and its
// /principal envelope. A key-scope or block rule referring to /now gives
// no marker (ReadsScope), and a role with one doesn't count (FilterOf), so
// the filter judges a read as the grant's read check does, without a
// clock; one decoded with such a rule (DecodeReadFilter) refuses every
// read, or doesn't count the role, as that check does (FailsRead).
// Fields must not change once Allows or AllowsItem has been called.
type ReadFilter struct {
	KeyRules, BlockRules []any
	Roles                [][]any // nil: the grant carries no roles
	Principal            map[string]any

	once     sync.Once
	compiled [][]*rules.Rule // KeyRules, BlockRules, then each role's
	item     []bool          // per role: it counts for AllowsItem
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
// filtered_gs): canonical JSON.
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

var (
	ptrPrincipal       = pointer.Pointer{"principal"}
	ptrPrincipalGroups = pointer.Pointer{"principal", "groups"}
	ptrPrincipalRoles  = pointer.Pointer{"principal", "roles"}
)

func (f *ReadFilter) compile() {
	f.once.Do(func() {
		lists := append([][]any{f.KeyRules, f.BlockRules}, f.Roles...)
		for i, l := range lists {
			var rs []*rules.Rule
			item := true
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
				for _, p := range r.RefPaths() {
					if p.Overlaps(ptrPrincipal) && !p.HasPrefix(ptrPrincipalGroups) && !p.HasPrefix(ptrPrincipalRoles) {
						item = false
					}
				}
				rs = append(rs, r)
			}
			f.compiled = append(f.compiled, rs)
			if i >= 2 {
				f.item = append(f.item, item)
			}
		}
	})
}

// Allows reports whether the reads f stands for may read resource: every
// key-scope and block rule passes against the read envelope (§6.4.1) and,
// with roles, every rule of some role does (§C.1.1).
func (f *ReadFilter) Allows(resource string) bool { return f.allows(resource, false) }

// AllowsItem is §B.11.9's item 2: Allows, but a role counts only as
// §B.11.5 counts roles, so one with a rule that refers to anything in
// /principal but /principal/groups and /principal/roles never allows.
func (f *ReadFilter) AllowsItem(resource string) bool { return f.allows(resource, true) }

func (f *ReadFilter) allows(resource string, item bool) bool {
	f.compile()
	if f.err != nil {
		return false
	}
	env := map[string]any{"action": "read", "resource": resource, "principal": f.Principal}
	pass := func(rs []*rules.Rule) bool {
		for _, r := range rs {
			if !r.Eval(env) {
				return false
			}
		}
		return true
	}
	if !pass(f.compiled[0]) || !pass(f.compiled[1]) {
		return false
	}
	if f.Roles == nil {
		return true
	}
	for i, rs := range f.compiled[2:] {
		if (!item || f.item[i]) && pass(rs) {
			return true
		}
	}
	return false
}
