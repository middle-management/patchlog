package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// P16: config writes, namespace and branch creation (§6.2, §7.4, §7.6,
// §C.2, §C.4, Addendum E Levels).

// expectInvalidAt checks a 422 invalid whose errors point at ptr (§7.4
// Validation, Errors; branch fields).
func expectInvalidAt(t *testing.T, r *resp, ptr string) {
	t.Helper()
	expectCode(t, r, 422, "invalid")
	errs, _ := r.Obj()["errors"].([]any)
	if len(errs) == 0 {
		t.Fatalf("no errors: %s", r.Body)
	}
	if e, _ := errs[0].(map[string]any); e["pointer"] != ptr {
		t.Fatalf("pointer %v, want %q: %s", e["pointer"], ptr, r.Body)
	}
}

// v0.73 §6.2 step 4, §C.2 "* keys" (GB-3, BBD-8): the namespace document a
// config write produces is validated as §7.4 says before the *-key guard
// (403), whose own place is step 6, and the branch fields' refusals are 422
// invalid with errors pointing at the member.
func TestV073P16ConfigValidationBeforeGuard(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, ck := newKey("sk"), newKey("ck")
	e.mkNS("cv", map[string]any{"read": "grant", "keys": []any{sk.entry("*"), ck.entry("config", "read", "branch")}})
	sg := e.grant(sk, "user:admin", []string{"cv", "cvb"}, allVerbs)
	cg := e.grant(ck, "user:cfg", []string{"cv", "cvb"}, []string{"config", "read", "branch"})
	newEntry := newKey("nk").entry("read")

	// A guarded member (/keys) with an invalid successor, or a base: 422,
	// not 403.
	expectInvalidAt(t, e.patchNS("cv", ops(op("add", "/keys/-", newEntry), op("add", "/successor", "nope")), cg), "/successor")
	expectInvalidAt(t, e.patchNS("cv", ops(op("add", "/keys/-", newEntry), op("add", "/base", map[string]any{"ns": "cv", "at": e.nsHead("cv", sg)})), cg), "/base")
	// Otherwise valid, the guard refuses it.
	expectCode(t, e.patchNS("cv", ops(op("add", "/keys/-", newEntry)), cg), 403, "forbidden")

	// A branch of a non-public base set public: a branch field, 422 at
	// /read, before the guard that setting read to public meets.
	expect(t, e.branch("cv", map[string]any{"name": "cvb"}, sg), 201)
	expectInvalidAt(t, e.patchNS("cvb", ops(op("replace", "/read", "public")), cg), "/read")
	expectInvalidAt(t, e.patchNS("cvb", ops(op("replace", "/read", "public")), sg), "/read")
	// Removing a base's * key: 422 at /keys, with errors.
	expectInvalidAt(t, e.patchNS("cvb", ops(op("remove", "/keys/0")), sg), "/keys")
}

// v0.73 §6.2 step 4: the patch-set and document limits come after the
// namespace document is validated as §7.4 says (GB-3).
func TestV073P16ConfigValidationBeforeLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("lim", map[string]any{"read": "public", "limits": map[string]any{"valueSize": 1024, "pathSize": 256, "patchSetSize": 5000}})
	var big []any
	for i := 0; i < 8; i++ {
		big = append(big, op("add", "/x-"+string(rune('a'+i)), strings.Repeat("x", 900)))
	}
	expectLimit(t, e.patchNS("lim", big, ""), 422, "patchSetSize", -1, 5000)
	withBase := append(append([]any{}, big...), op("add", "/base", map[string]any{"ns": "lim", "at": e.nsHead("lim")}))
	expectInvalidAt(t, e.patchNS("lim", withBase, ""), "/base")
}

// v0.73 §6.2 step 6: the *-key guard comes before a config write's in_use
// refusals (§7.4 dependents).
func TestV073P16GuardBeforeInUse(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, ck := newKey("sk"), newKey("ck")
	e.mkNS("pm", map[string]any{"read": "public", "keys": []any{sk.entry("*"), ck.entry("config", "read", "branch")}})
	sg := e.grant(sk, "user:admin", []string{"pm", "pb"}, allVerbs)
	cg := e.grant(ck, "user:cfg", []string{"pm", "pb"}, []string{"config", "read", "branch"})
	expect(t, e.branch("pm", map[string]any{"name": "pb"}, sg), 201)
	// read: grant alone needs no * key, and is in_use while pb is public.
	expectCode(t, e.patchNS("pm", ops(op("replace", "/read", "grant")), cg), 409, "in_use")
	expectCode(t, e.patchNS("pm", ops(op("replace", "/read", "grant"), op("add", "/signatures", "optional")), cg), 403, "forbidden")
	expectCode(t, e.patchNS("pm", ops(op("replace", "/read", "grant"), op("add", "/signatures", "optional")), sg), 409, "in_use")
}

// v0.73 §7.4 Branch fields, §8.4 (RH-54): only a write that sets or
// changes successor is checked; it names another namespace that exists and
// isn't purged, for a branch a branch of the same base or of a namespace
// further up its base chain, for a namespace that isn't a branch one that
// isn't either.
func TestV073P16Successor(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	e.mkNS("other", map[string]any{"read": "public"})
	for _, b := range []struct{ base, name string }{{"main", "rel"}, {"rel", "feat"}, {"main", "s1"}, {"rel", "s2"}, {"main", "dead"}, {"other", "ob"}} {
		expect(t, e.branch(b.base, map[string]any{"name": b.name}, "alice"), 201)
	}
	purgeNS := func(ns string) {
		t.Helper()
		expect(t, e.patchNS(ns, ops(op("add", "/frozen", true)), ""), 201)
		expect(t, e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns), author: "admin"}), 204)
	}
	purgeNS("dead")
	succ := func(ns, s string) *resp { return e.patchNS(ns, ops(op("add", "/successor", s)), "") }

	expectInvalidAt(t, succ("main", "main"), "/successor")  // itself
	expectInvalidAt(t, succ("main", "nope"), "/successor")  // doesn't exist
	expectInvalidAt(t, succ("main", "rel"), "/successor")   // a branch, for a namespace that isn't one
	expectInvalidAt(t, succ("feat", "other"), "/successor") // not a branch, for a branch
	expectInvalidAt(t, succ("feat", "ob"), "/successor")    // a branch of another base
	expectInvalidAt(t, succ("feat", "dead"), "/successor")  // purged
	expectInvalidAt(t, succ("feat", "feat"), "/successor")
	// A branch of a namespace further up feat's base chain (§F.4, §F.5).
	expect(t, succ("feat", "s1"), 201)
	expect(t, succ("main", "other"), 201)
	// A branch of the same base; once it is purged, writes that keep the
	// successor aren't checked, and one that changes it is.
	expect(t, e.patchNS("feat", ops(op("replace", "/successor", "s2")), ""), 201)
	purgeNS("s2")
	expect(t, e.patchNS("feat", ops(op("add", "/x-note", "kept")), ""), 201)
	expectInvalidAt(t, e.patchNS("feat", ops(op("replace", "/successor", "dead")), ""), "/successor")
	expect(t, e.patchNS("feat", ops(op("remove", "/successor")), ""), 201)
}

// v0.73 §E.2.1, §12.3: a namespace becoming sealed, which has no epoch
// keys yet, may start at any epoch; one already sealed moves by one, and
// the refusal is 422 invalid with errors pointing at the epoch.
func TestV073P16EpochBecomingSealed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	e.mkNS("er", atRest(map[string]any{"read": "grant"}))
	expect(t, e.patchNS("er", ops(op("replace", "/encryption", map[string]any{"level": "sealed", "epoch": 3.0})), ""), 201)
	expect(t, e.patchNS("er", ops(op("replace", "/encryption/epoch", 4.0)), ""), 201)
	expectInvalidAt(t, e.patchNS("er", ops(op("replace", "/encryption/epoch", 6.0)), ""), "/encryption/epoch")
	expectInvalidAt(t, e.patchNS("er", ops(op("replace", "/encryption", map[string]any{"level": "at-rest"})), ""), "/encryption")
}

// operatorGrantCan mints an operator grant for ns with verbs can (§C.4).
func (e *tenv) operatorGrantCan(ns string, can ...string) string {
	return mint(e.t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": strs(can), "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
}

// v0.73 §7.4 Namespace writes (RH-53): a creation (If-None-Match: *) under
// a taken name, a purged namespace's included, is 412 stale without config;
// an If-Match that doesn't match keeps { config }.
func TestV073P16TakenNameWithoutConfig(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	cfg := e.mkNS("tk", map[string]any{"read": "public"})
	noConfig := func(r *resp) {
		t.Helper()
		expectCode(t, r, 412, "stale")
		if _, has := r.Obj()["config"]; has {
			t.Fatalf("config in a taken name's 412: %s", r.Body)
		}
	}
	create := req{method: "PATCH", path: "/ns/tk", ifNoneMatch: "*", body: addRoot(map[string]any{"read": "public"}), author: "admin"}
	noConfig(e.do(create))
	r := e.do(req{method: "PATCH", path: "/ns/tk", ifMatch: hashID(t, "", []byte("x")), body: ops(op("add", "/x-a", 1.0)), author: "admin"})
	expectCode(t, r, 412, "stale")
	if r.Str("config") != cfg {
		t.Fatalf("If-Match mismatch: config %q, want %q: %s", r.Str("config"), cfg, r.Body)
	}
	expect(t, e.patchNS("tk", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/tk/purge", ifMatch: e.nsHead("tk"), author: "admin"}), 204)
	noConfig(e.do(create))
}

// v0.73 §C.2 item 2, §C.4 (GR-22): an operator grant checks config for a
// namespace's creation, and for the 412 of a taken name; without it 403.
func TestV073P16OperatorGrantNeedsConfig(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	create := func(ns, bearer string) *resp {
		return e.do(req{method: "PATCH", path: "/ns/" + ns, ifNoneMatch: "*", body: addRoot(map[string]any{"read": "public"}), bearer: bearer})
	}
	expectCode(t, create("og", e.operatorGrantCan("og", "read")), 403, "forbidden")
	expectCode(t, create("og", e.operatorGrantCan("og", "purge")), 403, "forbidden")
	expect(t, create("og", e.operatorGrantCan("og", "config")), 201)
	expectCode(t, create("og", e.operatorGrantCan("og", "read")), 403, "forbidden")
	expectCode(t, create("og", e.operatorGrantCan("og", "config")), 412, "stale")
}

// v0.73 §7.2, §7.4 (GR-21): a config write's idempotent retry needs the
// same principal, the same root sub and kid; the same sub under another key
// gets 412.
func TestV073P16ConfigRetrySameKid(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k1, k2 := newKey("k1"), newKey("k2")
	e.mkNS("cr", map[string]any{"read": "grant", "keys": []any{k1.entry("*"), k2.entry("*")}})
	g1 := e.grant(k1, "user:ann", []string{"cr"}, allVerbs)
	g2 := e.grant(k2, "user:ann", []string{"cr"}, allVerbs)
	g1b := e.grant(k1, "user:ann", []string{"cr"}, []string{"config", "read"})
	parent := e.configID("cr", g1)
	write := func(bearer string) *resp {
		return e.do(req{method: "PATCH", path: "/ns/cr", ifMatch: parent, body: ops(op("add", "/x-a", 1.0)), bearer: bearer})
	}
	r := write(g1)
	expect(t, r, 201)
	nsID := r.Str("ns_id")
	expectCode(t, write(g2), 412, "stale")
	// Another grant from the same key and sub is the same principal.
	r = write(g1b)
	expect(t, r, 200)
	if r.Str("ns_id") != nsID {
		t.Fatalf("retry ns_id %q, want %q", r.Str("ns_id"), nsID)
	}
}

// v0.73 §7.6 Result (BBD-2, BBD-3, GR-21): a retry of a local branch's
// creation by the same principal (the same root sub and kid) with the same
// at and patches gets 200 with the recorded entry; an omitted at counts as
// the at recorded for the branch, and config writes to the base since the
// creation don't matter.
func TestV073P16BranchRetry(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k1, k2 := newKey("k1"), newKey("k2")
	e.mkNS("main", map[string]any{"read": "grant", "x-title": "Main", "keys": []any{k1.entry("*"), k2.entry("*")}})
	ns := []string{"main", "b1", "b2"}
	g1, g2 := e.grant(k1, "user:ann", ns, allVerbs), e.grant(k2, "user:ann", ns, allVerbs)
	g1b := e.grant(k1, "user:ann", ns, []string{"branch", "read"})

	at1 := e.nsHead("main", g1) // the head as the branch entry is inserted
	r := e.branch("main", map[string]any{"name": "b1"}, g1)
	expect(t, r, 201)
	nsID1 := r.Str("ns_id")
	e.create("main", "doc", map[string]any{"v": 1.0}, g1)
	for _, body := range []map[string]any{{"name": "b1"}, {"name": "b1", "at": at1}, {"name": "b1", "patches": []any{}}} {
		r = e.branch("main", body, g1b)
		expect(t, r, 200)
		if r.Str("ns_id") != nsID1 {
			t.Fatalf("retry %v: ns_id %q, want %q", body, r.Str("ns_id"), nsID1)
		}
	}
	// The same sub under another key isn't the same principal.
	expectCode(t, e.branch("main", map[string]any{"name": "b1", "at": at1}, g2), 412, "stale")
	expectCode(t, e.branch("main", map[string]any{"name": "b1", "at": e.nsHead("main", g1)}, g1), 412, "stale")

	patches := ops(op("add", "/x-note", "b2"))
	r = e.branch("main", map[string]any{"name": "b2", "at": at1, "patches": patches}, g1)
	expect(t, r, 201)
	nsID2 := r.Str("ns_id")
	expect(t, e.patchNS("main", ops(op("replace", "/x-title", "Main 2")), g1), 201)
	r = e.branch("main", map[string]any{"name": "b2", "at": at1, "patches": patches}, g1)
	expect(t, r, 200)
	if r.Str("ns_id") != nsID2 {
		t.Fatalf("retry after a base config write: ns_id %q, want %q", r.Str("ns_id"), nsID2)
	}
	expectCode(t, e.branch("main", map[string]any{"name": "b2", "at": at1, "patches": ops(op("add", "/x-note", "other"))}, g1), 412, "stale")
}

// v0.73 §6.2, §7.6 (BBD-5, BBD-4, BBD-1): a taken name is 412, with no head
// or config, before an at outside the base's chain is 422, a purged
// branch's name included, its creator's retry too; If-Match alone is 428,
// never a retry.
func TestV073P16BranchTakenName(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	e.mkNS("other", map[string]any{"read": "public", "x-title": "Other"})
	notInChain := e.nsHead("other")
	expect(t, e.branch("main", map[string]any{"name": "tb"}, "alice"), 201)
	at := e.nsHead("main")
	taken := func(r *resp) {
		t.Helper()
		expectCode(t, r, 412, "stale")
		for _, k := range []string{"head", "config"} {
			if _, has := r.Obj()[k]; has {
				t.Fatalf("%s in a taken name's 412: %s", k, r.Body)
			}
		}
	}
	taken(e.branch("main", map[string]any{"name": "tb", "at": notInChain}, "alice"))
	taken(e.branch("main", map[string]any{"name": "tb", "patches": ops(op("add", "/x-a", 1.0))}, "alice"))
	expectInvalidAt(t, e.branch("main", map[string]any{"name": "fresh", "at": notInChain}, "alice"), "/base/at")
	// If-Match alone: 428, for the creator's exact retry too.
	r := e.do(req{method: "POST", path: "/ns/main/branches", ifMatch: at, body: map[string]any{"name": "tb"}, author: "alice"})
	expectCode(t, r, 428, "precondition_required")
	// After the branch is purged, its name stays taken, for its creator too.
	expect(t, e.patchNS("tb", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/tb/purge", ifMatch: e.nsHead("tb"), author: "admin"}), 204)
	taken(e.branch("main", map[string]any{"name": "tb"}, "alice"))
}

// v0.73 §7.6 Configuration (BBD-7, MF-14): cleanup is removed from a local
// branch's starting document, with frozen, successor, merged, abandoned,
// drafts and schemaReads; patches may set it.
func TestV073P16BranchDropsCleanup(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public", "cleanup": map[string]any{"merged": "P7D"}, "abandoned": true})
	expect(t, e.branch("main", map[string]any{"name": "c1"}, "alice"), 201)
	d := e.nsDoc("c1")
	for _, k := range []string{"cleanup", "abandoned"} {
		if _, has := d[k]; has {
			t.Fatalf("%s inherited: %v", k, d)
		}
	}
	expect(t, e.branch("main", map[string]any{"name": "c2", "patches": ops(op("add", "/cleanup", map[string]any{"merged": "P1D"}))}, "alice"), 201)
	if c, _ := e.nsDoc("c2")["cleanup"].(map[string]any); c["merged"] != "P1D" {
		t.Fatalf("cleanup set by patches: %v", e.nsDoc("c2"))
	}
}

// v0.73 §7.4 Branch fields, Addendum E Levels (BBD-8, ENC-49): a branch's
// creation that breaks a branch field is 422 invalid with errors pointing
// at the member, before the *-key guard of its patches.
func TestV073P16BranchFieldsBeforeGuard(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, bk := newKey("sk"), newKey("bk")
	e.mkNS("pv", map[string]any{"read": "grant", "nonce": "required", "keys": []any{sk.entry("*"), bk.entry("branch", "read")}})
	bg := e.grant(bk, "user:brancher", []string{"pv", "nb"}, []string{"branch", "read"})
	sg := e.grant(sk, "user:admin", []string{"pv", "nb"}, allVerbs)
	for _, c := range []struct {
		ptr     string
		patches []any
	}{
		{"/read", ops(op("replace", "/read", "public"), op("add", "/signatures", "optional"))},
		{"/nonce", ops(op("replace", "/nonce", "optional"))},
		{"/keys", ops(op("remove", "/keys/0"))},
		{"/successor", ops(op("add", "/successor", "nope"), op("add", "/signatures", "optional"))},
		{"/base", ops(op("replace", "/base/ns", "other"), op("add", "/signatures", "optional"))},
	} {
		expectInvalidAt(t, e.branch("pv", map[string]any{"name": "nb", "patches": c.patches}, bg), c.ptr)
	}
	// Valid otherwise, the guarded member needs a * key of the base.
	expectCode(t, e.branch("pv", map[string]any{"name": "nb", "patches": ops(op("add", "/signatures", "optional"))}, bg), 403, "forbidden")
	expect(t, e.branch("pv", map[string]any{"name": "nb", "patches": ops(op("add", "/signatures", "optional"))}, sg), 201)
	// A successor at creation names a branch of the base or further up.
	expect(t, e.branch("pv", map[string]any{"name": "nb2", "patches": ops(op("add", "/successor", "nb"))}, sg), 201)
}

// v0.73 §6.2 step 4 (GB-3 for branches): a branch's creation validates its
// document before the limits.
func TestV073P16BranchValidationBeforeLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("lb", map[string]any{"read": "grant", "limits": map[string]any{"branchesPerNamespace": 1}})
	expect(t, e.branch("lb", map[string]any{"name": "l1"}, "alice"), 201)
	expectLimit(t, e.branch("lb", map[string]any{"name": "l2"}, "alice"), 422, "branchesPerNamespace", 2, 1)
	expectInvalidAt(t, e.branch("lb", map[string]any{"name": "l2", "patches": ops(op("replace", "/read", "public"))}, "alice"), "/read")
}

// v0.73 §7.6 First write (BBD-13): a first write to a read-through
// resource whose base revision is pruned, as in a branch created at an at
// older than the base's horizon, is 410 pruned once its precondition
// passes.
func TestV073P16FirstWriteBelowBaseHorizon(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withArchive(t, t.TempDir()), withoutRetentionLoop)
	e.mkNS("main", map[string]any{"read": "public"})
	a0 := e.create("main", "a", map[string]any{"n": 0.0})
	at := e.nsHead("main")
	a1 := e.appendRev("main", "a", a0, ops(op("replace", "/n", 1.0)))
	a2 := e.appendRev("main", "a", a1, ops(op("replace", "/n", 2.0)))
	e.clock.Advance(time.Hour)
	expect(t, e.prune("main", "a", map[string]any{"horizon": a2}, "admin"), 200)
	expect(t, e.branch("main", map[string]any{"name": "late", "at": at}, "alice"), 201)
	expectCode(t, e.write("PATCH", "late", "a", a0, ops(op("replace", "/n", 9.0))), 410, "pruned")
	expectCode(t, e.write("DELETE", "late", "a", a0, nil), 410, "pruned")
	// The precondition comes first.
	expectCode(t, e.write("PATCH", "late", "a", a1, ops(op("replace", "/n", 9.0))), 412, "stale")
}

// v0.73 Addendum E Levels, §7.4 (ENC-49): a branch's creation below its
// base's level is 422 invalid at /encryption, as a branch field, before the
// *-key guard its patches to /encryption meet.
func TestV073P16BranchLevelBeforeGuard(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	sk, bk := newKey("sk"), newKey("bk")
	e.mkNS("sv", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}, "keys": []any{sk.entry("*"), bk.entry("branch", "read")}})
	bg := e.grant(bk, "user:brancher", []string{"sv", "lv"}, []string{"branch", "read"})
	sg := e.grant(sk, "user:admin", []string{"sv", "lv"}, allVerbs)
	lower := ops(op("replace", "/encryption", map[string]any{"level": "at-rest"}))
	expectInvalidAt(t, e.branch("sv", map[string]any{"name": "lv", "patches": lower}, bg), "/encryption")
	expectInvalidAt(t, e.branch("sv", map[string]any{"name": "lv", "patches": lower}, sg), "/encryption")
	expectCode(t, e.branch("sv", map[string]any{"name": "lv", "patches": ops(op("add", "/encryption/pad", true))}, bg), 403, "forbidden")
	expect(t, e.branch("sv", map[string]any{"name": "lv"}, bg), 201)
}

// v0.73 §7.4 Branch fields, §7.6, §C.4 keys follow the base: a config
// write to a branch keeps the entries its document holds that are * keys of
// a base; a * key a base adds after the branch was created is in no branch
// document, so a write that leaves it out, a branch's creation from a
// branch included, removes nothing. An entry the branch holds without *
// stays as it is when the base makes it a * key, and can't be removed.
func TestV073P16BranchKeepsHeldStarKeysOnly(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k1, k2, rk := newKey("k1"), newKey("k2"), newKey("rk")
	e.mkNS("main", map[string]any{"read": "grant", "keys": []any{k1.entry("*"), rk.entry("read")}})
	g1 := e.grant(k1, "user:admin", []string{"main", "b", "c", "d"}, allVerbs)
	expect(t, e.branch("main", map[string]any{"name": "b"}, g1), 201)
	expect(t, e.patchNS("main", ops(op("add", "/keys/-", k2.entry("*")), op("replace", "/keys/1/can", []any{"*"})), g1), 201)
	expect(t, e.patchNS("b", ops(op("add", "/x-note", "unrelated")), g1), 201)
	expect(t, e.branch("b", map[string]any{"name": "c"}, g1), 201)
	// The copies the branches hold stay protected.
	for _, ns := range []string{"b", "c"} {
		expectInvalidAt(t, e.patchNS(ns, ops(op("remove", "/keys/0")), g1), "/keys")
		expectInvalidAt(t, e.patchNS(ns, ops(op("replace", "/keys/0/can", []any{"read"})), g1), "/keys")
		expectInvalidAt(t, e.patchNS(ns, ops(op("remove", "/keys/1")), g1), "/keys")
	}
	expectInvalidAt(t, e.branch("b", map[string]any{"name": "d", "patches": ops(op("remove", "/keys/0"))}, g1), "/keys")
}

// v0.73 §E.2.1 rotation, §C.4 revocation in bases: when a base replaces its
// * key, its sealed branches rotate with it (rotate-on-revoke), and a
// branch's scheduled rotation still passes: neither config write needs the
// base's new * key in the branch's document (§7.4).
func TestV073P16BranchRotatesAfterBaseStarKeyChange(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t, func(o *core.Options) { o.RotateOnRevoke = true })
	k1, k2 := newKey("k1"), newKey("k2")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k1.entry("*")}}))
	can := []string{"config", "read", "branch"}
	g1, g2 := e.grant(k1, "user:admin", []string{"s", "sb"}, can), e.grant(k2, "user:admin", []string{"s", "sb"}, can)
	expect(t, e.branch("s", map[string]any{"name": "sb"}, g1), 201)
	latest := func(ns, bearer string) int {
		t.Helper()
		keys, r := e.keysOf(ns, nil, bearer)
		if keys == nil {
			t.Fatalf("keys of %s: %d %s", ns, r.Code, r.Body)
		}
		ep := 0
		for kid := range keys {
			if _, n, _ := seal.ParseKid(kid); n > ep {
				ep = n
			}
		}
		return ep
	}
	if got := latest("sb", g1); got != 1 {
		t.Fatalf("sb starts at epoch %d", got)
	}
	expect(t, e.patchNS("s", ops(op("add", "/keys/-", k2.entry("*")), op("remove", "/keys/0")), g1), 201)
	if got := latest("s", g2); got != 2 {
		t.Fatalf("base epoch %d after revoking k1, want 2", got)
	}
	if got := latest("sb", g2); got != 2 {
		t.Fatalf("branch epoch %d after its base revoked k1, want 2", got)
	}
	if ep, err := e.e.RotateEpoch(context.Background(), "sb", core.RotateAuthor); err != nil || ep != 3 {
		t.Fatalf("RotateEpoch(sb): epoch %d, %v; want 3", ep, err)
	}
}
