package server

import (
	"strings"
	"testing"
	"time"
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
