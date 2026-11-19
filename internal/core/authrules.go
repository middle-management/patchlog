package core

import (
	"fmt"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/rules"
)

var stepOneRefs = []string{"action", "resource", "principal", "now"}

// grantRules evaluates key-scope, block and role rules for a read. With
// stepOne, only rules that refer solely to action, resource, principal
// and now are evaluated.
//
// Their schema tests draw on the read check's budget of validationSteps,
// a fresh one unless the caller holds one for all the checks of its
// exchange or key request (readScope): running out fails the check as a
// rule that refuses does, so with the check's usual refusal (§6.6
// Validation work).
func (t *tx) grantRules(a *actor, verb string, roles []string, env map[string]any, stepOne bool) *Error {
	defer t.readScope()()
	return t.grantRulesMode(a, verb, roles, env, stepOne, nil, t.readMeter)
}

// readScope gives the read checks made until the function it returns is
// called one budget of validationSteps between them, as an exchange and
// a key request have for all the names they judge (§6.6 Validation work:
// "each read, exchange and key request a grant is presented for"). Inside
// another's scope it keeps that budget. Every other read check, a write's
// own included, is made outside any scope and gets a fresh budget
// (grantRules, readsNS, readRule).
func (t *tx) readScope() func() {
	if t.readMeter != nil {
		return func() {}
	}
	t.readMeter = &writeMeter{Meter: *rules.Budget(t.e.opt.MaxValidationSteps), read: true, t: t}
	return func() { t.readMeter = nil }
}

// readRule reports whether r passes against the read envelope env within
// the read check's budget (readScope): a rule whose schema tests run out
// of validationSteps doesn't, under a not either (§6.6 Validation work).
func (t *tx) readRule(r *rules.Rule, env map[string]any) bool {
	defer t.readScope()()
	return r.Passes(env, &t.readMeter.Meter)
}

// writeMeter counts the validation steps of one write against the
// deployment's validationSteps (§6.6 Validation work, §12.2): the steps of
// validating its resulting document (step 5, validateDoc) and of the
// schema tests of the rules evaluated for it, at step 1 and at step 6,
// together. A batch has one for each step of each item, as each is
// checked with its own envelope and document (§7.5); a config, branch or
// prune write, a purge, a registration and an upload have one each.
//
// readable reports whether the writer may read what the write results in:
// the refusal leaves measured out for one who can't (§6.6), and where it
// is nil.
type writeMeter struct {
	rules.Meter
	readable func() bool
	t        *tx
	// read: the meter is a read check's budget, not a write's (readScope).
	// Running out fails the check, as a rule that refuses does.
	read bool
	// stepOne is set while the write's step 1 draws on the meter
	// (authorize): running out there doesn't answer at once, since a check
	// that fails outright answers before it (§6.6 Validation work).
	stepOne bool
}

// newMeter is a meter for one write, at the deployment's limit.
func (t *tx) newMeter(readable func() bool) *writeMeter {
	return &writeMeter{Meter: *rules.Budget(t.e.opt.MaxValidationSteps), readable: readable, t: t}
}

// metered gives the write this transaction checks its meter, which the
// write's step-1 and step-6 rules draw on (authorize, checkGrantRules,
// checkRules), until the function it returns is called. A write that has
// one already keeps it.
func (t *tx) metered(readable func() bool) func() {
	if t.meter != nil {
		return func() {}
	}
	t.meter = t.newMeter(readable)
	return func() { t.meter = nil }
}

// rule is m as the rules package takes it, nil for no meter.
func (m *writeMeter) rule() *rules.Meter {
	if m == nil {
		return nil
	}
	return &m.Meter
}

// over is the refusal of a write whose steps ran out, nil if they haven't:
// 422 limit validationSteps at whatever stage, also where the rule that
// was being evaluated would have refused with 403 (§6.6).
func (m *writeMeter) over() *Error {
	if m == nil || !m.Over {
		return nil
	}
	err := limitErr(422, "validationSteps", int64(m.Steps), int64(m.Max), "validating the document against its schema and its rules' schema tests take too many steps together")
	if m.readable == nil || !m.readsWithin() {
		delete(err.Body, "measured")
	}
	return err
}

// deferred is over for a write whose step 1 has been through all its
// rules without one failing outright: the 422 that answers after the
// step's other checks and the rate limits (Error.ranOut), nil if the
// steps haven't run out.
func (m *writeMeter) deferred() *Error {
	err := m.over()
	if err != nil {
		err.ranOut = true
	}
	return err
}

// cut decides what a rule that evaluated to v means once the meter's
// steps have run out, for scopeRules and roleRules. stop is the refusal
// that answers at once: the write's 422 at steps 5 and 6, whatever the
// rule said (§6.6), and at step 1 the 403 of a rule that is False, which
// fails whatever the tests cut short would have said. Without one, at
// step 1, the rule is neither passed nor failed: the caller goes on to the
// rules left, any of which may still fail outright, and the run-out
// answers at the end (deferred). ok is false if the steps haven't run
// out, and v is to be read as usual.
func (m *writeMeter) cut(v rules.Tri) (stop *Error, ok bool) {
	if m == nil || !m.Over {
		return nil, false
	}
	if m.read {
		return errReadRanOut(), true
	}
	if !m.stepOne {
		return m.over(), true
	}
	if v == rules.False {
		return forbidden("a grant or key rule refuses the request"), true
	}
	return nil, true
}

// errReadRanOut is how a read check whose rules ran out of validationSteps
// fails: as one a rule refuses (§6.6 Validation work).
func errReadRanOut() *Error {
	return forbidden("the grant's rules take more than validationSteps steps for this read, which fails it (§6.6)")
}

// readsWithin is m.readable, each read check of which has a budget of its
// own, as every read check a write makes has (§6.6 Validation work): the
// grant whose rule just took too many steps on the write may take as many
// on the read envelope, and the refusal must not cost what it refuses. A
// check that runs out counts as can't read.
func (m *writeMeter) readsWithin() bool {
	t := m.t
	prev := t.readMeter
	t.readMeter = nil
	defer func() { t.readMeter = prev }()
	return m.readable()
}

// grantRulesMode is grantRules with the envelope members unknown names
// hidden, as a sealed write's writes and doc are at E3 (stepUnknown): a
// rule whose outcome depends on them fails as a whole, a key-scope or
// block rule refusing the request and a role with one not allowing it;
// one that passes, or fails, whatever they hold is decided as usual
// (§6.2, rules.EvalTri).
//
// The rules' schema tests draw on m, a write's meter or a read check's
// budget (readScope). Once a write's steps run out the answer is its 422,
// whatever the rule would have said (writeMeter.over); a read check
// fails, whatever role might still have passed. At step 1 (m.stepOne, authorize) that 422 waits:
// every rule is still evaluated, one that fails outright answers 403, and
// only if none does is the answer the run-out (writeMeter.deferred).
func (t *tx) grantRulesMode(a *actor, verb string, roles []string, env map[string]any, stepOne bool, unknown []string, m *writeMeter) *Error {
	if a.verified == nil {
		return nil
	}
	if err := t.scopeRules(a, env, stepOne, unknown, m); err != nil {
		return err
	}
	if err := t.roleRules(a, verb, roles, env, stepOne, unknown, m); err != nil {
		return err
	}
	if m != nil && m.stepOne {
		// No rule of step 1 failed outright: if its steps ran out, that
		// answers, after the rate limits.
		return m.deferred()
	}
	return nil
}

// scopeRules evaluates the key-scope and block rules of a's verified
// grant, as grantRulesMode does.
func (t *tx) scopeRules(a *actor, env map[string]any, stepOne bool, unknown []string, m *writeMeter) *Error {
	if m != nil && m.read && m.Over {
		// The budget its exchange or key request shares is spent.
		return errReadRanOut()
	}
	for _, src := range [][]any{a.verified.KeyRules, a.verified.BlockRules} {
		for _, rv := range src {
			r, err := compileCached(rv)
			if err != nil {
				return forbidden("invalid grant rule")
			}
			if forRead(env) && refersToNow(r) {
				// It fails as a whole for a read, branching's check
				// included (§C.2 item 5, Unrestricted read).
				return forbidden("a grant or key rule refers to /now, which no read passes (§C.2 item 5): a read's time window is its grant's nbf and exp")
			}
			if stepOne && !r.OnlyRefs(stepOneRefs...) {
				continue
			}
			v := r.EvalMetered(env, m.rule(), unknown...)
			if stop, cut := m.cut(v); stop != nil {
				return stop
			} else if cut {
				continue
			}
			switch v {
			case rules.Unknown:
				return forbidden("the outcome of a grant or key rule depends on writes or /doc, which the server can't see for this write in an e2e namespace (§6.2, §E.3.2)")
			case rules.False:
				return forbidden("a grant or key rule refuses the request")
			}
		}
	}
	return nil
}

// forRead reports whether env is a read envelope (§6.4.1), which has no
// now: wherever rules are evaluated for a read, one that refers to /now,
// at any depth, fails as a whole (§C.2 item 5). Dropping the member alone
// isn't enough, since a not or an any around a missing /now would pass.
func forRead(env map[string]any) bool { return env["action"] == "read" }

// refersToNow reports whether r refers to /now: it, or a rule nested in
// it, tests or compares /now, a path below it, or the whole envelope,
// which refers to every pointer (§2.1 Refers to).
func refersToNow(r *rules.Rule) bool {
	refs := r.Refs()
	return refs["now"] || refs["*"]
}

// rulesReferToNow reports whether a rule of rs refers to /now or to the
// whole envelope (refersToNow). A rule that doesn't compile counts: it
// refuses every read anyway.
func rulesReferToNow(rs []any) bool {
	for _, rv := range rs {
		r, err := compileCached(rv)
		if err != nil || refersToNow(r) {
			return true
		}
	}
	return false
}

// scopeReferToNow reports whether a rule of a's blocks or key scope refers
// to /now (rulesReferToNow): such a grant is refused every read (§C.2
// item 5), and is no partial reader (§B.11.9).
func scopeReferToNow(a *actor) bool {
	return a.verified != nil && (rulesReferToNow(a.verified.KeyRules) || rulesReferToNow(a.verified.BlockRules))
}

// readRoles are the effective roles of a's grant that count for read: those
// that list read and have no rule referring to /now (§C.2 item 5). ok
// reports whether the grant allows read through them, roles nil for a
// grant without roles.
func readRoles(a *actor) (roles []string, ok bool) {
	v := a.verified
	ok, all := v.Allows("read")
	if !ok || !v.HasRoles() {
		return nil, ok
	}
	for _, r := range all {
		if !rulesReferToNow(v.RoleRules(r)) {
			roles = append(roles, r)
		}
	}
	return roles, len(roles) > 0
}

// roleRules evaluates the role rules of a's verified grant, if it carries
// roles, as grantRulesMode does: roles are alternatives (§C.1.1), so the
// rules evaluated must pass for one of roles, or with roles nil for one of
// the effective roles that list verb.
func (t *tx) roleRules(a *actor, verb string, roles []string, env map[string]any, stepOne bool, unknown []string, m *writeMeter) *Error {
	if m != nil && m.read && m.Over {
		return errReadRanOut()
	}
	if a.verified.HasRoles() {
		if roles == nil {
			_, roles = a.verified.Allows(verb)
		}
		passed := false
		for _, role := range roles {
			ok := true
			for _, rv := range a.verified.RoleRules(role) {
				r, err := compileCached(rv)
				if err != nil || forRead(env) && refersToNow(r) {
					// A role with a rule on /now doesn't count for read
					// (§C.2 item 5).
					ok = false
					break
				}
				if stepOne && !r.OnlyRefs(stepOneRefs...) {
					continue
				}
				v := r.EvalMetered(env, m.rule(), unknown...)
				if stop, cut := m.cut(v); cut {
					if m.read || !m.stepOne {
						// Not a role that doesn't pass: the steps of the
						// write, or of the read check, ran out, which no
						// other role makes up for.
						return stop
					}
					if v == rules.False {
						// At step 1 the role fails outright.
						ok = false
						break
					}
					// The role may have passed: the request doesn't fail
					// outright, and its run-out answers (grantRulesMode).
					continue
				}
				if v != rules.True {
					ok = false
					break
				}
			}
			if ok {
				passed = true
				break
			}
		}
		if !passed {
			return forbidden("no role allows the request")
		}
	}
	return nil
}

// checkRules is the rules of step 6 of §6.2 for one write, after the
// *-key guard and a config write's in_use refusals, which its callers run:
// grant, key and role rules (403), then namespace rules (422) (§6.4.3,
// §C.2 item 4). A batch runs each half for every item before the next
// (checkItems).
func (t *tx) checkRules(cfg *Config, a *actor, env map[string]any, isConfig bool) *Error {
	// Never without a meter: no rule's schema test is unbounded (§6.6).
	defer t.metered(nil)()
	if err := t.checkGrantRules(a, env, nil); err != nil {
		return err
	}
	return checkNSRules(cfg, a, env, isConfig, nil, t.meter)
}

// checkGrantRules is step 6's grant, key and role rules, all of them,
// against the full envelope with the write's verb (§C.2 item 4): 403. The
// envelope members unknown names are hidden (grantRulesMode). Their schema
// tests draw on the write's meter (t.meter).
func (t *tx) checkGrantRules(a *actor, env map[string]any, unknown []string) *Error {
	defer t.metered(nil)()
	verb := env["action"].(string)
	if a.verified != nil {
		if ok, _ := a.verified.Allows(verb); !ok {
			return forbidden(fmt.Sprintf("the grant does not allow %s", verb))
		}
	}
	return t.grantRulesMode(a, verb, nil, env, false, unknown, t.meter)
}

// checkCreationRules is step 6 of a namespace's creation under the
// operator grant that creates it, a remote branch's included, once the
// genesis has been validated (§6.2 step 4, §7.4, §G.3). That grant passes
// the *-key guard (§C.2), a creation has no in_use refusals, and namespace
// rules don't judge it (§6.4.3), but its own key-scope and block rules all
// do, those that read /doc, /writes or /patches included, against the
// config envelope of the genesis patches (§C.2 item 4, §6.4.1): 403.
func (t *tx) checkCreationRules(a *actor, patches any) *Error {
	if a.verified == nil {
		return nil
	}
	// A remote branch's creation comes here in a later transaction than
	// its step 1, with a meter of its own.
	defer t.metered(func() bool { return true })()
	ops, err := patch.Parse(patches)
	if err != nil {
		return patchErr(err)
	}
	doc, w, err := patch.Apply(nil, false, ops, patch.Options{})
	if err != nil {
		return patchErr(err)
	}
	env := t.basicEnvelope("config", "", a)
	env["writes"] = anyStrings(patch.WritesStrings(w))
	env["doc"] = doc
	env["patches"] = jsonv.MustParse(jsonv.Canonical(patches))
	return t.checkGrantRules(a, env, nil)
}

// checkNSRules is step 6's namespace rules in cfg, the configuration in
// force (§6.4.3): the first that fails is 422 rule, with its index and the
// path of the failing rule form. With the envelope members unknown names
// hidden, a rule whose outcome depends on them fails as a whole, at its
// own path /rules/{i} (§6.2). A config write under a * key, so any while
// authentication is disabled, isn't judged by them (§1, §6.4.3); nor is a
// namespace's creation under the operator grant, whose step 6 runs only
// its grant and key rules (checkCreationRules). Their schema tests draw on
// m, the write's meter (writeMeter).
func checkNSRules(cfg *Config, a *actor, env map[string]any, isConfig bool, unknown []string, m *writeMeter) *Error {
	if isConfig && a.star {
		return nil
	}
	i, path, v := rules.EvalMetered(cfg.Rules, env, m.rule(), unknown...)
	if err := m.over(); err != nil {
		return err
	}
	switch v {
	case rules.False:
		return apiErr(422, "rule", "rule", i, "path", path)
	case rules.Unknown:
		return apiErr(422, "rule", "rule", i, "path", path, "message", blindMsg)
	}
	return nil
}
