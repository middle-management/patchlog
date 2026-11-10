package server

import (
	"crypto/ecdh"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// V81-02 (v0.78, v0.81): a rule referring to /now never passes for a
// read (§C.2 item 5); filtered reads cover no branch (§B.11.9 Where); the
// first namespace entry's prev is "" (§7.4).

// v081NowEnv is a private namespace dl with a * key k and a key dk whose
// scope rules are rules, and a document x.
func v081NowEnv(t *testing.T, rules []any) (e *tenv, admin, g string) {
	t.Helper()
	e = newAuthEnv(t)
	k, dk := newKey("k"), newKey("dk")
	dkEntry := dk.entry("read", "append", "branch")
	dkEntry["rules"] = rules
	e.mkNS("dl", map[string]any{"read": "grant", "keys": []any{k.entry("*"), dkEntry}})
	admin = e.grant(k, "user:root", []string{"dl", "dl-b"}, allVerbs)
	e.create("dl", "x", map[string]any{"n": 0.0}, admin)
	return e, admin, e.grant(dk, "user:d", []string{"dl", "dl-b"}, []string{"read", "append", "branch"},
		map[string]any{"exp": e.clock.Now().Add(24 * time.Hour).Format(time.RFC3339)})
}

// Grant scope 67 (§C.2 Unrestricted read, items 4 and 5): a key whose
// scope holds only a deadline on /now signs a grant with read, append and
// branch. Before the deadline, the grant reads nothing (404 at a resource
// URL, 403 at the namespace's), can't branch, and still appends; after
// it, the append is 403 as before. So does a rule that negates a /now
// comparison, which a read envelope merely lacking now would pass.
func TestV081AccessNowDeadline(t *testing.T) {
	t.Parallel()
	deadline := t0.Add(time.Hour).Format(time.RFC3339)
	for name, rule := range map[string]any{
		"lt deadline":     map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": deadline}},
		"not gt deadline": map[string]any{"not": map[string]any{"op": "compare", "path": "/now", "gt": map[string]any{"value": deadline}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, admin, g := v081NowEnv(t, []any{rule})
			head := e.nsHead("dl", admin)
			expect(t, e.get("/r/dl/x", g), 404)
			expect(t, e.get("/ns/dl/log", g), 403)
			expect(t, e.get("/ns/dl/rev/"+head+"/log", g), 403)
			expect(t, e.get("/ns/dl/rev/"+head+"/heads", g), 403)
			expect(t, e.do(req{method: "POST", path: "/ns/dl/branches", ifNoneMatch: "*", bearer: g,
				body: map[string]any{"name": "dl-b", "at": head, "patches": []any{}}}), 403)
			x := e.head("dl", "x", admin)
			x = e.appendRev("dl", "x", x, ops(op("replace", "/n", 1.0)), g)
			e.clock.Advance(2 * time.Hour)
			expect(t, e.write("PATCH", "dl", "x", x, ops(op("replace", "/n", 2.0)), g), 403)
		})
	}
}

// Grant scope 2 (§C.2 item 5, §2.1): roles B (an office-hours rule on
// /now, no /resource rule) and A (not /resource = "secret"), in hours or
// out: the namespace log is 403. B never counts for read, and A's
// /resource rule keeps it from counting where unrestricted read is needed.
// A alone still reads x.
func TestV081AccessNowOfficeHoursRole(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k, rk := newKey("k"), newKey("rk")
	hours := map[string]any{"all": []any{
		map[string]any{"op": "compare", "path": "/now", "gt": map[string]any{"value": t0.Add(-time.Hour).Format(time.RFC3339)}},
		map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": t0.Add(time.Hour).Format(time.RFC3339)}},
	}}
	e.mkNS("oh", map[string]any{"read": "grant", "keys": []any{k.entry("*"), rk.entry("read")},
		"roles": map[string]any{
			"B": map[string]any{"can": []any{"read"}, "rules": []any{hours}},
			"A": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "secret"}}}},
		}})
	day := e.clock.Now().Add(24 * time.Hour).Format(time.RFC3339)
	admin := e.grant(k, "user:root", []string{"oh"}, allVerbs, map[string]any{"exp": day})
	e.create("oh", "x", map[string]any{"n": 0.0}, admin)
	both := e.grant(rk, "user:r", []string{"oh"}, []string{"read"}, map[string]any{"roles": []any{"B", "A"}, "exp": day})
	onlyB := e.grant(rk, "user:r", []string{"oh"}, []string{"read"}, map[string]any{"roles": []any{"B"}, "exp": day})
	for _, at := range []time.Duration{0, 3 * time.Hour} {
		e.clock.Advance(at)
		expect(t, e.get("/ns/oh/log", both), 403)
		expect(t, e.get("/ns/oh/rev/"+e.nsHead("oh", admin)+"/heads", both), 403)
		expect(t, e.get("/r/oh/x", onlyB), 404)
		expect(t, e.get("/r/oh/x", both), 302)
	}
}

// §C.2 item 5, §E.2.3 At E3 (ENC-17): a grant with enc, a block rule on
// /resource ^pub- and one on /now is refused /keys (403), whatever its
// /resource rule would let it have; without the /now rule it isn't.
func TestV081AccessNowKeysE3(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	pub := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^pub-"}}
	now := map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	g := f.grant(f.writer, "user:reader", []string{"e"}, []string{"read"}, map[string]any{"enc": jwk, "rules": []any{pub, now}})
	r := f.do(req{method: "POST", path: "/ns/e/keys", body: map[string]any{"resources": []any{"pub-a"}}, bearer: g})
	expectCode(t, r, 403, "forbidden")
	plain := f.grant(f.writer, "user:reader", []string{"e"}, []string{"read"}, map[string]any{"enc": jwk, "rules": []any{pub}})
	if r := f.do(req{method: "POST", path: "/ns/e/keys", body: map[string]any{"resources": []any{"pub-a"}}, bearer: plain}); r.Code == 403 {
		t.Fatalf("without the /now rule: %d %s", r.Code, r.Body)
	}
}

// §C.2 item 5, §E.2.3 At E3: /keys relays only to a read grant whose
// rules pass for a read. A role with a rule on /now doesn't count for
// read, also beside a rule on /resource, so a grant whose only read role
// is such a role is refused GET /r/{ns}/{name} (404) and /keys (403): it
// gets no keyring entry, as one whose role has the /now rule alone.
func TestV081AccessNowKeysE3Role(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	now := map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	pub := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^pub-"}}
	f.mkNS("e3r", e2eDoc(map[string]any{
		"keys": []any{f.admin.entry("*"), f.writer.entry("read", "create", "append", "restore", "delete", "prune")},
		"roles": map[string]any{
			"clock":    map[string]any{"can": []any{"read"}, "rules": []any{now}},
			"clockpub": map[string]any{"can": []any{"read"}, "rules": []any{now, pub}},
			"pub":      map[string]any{"can": []any{"read"}, "rules": []any{pub}},
		},
	}))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	// A key holder's keyring, wrapping epoch 1's key to the reader's enc.
	_, holder, _ := seal.GenerateRecipient()
	kr, err := seal.BuildKeyringV2(holder, "e3r", 1, seal.NewKey(), []*ecdh.PublicKey{priv.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	f.create("e3r", "keyring", kr.Value(), f.grant(f.admin, "user:admin", []string{"e3r"}, []string{"read", "create"}))
	keys := func(roles ...any) (int, int) {
		g := f.grant(f.writer, "user:reader", []string{"e3r"}, []string{"read"}, map[string]any{"enc": jwk, "roles": roles})
		r := f.do(req{method: "POST", path: "/ns/e3r/keys", body: map[string]any{}, bearer: g})
		var body struct {
			Keys []any `json:"keys"`
		}
		_ = json.Unmarshal(r.Body, &body)
		if r.Code == 403 {
			expectCode(t, r, 403, "forbidden")
		}
		return r.Code, len(body.Keys)
	}
	if code, n := keys("clock"); code != 403 {
		t.Errorf("role with /now alone: /keys %d (%d entries), want 403", code, n)
	}
	clockpub := f.grant(f.writer, "user:reader", []string{"e3r"}, []string{"read"}, map[string]any{"enc": jwk, "roles": []any{"clockpub"}})
	if r := f.get("/r/e3r/pub-a", clockpub); r.Code != 404 {
		t.Errorf("GET /r/e3r/pub-a with role clockpub: %d, want 404", r.Code)
	}
	if code, n := keys("clockpub"); code != 403 {
		t.Errorf("role with /now and /resource rules: /keys %d (%d entries), want 403", code, n)
	}
	if code, n := keys("clock", "clockpub"); code != 403 {
		t.Errorf("roles clock and clockpub: /keys %d (%d entries), want 403", code, n)
	}
	// A role without the /now rule counts for read, beside one with it.
	if code, n := keys("clockpub", "pub"); code != 200 || n != 1 {
		t.Errorf("roles clockpub and pub: /keys %d (%d entries), want 200 with 1", code, n)
	}
}

// §C.2 item 5, §7, §E.2.3: /keys doesn't ignore the grant in a public
// namespace either, so a grant with a block rule on /now is 403 there
// too. At E3, a /resource rule beside the /now one makes the grant a
// per-resource reader for keysReadScope: only the read check's /keys arm
// refuses it.
func TestV081AccessNowKeysE3Public(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	f.mkNS("e3p", e2eDoc(map[string]any{"read": "public",
		"keys": []any{f.admin.entry("*"), f.writer.entry("read", "create", "append", "restore", "delete", "prune")}}))
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	pub := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^pub-"}}
	now := map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	g := f.grant(f.writer, "user:reader", []string{"e3p"}, []string{"read"}, map[string]any{"enc": jwk, "rules": []any{pub, now}})
	r := f.do(req{method: "POST", path: "/ns/e3p/keys", body: map[string]any{}, bearer: g})
	expectCode(t, r, 403, "forbidden")
	plain := f.grant(f.writer, "user:reader", []string{"e3p"}, []string{"read"}, map[string]any{"enc": jwk, "rules": []any{pub}})
	if r := f.do(req{method: "POST", path: "/ns/e3p/keys", body: map[string]any{}, bearer: plain}); r.Code != 200 {
		t.Fatalf("public E3 /keys without the /now rule: %d %s, want 200", r.Code, r.Body)
	}
}

// §C.2 item 5, §B.11.9 Partial reader (ACCESS-2): a grant with a block
// rule on /now is no partial reader. At an unfiltered URL of covered
// matches it is 403 at once, never a 302 to a filtered URL; and on a
// purged matches its gestures listing is 403, not the 410 of a read that
// passed the check.
func TestV081AccessNowNoPartialReader(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	now := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	r := w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/heads", now)
	expectCode(t, r, 403, "forbidden")
	if r.H.Get("Location") != "" {
		t.Fatalf("redirected to %q", r.H.Get("Location"))
	}
	expect(t, w.get("/ns/matches/log", now), 403)
	expect(t, w.do(req{method: "POST", path: "/edge-grants", bearer: now}), 403)
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	expectCode(t, w.get("/ns/matches/gestures/"+gA, now), 403, "forbidden")
	expectCode(t, w.get("/ns/matches/gestures/"+gA, w.li()), 410, "purged")
}

// TDA 63 (§B.11.9 Where, §C.5.2; v0.78): li's grant names matches-r7, a
// branch of covered matches: its filtered URLs are 403, and 401 with
// neither a grant nor a cookie; POST /edge-grants naming only matches-r7
// is 403 with no /ns/matches-r7/g/ prefix. An unrestricted reader of
// matches-r7 reads final, unfiltered.
func TestV081AccessBranchUncovered(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby", "final"}, nil, []string{"derby"})
	expect(t, w.do(req{method: "POST", path: "/ns/matches/branches", ifNoneMatch: "*", bearer: w.admin,
		body: map[string]any{"name": "matches-r7", "at": w.nsHead("matches", w.admin), "patches": []any{}}}), 201)
	w.put("matches-r7", "final", map[string]any{"title": "final"})
	gs, at := w.filtered(w.li())
	li := w.grant(w.cat, "user:li", []string{"matches-r7"}, []string{"read"}, map[string]any{"groups": []any{"editors", "interns"},
		"roles": []any{"reader"}, "at": map[string]any{"ns": "cat-season", "id": w.nsHead("cat-season", w.admin)},
		"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	base := "/ns/matches-r7/g/" + gs
	for _, path := range []string{base + "/heads", base + "/at/" + at + "/heads", base + "/at/" + at + "/log"} {
		expect(t, w.get(path, li), 403)
		expect(t, w.get(path), 401)
	}
	expect(t, w.get("/ns/matches-r7/rev/"+w.nsHead("matches-r7", w.admin)+"/heads", li), 403)
	r := w.do(req{method: "POST", path: "/edge-grants", bearer: li})
	expect(t, r, 403)
	for _, c := range r.H.Values("Set-Cookie") {
		if strings.Contains(c, "/ns/matches-r7/g/") {
			t.Fatalf("a g cookie: %s", c)
		}
	}
	h := w.get("/ns/matches-r7/rev/"+w.nsHead("matches-r7", w.admin)+"/heads", w.admin)
	expect(t, h, 200)
	if !strings.Contains(string(h.Body), `"final"`) {
		t.Fatalf("admin's heads %s", h.Body)
	}
}

// §7.4, HTTP-25 (v0.81 "Bytes fixed"): the first namespace entry carries
// prev "", in a log range and in a filtered one alike.
func TestV081AccessFirstPrev(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	first := func(r *resp) map[string]any {
		t.Helper()
		expect(t, r, 200)
		arr := r.Arr()
		if len(arr) == 0 {
			t.Fatalf("an empty log: %s", r.Body)
		}
		return arr[0].(map[string]any)
	}
	m := first(w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/log", w.admin))
	if p, ok := m["prev"]; !ok || p != "" {
		t.Fatalf("first entry %v: prev %v %v, want \"\"", m, p, ok)
	}
	if m2 := first(w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/log?since="+m["id"].(string), w.admin)); m2["prev"] != m["id"] {
		t.Fatalf("second entry's prev %v, want %v", m2["prev"], m["id"])
	}
	li := w.li()
	gs, at := w.filtered(li)
	fm := first(w.get("/ns/matches/g/"+gs+"/at/"+at+"/log", li))
	if p, ok := fm["prev"]; !ok || p != "" {
		t.Fatalf("first filtered entry %v: prev %v %v, want \"\"", fm, p, ok)
	}
}
