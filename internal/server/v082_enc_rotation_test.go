package server

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82encLastEntry is the newest entry of ns's log as it is served in
// development mode (the plaintext a sealed range seals).
func v82encLastEntry(t *testing.T, e *tenv, ns string) map[string]any {
	t.Helper()
	es := e.plainNSLog(ns, e.nsHead(ns)).Entries
	if len(es) == 0 {
		t.Fatal("empty log")
	}
	return es[len(es)-1]
}

// v82encLog is sealed namespace ns's whole log as served to bearer: the
// range's JWE, opened under K_n of the epoch its kid names.
func v82encLog(t *testing.T, e *tenv, ns, bearer string) []map[string]any {
	t.Helper()
	head := e.nsHead(ns, bearer)
	r := e.get("/ns/"+ns+"/rev/"+head+"/log", bearer)
	expect(t, r, 200)
	h, err := seal.ParseHeader(string(r.Body))
	if err != nil {
		t.Fatal(err)
	}
	keys, kr := e.keysOf(ns, nil, bearer)
	expect(t, kr, 200)
	arr, _ := jsonv.MustParse(open(t, string(r.Body), nsKey(t, keys[h.Kid], ns), h.Kid, seal.RangePL(ns, "", head))).([]any)
	out := make([]map[string]any, len(arr))
	for i, x := range arr {
		out[i] = x.(map[string]any)
	}
	return out
}

// v82encOwnRotation checks that m is the config entry of a rotation the
// origin made by itself (§E.2.1, §7.2): by RotateAuthor, with no grant
// and no via members at all, also where authentication is disabled, whose
// entries otherwise say "grant": null.
func v82encOwnRotation(t *testing.T, what string, m map[string]any) {
	t.Helper()
	if m["kind"] != "config" || m["author"] != core.RotateAuthor {
		t.Fatalf("%s: the newest entry is %v", what, m)
	}
	if _, has := m["grant"]; has {
		t.Fatalf("%s: the origin's own rotation carries a grant member: %v", what, m)
	}
	if _, has := m["via"]; has {
		t.Fatalf("%s: the origin's own rotation carries a via member: %v", what, m)
	}
}

// E2E-10 (§E.2.1 "the origin MAY rotate by itself", §7.2 grant bullet),
// authentication disabled: a rotation the bound makes due is written by
// system:rotate in a config entry with no grant and no via members, where
// a request's entry says "grant": null; a frozen namespace is rotated
// too. The served bytes are checked through the sealed range as well.
func TestV082OwnRotationEntryDev(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withSealBound(1<<20, 6, 1))
	ids := boundNS(t, e)
	expect(t, e.patchNS("s", ops(op("add", "/frozen", true)), ""), 201)
	// A request's entry, for contrast: null while authentication is
	// disabled (§7.4).
	req := v82encLastEntry(t, e, "s")
	if g, has := req["grant"]; !has || g != nil || req["author"] == core.RotateAuthor {
		t.Fatalf("a request's entry in development mode: %v", req)
	}
	head := e.nsHead("s")
	expect(t, e.get("/ns/s/rev/"+head+"/log?since="+ids[0]), 200)
	done, err := e.e.RetryRotations(context.Background())
	if err != nil || len(done) != 1 || done[0] != "s" {
		t.Fatalf("rotated %v %v", done, err)
	}
	if ep := e.configOf("s")["encryption"].(map[string]any)["epoch"]; ep != 2.0 {
		t.Fatalf("epoch %v after the rotation of a frozen namespace", ep)
	}
	v82encOwnRotation(t, "bound-triggered, authentication disabled", v82encLastEntry(t, e, "s"))
	// As served: the one-entry range of the rotation, opened under the
	// new epoch's K_n, has neither member.
	keys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	now := e.nsHead("s")
	r := e.get("/ns/s/rev/" + now + "/log?since=" + head)
	expect(t, r, 200)
	pt := open(t, string(r.Body), nsKey(t, keys["s#2"], "s"), "s#2", seal.RangePL("s", head, now))
	arr, _ := jsonv.MustParse(pt).([]any)
	if len(arr) != 1 {
		t.Fatalf("the rotation's range: %s", pt)
	}
	v82encOwnRotation(t, "the served range", arr[0].(map[string]any))
}

// E2E-10, authentication enabled: the rotation after a revocation, which
// follows a *-key holder's config write, is the origin's own entry: no
// grant, though the revoking write's entry names its grant, and no via.
// No request reaches it: RotateEpoch isn't served, and the rotation of an
// end-to-end namespace is refused, where only key holders rotate.
func TestV082OwnRotationEntryAuth(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t, func(o *core.Options) { o.RotateOnRevoke = true })
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	star := e.grant(k, "user:admin", []string{"s"}, []string{"config", "read"})
	expect(t, e.patchNS("s", ops(op("add", "/revoked", []any{"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})), star), 201)
	es := v82encLog(t, e, "s", star)
	if len(es) < 2 {
		t.Fatalf("log %v", es)
	}
	revoke, rot := es[len(es)-2], es[len(es)-1]
	if g, _ := revoke["grant"].(map[string]any); g == nil || revoke["author"] != "user:admin" {
		t.Fatalf("the revoking write's entry: %v", revoke)
	}
	v82encOwnRotation(t, "revoke-triggered, authentication enabled", rot)
	// The rotation moved the epoch.
	keys, kr := e.keysOf("s", nil, star)
	expect(t, kr, 200)
	if _, ok := keys["s#2"]; !ok {
		t.Fatalf("keys after the rotation: %v", keys)
	}
	// An explicit rotation by the origin: the same entry.
	if ep, err := e.e.RotateEpoch(context.Background(), "s", core.RotateAuthor); err != nil || ep != 3 {
		t.Fatalf("rotated to %d %v", ep, err)
	}
	v82encOwnRotation(t, "RotateEpoch", v82encLog(t, e, "s", star)[len(es)])

	// At E3 the origin never rotates.
	ke := newKey("ke")
	e.mkNS("e", e2eDoc(map[string]any{"read": "grant", "keys": []any{ke.entry("*")}}))
	if ep, err := e.e.RotateEpoch(context.Background(), "e", core.RotateAuthor); err == nil {
		t.Fatalf("the origin rotated an end-to-end namespace to epoch %d", ep)
	}
	// No URL rotates: the paths a rotation might be asked at aren't
	// served to any grant, a * key's included.
	for _, p := range []string{"/ns/s/rotate", "/ns/s/keys/rotate", "/ns/s/epoch"} {
		if r := e.do(req{method: "POST", path: p, bearer: star, body: map[string]any{}}); r.Code == 200 || r.Code == 201 || r.Code == 204 {
			t.Fatalf("POST %s: %d", p, r.Code)
		}
	}
	keys, _ = e.keysOf("s", nil, star)
	if _, ok := keys["s#4"]; ok {
		t.Fatal("a request rotated the epoch")
	}
}
