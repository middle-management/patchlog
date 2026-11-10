package server

import (
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// v0.78 (Addendum E Levels, Changing it; scenario 29): a namespace is
// end-to-end from its creation or never. A config write raising one to
// e2e is 422 invalid at /encryption, by PATCH and by batch, from none,
// at-rest and sealed (with the epoch+1 a raise once needed) alike.
func TestV081RaiseToE2ERefused(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("plain", map[string]any{"read": "public"})
	e.mkNS("rest", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	e.mkNS("sealed", sealedDoc(map[string]any{"read": "grant"}))
	for _, c := range []struct {
		ns  string
		enc map[string]any
		op  string
	}{
		{"plain", map[string]any{"level": "e2e"}, "add"},
		{"plain", map[string]any{"level": "e2e", "epoch": 1.0}, "add"},
		{"rest", map[string]any{"level": "e2e"}, "replace"},
		{"sealed", map[string]any{"level": "e2e", "epoch": 2.0}, "replace"},
	} {
		r := e.patchNS(c.ns, ops(op(c.op, "/encryption", c.enc)), "")
		expectCode(t, r, 422, "invalid")
		if p := errPointer(t, r); p != "/encryption" {
			t.Fatalf("%s: pointer %q: %s", c.ns, p, r.Body)
		}
		body := map[string]any{"config": map[string]any{"ifMatch": e.configID(c.ns), "patches": ops(op(c.op, "/encryption", c.enc))}}
		b := e.do(req{method: "POST", path: "/ns/" + c.ns + "/batch", body: body, author: "admin"})
		if b.Code != 422 {
			t.Fatalf("%s batch: %d %s", c.ns, b.Code, b.Body)
		}
		if levelOf(e.configOf(c.ns)) == "e2e" {
			t.Fatalf("%s raised to e2e", c.ns)
		}
	}
	// Creation at e2e, and other raises, are unchanged.
	e.mkNS("e", e2eDoc(map[string]any{"read": "grant"}))
	expect(t, e.patchNS("plain", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
}

// Scenario 29: a remote branch's raise to e2e is 422 as in any namespace,
// refused before its source is read, so a source that doesn't answer
// changes nothing (§G.5.2).
func TestV081RemoteRaiseToE2ERefusedWithoutSource(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r2", remoteGenesis("m", a.nsHead("m"), map[string]any{"encryption": map[string]any{"level": "sealed"}})), 201)
	down := httptest.NewServer(nil)
	down.Close()
	rt.set(down.URL, "")
	r := b.patchNS("r2", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), "")
	expectCode(t, r, 422, "invalid")
	if p := errPointer(t, r); p != "/encryption" {
		t.Fatalf("pointer %q: %s", p, r.Body)
	}
}

// LegacyE2ERaiseForTests lets the raise through, recording only the
// configuration, as a pre-v0.78 source did: the fixture of remote tests
// that follow a source's raise.
func TestV081LegacyE2ERaiseHook(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withLegacyE2ERaise)
	e.mkNS("m", sealedDoc(map[string]any{"read": "grant"}))
	expect(t, e.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), ""), 201)
	if levelOf(e.configOf("m")) != "e2e" {
		t.Fatal("not raised")
	}
}

func withLegacyE2ERaise(o *core.Options) { o.LegacyE2ERaiseForTests = true }
