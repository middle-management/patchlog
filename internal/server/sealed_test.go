package server

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Sealed for delivery (Addendum E, level E2).

func sealedDoc(doc map[string]any) map[string]any {
	doc["encryption"] = map[string]any{"level": "sealed"}
	return doc
}

func newSealedEnv(t *testing.T, opts ...envOpt) *tenv {
	return newEnv(t, append([]envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, opts...)...)
}

func newSealedAuthEnv(t *testing.T, opts ...envOpt) *tenv {
	return newAuthEnv(t, append([]envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, opts...)...)
}

// withNonce appends a fresh $nonce to a patch set (§C.7).
func withNonce(patches []any) []any {
	return append(append([]any{}, patches...), op("add", "/$nonce", seal.NewNonce()))
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// keysOf calls POST /ns/{ns}/keys and returns its keys by kid (and
// "kid resource" for per-resource keys), decoding raw keys.
func (e *tenv) keysOf(ns string, body map[string]any, bearer string) (map[string][]byte, *resp) {
	e.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	r := e.do(req{method: "POST", path: "/ns/" + ns + "/keys", body: body, bearer: bearer, author: "reader"})
	if r.Code != 200 {
		return nil, r
	}
	if r.H.Get("Cache-Control") != "no-store" {
		e.t.Fatalf("keys Cache-Control %q", r.H.Get("Cache-Control"))
	}
	out := map[string][]byte{}
	arr, _ := r.Obj()["keys"].([]any)
	for _, x := range arr {
		m := x.(map[string]any)
		k := m["kid"].(string)
		if res, ok := m["resource"].(string); ok {
			k += " " + res
		}
		if ks, ok := m["key"].(string); ok {
			b, err := base64.RawURLEncoding.DecodeString(ks)
			if err != nil || len(b) != 32 {
				e.t.Fatalf("bad key %v", m)
			}
			out[k] = b
		} else {
			out[k] = nil // wrapped
		}
	}
	return out, r
}

func resKey(t *testing.T, ke []byte, ns, name string) []byte {
	t.Helper()
	k, err := seal.ResourceKey(ke, ns, name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// open decrypts a JWE, requiring kid and pl.
func open(t *testing.T, jwe string, key []byte, kid string, pl seal.PL) []byte {
	t.Helper()
	pt, err := seal.OpenExpect(jwe, key, kid, pl)
	if err != nil {
		h, _ := seal.ParseHeader(jwe)
		t.Fatalf("open (want %s %v): %v; header %s", kid, pl, err, h.Raw)
	}
	return pt
}

func isJOSE(r *resp) bool { return r.H.Get("Content-Type") == seal.ContentType }

// wr writes patches (parent "" creates) and returns the new id.
func (e *tenv) wr(ns, name, parent string, patches []any, who ...string) string {
	e.t.Helper()
	r := e.write("PATCH", ns, name, parent, patches, who...)
	expect(e.t, r, 201)
	return etagOf(r)
}

// plainNSLog is the namespace log as an unsealed namespace would serve it.
func (e *tenv) plainNSLog(ns, head string) *core.Log {
	e.t.Helper()
	l, err := e.e.NamespaceLog(context.Background(), ns, head, "", 0, core.Credentials{})
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

// Every sealed output is a JWE bound to what it is, decrypts to exactly what
// an equivalent unsealed namespace serves, and is stored once: the same
// bytes on every read, across cache flushes.
func TestSealedOutputs(t *testing.T) {
	e := newSealedEnv(t, withLongPoll(200*time.Millisecond))
	e.mkNS("p", atRest(map[string]any{"read": "public"}))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	// The same patch sets (nonces included) in both namespaces give the
	// same ids.
	sets := [][]any{
		withNonce(addRoot(map[string]any{"v": encMarker, "big": strings.Repeat("compressible ", 200)})),
		withNonce(ops(op("add", "/k", encMarker+"-1"))),
		withNonce(ops(op("replace", "/v", encMarker+"-2"))),
	}
	var ids []string
	parent := ""
	for _, ps := range sets {
		a, b := e.wr("p", "x", parent, ps), e.wr("s", "x", parent, ps)
		if a != b {
			t.Fatalf("ids differ: %s %s", a, b)
		}
		ids = append(ids, a)
		parent = a
	}
	tomb := e.del("s", "x", ids[2])
	e.del("p", "x", ids[2])
	ids2 := e.wr("s", "x", tomb, []any{}) // a [] restore needs no nonce
	e.wr("p", "x", tomb, []any{})

	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	ke := keys["s#1"]
	if ke == nil || len(keys) != 1 {
		t.Fatalf("keys %v", keys)
	}
	kr := resKey(t, ke, "s", "x")

	collect := func() map[string]string {
		out := map[string]string{}
		// Documents.
		for i, id := range ids {
			sr, pr := e.get("/r/s/x/rev/"+id), e.get("/r/p/x/rev/"+id)
			expect(t, sr, 200)
			if !isJOSE(sr) || sr.H.Get("Cache-Control") != ccImmutable || sr.H.Get("ETag") != quote(id) || sr.H.Get("X-Revision") != id {
				t.Fatalf("doc headers %v", sr.H)
			}
			if strings.Contains(string(sr.Body), encMarker) {
				t.Fatal("plaintext in a sealed document")
			}
			if pt := open(t, string(sr.Body), kr, "s#1", seal.ResourcePL("s", "x", id, "doc")); string(pt) != string(pr.Body) {
				t.Fatalf("doc %d: %s != %s", i, pt, pr.Body)
			}
			if i == 0 {
				if h, _ := seal.ParseHeader(string(sr.Body)); h.Zip != seal.ZipDeflate {
					t.Fatal("a large document is not compressed before sealing")
				}
			}
			out["doc"+id] = string(sr.Body)
			// If-None-Match still answers 304.
			if r := e.do(req{method: "GET", path: "/r/s/x/rev/" + id, hdr: map[string]string{"If-None-Match": quote(id)}}); r.Code != 304 {
				t.Fatalf("304: %d", r.Code)
			}
		}
		// The resource log: an array of per-entry JWEs.
		sl, pl := e.get("/r/s/x/rev/"+ids2+"/log"), e.get("/r/p/x/rev/"+ids2+"/log")
		expect(t, sl, 200)
		if sl.H.Get("Cache-Control") != ccImmutable {
			t.Fatalf("log headers %v", sl.H)
		}
		sa, pa := sl.Arr(), pl.Arr()
		if len(sa) != 5 || len(pa) != 5 {
			t.Fatalf("log lengths %d %d", len(sa), len(pa))
		}
		for i := range sa {
			pe := pa[i].(map[string]any)
			kind := pe["kind"].(string)
			pt := open(t, sa[i].(string), kr, "s#1", seal.ResourcePL("s", "x", pe["id"].(string), kind))
			if string(pt) != string(canonical(pe)) {
				t.Fatalf("entry %d: %s != %s", i, pt, canonical(pe))
			}
			out["entry"+pe["id"].(string)] = sa[i].(string)
		}
		// The namespace document.
		head := e.nsHead("s")
		nr := e.get("/ns/s/rev/" + head)
		expect(t, nr, 200)
		if !isJOSE(nr) || nr.H.Get("Cache-Control") != ccImmutable || nr.H.Get("X-Config-Revision") == "" {
			t.Fatalf("ns doc headers %v", nr.H)
		}
		nd := open(t, string(nr.Body), ke, "s#1", seal.NamespaceDocPL("s", head))
		if v := jsonv.MustParse(nd).(map[string]any); v["read"] != "public" {
			t.Fatalf("ns doc %s", nd)
		}
		out["nsdoc"] = string(nr.Body)
		// Namespace log ranges: one JWE per range.
		plain := e.plainNSLog("s", head)
		rr := e.get("/ns/s/rev/" + head + "/log")
		expect(t, rr, 200)
		if !isJOSE(rr) || rr.H.Get("Cache-Control") != ccImmutable {
			t.Fatalf("range headers %v", rr.H)
		}
		want := make([]any, len(plain.Entries))
		for i, m := range plain.Entries {
			want[i] = m
		}
		pt := open(t, string(rr.Body), ke, "s#1", seal.RangePL("s", "", head))
		if string(pt) != string(canonical(want)) {
			t.Fatalf("range %s != %s", pt, canonical(want))
		}
		if h, _ := seal.ParseHeader(string(rr.Body)); h.Zip != "" {
			t.Fatal("a range was compressed")
		}
		out["range"] = string(rr.Body)
		since := plain.Entries[1]["id"].(string)
		rr2 := e.get("/ns/s/rev/" + head + "/log?since=" + since)
		expect(t, rr2, 200)
		open(t, string(rr2.Body), ke, "s#1", seal.RangePL("s", since, head))
		out["range2"] = string(rr2.Body)
		// Long-poll answers have the log shapes.
		lp := e.get("/ns/s/log?live=long-poll&since=" + since)
		expect(t, lp, 200)
		if !isJOSE(lp) || !strings.HasPrefix(lp.H.Get("Cache-Control"), "public, ") {
			t.Fatalf("long-poll headers %v", lp.H)
		}
		if string(lp.Body) != string(rr2.Body) {
			t.Fatal("long-poll range differs from the stored range")
		}
		lr := e.get("/r/s/x/log?live=long-poll&since=" + ids[1])
		expect(t, lr, 200)
		la := lr.Arr()
		if len(la) != 3 || la[0] != out["entry"+ids[2]] {
			t.Fatalf("resource long-poll %s", lr.Body)
		}
		// Head pointers use the public classes.
		if h := e.get("/r/s/x"); h.H.Get("Cache-Control") != ccHead {
			t.Fatalf("head %v", h.H)
		}
		return out
	}
	first := collect()
	second := collect()
	e.e.FlushCaches()
	third := collect()
	for k, v := range first {
		if second[k] != v || third[k] != v {
			t.Fatalf("%s: sealed bytes changed between reads", k)
		}
	}

	// Events: resource events carry the stored entry JWEs; namespace
	// events one JWE per entry, the stored range (prev, id].
	ch, _, cancel := e.openSSE("/r/s/x/events", nil)
	for _, id := range append(append([]string{}, ids...), tomb, ids2) {
		ev := next(t, ch)
		if ev.id != id || ev.data != first["entry"+id] {
			t.Fatalf("resource event %s: %v", id, ev)
		}
	}
	cancel()
	head := e.nsHead("s")
	plain := e.plainNSLog("s", head)
	nch, _, ncancel := e.openSSE("/ns/s/events", nil)
	prev := ""
	for _, m := range plain.Entries {
		ev := next(t, nch)
		id := m["id"].(string)
		pt := open(t, ev.data, ke, "s#1", seal.RangePL("s", prev, id))
		if ev.id != id || string(pt) != string(canonical([]any{m})) {
			t.Fatalf("ns event %s: %s", id, pt)
		}
		if r := e.get("/ns/s/rev/" + id + "/log?since=" + prev); prev != "" && string(r.Body) != ev.data {
			t.Fatal("an event's JWE differs from the stored range")
		}
		prev = id
	}
	// A live event.
	ids3 := e.wr("s", "x", ids2, withNonce(ops(op("add", "/live", true))))
	ev := next(t, nch)
	if ev.event != "head" || !strings.HasPrefix(ev.data, "ey") {
		t.Fatalf("live event %v", ev)
	}
	ncancel()
	_ = ids3

	// Tombstone and error bodies stay plaintext; ids are clear anyway.
	h := e.get("/r/s/x/rev/" + tomb)
	expect(t, h, 410)
	if isJOSE(h) {
		t.Fatal("a 410 was sealed")
	}
	// Nothing sealed is stored in plaintext either (E1 still applies).
	if s := e.get("/ns/s/rev/" + head + "/heads"); s.Code != 200 || isJOSE(s) || s.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("heads %d %v", s.Code, s.H)
	}
}

// read: "grant" still decides who may fetch ciphertext, while caching uses
// the public classes (§E.2.5).
func TestSealedReadGrant(t *testing.T) {
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	w := e.grant(k, "user:w", []string{"s"}, []string{"create", "append", "read"})
	id := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})), w)
	nr := e.grant(k, "user:x", []string{"s"}, []string{"append"})
	expect(t, e.get("/r/s/a/rev/"+id), 401)
	expect(t, e.get("/r/s/a/rev/"+id, nr), 404)
	expect(t, e.get("/ns/s/rev/"+e.nsHead("s", w)+"/log", nr), 404)
	r := e.get("/r/s/a/rev/"+id, w)
	expect(t, r, 200)
	if !isJOSE(r) || r.H.Get("Cache-Control") != ccImmutable || r.H.Get("CDN-Cache-Control") != "" {
		t.Fatalf("headers %v", r.H)
	}
	// Keys need a verified read grant.
	if _, r := e.keysOf("s", nil, ""); r.Code != 401 {
		t.Fatalf("keys without grant %d", r.Code)
	}
	if _, r := e.keysOf("s", nil, nr); r.Code != 404 {
		t.Fatalf("keys without read %d", r.Code)
	}
	// So does a sealed public namespace's.
	e.mkNS("sp", sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("*")}}))
	expect(t, e.get("/ns/sp/rev/"+e.nsHead("sp")), 200)
	if _, r := e.keysOf("sp", nil, ""); r.Code != 401 {
		t.Fatalf("keys of a public sealed namespace without grant %d", r.Code)
	}
	if keys, r := e.keysOf("sp", nil, e.grant(k, "user:r", []string{"sp"}, []string{"read"})); r.Code != 200 || keys["sp#1"] == nil {
		t.Fatalf("keys %d %v", r.Code, keys)
	}
	// A non-sealed namespace has no keys.
	e.mkNS("plain", atRest(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	if _, r := e.keysOf("plain", nil, e.grant(k, "user:r", []string{"plain"}, []string{"read"})); r.Code != 422 {
		t.Fatalf("keys of an at-rest namespace %d", r.Code)
	}
}

// POST /ns/{ns}/keys: epoch keys, per-resource keys, epoch ranges, wrapping.
func TestSealedKeys(t *testing.T) {
	e := newSealedAuthEnv(t)
	k := newKey("k")
	rk := newKey("rk")
	rkEntry := rk.entry("read")
	rkEntry["readScope"] = "resource"
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*"), rkEntry}}))
	long := map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339)}
	star := e.grant(k, "user:admin", []string{"s"}, []string{"create", "append", "read", "config"}, long)
	a := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": "a"})), star)
	b := e.wr("s", "b", "", withNonce(addRoot(map[string]any{"v": "b"})), star)

	// Epoch keys for an unrestricted read grant.
	reader := e.grant(k, "user:r", []string{"s"}, []string{"read"}, long)
	keys, r := e.keysOf("s", nil, reader)
	expect(t, r, 200)
	ke1 := keys["s#1"]
	if len(keys) != 1 || ke1 == nil {
		t.Fatalf("epoch keys %v", keys)
	}
	docA := string(e.get("/r/s/a/rev/"+a, star).Body)
	docB := string(e.get("/r/s/b/rev/"+b, star).Body)
	open(t, docA, resKey(t, ke1, "s", "a"), "s#1", seal.ResourcePL("s", "a", a, "doc"))

	// Per-resource keys for a grant fixed to /resource: only resources it
	// may read. K_a opens a's documents and not b's.
	fixed := e.grant(rk, "user:li", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	keys, r = e.keysOf("s", map[string]any{"resources": []any{"a", "b"}}, fixed)
	expect(t, r, 200)
	ka := keys["s#1 a"]
	if len(keys) != 1 || ka == nil {
		t.Fatalf("per-resource keys %s", r.Body)
	}
	open(t, docA, ka, "s#1", seal.ResourcePL("s", "a", a, "doc"))
	if _, err := seal.OpenExpect(docB, ka, "s#1", seal.ResourcePL("s", "b", b, "doc")); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("K_a opened b: %v", err)
	}
	// Per-resource grants get no epoch key, and nothing without resources.
	if keys, _ := e.keysOf("s", nil, fixed); len(keys) != 0 {
		t.Fatalf("per-resource grant without resources got %v", keys)
	}

	// Rotation needs a * key; epochs start at config writes.
	configOnly := newKey("cfg")
	cur := e.configID("s", star)
	expect(t, e.do(req{method: "PATCH", path: "/ns/s", ifMatch: cur, body: ops(op("add", "/keys/-", configOnly.entry("config", "read"))), bearer: star}), 201)
	cg := e.grant(configOnly, "user:c", []string{"s"}, []string{"config", "read"})
	expectCode(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), cg), 403, "forbidden")
	e.clock.Advance(time.Hour)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), star), 201)
	expectCode(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 4.0)), star), 422, "invalid")
	expectCode(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 1.0)), star), 422, "invalid")
	e.clock.Advance(time.Hour)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 3.0)), star), 201)
	e.clock.Advance(10 * time.Minute) // now t0+2h10m; epochs start at t0, t0+1h, t0+2h

	epochsOf := func(keys map[string][]byte) string {
		var out []string
		for _, n := range []string{"s#1", "s#2", "s#3", "s#4"} {
			if _, ok := keys[n]; ok {
				out = append(out, n)
			}
		}
		return strings.Join(out, ",")
	}
	keys, _ = e.keysOf("s", nil, e.grant(k, "user:r", []string{"s"}, []string{"read"}))
	if got := epochsOf(keys); got != "s#1,s#2,s#3" {
		t.Fatalf("all epochs: %s", got)
	}
	if string(keys["s#1"]) != string(ke1) {
		t.Fatal("epoch 1's key changed")
	}
	// From the epoch in force at the root's nbf.
	nbf := map[string]any{"nbf": t0.Add(90 * time.Minute).Format(time.RFC3339)}
	keys, _ = e.keysOf("s", nil, e.grant(k, "user:r", []string{"s"}, []string{"read"}, nbf))
	if got := epochsOf(keys); got != "s#2,s#3" {
		t.Fatalf("epochs from nbf: %s", got)
	}
	// Requested epochs outside the range are omitted.
	keys, _ = e.keysOf("s", map[string]any{"epochs": []any{1.0, 3.0, 9.0}}, e.grant(k, "user:r", []string{"s"}, []string{"read"}, nbf))
	if got := epochsOf(keys); got != "s#3" {
		t.Fatalf("requested epochs: %s", got)
	}
	// historyEpochs caps history.
	expect(t, e.patchNS("s", ops(op("add", "/encryption/historyEpochs", 1.0)), star), 201)
	keys, _ = e.keysOf("s", nil, reader)
	if got := epochsOf(keys); got != "s#3" {
		t.Fatalf("epochs with historyEpochs 1: %s", got)
	}
	expect(t, e.patchNS("s", ops(op("remove", "/encryption/historyEpochs")), star), 201)
	// Never an epoch that started after the grant's exp: epoch 4 starts at
	// t0+5h, and the clock is set back before it for the grant to verify.
	e.clock.set(t0.Add(5 * time.Hour))
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 4.0)), e.grant(k, "user:admin", []string{"s"}, []string{"config", "read"})), 201)
	e.clock.set(t0.Add(150 * time.Minute))
	short := e.grant(k, "user:r", []string{"s"}, []string{"read"}, map[string]any{"exp": t0.Add(3 * time.Hour).Format(time.RFC3339)})
	keys, _ = e.keysOf("s", nil, short)
	if got := epochsOf(keys); got != "s#1,s#2,s#3" {
		t.Fatalf("epochs before exp: %s", got)
	}
	later := e.grant(k, "user:r", []string{"s"}, []string{"read"}, map[string]any{"exp": t0.Add(6 * time.Hour).Format(time.RFC3339)})
	keys, _ = e.keysOf("s", nil, later)
	if got := epochsOf(keys); got != "s#1,s#2,s#3,s#4" {
		t.Fatalf("epochs before a later exp: %s", got)
	}

	// Wrapped to the grant's enc (HPKE): no raw key in the body.
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	wg := e.grant(k, "user:r", []string{"s"}, []string{"read"}, map[string]any{"enc": jwk})
	_, r = e.keysOf("s", map[string]any{"epochs": []any{1.0}}, wg)
	expect(t, r, 200)
	if strings.Contains(string(r.Body), `"key"`) || strings.Contains(string(r.Body), base64.RawURLEncoding.EncodeToString(ke1)) {
		t.Fatalf("raw key in a wrapped response: %s", r.Body)
	}
	arr := r.Obj()["keys"].([]any)
	if len(arr) != 1 {
		t.Fatalf("wrapped %s", r.Body)
	}
	w, err := seal.ParseWrappedKey(arr[0])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := seal.UnwrapKey(priv, w); err != nil || string(got) != string(ke1) {
		t.Fatalf("unwrap: %v", err)
	}
	var other *ecdh.PrivateKey
	_, other, _ = seal.GenerateRecipient()
	if _, err := seal.UnwrapKey(other, w); err == nil {
		t.Fatal("another recipient unwrapped the key")
	}
	// Per-resource keys are wrapped with their resource bound.
	fw := e.grant(rk, "user:li", []string{"s"}, []string{"read"}, map[string]any{"enc": jwk, "rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	_, r = e.keysOf("s", map[string]any{"epochs": []any{1.0}, "resources": []any{"a"}}, fw)
	arr = r.Obj()["keys"].([]any)
	w, _ = seal.ParseWrappedKey(arr[0])
	if got, err := seal.UnwrapKey(priv, w); err != nil || w.Resource != "a" || string(got) != string(ka) {
		t.Fatalf("unwrap per-resource: %v %s", err, r.Body)
	}
	// A malformed enc makes the grant invalid.
	bad := map[string]any{"kid": "k", "sub": "u", "ns": []any{"s"}, "can": []any{"read"}, "exp": t0.Add(3 * time.Hour).Format(time.RFC3339), "enc": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}}
	if _, err := seal.ParseRecipientJWK(bad["enc"]); err == nil {
		t.Fatal("Ed25519 accepted as a recipient")
	}
}

// With authentication disabled (development), anyone gets raw epoch keys.
func TestSealedKeysDev(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant"}))
	keys, r := e.keysOf("s", map[string]any{"resources": []any{"a"}}, "")
	expect(t, r, 200)
	if len(keys) != 1 || keys["s#1"] == nil {
		t.Fatalf("dev keys %s", r.Body)
	}
	if _, r := e.keysOf("nope", nil, ""); r.Code != 404 {
		t.Fatalf("unknown namespace %d", r.Code)
	}
	expect(t, e.do(req{method: "POST", path: "/ns/s/keys", body: map[string]any{"x": []any{}}}), 400)
}

// Rotation: new revisions are sealed under the new epoch, old ones keep
// their bytes forever.
func TestSealedRotation(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	a1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	before := string(e.get("/r/s/a/rev/" + a1).Body)
	beforeLog := string(e.get("/r/s/a/rev/" + a1 + "/log").Body)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	a2 := e.wr("s", "a", a1, withNonce(ops(op("replace", "/v", 2.0))))
	keys, _ := e.keysOf("s", nil, "")
	if keys["s#1"] == nil || keys["s#2"] == nil || string(keys["s#1"]) == string(keys["s#2"]) {
		t.Fatalf("keys %v", keys)
	}
	if got := string(e.get("/r/s/a/rev/" + a1).Body); got != before {
		t.Fatal("an old revision's bytes changed after rotation")
	}
	d2 := string(e.get("/r/s/a/rev/" + a2).Body)
	open(t, d2, resKey(t, keys["s#2"], "s", "a"), "s#2", seal.ResourcePL("s", "a", a2, "doc"))
	lg := e.get("/r/s/a/rev/" + a2 + "/log").Arr()
	if lg[0] != jsonv.MustParse([]byte(beforeLog)).([]any)[0] {
		t.Fatal("an old entry's bytes changed")
	}
	open(t, lg[1].(string), resKey(t, keys["s#2"], "s", "a"), "s#2", seal.ResourcePL("s", "a", a2, "rev"))
	// Namespace documents and ranges use the epoch in force at them.
	head := e.nsHead("s")
	open(t, string(e.get("/ns/s/rev/"+head).Body), keys["s#2"], "s#2", seal.NamespaceDocPL("s", head))

	// The engine's rotation (serve -rotate-epochs) writes the config as a
	// system principal.
	if ep, err := e.e.RotateEpoch(context.Background(), "s", core.RotateAuthor); err != nil || ep != 3 {
		t.Fatalf("rotate: %d %v", ep, err)
	}
	e.clock.Advance(2 * time.Hour)
	done, err := e.e.RotateDue(context.Background(), time.Hour)
	if err != nil || len(done) != 1 || done[0] != "s" {
		t.Fatalf("rotate due: %v %v", done, err)
	}
	if done, _ := e.e.RotateDue(context.Background(), time.Hour); len(done) != 0 {
		t.Fatalf("rotated again: %v", done)
	}
	lg2 := e.get("/ns/s/rev/" + e.nsHead("s") + "/log?since=" + head)
	k4, _ := e.keysOf("s", nil, "")
	pt := open(t, string(lg2.Body), k4["s#4"], "s#4", seal.RangePL("s", head, e.nsHead("s")))
	entries := jsonv.MustParse(pt).([]any)
	if len(entries) != 2 || entries[1].(map[string]any)["author"] != core.RotateAuthor {
		t.Fatalf("rotation entries %s", pt)
	}
}

// -rotate-on-revoke rotates right after a config write that revokes access.
func TestSealedRotateOnRevoke(t *testing.T) {
	e := newSealedAuthEnv(t, func(o *core.Options) { o.RotateOnRevoke = true })
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	star := e.grant(k, "user:admin", []string{"s", "sb"}, []string{"config", "read", "branch"})
	expect(t, e.branch("s", map[string]any{"name": "sb"}, star), 201)
	epoch := func(ns string) float64 {
		r := e.get("/ns/"+ns+"/rev/"+e.nsHead(ns, star), star)
		keys, _ := e.keysOf(ns, nil, star)
		var ep float64
		for kid := range keys {
			_, n, _ := seal.ParseKid(kid)
			if float64(n) > ep {
				ep = float64(n)
			}
		}
		h, _ := seal.ParseHeader(string(r.Body))
		_, n, _ := seal.ParseKid(h.Kid)
		if float64(n) != ep {
			t.Fatalf("%s: document under epoch %d, latest key %v", ns, n, ep)
		}
		return ep
	}
	// A change that doesn't revoke doesn't rotate.
	expect(t, e.patchNS("s", ops(op("add", "/maxLag", "PT1H")), star), 201)
	if epoch("s") != 1 {
		t.Fatal("rotated without a revocation")
	}
	expect(t, e.patchNS("s", ops(op("add", "/revoked", []any{"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})), star), 201)
	if epoch("s") != 2 || epoch("sb") != 2 {
		t.Fatalf("epochs after revoke: %v %v", epoch("s"), epoch("sb"))
	}
	lg := e.get("/ns/s/rev/"+e.nsHead("s", star)+"/log?since="+e.nsHead("s", star), star)
	expect(t, lg, 200)
	// Removing a key rotates too.
	k2 := newKey("k2")
	expect(t, e.patchNS("s", ops(op("add", "/keys/-", k2.entry("read"))), star), 201)
	if epoch("s") != 2 {
		t.Fatal("adding a key rotated")
	}
	expect(t, e.patchNS("s", ops(op("remove", "/keys/1")), star), 201)
	if epoch("s") != 3 {
		t.Fatal("removing a key did not rotate")
	}
}

// $nonce is required in every patch set of a sealed namespace (§E.2.5).
func TestSealedNonce(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	expectCode(t, e.write("PATCH", "s", "a", "", addRoot(map[string]any{"v": 1.0})), 422, "invalid")
	bad := append(addRoot(map[string]any{"v": 1.0}), op("add", "/$nonce", "short"))
	expectCode(t, e.write("PATCH", "s", "a", "", bad), 422, "invalid")
	undone := append(withNonce(addRoot(map[string]any{"v": 1.0})), op("remove", "/$nonce"))
	expectCode(t, e.write("PATCH", "s", "a", "", undone), 422, "invalid")
	n := seal.NewNonce()
	a1 := e.wr("s", "a", "", append(addRoot(map[string]any{"v": 1.0}), op("add", "/$nonce", n)))
	// The same nonce again is stale.
	expectCode(t, e.write("PATCH", "s", "a", a1, ops(op("replace", "/v", 2.0), op("add", "/$nonce", n))), 422, "invalid")
	expectCode(t, e.write("PATCH", "s", "a", a1, ops(op("replace", "/v", 2.0))), 422, "invalid")
	a2 := e.wr("s", "a", a1, withNonce(ops(op("replace", "/v", 2.0))))
	tomb := e.del("s", "a", a2)
	expectCode(t, e.write("PATCH", "s", "a", tomb, ops(op("replace", "/v", 3.0))), 422, "invalid")
	e.wr("s", "a", tomb, []any{})
	// Batches too.
	r := e.do(req{method: "POST", path: "/ns/s/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"v": 1.0})}}}}})
	expect(t, r, 422)
	// Unsealed namespaces don't need one.
	e.mkNS("p", atRest(map[string]any{"read": "public"}))
	e.create("p", "a", map[string]any{"v": 1.0})
}

// A branch of a sealed namespace has its own epoch keys and seals
// read-through content under them (§E.2.5, §F.8).
func TestSealedBranch(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant"}))
	a := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": encMarker})))
	// A branch can't drop sealing.
	expectCode(t, e.branch("s", map[string]any{"name": "low", "patches": ops(op("replace", "/encryption", map[string]any{"level": "at-rest"}))}, "admin"), 422, "invalid")
	expect(t, e.branch("s", map[string]any{"name": "b"}, "admin"), 201)
	sk, _ := e.keysOf("s", nil, "")
	bk, _ := e.keysOf("b", nil, "")
	if bk["b#1"] == nil || string(bk["b#1"]) == string(sk["s#1"]) {
		t.Fatalf("branch keys %v", bk)
	}
	base := e.get("/r/s/a/rev/" + a)
	br := e.get("/r/b/a/rev/" + a)
	expect(t, br, 200)
	pt := open(t, string(br.Body), resKey(t, bk["b#1"], "b", "a"), "b#1", seal.ResourcePL("b", "a", a, "doc"))
	if want := open(t, string(base.Body), resKey(t, sk["s#1"], "s", "a"), "s#1", seal.ResourcePL("s", "a", a, "doc")); string(pt) != string(want) {
		t.Fatal("read-through plaintext differs")
	}
	if _, err := seal.OpenExpect(string(br.Body), resKey(t, sk["s#1"], "s", "a"), "b#1", seal.ResourcePL("b", "a", a, "doc")); err == nil {
		t.Fatal("the base's key opened the branch's copy")
	}
	// Stored once in the branch too; the branch's own writes use its epoch.
	if string(e.get("/r/b/a/rev/"+a).Body) != string(br.Body) {
		t.Fatal("branch bytes changed")
	}
	a2 := e.wr("b", "a", a, withNonce(ops(op("add", "/b", true))))
	open(t, string(e.get("/r/b/a/rev/"+a2).Body), resKey(t, bk["b#1"], "b", "a"), "b#1", seal.ResourcePL("b", "a", a2, "doc"))
	lg := e.get("/r/b/a/rev/" + a2 + "/log").Arr()
	open(t, lg[0].(string), resKey(t, bk["b#1"], "b", "a"), "b#1", seal.ResourcePL("b", "a", a, "rev"))

	// A sealed branch of a sealed non-public base may be public (it only
	// exposes ciphertext); a non-sealed branch of a non-public base may not.
	expect(t, e.branch("s", map[string]any{"name": "pub", "patches": ops(op("replace", "/read", "public"))}, "admin"), 201)
	if r := e.get("/r/pub/a/rev/" + a); r.Code != 200 || r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("public sealed branch %d %v", r.Code, r.H)
	}
	e.mkNS("g", atRest(map[string]any{"read": "grant"}))
	expectCode(t, e.branch("g", map[string]any{"name": "gp", "patches": ops(op("replace", "/read", "public"))}, "admin"), 422, "invalid")
	// A sealed public branch doesn't stop a sealed base from going private.
	e.mkNS("sp", sealedDoc(map[string]any{"read": "public"}))
	expect(t, e.branch("sp", map[string]any{"name": "spb"}, "admin"), 201)
	expect(t, e.patchNS("sp", ops(op("replace", "/read", "grant")), ""), 201)

	// At-rest base, sealed branch: allowed, own keys from epoch 1.
	e.mkNS("r", atRest(map[string]any{"read": "public"}))
	e.create("r", "x", map[string]any{"v": 1.0})
	expect(t, e.branch("r", map[string]any{"name": "rs", "patches": ops(op("replace", "/encryption", map[string]any{"level": "sealed"}))}, "admin"), 201)
	rk, _ := e.keysOf("rs", nil, "")
	x := e.head("r", "x")
	open(t, string(e.get("/r/rs/x/rev/"+x).Body), resKey(t, rk["rs#1"], "rs", "x"), "rs#1", seal.ResourcePL("rs", "x", x, "doc"))

	// A namespace with public dependents can't become sealed (§7.4).
	e.mkNS("pb", atRest(map[string]any{"read": "public"}))
	expect(t, e.branch("pb", map[string]any{"name": "pbb"}, "admin"), 201)
	r := e.patchNS("pb", ops(op("replace", "/encryption", map[string]any{"level": "sealed"})), "")
	expectCode(t, r, 409, "in_use")
	if deps, _ := r.Obj()["dependents"].([]any); len(deps) != 1 || deps[0] != "pbb" {
		t.Fatalf("dependents %s", r.Body)
	}
	// Once the branch is sealed, the base may be.
	expect(t, e.patchNS("pbb", ops(op("replace", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	expect(t, e.patchNS("pb", ops(op("replace", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	pk, _ := e.keysOf("pb", nil, "")
	if pk["pb#1"] == nil {
		t.Fatalf("keys after becoming sealed %v", pk)
	}

	// Purging a resource deletes its sealed copies; purging a namespace its
	// epoch keys.
	h := e.head("s", "a")
	expect(t, e.do(req{method: "POST", path: "/r/s/a/purge", ifMatch: h, author: "admin"}), 204)
	expect(t, e.get("/r/b/a/rev/"+a), 410)
}

// A sealed namespace accepts remote branch registrations: that the branch
// is sealed too is B's obligation, which A can't check (§G.5; see
// remote_enc_test.go).
func TestSealedRemoteRegistration(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	r := e.do(req{method: "POST", path: "/ns/s/branches", ifNoneMatch: "*", author: "admin",
		body: map[string]any{"remote": map[string]any{"origin": "https://b.example", "ns": "x"}, "at": e.nsHead("s")}})
	expect(t, r, 201)
}

// A prune drops the sealed copies of what it pruned; kept documents keep
// their bytes.
func TestSealedPrune(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	r1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	r2 := e.wr("s", "a", r1, withNonce(ops(op("replace", "/v", 2.0))))
	r3 := e.wr("s", "a", r2, withNonce(ops(op("replace", "/v", 3.0))))
	d1, d3 := string(e.get("/r/s/a/rev/"+r1).Body), string(e.get("/r/s/a/rev/"+r3).Body)
	e.get("/r/s/a/rev/" + r2)
	e.get("/r/s/a/rev/" + r3 + "/log")
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("s", "a", map[string]any{"horizon": r3, "keep": []any{r1}}, "admin"), 200)
	expectCode(t, e.get("/r/s/a/rev/"+r2), 410, "pruned")
	if got := string(e.get("/r/s/a/rev/" + r1).Body); got != d1 {
		t.Fatal("a kept document's bytes changed")
	}
	if got := string(e.get("/r/s/a/rev/" + r3).Body); got != d3 {
		t.Fatal("the horizon's bytes changed")
	}
	expect(t, e.get("/r/s/a/rev/"+r3+"/log?since="+r2), 200)
	expectCode(t, e.get("/r/s/a/rev/"+r3+"/log"), 410, "pruned")
}
