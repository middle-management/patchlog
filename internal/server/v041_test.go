package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/sig"
)

const testOrigin = "https://cms.example"

func sigKey(kid string, seed byte) sig.Key {
	s := make([]byte, 32)
	s[0] = seed
	return sig.Key{Kid: kid, Priv: ed25519.NewKeyFromSeed(s)}
}

func pid(t *testing.T, s string) *ids.ID {
	t.Helper()
	if s == "" {
		return nil
	}
	id, err := ids.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return &id
}

// signP signs a write of ns/name on parent ("" for a genesis) with patches.
func signP(t *testing.T, k sig.Key, ns, name, parent string, patches []any) string {
	return k.SignPatches(testOrigin, ns, name, pid(t, parent), canonical(patches))
}

// signT signs a tombstone of ns/name on parent.
func signT(t *testing.T, k sig.Key, ns, name, parent string) string {
	return k.SignTombstone(testOrigin, ns, name, *pid(t, parent))
}

// swrite is write with a Signature header ("" for none).
func (e *tenv) swrite(method, ns, name, parent string, patches []any, bearer, signature string) *resp {
	e.t.Helper()
	q := req{method: method, path: "/r/" + ns + "/" + name, ifMatch: parent, bearer: bearer}
	if parent == "" {
		q.ifNoneMatch = "*"
	}
	if patches != nil {
		q.body = patches
	}
	if signature != "" {
		q.hdr = map[string]string{"Signature": signature}
	}
	return e.do(q)
}

// lastLog is the newest entry of a resource's log.
func (e *tenv) lastLog(ns, name, id, bearer string) map[string]any {
	e.t.Helper()
	r := e.get("/r/"+ns+"/"+name+"/rev/"+id+"/log", bearer)
	expect(e.t, r, 200)
	arr := r.Arr()
	return arr[len(arr)-1].(map[string]any)
}

func grantIDOf(t *testing.T, token string) string {
	t.Helper()
	g, err := grant.Decode(token, 0)
	if err != nil {
		t.Fatal(err)
	}
	return g.ID().String()
}

// §C.3.1 (v0.41): a signature whose kid the grant lists is verified at
// the gate; others are stored unverified; logs serve grant and signature.
func TestV041Signatures(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	k1, other := sigKey("k1", 1), sigKey("other", 2)
	g := e.grant(f.issuer, "user:alice", []string{"sec", "sec-b"}, []string{"read", "create", "append", "restore", "delete"},
		map[string]any{"signers": []any{k1.Entry()}})

	gen := addRoot(map[string]any{"t": "x"})
	r := e.swrite("PATCH", "sec", "a", "", gen, g, signP(t, k1, "sec", "a", "", gen))
	expect(t, r, 201)
	a0 := etagOf(r)
	if r.Str("signature") == "" {
		t.Fatalf("write response without signature: %s", r.Body)
	}
	le := e.lastLog("sec", "a", a0, g)
	gr, _ := le["grant"].(map[string]any)
	if le["signature"] != signP(t, k1, "sec", "a", "", gen) || gr == nil || gr["id"] != grantIDOf(t, g) || gr["sub"] != "user:alice" || gr["kid"] != "issuer" {
		t.Fatalf("log entry %v", le)
	}

	// A bad signature by a listed signer: 422, nothing written.
	p1 := ops(op("add", "/y", "1"))
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p1, g, signP(t, k1, "sec", "a", a0, ops(op("add", "/y", "2")))), 422, "signature")
	// Bound to the resource, namespace and parent.
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p1, g, signP(t, k1, "sec", "b", a0, p1)), 422, "signature")
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p1, g, signP(t, k1, "sec", "a", "", p1)), 422, "signature")
	if h := e.head("sec", "a", g); h != a0 {
		t.Fatalf("head moved to %s", h)
	}
	// Malformed: 400.
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p1, g, "Ed25519:k1"), 400, "bad_input")
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p1, g, "Ed25519:k1:not base64!"), 400, "bad_input")

	// An unlisted kid is stored unverified, and served.
	junk := other.SignPatches(testOrigin, "sec", "zzz", nil, []byte("[]"))
	r = e.swrite("PATCH", "sec", "a", a0, p1, g, junk)
	expect(t, r, 201)
	a1 := etagOf(r)
	if le := e.lastLog("sec", "a", a1, g); le["signature"] != junk {
		t.Fatalf("unverified signature not stored: %v", le)
	}
	// Checked at step 2.3, before the precondition comparison (§6.2), on
	// the parent If-Match names: with a stale If-Match, a signature that
	// doesn't verify is 422, one that does 412.
	p3 := ops(op("add", "/w", "3"))
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p3, g, signP(t, k1, "sec", "a", a0, p1)), 422, "signature")
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p3, g, signP(t, k1, "sec", "a", a0, p3)), 412, "stale")
	// Unsigned writes are fine in an optional namespace.
	a2 := e.appendRev("sec", "a", a1, ops(op("add", "/z", "1")), g)

	// Tombstones: signed over "tombstone", so a delete's signature can't
	// pass for an empty append's, nor the other way round.
	tsig := signT(t, k1, "sec", "a", a2)
	expectCode(t, e.swrite("PATCH", "sec", "a", a2, []any{}, g, tsig), 422, "signature")
	expectCode(t, e.swrite("DELETE", "sec", "a", a2, nil, g, signP(t, k1, "sec", "a", a2, []any{})), 422, "signature")
	r = e.swrite("DELETE", "sec", "a", a2, nil, g, tsig)
	expect(t, r, 200)
	tomb := r.Str("tombstone")
	if le := e.lastLog("sec", "a", tomb, g); le["kind"] != "tombstone" || le["signature"] != tsig || le["grant"] == nil {
		t.Fatalf("tombstone entry %v", le)
	}

	// Batches: the header is 400; each step carries its own signature,
	// over the id the step before it produces.
	s0 := addRoot(map[string]any{"n": "1"})
	s1 := ops(op("replace", "/n", "2"))
	id0 := ids.Revision(nil, canonical(s0))
	q := req{method: "POST", path: "/ns/sec/batch", bearer: g, hdr: map[string]string{"Signature": signP(t, k1, "sec", "c", "", s0)},
		body: map[string]any{"items": []any{map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{s0}}}}}
	expectCode(t, e.do(q), 400, "bad_input")
	good := map[string]any{"items": []any{map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{
		map[string]any{"patches": s0, "signature": signP(t, k1, "sec", "c", "", s0)},
		map[string]any{"patches": s1, "signature": signP(t, k1, "sec", "c", id0.String(), s1)},
	}}}}
	bad := map[string]any{"items": []any{map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{
		map[string]any{"patches": s0, "signature": signP(t, k1, "sec", "c", "", s0)},
		map[string]any{"patches": s1, "signature": signP(t, k1, "sec", "c", "", s1)}, // wrong parent
	}}}}
	r = e.batchReq("sec", bad, g)
	expectCode(t, r, 422, "batch")
	if it := r.Obj()["items"].([]any)[0].(map[string]any); it["code"] != "signature" {
		t.Fatalf("batch failure %s", r.Body)
	}
	r = e.batchReq("sec", good, g)
	expect(t, r, 201)
	c1 := e.head("sec", "c", g)
	lg := e.get("/r/sec/c/rev/"+c1+"/log", g).Arr()
	if len(lg) != 2 || lg[0].(map[string]any)["signature"] != signP(t, k1, "sec", "c", "", s0) ||
		lg[1].(map[string]any)["signature"] != signP(t, k1, "sec", "c", id0.String(), s1) {
		t.Fatalf("batch step signatures %v", lg)
	}

	// Narrowing blocks can't carry signers (401), so a holder can't add a
	// key of its own.
	root, err := grant.Decode(e.grant(f.issuer, "user:carol", []string{"sec"}, []string{"read", "create"}), 0)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := root.NarrowUnvalidated(map[string]any{"signers": []any{k1.Entry()}})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.swrite("PATCH", "sec", "d", "", gen, nb.Encode(), signP(t, k1, "sec", "d", "", gen)), 401)
}

// §C.3.1 (v0.41): "signatures": "required".
func TestV041RequiredSignatures(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	k1 := sigKey("k1", 1)
	g := e.grant(f.issuer, "user:alice", []string{"sec", "sec-b"}, []string{"read", "create", "append", "restore", "delete", "config"},
		map[string]any{"signers": []any{k1.Entry()}})
	gen := addRoot(map[string]any{})
	a0 := e.create("sec", "a", map[string]any{}, g)

	// Validated, and guarded by a * key.
	expectCode(t, e.patchNS("sec", ops(op("add", "/signatures", "maybe")), f.adminG), 422, "invalid")
	expectCode(t, e.patchNS("sec", ops(op("add", "/signatures", "required")), f.issuerG), 403, "forbidden")
	expect(t, e.patchNS("sec", ops(op("add", "/signatures", "required")), f.adminG), 201)

	// Unsigned writes and deletes: 422.
	p := ops(op("add", "/x", "1"))
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p, g, ""), 422, "signature")
	expectCode(t, e.swrite("PATCH", "sec", "b", "", gen, g, ""), 422, "signature")
	expectCode(t, e.swrite("DELETE", "sec", "a", a0, nil, g, ""), 422, "signature")
	// A kid the grant doesn't list doesn't count.
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p, g, sigKey("x", 9).SignPatches(testOrigin, "sec", "a", pid(t, a0), canonical(p))), 422, "signature")
	// Nor does a grant without signers.
	expectCode(t, e.swrite("PATCH", "sec", "a", a0, p, f.issuerG, signP(t, k1, "sec", "a", a0, p)), 422, "signature")
	// Signed by a listed signer: accepted.
	r := e.swrite("PATCH", "sec", "a", a0, p, g, signP(t, k1, "sec", "a", a0, p))
	expect(t, r, 201)
	a1 := etagOf(r)
	expect(t, e.swrite("DELETE", "sec", "a", a1, nil, g, signT(t, k1, "sec", "a", a1)), 200)

	// Batch steps: every step needs one.
	s0 := addRoot(map[string]any{"n": "1"})
	s1 := ops(op("replace", "/n", "2"))
	id0 := ids.Revision(nil, canonical(s0))
	half := map[string]any{"items": []any{map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{
		map[string]any{"patches": s0, "signature": signP(t, k1, "sec", "c", "", s0)}, s1,
	}}}}
	r = e.batchReq("sec", half, g)
	expectCode(t, r, 422, "batch")
	if it := r.Obj()["items"].([]any)[0].(map[string]any); it["code"] != "signature" {
		t.Fatalf("batch failure %s", r.Body)
	}
	full := map[string]any{"items": []any{map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{
		map[string]any{"patches": s0, "signature": signP(t, k1, "sec", "c", "", s0)},
		map[string]any{"patches": s1, "signature": signP(t, k1, "sec", "c", id0.String(), s1)},
	}}}}
	expect(t, e.batchReq("sec", full, g), 201)

	// Judged against the configuration the batch's config change produces.
	expect(t, e.patchNS("sec", ops(op("replace", "/signatures", "optional")), f.adminG), 201)
	turnOn := func(steps ...any) map[string]any {
		return map[string]any{"config": map[string]any{"ifMatch": e.configID("sec", f.adminG), "patches": ops(op("replace", "/signatures", "required"))},
			"items": []any{map[string]any{"resource": "d", "ifNoneMatch": "*", "steps": steps}}}
	}
	r = e.batchReq("sec", turnOn(gen), f.adminG)
	expectCode(t, r, 422, "batch")
	ak := sigKey("ak", 3)
	ag := e.grant(f.admin, "user:root", []string{"sec", "sec-b"}, allVerbs, map[string]any{"signers": []any{ak.Entry()}})
	expect(t, e.batchReq("sec", turnOn(map[string]any{"patches": gen, "signature": signP(t, ak, "sec", "d", "", gen)}), ag), 201)

	// In a branch, changing it needs a * key of the base.
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("replace", "/signatures", "optional"))}, f.issuerG), 403, "forbidden")
	expect(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("replace", "/signatures", "optional"))}, f.adminG), 201)
	// Namespace documents aren't signed: config writes need no signature.
	expect(t, e.patchNS("sec", ops(op("add", "/x-note", "n")), f.issuerG), 201)

	// With authentication disabled no grant lists signers, so every
	// resource write to such a namespace fails.
	d := newEnv(t)
	d.mkNS("req", map[string]any{"signatures": "required"})
	expectCode(t, d.write("PATCH", "req", "a", "", gen), 422, "signature")
}

// §C.3.1 (v0.41): GET /ns/{ns}/grants/{gid}.
func TestV041Grants(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	g := e.grant(f.issuer, "user:alice", []string{"sec", "sec-b"}, []string{"read", "create", "append"})
	a0 := e.create("sec", "a", map[string]any{}, g)
	gid := grantIDOf(t, g)

	r := e.get("/ns/sec/grants/"+gid, f.adminG)
	expect(t, r, 200)
	if cc := r.H.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("cache-control %q", cc)
	}
	m := r.Obj()
	dg, _ := grant.Decode(g, 0)
	root, _ := m["root"].(map[string]any)
	stored, _ := m["stored"].([]any)
	if m["id"] != gid || root["sub"] != "user:alice" || root["kid"] != "issuer" || len(stored) != 1 {
		t.Fatalf("grant %s", r.Body)
	}
	if string(canonical(root)) != string(canonical(dg.Blocks[0].Raw)) {
		t.Fatalf("root %v", root)
	}
	sb, err := base64.RawURLEncoding.DecodeString(stored[0].(string))
	if err != nil || string(sb) != string(dg.SignedBlocks()[0]) {
		t.Fatalf("stored %v %v", stored, err)
	}
	// The resource log references it.
	if le := e.lastLog("sec", "a", a0, g); le["grant"].(map[string]any)["id"] != gid {
		t.Fatalf("log %v", le)
	}
	// A grant not recorded here, or a malformed id: 404.
	expectCode(t, e.get("/ns/sec/grants/"+grantIDOf(t, f.svcGrant(e)), f.adminG), 404, "not_found")
	expect(t, e.get("/ns/sec/grants/nope", f.adminG), 404)
	// It needs read.
	expect(t, e.get("/ns/sec/grants/"+gid), 401)

	// A local branch serves its bases' grants up to its at, and its own.
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.adminG), 201)
	expect(t, e.get("/ns/sec-b/grants/"+gid, f.adminG), 200)
	h := e.grant(f.issuer, "user:hal", []string{"sec", "sec-b"}, []string{"read", "create", "append"})
	e.create("sec-b", "h", map[string]any{}, h)
	expect(t, e.get("/ns/sec-b/grants/"+grantIDOf(t, h), f.adminG), 200)
	expect(t, e.get("/ns/sec/grants/"+grantIDOf(t, h), f.adminG), 404)
	j := e.grant(f.issuer, "user:jo", []string{"sec", "sec-b"}, []string{"read", "create", "append"})
	e.create("sec", "j", map[string]any{}, j)
	expect(t, e.get("/ns/sec/grants/"+grantIDOf(t, j), f.adminG), 200)
	expect(t, e.get("/ns/sec-b/grants/"+grantIDOf(t, j), f.adminG), 404) // after the branch's at

	// Sealed and end-to-end namespaces serve them too (v0.42,
	// TestV042Grants).
}

func (f *authFixture) svcGrant(e *tenv) string {
	return e.grant(f.svc, "svc:x", []string{"sec"}, []string{"read"})
}

// §C.4 (v0.41): the operator key history as a JWK Set at jwks_uri.
func TestV041OperatorKeys(t *testing.T) {
	retired := sigKey("old", 7)
	var opPriv ed25519.PrivateKey
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := newEnv(t, withAuth(&opPriv), func(o *core.Options) {
		o.OperatorKeyHistory = []core.OperatorKeyPeriod{{Kid: "old", Pub: retired.Priv.Public().(ed25519.PublicKey), From: from, Until: until}}
	})
	e.opPriv = opPriv
	r := e.get("/")
	expect(t, r, 200)
	if r.Str("jwks_uri") != testOrigin+"/.well-known/patchlog-keys" {
		t.Fatalf("GET / %s", r.Body)
	}
	r = e.get("/.well-known/patchlog-keys")
	expect(t, r, 200)
	keys, _ := r.Obj()["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("jwks %s", r.Body)
	}
	old, cur := keys[0].(map[string]any), keys[1].(map[string]any)
	pold, _ := old["patchlog"].(map[string]any)
	if old["kid"] != "old" || old["kty"] != "OKP" || old["crv"] != "Ed25519" || old["use"] != "sig" ||
		old["x"] != base64.RawURLEncoding.EncodeToString(retired.Priv.Public().(ed25519.PublicKey)) ||
		pold["from"] != "2025-01-01T00:00:00Z" || pold["until"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("retired key %v", old)
	}
	pcur, _ := cur["patchlog"].(map[string]any)
	if cur["kid"] != "operator" || cur["x"] != base64.RawURLEncoding.EncodeToString(opPriv.Public().(ed25519.PublicKey)) ||
		pcur["from"] != t0.Format(time.RFC3339) || pcur["until"] != nil {
		t.Fatalf("operator key %v", cur)
	}
	// A retired key is published but doesn't create namespaces.
	og := mint(t, retired.Priv, map[string]any{"kid": "old", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, e.do(req{method: "PATCH", path: "/ns/n", ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: og}), 401)

	// A configured jwks_uri is published instead.
	o := newEnv(t, func(o *core.Options) { o.JWKSURI = "https://keys.example/jwks" })
	if r := o.get("/"); r.Str("jwks_uri") != "https://keys.example/jwks" {
		t.Fatalf("GET / %s", r.Body)
	}
	// A kid of the history naming another key than the operator key's is
	// refused at startup.
	var o2 core.Options
	withAuth(new(ed25519.PrivateKey))(&o2)
	o2.Path = ":memory:"
	o2.OperatorKeyHistory = []core.OperatorKeyPeriod{{Kid: "operator", Pub: retired.Priv.Public().(ed25519.PublicKey), From: from}}
	if eng, err := core.Open(o2); err == nil {
		eng.Close()
		t.Fatal("a reused kid was accepted")
	}
}
