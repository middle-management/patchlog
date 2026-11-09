package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// §1 Conformance, §G.5.2, §12.1 (v0.76, B-63): remote branch R of A's N,
// on a server with a key store; A raises N to sealed and R's raise fails
// (its config writes are over the patch set maximum). A read of a resource
// R reads through, and a PATCH with a test op, answer 502 upstream naming
// A, without Retry-After, as for a level the server lacks, never 503 and
// never the clear; a purge still works (204).
func TestV076EncFailedRaiseIs502(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	y := a.create("m", "y", map[string]any{"v": 2.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	b = reopen(func(o *core.Options) {
		o.Limits, o.Maximums = core.DefaultLimits(), core.DefaultMaximums()
		o.Limits.PatchSetSize, o.Maximums.PatchSetSize = 128<<10, 128<<10
	})
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if l := levelOf(b.configOf("r")); l != "" {
		t.Fatalf("raised to %q although its config writes fail", l)
	}
	upstream := func(what string, r *resp) {
		t.Helper()
		expectCode(t, r, 502, "upstream")
		if r.H.Get("Retry-After") != "" || r.Str("origin") != originA {
			t.Fatalf("%s: %v %s, want 502 upstream with origin %s and no Retry-After", what, r.H, r.Body, originA)
		}
	}
	upstream("read", b.get("/r/r/x/rev/"+x))
	upstream("read through rx", b.get("/r/rx/x/rev/"+x))
	upstream("PATCH with a test op", b.write("PATCH", "r", "x", x, ops(op("test", "/v", 1.0))))
	expect(t, b.purge("r", "y", y, "admin"), 204)
}

// §E.3.2, §C.7 (v0.76): in an e2e namespace, a keyring write whose
// document carries a $nonce that isn't of the fresh form is 422 invalid;
// a fresh one is written.
func TestV076EncKeyringNonceFresh(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	_, admin, _ := seal.GenerateRecipient()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	kr, err := seal.BuildKeyringV2(admin, "e", 1, seal.NewKey(), []*ecdh.PublicKey{admin.PublicKey(), readerPub})
	if err != nil {
		t.Fatal(err)
	}
	keys := kr.Value()["keys"]
	expectCode(t, e.write("PATCH", "e", "keyring", "", addRoot(map[string]any{"keys": keys, "$nonce": "not-a-nonce"}), f.adminG), 422, "invalid")
	e.create("e", "keyring", map[string]any{"keys": keys, "$nonce": seal.NewNonce()}, f.adminG)
}

// §E.2.2 Epochs, §2.1 Protection (v0.76, B-66): a check that judges a blob
// by its epoch fixes it as a request for the blob would. Sealed source s
// with read public, raised from none, and a blob whose referencing
// revisions, written before the raise, have no epoch yet: a Blob-From
// copy by a caller with the current epoch's key succeeds, and fixes the
// newest of them under that epoch; after a rotation, GET …/blob/{bid}
// redirects to the epoch the copy fixed, never the new one.
func TestV076EncCheckFixesBlobEpoch(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{"s": {"read": "public"}})
	bid := p.blobIn("s", "a", []byte("bytes from before the raise"))
	expect(t, p.patchNS("s", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), p.star), 201)
	w := p.grant(p.k, "user:w", []string{"s"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.copyBlob("s", "b", bid, blobPath("s", "a", bid), "", w), 201)
	p.rotate("s", 2)
	g := p.get(blobPath("s", "a", bid))
	expect(t, g, 302)
	if want := blobPath("s", "a", bid) + "/e/1"; g.H.Get("Location") != want {
		t.Fatalf("redirect to %q, want %q, the epoch the copy's check fixed", g.H.Get("Location"), want)
	}
}

// §E.2.2 Epochs, §6.1 Read permission (v0.76): resolving a schema revision
// written before its namespace was sealed judges it by its epoch, and so
// fixes it: after a rotation the revision is still served under the epoch
// the write's check fixed.
func TestV076EncCheckFixesRevEpoch(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{"docs": {"read": "grant"}, "schemas": {"read": "public"}})
	x := p.wr("schemas", "match", "", withNonce(addRoot(map[string]any{"$schema": dialect, "type": "object"})), p.star)
	expect(t, p.patchNS("schemas", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), p.star), 201)
	wk := p.grant(p.k, "user:w", []string{"docs", "schemas"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.write("PATCH", "docs", "d", "", addRoot(map[string]any{"$schema": "/r/schemas/match/rev/" + x}), wk), 201)
	p.rotate("schemas", 2)
	g := p.get("/r/schemas/match/rev/" + x)
	expect(t, g, 200)
	if want := `"` + x + `.1"`; g.H.Get("ETag") != want {
		t.Fatalf("ETag %s, want %s: the epoch the write's check fixed", g.H.Get("ETag"), want)
	}
}

// §G.5.2 E3 sources (v0.76, B-65): B relays the keys of a namespace
// further up A's chain only while it can read its current namespace
// document. A's eb is a branch of e, both e2e; B's E3 remote branch rel of
// eb mirrors e's keyring too. Once B's grant at A can't read e (403) and a
// sync has tried, POST /ns/rel/keys relays none of e's entries, though eb's
// still; once a sync reads e again, they are relayed again.
func TestV076EncDeeperBaseUnreadable(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("e", e2eDoc(map[string]any{"keys": []any{kA.entry("*")}}))
	g := a.grant(kA, "user:admin", []string{"e", "eb"}, allVerbs)
	readerJWK, readerPriv, _ := seal.GenerateRecipient()
	kre, _ := seal.BuildKeyringV2(readerPriv, "e", 1, seal.NewKey(), []*ecdh.PublicKey{readerPriv.PublicKey()})
	krHead := a.create("e", "keyring", kre.Value(), g)
	expect(t, a.branch("e", map[string]any{"name": "eb"}, g), 201)
	krb, _ := seal.BuildKeyringV2(readerPriv, "eb", 1, seal.NewKey(), []*ecdh.PublicKey{readerPriv.PublicKey()})
	a.appendRev("eb", "keyring", krHead, ops(op("replace", "", krb.Value())), g)
	at := a.nsHead("eb", g)

	both := a.grant(kA, "svc:b", []string{"e", "eb"}, []string{"read"})
	rt := &route{url: a.srv.URL, bearer: both}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	kB := newKey("badmin")
	doc := e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})
	doc["base"] = map[string]any{"origin": originA, "ns": "eb", "at": at, "chain": []any{"eb", "e"}}
	expect(t, b.mkRemote("rel", addRoot(doc)), 201)
	readerG := b.grant(kB, "user:reader", []string{"rel"}, []string{"read"}, map[string]any{"enc": readerJWK})
	relayed := func(want ...string) {
		t.Helper()
		keys, r := b.keysOf("rel", nil, readerG)
		expect(t, r, 200)
		if len(keys) != len(want) {
			t.Fatalf("relayed %v, want %v", keys, want)
		}
		for _, k := range want {
			if _, ok := keys[k]; !ok {
				t.Fatalf("relayed %v, want %v", keys, want)
			}
		}
	}
	// Creation read e's current document: both keyrings are relayed.
	relayed("e#1", "eb#1")
	// B's grant at A no longer reads e: /ns/e is 403 to it.
	expectCode(t, a.get("/ns/e", a.grant(kA, "svc:b", []string{"eb"}, []string{"read"})), 403, "forbidden")
	rt.set(a.srv.URL, a.grant(kA, "svc:b", []string{"eb"}, []string{"read"}))
	_ = syncRemotes(t, b) // reports e's failed read
	relayed("eb#1")
	rt.set(a.srv.URL, both)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	relayed("e#1", "eb#1")
}

// §G.5.2 E3 sources (v0.76): B mirrors A's sealings of content from before
// its raise byte for byte and never seals that content itself. A's m,
// sealed, is raised to e2e; B's grant at A is refused (403) the document
// of x, the log of w and the epoch URL of z's blob from before the raise,
// as A might refuse them. B's remote branch r answers each of those 502
// upstream naming A, never a sealing of its own, while what A served it,
// y's document, is A's bytes.
func TestV076EncPreRaiseSealingsAreAs(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	y1 := a.wr("m", "y", "", withNonce(addRoot(map[string]any{"v": 2.0})), root())
	w1 := a.wr("m", "w", "", withNonce(addRoot(map[string]any{"v": 3.0})), root())
	data := []byte("z's blob from before the raise")
	bid := a.upload("m", "z", "text/plain", data, root())
	z1 := a.wr("m", "z", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), root()), 201)
	raised := a.nsHead("m", root())

	// Refused from the n-th request on: w's log is read once to mirror its
	// chain (fetchChain), then again for A's sealings of its entries, and
	// z's blob once with it (fetchBlobs), then for A's sealing.
	blocked := map[string]int{
		"/r/m/x/rev/" + x1:               1,
		"/r/m/w/rev/" + w1 + "/log":      2,
		blobPath("m", "z", bid) + "/e/1": 2,
	}
	var seenMu sync.Mutex
	seen := map[string]int{}
	target, _ := url.Parse(a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMu.Lock()
		seen[r.URL.Path]++
		n := seen[r.URL.Path]
		seenMu.Unlock()
		if from := blocked[r.URL.Path]; from > 0 && n >= from {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"code":"forbidden","message":"not for this grant"}`))
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)

	bJWK, bID, _ := seal.GenerateRecipient()
	var mu sync.Mutex
	id := bID
	rt := &route{url: proxy.URL, bearer: a.grant(kA, "svc:b", []string{"m"}, []string{"read", "export"}, map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})

	for _, p := range []string{"/r/r/x/rev/" + x1, "/r/r/w/rev/" + w1 + "/log", blobPath("r", "z", bid) + "/e/1"} {
		r := b.get(p, g)
		expectCode(t, r, 502, "upstream")
		if r.Str("origin") != originA {
			t.Fatalf("%s: %s, want origin %s", p, r.Body, originA)
		}
	}
	ra, rb := a.get("/r/m/y/rev/"+y1, root()), b.get("/r/r/y/rev/"+y1, g)
	expect(t, ra, 200)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("y's document: %d %.120s, want A's bytes %.120s", rb.Code, rb.Body, ra.Body)
	}
	// z's document A served: A's bytes, and its blob's head points at the
	// epoch A serves it under.
	ra, rb = a.get("/r/m/z/rev/"+z1, root()), b.get("/r/r/z/rev/"+z1, g)
	if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("z's document: %d %.120s, want A's bytes", rb.Code, rb.Body)
	}
}
