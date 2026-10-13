package server

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// purgeAs freezes ns and purges it, as bearer when authentication is on,
// returning the purge-ns entry's ns_id. Unlike nsPurge it reads no log,
// which a purged sealed namespace no longer serves.
func (e *tenv) purgeAs(ns, bearer string) string {
	e.t.Helper()
	expect(e.t, e.patchNS(ns, ops(op("add", "/frozen", true)), bearer), 201)
	expect(e.t, e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns, bearer), bearer: bearer, author: "admin"}), 204)
	return e.nsHead(ns, bearer)
}

// v0.51 §8.5, §E.2.2: in a sealed namespace the purge destroys the epoch
// keys that seal its namespace documents and log ranges, so those reads,
// events and long-polls included, answer 410 purged with head, at any
// revision and before the 404 of an id not in the chain; the 410s of
// cacheable reads are long, as any purge (§9). GET /ns/{ns} still
// redirects, to a revision that is 410. At rest only, the documents and
// log stay readable in the clear.
func TestV051PurgedSealed(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	e.mkNS("r", atRest(map[string]any{"read": "public"}))
	for _, ns := range []string{"s", "r"} {
		e.wr(ns, "a", "", withNonce(addRoot(map[string]any{"v": encMarker})))
	}
	before := e.nsHead("s")
	// Sealed and stored before the purge, which deletes them with the keys.
	expect(t, e.get("/ns/s/rev/"+before), 200)
	expect(t, e.get("/ns/s/rev/"+before+"/log"), 200)
	head := e.purgeAs("s", "")
	unknown := hashID(t, "", nil)

	// GET /ns/{ns} redirects to the purge, which is 410.
	r := e.get("/ns/s")
	expect(t, r, 302)
	if loc := r.H.Get("Location"); loc != "/ns/s/rev/"+head {
		t.Fatalf("Location %s, want the purge %s", loc, head)
	}
	expectPurged(t, e.get(r.H.Get("Location")), head)
	r = e.get("/ns/s/log")
	expect(t, r, 302)
	expectPurged(t, e.get(r.H.Get("Location")), head)

	for _, p := range []string{
		"/ns/s/rev/" + before,
		"/ns/s/rev/" + unknown,
		"/ns/s/rev/" + head + "/log",
		"/ns/s/rev/" + head + "/log?since=" + before,
		"/ns/s/rev/" + before + "/log",
		"/ns/s/rev/" + unknown + "/log",
		"/ns/s/rev/" + head + "/log?since=" + unknown,
	} {
		r := e.get(p)
		expectPurged(t, r, head)
		if cc := r.H.Get("Cache-Control"); cc != ccLong {
			t.Errorf("%s: Cache-Control %q, want %q", p, cc, ccLong)
		}
	}
	for _, p := range []string{
		"/ns/s/log?live=long-poll",
		"/ns/s/log?live=long-poll&since=" + before,
		"/ns/s/events",
		"/ns/s/events?since=" + before,
		"/r/s/a/events",
	} {
		expectPurged(t, e.get(p), head)
	}
	if cc := e.get("/ns/s/events").H.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("events: Cache-Control %q", cc)
	}

	// At rest only: the log is served in the clear, its purge-ns entry last.
	rHead := e.purgeAs("r", "")
	expect(t, e.get("/ns/r/rev/"+rHead), 200)
	if k := e.nsKinds("r"); lastOf(k) != "purge-ns" {
		t.Fatalf("at-rest log %v", k)
	}
}

// v0.51 §8.5: the 410 comes after the full read check, so the purge of a
// sealed namespace shows only to a grant that may read its log: 401
// without a grant, 404 without read, then 410 at any revision.
func TestV051PurgedSealedReadCheck(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"encryption": map[string]any{"level": "sealed"}}, withKeyStore(newKeyStore(t)), withEncTuning)
	e := f.tenv
	e.wr("sec", "a", "", withNonce(addRoot(map[string]any{})), f.adminG)
	before := e.nsHead("sec", f.adminG)
	head := e.purgeAs("sec", f.adminG)
	writer := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"})
	reader := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"})
	for _, p := range []string{"/ns/sec/rev/" + before, "/ns/sec/rev/" + head + "/log", "/ns/sec/log?live=long-poll", "/ns/sec/events"} {
		expectCode(t, e.get(p), 401, "unauthenticated")
		expectCode(t, e.get(p, writer), 404, "not_found")
		expectPurged(t, e.get(p, reader), head)
	}
	r := e.get("/ns/sec", reader)
	expect(t, r, 302)
	if etagOf(r) != head {
		t.Fatalf("head %s, want %s", etagOf(r), head)
	}
}

// v0.51 §8.5, §G.3: a remote branch of a sealed base learns of the base's
// purge from the 410 purged of its log, whose head stands in for the
// purge-ns entry: every name the base had is purged here, the branch's own
// stay, and following again changes nothing.
func TestV051RemoteSealedBasePurged(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := a.grant(kA, "user:root", []string{"s"}, allVerbs)
	a.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": encMarker})), root)
	at := a.nsHead("s", root)
	bJWK, bPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bPriv
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"s"}, []string{"read", "export"}, map[string]any{"enc": bJWK})}
	b := newEnv(t, withOrigin(originB), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning)
	expect(t, b.mkRemote("rel", remoteGenesis("s", at, map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})), 201)
	b.wr("rel", "mine", "", withNonce(addRoot(map[string]any{})))
	ctx := context.Background()
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}

	head := a.purgeAs("s", root)
	expectPurged(t, a.get("/ns/s/rev/"+head+"/log?since="+at, rt.bearer), head)
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	expect(t, b.get("/r/rel/x"), 410)
	expect(t, b.get("/r/rel/mine"), 302)
	ns, err := b.e.RemoteNotices(ctx, "rel")
	if err != nil || len(ns) != 1 || ns[0].Kind != "purge-ns" || ns[0].ID != head || !ns[0].Applied {
		t.Fatalf("notices %+v %v", ns, err)
	}
	h := b.nsHead("rel")
	if err := b.e.SyncRemotes(ctx); err != nil || b.nsHead("rel") != h {
		t.Fatalf("second sync: %v", err)
	}
}
