package server

import (
	"testing"
)

// purgeAs freezes ns and purges it, as bearer when authentication is on,
// returning the purge-ns entry's ns_id. Unlike nsPurge it reads no log,
// which a purged sealed namespace no longer serves.
func (e *tenv) purgeAs(ns, bearer string) string {
	e.t.Helper()
	expect(e.t, e.patchNS(ns, ops(op("add", "/frozen", true)), bearer), 201)
	r := e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns, bearer), bearer: bearer, author: "admin"})
	expect(e.t, r, 204)
	return r.H.Get("X-Namespace-Revision")
}

// v0.51 §8.5, §E.2.2: in a sealed namespace the purge destroys the epoch
// keys that seal its namespace documents and log ranges, so those reads,
// events and long-polls included, answer 410 purged with head, at any
// revision and before the 404 of an id not in the chain; the 410s of
// cacheable reads are long, as any purge (§9). Since v0.91 so does
// GET /ns/{ns}, and an at-rest namespace's, sealed or not (§5).
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

	expectPurged(t, e.get("/ns/s"), head)
	expectPurged(t, e.get("/ns/s/log"), head)

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

	// At rest only: the same, nothing of it being left (v0.91).
	rHead := e.purgeAs("r", "")
	expectPurged(t, e.get("/ns/r/rev/"+rHead), rHead)
	expectPurged(t, e.get("/ns/r"), rHead)
}

// v0.51 §8.5, as v0.91 answers it: the 410 comes before any read check, so
// the purge of a sealed namespace shows to any request, without a grant
// and without read too, which until v0.91 got 401 and 403.
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
		expectPurged(t, e.get(p), head)
		expectPurged(t, e.get(p, writer), head)
		expectPurged(t, e.get(p, reader), head)
	}
	expectPurged(t, e.get("/ns/sec", reader), head)
}
