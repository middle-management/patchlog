package server

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// §G.5.2 Epoch start times, E3 sources (v0.74 review of LEVELS-6): where
// base.origin can't be read, only the start times of the source's epochs
// from before its e2e raise are unknown. B still holds those keys, checks
// A's sealings with them and mirrors them verbatim, so it serves A's
// pre-raise content as A does; it hands none of the keys out until a later
// sync reads the start times from the origin itself, and then by them.
func TestV074RemoteUnknownStartsKeepKeys(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	ak, kr := a.keysOf("m", nil, a.grant(kA, "user:k", []string{"m"}, []string{"read"}, map[string]any{"nbf": t0.Add(-time.Hour).Format(time.RFC3339)}))
	expect(t, kr, 200)
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), root()), 201)
	raised := a.nsHead("m", root())
	mirror := proxyA(t, a, nil, "", nil)

	// The origin itself, unreachable until up is set.
	var up atomic.Bool
	target, _ := url.Parse(a.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "unreachable", http.StatusBadGateway)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(origin.Close)

	bJWK, bID, _ := seal.GenerateRecipient()
	var mu sync.Mutex
	id := bID
	rt := &route{url: mirror, bearer: a.grant(kA, "svc:b", []string{"m"}, []string{"read", "export"}, map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id), withOriginURL(origin.URL)), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"})

	// Served as A serves it: A's sealing, verbatim.
	ra, rb := a.get("/r/m/x/rev/"+x1, root()), b.get("/r/r/x/rev/"+x1, g)
	expect(t, ra, 200)
	expect(t, rb, 200)
	if !bytes.Equal(ra.Body, rb.Body) {
		t.Fatalf("B serves %.120s for the pre-raise x1, A %.120s", rb.Body, ra.Body)
	}

	readerJWK, readerPriv, _ := seal.GenerateRecipient()
	reader := b.grant(kB, "user:k", []string{"r"}, []string{"read"}, map[string]any{"enc": readerJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})
	keys := func() map[string][]byte {
		t.Helper()
		_, r := b.keysOf("r", nil, reader)
		return p36Keys(t, r, func(w seal.WrappedKey) ([]byte, error) { return seal.UnwrapKey(readerPriv, w) })
	}
	if got := keys(); got["m#1"] != nil {
		t.Fatalf("m#1 handed out with its start time unknown: %v", got)
	}
	// Still unreachable: still none.
	_ = syncRemotes(t, b)
	if got := keys(); got["m#1"] != nil {
		t.Fatalf("m#1 handed out after a sync that couldn't reach the origin: %v", got)
	}
	// Once the origin answers, a sync reads the start times from it.
	up.Store(true)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if got := keys(); !bytes.Equal(got["m#1"], ak["m#1"]) {
		t.Fatalf("m#1 after the origin gave its start time: %v, want the source's key", got)
	}
}

// Addendum E Levels, Invariant; §1, §G.5.2 (v0.74 review of LEVELS-5):
// once B sees its source raised to sealed and its own raise fails for a
// reason other than a lacking level, it serves none of what it had at at
// below that level: reads and writes of those resources answer 503 with
// Retry-After (not §1's 502), and their /heads rows lack created, size and
// digest; resources created on the branch are unaffected.
func TestV074RemoteFailedRaiseHeld(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt, func(o *core.RemoteOptions) { o.FollowInterval = 90 * time.Second }), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	mine := b.create("r", "mine", map[string]any{"own": true})
	expect(t, b.get("/r/r/x/rev/"+x), 200) // cached before the raise
	b = reopen(func(o *core.Options) {
		o.Limits, o.Maximums = core.DefaultLimits(), core.DefaultMaximums()
		o.Limits.PatchSetSize, o.Maximums.PatchSetSize = 128<<10, 128<<10
	})
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if ra := a.get("/r/m/x/rev/" + x); !isJOSE(ra) {
		t.Fatalf("A serves %d %s, want sealed", ra.Code, ra.Body)
	}
	for _, r := range []*resp{b.get("/r/r/x/rev/" + x), b.get("/r/r/x"), b.write("PATCH", "r", "x", x, ops(op("replace", "/v", 2.0)))} {
		expectCode(t, r, 503, "encryption_unavailable")
		if r.H.Get("Retry-After") != "90" || !strings.Contains(string(r.Body), originA) {
			t.Fatalf("held answer %v %s, want Retry-After 90 naming %s", r.H, r.Body, originA)
		}
	}
	rows := headRows(t, b.get("/ns/r/rev/"+b.nsHead("r")+"/heads"))
	if row := rows["x"]; row == nil || row["target"] == nil || row["created"] != nil || row["size"] != nil || row["digest"] != nil {
		t.Fatalf("x row %v, want target without created, size, digest", row)
	}
	if row := rows["mine"]; row["created"] == nil || row["digest"] == nil {
		t.Fatalf("own row %v", row)
	}
	expect(t, b.get("/r/r/mine/rev/"+mine), 200)
	b.appendRev("r", "mine", mine, ops(op("replace", "/own", false)))
}
