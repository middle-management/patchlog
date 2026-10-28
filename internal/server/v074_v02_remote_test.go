package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// headRows is a /heads page's rows by resource.
func headRows(t *testing.T, r *resp) map[string]map[string]any {
	t.Helper()
	expect(t, r, 200)
	out := map[string]map[string]any{}
	for _, h := range r.Obj()["heads"].([]any) {
		m := h.(map[string]any)
		out[m["resource"].(string)] = m
	}
	return out
}

// §7.4, §1 (v0.74, LEVELS-8): on a server that lacks the level its
// remote branch's source was raised to, /heads rows of the resources §1
// answers 502 for lack created, size and digest, at the branch and at a
// local branch reading through it; resources created on the branch keep
// them.
func TestV074RemoteLostHeadsFields(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	x1 := a.create("m", "x", map[string]any{"v": 1.0})
	a.create("m", "y", map[string]any{"v": 2.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	b.appendRev("r", "x", x1, ops(op("replace", "/v", 10.0)))
	b.create("r", "mine", map[string]any{"own": true})
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	b.create("rx", "local", map[string]any{"own": true})
	full := func(m map[string]any) bool { return m["created"] != nil && m["size"] != nil && m["digest"] != nil }
	for _, ns := range []string{"r", "rx"} {
		for name, row := range headRows(t, b.get("/ns/"+ns+"/rev/"+b.nsHead(ns)+"/heads")) {
			if !full(row) {
				t.Fatalf("%s before the raise: %s %v", ns, name, row)
			}
		}
	}
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	expectCode(t, b.get("/r/r/y"), 502, "upstream")
	for _, ns := range []string{"r", "rx"} {
		rows := headRows(t, b.get("/ns/"+ns+"/rev/"+b.nsHead(ns)+"/heads"))
		for _, name := range []string{"x", "y"} {
			row := rows[name]
			if row == nil || row["target"] == nil || row["created"] != nil || row["size"] != nil || row["digest"] != nil {
				t.Fatalf("%s: %s row %v, want target without created, size, digest", ns, name, row)
			}
		}
		if !full(rows["mine"]) {
			t.Fatalf("%s: own row %v", ns, rows["mine"])
		}
	}
	if !full(headRows(t, b.get("/ns/rx/rev/"+b.nsHead("rx")+"/heads"))["local"]) {
		t.Fatal("rx's own resource lost its fields")
	}
}

// v074Reopenable is v073Reopenable for more than one restart: each
// closes the deployment it last opened.
func v074Reopenable(t *testing.T, opts ...envOpt) (*tenv, func(more ...envOpt) *tenv) {
	t.Helper()
	path, blobs := v073DB(t), t.TempDir()
	at := func(o *core.Options) { o.Path, o.BlobDir = path, blobs }
	e := newEnv(t, append(append([]envOpt{}, opts...), at)...)
	return e, func(more ...envOpt) *tenv {
		t.Helper()
		e.srv.Close()
		e.e.Close()
		next := newEnv(t, append(append(append([]envOpt{}, opts...), more...), at)...)
		next.clock = e.clock
		e = next
		return next
	}
}

// §G.5.2 (v0.74, LEVELS-4): a source raised from none straight to e2e,
// which Levels refuse a branch whose at is before the raise, is followed
// as far as Levels allow, to sealed, dependents first, leaves first, and
// the branch is marked for a rebase; its resources keep answering. A's
// document is rewritten in transit, as in TestV073RemoteE2ERaiseNeedsRebase.
func TestV074RemoteE2ERaiseFollowsToSealed(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "grant"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant"})), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	expect(t, a.patchNS("m", ops(op("add", "/x-note", "raised")), ""), 201)
	raised := a.nsHead("m")
	rt.set(proxyA(t, a, nil, "/ns/m/rev/"+raised, func(body []byte) []byte {
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("A's document: %v", err)
			return body
		}
		doc["encryption"] = map[string]any{"level": "e2e", "epoch": 1.0}
		out, _ := json.Marshal(doc)
		return out
	}), "")
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"rx", "r"} {
		if l := levelOf(b.configOf(ns)); l != "sealed" {
			t.Fatalf("%s: level %q after its source's raise to e2e, want sealed", ns, l)
		}
		if g := b.get("/r/" + ns + "/x/rev/" + x); g.Code != 200 || !isJOSE(g) {
			t.Fatalf("%s: read-through content %d %s", ns, g.Code, g.Body)
		}
	}
	ls, err := b.e.RemoteLevels(context.Background(), "r")
	if err != nil || len(ls) != 1 || ls[0].Level != "e2e" || !ls[0].Rebase || ls[0].Lacks || ls[0].ID != raised {
		t.Fatalf("levels %+v %v, want e2e marked for a rebase", ls, err)
	}
}

// §1, §G.5.2 (v0.74, LEVELS-5): a remote branch answers 502 only where
// its raise needs a level its server lacks. Here the server has a key
// store but the raise's config writes fail (the deployment's patchSetSize
// maximum was lowered below what §6.6 Values needs, so no config write
// that changes encryption passes): its resources keep answering, the
// raise is recorded for a rebase, not as lacking, and the next sync tries
// it again, which succeeds once the maximum is back.
func TestV074RemoteFailedRaiseIsNot502(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	rt := &route{url: a.srv.URL}
	ks := newKeyStore(t)
	b, reopen := v074Reopenable(t, withOrigin(originB), withRemote(rt), withKeyStore(ks), withEncTuning)
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
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
	for _, p := range []string{"/r/r/x/rev/" + x, "/r/rx/x/rev/" + x} {
		expect(t, b.get(p), 200)
	}
	ls, err := b.e.RemoteLevels(context.Background(), "r")
	if err != nil || len(ls) != 1 || ls[0].Level != "sealed" || ls[0].Lacks || !ls[0].Rebase {
		t.Fatalf("levels %+v %v, want sealed, not lacking, marked for a rebase", ls, err)
	}
	// Tried again at every sync: still failing, still answering.
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	expect(t, b.get("/r/r/x/rev/"+x), 200)
	// With the maximum back, the next sync raises, leaves first.
	b = reopen()
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"rx", "r"} {
		if l := levelOf(b.configOf(ns)); l != "sealed" {
			t.Fatalf("%s: level %q after the retry, want sealed", ns, l)
		}
	}
	if g := b.get("/r/r/x/rev/" + x); g.Code != 200 || !isJOSE(g) {
		t.Fatalf("after the retry: %d %s", g.Code, g.Body)
	}
	if ls, _ := b.e.RemoteLevels(context.Background(), "r"); len(ls) != 0 {
		t.Fatalf("levels after the retry %+v", ls)
	}
}

// withOriginURL makes the endpoint of withRemote say the origin itself
// answers at url, as an endpoint that is a mirror would (§G.5.2).
func withOriginURL(url string) func(*core.RemoteOptions) {
	return func(o *core.RemoteOptions) {
		inner := o.Resolve
		o.Resolve = func(origin string) (core.RemoteEndpoint, error) {
			ep, err := inner(origin)
			ep.OriginURL = url
			return ep, err
		}
	}
}

// §G.5.2 Epoch start times (v0.74, LEVELS-6): for the keys of a source's
// epochs from before its e2e raise, which B hands out itself, B reads the
// start times only through base.origin itself. B's endpoint here is a
// mirror that serves A's API and origin but rewrites when A's epoch 2
// began (t0+1h) to t0+20m in A's namespace log, which no id covers: a
// reader whose nbf is t0+40m gets the epochs the real times select (m#1
// and m#2), not m#2 alone; where the origin can't be reached, none.
func TestV074RemoteStartTimesFromOrigin(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/encryption/epoch", 2.0)), root()), 201)
	epoch2 := a.nsHead("m", root())
	a.wr("m", "x", x1, withNonce(ops(op("replace", "/v", 2.0))), root())
	ak, kr := a.keysOf("m", nil, a.grant(kA, "user:k", []string{"m"}, []string{"read"}, map[string]any{"nbf": t0.Add(-time.Hour).Format(time.RFC3339)}))
	expect(t, kr, 200)
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 3.0})), root()), 201)
	raised := a.nsHead("m", root())

	// The mirror: A's log with epoch 2's start moved, sealed pages
	// opened and sealed again under the same header.
	fake := t0.Add(20 * time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
	rewrite := func(entries []byte) []byte {
		var es []map[string]any
		if err := json.Unmarshal(entries, &es); err != nil {
			t.Errorf("A's log page: %v", err)
			return entries
		}
		for _, e := range es {
			if e["id"] == epoch2 {
				e["created"] = fake
			}
		}
		out, _ := json.Marshal(es)
		return out
	}
	rewritten := false
	var rmu sync.Mutex
	mirror := proxyA(t, a, nil, "/ns/m/rev/"+raised+"/log", func(body []byte) []byte {
		if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("ey")) {
			return rewrite(body)
		}
		h, plain, err := seal.Open(string(bytes.TrimSpace(body)), ak[mustHeader(t, body).Kid])
		if err != nil {
			t.Errorf("A's sealed log page: %v", err)
			return body
		}
		out, err := seal.Seal(ak[h.Kid], h.Kid, h.PL, rewrite(plain))
		if err != nil {
			t.Fatal(err)
		}
		rmu.Lock()
		rewritten = true
		rmu.Unlock()
		return []byte(out)
	})

	bJWK, bID, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	readerJWK, readerPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	gone := httptest.NewServer(nil)
	gone.Close()
	for _, c := range []struct {
		name, originURL string
		want            []string
	}{
		{"origin reachable", a.srv.URL, []string{"m#1", "m#2"}},
		{"origin unreachable", gone.URL, nil},
	} {
		var mu sync.Mutex
		id := bID
		rt := &route{url: mirror, bearer: a.grant(kA, "svc:b", []string{"m"}, []string{"read", "export"}, map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
		var bPriv ed25519.PrivateKey
		b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id), withOriginURL(c.originURL)), withKeyStore(newKeyStore(t)), withEncTuning)
		b.opPriv = bPriv
		b.clock.Advance(3 * time.Hour)
		kB := newKey("badmin")
		expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
		g := b.grant(kB, "user:reader", []string{"r"}, []string{"read"}, map[string]any{"enc": readerJWK, "nbf": t0.Add(40 * time.Minute).Format(time.RFC3339)})
		_, r := b.keysOf("r", nil, g)
		got := p36Keys(t, r, func(w seal.WrappedKey) ([]byte, error) { return seal.UnwrapKey(readerPriv, w) })
		for _, kid := range []string{"m#1", "m#2"} {
			_, has := got[kid]
			if want := contains(c.want, kid); has != want {
				t.Errorf("%s: %s given %v, want %v (keys %v)", c.name, kid, has, want, got)
			} else if has && !bytes.Equal(got[kid], ak[kid]) {
				t.Errorf("%s: %s isn't the source's key", c.name, kid)
			}
		}
	}
	if !rewritten {
		t.Fatal("the mirror rewrote no sealed log page")
	}
}

func mustHeader(t *testing.T, jwe []byte) *seal.Header {
	t.Helper()
	h, err := seal.ParseHeader(string(bytes.TrimSpace(jwe)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
