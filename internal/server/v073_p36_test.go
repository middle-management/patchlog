package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// P36 LEVELS-KEYS-BRANCHES: keys and remote branches after a raise to e2e
// (Addendum E Levels, §E.2.3, §G.3, §G.5.2).

// p36Keys is a 200 /keys answer's entries, unwrapped with priv, by kid
// ("kid name" for a K_r).
func p36Keys(t *testing.T, r *resp, unwrap func(seal.WrappedKey) ([]byte, error)) map[string][]byte {
	t.Helper()
	expect(t, r, 200)
	out := map[string][]byte{}
	for _, x := range keyEntries(t, r) {
		w, err := seal.ParseWrappedKey(x)
		if err != nil {
			t.Fatal(err)
		}
		label := w.Kid
		if w.Resource != "" {
			label += " " + w.Resource
		}
		k, err := unwrap(w)
		if err != nil {
			t.Fatalf("unwrapping %s: %v", label, err)
		}
		out[label] = k
	}
	return out
}

// v0.73 §G.3 Reading through, §G.5.2 Epoch start times, Addendum E Levels
// (MF-37, ENC-42; CONFORMANCE Levels scenarios 5 and 34): a remote branch
// of an E3 source raised from sealed mirrors the history from before the
// raise. It takes the source's epochs before the raise and their start
// times from the source's own log, fetches their keys from the source's
// POST /ns/{ns}/keys with its own grant, and its /keys gives them as at
// E2: K_e, or K_r derived with the source's ns, kids naming the source,
// for the base epochs §E.2.3 selects as at E2 (from the one in force at
// the reader's latest nbf; without nbf, the last epoch before the raise).
//
// A here is a sealed namespace whose last config entry this test's proxy
// serves as the e2e document of a raise from sealed (epoch 3); B reads
// A's documents only from A, so what B does is that of a branch of a
// raised source, whose pre-raise content A serves sealed as before the
// raise. TestV073W4IntRemoteBranchOfRaisedSource makes that raise at A
// for real, now that servers make it (P35).
func TestV073P36RemotePreRaiseKeys(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant"}))
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/encryption/epoch", 2.0)), ""), 201) // epoch 2 from t0+1h
	x2 := a.wr("m", "x", x1, withNonce(ops(op("replace", "/v", 2.0))))
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/x-raise", true)), ""), 201) // "e2e" epoch 3 from t0+2h
	raised := a.nsHead("m")
	raisedDoc, _ := json.Marshal(map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "epoch": 3.0}})
	ak, _ := a.keysOf("m", nil, "")

	var bPriv ed25519.PrivateKey
	rt := &route{}
	rt.set(proxyA(t, a, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/ns/m/rev/"+raised {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raisedDoc)
		return true
	}, "", nil), "")
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)

	readerJWK, readerPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	unwrap := func(w seal.WrappedKey) ([]byte, error) { return seal.UnwrapKey(readerPriv, w) }
	reader := func(extra ...map[string]any) string {
		return b.grant(kB, "user:reader", []string{"r"}, []string{"read"}, append(extra, map[string]any{"enc": readerJWK})...)
	}
	nbf := func(d time.Duration) map[string]any { return map[string]any{"nbf": t0.Add(d).Format(time.RFC3339)} }
	for name, c := range map[string]struct {
		grant string
		want  []string
	}{
		"no nbf: the last of the source's pre-raise epochs": {reader(), []string{"m#2"}},
		"nbf before the source's first epoch":               {reader(nbf(-time.Hour)), []string{"m#1", "m#2"}},
		"nbf in epoch 2, by the source's start times":       {reader(nbf(90 * time.Minute)), []string{"m#2"}},
	} {
		_, r := b.keysOf("r", nil, c.grant)
		got := p36Keys(t, r, unwrap)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
			continue
		}
		for _, kid := range c.want {
			if !bytes.Equal(got[kid], ak[kid]) {
				t.Errorf("%s: %s isn't the source's key", name, kid)
			}
		}
	}
	// A grant whose rules fix names gets K_r derived with the source's ns.
	fixX := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "x"}}}
	_, r := b.keysOf("r", nil, reader(nbf(-time.Hour), fixX))
	got := p36Keys(t, r, unwrap)
	want, _ := seal.ResourceKey(ak["m#1"], "m", "x")
	if len(got) != 2 || !bytes.Equal(got["m#1 x"], want) {
		t.Fatalf("per-resource pre-raise keys %v", got)
	}

	// The mirror records the raise where the source's log has it: a
	// prune snapshot in the branch of the source's pre-raise content is
	// sealed under the epoch the source serves it under, kid naming the
	// source (§E.3.1, snapshotKid).
	prune := func(kid string) *resp {
		jwe, err := seal.SealSnapshot(seal.NewKey(), kid, "r", "x", x2, map[string]any{"v": 2.0})
		if err != nil {
			t.Fatal(err)
		}
		return b.prune("r", "x", map[string]any{"horizon": x2, "snapshot": jwe}, b.grant(kB, "user:admin", []string{"r"}, allVerbs))
	}
	expectCode(t, prune("r#1"), 422, "invalid")
	expect(t, prune("m#2"), 200)
}

// v0.73 §E.2.3, §G.5.2 (ENC-18, remote half): a remote branch of an E3
// source relays the source's keyring entries for the base epochs §E.2.3
// selects: up to the one in force at at, and for a grant without nbf the
// epoch the source has in force now, which the follower learns from the
// source's log, so none once the source has moved past its epoch at at.
// The request's epochs don't select among them.
func TestV073P36RemoteBaseEpochNow(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("e", e2eDoc(map[string]any{"read": "grant"}))
	readerJWK, readerPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	readerPub := readerPriv.PublicKey()
	kr, err := seal.BuildKeyringV2(readerPriv, "e", 1, seal.NewKey(), []*ecdh.PublicKey{readerPub})
	if err != nil {
		t.Fatal(err)
	}
	head := a.create("e", "keyring", kr.Value(), "admin")
	at := a.nsHead("e")

	var bPriv ed25519.PrivateKey
	rt := &route{url: a.srv.URL}
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	kB := newKey("badmin")
	expect(t, b.mkRemote("rel", remoteGenesis("e", at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	reader := func(extra ...map[string]any) string {
		return b.grant(kB, "user:reader", []string{"rel"}, []string{"read"}, append(extra, map[string]any{"enc": readerJWK})...)
	}
	early := map[string]any{"nbf": t0.Add(-time.Hour).Format(time.RFC3339)}
	kids := func(body map[string]any, g string) string {
		t.Helper()
		_, r := b.keysOf("rel", body, g)
		return kidsOf(t, r)
	}
	if got := kids(nil, reader()); got != "e#1" {
		t.Fatalf("no nbf, source at its epoch at at: %q", got)
	}
	// The source rotates to epoch 2, keyring and epoch in one batch.
	if err := kr.Add(readerPriv, readerPub, "e#2", seal.NewKey()); err != nil {
		t.Fatal(err)
	}
	expect(t, a.do(req{method: "POST", path: "/ns/e/batch", author: "admin", body: map[string]any{
		"config": map[string]any{"ifMatch": a.configID("e"), "patches": ops(op("add", "/encryption/epoch", 2.0))},
		"items":  []any{map[string]any{"resource": "keyring", "ifMatch": head, "steps": []any{ops(op("replace", "", kr.Value()))}}}}}), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if got := kids(nil, reader()); got != "" {
		t.Errorf("no nbf, source past its epoch at at: %q, want none", got)
	}
	if got := kids(map[string]any{"epochs": []any{2}}, reader(early)); got != "e#1" {
		t.Errorf("nbf before the source's first epoch, after its rotation: %q, want its epoch at at alone", got)
	}
}

// v0.73 §G.5.2, Addendum E Levels (ENC-45, e2e half; CONFORMANCE Levels
// 25, 31): a remote branch MUST raise its level when it sees its source
// do so, as far as Levels allow, and rebase where they refuse the raise.
// A raise to e2e seen after at is one Levels refuse, so the branch is
// marked for a rebase, but it follows as far as they allow: to the level
// the source had before the raise, at which the source goes on serving
// what the branch reads through, where the branch missed it, as the
// follower before v0.73 did, which skipped config entries. Its local
// dependents are raised first.
//
// A raises m to sealed, then makes an entry this test's proxy serves as
// the e2e document of a raise from sealed. B's follower, as the one before
// v0.73 left it, has its checkpoint at that entry.
func TestV073P36RemoteE2ERaiseAsFarAsLevelsAllow(t *testing.T) {
	t.Parallel()
	path, blobs := v073DB(t), t.TempDir()
	ksB := newKeyStore(t)
	at := func(o *core.Options) { o.Path, o.BlobDir = path, blobs }
	a, b, rt := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withKeyStore(ksB), withEncTuning, at})
	a.mkNS("m", map[string]any{"read": "grant"})
	x1 := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant"})), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	expect(t, a.patchNS("m", ops(op("add", "/x-raise", true)), ""), 201)
	raised := a.nsHead("m")
	raisedDoc, _ := json.Marshal(map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "epoch": 2.0}})
	rt.set(proxyA(t, a, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/ns/m/rev/"+raised {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raisedDoc)
		return true
	}, "", nil), "")
	b.srv.Close()
	b.e.Close()
	db, q := v073SQL(t, path)
	for _, c := range []struct {
		s    string
		args []any
	}{
		{`UPDATE remote_bases SET checkpoint = ? WHERE ns = ?`, []any{raised, "m"}},
		{`DELETE FROM migrations WHERE name = 'remote-levels-catch-up'`, nil},
	} {
		if _, err := db.Exec(q(c.s), c.args...); err != nil {
			t.Fatal(err)
		}
	}
	b = newEnv(t, withOrigin(originB), withRemote(rt), withKeyStore(ksB), withEncTuning, at)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"rx", "r"} {
		if doc := b.configOf(ns); levelOf(doc) != "sealed" {
			t.Fatalf("%s after its source's raise to e2e from sealed: %v, want sealed", ns, doc)
		}
	}
	if g := b.get("/r/r/x/rev/" + x1); g.Code != 200 || !isJOSE(g) {
		t.Fatalf("read-through content after following: %d %s", g.Code, g.Body)
	}
	ls, err := b.e.RemoteLevels(context.Background(), "r")
	if err != nil || len(ls) != 1 || ls[0].Level != "e2e" || !ls[0].Rebase || ls[0].Lacks || ls[0].ID != raised {
		t.Fatalf("levels %+v %v, want e2e marked for a rebase", ls, err)
	}
}

// v0.73 §E.2.3 (ENC-18, remote half): a branch's /keys relays its bases'
// keyring entries "where no block has nbf, from the epoch that base has in
// force now, so none once it has moved past its epoch at at". For a remote
// branch of a branch (base.chain ["eb", "e"]), e is a base of rel too: the
// follower reads e's epoch now from e's current document at the origin, so
// once e has rotated B relays e#1 no more, as A doesn't for eb.
func TestV073P36RemoteChainBaseEpochNow(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("e", e2eDoc(map[string]any{"keys": []any{kA.entry("*")}}))
	g := a.grant(kA, "user:admin", []string{"e", "eb"}, allVerbs)
	readerJWK, readerPriv, _ := seal.GenerateRecipient()
	ke, kb := seal.NewKey(), seal.NewKey()
	kre, _ := seal.BuildKeyringV2(readerPriv, "e", 1, ke, []*ecdh.PublicKey{readerPriv.PublicKey()})
	krHead := a.create("e", "keyring", kre.Value(), g)
	expect(t, a.branch("e", map[string]any{"name": "eb"}, g), 201)
	krb, _ := seal.BuildKeyringV2(readerPriv, "eb", 1, kb, []*ecdh.PublicKey{readerPriv.PublicKey()})
	a.appendRev("eb", "keyring", krHead, ops(op("replace", "", krb.Value())), g)
	at := a.nsHead("eb", g)

	var bPriv ed25519.PrivateKey
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"e", "eb"}, []string{"read"})}
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	kB := newKey("badmin")
	doc := e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})
	doc["base"] = map[string]any{"origin": originA, "ns": "eb", "at": at, "chain": []any{"eb", "e"}}
	expect(t, b.mkRemote("rel", addRoot(doc)), 201)
	readerB := b.grant(kB, "user:reader", []string{"rel"}, []string{"read"}, map[string]any{"enc": readerJWK})
	readerA := a.grant(kA, "user:reader", []string{"eb"}, []string{"read"}, map[string]any{"enc": readerJWK})
	kidsB := func() string { _, r := b.keysOf("rel", nil, readerB); return kidsOf(t, r) }
	kidsA := func() string { _, r := a.keysOf("eb", nil, readerA); return kidsOf(t, r) }
	if got := kidsB(); got != "e#1,eb#1" && got != "eb#1,e#1" {
		t.Fatalf("before e rotates: B relays %q", got)
	}

	// e, a base of eb (and so of rel), rotates to epoch 2.
	expect(t, a.do(req{method: "PATCH", path: "/ns/e", ifMatch: a.configID("e", g), body: ops(op("add", "/encryption/epoch", 2.0)), bearer: g}), 201)
	// eb writes something so B has something to follow.
	expect(t, a.do(req{method: "PATCH", path: "/ns/eb", ifMatch: a.configID("eb", g), body: ops(op("add", "/x-touch", true)), bearer: g}), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if got := kidsA(); got != "eb#1" {
		t.Fatalf("A for eb after e rotated: %q, want eb#1 alone", got)
	}
	if got := kidsB(); got != "eb#1" {
		t.Errorf("B for rel after e (in base.chain) rotated: %q, want eb#1 alone, as A answers for eb", got)
	}
}

// v0.73 §E.3.1 (ENC-22/ENC-51, MF-37): a prune snapshot's kid, for content
// from before a raise from sealed, is "the epoch that revision is served
// under", and Levels have a branch serve what it reads through from before
// the raise "as the base serves it". A serves x2, written in epoch 1, under
// m#1; B mirrors the epoch each sealed entry was served under, so its
// remote branch takes a snapshot of x2 under m#1, not the last epoch before
// the raise, and names the source, not its internal shadow, when it
// refuses one.
func TestV073P36RemotePreRaiseSnapshotEpoch(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant"}))
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	x2 := a.wr("m", "x", x1, withNonce(ops(op("replace", "/v", 2.0)))) // epoch 1
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/x-raise", true)), ""), 201)
	raised := a.nsHead("m")
	raisedDoc, _ := json.Marshal(map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "epoch": 3.0}})
	// A serves x2 under the epoch it was written in.
	g := a.get("/r/m/x/rev/" + x2)
	if g.Code != 200 || !isJOSE(g) {
		t.Fatalf("A's x2: %d %s", g.Code, g.Body)
	}
	h, err := seal.ParseHeader(string(g.Body))
	if err != nil || h.Kid != "m#1" {
		t.Fatalf("A serves x2 under %q (%v), want m#1", h.Kid, err)
	}

	var bPriv ed25519.PrivateKey
	rt := &route{}
	rt.set(proxyA(t, a, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/ns/m/rev/"+raised {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raisedDoc)
		return true
	}, "", nil), "")
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	prune := func(kid string) *resp {
		jwe, err := seal.SealSnapshot(seal.NewKey(), kid, "r", "x", x2, map[string]any{"v": 2.0})
		if err != nil {
			t.Fatal(err)
		}
		return b.prune("r", "x", map[string]any{"horizon": x2, "snapshot": jwe}, b.grant(kB, "user:admin", []string{"r"}, allVerbs))
	}
	r := prune("m#2")
	expect(t, r, 422)
	if bytes.Contains(r.Body, []byte("~r")) || !bytes.Contains(r.Body, []byte("before m's raise")) {
		t.Errorf("B's refusal of a snapshot under m#2 names %s, want the source m, not the shadow", r.Body)
	}
	if r := prune("m#1"); r.Code != 200 {
		t.Errorf("B's snapshot of x2 under m#1, the epoch A serves it under: %d %s, want 200", r.Code, r.Body)
	}
}

// v0.73 §8.5, §E.2.4 (MF-37): a namespace purge destroys its epoch keys,
// and a remote branch's purge destroys the keys of its source's epochs
// from before a raise from sealed that its shadows hold (storeEpochKey).
func TestV073P36PurgedRemoteDropsPreRaiseKeys(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA), withKeyStore(newKeyStore(t)), withEncTuning)
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant"}))
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	_ = x1
	a.clock.Advance(time.Hour)
	expect(t, a.patchNS("m", ops(op("add", "/x-raise", true)), ""), 201)
	raised := a.nsHead("m")
	raisedDoc, _ := json.Marshal(map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "epoch": 2.0}})
	rt := &route{}
	rt.set(proxyA(t, a, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/ns/m/rev/"+raised {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raisedDoc)
		return true
	}, "", nil), "")
	path, blobs := v073DB(t), t.TempDir()
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning,
		func(o *core.Options) { o.Path, o.BlobDir = path, blobs })
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	expect(t, b.mkRemote("r", remoteGenesis("m", raised, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	db, q := v073SQL(t, path)
	count := func() int {
		var n int
		if err := db.QueryRow(q(`SELECT COUNT(*) FROM epoch_keys WHERE ns IN (SELECT ns FROM namespaces WHERE name LIKE ?)`), "~r%").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n == 0 {
		t.Fatal("the shadow holds no pre-raise key: the scenario didn't happen")
	}
	b.purgeNSAs("r", b.grant(kB, "user:admin", []string{"r"}, allVerbs))
	if n := count(); n != 0 {
		t.Errorf("after the remote branch's purge, its shadows still hold %d of A's epoch keys", n)
	}
}
