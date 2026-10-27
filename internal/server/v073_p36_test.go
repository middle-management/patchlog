package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

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
// for the base epochs §E.2.3 selects (from the one in force at the
// reader's latest nbf; none without nbf).
//
// A here is a sealed namespace whose last config entry this test's proxy
// serves as the e2e document of a raise from sealed (epoch 3), since this
// server raises a sealed namespace to e2e only once it serves what is
// stored before such a raise sealed (P35); B reads A's documents only
// from A, so what B does is that of a branch of a raised source, whose
// pre-raise content A serves sealed as before the raise.
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
		"no nbf: none of the source's pre-raise epochs": {reader(), nil},
		"nbf before the source's first epoch":           {reader(nbf(-time.Hour)), []string{"m#1", "m#2"}},
		"nbf in epoch 2, by the source's start times":   {reader(nbf(90 * time.Minute)), []string{"m#2"}},
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
