package server

import (
	"crypto/ecdh"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// V01 (v0.74): key windows. Addendum E Levels, After a raise (Open 2):
// /keys gives the keys of the epochs before a raise from sealed as at E2,
// "its window judged against the current epoch, so none to a grant
// without nbf"; §E.2.3 Which epochs (Open 26): "the current one if no
// block has nbf or authentication is disabled"; §E.2.3 At E3 (Open 25):
// base epochs "no more than that base's historyEpochs at at before its
// epoch there". Copies take only what those keys open (§2.1, §7.8).

// hasKid reports whether kids, as kidsOf gives them, has kid.
func hasKid(kids, kid string) bool {
	for _, k := range strings.Split(kids, ",") {
		if k == kid {
			return true
		}
	}
	return false
}

// v0.74 §E.2.3 Which epochs (LEVELS-2): with authentication disabled a
// request is judged as a grant without nbf: /keys gives the current
// epoch's key alone, and a copy takes only a blob that opens under it.
func TestV074V01AuthDisabledCurrentEpochOnly(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withBlobTuning)
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant"}))
	e.mkNS("dst", map[string]any{"read": "grant"})
	e.mkNS("e3", e2eDoc(map[string]any{"read": "grant"}))
	data := []byte("epoch one only")
	bid := e.upload("s", "a", "text/plain", data, "alice")
	e.wr("s", "a", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), "alice")
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 3.0)), ""), 201)
	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	if len(keys) != 1 || keys["s#3"] == nil {
		t.Errorf("/keys with authentication disabled at epoch 3: %s, want s#3 alone", r.Body)
	}
	expectCode(t, e.copyBlob("dst", "x", bid, blobPath("s", "a", bid), "", "alice"), 404, "not_found")
}

// v0.74 §E.2.3 At E3 (LEVELS-3): a branch's /keys relays its base's
// keyring entries for epochs no more than the base's historyEpochs at at
// before its epoch there, whatever the grant's nbf.
func TestV074V01BaseEpochsCappedByHistoryEpochs(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("admin")
	e.mkNS("b", e2eDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	star := e.grant(k, "user:admin", []string{"b", "c"}, allVerbs, map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339)})
	readerJWK, readerPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	readers := []*ecdh.PublicKey{readerPriv.PublicKey()}
	kr, err := seal.BuildKeyringV2(readerPriv, "b", 1, seal.NewKey(), readers)
	if err != nil {
		t.Fatal(err)
	}
	head := e.create("b", "keyring", kr.Value(), star)
	for _, epoch := range []int{2, 3} {
		e.clock.Advance(time.Hour)
		if err := kr.Add(readerPriv, readers[0], seal.Kid("b", epoch), seal.NewKey()); err != nil {
			t.Fatal(err)
		}
		r := e.do(req{method: "POST", path: "/ns/b/batch", bearer: star, body: map[string]any{
			"config": map[string]any{"ifMatch": e.configID("b", star), "patches": ops(op("add", "/encryption/epoch", float64(epoch)))},
			"items":  []any{map[string]any{"resource": "keyring", "ifMatch": head, "steps": []any{ops(op("replace", "", kr.Value()))}}}}})
		expect(t, r, 201)
		head = e.head("b", "keyring", star)
	}
	expect(t, e.patchNS("b", ops(op("add", "/encryption/historyEpochs", 1.0)), star), 201)
	expect(t, e.branch("b", map[string]any{"name": "c"}, star), 201)
	early := e.grant(k, "user:reader", []string{"c"}, []string{"read"}, map[string]any{"enc": readerJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})
	_, r := e.keysOf("c", nil, early)
	if got := kidsOf(t, r); got != "b#2,b#3" {
		t.Errorf("branch /keys of a base with historyEpochs 1 at epoch 3: %q, want b#2,b#3", got)
	}
}
