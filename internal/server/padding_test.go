package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// openPadded decrypts a JWE and reports whether it is padded to its bucket
// without compression (§E.2.2), with the plaintext minus the padding.
func openPadded(t *testing.T, jwe string, key []byte, kid string, pl seal.PL) (bool, []byte) {
	t.Helper()
	h, pt, err := seal.Open(jwe, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Expect(kid, pl); err != nil {
		t.Fatalf("header %s: %v", h.Raw, err)
	}
	return seal.IsPadded(h, pt), bytes.TrimRight(pt, " ")
}

// With "encryption": { "pad": true } every JWE of a sealed namespace is
// padded to its size bucket and never compressed: documents, log entries,
// namespace documents and log ranges. Turning pad off affects only what is
// sealed afterwards (§E.2.2).
func TestSealedPadding(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "pad": true}})
	big := strings.Repeat("abcdefgh", 300) // compressible
	a0 := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"title": encMarker, "body": big})))
	a1 := e.wr("s", "x", a0, withNonce(ops(op("replace", "/title", "second"))))
	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	ke := keys["s#1"]
	kr := resKey(t, ke, "s", "x")

	for _, id := range []string{a0, a1} {
		ok, pt := openPadded(t, string(e.get("/r/s/x/rev/"+id).Body), kr, "s#1", seal.ResourcePL("s", "x", id, "doc"))
		if !ok {
			t.Fatalf("document %s isn't padded", id)
		}
		if _, err := jsonv.Parse(pt); err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range e.get("/r/s/x/rev/" + a1 + "/log").Arr() {
		h, _ := seal.ParseHeader(x.(string))
		id := h.PL["id"].(string)
		if ok, _ := openPadded(t, x.(string), kr, "s#1", seal.ResourcePL("s", "x", id, "rev")); !ok {
			t.Fatalf("log entry %s isn't padded", id)
		}
	}
	head := e.nsHead("s")
	if ok, _ := openPadded(t, string(e.get("/ns/s/rev/"+head).Body), ke, "s#1", seal.NamespaceDocPL("s", head)); !ok {
		t.Fatal("namespace document isn't padded")
	}
	rng := string(e.get("/ns/s/rev/" + head + "/log").Body)
	if ok, pt := openPadded(t, rng, ke, "s#1", seal.RangePL("s", "", head)); !ok || !bytes.Contains(pt, []byte(a1)) {
		t.Fatal("log range isn't padded as a whole")
	}

	// Off again: stored bytes are served unchanged, new ones aren't padded.
	before := string(e.get("/r/s/x/rev/" + a0).Body)
	expect(t, e.patchNS("s", ops(op("replace", "/encryption/pad", false)), ""), 201)
	a2 := e.wr("s", "x", a1, withNonce(ops(op("replace", "/title", "third"))))
	if got := string(e.get("/r/s/x/rev/" + a0).Body); got != before {
		t.Fatal("stored sealed bytes changed")
	}
	if ok, _ := openPadded(t, string(e.get("/r/s/x/rev/"+a2).Body), kr, "s#1", seal.ResourcePL("s", "x", a2, "doc")); ok {
		t.Fatal("padded after pad was turned off")
	}

	// pad is for sealed and e2e namespaces only, and a boolean.
	for _, enc := range []map[string]any{{"level": "at-rest", "pad": true}, {"level": "sealed", "pad": "yes"}} {
		r := e.do(req{method: "PATCH", path: "/ns/bad", ifNoneMatch: "*", body: addRoot(map[string]any{"encryption": enc}), author: "admin"})
		if r.Code < 400 || r.Code >= 500 {
			t.Fatalf("%v: %d %s", enc, r.Code, r.Body)
		}
	}
}
