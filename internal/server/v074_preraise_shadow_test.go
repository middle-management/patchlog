package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// shadowChain is A's eb, an e2e branch of e, raised from sealed before eb
// was made, and B's remote branch rel of eb (chain [eb, e]). e's x1, in
// epoch 1, references blob bid, which x2, in epoch 2, keeps; eb wrote x3
// on x end to end since, with a blob of its own, bid2, so x's chain in eb
// starts with eb's segment, and B's with its shadow of eb, neither of
// which has a raise.
type shadowChain struct {
	a, b                  *tenv
	g, gb                 string
	x1, x2, x3, bid, bid2 string
	data                  []byte
}

func newShadowChain(t *testing.T) *shadowChain {
	t.Helper()
	c := &shadowChain{data: []byte("e's blob in epoch 1")}
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("e", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"e", "eb"}, allVerbs) }
	g := root()
	c.bid = a.upload("e", "x", "text/plain", c.data, g)
	c.x1 = a.wr("e", "x", "", withNonce(addRoot(map[string]any{"v": 1.0, "b": ref(c.bid, "text/plain", len(c.data), "")})), g)
	a.clock.Advance(time.Hour)
	g = root()
	expect(t, a.do(req{method: "PATCH", path: "/ns/e", ifMatch: a.configID("e", g), body: ops(op("add", "/encryption/epoch", 2.0)), bearer: g}), 201)
	c.x2 = a.wr("e", "x", c.x1, withNonce(ops(op("replace", "/v", 2.0))), g)
	a.clock.Advance(time.Hour)
	g = root()
	expect(t, a.do(req{method: "PATCH", path: "/ns/e", ifMatch: a.configID("e", g), body: ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 3.0})), bearer: g}), 201)
	expect(t, a.branch("e", map[string]any{"name": "eb"}, g), 201)
	ref2 := a.uploadE2E("eb", "x", []byte("eb's blob, end to end"), g)
	c.bid2 = ref2["$blob"].(string)
	ebEpoch := int(a.nsDoc("eb", g)["encryption"].(map[string]any)["epoch"].(float64))
	w := a.do(req{method: "PATCH", path: "/r/eb/x", ifMatch: c.x2, raw: p35Sealed(t, seal.NewKey(), "eb#"+strconv.Itoa(ebEpoch), "eb", "x", c.x2, ops(op("add", "/c", ref2)), c.bid2), hasRaw: true, bearer: g})
	expect(t, w, 201)
	c.x3 = etagOf(w)
	at := a.nsHead("eb", g)

	bJWK, bID, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bID
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"e", "eb"}, []string{"read", "export"}, map[string]any{"enc": bJWK, "nbf": t0.Add(-time.Hour).Format(time.RFC3339)})}
	var bPriv ed25519.PrivateKey
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	b.opPriv = bPriv
	b.clock.Advance(3 * time.Hour)
	kB := newKey("badmin")
	doc := e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})
	doc["base"] = map[string]any{"origin": originA, "ns": "eb", "at": at, "chain": []any{"eb", "e"}}
	expect(t, b.mkRemote("rel", addRoot(doc)), 201)
	c.a, c.b, c.g, c.gb = a, b, g, b.grant(kB, "user:reader", []string{"rel"}, []string{"read"})
	return c
}

// Addendum E Levels, §7.8, §E.2.2 (v0.74): a pre-raise blob is one any
// pre-raise revision references, and it keeps its epoch URLs under the
// epochs of the still served pre-raise revisions referencing it, also
// read through a remote branch's shadow of a level that had no raise of
// its own. B serves e's pre-raise blob as A serves it through eb:
// …/blob/{bid} redirects to its latest epoch, and each epoch URL is A's
// bytes, never the plaintext. The blob eb wrote end to end, which no
// pre-raise revision references, has no epoch URLs there either: 404
// not_offered.
func TestV074RemoteShadowPreRaiseBlob(t *testing.T) {
	t.Parallel()
	c := newShadowChain(t)
	a, b, g, gb := c.a, c.b, c.g, c.gb

	pa, pb := blobPath("eb", "x", c.bid), blobPath("rel", "x", c.bid)
	if r := a.get(pa, g); r.Code != 302 || r.H.Get("Location") != pa+"/e/2" {
		t.Fatalf("A's …/blob/{bid} through eb: %d %v", r.Code, r.H)
	}
	if r := b.get(pb, gb); r.Code != 302 || r.H.Get("Location") != pb+"/e/2" || bytes.Contains(r.Body, c.data) {
		t.Fatalf("B's …/blob/{bid}: %d %v, want 302 to %s/e/2 as A answers", r.Code, r.H, pb)
	}
	for _, e := range []string{"1", "2"} {
		ra := a.get(pa+"/e/"+e, g)
		expect(t, ra, 200)
		rb := b.get(pb+"/e/"+e, gb)
		if rb.Code != 200 || !bytes.Equal(ra.Body, rb.Body) {
			t.Fatalf("B's epoch %s URL of the pre-raise blob: %d, want 200 with A's bytes (%.120s)", e, rb.Code, rb.Body)
		}
	}
	expectCode(t, a.get(blobPath("eb", "x", c.bid2)+"/e/1", g), 404, "not_offered")
	expectCode(t, b.get(blobPath("rel", "x", c.bid2)+"/e/1", gb), 404, "not_offered")
}

// §7.1 Paging, Addendum E Levels (v0.74): no resource log page spans the
// raise, also read through a remote branch's shadow of a level that had
// no raise of its own. A's log of x through eb starts with a page of e's
// revisions from before the raise, x1 and x2, sealed per entry under the
// epochs A serves them under (e#1, e#2), ending there with X-Log-Next;
// eb's x3 written end to end follows. B's log of x through rel pages the
// same: the page from before the raise byte for byte (A's sealings,
// mirrored verbatim), the later one entry for entry, but for the grant
// reference, which mirrored entries don't carry.
func TestV074RemoteShadowPreRaiseLogPages(t *testing.T) {
	t.Parallel()
	c := newShadowChain(t)
	pages := func(e *tenv, ns, bearer string) []*resp {
		t.Helper()
		path := "/r/" + ns + "/x/rev/" + c.x3 + "/log"
		var out []*resp
		for since := ""; len(out) < 10; {
			p := path
			if since != "" {
				p += "?since=" + since
			}
			r := e.get(p, bearer)
			out = append(out, r)
			next := r.H.Get("X-Log-Next")
			if r.Code != 200 || next == "" || next == since {
				break
			}
			since = next
		}
		return out
	}
	pa, pb := pages(c.a, "eb", c.g), pages(c.b, "rel", c.gb)

	// A: the first page ends before the raise, with its sealed entries.
	expect(t, pa[0], 200)
	if next := pa[0].H.Get("X-Log-Next"); next != c.x2 {
		t.Fatalf("A's first page: X-Log-Next %q, want x2 %s", next, c.x2)
	}
	var first []string
	if err := json.Unmarshal(pa[0].Body, &first); err != nil || len(first) != 2 {
		t.Fatalf("A's first page isn't x1 and x2 sealed: %v %s", err, pa[0].Body)
	}
	for i, kid := range []string{"e#1", "e#2"} {
		if h := mustHeader(t, []byte(first[i])); h.Kid != kid || h.PL["ns"] != "e" {
			t.Fatalf("A's entry %d: kid %q pl %v, want %s naming e", i, h.Kid, h.PL, kid)
		}
	}
	if len(pa) != 2 {
		t.Fatalf("A's log of x through eb: %d pages, want 2", len(pa))
	}

	if len(pb) != len(pa) {
		t.Fatalf("B's log of x: %d pages, A's %d (B's first: %d next %q %.200s)", len(pb), len(pa), pb[0].Code, pb[0].H.Get("X-Log-Next"), pb[0].Body)
	}
	for i := range pa {
		if pb[i].Code != pa[i].Code || pb[i].H.Get("X-Log-Next") != pa[i].H.Get("X-Log-Next") {
			t.Fatalf("page %d: B %d next %q, A %d next %q", i, pb[i].Code, pb[i].H.Get("X-Log-Next"), pa[i].Code, pa[i].H.Get("X-Log-Next"))
		}
	}
	if !bytes.Equal(pb[0].Body, pa[0].Body) {
		t.Fatalf("B's page from before the raise isn't A's bytes\nA: %.300s\nB: %.300s", pa[0].Body, pb[0].Body)
	}
	var ea, eb []map[string]any
	if json.Unmarshal(pa[1].Body, &ea) != nil || json.Unmarshal(pb[1].Body, &eb) != nil || len(ea) != 1 || len(eb) != 1 || ea[0]["id"] != c.x3 {
		t.Fatalf("the page after the raise isn't x3 alone\nA: %.300s\nB: %.300s", pa[1].Body, pb[1].Body)
	}
	delete(ea[0], "grant")
	if a, b := jsonv.Canonical(ea[0]), jsonv.Canonical(eb[0]); !bytes.Equal(a, b) {
		t.Fatalf("x3's entry: B's isn't A's\nA: %s\nB: %s", a, b)
	}
}
