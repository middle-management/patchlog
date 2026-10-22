package vectors_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
	"github.com/middle-management/patchlog/internal/tree"
	"github.com/middle-management/patchlog/internal/verify"
)

var ctx = context.Background()

// The inputs and ids of I.2, which I.4, I.8 and I.9 build on.
const (
	patches1 = `[{"op":"add","path":"","value":{"title":"Hello","views":0}}]`
	patches2 = `[{"op":"replace","path":"/views","value":1}]`

	idG  = "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"
	hexG = "5e8c8d1cecdd67fd2e5a750b07aa0f91fd4ab16b"
	idC  = "1sywh54kpo3c4ezn2znktvl3avge4zl5d"
	hexC = "962c7ef14f76c5c265bacb553aaf60a989ccafa3"
	idT  = "1idx6u2b3z42obqmwsgmlzvrfuutks2bq"
	hexT = "40efea683bcf34e0c1969198bcd625a526a96830"

	entry1 = `{"kind":"config","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}`
	nsID1  = "1vmctae4vewju6nvxi374rkrkmyzpdrif"
	entry2 = `{"kind":"head","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}`
	nsID2  = "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"
)

// i1 is I.1's table, then what §3.1 states beside it: an input, and its
// canonical form, or "" where the verdict is 400.
var i1 = []struct{ in, canon string }{
	{`{"a":1,"b":2.0}`, `{"a":1,"b":2}`},
	{`{"a":1e2}`, `{"a":100}`},
	{`{"a":9007199254740991}`, `{"a":9007199254740991}`}, // 2⁵³−1
	{`{"a":9007199254740992}`, ""},                       // 2⁵³
	{`{"a":-9007199254740992}`, ""},
	{`{"a":1000000000000000000000}`, `{"a":1e+21}`}, // 10²¹, integer literal
	{`{"a":1e21}`, `{"a":1e+21}`},
	{`{"a":1e300}`, `{"a":1e+300}`},
	{`{"a":0.1}`, `{"a":0.1}`},
	{`{"a":1,"a":2}`, ""}, // duplicate key
	// Members sort by UTF-16 code units (I.1).
	{`{"b":1,"a":2,"ä":3}`, `{"a":2,"b":1,"ä":3}`},
	// Keys above U+FFFF sort by their surrogate pairs: U+1F600 (D83D DE00)
	// before U+E000 and U+FFEE, which code points would put first.
	{`{"￮":2,"":3,"😀":1}`, "{\"\U0001F600\":1,\"\":3,\"￮\":2}"},
	// §3.1: lone surrogates are 400.
	{`"\ud800"`, ""},
	{`"\udc00"`, ""},
	{`"\ud800A"`, ""},
	// §3.1: a number that overflows a double is 400; one that underflows
	// is read as the nearest double, so 1e-400 is 0.
	{`{"a":1e400}`, ""},
	{`{"a":-1e400}`, ""},
	{`{"a":1e-400}`, `{"a":0}`},
	{`{"a":-1e-400}`, `{"a":0}`},
	// §3.1: integral values with 2⁵³ ≤ |v| < 10²¹ are 400 however they
	// are written; with an exponent in their canonical form they are not.
	{`{"a":9007199254740992.0}`, ""},
	{`{"a":9.007199254740992e15}`, ""},
	{`{"a":-1e16}`, ""},
	{`{"a":1e20}`, ""},
	{`{"a":9007199254740991.0}`, `{"a":9007199254740991}`},
	{`{"a":1.5e300}`, `{"a":1.5e+300}`},
}

// I.1 (§3.1) through jsonv, the reference's parser and canonicaliser.
func TestI1CanonicalJSON(t *testing.T) {
	t.Parallel()
	for _, c := range i1 {
		v, err := jsonv.Parse([]byte(c.in))
		if c.canon == "" {
			if err == nil {
				t.Errorf("%s: accepted as %s, want 400", c.in, jsonv.Canonical(v))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: refused: %v", c.in, err)
			continue
		}
		if got := string(jsonv.Canonical(v)); got != c.canon {
			t.Errorf("%s: canonical %s, want %s", c.in, got, c.canon)
		}
	}
}

// I.1's verdicts as a deployment answers them (§3.1): the 400s for a
// request body, and the canonical form it stores and hashes, never the
// bytes as received, as the revision id it answers shows (§3.3).
func TestI1Server(t *testing.T) {
	t.Parallel()
	c := deployment(t, "vectors")
	for i, tc := range i1 {
		name := "i1-" + strconv.Itoa(i)
		res, err := c.Create(ctx, "vectors", name, []byte(`[{"op":"add","path":"","value":`+tc.in+`}]`))
		if tc.canon == "" {
			var ae *client.APIError
			if !errors.As(err, &ae) || ae.Status != http.StatusBadRequest {
				t.Errorf("%s: %v, want 400", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if want := ids.Revision(nil, []byte(`[{"op":"add","path":"","value":`+tc.canon+`}]`)).String(); res.ID != want {
			t.Errorf("%s: revision %s, want %s over the canonical form %s", tc.in, res.ID, want, tc.canon)
		}
	}
}

// I.2 (§3.2–§3.5): revision, tombstone and namespace ids through ids, and
// through the client and verify code that recompute them from what a
// deployment serves.
func TestI2IDs(t *testing.T) {
	t.Parallel()
	check := func(what string, id ids.ID, text, hx string) {
		t.Helper()
		if id.String() != text || hex.EncodeToString(id[:]) != hx {
			t.Errorf("%s = %s (%x), want %s (%s)", what, id, id[:], text, hx)
		}
	}
	g := ids.Revision(nil, []byte(patches1))
	c := ids.Revision(&g, []byte(patches2))
	check("g", g, idG, hexG)
	check("c", c, idC, hexC)
	check("tombstone of c", ids.Tombstone(c), idT, hexT)
	for text, hx := range map[string]string{idG: hexG, idC: hexC, idT: hexT} {
		id, err := ids.Parse(text)
		if err != nil {
			t.Errorf("Parse(%s): %v", text, err)
			continue
		}
		check("Parse", id, text, hx)
	}

	// The client canonicalises before hashing (§3.1 "What is stored").
	if got, err := client.ExpectedRevision("", []byte(`[ {"value": {"views": 0, "title": "Hello"}, "path": "", "op": "add"} ]`)); err != nil || got != idG {
		t.Errorf("ExpectedRevision(genesis) = %s %v, want %s", got, err, idG)
	}
	if got, err := client.ExpectedRevision(idG, jsonv.MustParse([]byte(patches2))); err != nil || got != idC {
		t.Errorf("ExpectedRevision(g) = %s %v, want %s", got, err, idC)
	}
	if got, err := client.ExpectedTombstone(idC); err != nil || got != idT {
		t.Errorf("ExpectedTombstone(c) = %s %v, want %s", got, err, idT)
	}
	for _, le := range []struct {
		parent string
		e      client.LogEntry
		want   string
	}{
		{"", client.LogEntry{Kind: "rev", Patches: jsonv.MustParse([]byte(patches1)), HasPatches: true}, idG},
		{idG, client.LogEntry{Kind: "rev", Patches: jsonv.MustParse([]byte(patches2)), HasPatches: true}, idC},
		{idC, client.LogEntry{Kind: "tombstone"}, idT},
	} {
		if got, err := verify.LogEntryID(le.parent, le.e); err != nil || got != le.want {
			t.Errorf("LogEntryID(%q, %s) = %s %v, want %s", le.parent, le.e.Kind, got, err, le.want)
		}
	}

	// The namespace chain: the hashed form of each entry is I.2's entry
	// text, and its ns_id the hash after the previous one.
	e1 := client.NSEntry{Kind: "config", Target: idG}
	e2 := client.NSEntry{Kind: "head", Resource: "derby", Target: idG}
	for _, e := range []struct {
		e    client.NSEntry
		text string
	}{{e1, entry1}, {e2, entry2}} {
		h, err := verify.HashedForm(e.e)
		if err != nil || string(jsonv.Canonical(h)) != e.text {
			t.Errorf("hashed form %s %v, want %s", jsonv.Canonical(h), err, e.text)
		}
	}
	n1 := ids.Hash(nil, []byte(entry1))
	if n1.String() != nsID1 {
		t.Errorf("ns_id₁ = %s, want %s", n1, nsID1)
	}
	if n2 := ids.Hash(&n1, []byte(entry2)); n2.String() != nsID2 {
		t.Errorf("ns_id₂ = %s, want %s", n2, nsID2)
	}
	if got, err := verify.NSEntryID("", e1); err != nil || got != nsID1 {
		t.Errorf("NSEntryID(entry₁) = %s %v, want %s", got, err, nsID1)
	}
	if got, err := verify.NSEntryID(nsID1, e2); err != nil || got != nsID2 {
		t.Errorf("NSEntryID(entry₂) = %s %v, want %s", got, err, nsID2)
	}
	// A local branch's chain starts with entry₁'s shape (§3.5, §7.6).
	if got, err := client.FirstBranchEntry(idG); err != nil || got != nsID1 {
		t.Errorf("FirstBranchEntry(g) = %s %v, want %s", got, err, nsID1)
	}
	e2.ID, e2.Prev = nsID2, nsID1
	if last, err := verify.VerifyNSChain([]client.NSEntry{{ID: nsID1, Kind: "config", Target: idG}, e2}, ""); err != nil || last != nsID2 {
		t.Errorf("VerifyNSChain = %s %v, want %s", last, err, nsID2)
	}
}

// I.2's text-id rejections (§3.2): exactly 33 characters, "1" then 32 of
// a–z2–7, with no padding bits, so the old draft's "trailing-bit" id is an
// ordinary valid id.
func TestI2TextForm(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"1L2GI2HHM3VT72LS2OUFQPKQPSH6UVMLL",  // uppercase
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvml",   // 32 characters
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvml1",  // "1" isn't in the alphabet
		"2l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",  // unknown version prefix
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlla", // 34 characters
		"l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",   // no prefix
		"",
	} {
		if id, err := ids.Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted as %s", s, id)
		}
	}
	const old = "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm"
	id, err := ids.Parse(old)
	if err != nil || id.String() != old {
		t.Errorf("Parse(%s) = %s %v, want a valid id with that text form", old, id, err)
	}
}

// I.3 (§3.7): blob ids, through ids and the client's (which lowercases the
// type and drops parameters first).
func TestI3BlobIDs(t *testing.T) {
	t.Parallel()
	data := []byte("hello patchlog\n")
	for nonce, want := range map[string]string{"": "1m5jj344d7tz7cicfmq53ayhmwuubpmyt", "aaaaaaaaaaaaaaaaaaaaaaaaaa": "1hdwkfub2zymqzgc75snybxosfk67633s"} {
		if got := ids.Blob("text/plain", nonce, data).String(); got != want {
			t.Errorf("Blob(nonce %q) = %s, want %s", nonce, got, want)
		}
		if got := client.BlobID("Text/Plain; charset=utf-8", nonce, data); got != want {
			t.Errorf("client.BlobID(nonce %q) = %s, want %s", nonce, got, want)
		}
	}
}

// I.2 and I.3 as a deployment computes them: the ids a write answers, from
// patch sets sent in a non-canonical form, and the blob ids it recomputes
// for an upload (§7.8).
func TestI2I3Server(t *testing.T) {
	t.Parallel()
	c := deployment(t, "matches")
	w, err := c.Create(ctx, "matches", "derby", []byte(` [ {"value": {"views": 0, "title": "Hello"}, "path": "", "op": "add"} ] `))
	if err != nil || w.ID != idG {
		t.Fatalf("genesis: %v %v, want %s", w, err, idG)
	}
	if w, err = c.Append(ctx, "matches", "derby", idG, []byte(`[{"value":1.0,"path":"/views","op":"replace"}]`)); err != nil || w.ID != idC {
		t.Fatalf("child: %v %v, want %s", w, err, idC)
	}
	data := []byte("hello patchlog\n")
	// The deployment recomputes the id over the body, with the Blob-Nonce
	// as its nonce (§7.8): the bytes sent without I.3's nonce don't hash
	// to the id with it.
	rq, err := http.NewRequest(http.MethodPut, c.BaseURL()+"/r/matches/derby/blob/1hdwkfub2zymqzgc75snybxosfk67633s", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	rq.Header.Set("Content-Type", "text/plain")
	rq.Header.Set("X-Author", "vectors") // authentication is disabled (§7.2)
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	v, _ := jsonv.Parse(body)
	if m, _ := v.(map[string]any); resp.StatusCode != http.StatusUnprocessableEntity || m["code"] != "blob_mismatch" {
		t.Errorf("upload without the nonce: %s %s, want 422 blob_mismatch", resp.Status, body)
	}
	for nonce, want := range map[string]string{"": "1m5jj344d7tz7cicfmq53ayhmwuubpmyt", "aaaaaaaaaaaaaaaaaaaaaaaaaa": "1hdwkfub2zymqzgc75snybxosfk67633s"} {
		if bid, err := c.UploadBlob(ctx, "matches", "derby", "text/plain", nonce, data); err != nil || bid != want {
			t.Errorf("upload (nonce %q): %s %v, want %s", nonce, bid, err, want)
		}
	}
	if w, err = c.Delete(ctx, "matches", "derby", idC); err != nil || w.ID != idT {
		t.Fatalf("tombstone: %v %v, want %s", w, err, idT)
	}
	// The log the deployment serves verifies to the same ids.
	log, err := c.Log(ctx, "matches", "derby", idT, "")
	if err != nil {
		t.Fatal(err)
	}
	if last, err := verify.VerifyResourceLog(log, ""); err != nil || last != idT {
		t.Errorf("VerifyResourceLog = %s %v, want %s", last, err, idT)
	}
}

// The root block, signing input and signature of I.4.
const (
	i4Root      = `{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}`
	i4GrantID   = "15swdvi5nbnlkv76v7y6k77h52atov6ru"
	i4Digest    = "43bba3f8e86bdd96435153ddb0d704cab7e5e9459087f3fd78c157b6a7102c54"
	i4Pub       = "RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM"
	i4Signature = "Ed25519:key-1:Zdm2HSg4Fefj9ZaOYm2nYdW7xyLjKc_6T8CruK76EDEL_H6rnZd_sKdQrlevjtIQDGpiudAJjyHigradmHXXCA"
)

// I.4 (§C.3, §C.3.1): the grant id of a root block, through a minted and
// decoded Biscuit grant, and an author signature checked as a deployment
// checks one, against the signers of a grant's root block.
func TestI4GrantIDAndSignature(t *testing.T) {
	t.Parallel()
	if got := ids.Of([]byte(i4Root)).String(); got != i4GrantID {
		t.Errorf("ids.Of(root block) = %s, want %s", got, i4GrantID)
	}
	_, key := grant.GenerateKey()
	minted, err := grant.Mint(jsonv.MustParse([]byte(i4Root)).(map[string]any), key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := grant.Decode(minted.Encode(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for what, g := range map[string]*grant.Grant{"minted": minted, "decoded": decoded} {
		if got := g.ID().String(); got != i4GrantID {
			t.Errorf("%s grant id %s, want %s", what, got, i4GrantID)
		}
	}

	g := ids.Revision(nil, []byte(patches1))
	d := sig.Digest("https://cms.example", "matches", "derby", &g, []byte(patches2))
	if hex.EncodeToString(d) != i4Digest {
		t.Errorf("signing input %x, want %s", d, i4Digest)
	}
	// A tombstone's signing input has the ASCII bytes "tombstone" in
	// place of canonical(patches).
	if !bytes.Equal(sig.Digest("https://cms.example", "matches", "derby", &g, nil), sig.Digest("https://cms.example", "matches", "derby", &g, []byte("tombstone"))) {
		t.Error(`a tombstone's signing input does not use "tombstone"`)
	}

	// key-1 listed in a grant's signers, as the root block carries it.
	withSigners := jsonv.MustParse([]byte(i4Root)).(map[string]any)
	withSigners["signers"] = jsonv.MustParse([]byte(`[{"kid":"key-1","alg":"Ed25519","pub":"` + i4Pub + `"}]`))
	sg, err := grant.Mint(withSigners, key)
	if err != nil {
		t.Fatal(err)
	}
	if sg, err = grant.Decode(sg.Encode(), 0); err != nil {
		t.Fatal(err)
	}
	signer, ok := sig.Find(sg.Blocks[0].Signers, "key-1")
	if !ok {
		t.Fatalf("key-1 not among the signers %v", sg.Blocks[0].Signers)
	}
	s, err := sig.Parse(i4Signature)
	if err != nil {
		t.Fatal(err)
	}
	if s.String() != i4Signature {
		t.Errorf("signature reads back as %s", s)
	}
	if !sig.Verify(signer, s, d) {
		t.Error("I.4's signature does not verify over the signing input")
	}
	if sig.Verify(signer, s, sig.Digest("https://cms.example", "matches", "derby", &g, []byte(patches1))) {
		t.Error("I.4's signature verifies over another signing input")
	}
}

// The key, claims and cookie of I.5.
const (
	i5Key    = "3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708"
	i5Claims = `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}`
	i5Name   = "__Secure-pl-eg-4390e78526d94754"
	i5Value  = "eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw"
	i5Exp    = 1790000900
)

// I.5 (§C.5.3): an edge grant in the default format, issued and verified
// by edge.Cookies with a clock before exp, and each cookie I.5 says an edge
// ignores.
func TestI5EdgeCookies(t *testing.T) {
	t.Parallel()
	key, _ := hex.DecodeString(i5Key)
	c := edge.NewCookies("origin", key)
	now := time.Unix(i5Exp-900, 0)
	if got := edge.Name("/r/demo/derby"); got != i5Name {
		t.Errorf("name %s, want %s", got, i5Name)
	}
	ck := c.Issue(edge.Claims{Prefix: "/r/demo/derby", Exp: i5Exp}, now)
	if ck.Name != i5Name || ck.Value != i5Value {
		t.Errorf("issued %s=%s, want %s=%s", ck.Name, ck.Value, i5Name, i5Value)
	}
	if p, _, _ := strings.Cut(i5Value, "."); mustB64(t, p) != i5Claims {
		t.Errorf("claims %s, want %s", mustB64(t, p), i5Claims)
	}
	if cl, err := c.Verify(i5Value, now); err != nil || *cl != (edge.Claims{Kid: "origin", Prefix: "/r/demo/derby", Exp: i5Exp}) {
		t.Errorf("Verify = %v %v", cl, err)
	}
	if p, ok := c.Check(get("/r/demo/derby", i5Name, i5Value), now); !ok || p != "/r/demo/derby" {
		t.Errorf("Check = %q %v, want /r/demo/derby", p, ok)
	}

	// mac is I.5's MAC over a value's first part as written, for the values
	// a minter other than Issue might send: each case below carries a MAC
	// that verifies over its own first part, or over the re-encoding I.5
	// names.
	mac := func(part string) string {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(part))
		return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	b64 := base64.RawURLEncoding.EncodeToString
	signed := func(claims string) string { return b64([]byte(claims)) + "." + mac(b64([]byte(claims))) }
	if signed(i5Claims) != i5Value {
		t.Fatalf("the test's MAC gives %s, not I.5's value", signed(i5Claims))
	}
	canonPart, _, _ := strings.Cut(i5Value, ".")
	// The claims' last base64url character carries two unused bits: set
	// them, and the part decodes to the same claims under a lax decoder.
	lax := canonPart[:len(canonPart)-1] + string(canonPart[len(canonPart)-1]+1)
	if got, err := base64.RawURLEncoding.DecodeString(lax); err != nil || string(got) != i5Claims {
		t.Fatalf("lax part %s decodes to %s %v", lax, got, err)
	}
	reordered := `{"kid":"origin","exp":1790000900,"p":"/r/demo/derby"}`
	for what, v := range map[string]string{
		"claims with a fourth member":         signed(`{"exp":1790000900,"kid":"origin","p":"/r/demo/derby","x":1}`),
		"claims reordered":                    signed(reordered),
		"claims with whitespace":              signed(`{"exp": 1790000900, "kid": "origin", "p": "/r/demo/derby"}`),
		"a MAC over the re-encoded claims":    b64([]byte(reordered)) + "." + mac(canonPart),
		"a MAC over the re-encoded base64url": lax + "." + mac(canonPart),
	} {
		if _, err := c.Verify(v, now); err == nil {
			t.Errorf("%s: verified", what)
		}
		if _, ok := c.Check(get("/r/demo/derby", i5Name, v), now); ok {
			t.Errorf("%s: passed Check", what)
		}
	}
	// A name that doesn't match its p.
	if _, ok := c.Check(get("/r/demo/derby", edge.Name("/r/demo"), i5Value), now); ok {
		t.Error("a cookie named for another p passed Check")
	}
	// An exp in the past: at exp and after.
	for _, at := range []time.Time{time.Unix(i5Exp, 0), time.Unix(i5Exp+1, 0)} {
		if _, err := c.Verify(i5Value, at); err == nil {
			t.Errorf("verified at %d, exp %d", at.Unix(), int64(i5Exp))
		}
		if _, ok := c.Check(get("/r/demo/derby", i5Name, i5Value), at); ok {
			t.Errorf("passed Check at %d, exp %d", at.Unix(), int64(i5Exp))
		}
	}
	// A p that covers the path only as a string prefix.
	ns := c.Issue(edge.Claims{Prefix: "/r/demo", Exp: i5Exp}, now)
	if _, ok := c.Check(get("/r/demo/derby", ns.Name, ns.Value), now); !ok {
		t.Error("/r/demo does not cover /r/demo/derby")
	}
	for _, path := range []string{"/r/demox", "/r/demox/derby"} {
		if _, ok := c.Check(get(path, ns.Name, ns.Value), now); ok {
			t.Errorf("/r/demo covers %s", path)
		}
	}
}

// get is a GET of path carrying one cookie.
func get(path, name, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	return r
}

func mustB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// I.6 (§E.2.2): every padding bucket, through PadLen and Pad.
func TestI6Padding(t *testing.T) {
	t.Parallel()
	for _, r := range [][2]int{
		{1, 256}, {255, 256}, {256, 256}, {257, 272}, {300, 304}, {511, 512},
		{513, 544}, {1000, 1024}, {4096, 4096}, {1000000, 1015808}, {1048576, 1048576}, {67108864, 67108864},
	} {
		if got := seal.PadLen(r[0]); got != r[1] {
			t.Errorf("PadLen(%d) = %d, want %d", r[0], got, r[1])
		}
		if r[0] > 1<<20 {
			continue // PadLen alone: no need to fill 64 MiB
		}
		p := seal.Pad(bytes.Repeat([]byte{'x'}, r[0]))
		if len(p) != r[1] || !seal.Padded(p) {
			t.Errorf("Pad of %d bytes: %d bytes (padded %v), want %d", r[0], len(p), seal.Padded(p), r[1])
		}
	}
}

// I.7 (§E.2.1): a per-resource key.
func TestI7ResourceKey(t *testing.T) {
	t.Parallel()
	ke := make([]byte, 32)
	for i := range ke {
		ke[i] = byte(i)
	}
	kr, err := seal.ResourceKey(ke, "demo", "derby")
	if err != nil || hex.EncodeToString(kr) != "37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25" {
		t.Errorf("K_r = %x %v", kr, err)
	}
}

// I.8 (§B.5, §B.11.5): a subject set's gs, and the combined checkpoint a
// tree service computes over its catalog and a namespace it trusts.
func TestI8SubjectSetAndCheckpoint(t *testing.T) {
	t.Parallel()
	const gs = "17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm"
	for _, subjects := range [][]string{
		{"group:match-desk", "user:anna"},
		{"user:anna", "group:match-desk"}, // sorted first
		{"user:anna", "group:match-desk", "user:anna"},
	} {
		if got := grantcheck.SubjectSetID(subjects); got != gs {
			t.Errorf("SubjectSetID(%q) = %s, want %s", subjects, got, gs)
		}
	}
	g := &tree.Graph{Catalog: "cat", Trust: map[string]bool{"matches": true}}
	at, nss := tree.CombinedAt(g, map[string]string{"cat": nsID1, "matches": nsID2})
	if at != "1vwnfnoyshruyx4lul4a25rtctooiph5v" || !slices.Equal(nss, []string{"cat", "matches"}) {
		t.Errorf("CombinedAt = %s %v", at, nss)
	}
}

// The two lines of I.9.
const i9 = `{"authors":false,"bundle":1,"origin":"https://staging.example"}` + "\n" +
	`{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}` + "\n"

// I.9 (§G.4.1): a bundle digest covers the bytes as written. I.9's lines
// are a digest test only (its header lacks created, at and docs), so the
// bundle Reader and Writer are held to the same digest over a readable
// bundle with I.9's history line, and the Reader refuses that bundle with
// either line re-encoded rather than digest it as its canonical lines.
func TestI9BundleDigest(t *testing.T) {
	t.Parallel()
	if got := ids.Of([]byte(i9)).String(); got != "1b3a64kkqf3o6f3rglkgi6ok5hgldbne6" {
		t.Errorf("digest %s, want 1b3a64kkqf3o6f3rglkgi6ok5hgldbne6", got)
	}

	_, line, _ := strings.Cut(i9, "\n")
	hdr := `{"at":{"matches":"` + nsID2 + `"},"authors":false,"bundle":1,"created":"2026-10-04T12:00:00Z","docs":{"matches/derby":{"head":"` + idG + `","history":"full"}},"origin":"https://staging.example"}` + "\n"
	b := hdr + line
	want := ids.Of([]byte(b)).String()

	var buf bytes.Buffer
	w, err := bundle.NewWriter(&buf, bundle.Header{Origin: "https://staging.example", Created: "2026-10-04T12:00:00Z",
		At: map[string]string{"matches": nsID2}, Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: idG}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Line(bundle.Line{NS: "matches", Resource: "derby", ID: idG, Kind: "rev", Patches: jsonv.MustParse([]byte(patches1))}); err != nil {
		t.Fatal(err)
	}
	d, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != b || d != want {
		t.Errorf("Writer wrote\n%s(digest %s), want\n%s(digest %s)", buf.String(), d, b, want)
	}

	if d, err := readBundle(b); err != nil || d != want {
		t.Errorf("Reader digest %s (%v), want %s over the bytes", d, err, want)
	}

	// The same bundle with a line that isn't canonical JSON followed by one
	// 0x0A is rejected (§G.4.1). A Reader that re-encoded such a line before
	// hashing would report want, the digest of other bytes than it was
	// given, so re-encoding either line never reproduces a digest.
	for _, c := range []struct{ what, b string }{
		{"history line re-encoded", hdr + `{"resource":"derby", "ns":"matches", "kind":"rev", "parent":"", "id":"` + idG + `", "patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}]}` + "\n"},
		{"history line with another number spelling", hdr + strings.Replace(line, `"views":0`, `"views":0.0`, 1)},
		{"history line with an escape", hdr + strings.Replace(line, `"Hello"`, `"\u0048ello"`, 1)},
		{"header re-encoded", strings.Replace(hdr, `,"authors":false,"bundle":1,`, `, "authors": false, "bundle": 1, `, 1) + line},
		{"blank line", hdr + "\n" + line},
		{"CRLF line ends", strings.ReplaceAll(b, "\n", "\r\n")},
		{"last line without its 0x0A", strings.TrimSuffix(b, "\n")},
	} {
		if d, err := readBundle(c.b); err == nil {
			t.Errorf("%s: read with digest %s (the bytes as written: %s), want rejected (§G.4.1, I.9)", c.what, d, ids.Of([]byte(c.b)))
		}
	}
}

// readBundle reads b to its end with the bundle Reader and returns the
// digest it reports, or the error it refuses b with.
func readBundle(b string) (string, error) {
	r, err := bundle.NewReader(strings.NewReader(b))
	if err != nil {
		return "", err
	}
	for {
		if _, err := r.Next(); err == io.EOF {
			return r.Digest(), nil
		} else if err != nil {
			return "", err
		}
	}
}

// I.10's document and the 118 bytes it renders as.
const (
	i10Doc       = `{"$nonce":"abcdefghijklmnopqrstuvwxyz","10":true,"2":[],"items":[{"id":"a","n":1.5},{}],"title":"Café"}`
	i10Rendering = "{\n  \"10\": true,\n  \"2\": [],\n  \"items\": [\n    {\n      \"id\": \"a\",\n      \"n\": 1.5\n    },\n    {}\n  ],\n  \"title\": \"Café\"\n}\n"
	i10SHA256    = "c7e8bfb3ff3fed1b111dda8cce06b4f2c1b7615565e828f4777ebf63055e887c"
)

// I.10 (§H.1): a file rendering, as tools claiming Addendum H show it, and
// the size a listing gives it (§H.3).
func TestI10Rendering(t *testing.T) {
	t.Parallel()
	doc := jsonv.MustParse([]byte(i10Doc))
	r := files.Rendering(doc)
	sum := sha256.Sum256(r)
	if string(r) != i10Rendering || len(r) != 118 || hex.EncodeToString(sum[:]) != i10SHA256 {
		t.Errorf("rendering (%d bytes, sha-256 %x):\n%s", len(r), sum, r)
	}
	if m, shown := files.Show(doc); m != (files.Meta{Size: 118, Type: files.JSONType}) || !bytes.Equal(shown, r) {
		t.Errorf("Show = %+v, %q", m, shown)
	}
}

// deployment starts an in-process deployment (core and server, with
// authentication disabled) and returns a client of it, writing as X-Author
// "vectors" (§7.2), with the public namespace ns created.
func deployment(t *testing.T, ns string) *client.Client {
	t.Helper()
	s := clienttest.New(t, clienttest.Options{})
	c, err := client.New(s.URL, client.WithAuthor("vectors"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	return c
}
