package vectors_test

// The candidate vectors of docs/VECTORS-PROPOSED.md for "Still to come"
// (§I.26's list since v0.86; §I.25's in the document, as v0.85 numbered it)
// (C.4 and C.5, computed independently from the v0.85 text), each computed
// here through the reference's production code and compared with the
// candidate. testdata/candidates.json holds the candidates as the document
// gives them (extracted, never computed, and never rewritten by -update);
// a value the reference computes otherwise is a failure here, reported to
// the writer as contested, never a candidate overwritten with ours.
//
// These are the computed values. What a deployment answers with them, the
// bundle Reader's verdict on C.5's rows and an index serving C.4's gs, is
// in v085_pending_test.go.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// candidatesFile is testdata/candidates.json.
type candidatesFile struct {
	C4 struct {
		Kid, Pub, KeySubject, Marker, GS string
		View, ViewKeyKn                  string
		Header, Plaintext, JWE           string
		PaddedJWE                        string
		PlaintextBytes, PaddedBytes      int
	} `json:"C.4"`
	C5 struct {
		Rows []struct{ Change, SHA256, Rule string }
	} `json:"C.5"`
}

// loadCandidates reads testdata/candidates.json. It only reads: the file
// is the candidates' text, and no run of the reference writes it.
func loadCandidates(t *testing.T) candidatesFile {
	t.Helper()
	var f candidatesFile
	if !golden.Load(t, "candidates", &f) {
		t.Fatal("testdata/candidates.json is missing")
	}
	return f
}

// C.4 (SERVICES §E.2.6 Whole-response sealing, §A.4, §7.9 gs): the
// key: string of demo's key ops-2026 with I.14's pub, as the reference
// binds a gs to a key (grantcheck.KeySubject: canonical([kid, pub]), pub the
// key entry's base64url string, the reading the candidates call
// underdetermined); the marker reads:demo:{key: string} and the gs over
// that one marker (grantcheck.SubjectSetID); the view of §I.23's query at
// ns_id₂ under that gs; the view key of K_n (seal.ViewKey); and the whole
// response sealed under it with the pl of derived.View, kid demo#3 and the
// IV c0 … cb, unpadded and padded, each JWE in full. derived.SealView,
// which draws its own IV, gives the same header and plaintext, and
// derived.OpenView opens the candidates at the URL fetched and at no
// other. The hit's members are §I.23's: those it serves in the clear and
// those its per-entry JWE seals.
func TestV085C4WholeResponse(t *testing.T) {
	t.Parallel()
	p := loadCandidates(t).C4
	i23 := loadAddendumI(t).I23
	ks := grantcheck.KeySubject(p.Kid, p.Pub)
	if ks != p.KeySubject {
		t.Errorf("the key: string of %s is %s, want %s", p.Kid, ks, p.KeySubject)
	}
	marker := "reads:demo:" + ks
	if marker != p.Marker {
		t.Errorf("the marker is %s, want %s", marker, p.Marker)
	}
	gs := grantcheck.SubjectSetID([]string{marker})
	if gs != p.GS {
		t.Errorf("the gs over %s is %s, want %s", marker, gs, p.GS)
	}
	cq := derived.CanonicalQuery(url.Values{"q": {i23.Q}, "sort": {i23.Sort}, "min": {nsID2}}, "min")
	view := "/demo/g/" + gs + "/at/" + nsID2 + cq
	if view != p.View {
		t.Fatalf("view\n%s\nwant\n%s", view, p.View)
	}
	kn, err := seal.NamespaceKey(seq(0x00), "demo")
	if err != nil {
		t.Fatal(err)
	}
	vk, err := seal.ViewKey(kn, view)
	if err != nil || hex.EncodeToString(vk) != p.ViewKeyKn {
		t.Errorf("the view key of K_n is %x %v, want %s", vk, err, p.ViewKeyKn)
	}
	v := derived.View{NS: "demo", Target: view}
	pt := []byte(p.Plaintext)
	if !bytes.Equal(jsonv.Canonical(jsonv.MustParse(pt)), pt) || len(pt) != p.PlaintextBytes {
		t.Errorf("the plaintext isn't canonical JSON of %d bytes", p.PlaintextBytes)
	}
	header := func(jwe string) string {
		b, err := base64.RawURLEncoding.DecodeString(jwe[:strings.IndexByte(jwe, '.')])
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	jwe, err := seal.SealWithIV(vk, "demo#3", v.PL(), pt, fixedIV)
	if err != nil {
		t.Fatal(err)
	}
	if jwe != p.JWE || header(jwe) != p.Header {
		t.Errorf("the whole response seals as\n%s\nwant\n%s", jwe, p.JWE)
	}
	// Padded: the canonical JSON followed by spaces to its bucket.
	pp := seal.Pad(pt)
	if len(pp) != p.PaddedBytes || !bytes.HasPrefix(pp, pt) || strings.Trim(string(pp[len(pt):]), " ") != "" {
		t.Errorf("the padded plaintext is %d bytes, want %d: the plaintext and spaces", len(pp), p.PaddedBytes)
	}
	padded, err := seal.SealWithIV(vk, "demo#3", v.PL(), pp, fixedIV)
	if err != nil {
		t.Fatal(err)
	}
	if padded != p.PaddedJWE {
		t.Errorf("the padded response seals as\n%s\nwant\n%s", padded, p.PaddedJWE)
	}
	// The services' sealing and reading.
	keyOf := func(kid string) []byte {
		if kid == "demo#3" {
			return seq(0x00)
		}
		return nil
	}
	for _, pad := range []bool{false, true} {
		own, err := derived.SealView(derived.Key{NS: "demo", Epoch: 3, K: seq(0x00), Pad: pad}, v, jsonv.MustParse(pt))
		if err != nil {
			t.Fatal(err)
		}
		if header(own) != p.Header {
			t.Errorf("the service's header (pad %v) is %s, want %s", pad, header(own), p.Header)
		}
		want := pt
		if pad {
			want = pp
		}
		if got, err := derived.OpenView(own, keyOf, v); err != nil || !bytes.Equal(got, want) {
			t.Errorf("the service's sealing (pad %v) opens to %s %v", pad, got, err)
		}
	}
	for what, c := range map[string]struct {
		jwe  string
		want []byte
	}{"the candidate": {p.JWE, pt}, "the padded candidate": {p.PaddedJWE, pp}} {
		if got, err := derived.OpenView(c.jwe, keyOf, v); err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s opens to %s %v", what, got, err)
		}
		// At I.8's gs, §I.23's view, it is another URL's.
		if got, err := derived.OpenView(c.jwe, keyOf, derived.View{NS: "demo", Target: i23.View}); err == nil {
			t.Errorf("%s opened at §I.23's view: %s", what, got)
		}
	}
	// The hit: §I.23's clear members and its sealed ones, and no other.
	hit := jsonv.MustParse(pt).(map[string]any)["hits"].([]any)[0].(map[string]any)
	served := jsonv.MustParse([]byte(strings.Replace(i23.Served, "%s", "x", 1))).(map[string]any)
	sealedVals := jsonv.MustParse([]byte(i23.Item.Plaintext)).(map[string]any)
	for k, x := range hit {
		if _, clear := served[k]; clear {
			if !jsonv.Equal(served[k], x) {
				t.Errorf("§I.23's served hit has %s %v, the whole response %v", k, served[k], x)
			}
		} else if !jsonv.Equal(sealedVals[k], x) {
			t.Errorf("§I.23's hit seals %s as %v, the whole response has %v", k, sealedVals[k], x)
		}
	}
	if len(hit) != len(served)-1+len(sealedVals) {
		t.Errorf("the hit's members split into %d clear and %d sealed, of %d", len(served)-1, len(sealedVals), len(hit))
	}
}

// c5Rows builds C.5's two bundles from §I.20's: the grant line's key.kid
// made ops-2027, and its key.pub made the key of seed 20 21 … 3f (§I.21's
// ops-2027). Nothing else changes: the grant id, root and stored block
// are I.4's.
func c5Rows(t *testing.T) [2]string {
	t.Helper()
	b := loadAddendumI(t).I20.Bundle
	const key = `"key":{"alg":"Ed25519","kid":"ops-2026","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}`
	if strings.Count(b, key) != 1 {
		t.Fatal("§I.20's grant line doesn't carry ops-2026 with I.14's pub as key")
	}
	return [2]string{
		strings.Replace(b, key, strings.Replace(key, `"kid":"ops-2026"`, `"kid":"ops-2027"`, 1), 1),
		strings.Replace(b, key, strings.Replace(key, "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg", i21Ops2027Pub, 1), 1),
	}
}

// i21Ops2027Pub is the Ed25519 public key of seed 20 21 … 3f, which §I.21
// lists as ops-2027.
const i21Ops2027Pub = "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc"

// C.5 (§G.4.1, v0.85), the computed values: the two bundles have the
// candidate's sha-256, and the second's key.pub is the key the reference
// derives from the seed 20 21 … 3f. That a reader rejects them whole is
// TestV085C5GrantLineKeyRejected (v085_pending_test.go).
func TestV085C5GrantLineKey(t *testing.T) {
	t.Parallel()
	p := loadCandidates(t).C5
	rows := c5Rows(t)
	if len(p.Rows) != len(rows) {
		t.Fatalf("%d rows in candidates.json, want %d", len(p.Rows), len(rows))
	}
	rules := [2]string{"a grant line whose `key` has a `kid` other than `root.kid`", "a grant line whose `key` doesn't verify the `stored` block"}
	for i, b := range rows {
		if p.Rows[i].Rule != rules[i] {
			t.Fatalf("row %d (%s) is no %q row", i, p.Rows[i].Rule, rules[i])
		}
		if got := sha256Hex([]byte(b)); got != p.Rows[i].SHA256 {
			t.Errorf("%s: the bundle is sha-256 %s, want %s", p.Rows[i].Change, got, p.Rows[i].SHA256)
		}
	}
	if pub := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seq(0x20)).Public().(ed25519.PublicKey)); pub != i21Ops2027Pub {
		t.Errorf("the key of seed 20 21 … 3f is %s, want %s", pub, i21Ops2027Pub)
	}
}
