package ids

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// The ids of Addendum I.2: the genesis g of patches₁, its child c by
// patches₂ and the tombstone of c, in text and binary form (§3.3, §3.4).
func TestRevisionAndTombstone(t *testing.T) {
	t.Parallel()
	g := Revision(nil, []byte(`[{"op":"add","path":"","value":{"title":"Hello","views":0}}]`))
	c := Revision(&g, []byte(`[{"op":"replace","path":"/views","value":1}]`))
	for _, v := range []struct {
		what     string
		id       ID
		text, hx string
	}{
		{"g", g, "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll", "5e8c8d1cecdd67fd2e5a750b07aa0f91fd4ab16b"},
		{"c", c, "1sywh54kpo3c4ezn2znktvl3avge4zl5d", "962c7ef14f76c5c265bacb553aaf60a989ccafa3"},
		{"tombstone of c", Tombstone(c), "1idx6u2b3z42obqmwsgmlzvrfuutks2bq", "40efea683bcf34e0c1969198bcd625a526a96830"},
	} {
		if v.id.String() != v.text || hex.EncodeToString(v.id[:]) != v.hx {
			t.Errorf("%s = %s (%x), want %s (%s)", v.what, v.id, v.id[:], v.text, v.hx)
		}
		if got := FromBytes(v.id[:]); got != v.id {
			t.Errorf("FromBytes(%x) = %x", v.id[:], got[:])
		}
	}
	// A tombstone is the hash of "tombstone" after its parent (§3.4).
	if Tombstone(c) != Hash(&c, []byte("tombstone")) {
		t.Error("Tombstone(c) is not Hash(c, \"tombstone\")")
	}
}

// The namespace chain of I.2 (§3.5): the first entry hashes after an
// empty previous id, the next after the first's.
func TestNamespaceChain(t *testing.T) {
	t.Parallel()
	n1 := Hash(nil, []byte(`{"kind":"config","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}`))
	n2 := Hash(&n1, []byte(`{"kind":"head","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}`))
	if n1.String() != "1vmctae4vewju6nvxi374rkrkmyzpdrif" || n2.String() != "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm" {
		t.Errorf("ns_id₁ %s, ns_id₂ %s", n1, n2)
	}
	// An empty previous id is zero bytes, not twenty zero bytes.
	var zero ID
	if Hash(nil, []byte("x")) == Hash(&zero, []byte("x")) {
		t.Error("a nil parent hashes as a zero id")
	}
}

// Blob ids of I.3 (§3.7).
func TestBlob(t *testing.T) {
	t.Parallel()
	data := []byte("hello patchlog\n")
	if got := Blob("text/plain", "", data).String(); got != "1m5jj344d7tz7cicfmq53ayhmwuubpmyt" {
		t.Errorf("no nonce: %s", got)
	}
	if got := Blob("text/plain", "aaaaaaaaaaaaaaaaaaaaaaaaaa", data).String(); got != "1hdwkfub2zymqzgc75snybxosfk67633s" {
		t.Errorf("nonce: %s", got)
	}
	// The fields are delimited: moving a byte across a boundary changes the id.
	if Blob("text/plain", "", data) == Blob("text/plai", "n", data) {
		t.Error("blob id fields run together")
	}
}

// Of over canonical JSON: I.4's grant id and I.8's gs and combined
// checkpoint (§C.3, §B.11.5, §B.5).
func TestOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}`: "15swdvi5nbnlkv76v7y6k77h52atov6ru",
		`["group:match-desk","user:anna"]`: "17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm",
		`{"cat":"1vmctae4vewju6nvxi374rkrkmyzpdrif","matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"}`: "1vwnfnoyshruyx4lul4a25rtctooiph5v",
	} {
		if got := Of(jsonv.Canonical(jsonv.MustParse([]byte(in)))).String(); got != want {
			t.Errorf("Of(%s) = %s, want %s", in, got, want)
		}
	}
	// I.9: a bundle digest is Of over the bytes as written (§G.4.1).
	b := `{"authors":false,"bundle":1,"origin":"https://staging.example"}` + "\n" +
		`{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}` + "\n"
	if got := Of([]byte(b)).String(); got != "1b3a64kkqf3o6f3rglkgi6ok5hgldbne6" {
		t.Errorf("bundle digest %s", got)
	}
}

// The text form (§3.2, I.2): exactly 33 characters, "1" then 32 of
// a–z2–7. 160 bits fill 32 characters exactly, so every such string is an
// id, the old draft's "trailing-bit" vector included, and reads back as
// itself.
func TestParse(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"1L2GI2HHM3VT72LS2OUFQPKQPSH6UVMLL",  // uppercase
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvml",   // 32 characters
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvml1",  // "1" isn't in the alphabet
		"2l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",  // unknown version prefix
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlla", // 34 characters
		"l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",
		"1l2gi2hhm3vt72ls2oufqpkqpsh6uvml=",
		" 1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",
		"",
	} {
		if id, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted as %s", s, id)
		}
	}
	// One character outside the alphabet anywhere in the data part.
	const g = "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"
	for i := 1; i < len(g); i++ {
		for _, c := range "0189AZ=-_" {
			s := g[:i] + string(c) + g[i+1:]
			if _, err := Parse(s); err == nil {
				t.Errorf("Parse(%q) accepted", s)
			}
		}
	}
	// Every last character is valid: there are no padding bits.
	for _, c := range "abcdefghijklmnopqrstuvwxyz234567" {
		s := g[:32] + string(c)
		id, err := Parse(s)
		if err != nil || id.String() != s {
			t.Errorf("Parse(%s) = %s %v", s, id, err)
		}
	}
	if id, err := Parse("1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm"); err != nil || hex.EncodeToString(id[:]) != "5e8c8d1cecdd67fd2e5a750b07aa0f91fd4ab16c" {
		t.Errorf("trailing-bit vector: %x %v", id[:], err)
	}
}

// String and Parse are inverse over random ids.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		var id ID
		for i := range id {
			id[i] = byte(r.Uint32())
		}
		s := id.String()
		if len(s) != 33 || s[0] != '1' || strings.ToLower(s) != s {
			t.Fatalf("String(%x) = %q", id[:], s)
		}
		back, err := Parse(s)
		if err != nil || !bytes.Equal(back[:], id[:]) {
			t.Fatalf("Parse(%s) = %x %v, want %x", s, back[:], err, id[:])
		}
	}
}
