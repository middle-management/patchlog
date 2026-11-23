package vectors_test

// v0.89's derived keys (§E.2.1) in Addendum I: §I.7's K_rev, K_log,
// K_blob and K_view; §I.12's K_view wrapped; §I.13's document of g under
// K_rev(g) and I.3's blob under its K_blob; and §I.27's view's keys and
// filtered answers under K_view. Each is computed through the reference's
// production code (seal.RevKey, LogKey, BlobKey, FilterViewKey,
// WrapViewKey, ViewKeysPL, ViewKeys.Plaintext, FilteredPlaintext,
// FilteredRangePL, FilteredHeadsPL) and compared with the value
// testdata/addendum_i.json copies from docs/SPEC.md. §I.19's rows and
// §I.23's hit are TestI19SealedPayloads' and TestI23ViewKey's.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// i27Addendum is the part of testdata/addendum_i.json these tests read.
type i27Addendum struct {
	I7 struct {
		Keys map[string]string
	} `json:"I.7"`
	I12 struct{ Enc, ViewInfo, ViewCiphertext string } `json:"I.12"`
	I13 struct {
		DocHeader, DocJWETail, DocPaddedTag string
		BlobHeader, Blob                    string
		BlobBytes, BlobPaddedBytes          int
	} `json:"I.13"`
	I19 struct{ Plaintexts map[string]string } `json:"I.19"`
	I27 struct {
		PL, Plaintext, JWE, PaddedTag string
		WithBlob                      struct{ Plaintext, Tag, PaddedTag string }
		Answers                       []struct{ Answer, PL, Body, Tag, PaddedTag string }
		RangePlaintextBytes           int
		RangeJWEBytes                 int
		RangeJWESHA256                string `json:"rangeJWESHA256"`
		HeadsPlaintextBytes           int
		Rejected                      string
	} `json:"I.27"`
}

const (
	i8View  = "17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm"
	i3Blob  = "1m5jj344d7tz7cicfmq53ayhmwuubpmyt"
	i3Bytes = "hello patchlog\n"
)

func loadI27(t *testing.T) i27Addendum {
	t.Helper()
	var f i27Addendum
	if !golden.Load(t, "addendum_i", &f) {
		t.Fatal("testdata/addendum_i.json is missing")
	}
	return f
}

// derivedKeys are I.7's keys as the reference derives them from K_e
// 00 01 … 1f.
type derivedKeys struct {
	kr, kn, view               []byte
	revG, revC, logG, logC, lt []byte
	blob                       []byte
}

func i7Keys(t *testing.T) derivedKeys {
	t.Helper()
	ke := seq(0x00)
	var k derivedKeys
	var err error
	must := func(b []byte, e error) []byte {
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	k.kr = must(seal.ResourceKey(ke, "demo", "derby"))
	k.kn = must(seal.NamespaceKey(ke, "demo"))
	k.revG = must(seal.RevKey(k.kr, idG))
	k.revC = must(seal.RevKey(k.kr, idC))
	k.logG = must(seal.LogKey(k.kr, idG))
	k.logC = must(seal.LogKey(k.kr, idC))
	k.lt = must(seal.LogKey(k.kr, idT))
	k.blob = must(seal.BlobKey(k.kr, i3Blob))
	k.view, err = seal.FilterViewKey(ke, "demo", i8View)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// I.7 (§E.2.1, v0.89): the keys below K_r and K_e.
func TestI7DerivedKeys(t *testing.T) {
	t.Parallel()
	p := loadI27(t).I7
	k := i7Keys(t)
	got := map[string][]byte{
		"K_r": k.kr, "K_n": k.kn, "K_rev(g)": k.revG, "K_rev(c)": k.revC,
		"K_log(g)": k.logG, "K_log(c)": k.logC, "K_log(t)": k.lt, "K_blob": k.blob, "K_view": k.view,
	}
	if len(p.Keys) != len(got) {
		t.Fatalf("addendum_i.json lists %d keys of I.7, want %d", len(p.Keys), len(got))
	}
	for name, want := range p.Keys {
		if hex.EncodeToString(got[name]) != want {
			t.Errorf("%s = %x, want %s (§I.7)", name, got[name], want)
		}
	}
	// One way, no siblings: no derived key is another (§E.2.1).
	seen := map[string]string{}
	for name, b := range got {
		if o, dup := seen[string(b)]; dup {
			t.Errorf("%s = %s", name, o)
		}
		seen[string(b)] = name
	}
}

// I.12 (§E.2.3, v0.89): K_view wrapped in base mode to the recipient
// under the fixed ephemeral key, info "patchlog-key-v1\ndemo#3\nview:{view}".
func TestI12ViewKeyWrapped(t *testing.T) {
	t.Parallel()
	p := loadI27(t).I12
	k := i7Keys(t)
	recipient, eph := x25519(t, recipientSeed), x25519(t, ephemeralSeed)
	if p.ViewInfo != "patchlog-key-v1\ndemo#3\n"+seal.ViewWrapName(i8View) {
		t.Fatalf("§I.12's info is %q", p.ViewInfo)
	}
	w, err := seal.WrapKeyWithEphemeral(eph, recipient.PublicKey(), "demo#3", seal.ViewWrapName(i8View), k.view)
	if err != nil {
		t.Fatal(err)
	}
	if enc, ct := hex.EncodeToString(w.Wrapped[:32]), hex.EncodeToString(w.Wrapped[32:]); enc != p.Enc || ct != p.ViewCiphertext {
		t.Errorf("K_view wraps to enc %s, ciphertext %s; want %s, %s", enc, ct, p.Enc, p.ViewCiphertext)
	}
	// As /keys lists it, { kid, view, wrapped }: read back and opened.
	w.Resource, w.View = "", i8View
	entry := jsonv.Canonical(w.Value())
	back, err := seal.ParseWrappedKey(entry)
	if err != nil || back.View != i8View || back.Resource != "" {
		t.Fatalf("%s read as %+v %v", entry, back, err)
	}
	if got, err := seal.UnwrapKey(recipient, back); err != nil || !bytes.Equal(got, k.view) {
		t.Errorf("the /keys entry opens to %x %v", got, err)
	}
	// The production wrapper, under its own ephemeral key, opens too, and
	// a K_view is no K_r of a resource named "view:{view}" on the wire.
	pw, err := seal.WrapViewKey(recipient.PublicKey(), "demo#3", i8View, k.view)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := seal.UnwrapKey(recipient, pw); err != nil || !bytes.Equal(got, k.view) {
		t.Errorf("WrapViewKey opens to %x %v", got, err)
	}
	pw.View = "1h3svqdgo2zzbsi4ue4judyzylpexfd6q"
	if _, err := seal.UnwrapKey(recipient, pw); err == nil {
		t.Error("a K_view opened as another view's")
	}
}

// I.13 (§E.2.2, v0.89): g's document under K_rev(g), and I.3's blob under
// its K_blob, unpadded and padded.
func TestI13DerivedSealing(t *testing.T) {
	t.Parallel()
	p := loadI27(t).I13
	k := i7Keys(t)
	pl := seal.ResourcePL("demo", "derby", idG, seal.KindDoc)
	doc := []byte(`{"title":"Hello","views":0}`)
	jwe, tag, padded := sealedTags(t, k.revG, pl, doc)
	hdr, _, _ := strings.Cut(jwe, ".")
	raw, _ := b64u.DecodeString(hdr)
	if string(raw) != p.DocHeader || jwe != hdr+p.DocJWETail {
		t.Errorf("g's document seals as\n%s\nwant header %s and %s", jwe, p.DocHeader, p.DocJWETail)
	}
	if padded != p.DocPaddedTag {
		t.Errorf("padded: tag %s, want %s", padded, p.DocPaddedTag)
	}
	_ = tag
	// Not under K_r, nor K_log(g).
	for what, key := range map[string][]byte{"K_r": k.kr, "K_log(g)": k.logG} {
		if _, err := seal.OpenExpect(jwe, key, "demo#3", pl); !errors.Is(err, seal.ErrDecrypt) {
			t.Errorf("g's document opened under %s: %v", what, err)
		}
	}

	bpl := seal.BlobPL("demo", "derby", i3Blob)
	sb, err := seal.SealBlobWithIV(k.blob, "demo#3", bpl, []byte(i3Bytes), false, fixedIV)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sb) != p.Blob || len(sb) != p.BlobBytes {
		t.Errorf("the blob seals as %d bytes\n%x\nwant %d\n%s", len(sb), sb, p.BlobBytes, p.Blob)
	}
	h, data, err := seal.OpenBlob(sb, k.blob)
	if err != nil || string(data) != i3Bytes || string(h.Raw) != p.BlobHeader {
		t.Errorf("the blob opens to %q %v, header %s", data, err, h.Raw)
	}
	pb, err := seal.SealBlobWithIV(k.blob, "demo#3", bpl, []byte(i3Bytes), true, fixedIV)
	if err != nil || len(pb) != p.BlobPaddedBytes {
		t.Errorf("padded, the blob is %d bytes %v, want %d", len(pb), err, p.BlobPaddedBytes)
	}
	if _, _, err := seal.OpenBlob(sb, k.kr); !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("the blob opened under K_r: %v", err)
	}
}

// I.27 (§E.2.2, §7.9, v0.89): a view's keys for g, sealed under K_view,
// with and without a blob; the filtered namespace range from the start
// and the first /heads page at ns_id₂, each {body, keys: [that keys
// JWE]}; and the rejections.
func TestI27FilteredAnswers(t *testing.T) {
	t.Parallel()
	all := loadI27(t)
	p := all.I27
	k := i7Keys(t)
	kpl := seal.ViewKeysPL("demo", i8View, "derby", idG)
	if got := string(jsonv.Canonical(jsonv.FromGo(map[string]any(kpl)))); got != p.PL {
		t.Errorf("keys pl %s, want %s", got, p.PL)
	}
	vk := seal.ViewKeys{Key: k.revG, Log: k.logG}
	if got := string(vk.Plaintext()); got != p.Plaintext {
		t.Errorf("keys plaintext %s, want %s", got, p.Plaintext)
	}
	keysJWE, _, keysPadded := sealedTags(t, k.view, kpl, vk.Plaintext())
	if keysJWE != p.JWE {
		t.Errorf("the view's keys for g seal as\n%s\nwant\n%s", keysJWE, p.JWE)
	}
	if keysPadded != p.PaddedTag {
		t.Errorf("padded: tag %s, want %s", keysPadded, p.PaddedTag)
	}
	withBlob := seal.ViewKeys{Key: k.revG, Log: k.logG, Blobs: map[string][]byte{i3Blob: k.blob}}
	if got := string(withBlob.Plaintext()); got != p.WithBlob.Plaintext {
		t.Errorf("with the blob: %s, want %s", got, p.WithBlob.Plaintext)
	}
	if _, tag, padded := sealedTags(t, k.view, kpl, withBlob.Plaintext()); tag != p.WithBlob.Tag || padded != p.WithBlob.PaddedTag {
		t.Errorf("with the blob: tags %s and %s, want %s and %s", tag, padded, p.WithBlob.Tag, p.WithBlob.PaddedTag)
	}
	// They open I.13's document of g and sealed blob, and I.19's entry_g.
	pt, err := seal.OpenExpect(keysJWE, k.view, "demo#3", kpl)
	if err != nil {
		t.Fatal(err)
	}
	got, err := seal.ParseViewKeys(pt)
	if err != nil || !bytes.Equal(got.Key, k.revG) || !bytes.Equal(got.Log, k.logG) || len(got.Blobs) != 0 {
		t.Fatalf("keys read as %+v %v", got, err)
	}
	if _, err := seal.OpenExpect(mustSeal(t, got.Key, seal.ResourcePL("demo", "derby", idG, seal.KindDoc), []byte(`{"title":"Hello","views":0}`)),
		got.Key, "demo#3", seal.ResourcePL("demo", "derby", idG, seal.KindDoc)); err != nil {
		t.Errorf("the carried key doesn't open g's document: %v", err)
	}
	entryPL := seal.ResourcePL("demo", "derby", idG, seal.KindRev)
	entryJWE := mustSeal(t, k.logG, entryPL, []byte(all.I19.Plaintexts["entry_g"]))
	if _, err := seal.OpenExpect(entryJWE, got.Log, "demo#3", entryPL); err != nil {
		t.Errorf("the carried log key doesn't open entry_g: %v", err)
	}

	pts := all.I19.Plaintexts
	bodies := []any{
		jsonv.MustParse([]byte(sealedPlaintext(t, pts, "[nsentry₁,nsentry₂]"))),
		jsonv.MustParse([]byte(p.Answers[1].Body)),
	}
	pls := []seal.PL{
		seal.FilteredRangePL("demo", i8View, "", nsID2),
		seal.FilteredHeadsPL("demo", i8View, nsID2, ""),
	}
	if len(p.Answers) != len(pls) {
		t.Fatalf("%d answers, want %d", len(p.Answers), len(pls))
	}
	var rangeJWE string
	for i, a := range p.Answers {
		if got := string(jsonv.Canonical(jsonv.FromGo(map[string]any(pls[i])))); got != a.PL {
			t.Errorf("%s: pl %s, want %s", a.Answer, got, a.PL)
		}
		plain := seal.FilteredPlaintext(bodies[i], []string{keysJWE})
		jwe, tag, padded := sealedTags(t, k.view, pls[i], plain)
		if tag != a.Tag || padded != a.PaddedTag {
			t.Errorf("%s: tags %s and %s, want %s and %s", a.Answer, tag, padded, a.Tag, a.PaddedTag)
		}
		switch i {
		case 0:
			rangeJWE = jwe
			if len(plain) != p.RangePlaintextBytes || len(jwe) != p.RangeJWEBytes || sha256Hex([]byte(jwe)) != p.RangeJWESHA256 {
				t.Errorf("the range: plaintext %d bytes, JWE %d bytes, sha-256 %s; want %d, %d, %s",
					len(plain), len(jwe), sha256Hex([]byte(jwe)), p.RangePlaintextBytes, p.RangeJWEBytes, p.RangeJWESHA256)
			}
		case 1:
			if len(plain) != p.HeadsPlaintextBytes || seal.PadLen(len(plain)) != len(plain) {
				t.Errorf("the /heads plaintext is %d bytes, want %d, a bucket size", len(plain), p.HeadsPlaintextBytes)
			}
		}
		// Each opens under K_view, and its body and keys read back.
		opened, err := seal.OpenExpect(jwe, k.view, "demo#3", pls[i])
		if err != nil {
			t.Fatalf("%s: %v", a.Answer, err)
		}
		body, keys, err := seal.ParseFiltered(opened)
		if err != nil || len(keys) != 1 || keys[0] != keysJWE || !jsonv.Equal(body, bodies[i]) {
			t.Errorf("%s reads back as %v %v %v", a.Answer, body, keys, err)
		}
		// Rejected: any of these under K_n or K_r.
		for what, key := range map[string][]byte{"K_n": k.kn, "K_r": k.kr} {
			if _, err := seal.OpenExpect(jwe, key, "demo#3", pls[i]); !errors.Is(err, seal.ErrDecrypt) {
				t.Errorf("%s opened under %s: %v", a.Answer, what, err)
			}
		}
	}
	if !strings.Contains(p.Rejected, "unfiltered range's `pl`, without `view`") {
		t.Fatalf("§I.27's rejections changed: %s", p.Rejected)
	}
	// The range's JWE read as the unfiltered range, pl without view.
	if _, err := seal.OpenExpect(rangeJWE, k.view, "demo#3", seal.RangePL("demo", "", nsID2)); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("the filtered range read with the unfiltered pl: %v, want a mismatch", err)
	}
	for what, key := range map[string][]byte{"K_n": k.kn, "K_r": k.kr} {
		if _, err := seal.OpenExpect(keysJWE, key, "demo#3", kpl); !errors.Is(err, seal.ErrDecrypt) {
			t.Errorf("the view's keys opened under %s: %v", what, err)
		}
	}
}

func mustSeal(t *testing.T, key []byte, pl seal.PL, pt []byte) string {
	t.Helper()
	j, err := seal.SealWithIV(key, "demo#3", pl, pt, fixedIV)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
