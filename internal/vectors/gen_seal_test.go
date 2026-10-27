package vectors_test

// The encryption vectors (Addendum E, §G.5.1.1): keyring wraps in HPKE
// base and auth mode (the writer's list), /keys entries, sealed payloads
// with each pl, sealed blobs, sealed bundles, and the E3 per-resource key.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// The fixed X25519 keys and the epoch key: the recipient (a reader's
// enc), the sender (a key-holding admin), the HPKE ephemeral key the hooks
// take, and K_e, I.7's 00 01 … 1f.
var (
	recipientSeed = seq(0x20)
	senderSeed    = seq(0x40)
	ephemeralSeed = seq(0x60)
	otherSeed     = seq(0x80)
	epochKey      = seq(0x00)
	fixedIV       = seq(0xc0)[:12]
)

func x25519(t *testing.T, b []byte) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// keyObj describes a fixed X25519 key: its private bytes, public JWK x and
// RFC 7638 thumbprint, with the JWK whose canonical form is hashed.
func keyObj(t *testing.T, name string, priv *ecdh.PrivateKey) obj {
	return obj{{Key: "name", Value: name}, {Key: "fn", Value: "seal.RecipientJWK, seal.Thumbprint"},
		{Key: "private", Value: golden.Hex(priv.Bytes())},
		{Key: "jwk", Value: string(jsonv.Canonical(seal.RecipientJWK(priv.PublicKey())))},
		{Key: "thumbprint", Value: seal.Thumbprint(priv.PublicKey())}}
}

// ---- 2, 3. Keyring wraps (§E.2.3, §E.3.2; ENC-7, ENC-10, ENC-11) ----

// TestVectorKeyWraps: a key wrapped to a reader's enc in HPKE base mode
// (K_e and K_r, §E.2.3), and a keyring entry wrapped in auth mode under
// the admin's key (§E.3.2), each under the fixed ephemeral key, so the
// wrap can be reproduced; any wrap, whatever its ephemeral key, opens to
// the same key, which the test checks with the production wrappers too.
func TestVectorKeyWraps(t *testing.T) {
	t.Parallel()
	recipient, sender, eph, other := x25519(t, recipientSeed), x25519(t, senderSeed), x25519(t, ephemeralSeed), x25519(t, otherSeed)
	kr, err := seal.ResourceKey(epochKey, "demo", "derby")
	if err != nil {
		t.Fatal(err)
	}
	kid := seal.Kid("demo", 3)
	var vs []any

	// Base mode (§E.2.3): K_e (name empty, the info ends in LF) and K_r.
	for _, c := range []struct {
		name, resource string
		key            []byte
	}{{"K_e, base mode", "", epochKey}, {"K_r, base mode", "derby", kr}} {
		w, err := seal.WrapKeyWithEphemeral(eph, recipient.PublicKey(), kid, c.resource, c.key)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := seal.UnwrapKey(recipient, w); err != nil || !bytes.Equal(got, c.key) {
			t.Fatalf("%s: UnwrapKey %x, %v", c.name, got, err)
		}
		if got, err := seal.UnwrapRelayed(recipient, w, nil); err != nil || !bytes.Equal(got, c.key) {
			t.Fatalf("%s: UnwrapRelayed %x, %v", c.name, got, err)
		}
		if _, err := seal.UnwrapKey(other, w); err == nil {
			t.Fatalf("%s: opened by another key", c.name)
		}
		fresh, err := seal.WrapKey(recipient.PublicKey(), kid, c.resource, c.key)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := seal.UnwrapKey(recipient, fresh); err != nil || !bytes.Equal(got, c.key) || bytes.Equal(fresh.Wrapped, w.Wrapped) {
			t.Fatalf("%s: WrapKey (fresh ephemeral) opens to %x, %v", c.name, got, err)
		}
		vs = append(vs, obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "seal.WrapKeyWithEphemeral (opened by seal.UnwrapKey)"},
			{Key: "mode", Value: "base"}, {Key: "suite", Value: "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM"},
			{Key: "recipient_private", Value: golden.Hex(recipient.Bytes())}, {Key: "ephemeral_private", Value: golden.Hex(eph.Bytes())},
			{Key: "kid", Value: kid}, {Key: "resource", Value: c.resource},
			{Key: "info", Value: seal.WrapInfoPrefix + kid + "\n" + c.resource}, {Key: "aad", Value: ""},
			{Key: "key", Value: golden.Hex(c.key)},
			{Key: "enc", Value: golden.Hex(w.Wrapped[:32])}, {Key: "ct", Value: golden.Hex(w.Wrapped[32:])},
			{Key: "entry", Value: string(jsonv.Canonical(w.Value()))}})
	}

	// Auth mode (§E.3.2): the admin wraps K_e for the reader; the entry
	// opens only under the sender its from names.
	w, err := seal.WrapKeyAuthWithEphemeral(eph, sender, recipient.PublicKey(), kid, "", epochKey)
	if err != nil {
		t.Fatal(err)
	}
	e := seal.KeyringEntry{Kid: kid, To: seal.Thumbprint(recipient.PublicKey()), From: seal.Thumbprint(sender.PublicKey()), Wrapped: w.Wrapped}
	ring := &seal.KeyringV2{Entries: []seal.KeyringEntry{e}}
	doc := jsonv.Canonical(ring.Value())
	parsed, err := seal.ParseKeyringV2(doc)
	if err != nil || len(parsed.Entries) != 1 || !bytes.Equal(jsonv.Canonical(parsed.Value()), doc) {
		t.Fatalf("ParseKeyringV2: %v", err)
	}
	if got, err := parsed.Entries[0].Open(recipient, sender.PublicKey()); err != nil || !bytes.Equal(got, epochKey) {
		t.Fatalf("entry Open %x, %v", got, err)
	}
	if got, err := parsed.EpochKey(recipient, kid, []*ecdh.PublicKey{sender.PublicKey()}); err != nil || !bytes.Equal(got, epochKey) {
		t.Fatalf("EpochKey %x, %v", got, err)
	}
	if _, err := parsed.EpochKey(recipient, kid, []*ecdh.PublicKey{other.PublicKey()}); err == nil {
		t.Fatal("EpochKey trusted an entry from a sender not trusted")
	}
	if _, err := seal.UnwrapKeyAuth(recipient, other.PublicKey(), w); err == nil {
		t.Fatal("an auth-mode wrap opened under another sender")
	}
	if _, err := seal.UnwrapKey(recipient, w); err == nil {
		t.Fatal("an auth-mode wrap opened in base mode")
	}
	relayed := parsed.Entries[0].Relayed()
	if got, err := seal.UnwrapRelayed(recipient, relayed, []*ecdh.PublicKey{sender.PublicKey()}); err != nil || !bytes.Equal(got, epochKey) {
		t.Fatalf("UnwrapRelayed %x, %v", got, err)
	}
	built, err := seal.BuildKeyringV2(sender, "demo", 3, epochKey, []*ecdh.PublicKey{recipient.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := built.EpochKey(recipient, kid, []*ecdh.PublicKey{sender.PublicKey()}); err != nil || !bytes.Equal(got, epochKey) {
		t.Fatalf("BuildKeyringV2 (fresh ephemeral): %x, %v", got, err)
	}
	vs = append(vs, obj{{Key: "name", Value: "K_e, auth mode (keyring entry)"}, {Key: "fn", Value: "seal.WrapKeyAuthWithEphemeral, seal.KeyringV2.Value (opened by seal.KeyringEntry.Open)"},
		{Key: "mode", Value: "auth"}, {Key: "suite", Value: "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM"},
		{Key: "recipient_private", Value: golden.Hex(recipient.Bytes())}, {Key: "sender_private", Value: golden.Hex(sender.Bytes())},
		{Key: "ephemeral_private", Value: golden.Hex(eph.Bytes())},
		{Key: "kid", Value: kid}, {Key: "info", Value: seal.WrapInfoPrefix + kid + "\n"}, {Key: "aad", Value: ""},
		{Key: "key", Value: golden.Hex(epochKey)},
		{Key: "enc", Value: golden.Hex(w.Wrapped[:32])}, {Key: "ct", Value: golden.Hex(w.Wrapped[32:])},
		{Key: "keyring", Value: string(doc)},
		{Key: "relayed by /keys", Value: string(jsonv.Canonical(relayed.Value()))},
		{Key: "opens under another sender", Value: false}})

	golden.Check(t, "keywrap", obj{
		{Key: "section", Value: "§E.2.3, §E.3.2"},
		{Key: "about", Value: "keys wrapped to a reader's X25519 key with HPKE (RFC 9180): base mode for /keys, auth mode under the admin's key for keyring entries; info \"patchlog-key-v1\" LF kid LF name, wrapped = enc ‖ ct; the ephemeral key is fixed so the wrap reproduces"},
		{Key: "keys", Value: []any{keyObj(t, "recipient, seq(0x20)", recipient), keyObj(t, "sender (admin), seq(0x40)", sender), keyObj(t, "ephemeral, seq(0x60)", eph)}},
		{Key: "vectors", Value: vs},
	})
}

// ---- 7. /keys entries (§E.2.3) ----

// TestVectorWrappedKeys: /keys entries {kid, name?, from?, wrapped} as the
// reference writes and reads them, the form before v0.63 it still reads,
// and the entries it refuses.
func TestVectorWrappedKeys(t *testing.T) {
	t.Parallel()
	recipient, sender, eph := x25519(t, recipientSeed), x25519(t, senderSeed), x25519(t, ephemeralSeed)
	kid := seal.Kid("demo", 3)
	kr, _ := seal.ResourceKey(epochKey, "demo", "derby")
	ke, _ := seal.WrapKeyWithEphemeral(eph, recipient.PublicKey(), kid, "", epochKey)
	kre, _ := seal.WrapKeyWithEphemeral(eph, recipient.PublicKey(), kid, "derby", kr)
	auth, _ := seal.WrapKeyAuthWithEphemeral(eph, sender, recipient.PublicKey(), kid, "", epochKey)
	auth.From = seal.Thumbprint(sender.PublicKey())
	wrapped := b64u.EncodeToString(ke.Wrapped)
	var vs []any
	for _, c := range []struct {
		name string
		w    seal.WrappedKey
		key  []byte
	}{
		{"K_e (E2, base mode)", ke, epochKey},
		{"K_r (E2, a grant that fixes /resource)", kre, kr},
		{"keyring entry relayed (E3, auth mode)", auth, epochKey},
	} {
		entry := jsonv.Canonical(c.w.Value())
		back, err := seal.ParseWrappedKey(entry)
		if err != nil {
			t.Fatal(err)
		}
		got, err := seal.UnwrapRelayed(recipient, back, []*ecdh.PublicKey{sender.PublicKey()})
		if err != nil || !bytes.Equal(got, c.key) {
			t.Fatalf("%s: %x, %v", c.name, got, err)
		}
		vs = append(vs, obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "seal.WrappedKey.MarshalJSON (read by seal.ParseWrappedKey, opened by seal.UnwrapRelayed)"},
			{Key: "entry", Value: string(entry)}, {Key: "verdict", Value: "accept"}, {Key: "key", Value: golden.Hex(c.key)}})
	}
	for _, c := range []struct{ name, entry string }{
		{"before v0.63: resource and suite", `{"kid":"` + kid + `","resource":"derby","suite":"` + seal.Suite + `","wrapped":"` + wrapped + `"}`},
		{"name and resource agreeing", `{"kid":"` + kid + `","name":"derby","resource":"derby","wrapped":"` + wrapped + `"}`},
		{"name and resource differing", `{"kid":"` + kid + `","name":"derby","resource":"cup","wrapped":"` + wrapped + `"}`},
		{"another suite", `{"kid":"` + kid + `","suite":"hpke-base-0x0020-0x0001-0x0001","wrapped":"` + wrapped + `"}`},
		{"from not a thumbprint", `{"from":"admin","kid":"` + kid + `","wrapped":"` + wrapped + `"}`},
		{"no wrapped", `{"kid":"` + kid + `"}`},
		{"no kid", `{"wrapped":"` + wrapped + `"}`},
	} {
		v := obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "seal.ParseWrappedKey"}, {Key: "entry", Value: c.entry}}
		w, err := seal.ParseWrappedKey([]byte(c.entry))
		if err != nil {
			v = append(v, golden.Member{Key: "verdict", Value: "reject"})
		} else {
			v = append(v, golden.Member{Key: "verdict", Value: "accept"}, golden.Member{Key: "read as", Value: string(jsonv.Canonical(w.Value()))})
		}
		vs = append(vs, v)
	}
	golden.Check(t, "wrappedkeys", obj{
		{Key: "section", Value: "§E.2.3"},
		{Key: "about", Value: "/keys entries {kid, name?, from?, wrapped}: name for a K_r, from for a keyring entry relayed at E3; keys and wraps as in keywrap.json"},
		{Key: "vectors", Value: vs},
	})
}

// ---- 6. Sealed payloads and blobs (§E.2.2, §E.3.1; ENC-52) ----

// TestVectorSealedPayloads: a JWE for each row of §E.2.2's table and each
// sealed payload of §E.3.1, under a fixed IV, padded and not; the sealed
// blob layout with the E2 and the E3 header; and an E3 patch set under
// K_r with the revision id over its ciphertext.
func TestVectorSealedPayloads(t *testing.T) {
	t.Parallel()
	kr, err := seal.ResourceKey(epochKey, "demo", "derby")
	if err != nil {
		t.Fatal(err)
	}
	kid := seal.Kid("demo", 3)
	doc := []byte(`{"title":"Hello","views":0}`)
	entry := []byte(`{"author":"user:bob","created":"2026-10-04T12:00:00Z","id":"` + idG + `","kind":"rev","parent":"","patches":` + patches1 + `}`)
	var vs []any
	for _, c := range []struct {
		name, keyName string
		key           []byte
		pl            seal.PL
		plaintext     []byte
		pad           bool
	}{
		{"/rev/{id} document", "K_r", kr, seal.ResourcePL("demo", "derby", idG, seal.KindDoc), doc, false},
		{"/rev/{id} document, padded", "K_r", kr, seal.ResourcePL("demo", "derby", idG, seal.KindDoc), doc, true},
		{"resource log entry (rev)", "K_r", kr, seal.ResourcePL("demo", "derby", idG, seal.KindRev), entry, false},
		{"resource log entry (tombstone)", "K_r", kr, seal.ResourcePL("demo", "derby", idT, seal.KindTombstone), []byte(`{"id":"` + idT + `","kind":"tombstone","parent":"` + idC + `"}`), false},
		{"resource purge event", "K_r", kr, seal.ResourceEventPL("demo", "derby", seal.KindPurge), []byte(`{"kind":"purge","resource":"derby"}`), false},
		{"namespace document", "K_e", epochKey, seal.NamespaceDocPL("demo", nsID1), []byte(`{"encryption":{"epoch":3,"level":"sealed"},"read":"public"}`), false},
		{"namespace log range", "K_e", epochKey, seal.RangePL("demo", nsID1, nsID2), []byte(`[` + entry2 + `]`), false},
		{"grant", "K_e", epochKey, seal.GrantPL("demo", i4GrantID), []byte(`{"root":` + i4Root + `}`), false},
		{"E3 patch set", "K_r", kr, seal.PatchSetPL("demo", "derby", ""), []byte(patches1), false},
		{"E3 prune snapshot", "K_r", kr, seal.SnapshotPL("demo", "derby", idC), []byte(`{"title":"Hello","views":1}`), false},
	} {
		pt := c.plaintext
		if c.pad {
			pt = seal.Pad(pt)
		}
		jwe, err := seal.SealWithIV(c.key, kid, c.pl, pt, fixedIV)
		if err != nil {
			t.Fatal(err)
		}
		got, err := seal.OpenExpect(jwe, c.key, kid, c.pl)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("%s: OpenExpect: %v", c.name, err)
		}
		h, _ := seal.ParseHeader(jwe)
		if seal.IsPadded(h, got) != c.pad && c.pad {
			t.Fatalf("%s: not padded", c.name)
		}
		parts := strings.Split(jwe, ".")
		vs = append(vs, obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "seal.SealWithIV (pl from seal.*PL; opened by seal.OpenExpect)"},
			{Key: "key", Value: c.keyName}, {Key: "kid", Value: kid}, {Key: "iv", Value: golden.Hex(fixedIV)},
			{Key: "plaintext", Value: string(c.plaintext)}, {Key: "padded_length", Value: len(pt)},
			{Key: "protected", Value: string(h.Raw)}, {Key: "tag", Value: parts[4]}, {Key: "jwe", Value: jwe}})
	}

	// The E3 patch set as written: one sealed op, its blobs declared, and
	// the revision id over the ciphertext (§E.3.1, §3.3).
	pjwe, _ := seal.SealWithIV(kr, kid, seal.PatchSetPL("demo", "derby", ""), []byte(patches1), fixedIV)
	bid := ids.Blob(seal.BlobContentType, "", []byte("x")).String()
	sealedSet, err := seal.WithBlobs(jsonv.Canonical([]any{map[string]any{"op": "sealed", "value": pjwe}}), []string{bid})
	if err != nil {
		t.Fatal(err)
	}
	set := jsonv.MustParse(sealedSet)
	if j, blobs, ok := seal.SealedOp(set); !ok || j != pjwe || len(blobs) != 1 {
		t.Fatalf("SealedOp: %v %v", blobs, ok)
	}
	if p, err := seal.OpenPatchSet(set, kr, kid, "demo", "derby", ""); err != nil || string(jsonv.Canonical(p)) != patches1 {
		t.Fatalf("OpenPatchSet: %v", err)
	}
	vs = append(vs, obj{{Key: "name", Value: "E3 write: sealed op with declared blobs"}, {Key: "fn", Value: "seal.WithBlobs, ids.Revision (read by seal.SealedOp, seal.OpenPatchSet)"},
		{Key: "patches", Value: string(sealedSet)}, {Key: "revision", Value: ids.Revision(nil, sealedSet).String()}})

	// Sealed blobs (§E.2.2): E2 under K_r with {enc, kid, pl}, padded and
	// not; E3 under the writer's own key with {enc} only (§E.3.1).
	data := []byte("hello patchlog\n")
	plainBid := ids.Blob("text/plain", "", data).String()
	blobKey := seq(0xe0)
	for _, c := range []struct {
		name string
		key  []byte
		kid  string
		pl   seal.PL
		pad  bool
	}{
		{"E2 sealed blob", kr, kid, seal.BlobPL("demo", "derby", plainBid), false},
		{"E2 sealed blob, padded", kr, kid, seal.BlobPL("demo", "derby", plainBid), true},
		{"E3 sealed blob", blobKey, "", nil, false},
	} {
		sb, err := seal.SealBlobWithIV(c.key, c.kid, c.pl, data, c.pad, fixedIV)
		if err != nil {
			t.Fatal(err)
		}
		h, got, err := seal.OpenBlob(sb, c.key)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s: OpenBlob: %v", c.name, err)
		}
		if c.kid != "" {
			if err := h.Expect(c.kid, c.pl); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		hl := int(binary.BigEndian.Uint32(sb[4:8]))
		v := obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "seal.SealBlobWithIV (opened by seal.OpenBlob)"},
			{Key: "key", Value: golden.Hex(c.key)}, {Key: "iv", Value: golden.Hex(fixedIV)}, {Key: "data", Value: string(data)}, {Key: "pad", Value: c.pad},
			{Key: "header", Value: string(h.Raw)}, {Key: "len", Value: golden.Hex(sb[4:8])},
			{Key: "aad", Value: golden.Hex(sb[:8+hl])},
			{Key: "ciphertext_and_tag", Value: golden.Hex(sb[8+hl+12:])},
			{Key: "sealed_length", Value: len(sb)}, {Key: "sealed", Value: golden.Hex(sb)}}
		if c.kid == "" {
			id := ids.Blob(seal.BlobContentType, "", sb).String()
			ref := map[string]any{"$blob": id, "type": seal.BlobContentType, "size": float64(len(sb)),
				"sealed": map[string]any{"key": b64u.EncodeToString(c.key), "type": "text/plain", "size": float64(len(data))}}
			v = append(v, golden.Member{Key: "blob id", Value: id}, golden.Member{Key: "reference", Value: string(jsonv.Canonical(ref))})
		}
		vs = append(vs, v)
	}
	golden.Check(t, "sealed", obj{
		{Key: "section", Value: "§E.2.1, §E.2.2, §E.3.1"},
		{Key: "about", Value: "sealed payloads: JWEs (alg dir, enc A256GCM, protected header {alg, enc, kid, pl}) under K_r = HKDF(K_e, \"patchlog-e2\", ns LF name) or K_e, with K_e = 00 01 … 1f, ns demo, name derby, epoch 3 and a fixed IV; the E3 write; sealed blobs \"PLB1\" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(size ‖ bytes ‖ padding) ‖ tag"},
		{Key: "K_r", Value: golden.Hex(kr)},
		{Key: "vectors", Value: vs},
	})
}

// ---- 5. Sealed bundles (§G.5.1.1; MF-60, MF-61) ----

// The plain bundle the sealed bundles carry: a header and one history
// line, as I.9 but importable.
var plainBundle = `{"at":{"matches":"` + nsID2 + `"},"authors":false,"bundle":1,"created":"2026-10-04T12:00:00Z","docs":{"matches/derby":{"head":"` + idG + `","history":"full"}},"origin":"https://staging.example"}` + "\n" +
	`{"id":"` + idG + `","kind":"rev","ns":"matches","parent":"","patches":` + patches1 + `,"resource":"derby"}` + "\n"

// sealedBundleFile is the stored group, read back for the bundles it
// holds: the writer draws its id, content key, ephemeral keys and IVs at
// random, so the bundles are kept and the checks recomputed over them.
type sealedBundleFile struct {
	Vectors []struct {
		Name   string `json:"name"`
		Sealed string `json:"sealed"`
	} `json:"vectors"`
}

// storedBundles name the sealed bundles the writer drew, which are kept.
var storedBundles = []string{"sealed bundle", "sealed bundle, padded lines", "another sealed bundle"}

// TestVectorSealedBundles: a sealed bundle of the two-line plain bundle,
// and one with padded lines, as seal.NewBundleWriter writes them; what
// seal.OpenBundle and the bundle Reader make of each; and the cases a
// reader must reject (§G.5.1.1, §G.4.1), built from the first bundle's
// own lines or sealed again under its content key. The bundles are written
// under a fixed seed of crypto/rand, and -update writes them; otherwise
// the stored ones are checked, since how the standard library draws its
// randomness may change between Go versions.
func TestVectorSealedBundles(t *testing.T) {
	recipient := x25519(t, recipientSeed)
	src := map[string][]byte{}
	if golden.Updating() {
		for i, name := range storedBundles {
			cryptotest.SetGlobalRandom(t, uint64(i+1))
			var buf bytes.Buffer
			w, err := seal.NewBundleWriter(&buf, []*ecdh.PublicKey{recipient.PublicKey()})
			if err != nil {
				t.Fatal(err)
			}
			w.Pad = strings.Contains(name, "padded")
			if _, err := io.WriteString(w, plainBundle); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			src[name] = buf.Bytes()
		}
	} else {
		var f sealedBundleFile
		if !golden.Load(t, "sealedbundle", &f) {
			t.Fatal("testdata/sealedbundle.json is missing (run with -update to write the vectors)")
		}
		for _, v := range f.Vectors {
			if slices.Contains(storedBundles, v.Name) {
				src[v.Name] = []byte(v.Sealed)
			}
		}
	}
	// Whatever the stored bundles, the writer seals the plain bundle so it
	// opens to the same bytes.
	var fresh bytes.Buffer
	if w, err := seal.NewBundleWriter(&fresh, []*ecdh.PublicKey{recipient.PublicKey()}); err != nil {
		t.Fatal(err)
	} else if _, err := io.WriteString(w, plainBundle); err != nil || w.Close() != nil {
		t.Fatal(err)
	}
	if plain, _, err := openSealed(fresh.Bytes(), recipient); err != nil || plain != plainBundle {
		t.Fatalf("a fresh sealed bundle opens to %q, %v", plain, err)
	}

	for _, name := range storedBundles {
		if src[name] == nil {
			t.Fatalf("no stored %s", name)
		}
	}
	base := src["sealed bundle"]
	lines := strings.SplitAfter(strings.TrimSuffix(string(base), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("the sealed bundle has %d lines, want the envelope and two", len(lines))
	}
	lines[2] += "\n"
	env, _, err := seal.ParseBundleEnvelope([]byte(strings.TrimSuffix(lines[0], "\n")))
	if err != nil {
		t.Fatal(err)
	}
	kb := contentKey(t, recipient, env)
	header, entry, _ := strings.Cut(plainBundle, "\n")
	entry = strings.TrimSuffix(entry, "\n")
	// line seals a line of the bundle under its content key as a writer
	// would, with a fixed IV and the protected header hdr.
	line := func(hdr map[string]any, pt string) string {
		return sealLine(t, kb, hdr, []byte(pt)) + "\n"
	}
	pl := func(n int, last bool, extra ...string) map[string]any {
		p := map[string]any{"bundle": env.ID, "line": float64(n)}
		if last {
			p["last"] = true
		}
		h := map[string]any{"alg": "dir", "enc": "A256GCM", "pl": p}
		for i := 0; i+1 < len(extra); i += 2 {
			switch extra[i] {
			case "bundle":
				p["bundle"] = extra[i+1]
			case "top-last":
				delete(p, "last")
				h["last"] = true
			}
		}
		return h
	}
	otherLines := strings.SplitAfter(string(src["another sealed bundle"]), "\n")

	vs := []any{}
	for _, c := range []struct {
		name, sealed string
		stored       bool // the bundle is stored, not computed
	}{
		{"sealed bundle", string(base), true},
		{"sealed bundle, padded lines", string(src["sealed bundle, padded lines"]), true},
		{"another sealed bundle", string(src["another sealed bundle"]), true},
		{"lines out of order", lines[0] + lines[2] + lines[1], false},
		{"last line missing (truncated)", lines[0] + lines[1], false},
		{"a line after the last", lines[0] + lines[1] + lines[2] + lines[2], false},
		{"a line of another bundle", lines[0] + lines[1] + otherLines[2], false},
		{"pl.line wrong", lines[0] + lines[1] + line(pl(2, true), entry), false},
		{"pl.bundle another id", lines[0] + lines[1] + line(pl(1, true, "bundle", "AAAAAAAAAAAAAAAAAAAAAA"), entry), false},
		{"no line says last", lines[0] + lines[1] + line(pl(1, false), entry), false},
		{"plaintext line not canonical", lines[0] + lines[1] + line(pl(1, true), strings.Replace(entry, `"views":0`, `"views":0.0`, 1)), false},
		{"plaintext line blank", lines[0] + lines[1] + line(pl(1, false), "") + line(pl(2, true), entry), false},
		{"last beside pl (before v0.73)", lines[0] + line(pl(0, false), header) + line(pl(1, false, "top-last", ""), entry), false},
		{"a blank line between sealed lines", lines[0] + lines[1] + "\n" + lines[2], false},
		{"envelope not canonical", strings.Replace(lines[0], `{"id":`, `{ "id":`, 1) + lines[1] + lines[2], false},
	} {
		v := obj{{Key: "name", Value: c.name}}
		if c.stored {
			v = append(v, golden.Member{Key: "fn", Value: "seal.NewBundleWriter (opened by seal.OpenBundle, read by bundle.NewReader)"})
		} else {
			v = append(v, golden.Member{Key: "fn", Value: "built from the sealed bundle's lines (opened by seal.OpenBundle, read by bundle.NewReader)"})
		}
		v = append(v, golden.Member{Key: "sealed", Value: c.sealed})
		plain, digest, err := openSealed([]byte(c.sealed), recipient)
		if err != nil {
			v = append(v, golden.Member{Key: "verdict", Value: "reject"}, golden.Member{Key: "because", Value: err.Error()})
		} else {
			v = append(v, golden.Member{Key: "verdict", Value: "accept"}, golden.Member{Key: "plain", Value: plain}, golden.Member{Key: "digest", Value: digest})
		}
		vs = append(vs, v)
	}
	// What §G.5.1.1 requires of these, whatever the stored file says.
	for _, v := range vs {
		o := v.(obj)
		name, verdict := o[0].Value.(string), ""
		for _, m := range o {
			if m.Key == "verdict" {
				verdict = m.Value.(string)
			}
		}
		accept := slices.Contains(storedBundles, name) || name == "last beside pl (before v0.73)" ||
			name == "a blank line between sealed lines" || name == "envelope not canonical"
		if (verdict == "accept") != accept {
			t.Errorf("%s: %s", name, verdict)
		}
	}
	if d := ids.Of([]byte(plainBundle)).String(); !strings.Contains(string(golden.Encode(t, vs[0])), d) {
		t.Errorf("the sealed bundle's digest isn't the plain bundle's, %s", d)
	}
	golden.Check(t, "sealedbundle", obj{
		{Key: "section", Value: "§G.5.1.1"},
		{Key: "about", Value: "sealed bundles to the recipient seq(0x20) (keywrap.json): the envelope line, then each bundle line as a JWE under K_b with pl {bundle, line, last?}; the digest is the plain bundle's (§G.4.1). The stored bundles were drawn under a fixed seed and are decrypt vectors; the rejection cases reuse their envelope and lines, or seal a line under the same K_b with the IV seq(0xc0)[:12]"},
		{Key: "recipient_private", Value: golden.Hex(recipient.Bytes())},
		{Key: "K_b", Value: golden.Hex(kb)},
		{Key: "vectors", Value: vs},
	})
}

// openSealed opens a sealed bundle as an importer does: seal.OpenBundle,
// then the bundle Reader over the plain bundle (§G.5.1.1, §G.4.1). It
// returns the plain bundle and its digest.
func openSealed(sealed []byte, identity *ecdh.PrivateKey) (string, string, error) {
	r, err := seal.OpenBundle(bytes.NewReader(sealed), identity)
	if err != nil {
		return "", "", err
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return "", "", err
	}
	d, err := readBundle(string(plain))
	if err != nil {
		return "", "", err
	}
	return string(plain), d, nil
}

// contentKey unwraps a sealed bundle's content key K_b for identity, as
// §G.5.1.1 defines its wrap: HPKE base mode, info "patchlog-bundle-v1" LF
// id. The reference keeps K_b inside seal; the test needs it to seal the
// lines of the rejection cases.
func contentKey(t *testing.T, identity *ecdh.PrivateKey, env *seal.BundleEnvelope) []byte {
	t.Helper()
	sk, err := hpke.NewDHKEMPrivateKey(identity)
	if err != nil {
		t.Fatal(err)
	}
	k, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-bundle-v1\n"+env.ID), env.Recipients[seal.Thumbprint(identity.PublicKey())])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sealLine seals pt as one line of a sealed bundle: a JWE compact under
// K_b with the canonical protected header hdr and the fixed IV.
func sealLine(t *testing.T, kb []byte, hdr map[string]any, pt []byte) string {
	t.Helper()
	block, err := aes.NewCipher(kb)
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := cipher.NewGCM(block)
	protected := b64u.EncodeToString(jsonv.Canonical(hdr))
	ct := gcm.Seal(nil, fixedIV, pt, []byte(protected))
	n := len(ct) - gcm.Overhead()
	return protected + ".." + b64u.EncodeToString(fixedIV) + "." + b64u.EncodeToString(ct[:n]) + "." + b64u.EncodeToString(ct[n:])
}

// ---- Carry-over: a history line with via (§G.4.1, §7.1; MF-44) ----

// TestVectorBundleVia: a history line with via, which a bundle carries
// only with "authors": true, like the other attribution members; a bundle
// without authors that carries it is rejected.
func TestVectorBundleVia(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w, err := bundle.NewWriter(&buf, bundle.Header{Origin: "https://staging.example", Created: "2026-10-04T12:00:00Z", Authors: true,
		At: map[string]string{"matches": nsID2}, Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: idG}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Line(bundle.Line{NS: "matches", Resource: "derby", ID: idG, Kind: "rev", Patches: jsonv.MustParse([]byte(patches1)),
		Author: "user:anna", Created: "2026-10-04T12:00:00Z", Via: []string{"svc:merge", "svc:import"}}); err != nil {
		t.Fatal(err)
	}
	d, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := bundle.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	l, err := r.Next()
	if err != nil || strings.Join(l.Via, ",") != "svc:merge,svc:import" {
		t.Fatalf("read back: %+v, %v", l, err)
	}
	withVia := buf.String()
	noAuthors := strings.Replace(withVia, `"authors":true`, `"authors":false`, 1)
	var vs []any
	for _, c := range []struct{ name, b string }{
		{"history line with via, authors true", withVia},
		{"the same line in a bundle without authors", noAuthors},
		{"via empty", strings.Replace(withVia, `"via":["svc:merge","svc:import"]`, `"via":[]`, 1)},
		{"via with an empty delegatee", strings.Replace(withVia, `"via":["svc:merge","svc:import"]`, `"via":["svc:merge",""]`, 1)},
	} {
		v := obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "bundle.Writer (read by bundle.NewReader)"}, {Key: "bundle", Value: c.b}}
		if got, err := readBundle(c.b); err != nil {
			v = append(v, golden.Member{Key: "verdict", Value: "reject"})
		} else {
			v = append(v, golden.Member{Key: "verdict", Value: "accept"}, golden.Member{Key: "digest", Value: got})
			if got != d && c.b == withVia {
				t.Errorf("digest %s, the Writer's %s", got, d)
			}
		}
		vs = append(vs, v)
	}
	golden.Check(t, "bundlevia", obj{
		{Key: "section", Value: "§G.4.1, §7.1"},
		{Key: "about", Value: "history lines carry via, the delegatees of the grant a revision was written under, only with \"authors\": true; it isn't hashed into the id"},
		{Key: "vectors", Value: vs},
	})
}
