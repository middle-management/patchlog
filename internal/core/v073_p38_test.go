package core

// Spec v0.73, package P38 (CIS-38, carry-over from wave 3): vectors for
// Addendum I that only the core's unexported code computes: a resource's
// archive key (§8.6, §G.5.1.1; archiveIdentity), and a resource stream's
// purge and prune events (§7.3, §E.2.2; resourceEvents), sealed under
// K_r of the current epoch with pl { ns, name, kind }. Kept in
// internal/vectors/testdata (internal/vectors/golden).

import (
	"bytes"
	"crypto/ecdh"
	"io"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// p38Seed is the 32 bytes n, n+1, … n+31.
func p38Seed(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n + byte(i)
	}
	return b
}

// TestVectorArchiveKey: an encrypted resource's archives are sealed
// bundles to its archive key, the X25519 key d = HKDF-SHA256(the
// resource's DEK, no salt, info "patchlog-archive-key-v1"), named in the
// envelope by its thumbprint.
func TestVectorArchiveKey(t *testing.T) {
	var vs []any
	for _, n := range []byte{0x00, 0x10} {
		dek := p38Seed(n)
		k := archiveIdentity(dek)
		// The key opens an archive sealed to it, as Engine.ReadArchive
		// does, and no other key does.
		var buf bytes.Buffer
		w, err := seal.NewBundleWriter(&buf, []*ecdh.PublicKey{k.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		const plain = `{"authors":false,"bundle":1,"origin":"https://cms.example"}` + "\n"
		io.WriteString(w, plain)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), `"kid":"`+seal.Thumbprint(k.PublicKey())+`"`) {
			t.Fatalf("the envelope doesn't name the archive key: %s", buf.String())
		}
		r, err := seal.OpenBundle(bytes.NewReader(buf.Bytes()), k)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := io.ReadAll(r); string(got) != plain {
			t.Fatalf("opened %q", got)
		}
		if _, err := seal.OpenBundle(bytes.NewReader(buf.Bytes()), archiveIdentity(p38Seed(n+1))); err == nil {
			t.Fatal("another resource's archive key opened the archive")
		}
		vs = append(vs, golden.Obj{{Key: "name", Value: "DEK seq(0x" + golden.Hex([]byte{n}) + ")"},
			{Key: "fn", Value: "core archiveIdentity"},
			{Key: "dek", Value: golden.Hex(dek)},
			{Key: "info", Value: archiveKeyInfo},
			{Key: "private", Value: golden.Hex(k.Bytes())},
			{Key: "jwk", Value: string(jsonv.Canonical(seal.RecipientJWK(k.PublicKey())))},
			{Key: "kid", Value: seal.Thumbprint(k.PublicKey())}})
	}
	golden.Check(t, "archivekey", golden.Obj{
		{Key: "section", Value: "§8.6, §G.5.1.1, §E.1"},
		{Key: "about", Value: "a resource's archive key in an encrypted namespace: the X25519 private key d = HKDF-SHA256(secret = the resource's data key, salt = none, info = \"patchlog-archive-key-v1\"), 32 bytes; its archives are sealed bundles whose one recipient's kid is its thumbprint. The derivation is the reference's choice (§8.6 leaves the key to the deployment), shown for implementations that read the reference's archives"},
		{Key: "vectors", Value: vs},
	})
}

// TestVectorResourceEvents: a resource stream's purge and prune events
// carry the namespace entry without id and prev, and no SSE id (§7.3); in
// a sealed namespace each is a JWE under the resource's K_r of the current
// epoch with pl { ns, name, kind }, padded as the namespace pads (§E.2.2).
// The vector seals with a fixed IV; the server draws one.
func TestVectorResourceEvents(t *testing.T) {
	page := []map[string]any{
		{"id": "1vmctae4vewju6nvxi374rkrkmyzpdrif", "prev": "", "kind": "head", "resource": "derby", "target": "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll", "created": "2026-10-04T12:00:00Z"},
		{"id": "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm", "prev": "1vmctae4vewju6nvxi374rkrkmyzpdrif", "kind": "prune", "resource": "derby", "target": "1sywh54kpo3c4ezn2znktvl3avge4zl5d", "created": "2026-10-04T12:05:00Z"},
		{"id": "1vwnfnoyshruyx4lul4a25rtctooiph5v", "prev": "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm", "kind": "purge", "resource": "cup", "target": "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll", "created": "2026-10-04T12:06:00Z"},
		{"id": "17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm", "prev": "1vwnfnoyshruyx4lul4a25rtctooiph5v", "kind": "purge", "resource": "derby", "target": "1idx6u2b3z42obqmwsgmlzvrfuutks2bq", "created": "2026-10-04T12:07:00Z"},
	}
	events := resourceEvents(page, "derby")
	if len(events) != 2 {
		t.Fatalf("%d events, want derby's prune and purge", len(events))
	}
	ke := p38Seed(0x00)
	kr, err := seal.ResourceKey(ke, "demo", "derby")
	if err != nil {
		t.Fatal(err)
	}
	kid := seal.Kid("demo", 3)
	iv := p38Seed(0xc0)[:12]
	var vs []any
	for _, d := range events {
		kind := d["kind"].(string)
		data := jsonv.Canonical(d)
		for _, pad := range []bool{false, true} {
			pt := data
			if pad {
				pt = seal.Pad(data)
			}
			pl := seal.ResourceEventPL("demo", "derby", kind)
			jwe, err := seal.SealWithIV(kr, kid, pl, pt, iv)
			if err != nil {
				t.Fatal(err)
			}
			got, err := seal.OpenExpect(jwe, kr, kid, pl)
			if err != nil || !bytes.Equal(bytes.TrimRight(got, " "), data) {
				t.Fatalf("%s: %v", kind, err)
			}
			h, _ := seal.ParseHeader(jwe)
			name := kind + " event"
			if pad {
				name += ", padded"
			}
			vs = append(vs, golden.Obj{{Key: "name", Value: name}, {Key: "fn", Value: "core resourceEvents; seal.ResourceKey, seal.ResourceEventPL, seal.SealWithIV"},
				{Key: "data", Value: string(data)}, {Key: "padded_length", Value: len(pt)},
				{Key: "protected", Value: string(h.Raw)}, {Key: "jwe", Value: jwe}})
		}
	}
	var page0 []any
	for _, e := range page {
		page0 = append(page0, map[string]any(e))
	}
	golden.Check(t, "resourceevents", golden.Obj{
		{Key: "section", Value: "§7.3, §E.2.2"},
		{Key: "about", Value: "a resource stream's purge and prune events for derby from a namespace log page: the entry without id and prev; sealed under K_r of the current epoch (K_e = 00 01 … 1f, ns demo, epoch 3) with pl {ns, name, kind} and the IV seq(0xc0)[:12], and no SSE id"},
		{Key: "namespace page", Value: string(jsonv.Canonical(page0))},
		{Key: "K_r", Value: golden.Hex(kr)},
		{Key: "vectors", Value: vs},
	})
}
