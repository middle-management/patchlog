package bundle_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 bundle format (P11): canonical lines and the digest over the
// bytes as written (§G.4.1, §I.9), sealed bundles' pl.last and padding
// (§G.5.1.1), grant lines' stored authority block (§G.4.1, §C.3.1), and
// limit refusals of either status (§6.6).

// writtenBundle is a small bundle the Writer wrote: a header and two
// snapshot lines.
func writtenBundle(t *testing.T) []byte {
	t.Helper()
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{"n": ids.Hash(nil, []byte("at")).String()}, Docs: map[string]bundle.DocInfo{}}
	docs := map[string]any{"a": map[string]any{"title": "A", "n": 1.5}, "b": map[string]any{"title": "B"}}
	idOf := map[string]string{}
	for name, doc := range docs {
		idOf[name] = must(client.ExpectedRevision("", client.GenesisPatches(doc)))
		h.Docs[bundle.Key("n", name)] = bundle.DocInfo{History: bundle.Snapshot, Head: idOf[name]}
	}
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	for _, name := range []string{"a", "b"} {
		noErr(t, w.SnapshotDoc("n", name, idOf[name], docs[name], false))
	}
	must(w.Close())
	return buf.Bytes()
}

// The digest is over the bytes as written (§I.9), and every line is
// canonical JSON followed by one 0x0A: a blank line, a line that isn't
// byte for byte its canonical form, or a last line without its 0x0A
// rejects the bundle (§G.4.1, CIS-37).
func TestV073BundleLinesCanonical(t *testing.T) {
	t.Parallel()
	b := writtenBundle(t)
	sum := must(bundle.Verify(bytes.NewReader(b)))
	h := sha256.Sum256(b)
	var id ids.ID
	copy(id[:], h[:])
	if sum.Digest != id.String() {
		t.Fatalf("digest %s, want trunc160(sha256(bytes)) %s", sum.Digest, id)
	}
	ls := lines(b)
	reorder := func(l []byte) []byte { // the same members, not in canonical order
		m := jsonv.MustParse(l).(map[string]any)
		var sb strings.Builder
		sb.WriteString(`{"snapshot":` + string(jsonv.Canonical(m["snapshot"])))
		for _, k := range []string{"doc", "ns", "resource"} {
			sb.WriteString(`,"` + k + `":` + string(jsonv.Canonical(m[k])))
		}
		sb.WriteString("}")
		return []byte(sb.String())
	}
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"blank line between":     {join([][]byte{ls[0], {}, ls[1], ls[2]}), "line 2: a blank line"},
		"blank line at the end":  {append(append([]byte{}, b...), '\n'), "line 4: a blank line"},
		"blank line first":       {append([]byte("\n"), b...), "line 1: a blank line"},
		"no final 0x0A":          {b[:len(b)-1], "line 3: the last line doesn't end in 0x0A"},
		"pretty header":          {join([][]byte{bytes.ReplaceAll(ls[0], []byte(`":`), []byte(`": `)), ls[1], ls[2]}), "line 1: not canonical"},
		"member order":           {join([][]byte{ls[0], reorder(ls[1]), ls[2]}), "line 2: not canonical"},
		"number spelling":        {bytes.Replace(b, []byte(`"n":1.5`), []byte(`"n":1.50`), 1), "line 2: not canonical"},
		"escaped character":      {bytes.Replace(b, []byte(`"title":"A"`), []byte(`"title":"\`+`u0041"`), 1), "line 2: not canonical"},
		"CRLF":                   {bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")), "line 1: not canonical"},
		"trailing space":         {join([][]byte{ls[0], append(append([]byte{}, ls[1]...), ' '), ls[2]}), "line 2: not canonical"},
		"byte order mark":        {append([]byte("\xef\xbb\xbf"), b...), "line 1: not"},
		"leading space on entry": {join([][]byte{ls[0], append([]byte(" "), ls[1]...), ls[2]}), "line 2: not canonical"},
	} {
		_, err := bundle.Verify(bytes.NewReader(c.b))
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}
	// The importer reads through the same Reader: nothing is written.
	dst := newDeployment(t, cmsOrigin)
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b[:len(b)-1]), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	if err == nil || !errors.Is(err, bundle.ErrInvalid) {
		t.Fatalf("import of an unterminated bundle: %v", err)
	}
	if _, err := dst.c.NSHead(ctx, "n"); !client.IsNotFound(err) {
		t.Fatalf("the refused import created n: %v", err)
	}
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealedProtected is the protected header of a sealed bundle's JWE line.
func sealedProtected(t *testing.T, line []byte) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(string(line), ".", 2)[0])
	noErr(t, err)
	return jsonv.MustParse(raw).(map[string]any)
}

// A sealed bundle's last line says so in pl, { bundle, line, last: true }
// (§G.5.1.1, MF-60); one with last beside pl, as written before v0.73,
// still reads.
func TestV073SealedBundleLastInPL(t *testing.T) {
	t.Parallel()
	plain := writtenBundle(t)
	id := identity(t)
	var buf bytes.Buffer
	sw := must(bundle.NewSealedWriter(&buf, []*ecdh.PublicKey{id.PublicKey()}))
	must(sw.Write(plain))
	noErr(t, sw.Close())
	b := buf.Bytes()
	ls := lines(b)
	for i, l := range ls[1:] {
		h := sealedProtected(t, l)
		pl := h["pl"].(map[string]any)
		if _, top := h["last"]; top {
			t.Fatalf("line %d: last beside pl: %v", i, h)
		}
		if last := i == len(ls)-2; (pl["last"] == true) != last || (!last && len(pl) != 2) {
			t.Fatalf("line %d: pl %v", i, pl)
		}
	}
	r, sealed, err := bundle.Unseal(bytes.NewReader(b), id)
	noErr(t, err)
	got := must(io.ReadAll(r))
	if !sealed || !bytes.Equal(got, plain) {
		t.Fatal("the unsealed bundle differs from the plain one")
	}

	env, key := sealedParts(t, b, id)
	bid := env["id"].(string)
	last := len(ls) - 1
	pt := lines(plain)[last-1]
	with := func(line []byte) []byte {
		out := append([][]byte{}, ls...)
		out[last] = line
		return join(out)
	}
	hdr := func(pl map[string]any, top map[string]any) map[string]any {
		h := map[string]any{"alg": "dir", "enc": "A256GCM", "pl": pl}
		for k, v := range top {
			h[k] = v
		}
		return h
	}
	// The form written before v0.73.
	legacy := with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1}, map[string]any{"last": true}), pt))
	r, _, err = bundle.Unseal(bytes.NewReader(legacy), id)
	noErr(t, err)
	if s, err := bundle.Verify(r); err != nil || s.Digest != must(bundle.Verify(bytes.NewReader(plain))).Digest {
		t.Fatalf("legacy last: %v", err)
	}
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"pl.last false":   {with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1, "last": false}, nil), pt)), "pl.last must be true"},
		"pl other member": {with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1, "first": true}, nil), pt)), "pl must be {bundle, line, last?}"},
		"no last":         {with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1}, nil), pt)), "no line says last"},
		"pl.last early":   {join(append(append([][]byte{}, ls[:last]...), sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1, "last": true}, nil), pt), ls[last])), "follows the last"},
	} {
		r, _, err := bundle.Unseal(bytes.NewReader(c.b), id)
		if err == nil {
			_, err = bundle.Verify(r)
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}
}

// Padding (§E.2.2) may be applied to each sealed line's plaintext: the
// writer pads to the bucket on request, and readers remove the trailing
// spaces before the checks and the digest (§G.5.1.1, MF-61). What is left
// is checked as strictly as a plain line (CIS-37).
func TestV073SealedBundlePadding(t *testing.T) {
	t.Parallel()
	plain := writtenBundle(t)
	digest := must(bundle.Verify(bytes.NewReader(plain))).Digest
	id := identity(t)
	var buf bytes.Buffer
	sw := must(bundle.NewSealedWriter(&buf, []*ecdh.PublicKey{id.PublicKey()}))
	sw.Pad = true
	must(sw.Write(plain))
	noErr(t, sw.Close())
	b := buf.Bytes()
	env, key := sealedParts(t, b, id)
	block := must(aesGCM(key))
	for i, l := range lines(b)[1:] {
		parts := strings.Split(string(l), ".")
		iv, _ := base64.RawURLEncoding.DecodeString(parts[2])
		ct, _ := base64.RawURLEncoding.DecodeString(parts[3])
		tag, _ := base64.RawURLEncoding.DecodeString(parts[4])
		pt := must(block.Open(nil, iv, append(ct, tag...), []byte(parts[0])))
		if want := lines(plain)[i]; len(pt) != seal.PadLen(len(want)) || !bytes.Equal(bytes.TrimRight(pt, " "), want) {
			t.Fatalf("line %d: %d bytes, want %q padded to %d", i, len(pt), want, seal.PadLen(len(want)))
		}
	}
	r, _, err := bundle.Unseal(bytes.NewReader(b), id)
	noErr(t, err)
	if s, err := bundle.Verify(r); err != nil || s.Digest != digest {
		t.Fatalf("padded: %v, digest %v, want %s", err, s, digest)
	}
	// Padded or not, the import's source.bundle is the plain digest.
	dst := newDeployment(t, cmsOrigin)
	rep, err := bundle.Import(ctx, dst.c, bundle.UnsealOpener(bundle.BytesOpener(b), id), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	noErr(t, err)
	if rep.Digest != digest {
		t.Fatalf("import digest %s, want %s", rep.Digest, digest)
	}

	// Plaintexts that aren't one canonical line, padded or not.
	ls := lines(b)
	bid := env["id"].(string)
	hdr := map[string]any{"alg": "dir", "enc": "A256GCM", "pl": map[string]any{"bundle": bid, "line": 1}}
	with := func(pt []byte) []byte {
		out := append([][]byte{}, ls...)
		out[2] = sealLine(t, key, hdr, pt)
		return join(out)
	}
	line1 := lines(plain)[1]
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"padded with a tab":  {with(append(append([]byte{}, line1...), '\t')), "not canonical"},
		"leading space":      {with(append([]byte(" "), line1...)), "not canonical"},
		"not canonical":      {with(bytes.Replace(line1, []byte(`":`), []byte(`": `), 1)), "not canonical"},
		"empty":              {with([]byte("   ")), "a blank line"},
		"two lines":          {with(append(append(append([]byte{}, line1...), '\n'), line1...)), "holds a 0x0A"},
		"newline at the end": {with(append(append([]byte{}, line1...), '\n')), "holds a 0x0A"},
	} {
		r, _, err := bundle.Unseal(bytes.NewReader(c.b), id)
		if err == nil {
			_, err = bundle.Verify(r)
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}

	// The writer seals only what a Reader would read.
	for name, in := range map[string][]byte{
		"blank line":    append([]byte("\n"), plain...),
		"not canonical": bytes.Replace(plain, []byte(`":`), []byte(`": `), 1),
		"no final 0x0A": plain[:len(plain)-1],
	} {
		sw := must(bundle.NewSealedWriter(io.Discard, []*ecdh.PublicKey{id.PublicKey()}))
		_, err := sw.Write(in)
		if err == nil {
			err = sw.Close()
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) {
			t.Errorf("sealed writer, %s: %v", name, err)
		}
	}
}
