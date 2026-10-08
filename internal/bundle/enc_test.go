package bundle_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/server"
	"github.com/middle-management/patchlog/internal/testenv"
)

// §G.5: sealed bundles, access levels, and bundles of sealed (E2) and e2e
// (E3) namespaces.

const marker = "zqx-bundle-secret"

// newEncDeployment is a deployment with a key store (sealed and e2e
// namespaces need one), whose client decrypts sealed namespaces with keys
// fetched from the server (development mode: raw keys).
func newEncDeployment(t *testing.T, origin string) *deployment {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	o := core.Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), Origin: origin, AuthDisabled: true, Purger: nopPurger{}, KeyStore: ks}
	testenv.Apply(&o)
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(clienttest.CountPages(server.New(e)))
	t.Cleanup(func() {
		hs.CloseClientConnections()
		hs.Close()
		e.Close()
	})
	c, err := client.New(hs.URL, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &deployment{t: t, origin: origin, url: hs.URL, c: c}
}

func identity(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func nonce(ps ...map[string]any) []any {
	return append(ops(ps...), op("add", "/$nonce", seal.NewNonce()))
}

func exportErr(t *testing.T, c *client.Client, opt bundle.ExportOptions, want string) {
	t.Helper()
	_, _, err := bundle.Export(ctx, c, io.Discard, opt)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("export: %v, want an error containing %q", err, want)
	}
}

func importErr(t *testing.T, d *deployment, b []byte, opt bundle.ImportOptions, want string) {
	t.Helper()
	opt.Mode, opt.CreateNamespaces = bundle.Atomic, true
	_, err := bundle.Import(ctx, d.c, bundle.BytesOpener(b), opt)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("import: %v, want an error containing %q", err, want)
	}
}

func fixedNow() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }

// A sealed bundle round-trips for each recipient, keeps the plain bundle's
// digest, and opens for nobody else.
func TestSealedBundleRoundTrip(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	plain, _, psum := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Now: fixedNow})
	alice, bob, eve := identity(t), identity(t), identity(t)
	b, _, sum := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Now: fixedNow,
		Recipients: []*ecdh.PublicKey{alice.PublicKey(), bob.PublicKey()}})
	if bytes.Contains(b, []byte("Derby")) {
		t.Fatal("plaintext in the sealed bundle")
	}
	if sum.Digest != psum.Digest {
		t.Fatalf("digest %s, plain %s", sum.Digest, psum.Digest)
	}
	env := jsonv.MustParse(lines(b)[0]).(map[string]any)
	rs := env["recipients"].([]any)
	if env["sealedBundle"] != 1.0 || len(rs) != 2 || rs[0].(map[string]any)["kid"] != bundle.Thumbprint(alice.PublicKey()) && rs[1].(map[string]any)["kid"] != bundle.Thumbprint(alice.PublicKey()) {
		t.Fatalf("envelope %s", lines(b)[0])
	}
	if len(lines(b)) != len(lines(plain))+1 {
		t.Fatalf("%d sealed lines for %d plain", len(lines(b)), len(lines(plain)))
	}
	for _, id := range []*ecdh.PrivateKey{alice, bob} {
		r, sealed, err := bundle.Unseal(bytes.NewReader(b), id)
		noErr(t, err)
		got, err := io.ReadAll(r)
		noErr(t, err)
		if !sealed || !bytes.Equal(got, plain) {
			t.Fatal("the unsealed bundle differs from the plain one")
		}
	}
	for _, id := range []*ecdh.PrivateKey{eve, nil} {
		if _, _, err := bundle.Unseal(bytes.NewReader(b), id); !errors.Is(err, bundle.ErrNotRecipient) {
			t.Fatalf("unseal by a non-recipient: %v", err)
		}
	}
	// A plain bundle passes through Unseal.
	r, sealed, err := bundle.Unseal(bytes.NewReader(plain), nil)
	noErr(t, err)
	if got, _ := io.ReadAll(r); sealed || !bytes.Equal(got, plain) {
		t.Fatal("plain bundle through Unseal")
	}
	// Import takes it with the identity; source.bundle is the plain digest.
	dst := newDeployment(t, cmsOrigin)
	rep, err := bundle.Import(ctx, dst.c, bundle.UnsealOpener(bundle.BytesOpener(b), bob), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	noErr(t, err)
	if rep.Digest != psum.Digest || rep.Batches[0].Source["bundle"] != psum.Digest {
		t.Fatalf("import digest %s", rep.Digest)
	}
	if dst.head("matches", "derby").ID != f.derby {
		t.Fatal("imported head")
	}
}

// sealedParts opens a sealed bundle's content key with id, for crafting
// lines in the rejection tests.
func sealedParts(t *testing.T, b []byte, id *ecdh.PrivateKey) (env map[string]any, key []byte) {
	t.Helper()
	env = jsonv.MustParse(lines(b)[0]).(map[string]any)
	sk, err := hpke.NewDHKEMPrivateKey(id)
	noErr(t, err)
	for _, x := range env["recipients"].([]any) {
		r := x.(map[string]any)
		if r["kid"] != bundle.Thumbprint(id.PublicKey()) {
			continue
		}
		w, _ := base64.RawURLEncoding.DecodeString(r["wrapped"].(string))
		key, err = hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("patchlog-bundle-v1\n"+env["id"].(string)), w)
		noErr(t, err)
		return env, key
	}
	t.Fatal("not a recipient")
	return nil, nil
}

// sealLine seals pt under key with the protected header hdr.
func sealLine(t *testing.T, key []byte, hdr map[string]any, pt []byte) []byte {
	t.Helper()
	protected := base64.RawURLEncoding.EncodeToString(jsonv.Canonical(jsonv.FromGo(hdr)))
	iv := make([]byte, 12)
	rand.Read(iv)
	block, err := aes.NewCipher(key)
	noErr(t, err)
	aead, err := cipher.NewGCM(block)
	noErr(t, err)
	ct := aead.Seal(nil, iv, pt, []byte(protected))
	n := len(ct) - aead.Overhead()
	enc := base64.RawURLEncoding.EncodeToString
	return []byte(protected + ".." + enc(iv) + "." + enc(ct[:n]) + "." + enc(ct[n:]))
}

// Every check of §G.5.1.1 rejects the whole sealed bundle.
func TestSealedBundleRejects(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := identity(t)
	b, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"media/photo"}, Recipients: []*ecdh.PublicKey{id.PublicKey()}})
	other, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"media/photo"}, Recipients: []*ecdh.PublicKey{id.PublicKey()}})
	ls := lines(b)
	if len(ls) < 4 {
		t.Fatalf("want at least 3 bundle lines, got %d", len(ls)-1)
	}
	env, key := sealedParts(t, b, id)
	bid := env["id"].(string)
	plainLine := func(i int) []byte { // bundle line i, decrypted
		r, _, err := bundle.Unseal(bytes.NewReader(b), id)
		noErr(t, err)
		all, _ := io.ReadAll(r)
		return lines(all)[i]
	}
	hdr := func(n int, extra map[string]any) map[string]any {
		h := map[string]any{"alg": "dir", "enc": "A256GCM", "pl": map[string]any{"bundle": bid, "line": n}}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	with := func(i int, line []byte) [][]byte {
		out := append([][]byte{}, ls...)
		out[i] = line
		return out
	}
	// One ciphertext character changed (the tag is the last 22).
	flip := append([]byte{}, ls[2]...)
	if i := len(flip) - 30; flip[i] == 'A' {
		flip[i] = 'B'
	} else {
		flip[i] = 'A'
	}
	last := len(ls) - 1
	cases := map[string]struct {
		lines [][]byte
		want  string
	}{
		"tampered ciphertext": {with(2, flip), "fails to decrypt"},
		"swapped lines":       {with(2, ls[3]), "out of order"},
		"replayed line":       {append(append([][]byte{}, ls[:3]...), ls[2:]...), "out of order"},
		"truncated":           {ls[:last], "no line says last"},
		"after last":          {append(append([][]byte{}, ls...), ls[2]), "follows the last"},
		"spliced":             {with(2, lines(other)[2]), "fails to decrypt"},
		"other bundle id":     {with(2, sealLine(t, key, map[string]any{"alg": "dir", "enc": "A256GCM", "pl": map[string]any{"bundle": "AAAAAAAAAAAAAAAAAAAAAA", "line": 1}}, plainLine(1))), "isn't this bundle's id"},
		"skipped number":      {with(2, sealLine(t, key, hdr(2, nil), plainLine(1))), "out of order"},
		"last too early":      {with(2, sealLine(t, key, hdr(1, map[string]any{"last": true}), plainLine(1))), "follows the last"},
		"last false":          {with(2, sealLine(t, key, hdr(1, map[string]any{"last": false}), plainLine(1))), "last must be true"},
		"extra header member": {with(2, sealLine(t, key, hdr(1, map[string]any{"zip": "DEF"}), plainLine(1))), "unsupported header member"},
		"extra pl member":     {with(2, sealLine(t, key, map[string]any{"alg": "dir", "enc": "A256GCM", "pl": map[string]any{"bundle": bid, "line": 1, "x": 1}}, plainLine(1))), "pl must be"},
		"not a JWE":           {with(2, []byte("nope")), "not a JWE"},
		"envelope member":     {with(0, jsonv.Canonical(jsonv.FromGo(map[string]any{"sealedBundle": 1, "id": bid, "recipients": env["recipients"], "x": 1}))), "unknown member"},
		"envelope version":    {with(0, jsonv.Canonical(jsonv.FromGo(map[string]any{"sealedBundle": 2, "id": bid, "recipients": env["recipients"]}))), "unsupported version"},
		"envelope id":         {with(0, jsonv.Canonical(jsonv.FromGo(map[string]any{"sealedBundle": 1, "id": "AAAAAAAAAAAAAAAAAAAAAA", "recipients": env["recipients"]}))), "fails to unwrap"},
		"no recipients":       {with(0, jsonv.Canonical(jsonv.FromGo(map[string]any{"sealedBundle": 1, "id": bid, "recipients": []any{}}))), "no recipients"},
	}
	// The crafted lines themselves are well-formed: a correct one passes.
	good := with(2, sealLine(t, key, hdr(1, nil), plainLine(1)))
	if r, _, err := bundle.Unseal(bytes.NewReader(join(good)), id); err != nil {
		t.Fatal(err)
	} else if _, err := bundle.Verify(r); err != nil {
		t.Fatalf("a correctly crafted line: %v", err)
	}
	for name, c := range cases {
		r, _, err := bundle.Unseal(bytes.NewReader(join(c.lines)), id)
		if err == nil {
			_, err = bundle.Verify(r)
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}
}

// The header records each namespace's access level; private content isn't
// written unsealed unless asked; the importer refuses less protected
// targets unless overridden, and creates missing ones as protected.
func TestBundleAccess(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("pub", nil)
	src.ns("priv", map[string]any{"read": "grant"})
	src.create("pub", "a", map[string]any{"v": 1.0})
	src.create("priv", "a", map[string]any{"v": marker})
	exportErr(t, src.c, bundle.ExportOptions{Select: []string{"priv", "pub"}}, "private or sealed content")
	var buf bytes.Buffer
	_, sum, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"priv", "pub"}, Plaintext: true})
	noErr(t, err)
	if a := sum.Header.Access; a["pub"] != bundle.AccessPublic || a["priv"] != bundle.AccessPrivate {
		t.Fatalf("access %v", a)
	}
	b := buf.Bytes()
	_, psum, _ := bundle.Export(ctx, src.c, io.Discard, bundle.ExportOptions{Select: []string{"pub"}})
	if psum.Header.Access["pub"] != bundle.AccessPublic {
		t.Fatal("public access")
	}

	// A public target for a private source: refused, unless overridden.
	dst := newDeployment(t, cmsOrigin)
	dst.ns("priv", nil)
	importErr(t, dst, b, bundle.ImportOptions{}, "less protected")
	rep := importB(t, dst, b, bundle.ImportOptions{AllowLessProtected: true})
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, " "), "overrode") {
		t.Fatalf("notes %v", rep.Notes)
	}
	// A missing target is created private; the public source's as usual.
	dst2 := newDeployment(t, cmsOrigin)
	importB(t, dst2, b, bundle.ImportOptions{})
	h := must(dst2.c.NSHead(ctx, "priv"))
	if d := must(dst2.c.NSDoc(ctx, "priv", h.ID)); d.Value["read"] != "grant" {
		t.Fatalf("created %v", d.Value)
	}
	// Mapped onto a public namespace: refused.
	dst2.ns("open", nil)
	importErr(t, dst2, b, bundle.ImportOptions{NSMap: map[string]string{"priv": "open"}}, "less protected")
	// A bundle whose header doesn't give access is private (§G.5.1).
	legacy := editHeader(t, b, func(h map[string]any) { delete(h, "access") })
	dst3 := newDeployment(t, cmsOrigin)
	dst3.ns("pub", nil)
	importErr(t, dst3, legacy, bundle.ImportOptions{}, "pub is public, less protected than its source pub (private)")
	// access must name namespaces of at, with known levels.
	verifyErr(t, editHeader(t, b, func(h map[string]any) { h["access"].(map[string]any)["x"] = "public" }), "has no at")
	verifyErr(t, editHeader(t, b, func(h map[string]any) { h["access"].(map[string]any)["pub"] = "secret" }), "access: pub")
}

// E2: the exporter decrypts with keys, seals the bundle to its recipient,
// and the import lands in a sealed target, ids unchanged; snapshots too,
// with a fresh $nonce in the patch sets the importer makes.
func TestBundleSealedNamespace(t *testing.T) {
	t.Parallel()
	src := newEncDeployment(t, stagingOrigin)
	src.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	a1 := must(src.c.Create(ctx, "s", "a", append(client.GenesisPatches(map[string]any{"v": marker}), op("add", "/$nonce", seal.NewNonce())))).ID
	a2 := must(src.c.Append(ctx, "s", "a", a1, nonce(op("add", "/w", 2.0)))).ID
	// Without keys the export can't read it.
	noKeys := must(client.New(src.url))
	exportErr(t, noKeys, bundle.ExportOptions{Select: []string{"s"}}, "no keys")
	exportErr(t, src.c, bundle.ExportOptions{Select: []string{"s"}}, "private or sealed content")
	id := identity(t)
	var buf bytes.Buffer
	_, sum, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"s"}, Recipients: []*ecdh.PublicKey{id.PublicKey()}})
	noErr(t, err)
	if sum.Header.Access["s"] != bundle.AccessSealed || bytes.Contains(buf.Bytes(), []byte(marker)) {
		t.Fatalf("access %v", sum.Header.Access)
	}
	dst := newEncDeployment(t, cmsOrigin)
	rep, err := bundle.Import(ctx, dst.c, bundle.UnsealOpener(bundle.BytesOpener(buf.Bytes()), id), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	noErr(t, err)
	if rep.Doc("s/a").Class != "create" || dst.head("s", "a").ID != a2 {
		t.Fatalf("import %+v", rep.Doc("s/a"))
	}
	if lv := must(dst.c.EncryptionLevel(ctx, "s")); lv != "sealed" {
		t.Fatalf("target level %q", lv)
	}
	if d := dst.doc("s", "a"); d["v"] != marker || d["w"] != 2.0 {
		t.Fatalf("target doc %v", d)
	}

	// Snapshots into a sealed target: the upstream and the target get a
	// fresh $nonce; importing the same snapshot again changes nothing.
	var snap bytes.Buffer
	_, _, err = bundle.Export(ctx, src.c, &snap, bundle.ExportOptions{Select: []string{"s"}, Mode: bundle.Snapshot, Plaintext: true})
	noErr(t, err)
	dst2 := newEncDeployment(t, cmsOrigin)
	importB(t, dst2, snap.Bytes(), bundle.ImportOptions{})
	for _, ns := range []string{"s", "s-upstream"} {
		if lv := must(dst2.c.EncryptionLevel(ctx, ns)); lv != "sealed" {
			t.Fatalf("%s level %q", ns, lv)
		}
	}
	if d := dst2.doc("s", "a"); d["v"] != marker || d["$nonce"] == nil {
		t.Fatalf("snapshot target doc %v", d)
	}
	rep = importB(t, dst2, snap.Bytes(), bundle.ImportOptions{})
	if u := rep.Doc("s/a").Upstream; u.Class != "unchanged" {
		t.Fatalf("second snapshot import: upstream %s", u.Class)
	}
	// A sealed source never goes into a public target without override.
	dst3 := newEncDeployment(t, cmsOrigin)
	dst3.ns("s", nil)
	importErr(t, dst3, snap.Bytes(), bundle.ImportOptions{}, "less protected")
}

// e2eWrite writes a sealed patch set (§E.3.1).
func e2eWrite(t *testing.T, d *deployment, key []byte, kid, ns, name, parent string, patches []any) string {
	t.Helper()
	ps, err := seal.SealPatchSet(key, kid, ns, name, parent, jsonv.FromGo(patches))
	noErr(t, err)
	if parent == "" {
		return must(d.c.Create(ctx, ns, name, jsonv.MustParse(ps))).ID
	}
	return must(d.c.Append(ctx, ns, name, parent, jsonv.MustParse(ps))).ID
}

// E3: full history carries the ciphertext and the keyring verbatim, ids
// verify over it, and it imports only into an e2e namespace of the same
// name, created with the bundle's epochs.
func TestBundleE2E(t *testing.T) { t.Parallel(); testBundleE2E(t) }

func testBundleE2E(t *testing.T) {
	src := newEncDeployment(t, stagingOrigin)
	src.ns("e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
	reader := identity(t)
	k1, k2 := seal.NewKey(), seal.NewKey()
	kr, err := seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()})
	noErr(t, err)
	krHead := src.create("e", "keyring", kr.Value())
	d0 := e2eWrite(t, src, k1, "e#1", "e", "d", "", client.GenesisPatches(map[string]any{"v": marker}))
	_, err = kr.Rotate(k2, []*ecdh.PublicKey{reader.PublicKey()})
	noErr(t, err)
	h := must(src.c.NSHead(ctx, "e"))
	_, err = src.c.Batch(ctx, "e", client.BatchRequest{Config: &client.BatchConfig{IfMatch: h.Config, Patches: ops(op("add", "/encryption/epoch", 2.0))},
		Items: []client.BatchItem{{Resource: "keyring", IfMatch: krHead, Steps: []client.Step{client.PatchStep(ops(op("replace", "", kr.Value())))}}}}, false)
	noErr(t, err)
	d1 := e2eWrite(t, src, k2, "e#2", "e", "d", d0, ops(op("add", "/w", 1.0)))

	exportErr(t, src.c, bundle.ExportOptions{Select: []string{"e/d"}, Mode: bundle.Snapshot}, "snapshot needs a client holding its keys")
	var buf bytes.Buffer
	p, sum, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"e/d"}})
	noErr(t, err)
	b := buf.Bytes()
	if sum.Header.Access["e"] != bundle.AccessE2E || p.Docs["e/keyring"] == nil || bytes.Contains(b, []byte(marker)) {
		t.Fatalf("e2e export: access %v, docs %v", sum.Header.Access, sum.Header.Docs)
	}
	// Ciphertext needs no sealing, and verifies as any bundle.
	if _, err := bundle.Verify(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"op":"sealed"`)) {
		t.Fatal("no sealed patch sets")
	}

	// Under another name: refused (pl.ns is bound).
	dst := newEncDeployment(t, cmsOrigin)
	importErr(t, dst, b, bundle.ImportOptions{NSMap: map[string]string{"e": "f"}}, "only be imported under its own name")
	// Into a namespace that isn't e2e: refused.
	dst.ns("e", map[string]any{"read": "grant"})
	importErr(t, dst, b, bundle.ImportOptions{AllowLessProtected: true}, "only go into an e2e target")
	// A missing target is created e2e and moved to the bundle's epoch.
	dst2 := newEncDeployment(t, cmsOrigin)
	rep := importB(t, dst2, b, bundle.ImportOptions{})
	if rep.Doc("e/d").Class != "create" || dst2.head("e", "d").ID != d1 || dst2.head("e", "keyring").ID != src.head("e", "keyring").ID {
		t.Fatalf("e2e import %+v", rep.Docs)
	}
	nh := must(dst2.c.NSHead(ctx, "e"))
	enc := must(dst2.c.NSDoc(ctx, "e", nh.ID)).Value["encryption"].(map[string]any)
	if enc["level"] != "e2e" || enc["epoch"] != 2.0 {
		t.Fatalf("target encryption %v", enc)
	}
	la, lb := must(src.c.Log(ctx, "e", "d", d1, "")), must(dst2.c.Log(ctx, "e", "d", d1, ""))
	for i := range la {
		if la[i].ID != lb[i].ID || string(jsonv.Canonical(la[i].Patches)) != string(jsonv.Canonical(lb[i].Patches)) {
			t.Fatalf("entry %d differs", i)
		}
	}
	// The readers decrypt the target's copy with the source's keys.
	x := dst2.c.E2EKeys(map[string][]byte{"e#1": k1, "e#2": k2}).WithoutValidation()
	doc, err := x.DocE2E(ctx, "e", "d", d1)
	noErr(t, err)
	if m := doc.Value.(map[string]any); m["v"] != marker || m["w"] != 1.0 {
		t.Fatalf("decrypted %v", doc.Value)
	}
	// Again: present. A diverged e2e document is a conflict only skip resolves.
	rep = importB(t, dst2, b, bundle.ImportOptions{})
	if rep.Doc("e/d").Class != "present" {
		t.Fatalf("second import %s", rep.Doc("e/d").Class)
	}
	e2eWrite(t, dst2, k2, "e#2", "e", "d", d1, ops(op("add", "/x", 1.0)))
	e2eWrite(t, src, k2, "e#2", "e", "d", d1, ops(op("add", "/y", 1.0)))
	var b2 bytes.Buffer
	_, _, err = bundle.Export(ctx, src.c, &b2, bundle.ExportOptions{Select: []string{"e/d"}})
	noErr(t, err)
	importErr(t, dst2, b2.Bytes(), bundle.ImportOptions{Resolutions: map[string]bundle.Resolution{"e/d": bundle.ResolveTake}}, "can't resolve e2e content")
	rep, err = bundle.Import(ctx, dst2.c, bundle.BytesOpener(b2.Bytes()), bundle.ImportOptions{Mode: bundle.Atomic})
	if !errors.Is(err, bundle.ErrConflicts) || rep.Doc("e/d").Class != "conflict" {
		t.Fatalf("diverged e2e: %v", err)
	}
	importB(t, dst2, b2.Bytes(), bundle.ImportOptions{Resolutions: map[string]bundle.Resolution{"e/d": bundle.ResolveSkip}})
}

// Key files: a private JWK round-trips and stands for its public key.
func TestIdentityFiles(t *testing.T) {
	t.Parallel()
	id := identity(t)
	b := jsonv.Canonical(bundle.IdentityJWK(id))
	got, err := bundle.ParseIdentity(b)
	noErr(t, err)
	if !got.Equal(id) {
		t.Fatal("identity round trip")
	}
	pub, err := bundle.ParseRecipient(b)
	noErr(t, err)
	if !pub.Equal(id.PublicKey()) {
		t.Fatal("recipient from a private JWK")
	}
	pub, err = bundle.LoadRecipient(string(jsonv.Canonical(seal.RecipientJWK(id.PublicKey()))))
	noErr(t, err)
	if !pub.Equal(id.PublicKey()) {
		t.Fatal("inline recipient")
	}
	bad := bundle.IdentityJWK(id)
	bad["x"] = seal.RecipientJWK(identity(t).PublicKey())["x"]
	if _, err := bundle.ParseIdentity(jsonv.Canonical(bad)); err == nil {
		t.Fatal("mismatched x accepted")
	}
}

// The CLI: keygen, export to a recipient, verify and import with the
// identity; plaintext of private content only with -plaintext.
func TestSealedBundleCLI(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("priv", map[string]any{"read": "grant"})
	src.create("priv", "a", map[string]any{"v": marker})
	dir := t.TempDir()
	idPath, out := dir+"/id.jwk", dir+"/b.plb"
	var so, se bytes.Buffer
	run := func(cmd string, args ...string) int {
		so.Reset()
		se.Reset()
		return bundle.CLI(ctx, cmd, args, &so, &se)
	}
	if code := run("bundle", "keygen", "-o", idPath); code != 0 {
		t.Fatalf("keygen: %s", se.String())
	}
	pub := strings.TrimSpace(so.String())
	if code := run("bundle", "keygen", "-o", idPath); code == 0 {
		t.Fatal("keygen overwrote a key file")
	}
	if code := run("export", "-api", src.url, "-ns", "priv", "-o", out); code != 1 || !strings.Contains(se.String(), "private or sealed content") {
		t.Fatalf("unsealed private export: %d %s", code, se.String())
	}
	if code := run("export", "-api", src.url, "-ns", "priv", "-o", out, "-recipient", pub); code != 0 {
		t.Fatalf("export: %s", se.String())
	}
	if code := run("bundle", "verify", "-i", out); code != 1 || !strings.Contains(se.String(), "not addressed") {
		t.Fatalf("verify without identity: %d %s", code, se.String())
	}
	if code := run("bundle", "verify", "-i", out, "-identity", idPath); code != 0 || !strings.Contains(so.String(), "sealed bundle") || !strings.Contains(so.String(), "priv: private") {
		t.Fatalf("verify: %s %s", so.String(), se.String())
	}
	dst := newDeployment(t, cmsOrigin)
	dst.ns("priv", nil)
	if code := run("import", "-api", dst.url, "-ns", "priv", "-i", out, "-identity", idPath, "-atomic"); code != 1 || !strings.Contains(se.String(), "less protected") {
		t.Fatalf("import into a public target: %d %s", code, se.String())
	}
	if code := run("import", "-api", dst.url, "-ns", "priv", "-i", out, "-identity", idPath, "-atomic", "-allow-less-protected"); code != 0 {
		t.Fatalf("import: %s", se.String())
	}
	if d := dst.doc("priv", "a"); d["v"] != marker {
		t.Fatalf("imported %v", d)
	}
	if code := run("export", "-api", src.url, "-ns", "priv", "-o", out, "-plaintext"); code != 0 {
		t.Fatalf("plaintext export: %s", se.String())
	}
}
