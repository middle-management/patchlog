package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// upload uploads data as a blob of ns/name and returns its reference.
func (d *deployment) upload(ns, name, typ, nonce string, data []byte) map[string]any {
	d.t.Helper()
	bid := must(d.c.UploadBlob(ctx, ns, name, typ, nonce, data))
	return client.BlobRef(bid, typ, len(data), nonce)
}

// blobBytes reads a blob of ns/name, or fails.
func (d *deployment) blobBytes(ns, name string, ref map[string]any) string {
	d.t.Helper()
	nonce, _ := ref["nonce"].(string)
	b, err := d.c.GetBlob(ctx, ns, name, ref["$blob"].(string), nonce)
	if err != nil {
		d.t.Fatalf("blob %s of %s/%s: %v", ref["$blob"], ns, name, err)
	}
	return string(b.Data)
}

// order lists a bundle's entry lines as "blob:<bytes>", "rev:<id>" or
// "snap:<id>".
func order(t *testing.T, b []byte) string {
	t.Helper()
	var out []string
	for _, l := range lines(b)[1:] {
		m := jsonv.MustParse(l).(map[string]any)
		switch {
		case m["blob"] != nil:
			d, err := base64.RawURLEncoding.DecodeString(m["data"].(string))
			noErr(t, err)
			out = append(out, "blob:"+string(d))
		case m["snapshot"] != nil:
			out = append(out, "snap:"+m["snapshot"].(string))
		default:
			out = append(out, "rev:"+m["id"].(string))
		}
	}
	return strings.Join(out, " ")
}

func sentBlobs(rep *bundle.Report) (uploaded, copied int) {
	for _, b := range rep.Batches {
		uploaded += b.Uploaded
		copied += b.Copied
	}
	return
}

// §G.4.1, §G.4.4: an export carries every blob its revisions and snapshots
// reference, once per resource, before the first line that references it;
// an import uploads them before the batches, into a snapshot document's
// upstream resource and its target; an incremental bundle leaves out what
// the history up to requires referenced; within one deployment blobs are
// copied.
func TestBundleBlobs(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("m", nil)
	nonce := seal.NewNonce()
	rx := src.upload("m", "a", "image/png", "", []byte("blob x"))
	ry := src.upload("m", "a", "image/png", nonce, []byte("blob y"))
	r1 := src.create("m", "a", map[string]any{"img": rx, "again": rx})
	r2 := src.append("m", "a", op("replace", "/img", ry), map[string]any{"op": "remove", "path": "/again"})
	r3 := src.append("m", "a", op("add", "/n", 1.0))
	rz := src.upload("m", "s", "text/plain", "", []byte("blob z"))
	s1 := src.create("m", "s", map[string]any{"t": rz})

	var buf bytes.Buffer
	_, sum, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"m/a"}})
	noErr(t, err)
	want := "blob:blob x rev:" + r1 + " blob:blob y rev:" + r2 + " rev:" + r3
	if got := order(t, buf.Bytes()); got != want || sum.Lines != 5 {
		t.Fatalf("lines %s (%d), want %s", got, sum.Lines, want)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"nonce":"`+nonce+`"`)) {
		t.Fatal("the blob line has no nonce")
	}
	full := bytes.Clone(buf.Bytes())
	buf.Reset()
	_, _, err = bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"m/s"}, Mode: bundle.Snapshot})
	noErr(t, err)
	if got := order(t, buf.Bytes()); got != "blob:blob z snap:"+s1 {
		t.Fatalf("snapshot lines %s", got)
	}
	snap := bytes.Clone(buf.Bytes())

	// A dry run uploads nothing, and defers the blob failures.
	dst := newDeployment(t, cmsOrigin)
	dst.ns("m", nil)
	rep := importB(t, dst, full, bundle.ImportOptions{DryRun: true})
	if rep.Batches[0].DryRun != "deferred" {
		t.Fatalf("dry run %+v", rep.Batches[0])
	}
	if u, _ := sentBlobs(rep); u != 0 {
		t.Fatal("a dry run uploaded blobs")
	}
	rep = importB(t, dst, full, bundle.ImportOptions{})
	if u, c := sentBlobs(rep); u != 2 || c != 0 {
		t.Fatalf("uploaded %d, copied %d", u, c)
	}
	if dst.head("m", "a").ID != r3 || dst.blobBytes("m", "a", rx) != "blob x" || dst.blobBytes("m", "a", ry) != "blob y" {
		t.Fatal("full import with blobs")
	}
	rep = importB(t, dst, snap, bundle.ImportOptions{})
	if u, _ := sentBlobs(rep); u != 2 {
		t.Fatalf("snapshot import uploaded %d", u)
	}
	if dst.blobBytes("m", "s", rz) != "blob z" || dst.blobBytes("m-upstream", "s", rz) != "blob z" {
		t.Fatal("snapshot import with blobs")
	}

	// Incremental: only what the history up to requires didn't reference.
	rw := src.upload("m", "a", "image/png", "", []byte("blob w"))
	r4 := src.append("m", "a", op("add", "/w", rw), op("add", "/x", rx))
	buf.Reset()
	_, _, err = bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"m/a"}, Requires: map[string]string{"m/a": r3}})
	noErr(t, err)
	if got := order(t, buf.Bytes()); got != "blob:blob w rev:"+r4 {
		t.Fatalf("incremental lines %s", got)
	}
	rep = importB(t, dst, buf.Bytes(), bundle.ImportOptions{})
	if u, _ := sentBlobs(rep); u != 1 || dst.head("m", "a").ID != r4 || dst.blobBytes("m", "a", rw) != "blob w" {
		t.Fatalf("incremental import %+v", rep.Batches)
	}

	// Within one deployment the blobs are copied, not uploaded.
	rep = importB(t, src, full, bundle.ImportOptions{NSMap: map[string]string{"m": "m2"}})
	if u, c := sentBlobs(rep); u != 0 || c != 2 {
		t.Fatalf("local import uploaded %d, copied %d", u, c)
	}
	if src.head("m2", "a").ID != r3 || src.blobBytes("m2", "a", ry) != "blob y" {
		t.Fatal("local import with blobs")
	}

	// A new target replays the whole upstream chain: the blob of an earlier
	// snapshot, which this bundle doesn't carry, comes from the upstream
	// resource.
	rv := src.upload("m", "s", "text/plain", "", []byte("blob v"))
	src.append("m", "s", op("replace", "/t", rv))
	buf.Reset()
	_, _, err = bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"m/s"}, Mode: bundle.Snapshot})
	noErr(t, err)
	rep = importB(t, dst, buf.Bytes(), bundle.ImportOptions{NSMap: map[string]string{"m": "m3"}})
	if u, c := sentBlobs(rep); u != 2 || c != 1 {
		t.Fatalf("snapshot import into a new target uploaded %d, copied %d", u, c)
	}
	if dst.blobBytes("m3", "s", rv) != "blob v" || dst.blobBytes("m3", "s", rz) != "blob z" {
		t.Fatal("new target of an upstream chain")
	}
}

// A blob line after a line that references it rejects the bundle, and a
// referenced blob the target lacks fails the batch with code "blob".
func TestBundleBlobOrder(t *testing.T) {
	data := []byte("late blob")
	bid := ids.Blob("text/plain", "", data).String()
	patches := client.GenesisPatches(map[string]any{"b": client.BlobRef(bid, "text/plain", len(data), "")})
	pv, err := client.ToValue(patches)
	noErr(t, err)
	r := ids.Revision(nil, jsonv.Canonical(pv)).String()
	write := func(withBlob bool) []byte {
		var buf bytes.Buffer
		w, err := bundle.NewWriter(&buf, bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z",
			At: map[string]string{"m": r}, Docs: map[string]bundle.DocInfo{"m/a": {History: bundle.Full, Head: r}},
			Access: map[string]string{"m": bundle.AccessPublic}})
		noErr(t, err)
		noErr(t, w.Line(bundle.Line{NS: "m", Resource: "a", ID: r, Kind: "rev", Patches: patches}))
		if withBlob {
			noErr(t, w.Line(bundle.Line{NS: "m", Resource: "a", Blob: bid, Type: "text/plain", Data: data}))
		}
		_, err = w.Close()
		noErr(t, err)
		return buf.Bytes()
	}
	dst := newDeployment(t, cmsOrigin)
	importErr(t, dst, write(true), bundle.ImportOptions{}, "comes after a line that references it")
	importErr(t, dst, write(false), bundle.ImportOptions{}, "blob")
}

// §G.5.1.1: in a sealed bundle a blob line is sealed like any other.
func TestSealedBundleBlobs(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("p", map[string]any{"read": "grant"})
	secret := []byte(marker + " in a blob, long enough to look for")
	ref := src.upload("p", "a", "application/octet-stream", seal.NewNonce(), secret)
	src.create("p", "a", map[string]any{"f": ref})
	alice := identity(t)
	var buf bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"p/a"}, Recipients: []*ecdh.PublicKey{alice.PublicKey()}})
	noErr(t, err)
	if bytes.Contains(buf.Bytes(), []byte(base64.RawURLEncoding.EncodeToString(secret)[:24])) {
		t.Fatal("blob bytes in the sealed bundle")
	}
	dst := newDeployment(t, cmsOrigin)
	dst.ns("p", map[string]any{"read": "grant"})
	_, err = bundle.Import(ctx, dst.c, bundle.UnsealOpener(bundle.BytesOpener(buf.Bytes()), alice), bundle.ImportOptions{Mode: bundle.Atomic})
	noErr(t, err)
	if dst.blobBytes("p", "a", ref) != string(secret) {
		t.Fatal("blob of a sealed bundle")
	}
}

// §G.4.1, §E.2.2, §G.5.1: a sealed (E2) source serves its blobs sealed
// under an epoch; the exporter follows the redirect and opens them with
// its keys, so the blob lines carry the plaintext, which a sealed bundle
// seals per line; the import uploads the plaintext to the sealed target.
func TestBundleSealedNamespaceBlobs(t *testing.T) {
	src := newEncDeployment(t, stagingOrigin)
	src.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	secret := []byte(marker + " in a sealed blob")
	ref := src.upload("s", "a", "image/png", seal.NewNonce(), secret)
	a1 := must(src.c.Create(ctx, "s", "a", append(client.GenesisPatches(map[string]any{"img": ref}), op("add", "/$nonce", seal.NewNonce())))).ID
	// The source serves it sealed only: GetBlob refuses the redirect.
	if _, err := src.c.GetBlob(ctx, "s", "a", ref["$blob"].(string), ref["nonce"].(string)); err == nil {
		t.Fatal("a sealed namespace served a blob's plaintext")
	}

	var plain bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &plain, bundle.ExportOptions{Select: []string{"s"}, Plaintext: true})
	noErr(t, err)
	if got := order(t, plain.Bytes()); got != "blob:"+string(secret)+" rev:"+a1 {
		t.Fatalf("lines %s", got)
	}
	id := identity(t)
	var buf bytes.Buffer
	_, _, err = bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"s"}, Recipients: []*ecdh.PublicKey{id.PublicKey()}})
	noErr(t, err)
	if bytes.Contains(buf.Bytes(), []byte(base64.RawURLEncoding.EncodeToString(secret)[:24])) {
		t.Fatal("blob bytes in the sealed bundle")
	}
	dst := newEncDeployment(t, cmsOrigin)
	_, err = bundle.Import(ctx, dst.c, bundle.UnsealOpener(bundle.BytesOpener(buf.Bytes()), id), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	noErr(t, err)
	if lv := must(dst.c.EncryptionLevel(ctx, "s")); lv != "sealed" || dst.head("s", "a").ID != a1 {
		t.Fatalf("target level %q", lv)
	}
	b, err := dst.c.GetBlobRef(ctx, "s", "a", ref)
	noErr(t, err)
	if string(b.Data) != string(secret) || b.Type != "image/png" {
		t.Fatalf("target blob %q %s", b.Data, b.Type)
	}
}

// §G.4.1, §E.3.1: an e2e export carries the blobs the sealed ops declare,
// the writers' ciphertext verbatim (a restore with [] declares nothing
// new); the import uploads them as sealed blobs, so the target serves the
// same bytes, which the references' keys decrypt.
func TestBundleE2EBlobs(t *testing.T) {
	src := newEncDeployment(t, stagingOrigin)
	src.ns("e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
	reader := identity(t)
	k := seal.NewKey()
	kr, err := seal.BuildKeyring("e", 1, k, []*ecdh.PublicKey{reader.PublicKey()})
	noErr(t, err)
	krHead := src.create("e", "keyring", kr.Value())
	upload := func(data string) ([]byte, map[string]any) {
		sealed, ref, err := client.EncryptBlob("image/png", []byte(data), false)
		noErr(t, err)
		must(src.c.UploadBlob(ctx, "e", "d", bundle.SealedBlobType, "", sealed))
		return sealed, ref
	}
	write := func(parent string, patches []any, blobs ...string) string {
		ps, err := seal.SealPatchSet(k, "e#1", "e", "d", parent, jsonv.FromGo(patches))
		noErr(t, err)
		ps, err = seal.WithBlobs(ps, blobs)
		noErr(t, err)
		if parent == "" {
			return must(src.c.Create(ctx, "e", "d", jsonv.MustParse(ps))).ID
		}
		return must(src.c.Append(ctx, "e", "d", parent, jsonv.MustParse(ps))).ID
	}
	s1, ref1 := upload(marker + " one")
	s2, ref2 := upload(marker + " two")
	b1, b2 := ref1["$blob"].(string), ref2["$blob"].(string)
	d0 := write("", client.GenesisPatches(map[string]any{"p": ref1}), b1)
	d1 := write(d0, ops(op("add", "/q", ref2)), b1, b2)
	tomb := must(src.c.Delete(ctx, "e", "d", d1)).ID
	d2 := must(src.c.Append(ctx, "e", "d", tomb, []any{})).ID

	var buf bytes.Buffer
	_, _, err = bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"e/d"}})
	noErr(t, err)
	want := "blob:" + string(s1) + " rev:" + d0 + " blob:" + string(s2) + " rev:" + d1 + " rev:" + tomb + " rev:" + d2 + " rev:" + krHead
	if got := order(t, buf.Bytes()); got != want {
		t.Fatalf("lines %q, want %q", got, want)
	}
	if bytes.Contains(buf.Bytes(), []byte(`"type":"image/png"`)) {
		t.Fatal("a blob line of an e2e namespace isn't of the sealed type")
	}

	dst := newEncDeployment(t, cmsOrigin)
	rep := importB(t, dst, buf.Bytes(), bundle.ImportOptions{})
	if u, _ := sentBlobs(rep); u != 2 || dst.head("e", "d").ID != d2 {
		t.Fatalf("e2e import uploaded %d, head %s", u, dst.head("e", "d").ID)
	}
	for _, c := range []struct {
		ref    map[string]any
		sealed []byte
		plain  string
	}{{ref1, s1, marker + " one"}, {ref2, s2, marker + " two"}} {
		g := must(dst.c.GetBlob(ctx, "e", "d", c.ref["$blob"].(string), ""))
		if !bytes.Equal(g.Data, c.sealed) || g.Type != bundle.SealedBlobType {
			t.Fatalf("target blob %s", g.Type)
		}
		if b := must(client.DecryptBlob(c.ref, g.Data)); string(b.Data) != c.plain {
			t.Fatalf("decrypted %q", b.Data)
		}
	}

	// A blob line of an e2e namespace that isn't a sealed blob (only a
	// crafted bundle has one) is refused before it is uploaded.
	png := []byte("not sealed")
	pbid := ids.Blob("image/png", "", png).String()
	ps, err := seal.SealPatchSet(k, "e#1", "e", "x", "", jsonv.FromGo(client.GenesisPatches(map[string]any{})))
	noErr(t, err)
	ps, err = seal.WithBlobs(ps, []string{pbid})
	noErr(t, err)
	pv := jsonv.MustParse(ps)
	x0 := ids.Revision(nil, jsonv.Canonical(pv)).String()
	krPatches := client.GenesisPatches(kr.Value())
	krv, err := client.ToValue(krPatches)
	noErr(t, err)
	var crafted bytes.Buffer
	w, err := bundle.NewWriter(&crafted, bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z",
		At: map[string]string{"e": x0}, Docs: map[string]bundle.DocInfo{"e/x": {History: bundle.Full, Head: x0}, "e/keyring": {History: bundle.Full, Head: krHead}},
		Access: map[string]string{"e": bundle.AccessE2E}})
	noErr(t, err)
	noErr(t, w.Line(bundle.Line{NS: "e", Resource: "keyring", ID: ids.Revision(nil, jsonv.Canonical(krv)).String(), Kind: "rev", Patches: krPatches}))
	noErr(t, w.Line(bundle.Line{NS: "e", Resource: "x", Blob: pbid, Type: "image/png", Data: png}))
	noErr(t, w.Line(bundle.Line{NS: "e", Resource: "x", ID: x0, Kind: "rev", Patches: pv}))
	_, err = w.Close()
	noErr(t, err)
	importErr(t, newEncDeployment(t, cmsOrigin), crafted.Bytes(), bundle.ImportOptions{}, "an e2e target accepts only sealed blobs")
}
