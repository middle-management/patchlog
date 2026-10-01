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
