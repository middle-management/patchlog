package bundle_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// §G.4.1 blob lines: written, read back with recomputed ids, at most once
// per resource, and tampering rejects the bundle.
func TestBlobLines(t *testing.T) {
	data := []byte("blob bytes \x00\xff")
	bid := ids.Blob("image/png", "", data).String()
	patches := client.GenesisPatches(map[string]any{"img": client.BlobRef(bid, "image/png", len(data), "")})
	pv, err := client.ToValue(patches)
	if err != nil {
		t.Fatal(err)
	}
	rev := ids.Revision(nil, jsonv.Canonical(pv)).String()
	h := bundle.Header{Origin: "https://a.example", Created: "2026-10-01T00:00:00Z",
		At:   map[string]string{"m": rev},
		Docs: map[string]bundle.DocInfo{"m/a": {History: bundle.Full, Head: rev}}}
	var buf bytes.Buffer
	w, err := bundle.NewWriter(&buf, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Line(bundle.Line{NS: "m", Resource: "a", Blob: bid, Type: "image/png", Data: data}); err != nil {
		t.Fatal(err)
	}
	if err := w.Line(bundle.Line{NS: "m", Resource: "a", Blob: bid, Type: "image/png", Data: data}); err == nil {
		t.Fatal("a second line for the same blob was written")
	}
	if err := w.Line(bundle.Line{NS: "m", Resource: "a", ID: rev, Kind: "rev", Patches: patches}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"data":"YmxvYiBieXRlcyAA_w"`) {
		t.Fatalf("data is not unpadded base64url: %s", buf.String())
	}
	rd, err := bundle.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	l, err := rd.Next()
	if err != nil || !l.IsBlob() || string(l.Data) != string(data) || l.Type != "image/png" {
		t.Fatalf("blob line %+v %v", l, err)
	}
	for {
		if _, err := rd.Next(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	// Other bytes under the same id: rejected.
	verifyErr(t, bytes.Replace(buf.Bytes(), []byte("YmxvYiBieXRlcyAA_w"), []byte("YmxvYiBieXRlcyAB_w"), 1), "does not match its bytes")
	verifyErr(t, bytes.Replace(buf.Bytes(), []byte("YmxvYiBieXRlcyAA_w"), []byte("YmxvYiBieXRlcyAA_x"), 1), "base64url")
	// A resource not in docs: rejected.
	verifyErr(t, bytes.Replace(buf.Bytes(), []byte(`"resource":"a","type"`), []byte(`"resource":"b","type"`), 1), "not listed")
}
