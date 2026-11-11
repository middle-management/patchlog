package seal

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// v082Lines lowers the sealed-bundle line bound for one test. Not for
// parallel tests: sequential tests end before parallel ones resume.
func v082Lines(t *testing.T, n uint64) {
	old := bundleLineLimit
	bundleLineLimit = n
	t.Cleanup(func() { bundleLineLimit = old })
}

// E2E-1 (§E.2.2, §7.3, v0.82): a namespace event's pl is { ns, event: id }
// and nothing else; it is neither a range's nor a document's, so Expect
// refuses each as the other.
func TestV082NamespaceEventPL(t *testing.T) {
	t.Parallel()
	pl := NamespaceEventPL("cat", "id1")
	if len(pl) != 2 || pl["ns"] != "cat" || pl["event"] != "id1" {
		t.Fatalf("pl = %v", pl)
	}
	k := NewKey()
	ev, err := SealUncompressed(k, "cat#1", pl, []byte(`{"id":"id1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExpect(ev, k, "cat#1", pl); err != nil {
		t.Fatal(err)
	}
	for _, other := range []PL{RangePL("cat", "", "id1"), RangePL("cat", "id0", "id1"), NamespaceDocPL("cat", "id1"),
		NamespaceEventPL("cat", "id2"), NamespaceEventPL("dog", "id1"), {"ns": "cat", "event": "id1", "range": []any{"", "id1"}}} {
		if _, err := OpenExpect(ev, k, "cat#1", other); !errors.Is(err, ErrMismatch) {
			t.Fatalf("the event opened as %v: %v", other, err)
		}
		o, _ := SealUncompressed(k, "cat#1", other, []byte(`{"id":"id1"}`))
		if _, err := OpenExpect(o, k, "cat#1", pl); !errors.Is(err, ErrMismatch) {
			t.Fatalf("%v opened as the event: %v", other, err)
		}
	}
}

// E2E-8 (§E.2.1 Message bound, §G.5.1.1, v0.82): the writer seals no line
// numbered at the bound or beyond, refusing before it seals, and stays
// refused.
func TestV082BundleWriterLineBound(t *testing.T) {
	v082Lines(t, 3)
	_, id, _ := GenerateRecipient()
	var buf bytes.Buffer
	w, err := NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	// Each line is sealed once the next starts: the fifth Write would
	// seal line number 3.
	for i := 0; i < 4; i++ {
		if _, err := w.Write([]byte(`{"a":1}` + "\n")); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}
	before := buf.Len()
	if got := strings.Count(buf.String(), "\n"); got != 4 { // envelope and lines 0, 1, 2
		t.Fatalf("%d lines written", got)
	}
	_, err = w.Write([]byte(`{"a":1}` + "\n"))
	var be *BundleError
	if !errors.As(err, &be) || !strings.Contains(be.Msg, "§E.2.1") {
		t.Fatalf("the fourth sealing: %v", err)
	}
	if _, err := w.Write([]byte(`{"a":1}` + "\n")); err == nil {
		t.Fatal("a write after the refusal passed")
	}
	if err := w.Close(); err == nil {
		t.Fatal("Close after the refusal passed")
	}
	if buf.Len() != before {
		t.Fatal("the writer wrote after refusing")
	}

	// Exactly the bound's worth of lines is a whole bundle; Close itself
	// refuses the line that would be numbered at it.
	buf.Reset()
	w, _ = NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
	plain := strings.Repeat(`{"a":1}`+"\n", 3)
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := OpenBundle(bytes.NewReader(buf.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(r); err != nil || string(got) != plain {
		t.Fatalf("%q, %v", got, err)
	}
	buf.Reset()
	w, _ = NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
	if _, err := w.Write([]byte(plain + `{"a":1}` + "\n")); err != nil {
		t.Fatal(err)
	}
	before = buf.Len()
	if err := w.Close(); !errors.As(err, &be) {
		t.Fatalf("Close sealing the line at the bound: %v", err)
	}
	if buf.Len() != before {
		t.Fatal("Close wrote the line at the bound")
	}
}

// E2E-8: a reader rejects the whole bundle at a line numbered at the
// bound, on the authenticated pl.line, and yields nothing after it.
func TestV082BundleReaderLineBound(t *testing.T) {
	_, id, _ := GenerateRecipient()
	var buf bytes.Buffer
	w, err := NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.Repeat(`{"a":1}`+"\n", 5)
	if _, err := w.Write([]byte(plain)); err != nil || w.Close() != nil {
		t.Fatal(err)
	}
	// Written under the real bound; read under a lower one, every line's
	// tag is valid.
	v082Lines(t, 3)
	r, err := OpenBundle(bytes.NewReader(buf.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	var be *BundleError
	if !errors.As(err, &be) || !strings.Contains(be.Msg, "reaches the bound") || be.Line != 5 {
		t.Fatalf("read: %v", err)
	}
	if string(got) != strings.Repeat(`{"a":1}`+"\n", 3) {
		t.Fatalf("lines yielded before the rejection: %q", got)
	}
	// Sticky: no later line is yielded.
	if n, err2 := r.Read(make([]byte, 64)); n != 0 || err2 != err {
		t.Fatalf("after the rejection: %d, %v", n, err2)
	}
}

// E2E-8: the real bound, with counters preset just below it (uint64, so
// the same on a 32-bit platform): line 2³² − 2 is the highest sealed and
// read, 2³² − 1 is refused by both.
func TestV082BundleLineBoundAt2To32(t *testing.T) {
	t.Parallel()
	if MaxBundleLines != 4294967295 {
		t.Fatalf("MaxBundleLines = %d", MaxBundleLines)
	}
	_, id, _ := GenerateRecipient()
	var buf bytes.Buffer
	w, err := NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	envLen := buf.Len()
	w.n = MaxBundleLines - 1
	if _, err := w.Write([]byte(`{"a":1}` + "\n" + `{"a":2}` + "\n")); err != nil {
		t.Fatal(err) // seals line 2³² − 2
	}
	sealed := append([]byte(nil), buf.Bytes()...)
	var be *BundleError
	if err := w.Close(); !errors.As(err, &be) {
		t.Fatalf("sealing line 2³² − 1: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), sealed) {
		t.Fatal("line 2³² − 1 was written")
	}
	// The reader takes line 2³² − 2 where it expects it.
	r, err := OpenBundle(bytes.NewReader(sealed), id)
	if err != nil {
		t.Fatal(err)
	}
	r.(*bundleReader).n = MaxBundleLines - 1
	p := make([]byte, 64)
	if n, err := r.Read(p); err != nil || string(p[:n]) != `{"a":1}`+"\n" {
		t.Fatalf("line 2³² − 2: %q, %v", p[:n], err)
	}
	// A line numbered 2³² − 1 with a valid tag, as a writer without the
	// bound would seal it, marked last.
	buf.Reset()
	buf.Write(sealed[:envLen])
	w2 := &BundleWriter{w: &buf, aead: w.aead, id: w.id, n: MaxBundleLines}
	line := v082SealLine(t, w2, []byte(`{"a":3}`), true)
	r, err = OpenBundle(strings.NewReader(string(sealed[:envLen])+line), id)
	if err != nil {
		t.Fatal(err)
	}
	r.(*bundleReader).n = MaxBundleLines
	if n, err := r.Read(p); n != 0 || !errors.As(err, &be) || !strings.Contains(be.Msg, "reaches the bound") {
		t.Fatalf("line 2³² − 1: %d, %v", n, err)
	}
}

// v082SealLine seals pt as w's next line by hand, without the writer's
// bound.
func v082SealLine(t *testing.T, w *BundleWriter, pt []byte, last bool) string {
	t.Helper()
	pl := map[string]any{"bundle": w.id, "line": float64(w.n)}
	if last {
		pl["last"] = true
	}
	protected := b64.EncodeToString(jsonv.Canonical(map[string]any{"alg": AlgDir, "enc": EncA256GCM, "pl": pl}))
	iv := make([]byte, w.aead.NonceSize())
	ct := w.aead.Seal(nil, iv, pt, []byte(protected))
	tag := ct[len(ct)-w.aead.Overhead():]
	ct = ct[:len(ct)-w.aead.Overhead()]
	return protected + ".." + b64.EncodeToString(iv) + "." + b64.EncodeToString(ct) + "." + b64.EncodeToString(tag) + "\n"
}
