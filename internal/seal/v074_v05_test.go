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

// LEVELS-10/TOOLS-5 (§G.5.1.1, v0.74): sealed bundles are framed
// strictly. The envelope is canonical JSON, each line is followed by
// exactly one 0x0A, and each line's protected header is canonical JSON of
// alg, enc and pl only; anything else rejects the whole sealed bundle.
func TestV074SealedBundleStrictFraming(t *testing.T) {
	t.Parallel()
	_, id, _ := GenerateRecipient()
	plain := []byte(`{"authors":false,"bundle":1}` + "\n" + `{"a":1}` + "\n")
	var buf bytes.Buffer
	w, err := NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil || w.Close() != nil {
		t.Fatal(err)
	}
	good := buf.String()
	open := func(s string) error {
		r, err := OpenBundle(strings.NewReader(s), id)
		if err != nil {
			return err
		}
		got, err := io.ReadAll(r)
		if err == nil && !bytes.Equal(got, plain) {
			t.Fatalf("opened %q", got)
		}
		return err
	}
	// The writer's output conforms.
	if err := open(good); err != nil {
		t.Fatalf("a freshly written sealed bundle: %v", err)
	}
	lines := strings.SplitAfter(good, "\n") // envelope, line 0, line 1, ""
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("%d lines", len(lines))
	}
	// craft seals plaintext pt as a line under the bundle's key with the
	// protected header raw, as given.
	craft := func(raw string, pt string) string {
		protected := b64.EncodeToString([]byte(raw))
		iv := make([]byte, w.aead.NonceSize())
		ct := w.aead.Seal(nil, iv, []byte(pt), []byte(protected))
		n := len(ct) - w.aead.Overhead()
		return protected + ".." + b64.EncodeToString(iv) + "." + b64.EncodeToString(ct[:n]) + "." + b64.EncodeToString(ct[n:]) + "\n"
	}
	hdr := func(h map[string]any) string { return string(jsonv.Canonical(jsonv.FromGo(h))) }
	// The crafted lines themselves are well formed: a correct one opens.
	lastOK := craft(hdr(map[string]any{"alg": "dir", "enc": "A256GCM", "pl": map[string]any{"bundle": w.id, "line": 1, "last": true}}), `{"a":1}`)
	if err := open(lines[0] + lines[1] + lastOK); err != nil {
		t.Fatalf("a correctly crafted last line: %v", err)
	}
	for name, c := range map[string]struct{ sealed, want string }{
		"a blank line":         {lines[0] + lines[1] + "\n" + lines[2], "blank line"},
		"a blank line at end":  {good + "\n", "blank line"},
		"CRLF line ends":       {strings.ReplaceAll(good, "\n", "\r\n"), "0x0D"},
		"CRLF after a line":    {lines[0] + strings.TrimSuffix(lines[1], "\n") + "\r\n" + lines[2], "0x0D"},
		"no final 0x0A":        {strings.TrimSuffix(good, "\n"), "doesn't end in 0x0A"},
		"envelope with space":  {strings.Replace(lines[0], `{"id":`, `{ "id":`, 1) + lines[1] + lines[2], "not canonical"},
		"envelope reordered":   {reorderEnvelope(t, lines[0]) + lines[1] + lines[2], "not canonical"},
		"envelope CRLF":        {strings.TrimSuffix(lines[0], "\n") + "\r\n" + lines[1] + lines[2], "line 1: sealed bundle: a 0x0D"},
		"last beside pl":       {lines[0] + lines[1] + craft(hdr(map[string]any{"alg": "dir", "enc": "A256GCM", "last": true, "pl": map[string]any{"bundle": w.id, "line": 1}}), `{"a":1}`), "unsupported header member"},
		"header not canonical": {lines[0] + lines[1] + craft(`{"enc":"A256GCM","alg":"dir","pl":{"bundle":"`+w.id+`","last":true,"line":1}}`, `{"a":1}`), "not canonical"},
		"header with a space":  {lines[0] + lines[1] + craft(`{"alg":"dir", "enc":"A256GCM","pl":{"bundle":"`+w.id+`","last":true,"line":1}}`, `{"a":1}`), "not canonical"},
	} {
		err := open(c.sealed)
		var be *BundleError
		if !errors.As(err, &be) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a BundleError containing %q", name, err, c.want)
		}
	}
}

// reorderEnvelope writes the envelope's members in another order, which
// is still JSON but not canonical.
func reorderEnvelope(t *testing.T, line string) string {
	t.Helper()
	m := jsonv.MustParse([]byte(strings.TrimSuffix(line, "\n"))).(map[string]any)
	return `{"sealedBundle":1,"id":` + string(jsonv.Canonical(m["id"])) + `,"recipients":` + string(jsonv.Canonical(m["recipients"])) + "}\n"
}
