package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
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
