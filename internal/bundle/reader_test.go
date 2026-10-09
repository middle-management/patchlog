package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// readAll reads a bundle to its end, parsing lines ahead on workers if
// more than one: the keys of its lines in order, its digest, and the
// error it stopped at.
func readAll(t *testing.T, b []byte, workers int) ([]string, string, error) {
	t.Helper()
	rd, err := NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	rd.parallel(workers)
	defer rd.Close()
	var keys []string
	for {
		l, err := rd.Next()
		if err == io.EOF {
			return keys, rd.Digest(), nil
		}
		if err != nil {
			// Parsing ahead stops there: it stays the error.
			if _, again := rd.Next(); workers > 1 && (again == nil || again.Error() != err.Error()) {
				t.Fatalf("read again after %v: %v", err, again)
			}
			return keys, "", err
		}
		keys = append(keys, fmt.Sprintf("%d %s %s%s", rd.lineNo, l.Key(), l.ID, l.Snapshot))
	}
}

// A reader parsing lines ahead on workers reads what one reading them in
// turn does: the same lines in order, with their line numbers, the same
// digest, and the same error at the same line.
func TestReaderParallel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h := Header{Origin: "https://a.example", Created: "2026-10-01T00:00:00Z", At: map[string]string{}, Docs: map[string]DocInfo{}}
	h.At["n"] = must(client.ExpectedRevision("", client.GenesisPatches("n")))
	var ids []string
	for i := 0; i < 300; i++ {
		doc := map[string]any{"i": float64(i), "s": fmt.Sprint("doc ", i)}
		id := must(client.ExpectedRevision("", client.GenesisPatches(doc)))
		ids = append(ids, id)
		h.Docs[Key("n", fmt.Sprint("d", i))] = DocInfo{History: Snapshot, Head: id}
	}
	w := must(NewWriter(&buf, h))
	for i, id := range ids {
		if err := w.SnapshotDoc("n", fmt.Sprint("d", i), id, map[string]any{"i": float64(i), "s": fmt.Sprint("doc ", i)}, false); err != nil {
			t.Fatal(err)
		}
	}
	must(w.Close())
	b := buf.Bytes()
	// Blank lines are skipped, and counted.
	b = bytes.Replace(b, []byte("\n"), []byte("\n\n"), 3)

	seqKeys, seqDigest, err := readAll(t, b, 1)
	if err != nil || len(seqKeys) != 300 {
		t.Fatalf("%d lines, %v", len(seqKeys), err)
	}
	keys, digest, err := readAll(t, b, 4)
	if err != nil || digest != seqDigest || fmt.Sprint(keys) != fmt.Sprint(seqKeys) {
		t.Fatalf("parallel: %v, digest %s, want %s", err, digest, seqDigest)
	}

	for _, bad := range []struct {
		name string
		from []byte
		to   []byte
	}{
		{"not JSON", []byte(`"doc 150"`), []byte(`"doc 150`)},
		{"not a line", []byte(`"resource":"d150"`), []byte(`"resource":"d150","zz":1`)},
		{"truncated", b, b[:bytes.LastIndexByte(b[:len(b)-1], '\n')+1]},
	} {
		c := bytes.Replace(b, bad.from, bad.to, 1)
		seqKeys, _, seqErr := readAll(t, c, 1)
		keys, _, err := readAll(t, c, 4)
		var be *Error
		if seqErr == nil || err == nil || err.Error() != seqErr.Error() || !errors.As(err, &be) || fmt.Sprint(keys) != fmt.Sprint(seqKeys) {
			t.Fatalf("%s: %v after %d lines, want %v after %d", bad.name, err, len(keys), seqErr, len(seqKeys))
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
