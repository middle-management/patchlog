package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
)

func TestRowSeal(t *testing.T) {
	dek := make([]byte, dekSize)
	rand.Read(dek)
	id := ids.Of([]byte("x"))
	row := sealRow(dek, revAAD(7, id), []byte(`[{"op":"add"}]`))
	if !isSealed(string(row)) || isSealed(`[{"op":"add"}]`) || isSealed(`"s"`) {
		t.Fatal("version byte doesn't tell rows apart")
	}
	if b, err := openRow(dek, revAAD(7, id), row); err != nil || string(b) != `[{"op":"add"}]` {
		t.Fatalf("open: %v", err)
	}
	for _, aad := range [][]byte{revAAD(8, id), docAAD("heads", 7, 1), docAAD("snapshots", 7, 1)} {
		if _, err := openRow(dek, aad, row); err == nil {
			t.Fatal("a row opened under another aad")
		}
	}
}

func TestArchiveStream(t *testing.T) {
	dek := make([]byte, dekSize)
	rand.Read(dek)
	for _, n := range []int{0, 1, archiveChunk - 1, archiveChunk, archiveChunk + 1, 3 * archiveChunk} {
		plain := make([]byte, n)
		rand.Read(plain)
		var buf bytes.Buffer
		w, err := sealArchive(&buf, dek)
		if err != nil {
			t.Fatal(err)
		}
		// Uneven writes.
		for p := plain; len(p) > 0; {
			k := min(len(p), 1000+len(p)%7777)
			w.Write(p[:k])
			p = p[k:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		enc := buf.Bytes()
		r, err := openArchive(bufio.NewReader(bytes.NewReader(enc)), dek)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%d bytes: round trip %v", n, err)
		}
		// Truncation, a flipped bit and another key all fail.
		for _, bad := range [][]byte{enc[:len(enc)-1], enc[:archiveHdr+2], flip(enc, len(enc)/2+archiveHdr/2)} {
			r, err := openArchive(bufio.NewReader(bytes.NewReader(bad)), dek)
			if err == nil {
				_, err = io.ReadAll(r)
			}
			if err == nil {
				t.Fatalf("%d bytes: damaged archive read", n)
			}
		}
		other := make([]byte, dekSize)
		rand.Read(other)
		r, _ = openArchive(bufio.NewReader(bytes.NewReader(enc)), other)
		if _, err := io.ReadAll(r); err == nil {
			t.Fatalf("%d bytes: read with another key", n)
		}
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 1
	return c
}
