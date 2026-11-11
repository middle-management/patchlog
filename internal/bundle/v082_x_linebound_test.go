package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"io"
	"strings"
	"testing"
	_ "unsafe" // go:linkname, below

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82xSealLineLimit is seal's bundleLineLimit (seal.MaxBundleLines unless a
// test lowers it), reached from here because no bundle of 2³² − 1 lines
// can be written in a test and seal exports no hook for it.
//
//go:linkname v82xSealLineLimit github.com/middle-management/patchlog/internal/seal.bundleLineLimit
var v82xSealLineLimit uint64

// XT-1 (2), E2E-8 through the bundle package (§E.2.1 Message bound,
// §G.5.1.1: "line numbers stop before 2³² − 1"): seal's bound on a sealed
// bundle's lines reaches the callers of bundle.SealedWriter, OpenSealed
// and Unseal as a *bundle.Error naming the line, the writer before that
// line is sealed, the reader for the whole bundle (every later
// Read fails too). With the bound lowered to 3 lines, a bundle of four is
// refused by both and one of three passes; at seal.MaxBundleLines, the
// four lines pass. Not parallel: the bound is seal's package variable.
func TestV082XSealedBundleLineBound(t *testing.T) {
	if v82xSealLineLimit != seal.MaxBundleLines || seal.MaxBundleLines != 1<<32-1 {
		t.Fatalf("seal's line bound is %d, MaxBundleLines %d, want 2³² − 1", v82xSealLineLimit, seal.MaxBundleLines)
	}
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{`{"n":0}`, `{"n":1}`, `{"n":2}`, `{"n":3}`}
	plain := func(n int) []byte { return []byte(strings.Join(lines[:n], "\n") + "\n") }
	sealN := func(n int) ([]byte, error) {
		var buf bytes.Buffer
		w, err := bundle.NewSealedWriter(&buf, []*ecdh.PublicKey{priv.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plain(n)); err != nil {
			return nil, err
		}
		err = w.Close()
		return buf.Bytes(), err
	}
	four, err := sealN(4)
	if err != nil {
		t.Fatal(err)
	}
	three, err := sealN(3)
	if err != nil {
		t.Fatal(err)
	}
	open := func(b []byte) ([]byte, io.Reader, error) {
		r, err := bundle.OpenSealed(bytes.NewReader(b), priv)
		if err != nil {
			return nil, nil, err
		}
		pt, err := io.ReadAll(r)
		return pt, r, err
	}
	if pt, _, err := open(four); err != nil || !bytes.Equal(pt, plain(4)) {
		t.Fatalf("four lines under the real bound: %q %v", pt, err)
	}

	v82xSealLineLimit = 3
	t.Cleanup(func() { v82xSealLineLimit = seal.MaxBundleLines })
	// The writer names the plain bundle's line, the reader the sealed
	// file's, whose first line is the envelope.
	bound := func(what string, err error, line int) {
		t.Helper()
		var be *bundle.Error
		if !errors.As(err, &be) {
			t.Fatalf("%s: %v (%T), want a *bundle.Error", what, err, err)
		}
		if be.Line != line || !strings.Contains(be.Msg, "2³²") || !strings.Contains(be.Msg, "§E.2.1") {
			t.Fatalf("%s: line %d, %q; want line %d and the message bound (§E.2.1)", what, be.Line, be.Msg, line)
		}
	}
	// The writer refuses to seal the line numbered 3.
	if _, err := sealN(4); err == nil {
		t.Fatal("the writer sealed a line at the bound")
	} else {
		bound("the writer", err, 4)
	}
	// The reader rejects the whole bundle at that line, and stays failed.
	pt, r, err := open(four)
	bound("OpenSealed", err, 5)
	if bytes.Contains(pt, []byte(lines[3])) {
		t.Fatalf("the reader gave the line at the bound: %q", pt)
	}
	if _, err := r.Read(make([]byte, 16)); err == nil || err == io.EOF {
		t.Fatalf("a Read after the rejection: %v, want the same refusal", err)
	} else {
		bound("a later Read", err, 5)
	}
	ur, sealed, err := bundle.Unseal(bytes.NewReader(four), priv)
	if err != nil || !sealed {
		t.Fatalf("Unseal: %v %v", sealed, err)
	}
	_, err = io.ReadAll(ur)
	bound("Unseal", err, 5)
	// One line fewer is within the bound for both.
	if pt, _, err := open(three); err != nil || !bytes.Equal(pt, plain(3)) {
		t.Fatalf("three lines under a bound of 3: %q %v", pt, err)
	}
	if _, err := sealN(3); err != nil {
		t.Fatalf("the writer, three lines under a bound of 3: %v", err)
	}
}
