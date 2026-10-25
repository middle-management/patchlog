package seal

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"errors"
	"io"
	"strings"
	"testing"
)

// P34, CIS-34 (§G.5.1.1): the sealed-bundle writer and reader live here,
// so the core can write pruning archives of encrypted namespaces with
// them. A bundle sealed to two recipients opens with either, line for
// line; padding is removed; a third identity is ErrNotRecipient; failed
// checks are *BundleError naming the file's line.
func TestV073SealedBundleInSeal(t *testing.T) {
	t.Parallel()
	_, alice, _ := GenerateRecipient()
	_, bob, _ := GenerateRecipient()
	_, eve, _ := GenerateRecipient()
	plain := []byte(`{"authors":false,"bundle":1}` + "\n" + `{"a":1}` + "\n" + `{"b":[true,null]}` + "\n")
	for _, pad := range []bool{false, true} {
		var buf bytes.Buffer
		w, err := NewBundleWriter(&buf, []*ecdh.PublicKey{alice.PublicKey(), bob.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		w.Pad = pad
		// Written in pieces that split lines.
		for _, part := range [][]byte{plain[:5], plain[5:31], plain[31:]} {
			if _, err := w.Write(part); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		b := buf.Bytes()
		lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
		if len(lines) != 4 {
			t.Fatalf("pad %v: %d lines, want the envelope and 3", pad, len(lines))
		}
		env, ok, err := ParseBundleEnvelope(lines[0])
		if !ok || err != nil || len(env.Recipients) != 2 || env.Recipients[Thumbprint(alice.PublicKey())] == nil {
			t.Fatalf("pad %v: envelope %+v %v %v", pad, env, ok, err)
		}
		for _, id := range []*ecdh.PrivateKey{alice, bob} {
			r, err := OpenBundle(bytes.NewReader(b), id)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("pad %v: opened %q, %v", pad, got, err)
			}
		}
		if _, err := OpenBundle(bytes.NewReader(b), eve); !errors.Is(err, ErrNotRecipient) {
			t.Fatalf("pad %v: another identity: %v", pad, err)
		}
		// Truncated: the last line is missing.
		r, err := env.Open(bufio.NewReader(bytes.NewReader(bytes.Join(lines[1:3], []byte("\n")))), alice)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(r)
		var be *BundleError
		if !errors.As(err, &be) || be.Line != 4 || !strings.Contains(be.Msg, "no line says last") {
			t.Fatalf("pad %v: truncated: %v", pad, err)
		}
	}
	// A plain bundle's header isn't an envelope.
	if _, ok, err := ParseBundleEnvelope([]byte(`{"authors":false,"bundle":1}`)); ok || err != nil {
		t.Fatalf("plain header: %v %v", ok, err)
	}
	if _, err := OpenBundle(bytes.NewReader(plain), alice); err == nil || !strings.Contains(err.Error(), "not a sealed bundle") {
		t.Fatalf("plain bundle: %v", err)
	}
	// The writer seals canonical lines only.
	for name, in := range map[string]string{
		"blank":         "\n",
		"not canonical": `{ "a":1}` + "\n",
		"not I-JSON":    `{"a":1,"a":2}` + "\n",
		"unterminated":  `{"a":1}`,
	} {
		w, _ := NewBundleWriter(io.Discard, []*ecdh.PublicKey{alice.PublicKey()})
		_, err := w.Write([]byte(in))
		if err == nil {
			err = w.Close()
		}
		var be *BundleError
		if !errors.As(err, &be) || be.Line != 1 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewBundleWriter(io.Discard, nil); err == nil {
		t.Fatal("no recipients")
	}
}

// P34 review (§G.5.1.1, §8.6): MaxBundleLine is a bound of this package,
// not of the format. BundleWriter.MaxLine refuses a line whose sealed form
// would be longer, naming the plain bundle's line, before writing any of
// it, so the writer never writes a bundle that a reader with the same
// bound refuses; OpenBundleMax and BundleEnvelope.OpenMax read with a
// bound of their own, or none (negative), as pruning archives are read.
// 0 stands for MaxBundleLine on both sides.
func TestV073SealedBundleLineBound(t *testing.T) {
	t.Parallel()
	_, id, _ := GenerateRecipient()
	plain := []byte(`{"authors":false,"bundle":1}` + "\n" + `{"data":"` + strings.Repeat("x", 4000) + `"}` + "\n" + `{"a":1}` + "\n")
	write := func(max int, pad bool) ([]byte, error) {
		var buf bytes.Buffer
		w, err := NewBundleWriter(&buf, []*ecdh.PublicKey{id.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		w.Pad, w.MaxLine = pad, max
		if _, err = w.Write(plain); err == nil {
			err = w.Close()
		}
		return buf.Bytes(), err
	}
	for _, pad := range []bool{false, true} {
		b, err := write(-1, pad)
		if err != nil {
			t.Fatalf("pad %v: no bound: %v", pad, err)
		}
		lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
		longest, at := 0, 0
		for i, l := range lines[1:] {
			if len(l) > longest {
				longest, at = len(l), i
			}
		}
		if at != 1 {
			t.Fatalf("pad %v: line %d is the longest, not the long one", pad, at)
		}
		// Read with the longest line's length as the bound, and with none.
		for _, max := range []int{longest, -1, 0} {
			r, err := OpenBundleMax(bytes.NewReader(b), id, max)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("pad %v, max %d: %q %v", pad, max, got, err)
			}
		}
		// One byte less, and the long line is refused.
		r, err := OpenBundleMax(bytes.NewReader(b), id, longest-1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r); err == nil || !strings.Contains(err.Error(), "too long") {
			t.Fatalf("pad %v: read with a bound below the longest line: %v", pad, err)
		}
		env, _, _ := ParseBundleEnvelope(lines[0])
		br := bufio.NewReader(bytes.NewReader(b[len(lines[0])+1:]))
		if r, err = env.OpenMax(br, id, longest-1); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r); err == nil || !strings.Contains(err.Error(), "too long") {
			t.Fatalf("pad %v: OpenMax below the longest line: %v", pad, err)
		}
		// The writer: the same bundle within the longest line's length;
		// one byte less refuses the plain bundle's line 2 with only the
		// envelope and line 1 written.
		if again, err := write(longest, pad); err != nil || len(again) != len(b) {
			t.Fatalf("pad %v: written within the bound: %d bytes, %v", pad, len(again), err)
		}
		part, err := write(longest-1, pad)
		var be *BundleError
		if !errors.As(err, &be) || be.Line != 2 || !strings.Contains(be.Msg, "a reader takes") {
			t.Fatalf("pad %v: written over the bound: %v", pad, err)
		}
		if n := bytes.Count(part, []byte("\n")); n != 2 {
			t.Fatalf("pad %v: %d lines written before the refused one, want 2", pad, n)
		}
	}
	if lineBound(0) != MaxBundleLine || lineBound(-7) != -1 || lineBound(10) != 10 {
		t.Fatal("lineBound")
	}
}
