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
