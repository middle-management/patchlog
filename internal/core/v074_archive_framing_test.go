package core

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// v0.74 integration (§8.6, §G.5.1.1): an encrypted archive is a sealed
// bundle, so the server reads its envelope line framed as strictly as
// bundle import does: the line is followed by exactly one 0x0A and
// nothing else, with no space or 0x0D taken off. The lines after it were
// already framed strictly by internal/seal.
func TestV074ArchiveEnvelopeFraming(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Limits: lim, Purger: discardPurger{}, KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	mkNS(t, e, "enc", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	if _, err := put(e, "enc", "a", "", 1); err != nil {
		t.Fatal(err)
	}
	bundleBytes := []byte(`{"authors":true,"bundle":1}` + "\n" + `{"a":1}` + "\n")
	var sealed bytes.Buffer
	if err := e.update(ctx, func(t2 *tx) error {
		n := t2.nsByName("enc")
		sw, err := t2.archiveBundleSealer(n, t2.resource(n.id, "a").id)(&sealed)
		if err != nil {
			return err
		}
		if _, err := sw.Write(bundleBytes); err != nil {
			return err
		}
		return sw.Close()
	}); err != nil {
		t.Fatal(err)
	}
	good := sealed.Bytes()
	nl := bytes.IndexByte(good, '\n')
	env, rest := good[:nl], good[nl+1:]
	read := func(b []byte) ([]byte, error) {
		r, err := e.ReadArchive(ctx, "enc", "a", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	}
	if got, err := read(good); err != nil || !bytes.Equal(got, bundleBytes) {
		t.Fatalf("the archiver's own output: %q, %v", got, err)
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for name, b := range map[string][]byte{
		"envelope ended by CRLF":    join(env, []byte("\r\n"), rest),
		"space before the 0x0A":     join(env, []byte(" \n"), rest),
		"space before the envelope": join([]byte(" "), env, []byte("\n"), rest),
		"blank line after envelope": join(env, []byte("\n\n"), rest),
		"tab around the envelope":   join([]byte("\t"), env, []byte("\t\n"), rest),
	} {
		if got, err := read(b); err == nil && bytes.Equal(got, bundleBytes) {
			t.Errorf("%s: read as the archived bundle", name)
		}
	}
}
