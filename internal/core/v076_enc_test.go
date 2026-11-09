package core

import (
	"context"
	"crypto/ecdh"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// §G.5.2 E3 sources (v0.76): a remote branch's deeper shadow, one below
// its first, is readable for its keys only while the follower's latest
// read of its current namespace document succeeded (remote_chain_read):
// not before the first success, not after a failure; the first shadow, and
// any namespace that isn't a shadow, always are. On SQLite and, with
// PATCHLOG_TEST_PG, on Postgres.
func TestV076EncChainReadable(t *testing.T) {
	t.Parallel()
	e := openBlobEngine(t)
	ctx := context.Background()
	var first, deeper, branch int64
	if err := e.update(ctx, func(t *tx) error {
		deeper = t.mustInsert(`INSERT INTO namespaces (name) VALUES ('~v076-1') RETURNING ns`)
		first = t.mustInsert(`INSERT INTO namespaces (name, base) VALUES ('~v076-0', ?) RETURNING ns`, deeper)
		branch = t.mustInsert(`INSERT INTO namespaces (name, base) VALUES ('v076', ?) RETURNING ns`, first)
		_, err := t.Exec(`INSERT INTO remote_bases (shadow, branch, origin, ns, at, checkpoint) VALUES (?,?,?,?,?,?)`, first, branch, "https://a.example", "eb", "x", "x")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	readable := func() (f, d, b bool) {
		if err := e.read(ctx, func(t *tx) error {
			f, d, b = t.chainReadable(t.nsByID(first)), t.chainReadable(t.nsByID(deeper)), t.chainReadable(t.nsByID(branch))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	mark := func(ok bool) {
		if err := e.update(ctx, func(t *tx) error { t.chainRead(deeper, ok); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		what string
		mark func()
		want bool
	}{
		{"before any read", func() {}, false},
		{"after a successful read", func() { mark(true) }, true},
		{"after a failed read", func() { mark(false) }, false},
		{"after a successful read again", func() { mark(true) }, true},
	} {
		c.mark()
		f, d, b := readable()
		if !f || !b || d != c.want {
			t.Fatalf("%s: first %v, deeper %v, branch %v; want true, %v, true", c.what, f, d, b, c.want)
		}
	}
}

// §G.5.2 E3 sources (v0.76): a sealing of A's that B can't open is kept on
// its shape alone: a compact JWE whose kid and pl are the ones A serves
// that content under.
func TestV076EncPreSealingShape(t *testing.T) {
	t.Parallel()
	pl := seal.ResourcePL("m", "x", "1abc", seal.KindDoc)
	jwe, err := seal.Seal(seal.NewKey(), "m#1", pl, []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if !preSealingShape(jwe, "m#1", pl) {
		t.Fatal("A's JWE under m#1 for the content: refused")
	}
	for what, c := range map[string]struct {
		jwe, kid string
		pl       seal.PL
	}{
		"another epoch":   {jwe, "m#2", pl},
		"another content": {jwe, "m#1", seal.ResourcePL("m", "y", "1abc", seal.KindDoc)},
		"not a JWE":       {"not.a.jwe", "m#1", pl},
		"JSON":            {`{"v":1}`, "m#1", pl},
	} {
		if preSealingShape(c.jwe, c.kid, c.pl) {
			t.Errorf("%s: accepted", what)
		}
	}
}

// §E.2.2, §G.5.2 (v0.76): B learns the epoch A fixes for a blob from the
// redirect of its …/blob/{bid} URL, which it doesn't follow; any other
// answer but a 5xx gives none.
func TestV076EncBlobHeadEpoch(t *testing.T) {
	t.Parallel()
	const path = "/r/m/x/blob/1bid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path+"/e/3" {
			t.Errorf("the redirect was followed")
		}
		http.Redirect(w, r, path+"/e/3", http.StatusFound)
	}))
	defer srv.Close()
	ep := RemoteEndpoint{HTTPClient: srv.Client()}
	if e, err := blobHeadEpoch(context.Background(), ep, srv.URL, path); err != nil || e != 3 {
		t.Fatalf("epoch %d %v, want 3", e, err)
	}
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	if _, err := blobHeadEpoch(context.Background(), RemoteEndpoint{HTTPClient: down.Client()}, down.URL, path); err == nil || !noAnswer(err) {
		t.Fatalf("a 503: %v, want no answer", err)
	}
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer gone.Close()
	if e, err := blobHeadEpoch(context.Background(), RemoteEndpoint{HTTPClient: gone.Client()}, gone.URL, path); err != nil || e != 0 {
		t.Fatalf("a 404: %d %v, want none", e, err)
	}
}

// §E.3.2, §C.7 (v0.76): only a keyring write needs a fresh $nonce. One
// stored before v0.76, when the gate took a $nonce of any form, or mirrored
// from such a remote base, is still relayed by /keys (keyringEntries).
func TestV076EncStoredKeyringNonceRelayed(t *testing.T) {
	_, admin, _ := seal.GenerateRecipient()
	_, reader, _ := seal.GenerateRecipient()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, seal.NewKey(), []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{seal.NewNonce(), "x", ""} {
		d := kr.Value()
		d["$nonce"] = n
		if got := keyringEntries(d, reader.PublicKey(), []int{1}); len(got) != 1 {
			t.Fatalf("stored keyring with $nonce %q: relayed %v, want the one entry it wraps to the reader", n, got)
		}
	}
}
