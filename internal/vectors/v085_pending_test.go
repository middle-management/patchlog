package vectors_test

// What a deployment answers with the candidates C.4 and C.5 of
// docs/VECTORS-PROPOSED.md (v0.85): the two checks that need v0.85's
// changes to the bundle Reader (§G.4.1: a grant line's key) and to the
// index (§A.4: the marker reads:{ns}:{k}). Their computed values are in
// v085_candidates_test.go.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// C.5 (§G.4.1, v0.85: "Any of these rejects the bundle: … a grant line …
// whose key has a kid other than root.kid or doesn't verify the stored
// block"): each of the candidate's two bundles, §I.20's with the grant
// line's key.kid made ops-2027 or its key.pub made another key, is
// rejected whole by the bundle Reader, at the grant line; §I.20's own
// bundle is the control.
func TestV085C5GrantLineKeyRejected(t *testing.T) {
	t.Parallel()
	ai := loadAddendumI(t)
	if d, err := readBundle(ai.I20.Bundle); err != nil || d != ai.I20.Digest {
		t.Fatalf("§I.20's bundle, the control: %s %v", d, err)
	}
	p := loadCandidates(t).C5
	for i, b := range c5Rows(t) {
		row := p.Rows[i]
		d, err := readBundle(b)
		var be *bundle.Error
		if err == nil || !errors.As(err, &be) {
			t.Errorf("%s: read with digest %s, %v; want rejected (%s)", row.Change, d, err, row.Rule)
			continue
		}
		if be.Line != 2 {
			t.Errorf("%s: rejected at line %d (%v), want the grant line, 2", row.Change, be.Line, err)
		}
	}
}

// C.4, served (SERVICES §A.4 gs, §E.2.6 Whole-response sealing): an index
// of private, sealed demo at epoch 3, whose key ops-2026 has I.14's pub,
// answers bob, whom that key's grant lets read demo whole, at the
// candidate's gs, the one over the marker reads:demo:{key: string}, and
// seals the whole response under the view key of K_n with kid demo#3 and
// pl { ns, view }, view the URL it is served at.
func TestV085C4IndexServesWhole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := loadCandidates(t).C4
	i19 := loadAddendumI(t).I19
	// §I.19's demo, private as C.4 has it.
	if strings.Count(i19.Plaintexts["nsdoc"], `"read":"public"`) != 1 {
		t.Fatal("§I.19's nsdoc isn't public")
	}
	d := newSealedDemo(t, strings.Replace(i19.Plaintexts["nsdoc"], `"read":"public"`, `"read":"grant"`, 1), i19.Plaintexts)
	root := clienttest.Key{Kid: p.Kid, Pub: p.Pub, Priv: ed25519.NewKeyFromSeed(seq(0x00))}
	if pub := base64.RawURLEncoding.EncodeToString(root.Priv.Public().(ed25519.PublicKey)); pub != p.Pub {
		t.Fatalf("the key of seed 00 … 1f is %s, the candidate's %s", pub, p.Pub)
	}
	if _, err := d.bc.Create(ctx, "demo", "other", []byte(`[{"op":"add","path":"","value":{"title":"Hello"}},{"op":"add","path":"/$nonce","value":"`+seal.NewNonce()+`"}]`)); err != nil {
		t.Fatal(err)
	}
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := d.s.Client(t, client.WithBearer(root.Grant(t, d.s.Now(), "svc:indexer", []string{"demo"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	ix, err := index.Open(ctx, index.Options{Client: ic, DB: filepath.Join(t.TempDir(), "i.db"), Namespaces: []string{"demo"}, UntypedListing: true,
		Now: d.s.Now, Recipient: priv, CheckerTTL: time.Millisecond, RepurgeInterval: -1, Logf: func(f string, a ...any) { t.Logf(f, a...) }})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ix.Handler())
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { ix.Run(runCtx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; srv.Close(); ix.Close() })

	noFollow := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+d.bob)
		res, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, b
	}
	// The pointer, once the index has caught up.
	var loc string
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		res, b := get("/demo?limit=5")
		if res.StatusCode == http.StatusFound {
			loc = res.Header.Get("Location")
			break
		}
		if res.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
			t.Fatalf("GET /demo?limit=5: %d %s", res.StatusCode, b)
		}
	}
	if !strings.HasPrefix(loc, "/demo/g/"+p.GS+"/at/") {
		t.Fatalf("bob, reading demo whole through %s, is served at %s, want the candidate's gs %s (the marker %s)", p.Kid, loc, p.GS, p.Marker)
	}
	var res *http.Response
	var body []byte
	for i := 0; i < 5 && (res == nil || res.StatusCode == http.StatusFound); i++ {
		if res != nil {
			loc = res.Header.Get("Location")
		}
		res, body = get(loc)
	}
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), seal.ContentType) {
		t.Fatalf("GET %s: %d %s %s, want one JWE", loc, res.StatusCode, res.Header.Get("Content-Type"), body)
	}
	if !strings.HasPrefix(loc, "/demo/g/"+p.GS+"/at/") {
		t.Fatalf("served at %s", loc)
	}
	h, err := seal.ParseHeader(string(body))
	if err != nil {
		t.Fatal(err)
	}
	view := derived.View{NS: "demo", Target: loc}
	if h.Kid != "demo#3" || !jsonv.Equal(jsonv.FromGo(map[string]any(h.PL)), jsonv.FromGo(map[string]any(view.PL()))) {
		t.Errorf("the response is sealed under %s with pl %v, want demo#3 and %v", h.Kid, h.PL, view.PL())
	}
	pt, err := derived.OpenView(string(body), func(kid string) []byte {
		if kid == "demo#3" {
			return d.ke
		}
		return nil
	}, view)
	if err != nil {
		t.Fatalf("the response doesn't open under the view key of K_n: %v", err)
	}
	m, _ := jsonv.MustParse([]byte(strings.TrimRight(string(pt), " "))).(map[string]any)
	if hits, _ := m["hits"].([]any); len(hits) == 0 || m["at"] == nil {
		t.Errorf("the whole response: %s", pt)
	}
}
