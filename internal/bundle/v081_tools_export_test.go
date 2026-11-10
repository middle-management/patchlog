package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// claimE2E is a transport that serves the namespace documents of ns as
// if ns were e2e: a server whose e2e namespace log holds plaintext rev
// lines, which v0.78 can no longer make (End-to-end from creation, or
// never).
type claimE2E struct {
	ns   string
	next http.RoundTripper
}

var nsDocPath = regexp.MustCompile(`^/ns/([^/]+)/rev/[^/]+$`)

func (c claimE2E) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(r)
	if err != nil || r.Method != http.MethodGet || res.StatusCode != http.StatusOK {
		return res, err
	}
	if m := nsDocPath.FindStringSubmatch(r.URL.Path); m == nil || m[1] != c.ns {
		return res, nil
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	doc["encryption"] = map[string]any{"level": "e2e"}
	body, _ = json.Marshal(doc)
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	res.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return res, nil
}

// E2E-12 (§G.5.1 step 1, v0.78 "End-to-end from creation, or never"): an
// e2e namespace's rev lines, the keyring's apart, are sealed ops or a
// restore's []. The exporter refuses, naming the line, an e2e namespace
// whose log holds any other, rather than bundling it under access "e2e"
// in plaintext, asked for or not; there is no pre-raise history to label.
func TestV081ExportRefusesPlaintextE2ELine(t *testing.T) {
	t.Parallel()
	src := newEncDeployment(t, stagingOrigin)

	// A real e2e namespace: its keyring, sealed ops and a restore's []
	// export as before.
	src.ns("e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
	reader := identity(t)
	k1 := seal.NewKey()
	kr, err := seal.BuildKeyringV2(reader, "e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()})
	noErr(t, err)
	src.create("e", "keyring", kr.Value())
	e2eWrite(t, src, k1, "e#1", "e", "d", "", client.GenesisPatches(map[string]any{"v": marker}))
	r0 := e2eWrite(t, src, k1, "e#1", "e", "r", "", client.GenesisPatches(map[string]any{"v": 1.0}))
	ts := must(src.c.Delete(ctx, "e", "r", r0)).ID
	restored := must(src.c.Restore(ctx, "e", "r", ts, []any{})).ID
	var buf bytes.Buffer
	p, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"e/d", "e/r"}})
	noErr(t, err)
	if p.Docs["e/keyring"] == nil || p.Docs["e/r"].Head != restored || bytes.Contains(buf.Bytes(), []byte(marker)) {
		t.Fatalf("e2e export: docs %v", p.Docs)
	}
	if prot := p.Protected(); len(prot) != 0 {
		t.Fatalf("an e2e namespace's ciphertext counted as protected plaintext: %v", prot)
	}

	// A namespace served as e2e whose log holds plaintext lines.
	src.ns("p", map[string]any{"read": "public"})
	src.create("p", "keyring", map[string]any{"v": 1.0})
	d0 := src.create("p", "d", map[string]any{"v": "plaintext-v081"})
	c := src.c.With(client.WithTransport(func(next http.RoundTripper) http.RoundTripper { return claimE2E{ns: "p", next: next} }))
	if lv := must(c.EncryptionLevel(ctx, "p")); lv != "e2e" {
		t.Fatalf("p served as %q", lv)
	}
	for _, opt := range []bundle.ExportOptions{{Select: []string{"p/d"}}, {Select: []string{"p/d"}, Plaintext: true}} {
		_, _, err := bundle.Export(ctx, c, io.Discard, opt)
		if err == nil || !strings.Contains(err.Error(), "p/d") || !strings.Contains(err.Error(), d0) || !strings.Contains(err.Error(), "sealed") {
			t.Fatalf("export of p/d (plaintext %v): %v, want a refusal naming the line %s", opt.Plaintext, err, d0)
		}
	}
	// Its keyring is plaintext by definition (§E.3.2).
	_, _, err = bundle.Export(ctx, c, io.Discard, bundle.ExportOptions{Select: []string{"p/keyring"}})
	noErr(t, err)
}
