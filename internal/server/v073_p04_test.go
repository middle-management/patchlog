package server

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// Spec v0.73 (P04, seal formats) at the wire: what a sealed (E2) namespace
// serves is in the §E.2.2 formats.

// A large, compressible document is served without a zip header (§E.2.2:
// sealed payloads are never compressed, v0.65).
func TestV073P04SealedNoZip(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	big := strings.Repeat("compressible ", 400)
	id := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": encMarker, "big": big})))
	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	ke := keys["s#1"]
	if ke == nil {
		t.Fatalf("keys %v", keys)
	}

	dr := e.get("/r/s/x/rev/" + id)
	expect(t, dr, 200)
	h, err := seal.ParseHeader(string(dr.Body))
	if err != nil {
		t.Fatal(err)
	}
	if h.Zip != "" || strings.Contains(string(h.Raw), `"zip"`) {
		t.Fatalf("a sealed document carries a zip header: %s", h.Raw)
	}
	if pt := open(t, string(dr.Body), resKey(t, ke, "s", "x"), "s#1", seal.ResourcePL("s", "x", id, seal.KindDoc)); !strings.Contains(string(pt), big) {
		t.Fatalf("document %s", pt)
	}
}
