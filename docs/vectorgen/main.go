// Command vectorgen prints the known-answer vectors for docs/TESTVECTORS.md.
// It is a scratch tool; delete tmp/ after use.
package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"io"

	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

func canon(v any) string { return string(jsonv.Canonical(v)) }

// hkdfNew is HKDF (RFC 5869) instantiated with crypto/sha256, avoiding an
// x/crypto dependency in this scratch tool.
func hkdfNew(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
	prkMAC := hmac.New(hash, salt)
	prkMAC.Write(secret)
	prk := prkMAC.Sum(nil)
	return &hkdfReader{hash: hash, prk: prk, info: info}
}

type hkdfReader struct {
	hash func() hash.Hash
	prk  []byte
	info []byte
	t    []byte
	n    int
}

func (r *hkdfReader) Read(p []byte) (int, error) {
	for len(r.t) < len(p) {
		r.n++
		m := hmac.New(r.hash, r.prk)
		if r.n > 1 {
			m.Write(r.t[:r.hash().Size()])
		}
		m.Write(r.info)
		m.Write([]byte{byte(r.n)})
		r.t = m.Sum(nil)
	}
	n := copy(p, r.t[:len(p)])
	return n, nil
}

func main() {
	// §3.3 revision ids
	genesisPatches := `[{"op":"add","path":"","value":{"title":"Hello","views":0}}]`
	g := ids.Revision(nil, []byte(genesisPatches))
	fmt.Printf("rev genesis: %s\n  hex: %s\n", g, hex.EncodeToString(g[:]))
	childPatches := `[{"op":"replace","path":"/views","value":1}]`
	c := ids.Revision(&g, []byte(childPatches))
	fmt.Printf("rev child:   %s\n  hex: %s\n", c, hex.EncodeToString(c[:]))

	// §3.4 tombstone
	t := ids.Tombstone(c)
	fmt.Printf("tombstone:   %s\n  hex: %s\n", t, hex.EncodeToString(t[:]))

	// §3.5 namespace revision id, config entry over a small namespace document
	nsdoc := map[string]any{"read": "public"}
	entry := map[string]any{"kind": "config", "target": g.String()}
	ns1 := ids.Hash(nil, []byte(canon(entry)))
	fmt.Printf("nsdoc canon: %s\n", canon(nsdoc))
	fmt.Printf("ns entry:    %s\n", canon(entry))
	fmt.Printf("ns_id 1:     %s\n", ns1)
	headEntry := map[string]any{"kind": "head", "resource": "derby", "target": g.String()}
	ns2 := ids.Hash(&ns1, []byte(canon(headEntry)))
	fmt.Printf("ns entry2:   %s\n", canon(headEntry))
	fmt.Printf("ns_id 2:     %s\n", ns2)

	// §3.7 blob ids
	data := []byte("hello patchlog\n")
	b1 := ids.Blob("text/plain", "", data)
	b2 := ids.Blob("text/plain", "aaaaaaaaaaaaaaaaaaaaaaaaaa", data)
	fmt.Printf("blob no nonce:   %s\n", b1)
	fmt.Printf("blob with nonce: %s\n", b2)

	// §C.3 grant id
	root := map[string]any{
		"kid": "ops-2026", "sub": "user:bob", "groups": []string{"match-desk"},
		"ns": []string{"matches"}, "can": []string{"read", "append"},
		"exp": "2026-10-05T00:00:00Z", "rules": []any{},
	}
	gid := ids.Of([]byte(canon(root)))
	fmt.Printf("grant root: %s\ngrant id: %s\n", canon(root), gid)

	// §C.3.1 signature
	pub, priv, _ := ed25519.GenerateKey(strings.NewReader(strings.Repeat("deterministic-seed-for-vectors!", 2)))
	origin := "https://cms.example"
	var sigInput []byte
	sigInput = append(sigInput, []byte("patchlog-sig-v2\n")...)
	sigInput = append(sigInput, []byte(origin)...)
	sigInput = append(sigInput, 0x0A)
	sigInput = append(sigInput, []byte("matches")...)
	sigInput = append(sigInput, 0x0A)
	sigInput = append(sigInput, []byte("derby")...)
	sigInput = append(sigInput, 0x0A)
	sigInput = append(sigInput, g[:]...)
	sigInput = append(sigInput, 0x0A)
	sigInput = append(sigInput, []byte(childPatches)...)
	digest := sha256.Sum256(sigInput)
	sig := ed25519.Sign(priv, digest[:])
	b64 := base64.RawURLEncoding.EncodeToString
	fmt.Printf("sig pub: %s\nsig digest: %s\nsignature: Ed25519:key-1:%s\n", b64(pub), hex.EncodeToString(digest[:]), b64(sig))

	// §C.5.3 cookie vector (README's pinned example)
	key := edge.KeyFromSecret([]byte("example edge secret"))
	fmt.Printf("edge key: %s\n", hex.EncodeToString(key))
	cks := edge.NewCookies("origin", key)
	_ = edge.Claims{Kid: "origin", Prefix: "/r/demo/derby", Exp: 1790000900}
	fmt.Printf("cookie name: %s\n", edge.Name("/r/demo/derby"))
	canonClaims := `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}`
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(base64.RawURLEncoding.EncodeToString([]byte(canonClaims))))
	fmt.Printf("cookie value: %s.%s\n", b64([]byte(canonClaims)), b64(mac.Sum(nil)))
	_ = cks

	// §E.2.1 per-resource key derivation
	ke := make([]byte, 32)
	for i := range ke {
		ke[i] = byte(i)
	}
	h := hkdfNew(sha256.New, ke, []byte("patchlog-e2"), []byte("demo\x0aderby"))
	kr := make([]byte, 32)
	_, _ = rand.Read(nil)
	n, _ := h.Read(kr)
	fmt.Printf("K_e (hex, test): %s\nK_r len=%d: %s\n", hex.EncodeToString(ke), n, hex.EncodeToString(kr))

	// §E.2.2 padmé buckets
	for _, l := range []int{1, 255, 256, 257, 300, 511, 513, 1000, 4096, 1000000, 1 << 20, 64 << 20} {
		fmt.Printf("padme(%d) = %d\n", l, seal.PadLen(l))
	}

	// §B.11.5 subject-set gs
	subjects := []string{"group:match-desk", "user:anna"}
	gs := ids.Of([]byte(canon(subjects)))
	fmt.Printf("gs subjects: %s\ngs: %s\n", canon(subjects), gs)

	// §B.5 combined checkpoint
	comb := map[string]any{"cat": ns1.String(), "matches": ns2.String()}
	at := ids.Of([]byte(canon(comb)))
	fmt.Printf("combined checkpoint: %s\nat: %s\n", canon(comb), at)

	// §G.4.1 bundle digest
	line0 := canon(map[string]any{"bundle": 1, "origin": "https://staging.example", "authors": false})
	line1 := canon(map[string]any{"ns": "matches", "resource": "derby", "id": g.String(), "parent": "", "kind": "rev", "patches": jsonv.MustParse([]byte(genesisPatches))})
	bundle := line0 + "\n" + line1 + "\n"
	fmt.Printf("bundle line0: %s\nbundle line1: %s\nbundle digest: %s\n", line0, line1, ids.Of([]byte(bundle)))
}
