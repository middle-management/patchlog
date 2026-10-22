package playground

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// legacyZipJWE seals plaintext as JWEs were sealed before v0.65 when they
// were compressed: raw DEFLATE under the protected header canonical({alg,
// enc, kid, pl, zip: "DEF"}) (RFC 7516 §5.1). Seal never compresses now
// (§E.2.2), but readers still open such stored bytes.
func legacyZipJWE(key []byte, kid string, pl seal.PL, plaintext []byte) (string, error) {
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	w.Write(plaintext)
	w.Close()
	hdr := map[string]any{"alg": seal.AlgDir, "enc": seal.EncA256GCM, "kid": kid, "pl": map[string]any(pl), "zip": seal.ZipDeflate}
	protected := b64.EncodeToString(jsonv.Canonical(hdr))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	out := gcm.Seal(nil, iv, z.Bytes(), []byte(protected))
	ct, tag := out[:len(out)-gcm.Overhead()], out[len(out)-gcm.Overhead():]
	return protected + ".." + b64.EncodeToString(iv) + "." + b64.EncodeToString(ct) + "." + b64.EncodeToString(tag), nil
}
