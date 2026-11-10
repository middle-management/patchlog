package server

import (
	"encoding/base64"
	"testing"
)

// E2E-10 (§E.2.2: a sealed revision's ETag is "{id}.{e}"): a row sealed
// with zip "DEF" before v0.65, which stored 'doc' and 'entry' rows keep
// and are served as stored, is still tagged with its stored sealing's
// epoch, never the bare "{id}" its plaintext copy had before the namespace
// was sealed, which a cached copy's If-None-Match would match (304). The
// zip refusal is Open's, not the header's.
func TestV081SealedTagOfZipRow(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	jwe := func(hdr string) string {
		return enc([]byte(hdr)) + ".." + enc(make([]byte, 12)) + "." + enc([]byte("ct")) + "." + enc(make([]byte, 16))
	}
	for name, hdr := range map[string]string{
		"plain": `{"alg":"dir","enc":"A256GCM","kid":"m#3","pl":{"id":"1a","kind":"doc","name":"r","ns":"m"}}`,
		"zip":   `{"alg":"dir","enc":"A256GCM","kid":"m#3","pl":{"id":"1a","kind":"doc","name":"r","ns":"m"},"zip":"DEF"}`,
	} {
		if got := sealedTag("1a", jwe(hdr)); got != `"1a.3"` {
			t.Errorf("%s row tagged %s, want \"1a.3\"", name, got)
		}
	}
}
