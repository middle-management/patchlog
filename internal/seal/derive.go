// Key schedule, continued: namespace keys K_n = HKDF-SHA256(K_e,
// "patchlog-e2", ns ‖ 0x0A), which seal namespace documents, log ranges,
// events and grants, so that K_e itself seals nothing (§E.2.1); and view
// keys HKDF-SHA256(K_n or K_r, "patchlog-view", view), under which services
// seal derived views (§E.2.6).
package seal

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// ViewKeySalt is the HKDF salt of view keys (§E.2.6).
const ViewKeySalt = "patchlog-view"

// NamespaceKey derives K_n = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2",
// info = ns ‖ 0x0A), 32 bytes (§E.2.1). Its info is no K_r's, as a
// resource name is never empty (§3.6).
func NamespaceKey(epochKey []byte, ns string) ([]byte, error) {
	if len(epochKey) != KeySize {
		return nil, ErrKeySize
	}
	return hkdf.Key(sha256.New, epochKey, []byte(ResourceKeySalt), ns+"\n", KeySize)
}

// ViewKey derives the key a view is sealed under from the K_n or K_r the
// view would otherwise be sealed under: HKDF-SHA256(ikm = key, salt =
// "patchlog-view", info = view), 32 bytes (§E.2.6). view is the request
// target exactly as the service's redirect gave it: path and query,
// percent-encoded, without scheme or host.
func ViewKey(key []byte, view string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	return hkdf.Key(sha256.New, key, []byte(ViewKeySalt), view, KeySize)
}
