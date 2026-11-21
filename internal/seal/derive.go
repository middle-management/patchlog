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

// Salts of the keys derived below each resource's K_r and each epoch's
// K_e (§E.2.1, v0.89).
const (
	RevKeySalt      = "patchlog-e2-rev"
	LogKeySalt      = "patchlog-e2-log"
	BlobKeySalt     = "patchlog-e2-blob"
	FilterViewSalt  = "patchlog-e2-view"
	viewWrapNamePfx = "view:"
)

// RevKey derives K_rev = HKDF-SHA256(ikm = K_r, salt = "patchlog-e2-rev",
// info = id), 32 bytes (§E.2.1): the key a revision's document is sealed
// under at E2. id is the revision's id in text form. It yields no sibling
// and no K_r.
func RevKey(resourceKey []byte, id string) ([]byte, error) {
	return deriveBelow(resourceKey, RevKeySalt, id)
}

// LogKey derives K_log = HKDF-SHA256(ikm = K_r, salt = "patchlog-e2-log",
// info = id), 32 bytes (§E.2.1): the key a revision's or tombstone's
// resource log entry is sealed under at E2, in a range or as an event.
func LogKey(resourceKey []byte, id string) ([]byte, error) {
	return deriveBelow(resourceKey, LogKeySalt, id)
}

// BlobKey derives K_blob = HKDF-SHA256(ikm = K_r, salt =
// "patchlog-e2-blob", info = bid), 32 bytes (§E.2.1): the key a blob is
// sealed under at E2 (§E.2.2 Sealed blobs). bid is the blob's id in text
// form.
func BlobKey(resourceKey []byte, bid string) ([]byte, error) {
	return deriveBelow(resourceKey, BlobKeySalt, bid)
}

// FilterViewKey derives K_view = HKDF-SHA256(ikm = K_e, salt =
// "patchlog-e2-view", info = ns ‖ 0x0A ‖ view), 32 bytes (§E.2.1): the
// only key of a partial reader at E2 (§E.2.3), under which its filtered
// answers and a view's keys for each revision are sealed (§E.2.2, §7.9).
// view is the §7.9 view id in text form. It yields no other key. It is not
// ViewKey, the "patchlog-view" key services seal derived views under
// (§E.2.6).
func FilterViewKey(epochKey []byte, ns, view string) ([]byte, error) {
	return deriveBelow(epochKey, FilterViewSalt, ns+"\n"+view)
}

func deriveBelow(ikm []byte, salt, info string) ([]byte, error) {
	if len(ikm) != KeySize {
		return nil, ErrKeySize
	}
	return hkdf.Key(sha256.New, ikm, []byte(salt), info, KeySize)
}
