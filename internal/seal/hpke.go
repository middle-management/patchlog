package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// HPKE (RFC 9180) for the one suite of §E.2.3, DHKEM(X25519, HKDF-SHA256)
// 0x0020, HKDF-SHA256 0x0001 and AES-256-GCM 0x0002, single-shot (sequence
// number 0) with an empty aad, in the wire form enc ‖ ct.
//
// Base mode is crypto/hpke's (WrapKey). Auth mode (mode_auth, 0x02), in
// which keyring entries are wrapped (§E.3.2), isn't in the standard
// library, so the KEM's AuthEncap/AuthDecap (RFC 9180 §4.1), the key
// schedule (§5.1) and the single-shot AEAD (§5.2, §6.1) are written here.
// They do base mode too, so that a fixed ephemeral key can give test
// vectors (WrapKeyWithEphemeral). The tests check them against RFC 9180's
// test vectors (A.1.1 base, A.1.3 auth) and the CFRG's for this suite,
// and base mode against crypto/hpke in both directions.

const (
	hpkeModeBase = 0x00
	hpkeModeAuth = 0x02

	hpkeAEADAES128GCM = 0x0001 // RFC 9180 A.1's AEAD, for its test vectors only
	hpkeAEADAES256GCM = 0x0002

	hpkeNenc = 32 // X25519 enc, pkXm and DH output sizes
	hpkeNn   = 12 // AES-GCM nonce size
)

// kemSuiteID is "KEM" ‖ I2OSP(kem_id, 2) (RFC 9180 §4.1).
var kemSuiteID = []byte{'K', 'E', 'M', 0x00, 0x20}

// hpkeSuiteID is "HPKE" ‖ I2OSP(kem_id, 2) ‖ I2OSP(kdf_id, 2) ‖
// I2OSP(aead_id, 2) (RFC 9180 §5.1).
func hpkeSuiteID(aead uint16) []byte {
	return []byte{'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, byte(aead >> 8), byte(aead)}
}

// hpkeNk is the AEAD key size of aead.
func hpkeNk(aead uint16) int {
	if aead == hpkeAEADAES128GCM {
		return 16
	}
	return 32
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// labeledExtract is LabeledExtract(salt, label, ikm) = Extract(salt,
// "HPKE-v1" ‖ suite_id ‖ label ‖ ikm) (RFC 9180 §4).
func labeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, concat([]byte("HPKE-v1"), suiteID, []byte(label), ikm), salt)
	if err != nil {
		panic(err) // HMAC-SHA256 takes any input
	}
	return prk
}

// labeledExpand is LabeledExpand(prk, label, info, L) = Expand(prk,
// I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L) (RFC 9180 §4).
func labeledExpand(suiteID, prk []byte, label string, info []byte, l int) []byte {
	out, err := hkdf.Expand(sha256.New, prk, string(concat([]byte{byte(l >> 8), byte(l)}, []byte("HPKE-v1"), suiteID, []byte(label), info)), l)
	if err != nil {
		panic(err) // l is at most 32 here
	}
	return out
}

// extractAndExpand derives DHKEM's shared secret (RFC 9180 §4.1).
func extractAndExpand(dh, kemContext []byte) []byte {
	prk := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	return labeledExpand(kemSuiteID, prk, "shared_secret", kemContext, 32)
}

// hpkeEncap is DHKEM's Encap(pkR) with ephemeral key skE, or, with a
// sender key skS, AuthEncap(pkR, skS): dh = DH(skE, pkR) ‖ DH(skS, pkR) and
// kem_context = enc ‖ pkRm ‖ pkSm (RFC 9180 §4.1). It returns the shared
// secret and enc. ECDH fails on an all-zero output, as §7.1.4 requires.
func hpkeEncap(pkR *ecdh.PublicKey, skS, skE *ecdh.PrivateKey) (shared, enc []byte, err error) {
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc = skE.PublicKey().Bytes()
	kemContext := concat(enc, pkR.Bytes())
	if skS != nil {
		dhS, err := skS.ECDH(pkR)
		if err != nil {
			return nil, nil, err
		}
		dh = concat(dh, dhS)
		kemContext = concat(kemContext, skS.PublicKey().Bytes())
	}
	return extractAndExpand(dh, kemContext), enc, nil
}

// hpkeDecap is DHKEM's Decap(enc, skR), or, with the sender's public key
// pkS, AuthDecap(enc, skR, pkS) (RFC 9180 §4.1).
func hpkeDecap(enc []byte, skR *ecdh.PrivateKey, pkS *ecdh.PublicKey) ([]byte, error) {
	pkE, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, err
	}
	kemContext := concat(enc, skR.PublicKey().Bytes())
	if pkS != nil {
		dhS, err := skR.ECDH(pkS)
		if err != nil {
			return nil, err
		}
		dh = concat(dh, dhS)
		kemContext = concat(kemContext, pkS.Bytes())
	}
	return extractAndExpand(dh, kemContext), nil
}

// hpkeSchedule is the outcome of KeySchedule (RFC 9180 §5.1), with its
// intermediate values for the test vectors.
type hpkeSchedule struct {
	context, secret, key, baseNonce []byte
}

// hpkeKeySchedule is KeySchedule(mode, shared_secret, info, psk = "",
// psk_id = "") for aead (RFC 9180 §5.1): modes base and auth have no PSK.
func hpkeKeySchedule(aead uint16, mode byte, shared, info []byte) hpkeSchedule {
	sid := hpkeSuiteID(aead)
	pskIDHash := labeledExtract(sid, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(sid, nil, "info_hash", info)
	ks := hpkeSchedule{context: concat([]byte{mode}, pskIDHash, infoHash)}
	ks.secret = labeledExtract(sid, shared, "secret", nil)
	ks.key = labeledExpand(sid, ks.secret, "key", ks.context, hpkeNk(aead))
	ks.baseNonce = labeledExpand(sid, ks.secret, "base_nonce", ks.context, hpkeNn)
	return ks
}

func hpkeGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// hpkeSeal is the single-shot SealBase(pkR, info, aad, pt), or, with
// sender skS, SealAuth(pkR, info, aad, pt, skS) (RFC 9180 §6.1), under
// ephemeral key skE: enc ‖ ct, the first message's nonce being base_nonce.
func hpkeSeal(aead uint16, pkR *ecdh.PublicKey, skS, skE *ecdh.PrivateKey, info, aad, pt []byte) ([]byte, error) {
	mode := byte(hpkeModeBase)
	if skS != nil {
		mode = hpkeModeAuth
	}
	shared, enc, err := hpkeEncap(pkR, skS, skE)
	if err != nil {
		return nil, err
	}
	ks := hpkeKeySchedule(aead, mode, shared, info)
	gcm, err := hpkeGCM(ks.key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(enc, ks.baseNonce, pt, aad), nil
}

// hpkeOpen is the single-shot OpenBase(enc, skR, info, aad, ct), or, with
// the sender's public key pkS, OpenAuth(enc, skR, info, aad, ct, pkS)
// (RFC 9180 §6.1), of encct = enc ‖ ct.
func hpkeOpen(aead uint16, skR *ecdh.PrivateKey, pkS *ecdh.PublicKey, info, aad, encct []byte) ([]byte, error) {
	if len(encct) < hpkeNenc+16 {
		return nil, ErrDecrypt
	}
	mode := byte(hpkeModeBase)
	if pkS != nil {
		mode = hpkeModeAuth
	}
	shared, err := hpkeDecap(encct[:hpkeNenc], skR, pkS)
	if err != nil {
		return nil, ErrDecrypt
	}
	ks := hpkeKeySchedule(aead, mode, shared, info)
	gcm, err := hpkeGCM(ks.key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, ks.baseNonce, encct[hpkeNenc:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newEphemeral() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// wrapWith wraps key for recipient under ephemeral key eph (fresh when
// nil), in auth mode when sender isn't nil.
func wrapWith(eph, sender *ecdh.PrivateKey, recipient *ecdh.PublicKey, kid, resource string, key []byte) (WrappedKey, error) {
	if len(key) != KeySize {
		return WrappedKey{}, ErrKeySize
	}
	for _, k := range []*ecdh.PrivateKey{eph, sender} {
		if k != nil && k.Curve() != ecdh.X25519() {
			return WrappedKey{}, fmt.Errorf("seal: an X25519 key is needed")
		}
	}
	if recipient == nil || recipient.Curve() != ecdh.X25519() {
		return WrappedKey{}, fmt.Errorf("seal: an X25519 key is needed")
	}
	if eph == nil {
		var err error
		if eph, err = newEphemeral(); err != nil {
			return WrappedKey{}, err
		}
	}
	w, err := hpkeSeal(hpkeAEADAES256GCM, recipient, sender, eph, wrapInfo(kid, resource), nil, key)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{Kid: kid, Resource: resource, Wrapped: w}, nil
}

// WrapKeyAuth wraps key (K_e, or K_r when resource is non-empty) for
// recipient as WrapKey does, but in HPKE auth mode under sender's key
// (§E.2.3): it opens only with sender's public key, which so proves who
// wrapped it. Keyring entries are wrapped so (§E.3.2, KeyringV2).
func WrapKeyAuth(sender *ecdh.PrivateKey, recipient *ecdh.PublicKey, kid, resource string, key []byte) (WrappedKey, error) {
	if sender == nil {
		return WrappedKey{}, fmt.Errorf("seal: auth mode needs a sender key")
	}
	return wrapWith(nil, sender, recipient, kid, resource, key)
}

// UnwrapKeyAuth recovers the key in w, wrapped by WrapKeyAuth, with the
// recipient's private key and the public key of the sender it claims. It
// fails with ErrDecrypt for any other sender: anyone can wrap to a key, so
// a reader trusts a key only from a sender it trusts (§E.3.2).
func UnwrapKeyAuth(priv *ecdh.PrivateKey, sender *ecdh.PublicKey, w WrappedKey) ([]byte, error) {
	if sender == nil || sender.Curve() != ecdh.X25519() || priv.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("seal: an X25519 key is needed")
	}
	k, err := hpkeOpen(hpkeAEADAES256GCM, priv, sender, wrapInfo(w.Kid, w.Resource), nil, w.Wrapped)
	if err != nil || len(k) != KeySize {
		return nil, ErrDecrypt
	}
	return k, nil
}

// WrapKeyWithEphemeral is WrapKey with ephemeral as HPKE's ephemeral key
// in place of a fresh one, for test vectors (Addendum I). Never use it
// for keys: an ephemeral key used twice links the wraps.
func WrapKeyWithEphemeral(ephemeral *ecdh.PrivateKey, recipient *ecdh.PublicKey, kid, resource string, key []byte) (WrappedKey, error) {
	if ephemeral == nil {
		return WrappedKey{}, fmt.Errorf("seal: no ephemeral key")
	}
	return wrapWith(ephemeral, nil, recipient, kid, resource, key)
}

// WrapKeyAuthWithEphemeral is WrapKeyAuth with a fixed ephemeral key, for
// test vectors only, like WrapKeyWithEphemeral.
func WrapKeyAuthWithEphemeral(ephemeral, sender *ecdh.PrivateKey, recipient *ecdh.PublicKey, kid, resource string, key []byte) (WrappedKey, error) {
	if ephemeral == nil || sender == nil {
		return WrappedKey{}, fmt.Errorf("seal: no ephemeral or sender key")
	}
	return wrapWith(ephemeral, sender, recipient, kid, resource, key)
}
