package seal

import (
	"crypto/ecdh"
	"fmt"
	"sort"
	"strconv"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Keyring is the E3 `keyring` resource document (§E.3.2) that a
// key-holding admin client writes into an e2e namespace. The server only
// relays it. Its JSON form is:
//
//	{
//	  "keyring": 1,                         // format version
//	  "suite": "hpke-base-0x0020-0x0001-0x0002",
//	  "ns": "matches",
//	  "current": 4,                         // newest epoch in the keyring
//	  "recipients": { "<rid>": { "kty": "OKP", "crv": "X25519", "x": "…" }, … },
//	  "epochs": { "3": { "<rid>": "<base64url(enc ‖ ct)>", … }, "4": { … } }
//	}
//
// rid is RecipientID (text(trunc160(sha256(canonical(jwk))))). Each epoch
// maps recipients to K_e wrapped with HPKE under context kid = "{ns}#{e}"
// (WrapKey with no resource). `recipients` lists every key referenced by
// some epoch. Old epochs are kept: revoked readers already held them
// (§E.2.4), and current readers need them for old revisions.
type Keyring struct {
	NS         string
	Current    int
	Recipients map[string]*ecdh.PublicKey // rid → key
	Epochs     map[int]map[string][]byte  // epoch → rid → wrapped
}

// KeyringVersion is the "keyring" format member.
const KeyringVersion = 1

// BuildKeyring starts a keyring for ns at epoch with epochKey wrapped for
// each reader.
func BuildKeyring(ns string, epoch int, epochKey []byte, readers []*ecdh.PublicKey) (*Keyring, error) {
	kr := &Keyring{NS: ns, Current: epoch, Recipients: map[string]*ecdh.PublicKey{}, Epochs: map[int]map[string][]byte{}}
	for _, r := range readers {
		if err := kr.Add(r, epoch, epochKey); err != nil {
			return nil, err
		}
	}
	if kr.Epochs[epoch] == nil {
		kr.Epochs[epoch] = map[string][]byte{}
	}
	return kr, nil
}

// Add wraps epochKey of epoch for reader (adding a reader wraps the current
// epoch key for them; older epochs may be added the same way).
func (kr *Keyring) Add(reader *ecdh.PublicKey, epoch int, epochKey []byte) error {
	if epoch < 0 {
		return fmt.Errorf("seal: negative epoch")
	}
	w, err := WrapKey(reader, Kid(kr.NS, epoch), "", epochKey)
	if err != nil {
		return err
	}
	rid := RecipientID(reader)
	kr.Recipients[rid] = reader
	if kr.Epochs[epoch] == nil {
		kr.Epochs[epoch] = map[string][]byte{}
	}
	kr.Epochs[epoch][rid] = w.Wrapped
	if epoch > kr.Current {
		kr.Current = epoch
	}
	return nil
}

// Rotate starts epoch Current+1 with newKey wrapped for exactly readers
// (revocation: leave the revoked reader out). It returns the new epoch.
func (kr *Keyring) Rotate(newKey []byte, readers []*ecdh.PublicKey) (int, error) {
	e := kr.Current + 1
	kr.Epochs[e] = map[string][]byte{}
	for _, r := range readers {
		if err := kr.Add(r, e, newKey); err != nil {
			delete(kr.Epochs, e)
			return 0, err
		}
	}
	kr.Current = e
	return e, nil
}

// Readers returns the recipient ids holding epoch, sorted.
func (kr *Keyring) Readers(epoch int) []string {
	var out []string
	for rid := range kr.Epochs[epoch] {
		out = append(out, rid)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the wrapped key of epoch for the recipient whose public key
// is jwk (a model value, JSON text, or *ecdh.PublicKey).
func Lookup(kr *Keyring, jwk any, epoch int) (WrappedKey, error) {
	pub, ok := jwk.(*ecdh.PublicKey)
	if !ok {
		var err error
		if pub, err = ParseRecipientJWK(jwk); err != nil {
			return WrappedKey{}, err
		}
	}
	w, ok := kr.Epochs[epoch][RecipientID(pub)]
	if !ok {
		return WrappedKey{}, fmt.Errorf("seal: no key for recipient in epoch %d", epoch)
	}
	return WrappedKey{Kid: Kid(kr.NS, epoch), Wrapped: w}, nil
}

// EpochKey looks up and unwraps epoch's key with the recipient's private key.
func (kr *Keyring) EpochKey(priv *ecdh.PrivateKey, epoch int) ([]byte, error) {
	w, err := Lookup(kr, priv.PublicKey(), epoch)
	if err != nil {
		return nil, err
	}
	return UnwrapKey(priv, w)
}

// Value returns the keyring document as a jsonv model value.
func (kr *Keyring) Value() map[string]any {
	recips := map[string]any{}
	for rid, pub := range kr.Recipients {
		recips[rid] = RecipientJWK(pub)
	}
	epochs := map[string]any{}
	for e, m := range kr.Epochs {
		em := map[string]any{}
		for rid, w := range m {
			em[rid] = b64.EncodeToString(w)
		}
		epochs[strconv.Itoa(e)] = em
	}
	return map[string]any{
		"keyring": float64(KeyringVersion), "suite": Suite, "ns": kr.NS,
		"current": float64(kr.Current), "recipients": recips, "epochs": epochs,
	}
}

// MarshalJSON returns the canonical JSON of Value.
func (kr *Keyring) MarshalJSON() ([]byte, error) { return jsonv.Canonical(kr.Value()), nil }

// ParseKeyring parses a keyring document (model value or JSON text). It
// checks that every wrapped entry names a listed recipient whose id matches
// its key.
func ParseKeyring(v any) (*Keyring, error) {
	if b, ok := v.([]byte); ok {
		p, err := jsonv.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%w: keyring: %v", ErrFormat, err)
		}
		v = p
	}
	bad := func(what string) (*Keyring, error) { return nil, fmt.Errorf("%w: keyring %s", ErrFormat, what) }
	m, ok := v.(map[string]any)
	if !ok {
		return bad("not an object")
	}
	if m["keyring"] != float64(KeyringVersion) {
		return bad("version")
	}
	if s, ok := m["suite"]; ok && s != Suite {
		return bad("suite")
	}
	kr := &Keyring{Recipients: map[string]*ecdh.PublicKey{}, Epochs: map[int]map[string][]byte{}}
	if kr.NS, ok = m["ns"].(string); !ok || kr.NS == "" {
		return bad("ns")
	}
	cur, ok := m["current"].(float64)
	if !ok || cur < 0 || cur != float64(int(cur)) {
		return bad("current")
	}
	kr.Current = int(cur)
	recips, ok := m["recipients"].(map[string]any)
	if !ok {
		return bad("recipients")
	}
	for rid, j := range recips {
		pub, err := ParseRecipientJWK(j)
		if err != nil || RecipientID(pub) != rid {
			return bad("recipient " + rid)
		}
		kr.Recipients[rid] = pub
	}
	epochs, ok := m["epochs"].(map[string]any)
	if !ok {
		return bad("epochs")
	}
	for es, em := range epochs {
		e, err := strconv.Atoi(es)
		if err != nil || e < 0 || strconv.Itoa(e) != es || e > kr.Current {
			return bad("epoch " + es)
		}
		entries, ok := em.(map[string]any)
		if !ok {
			return bad("epoch " + es)
		}
		kr.Epochs[e] = map[string][]byte{}
		for rid, ws := range entries {
			s, _ := ws.(string)
			w, err := b64.DecodeString(s)
			if err != nil || len(w) == 0 || kr.Recipients[rid] == nil {
				return bad("entry " + es + "/" + rid)
			}
			kr.Epochs[e][rid] = w
		}
	}
	return kr, nil
}
