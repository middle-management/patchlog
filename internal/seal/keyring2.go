package seal

import (
	"crypto/ecdh"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// KeyringV2 is the document of the E3 `keyring` resource (§E.3.2), which
// a key-holding admin client writes in plaintext and the server only
// relays:
//
//	{ "keys": [{ "kid": "{ns}#{e}", "to": "<thumbprint>", "from": "<thumbprint>", "wrapped": "<base64url(enc ‖ ct)>" }, …], "$nonce"?: "…" }
//
// Each entry is the epoch key K_e of kid wrapped for the recipient named
// by to, in HPKE auth mode under the admin key named by from (WrapKeyAuth,
// with the info of a K_e). to and from are RFC 7638 thumbprints
// (Thumbprint). Members are exactly these, with no two entries for one
// kid and to. A reader opens only an entry whose from it trusts to
// distribute keys, configured out of band: anyone can wrap to a
// thumbprint, the server included.
//
// The format before v0.63 is Keyring (ParseKeyring); it is kept to read
// stored keyrings and migrate them.
type KeyringV2 struct {
	Entries []KeyringEntry
	// Nonce is the document's `$nonce` (§C.7), "" when absent.
	Nonce string
}

// KeyringEntry is one entry of a KeyringV2.
type KeyringEntry struct {
	Kid     string // "{ns}#{e}"
	To      string // thumbprint of the recipient's X25519 key
	From    string // thumbprint of the admin's X25519 key that wrapped it
	Wrapped []byte // HPKE auth-mode enc ‖ ct of the 32-byte K_e
}

// wrappedLen is the size of an HPKE wrap of a 32-byte key: enc (32), the
// key's ciphertext (32) and the AES-GCM tag (16).
const wrappedLen = hpkeNenc + KeySize + 16

// ParseKeyringV2 parses a keyring document (a model value or JSON text) and
// checks its shape (§E.3.2): an object with `keys` and at most a string
// `$nonce` besides; entries that are objects of exactly kid, to, from and
// wrapped; a kid "{ns}#{e}", thumbprints of 43 base64url characters, a
// wrapped of base64url decoding to enc ‖ ct of a 32-byte key; and no two
// entries for one kid and to. Errors wrap ErrFormat. Whether kid names the
// keyring's own namespace and an epoch it has is the caller's to check.
func ParseKeyringV2(v any) (*KeyringV2, error) {
	if b, ok := v.([]byte); ok {
		p, err := jsonv.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%w: keyring: %v", ErrFormat, err)
		}
		v = p
	}
	bad := func(format string, a ...any) (*KeyringV2, error) {
		return nil, fmt.Errorf("%w: keyring: %s", ErrFormat, fmt.Sprintf(format, a...))
	}
	m, ok := v.(map[string]any)
	if !ok {
		return bad("not an object")
	}
	kr := &KeyringV2{}
	for k, x := range m {
		switch k {
		case "keys":
		case "$nonce":
			if kr.Nonce, ok = x.(string); !ok {
				return bad("$nonce is not a string")
			}
		default:
			return bad("member %q: a keyring has only keys and $nonce", k)
		}
	}
	keys, ok := m["keys"].([]any)
	if !ok {
		return bad("keys must be an array")
	}
	seen := map[[2]string]bool{}
	for i, x := range keys {
		e, ok := x.(map[string]any)
		if !ok || len(e) != 4 {
			return bad("entry %d: members must be exactly kid, to, from and wrapped", i)
		}
		var ent KeyringEntry
		var ws string
		for name, dst := range map[string]*string{"kid": &ent.Kid, "to": &ent.To, "from": &ent.From, "wrapped": &ws} {
			if *dst, ok = e[name].(string); !ok {
				return bad("entry %d: members must be exactly kid, to, from and wrapped, all strings", i)
			}
		}
		if _, _, err := ParseKid(ent.Kid); err != nil {
			return bad("entry %d: kid %q is not {ns}#{e}", i, ent.Kid)
		}
		if !ValidThumbprint(ent.To) || !ValidThumbprint(ent.From) {
			return bad("entry %d: to and from must be thumbprints, 43 base64url characters", i)
		}
		w, err := b64.DecodeString(ws)
		if err != nil || len(w) != wrappedLen {
			return bad("entry %d: wrapped must be base64url of a wrapped key's %d bytes", i, wrappedLen)
		}
		ent.Wrapped = w
		if seen[[2]string{ent.Kid, ent.To}] {
			return bad("entry %d: a second entry for kid %q and to %q", i, ent.Kid, ent.To)
		}
		seen[[2]string{ent.Kid, ent.To}] = true
		kr.Entries = append(kr.Entries, ent)
	}
	return kr, nil
}

// ValidThumbprint reports whether s has the form of a thumbprint
// (Thumbprint): base64url without padding of 32 bytes, 43 characters.
func ValidThumbprint(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := b64.DecodeString(s)
	return err == nil && len(b) == 32
}

// Value returns the keyring document as a jsonv model value, entries in
// their order.
func (kr *KeyringV2) Value() map[string]any {
	keys := make([]any, len(kr.Entries))
	for i, e := range kr.Entries {
		keys[i] = map[string]any{"kid": e.Kid, "to": e.To, "from": e.From, "wrapped": b64.EncodeToString(e.Wrapped)}
	}
	m := map[string]any{"keys": keys}
	if kr.Nonce != "" {
		m["$nonce"] = kr.Nonce
	}
	return m
}

// MarshalJSON returns the canonical JSON of Value.
func (kr *KeyringV2) MarshalJSON() ([]byte, error) { return jsonv.Canonical(kr.Value()), nil }

// Entry returns the entry for kid and the recipient thumbprint to.
func (kr *KeyringV2) Entry(kid, to string) (KeyringEntry, bool) {
	for _, e := range kr.Entries {
		if e.Kid == kid && e.To == to {
			return e, true
		}
	}
	return KeyringEntry{}, false
}

// Put adds e, replacing the entry for the same kid and to if there is one,
// so the keyring never holds two.
func (kr *KeyringV2) Put(e KeyringEntry) {
	for i := range kr.Entries {
		if kr.Entries[i].Kid == e.Kid && kr.Entries[i].To == e.To {
			kr.Entries[i] = e
			return
		}
	}
	kr.Entries = append(kr.Entries, e)
}

// Add wraps epochKey, the K_e of kid, for recipient in auth mode under the
// admin key sender, and puts the entry (§E.3.2). Adding a reader wraps the
// current epoch's key for them; a rotation adds the new kid's entries for
// the remaining readers.
func (kr *KeyringV2) Add(sender *ecdh.PrivateKey, recipient *ecdh.PublicKey, kid string, epochKey []byte) error {
	if _, _, err := ParseKid(kid); err != nil {
		return err
	}
	w, err := WrapKeyAuth(sender, recipient, kid, "", epochKey)
	if err != nil {
		return err
	}
	kr.Put(KeyringEntry{Kid: kid, To: Thumbprint(recipient), From: Thumbprint(sender.PublicKey()), Wrapped: w.Wrapped})
	return nil
}

// BuildKeyringV2 starts the keyring of ns with epochKey, the K_e of epoch,
// wrapped for each reader in auth mode under the admin key sender (Add).
// Readers repeated, or the same key as another, get one entry.
func BuildKeyringV2(sender *ecdh.PrivateKey, ns string, epoch int, epochKey []byte, readers []*ecdh.PublicKey) (*KeyringV2, error) {
	kr := &KeyringV2{}
	for _, r := range readers {
		if err := kr.Add(sender, r, Kid(ns, epoch), epochKey); err != nil {
			return nil, err
		}
	}
	return kr, nil
}

// Relayed is the entry as /keys relays it (§E.2.3): kid, from and wrapped.
func (e KeyringEntry) Relayed() WrappedKey {
	return WrappedKey{Kid: e.Kid, From: e.From, Wrapped: e.Wrapped}
}

// To returns the entries for the recipient thumbprint to, in order.
func (kr *KeyringV2) To(to string) []KeyringEntry {
	var out []KeyringEntry
	for _, e := range kr.Entries {
		if e.To == to {
			out = append(out, e)
		}
	}
	return out
}

// Recipients returns the recipient thumbprints of kid's entries, sorted.
func (kr *KeyringV2) Recipients(kid string) []string {
	var out []string
	for _, e := range kr.Entries {
		if e.Kid == kid {
			out = append(out, e.To)
		}
	}
	sort.Strings(out)
	return out
}

// Current returns the newest epoch of namespace ns that some entry holds
// a key of, 0 if none.
func (kr *KeyringV2) Current(ns string) int {
	eps := kr.Epochs(ns)
	if len(eps) == 0 {
		return 0
	}
	return eps[len(eps)-1]
}

// UnwrapRelayed opens a key /keys relays (§E.2.3) with priv: a keyring
// entry, which names its sender's thumbprint in From, in auth mode under
// the one of senders it names, failing unless senders holds it (anyone
// can wrap to a thumbprint, §E.3.2); a key without From in base mode, under
// the HPKE info of v0.63 or, for an entry of a keyring stored before
// (Keyring) relayed as stored, the info of that time. Every info binds the
// kid (and a K_r's name), so a key can't be presented as another epoch's.
func UnwrapRelayed(priv *ecdh.PrivateKey, w WrappedKey, senders []*ecdh.PublicKey) ([]byte, error) {
	if w.From == "" {
		k, err := UnwrapKey(priv, w)
		if err != nil {
			k, err = UnwrapKeyLegacy(priv, w)
		}
		return k, err
	}
	for _, s := range senders {
		if s != nil && Thumbprint(s) == w.From {
			return UnwrapKeyAuth(priv, s, w)
		}
	}
	return nil, fmt.Errorf("seal: the key of %s is from %s, which isn't a known sender", w.Kid, w.From)
}

// Open unwraps the entry's key with the recipient's private key and the
// public key of the sender its from names. It fails unless to and from
// are the thumbprints of those keys, and with ErrDecrypt unless sender
// wrapped it.
func (e KeyringEntry) Open(priv *ecdh.PrivateKey, sender *ecdh.PublicKey) ([]byte, error) {
	if Thumbprint(priv.PublicKey()) != e.To {
		return nil, fmt.Errorf("seal: keyring entry for %s is not to this key", e.Kid)
	}
	if Thumbprint(sender) != e.From {
		return nil, fmt.Errorf("seal: keyring entry for %s is not from this sender", e.Kid)
	}
	return UnwrapKeyAuth(priv, sender, WrappedKey{Kid: e.Kid, Wrapped: e.Wrapped})
}

// EpochKey returns the K_e of kid that the keyring holds for priv, from one
// of the trusted senders: the entry's from must be one of theirs.
func (kr *KeyringV2) EpochKey(priv *ecdh.PrivateKey, kid string, trusted []*ecdh.PublicKey) ([]byte, error) {
	e, ok := kr.Entry(kid, Thumbprint(priv.PublicKey()))
	if !ok {
		return nil, fmt.Errorf("seal: the keyring has no key of %s for this recipient", kid)
	}
	for _, s := range trusted {
		if Thumbprint(s) == e.From {
			return e.Open(priv, s)
		}
	}
	return nil, fmt.Errorf("seal: the key of %s is from %s, which isn't trusted", kid, e.From)
}

// Epochs returns the epochs of namespace ns that some entry holds a key
// of, ascending.
func (kr *KeyringV2) Epochs(ns string) []int {
	seen := map[int]bool{}
	var out []int
	for _, e := range kr.Entries {
		if kns, ep, err := ParseKid(e.Kid); err == nil && kns == ns && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	sort.Ints(out)
	return out
}
