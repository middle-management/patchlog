// Package grant implements capability grants (Addendum C): a Biscuit-like
// chain of Ed25519-signed blocks, key scopes, roles and verification.
//
// Token format (bearer) is base64url without padding of the canonical JSON
//
//	{ "blocks": [ { "b": {…}, "next": "<pub>", "sig": "<sig>" }, … ],
//	  "proof": "<seed of the key matching the last block's next>" }
//
// with
//
//	sig_0 = Ed25519(root key, "patchlog-grant-v1\n" ‖ canonical(b_0) ‖ "\n" ‖ next_0)
//	sig_i = Ed25519(sk(next_{i-1}), "patchlog-grant-v1\n" ‖ canonical(b_i) ‖ "\n" ‖ next_i ‖ "\n" ‖ sig_{i-1})
//
// The non-bearer stored form (§C.3) is the canonical JSON of {"blocks": […]}
// without "proof".
package grant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Verbs are the actions a grant may carry (§C.1). "*" is valid only in a
// key's can.
var Verbs = []string{"read", "create", "append", "restore", "delete", "purge", "config", "branch", "purge-ns", "export", "prune"}

var verbSet = func() map[string]bool {
	m := map[string]bool{}
	for _, v := range Verbs {
		m[v] = true
	}
	return m
}()

// IsVerb reports whether s is a grant verb (not "*").
func IsVerb(s string) bool { return verbSet[s] }

const sigDomain = "patchlog-grant-v1\n"

// maxBlocks bounds the chain length independently of the size limit.
const maxBlocks = 64

var b64 = base64.RawURLEncoding.Strict()

// ErrTooLarge reports a token over the grant size limit (§6.6).
var ErrTooLarge = errors.New("grant exceeds size limit")

// AuthError is an authentication (401) or authorisation (403) failure.
type AuthError struct {
	Status int
	Msg    string
}

func (e *AuthError) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Msg) }

func unauth(format string, a ...any) error {
	return &AuthError{Status: 401, Msg: fmt.Sprintf(format, a...)}
}

func forbid(format string, a ...any) error {
	return &AuthError{Status: 403, Msg: fmt.Sprintf(format, a...)}
}

// Block is one parsed block. Raw is the block object exactly as signed.
type Block struct {
	Kid, Sub, Via           string
	Groups, Roles, NS, Can  []string
	Attrs                   map[string]any
	Nbf, Exp                *time.Time
	At                      any
	Rules                   []any
	HasRoles, HasCan, HasNS bool
	Raw                     map[string]any
}

// Grant is a decoded chain of blocks.
type Grant struct {
	Blocks []Block

	sigs  [][]byte
	nexts []string           // b64url public keys
	proof ed25519.PrivateKey // nil in the stored form
}

// ID is the grant id of §C.3: trunc160(sha256(canonical(root block))).
func (g *Grant) ID() ids.ID { return ids.Of(jsonv.Canonical(g.Blocks[0].Raw)) }

// RevocationIDs returns the revocation id of every block, in order.
func (g *Grant) RevocationIDs() []string {
	out := make([]string, len(g.sigs))
	for i, s := range g.sigs {
		out[i] = ids.Of(s).String()
	}
	return out
}

func (g *Grant) envelopes() []any {
	bs := make([]any, len(g.Blocks))
	for i, b := range g.Blocks {
		bs[i] = map[string]any{"b": b.Raw, "next": g.nexts[i], "sig": b64.EncodeToString(g.sigs[i])}
	}
	return bs
}

// Stored is the non-bearer form: canonical JSON of {"blocks": […]}.
func (g *Grant) Stored() []byte {
	return jsonv.Canonical(map[string]any{"blocks": g.envelopes()})
}

// Encode returns the bearer token. It panics if the grant has no proof
// (a grant parsed from its stored form cannot be turned back into a bearer).
func (g *Grant) Encode() string {
	if g.proof == nil {
		panic("grant: Encode on a grant without proof")
	}
	v := map[string]any{"blocks": g.envelopes(), "proof": b64.EncodeToString(g.proof.Seed())}
	return b64.EncodeToString(jsonv.Canonical(v))
}

// HasProof reports whether the grant carries its proof (bearer form).
func (g *Grant) HasProof() bool { return g.proof != nil }

func signingInput(block map[string]any, next string, prevSig []byte) []byte {
	var b bytes.Buffer
	b.WriteString(sigDomain)
	b.Write(jsonv.Canonical(block))
	b.WriteByte('\n')
	b.WriteString(next)
	if prevSig != nil {
		b.WriteByte('\n')
		b.WriteString(b64.EncodeToString(prevSig))
	}
	return b.Bytes()
}

// normalizeInput converts a caller-built block to the value model and back
// through canonical JSON, so it is exactly what a verifier will parse.
func normalizeInput(m map[string]any) (v map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("grant: invalid block value: %v", r)
		}
	}()
	pv, err := jsonv.Parse(jsonv.Canonical(jsonv.FromGo(m)))
	if err != nil {
		return nil, err
	}
	obj, ok := pv.(map[string]any)
	if !ok {
		return nil, errors.New("grant: block must be an object")
	}
	return obj, nil
}

// GenerateKey returns a fresh Ed25519 key pair, the public key as b64url.
func GenerateKey() (pubB64 string, priv ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return b64.EncodeToString(pub), priv
}

// ParsePrivateKey parses a b64url-encoded 32-byte Ed25519 seed.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	seed, err := b64.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("grant: private key must be a b64url 32-byte ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// EncodePrivateKey is the inverse of ParsePrivateKey.
func EncodePrivateKey(k ed25519.PrivateKey) string { return b64.EncodeToString(k.Seed()) }

// Mint signs a root block with the key's private half. A fresh key pair is
// generated for the next link; its private half is the grant's proof.
func Mint(root map[string]any, signer ed25519.PrivateKey) (*Grant, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("grant: invalid signer key")
	}
	raw, err := normalizeInput(root)
	if err != nil {
		return nil, err
	}
	blk, err := parseBlock(raw, true)
	if err != nil {
		return nil, err
	}
	next, nextPriv := GenerateKey()
	sig := ed25519.Sign(signer, signingInput(raw, next, nil))
	return &Grant{Blocks: []Block{blk}, sigs: [][]byte{sig}, nexts: []string{next}, proof: nextPriv}, nil
}

// Narrow appends a narrowing block and returns the new grant. The receiver
// is unchanged. It needs the proof.
func (g *Grant) Narrow(block map[string]any) (*Grant, error) {
	if g.proof == nil {
		return nil, errors.New("grant: cannot narrow a grant without proof")
	}
	if len(g.Blocks) >= maxBlocks {
		return nil, errors.New("grant: too many blocks")
	}
	raw, err := normalizeInput(block)
	if err != nil {
		return nil, err
	}
	blk, err := parseBlock(raw, false)
	if err != nil {
		return nil, err
	}
	next, nextPriv := GenerateKey()
	sig := ed25519.Sign(g.proof, signingInput(raw, next, g.sigs[len(g.sigs)-1]))
	n := &Grant{
		Blocks: append(append([]Block(nil), g.Blocks...), blk),
		sigs:   append(append([][]byte(nil), g.sigs...), sig),
		nexts:  append(append([]string(nil), g.nexts...), next),
		proof:  nextPriv,
	}
	return n, nil
}

// Decode parses a bearer token and checks its structure, every signature in
// the chain except the root's (which needs the namespace keys, see Verify)
// and the proof. maxSize (bytes of the token text) is ignored when <= 0.
// Errors are ErrTooLarge or *AuthError with status 401.
func Decode(token string, maxSize int) (*Grant, error) {
	if maxSize > 0 && len(token) > maxSize {
		return nil, ErrTooLarge
	}
	data, err := b64.DecodeString(token)
	if err != nil {
		return nil, unauth("grant is not base64url")
	}
	return decode(data, true)
}

// ParseStored parses the non-bearer stored form and checks structure and
// the chain signatures (not the root signature). The result has no proof.
func ParseStored(data []byte) (*Grant, error) { return decode(data, false) }

func decode(data []byte, bearer bool) (*Grant, error) {
	v, err := jsonv.Parse(data)
	if err != nil {
		return nil, unauth("grant is not valid JSON")
	}
	top, ok := v.(map[string]any)
	if !ok {
		return nil, unauth("grant must be an object")
	}
	for k := range top {
		if k != "blocks" && !(bearer && k == "proof") {
			return nil, unauth("unknown grant member %q", k)
		}
	}
	arr, ok := top["blocks"].([]any)
	if !ok || len(arr) == 0 {
		return nil, unauth("grant blocks missing")
	}
	if len(arr) > maxBlocks {
		return nil, unauth("too many blocks")
	}
	g := &Grant{}
	for i, e := range arr {
		env, ok := e.(map[string]any)
		if !ok {
			return nil, unauth("block %d must be an object", i)
		}
		for k := range env {
			if k != "b" && k != "next" && k != "sig" {
				return nil, unauth("unknown member %q in block %d", k, i)
			}
		}
		raw, ok := env["b"].(map[string]any)
		if !ok {
			return nil, unauth("block %d: b must be an object", i)
		}
		next, ok := env["next"].(string)
		if !ok {
			return nil, unauth("block %d: next missing", i)
		}
		if pk, err := b64.DecodeString(next); err != nil || len(pk) != ed25519.PublicKeySize {
			return nil, unauth("block %d: invalid next key", i)
		}
		sigText, ok := env["sig"].(string)
		if !ok {
			return nil, unauth("block %d: sig missing", i)
		}
		sig, err := b64.DecodeString(sigText)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, unauth("block %d: invalid signature", i)
		}
		blk, err := parseBlock(raw, i == 0)
		if err != nil {
			return nil, unauth("block %d: %v", i, err)
		}
		if i > 0 {
			pk, _ := b64.DecodeString(g.nexts[i-1])
			if !ed25519.Verify(pk, signingInput(raw, next, g.sigs[i-1]), sig) {
				return nil, unauth("block %d: bad signature", i)
			}
		}
		g.Blocks = append(g.Blocks, blk)
		g.sigs = append(g.sigs, sig)
		g.nexts = append(g.nexts, next)
	}
	if bearer {
		ps, ok := top["proof"].(string)
		if !ok {
			return nil, unauth("grant proof missing")
		}
		seed, err := b64.DecodeString(ps)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, unauth("invalid grant proof")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		want, _ := b64.DecodeString(g.nexts[len(g.nexts)-1])
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), want) {
			return nil, unauth("grant proof does not match")
		}
		g.proof = priv
	}
	return g, nil
}

// verifyRoot checks the root signature against pub.
func (g *Grant) verifyRoot(pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, signingInput(g.Blocks[0].Raw, g.nexts[0], nil), g.sigs[0])
}

var rootFields = map[string]bool{"kid": true, "sub": true, "groups": true, "roles": true, "attrs": true, "ns": true, "can": true, "nbf": true, "exp": true, "at": true, "rules": true}
var narrowFields = map[string]bool{"via": true, "ns": true, "can": true, "roles": true, "nbf": true, "exp": true, "rules": true}

func parseBlock(raw map[string]any, root bool) (Block, error) {
	b := Block{Raw: raw}
	allowed := narrowFields
	if root {
		allowed = rootFields
	}
	for k := range raw {
		if !allowed[k] {
			if !root && rootFields[k] {
				return b, fmt.Errorf("a narrowing block must not contain %q", k)
			}
			return b, fmt.Errorf("unknown block field %q", k)
		}
	}
	var err error
	str := func(k string, required bool) (string, error) {
		v, ok := raw[k]
		if !ok {
			if required {
				return "", fmt.Errorf("%s is required", k)
			}
			return "", nil
		}
		s, ok := v.(string)
		if !ok || s == "" {
			return "", fmt.Errorf("%s must be a non-empty string", k)
		}
		return s, nil
	}
	if root {
		if b.Kid, err = str("kid", true); err != nil {
			return b, err
		}
		if b.Sub, err = str("sub", true); err != nil {
			return b, err
		}
		if b.Groups, _, err = strList(raw, "groups"); err != nil {
			return b, err
		}
		if b.Groups == nil {
			b.Groups = []string{}
		}
		b.Attrs = map[string]any{}
		if v, ok := raw["attrs"]; ok {
			m, ok := v.(map[string]any)
			if !ok {
				return b, errors.New("attrs must be an object")
			}
			b.Attrs = m
		}
		if v, ok := raw["at"]; ok {
			if err := checkAt(v); err != nil {
				return b, err
			}
			b.At = v
		}
	} else {
		if b.Via, err = str("via", false); err != nil {
			return b, err
		}
	}
	if b.Roles, b.HasRoles, err = strList(raw, "roles"); err != nil {
		return b, err
	}
	if b.NS, b.HasNS, err = strList(raw, "ns"); err != nil {
		return b, err
	}
	if root && !b.HasNS {
		return b, errors.New("ns is required")
	}
	if b.Can, b.HasCan, err = strList(raw, "can"); err != nil {
		return b, err
	}
	for _, c := range b.Can {
		if !verbSet[c] {
			return b, fmt.Errorf("unknown verb %q", c)
		}
	}
	if root && !b.HasCan && !b.HasRoles {
		return b, errors.New("a root block needs can or roles")
	}
	if b.Nbf, err = timeField(raw, "nbf"); err != nil {
		return b, err
	}
	if b.Exp, err = timeField(raw, "exp"); err != nil {
		return b, err
	}
	if root && b.Exp == nil {
		return b, errors.New("exp is required")
	}
	if b.Nbf != nil && b.Exp != nil && !b.Nbf.Before(*b.Exp) {
		return b, errors.New("nbf must be before exp")
	}
	if v, ok := raw["rules"]; ok {
		r, ok := v.([]any)
		if !ok {
			return b, errors.New("rules must be an array")
		}
		b.Rules = r
	}
	return b, nil
}

func strList(raw map[string]any, k string) ([]string, bool, error) {
	v, ok := raw[k]
	if !ok {
		return nil, false, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false, fmt.Errorf("%s must be an array of strings", k)
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok || s == "" {
			return nil, false, fmt.Errorf("%s must be an array of non-empty strings", k)
		}
		out = append(out, s)
	}
	return out, true, nil
}

func timeField(raw map[string]any, k string) (*time.Time, error) {
	v, ok := raw[k]
	if !ok {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be an RFC 3339 time", k)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC 3339 time", k)
	}
	return &t, nil
}

func checkAt(v any) error {
	switch x := v.(type) {
	case string:
		if _, err := ids.Parse(x); err != nil {
			return errors.New("at must be an ns_id")
		}
		return nil
	case map[string]any:
		if len(x) != 2 {
			return errors.New(`at must be an ns_id or {"ns","id"}`)
		}
		ns, ok1 := x["ns"].(string)
		id, ok2 := x["id"].(string)
		if !ok1 || !ok2 || ns == "" {
			return errors.New(`at must be an ns_id or {"ns","id"}`)
		}
		if _, err := ids.Parse(id); err != nil {
			return errors.New("at.id must be an ns_id")
		}
		return nil
	}
	return errors.New(`at must be an ns_id or {"ns","id"}`)
}
