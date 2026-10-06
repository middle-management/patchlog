// Package grant implements capability grants (Addendum C): a chain of
// Ed25519-signed JSON blocks, key scopes, roles and verification.
//
// Grants are Biscuit v3 tokens (§C.8): the authority block carries the
// root block and each appended block one narrowing block, every block
// holding exactly one fact grant_block("<canonical JSON>"). Biscuit's
// Datalog is not evaluated; the JSON blocks are checked as §C.2 says. The
// wire format and signatures are in biscuit.go.
//
// The bearer form is Biscuit's URL-safe base64 (padded, accepted with or
// without padding and with or without the "biscuit:" prefix). The
// non-bearer stored form (§C.3) is the same protobuf message without its
// proof, so every block signature can be checked but it is not a token.
package grant

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
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

// maxBlocks bounds the chain length independently of the size limit.
const maxBlocks = 64

// b64 encodes keys and seeds (namespace documents, CLI).
var b64 = base64.RawURLEncoding.Strict()

// tokenPrefix is the optional text prefix of a Biscuit token.
const tokenPrefix = "biscuit:"

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
	// Enc is the root block's recipient key for wrapped key responses
	// (§E.2.3): { "kty": "OKP", "crv": "X25519", "x" }. Nil if absent.
	// Narrowing blocks cannot carry or change it.
	Enc *ecdh.PublicKey
	// Signers are the root block's signer keys (§C.3.1), nil if absent.
	// Narrowing blocks cannot carry them (401).
	Signers []sig.Signer
	Raw     map[string]any
}

// Grant is a decoded chain of blocks.
type Grant struct {
	Blocks []Block

	c       *container
	symbols []string           // the token's own symbol table, for appending
	proof   ed25519.PrivateKey // the next secret; nil when sealed or stored
}

// ID is the grant id of §C.3: trunc160(sha256(canonical(root block))).
func (g *Grant) ID() ids.ID { return ids.Of(jsonv.Canonical(g.Blocks[0].Raw)) }

// RevocationIDs returns the revocation id of every block, in order:
// text(trunc160(sha256(its Biscuit signature))) (§C.4, §C.8).
func (g *Grant) RevocationIDs() []string {
	out := make([]string, len(g.c.blocks))
	for i, sb := range g.c.blocks {
		out[i] = ids.Of(sb.sig).String()
	}
	return out
}

// Stored is the non-bearer form (§C.3): the Biscuit without its proof.
func (g *Grant) Stored() []byte {
	return (&container{blocks: g.c.blocks}).encode()
}

// SignedBlocks are the token's protobuf SignedBlock messages in order,
// authority first: the stored form's blocks, as GET /ns/{ns}/grants/{gid}
// serves them (§C.3.1).
func (g *Grant) SignedBlocks() [][]byte {
	out := make([][]byte, len(g.c.blocks))
	for i, sb := range g.c.blocks {
		out[i] = sb.encode()
	}
	return out
}

// Encode returns the bearer token, Biscuit URL-safe base64 without the
// "biscuit:" prefix. It panics on a grant parsed from its stored form,
// which cannot be turned back into a bearer.
func (g *Grant) Encode() string {
	if g.c.nextSecret == nil && g.c.finalSig == nil {
		panic("grant: Encode on a grant without proof")
	}
	return base64.URLEncoding.EncodeToString(g.c.encode())
}

// HasProof reports whether the grant can be narrowed: it carries the next
// secret (a bearer token that isn't sealed).
func (g *Grant) HasProof() bool { return g.proof != nil }

// Sealed reports whether the grant is a sealed token (§C.8).
func (g *Grant) Sealed() bool { return g.c.finalSig != nil }

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

// Mint signs a root block with the key's private half, as the authority
// block of a new Biscuit. A fresh key pair is generated for the next
// block; its private half is the grant's proof.
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
	data, symbols := encodeBlockData(string(jsonv.Canonical(raw)), nil)
	sb, next := newBlock(signer, data, nil)
	return &Grant{Blocks: []Block{blk}, symbols: symbols, proof: next,
		c: &container{blocks: []signedBlock{sb}, nextSecret: next.Seed()}}, nil
}

// Narrow appends a narrowing block and returns the new grant. The receiver
// is unchanged. It needs the proof, so a sealed or stored grant can't be
// narrowed.
func (g *Grant) Narrow(block map[string]any) (*Grant, error) {
	if g.proof == nil {
		if g.Sealed() {
			return nil, errors.New("grant: the grant is sealed")
		}
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
	return g.appendBlock(raw, blk), nil
}

// NarrowUnvalidated appends block like Narrow without checking it is a
// valid narrowing block, so tests can build the grants a verifier must
// refuse (a narrowing block with signers, §C.3.1). Anyone holding a grant's
// proof can do this; verification is what refuses it.
func (g *Grant) NarrowUnvalidated(block map[string]any) (*Grant, error) {
	if g.proof == nil {
		return nil, errors.New("grant: cannot narrow a grant without proof")
	}
	raw, err := normalizeInput(block)
	if err != nil {
		return nil, err
	}
	return g.appendBlock(raw, Block{Raw: raw}), nil
}

func (g *Grant) appendBlock(raw map[string]any, blk Block) *Grant {
	data, added := encodeBlockData(string(jsonv.Canonical(raw)), g.symbols)
	prev := g.c.blocks[len(g.c.blocks)-1]
	sb, next := newBlock(g.proof, data, prev.sig)
	return &Grant{
		Blocks:  append(append([]Block(nil), g.Blocks...), blk),
		symbols: append(append([]string(nil), g.symbols...), added...),
		proof:   next,
		c: &container{blocks: append(append([]signedBlock(nil), g.c.blocks...), sb),
			nextSecret: next.Seed()},
	}
}

// Seal returns the grant as a sealed token (§C.8): the proof becomes a
// final signature, so nobody can narrow it further. The receiver is
// unchanged.
func (g *Grant) Seal() (*Grant, error) {
	if g.proof == nil {
		return nil, errors.New("grant: only an unsealed bearer grant can be sealed")
	}
	last := g.c.blocks[len(g.c.blocks)-1]
	sig := ed25519.Sign(g.proof, last.sealPayload())
	return &Grant{Blocks: g.Blocks, symbols: g.symbols,
		c: &container{blocks: g.c.blocks, finalSig: sig}}, nil
}

// Decode parses a bearer token: Biscuit URL-safe base64, with or without
// padding and the "biscuit:" prefix. It checks the structure and the JSON
// blocks but no signature: Verify checks the chain, after the namespace
// check of §C.2 (whose 403 comes first). maxSize bounds the decoded bytes
// and is ignored when <= 0. Errors are ErrTooLarge or *AuthError with
// status 401.
func Decode(token string, maxSize int) (*Grant, error) {
	token = strings.TrimPrefix(token, tokenPrefix)
	if maxSize > 0 && len(token) > base64.URLEncoding.EncodedLen(maxSize) {
		return nil, ErrTooLarge
	}
	var data []byte
	var err error
	if strings.HasSuffix(token, "=") || len(token)%4 == 0 {
		data, err = base64.URLEncoding.Strict().DecodeString(token)
	} else {
		data, err = base64.RawURLEncoding.Strict().DecodeString(token)
	}
	if err != nil || len(data) == 0 {
		return nil, unauth("grant is not a Biscuit token in URL-safe base64")
	}
	if maxSize > 0 && len(data) > maxSize {
		return nil, ErrTooLarge
	}
	return decode(data, true)
}

// ParseStored parses the non-bearer stored form and checks its structure
// and the chain signatures (not the root signature, which needs the
// namespace keys). The result has no proof.
func ParseStored(data []byte) (*Grant, error) {
	g, err := decode(data, false)
	if err != nil {
		return nil, err
	}
	if err := g.c.verify(nil); err != nil {
		return nil, unauth("%v", err)
	}
	return g, nil
}

func decode(data []byte, bearer bool) (*Grant, error) {
	c, err := parseContainer(data, bearer)
	if err != nil {
		return nil, unauth("malformed grant: %v", err)
	}
	strs, symbols, err := c.blockStrings()
	if err != nil {
		return nil, unauth("malformed grant: %v", err)
	}
	g := &Grant{c: c, symbols: symbols}
	for i, s := range strs {
		v, err := jsonv.Parse([]byte(s))
		if err != nil {
			return nil, unauth("block %d is not I-JSON: %v", i, err)
		}
		if string(jsonv.Canonical(v)) != s {
			return nil, unauth("block %d is not in canonical form", i)
		}
		raw, ok := v.(map[string]any)
		if !ok {
			return nil, unauth("block %d must be an object", i)
		}
		blk, err := parseBlock(raw, i == 0)
		if err != nil {
			return nil, unauth("block %d: %v", i, err)
		}
		g.Blocks = append(g.Blocks, blk)
	}
	if c.nextSecret != nil {
		g.proof = ed25519.NewKeyFromSeed(c.nextSecret)
	}
	return g, nil
}

// NamesNS reports whether every block that carries ns names the namespace
// (§C.2, §7). "*" names every namespace; only operator grants may use it,
// which Verify checks once the key is known.
func (g *Grant) NamesNS(ns string) bool {
	for _, b := range g.Blocks {
		if b.HasNS && !contains(b.NS, ns) && !contains(b.NS, "*") {
			return false
		}
	}
	return true
}

// usesStar reports whether any block names "*" in ns.
func (g *Grant) usesStar() bool {
	for _, b := range g.Blocks {
		if contains(b.NS, "*") {
			return true
		}
	}
	return false
}

var rootFields = map[string]bool{"kid": true, "sub": true, "groups": true, "roles": true, "attrs": true, "ns": true, "can": true, "nbf": true, "exp": true, "at": true, "rules": true, "enc": true, "signers": true}
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
		if v, ok := raw["enc"]; ok {
			m, isObj := v.(map[string]any)
			pub, err := seal.ParseRecipientJWK(v)
			if !isObj || err != nil || len(m) != 3 {
				return b, errors.New(`enc must be { "kty": "OKP", "crv": "X25519", "x" }`)
			}
			b.Enc = pub
		}
		if v, ok := raw["signers"]; ok {
			ss, err := sig.ParseSigners(v)
			if err != nil {
				return b, err
			}
			b.Signers = ss
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
