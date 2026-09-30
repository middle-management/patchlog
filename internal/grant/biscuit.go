package grant

// Biscuit v3 wire format (§C.8), implemented directly on the protobuf
// schema and signature scheme of the Biscuit specification
// (https://github.com/eclipse-biscuit/biscuit, SPECIFICATIONS.md and
// schema.proto). Only what grants need is encoded; everything else a
// Biscuit may carry is rejected when parsing:
//
//	Biscuit     { rootKeyId? = 1; authority = 2; blocks* = 3; proof = 4 }
//	SignedBlock { block = 1; nextKey = 2; signature = 3; version? = 5 }
//	              (externalSignature = 4, a third-party block, is refused)
//	PublicKey   { algorithm = 1 (Ed25519 = 0 only); key = 2 }
//	Proof       { nextSecret = 1 | finalSignature = 2 }
//	Block       { symbols* = 1; context? = 2 (empty only); version = 3;
//	              facts = 4 (exactly one) }
//	Fact        { predicate = 1 }
//	Predicate   { name = 1; terms = 2 (exactly one) }
//	Term        { string = 3 }
//
// Every block holds the single fact grant_block("<canonical JSON>").
// Signatures are Ed25519 throughout. Blocks are produced with signature
// payload version 1; versions 0 and 1 are both verified. Sealing uses the
// seal payload of the specification (block data ‖ algorithm ‖ next key ‖
// signature), which has no versioned form.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// Datalog block version written into each block (Biscuit 3.0 datalog: the
// minimum, enough for one fact with a string term), and the range accepted.
const (
	blockVersion    = 3
	minBlockVersion = 3
	maxBlockVersion = 6
)

// sigVersion is the signature payload version of the blocks we produce.
const sigVersion = 1

// algEd25519 is PublicKey.Algorithm.Ed25519.
const algEd25519 = 0

const factName = "grant_block"

// defaultSymbols is Biscuit's default symbol table (indexes 0…27). Symbols
// a token defines start at 1024.
var defaultSymbols = []string{"read", "write", "resource", "operation", "right", "time", "role", "owner",
	"tenant", "namespace", "user", "team", "service", "admin", "email", "group", "member", "ip_address",
	"client", "client_ip", "domain", "path", "version", "cluster", "node", "hostname", "nonce", "query"}

const symbolOffset = 1024

// signedBlock is one SignedBlock of the container.
type signedBlock struct {
	data    []byte // serialized Block
	nextKey ed25519.PublicKey
	sig     []byte
	version uint32 // signature payload version, 0 or 1
}

// container is a parsed Biscuit (or its stored form, without proof).
type container struct {
	blocks     []signedBlock
	nextSecret []byte // 32-byte Ed25519 seed; nil if sealed or stored
	finalSig   []byte // seal signature; nil unless sealed
}

// --- protobuf encoding --------------------------------------------------

func pbVarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func pbKey(b []byte, field, wt int) []byte { return pbVarint(b, uint64(field)<<3|uint64(wt)) }

func pbUint(b []byte, field int, v uint64) []byte { return pbVarint(pbKey(b, field, 0), v) }

func pbBytes(b []byte, field int, v []byte) []byte {
	b = pbVarint(pbKey(b, field, 2), uint64(len(v)))
	return append(b, v...)
}

func encodePublicKey(k ed25519.PublicKey) []byte {
	var b []byte
	b = pbUint(b, 1, algEd25519)
	return pbBytes(b, 2, k)
}

func (sb signedBlock) encode() []byte {
	var b []byte
	b = pbBytes(b, 1, sb.data)
	b = pbBytes(b, 2, encodePublicKey(sb.nextKey))
	b = pbBytes(b, 3, sb.sig)
	if sb.version > 0 {
		b = pbUint(b, 5, uint64(sb.version))
	}
	return b
}

// encode serializes the container. Without nextSecret and finalSig the
// result has no proof: the stored form of §C.3, which is not a token.
func (c *container) encode() []byte {
	var b []byte
	b = pbBytes(b, 2, c.blocks[0].encode())
	for _, sb := range c.blocks[1:] {
		b = pbBytes(b, 3, sb.encode())
	}
	switch {
	case c.nextSecret != nil:
		b = pbBytes(b, 4, pbBytes(nil, 1, c.nextSecret))
	case c.finalSig != nil:
		b = pbBytes(b, 4, pbBytes(nil, 2, c.finalSig))
	}
	return b
}

// encodeBlockData serializes the Block holding grant_block(json), given the
// symbols the token defined so far. It returns the data and the symbols the
// block adds.
func encodeBlockData(json string, symbols []string) ([]byte, []string) {
	var added []string
	index := func(s string) uint64 {
		for i, d := range defaultSymbols {
			if d == s {
				return uint64(i)
			}
		}
		for i, d := range symbols {
			if d == s {
				return uint64(symbolOffset + i)
			}
		}
		for i, d := range added {
			if d == s {
				return uint64(symbolOffset + len(symbols) + i)
			}
		}
		added = append(added, s)
		return uint64(symbolOffset + len(symbols) + len(added) - 1)
	}
	name := index(factName)
	str := index(json)
	term := pbUint(nil, 3, str)
	pred := pbBytes(pbUint(nil, 1, name), 2, term)
	fact := pbBytes(nil, 1, pred)
	var b []byte
	for _, s := range added {
		b = pbBytes(b, 1, []byte(s))
	}
	b = pbUint(b, 3, blockVersion)
	b = pbBytes(b, 4, fact)
	return b, added
}

// --- protobuf decoding --------------------------------------------------

type pbField struct {
	num int
	wt  int
	v   uint64 // varint value
	b   []byte // length-delimited value
}

var errPB = errors.New("malformed protobuf")

// pbParse splits a message into its fields. Only varint and
// length-delimited fields occur in the messages grants use.
func pbParse(data []byte) ([]pbField, error) {
	var out []pbField
	for len(data) > 0 {
		k, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, errPB
		}
		data = data[n:]
		f := pbField{num: int(k >> 3), wt: int(k & 7)}
		if f.num == 0 || k>>3 > 1<<29 {
			return nil, errPB
		}
		switch f.wt {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, errPB
			}
			f.v, data = v, data[n:]
		case 2:
			l, n := binary.Uvarint(data)
			if n <= 0 || l > uint64(len(data)-n) {
				return nil, errPB
			}
			f.b, data = data[n:n+int(l)], data[n+int(l):]
		default:
			return nil, fmt.Errorf("unexpected protobuf wire type %d", f.wt)
		}
		out = append(out, f)
	}
	return out, nil
}

// pbSchema describes the fields a message may have: wire type and whether
// it repeats. Unknown fields and repeated singular fields are rejected.
type pbSchema map[int]struct {
	wt       int
	repeated bool
}

func (s pbSchema) parse(msg string, data []byte) (map[int][]pbField, error) {
	fs, err := pbParse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", msg, err)
	}
	out := map[int][]pbField{}
	for _, f := range fs {
		d, ok := s[f.num]
		if !ok {
			return nil, fmt.Errorf("%s: unexpected field %d", msg, f.num)
		}
		if f.wt != d.wt {
			return nil, fmt.Errorf("%s: field %d has the wrong wire type", msg, f.num)
		}
		if !d.repeated && len(out[f.num]) > 0 {
			return nil, fmt.Errorf("%s: field %d repeated", msg, f.num)
		}
		out[f.num] = append(out[f.num], f)
	}
	return out, nil
}

var (
	schemaBiscuit     = pbSchema{1: {0, false}, 2: {2, false}, 3: {2, true}, 4: {2, false}}
	schemaSignedBlock = pbSchema{1: {2, false}, 2: {2, false}, 3: {2, false}, 4: {2, false}, 5: {0, false}}
	schemaPublicKey   = pbSchema{1: {0, false}, 2: {2, false}}
	schemaProof       = pbSchema{1: {2, false}, 2: {2, false}}
	// Block: symbols, context, version, facts, rules, checks, scope,
	// publicKeys. All are known so the error can say what is not allowed.
	schemaBlock     = pbSchema{1: {2, true}, 2: {2, false}, 3: {0, false}, 4: {2, true}, 5: {2, true}, 6: {2, true}, 7: {2, true}, 8: {2, true}}
	schemaFact      = pbSchema{1: {2, false}}
	schemaPredicate = pbSchema{1: {0, false}, 2: {2, true}}
)

// parseContainer parses a Biscuit. With bearer, the proof is required;
// otherwise (the stored form) it must be absent. No signature is checked.
func parseContainer(data []byte, bearer bool) (*container, error) {
	top, err := schemaBiscuit.parse("Biscuit", data)
	if err != nil {
		return nil, err
	}
	// rootKeyId (1) is ignored: the key is named by kid in the root block.
	if len(top[2]) == 0 {
		return nil, errors.New("no authority block")
	}
	if len(top[3])+1 > maxBlocks {
		return nil, errors.New("too many blocks")
	}
	c := &container{}
	for _, f := range append(top[2], top[3]...) {
		sb, err := parseSignedBlock(f.b)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", len(c.blocks), err)
		}
		c.blocks = append(c.blocks, sb)
	}
	if !bearer {
		if len(top[4]) > 0 {
			return nil, errors.New("the stored form has no proof")
		}
		return c, nil
	}
	if len(top[4]) == 0 {
		return nil, errors.New("no proof")
	}
	pf, err := schemaProof.parse("Proof", top[4][0].b)
	if err != nil {
		return nil, err
	}
	switch {
	case len(pf[1]) == 1 && len(pf[2]) == 0:
		if len(pf[1][0].b) != ed25519.SeedSize {
			return nil, errors.New("invalid next secret")
		}
		c.nextSecret = pf[1][0].b
	case len(pf[2]) == 1 && len(pf[1]) == 0:
		if len(pf[2][0].b) != ed25519.SignatureSize {
			return nil, errors.New("invalid final signature")
		}
		c.finalSig = pf[2][0].b
	default:
		return nil, errors.New("the proof needs a next secret or a final signature")
	}
	return c, nil
}

func parseSignedBlock(data []byte) (signedBlock, error) {
	var sb signedBlock
	m, err := schemaSignedBlock.parse("SignedBlock", data)
	if err != nil {
		return sb, err
	}
	if len(m[4]) > 0 {
		return sb, errors.New("third-party blocks are not allowed")
	}
	if len(m[1]) == 0 || len(m[2]) == 0 || len(m[3]) == 0 {
		return sb, errors.New("incomplete signed block")
	}
	sb.data = m[1][0].b
	if len(m[5]) > 0 {
		if m[5][0].v > 1 {
			return sb, fmt.Errorf("unsupported signature version %d", m[5][0].v)
		}
		sb.version = uint32(m[5][0].v)
	}
	pk, err := schemaPublicKey.parse("PublicKey", m[2][0].b)
	if err != nil {
		return sb, err
	}
	if len(pk[1]) == 0 || len(pk[2]) == 0 {
		return sb, errors.New("incomplete public key")
	}
	if pk[1][0].v != algEd25519 {
		return sb, errors.New("only Ed25519 keys are allowed")
	}
	if len(pk[2][0].b) != ed25519.PublicKeySize {
		return sb, errors.New("invalid Ed25519 public key")
	}
	sb.nextKey = ed25519.PublicKey(pk[2][0].b)
	sb.sig = m[3][0].b
	if len(sb.sig) != ed25519.SignatureSize {
		return sb, errors.New("invalid Ed25519 signature")
	}
	return sb, nil
}

// blockStrings extracts the grant_block string of every block, applying
// the symbol table rules of the specification. It returns the strings and
// the token's own symbols (for appending).
func (c *container) blockStrings() ([]string, []string, error) {
	var symbols []string
	out := make([]string, len(c.blocks))
	for i, sb := range c.blocks {
		s, added, err := parseBlockData(sb.data, symbols)
		if err != nil {
			return nil, nil, fmt.Errorf("block %d: %w", i, err)
		}
		symbols = append(symbols, added...)
		out[i] = s
	}
	return out, symbols, nil
}

func parseBlockData(data []byte, symbols []string) (string, []string, error) {
	m, err := schemaBlock.parse("Block", data)
	if err != nil {
		return "", nil, err
	}
	switch {
	case len(m[2]) > 0 && len(m[2][0].b) > 0:
		// biscuit-go writes an empty context into every block.
		return "", nil, errors.New("a block must not have a context")
	case len(m[5]) > 0:
		return "", nil, errors.New("a block must not have rules")
	case len(m[6]) > 0:
		return "", nil, errors.New("a block must not have checks")
	case len(m[7]) > 0:
		return "", nil, errors.New("a block must not have scopes")
	case len(m[8]) > 0:
		return "", nil, errors.New("a block must not have public keys")
	case len(m[4]) != 1:
		return "", nil, errors.New("a block must have exactly one fact")
	case len(m[3]) == 0 || m[3][0].v < minBlockVersion || m[3][0].v > maxBlockVersion:
		return "", nil, errors.New("unsupported block version")
	}
	var added []string
	for _, f := range m[1] {
		s := string(f.b)
		if contains(defaultSymbols, s) || contains(symbols, s) || contains(added, s) {
			return "", nil, errors.New("symbol defined twice")
		}
		added = append(added, s)
	}
	lookup := func(i uint64) (string, bool) {
		switch {
		case i < uint64(len(defaultSymbols)):
			return defaultSymbols[i], true
		case i >= symbolOffset && i-symbolOffset < uint64(len(symbols)+len(added)):
			j := int(i - symbolOffset)
			if j < len(symbols) {
				return symbols[j], true
			}
			return added[j-len(symbols)], true
		}
		return "", false
	}
	fact, err := schemaFact.parse("Fact", m[4][0].b)
	if err != nil {
		return "", nil, err
	}
	if len(fact[1]) == 0 {
		return "", nil, errors.New("fact without predicate")
	}
	pred, err := schemaPredicate.parse("Predicate", fact[1][0].b)
	if err != nil {
		return "", nil, err
	}
	if len(pred[1]) == 0 || len(pred[2]) != 1 {
		return "", nil, errors.New("the fact must be grant_block(<string>)")
	}
	if name, ok := lookup(pred[1][0].v); !ok || name != factName {
		return "", nil, errors.New("the fact must be grant_block(<string>)")
	}
	term, err := pbParse(pred[2][0].b)
	if err != nil || len(term) != 1 || term[0].num != 3 || term[0].wt != 0 {
		return "", nil, errors.New("the fact must be grant_block(<string>)")
	}
	s, ok := lookup(term[0].v)
	if !ok {
		return "", nil, errors.New("unknown symbol")
	}
	// Symbols the block defines but doesn't use would carry data outside
	// the one fact.
	for _, a := range added {
		if a != factName && a != s {
			return "", nil, errors.New("unused symbol")
		}
	}
	return s, added, nil
}

// --- signatures ---------------------------------------------------------

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// payload is the signed payload of block i (prevSig is nil for the
// authority block).
func (sb signedBlock) payload(prevSig []byte) []byte {
	var b bytes.Buffer
	if sb.version == 0 {
		b.Write(sb.data)
		b.Write(le32(algEd25519))
		b.Write(sb.nextKey)
		return b.Bytes()
	}
	b.WriteString("\x00BLOCK\x00\x00VERSION\x00")
	b.Write(le32(sb.version))
	b.WriteString("\x00PAYLOAD\x00")
	b.Write(sb.data)
	b.WriteString("\x00ALGORITHM\x00")
	b.Write(le32(algEd25519))
	b.WriteString("\x00NEXTKEY\x00")
	b.Write(sb.nextKey)
	if prevSig != nil {
		b.WriteString("\x00PREVSIG\x00")
		b.Write(prevSig)
	}
	return b.Bytes()
}

// sealPayload is what the final signature of a sealed token signs.
func (sb signedBlock) sealPayload() []byte {
	var b bytes.Buffer
	b.Write(sb.data)
	b.Write(le32(algEd25519))
	b.Write(sb.nextKey)
	b.Write(sb.sig)
	return b.Bytes()
}

// newBlock signs data with key, generating the next key pair.
func newBlock(key ed25519.PrivateKey, data, prevSig []byte) (signedBlock, ed25519.PrivateKey) {
	_, next := GenerateKey()
	sb := signedBlock{data: data, nextKey: next.Public().(ed25519.PublicKey), version: sigVersion}
	sb.sig = ed25519.Sign(key, sb.payload(prevSig))
	return sb, next
}

// verify checks every signature of the chain and the proof. root is the
// root public key; nil skips the authority block's signature (it needs
// the namespace keys). crypto/ed25519 verifies strictly per RFC 8032,
// rejecting S ≥ L.
func (c *container) verify(root ed25519.PublicKey) error {
	if root != nil {
		if len(root) != ed25519.PublicKeySize || !ed25519.Verify(root, c.blocks[0].payload(nil), c.blocks[0].sig) {
			return errors.New("bad root signature")
		}
	}
	for i := 1; i < len(c.blocks); i++ {
		prev := c.blocks[i-1]
		if !ed25519.Verify(prev.nextKey, c.blocks[i].payload(prev.sig), c.blocks[i].sig) {
			return fmt.Errorf("block %d: bad signature", i)
		}
	}
	last := c.blocks[len(c.blocks)-1]
	switch {
	case c.nextSecret != nil:
		pub := ed25519.NewKeyFromSeed(c.nextSecret).Public().(ed25519.PublicKey)
		if !bytes.Equal(pub, last.nextKey) {
			return errors.New("the proof does not match the last block")
		}
	case c.finalSig != nil:
		if !ed25519.Verify(last.nextKey, last.sealPayload(), c.finalSig) {
			return errors.New("bad final signature")
		}
	}
	return nil
}
