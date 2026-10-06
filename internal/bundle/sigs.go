package bundle

// Author signatures in bundles (§C.3.1, §G.4.1): checking the chain
//
//	revision signature → signers entry of the grant's root block →
//	the key that signed the root block (the grant line's key) →
//	the namespace log, or the operator key history
//
// offline as far as a bundle goes. The last link needs the source's
// namespace log or operator key history, which a bundle doesn't carry, so
// a chain that is complete up to the grant line's key is "attested": the
// exporter vouches for that key. With a KeyChecker that can read the source
// (SourceKeyChecker) the same chain is "verified".

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"
)

// SigStatus is the outcome of checking one revision's signature.
type SigStatus string

const (
	// SigVerified: the chain is complete and its last link, the key that
	// signed the grant's root block, was checked against the source's
	// namespace log or operator key history at the revision's position.
	SigVerified SigStatus = "verified"
	// SigAttested: the chain is complete up to the key the grant line
	// names, which only the exporter vouches for.
	SigAttested SigStatus = "attested"
	// SigFailed: a link is broken: the signature doesn't verify, or the
	// grant line isn't a genuine grant under its key, or the key wasn't in
	// force at the revision's position.
	SigFailed SigStatus = "failed"
	// SigUnsigned: the revision carries no signature.
	SigUnsigned SigStatus = "unsigned"
	// SigUnverifiable: the chain can't be completed from the bundle: the
	// revision names no grant (it was written where the exporter couldn't
	// read grants, or before the source recorded them), or the grant's
	// signers don't list the signature's kid (a server stores such
	// signatures unverified, §C.3.1).
	SigUnverifiable SigStatus = "unverifiable"
)

// SigResult is the status of one revision (or tombstone) of a bundle.
type SigResult struct {
	NS       string    `json:"ns"`
	Resource string    `json:"resource"`
	ID       string    `json:"id"`
	Status   SigStatus `json:"status"`
	// Kid is the signature's kid, Grant the grant id and Sub the grant's
	// root sub, where known.
	Kid    string `json:"kid,omitempty"`
	Grant  string `json:"grant,omitempty"`
	Sub    string `json:"sub,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// SigReport summarises the signatures of a bundle with authors.
type SigReport struct {
	Counts map[SigStatus]int `json:"counts"`
	// Problems lists the failed and unverifiable revisions, in bundle
	// order.
	Problems []SigResult `json:"problems,omitempty"`
	// Grants is the number of grant lines; BadGrants lists those that
	// aren't genuine, as "ns/grant: reason".
	Grants    int      `json:"grants"`
	BadGrants []string `json:"badGrants,omitempty"`
}

// KeyVerdict is a KeyChecker's answer.
type KeyVerdict int

const (
	// KeyUnchecked: the checker can't say (the revision or the key's
	// source isn't readable), so the signature stays attested.
	KeyUnchecked KeyVerdict = iota
	// KeyInForce: the key was in force at the revision's position.
	KeyInForce
	// KeyNotInForce: it wasn't.
	KeyNotInForce
)

// KeyChecker checks the key a grant line names against the source's
// namespace log or operator key history, at the position of the revision
// rev (§C.3.1). reason explains a verdict other than KeyInForce.
type KeyChecker func(ctx context.Context, ns string, key KeyEntry, rev *Line) (v KeyVerdict, reason string)

// KeyFinder supplies the keys that could have signed the root block of a
// grant whose grant line leaves `key` out (§G.4.1): the keys named kid that
// were in force at the revision's position in ns's log or, for an operator
// key, at its created time. The verifier tries each against the root block.
type KeyFinder func(ctx context.Context, ns, kid string, rev *Line) []KeyEntry

// VerifyOptions configure VerifyWith.
type VerifyOptions struct {
	// Keys, if set, completes the chain at its last link (see
	// SourceKeyChecker); without it every complete chain is attested.
	Keys KeyChecker
	// Finder, if set, supplies the key of a grant line without one; the
	// chain is then complete only if a key it names verifies the root
	// block, and such a key counts as in force (SourceKeyChecker's finder).
	Finder KeyFinder
	// OnSignature, if set, is called with the status of every revision of
	// a bundle with authors, in bundle order.
	OnSignature func(SigResult)
}

// grantState is a grant line, checked.
type grantState struct {
	line    *GrantLine
	err     string // "" if the grant is genuine under its key
	signers []sig.Signer
	sub     string
	// gr is the parsed stored grant; it is set when the line carries no
	// key, so that a finder's key can be tried against its root block.
	gr *grant.Grant
	ns string // the grant line's namespace
}

// SigVerifier checks the signatures of a bundle's lines as they are read.
type SigVerifier struct {
	ctx    context.Context
	origin string
	opt    VerifyOptions
	grants map[string]*grantState
	rep    SigReport
}

// NewSigVerifier returns a verifier for the bundle with header h, whose
// origin the signatures bind. Feed it every line in order.
func NewSigVerifier(ctx context.Context, h *Header, opt VerifyOptions) *SigVerifier {
	return &SigVerifier{ctx: ctx, origin: h.Origin, opt: opt, grants: map[string]*grantState{},
		rep: SigReport{Counts: map[SigStatus]int{}}}
}

// Report is the report so far.
func (v *SigVerifier) Report() *SigReport { return &v.rep }

// Line takes the next line of the bundle: a grant line is checked and
// remembered, a history line's signature is checked through it.
func (v *SigVerifier) Line(l *Line) {
	switch {
	case l.IsGrant():
		gs := checkGrantLine(l)
		v.grants[l.GrantLine.ID] = gs
		v.rep.Grants++
		if gs.err != "" {
			v.rep.BadGrants = append(v.rep.BadGrants, l.NS+"/"+l.GrantLine.ID+": "+gs.err)
		}
	case l.IsBlob() || l.IsSnapshot():
	default:
		v.history(l)
	}
}

func (v *SigVerifier) done(r SigResult) {
	v.rep.Counts[r.Status]++
	if r.Status == SigFailed || r.Status == SigUnverifiable {
		v.rep.Problems = append(v.rep.Problems, r)
	}
	if v.opt.OnSignature != nil {
		v.opt.OnSignature(r)
	}
}

func (v *SigVerifier) history(l *Line) {
	r := SigResult{NS: l.NS, Resource: l.Resource, ID: l.ID, Grant: l.Grant}
	if l.Signature == "" {
		r.Status = SigUnsigned
		v.done(r)
		return
	}
	fail := func(status SigStatus, format string, args ...any) {
		r.Status, r.Reason = status, fmt.Sprintf(format, args...)
		v.done(r)
	}
	s, err := sig.Parse(l.Signature)
	if err != nil {
		fail(SigFailed, "%v", err)
		return
	}
	r.Kid = s.Kid
	if l.Grant == "" {
		fail(SigUnverifiable, "the revision names no grant, so its signer's key can't be found")
		return
	}
	gs := v.grants[l.Grant]
	if gs == nil {
		fail(SigUnverifiable, "no grant line for %s", l.Grant)
		return
	}
	r.Sub = gs.sub
	if gs.err != "" {
		fail(SigFailed, "grant %s: %s", l.Grant, gs.err)
		return
	}
	signer, ok := sig.Find(gs.signers, s.Kid)
	if !ok {
		fail(SigUnverifiable, "kid %q is not listed in the grant's signers: a server stores such a signature unverified (§C.3.1)", s.Kid)
		return
	}
	var parent *ids.ID
	if l.Parent != "" {
		id, err := ids.Parse(l.Parent)
		if err != nil {
			fail(SigFailed, "parent: %v", err)
			return
		}
		parent = &id
	}
	var body []byte // nil: a tombstone
	if l.Kind == "rev" {
		body = jsonv.Canonical(l.Patches)
	}
	origin, ns := l.Signing(v.origin)
	if !sig.Verify(signer, s, sig.Digest(origin, ns, l.Resource, parent, body)) {
		fail(SigFailed, "the signature doesn't verify for %s %s/%s at origin %s", ns, l.Resource, l.ID, origin)
		return
	}
	if gs.gr != nil {
		// The grant line has no key (§G.4.1): only a finder can complete
		// the chain, with a key that verifies the root block.
		if v.opt.Finder == nil {
			fail(SigUnverifiable, "the grant line for %s names no key, so the chain can't be completed from the bundle", l.Grant)
			return
		}
		kid := gs.gr.Blocks[0].Kid
		for _, k := range v.opt.Finder(v.ctx, ns, kid, l) {
			pub, err := base64.RawURLEncoding.Strict().DecodeString(k.Pub)
			if err != nil || len(pub) != ed25519.PublicKeySize || k.Kid != kid {
				continue
			}
			if verifyRootSignature(gs.gr, gs.ns, ed25519.PublicKey(pub)) == nil {
				r.Status = SigVerified
				v.done(r)
				return
			}
		}
		fail(SigUnverifiable, "the grant line for %s names no key, and no key named %q in the source's namespace log or operator key history verifies its root block", l.Grant, kid)
		return
	}
	// The chain is complete up to the grant line's key.
	r.Status = SigAttested
	if v.opt.Keys != nil {
		switch verdict, why := v.opt.Keys(v.ctx, ns, gs.line.Key, l); verdict {
		case KeyInForce:
			r.Status = SigVerified
		case KeyNotInForce:
			r.Status, r.Reason = SigFailed, why
		default:
			r.Reason = why
		}
	}
	v.done(r)
}

// storedContainer rebuilds the Biscuit container of a grant line's stored
// blocks, without proof: the authority block is field 2 of the container,
// the others field 3 (§C.8).
func storedContainer(stored []string) ([]byte, error) {
	var out []byte
	for i, s := range stored {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("stored[%d] is not base64url without padding", i)
		}
		field := byte(3)
		if i == 0 {
			field = 2
		}
		out = append(out, field<<3|2)
		out = binary.AppendUvarint(out, uint64(len(raw)))
		out = append(out, raw...)
	}
	return out, nil
}

// checkGrantLine checks a grant line as §C.3.1 has a verifier do: the
// authority block's signature under the line's key, its one grant_block
// equal to canonical(root), the id the text of trunc160(sha256) of that
// string, and the signers of the root block.
func checkGrantLine(l *Line) *grantState {
	g := l.GrantLine
	gs := &grantState{line: g, ns: l.NS}
	bad := func(format string, args ...any) *grantState {
		gs.err = fmt.Sprintf(format, args...)
		return gs
	}
	gr, err := parseStoredGrant(g.Stored)
	if err != nil {
		return bad("%v", err)
	}
	root := gr.Blocks[0]
	// ParseStored read the grant_block string and checked it is canonical,
	// so canonical(Raw) is that string byte for byte.
	if string(jsonv.Canonical(jsonv.FromGo(g.Root))) != string(jsonv.Canonical(root.Raw)) {
		return bad("root is not the stored grant_block")
	}
	if id := gr.ID().String(); id != g.ID {
		return bad("id is %s, not the grant_block's %s", g.ID, id)
	}
	if !g.HasKey() {
		// Everything but the authority block's signature, which needs a key.
		gs.gr = gr
		gs.sub = root.Sub
		if raw, has := g.Root["signers"]; has {
			if gs.signers, err = sig.ParseSigners(raw); err != nil {
				return bad("signers: %v", err)
			}
		}
		return gs
	}
	if root.Kid != g.Key.Kid {
		return bad("the root block names key %q, the line's key is %q", root.Kid, g.Key.Kid)
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(g.Key.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return bad("key.pub is not an Ed25519 key")
	}
	if err := verifyRootSignature(gr, l.NS, ed25519.PublicKey(pub)); err != nil {
		return bad("%v", err)
	}
	gs.sub = root.Sub
	if raw, has := g.Root["signers"]; has {
		if gs.signers, err = sig.ParseSigners(raw); err != nil {
			return bad("signers: %v", err)
		}
	}
	return gs
}

// parseStoredGrant decodes the stored blocks of a grant: the structure and
// the chain's signatures after the authority block, not the authority
// block's, which needs the key.
func parseStoredGrant(stored []string) (*grant.Grant, error) {
	data, err := storedContainer(stored)
	if err != nil {
		return nil, err
	}
	gr, err := grant.ParseStored(data)
	if err != nil {
		return nil, fmt.Errorf("stored form: %v", err)
	}
	return gr, nil
}

// verifyRootSignature checks the authority block's signature under pub,
// through the grant package's chain check. Its time window, scope and
// revocation rules say what the server decided when it let the write in
// (§C.3.1: verifiers don't re-judge them), so they are met here: the key is
// taken as unrestricted, and the clock is a time inside the grant's window.
func verifyRootSignature(gr *grant.Grant, ns string, pub ed25519.PublicKey) error {
	kid := gr.Blocks[0].Kid
	env := grant.Env{NS: ns, Now: windowTime(gr), Operator: true,
		Keys: []grant.Key{{Kid: kid, Alg: sig.Alg, Pub: pub, Can: []string{"*"}}}}
	_, err := grant.Verify(gr, env)
	return err
}

// windowTime is a time at which every block of gr is valid: the latest nbf,
// or just before the earliest exp when none has an nbf.
func windowTime(gr *grant.Grant) time.Time {
	var nbf, exp *time.Time
	for _, b := range gr.Blocks {
		if b.Nbf != nil && (nbf == nil || b.Nbf.After(*nbf)) {
			nbf = b.Nbf
		}
		if b.Exp != nil && (exp == nil || b.Exp.Before(*exp)) {
			exp = b.Exp
		}
	}
	switch {
	case nbf != nil:
		return *nbf
	case exp != nil:
		return exp.Add(-time.Second)
	}
	return time.Now()
}

// VerifyWith reads a whole bundle like Verify and, for a bundle with
// authors, checks every signature through its grant lines (§C.3.1). The
// outcome is in Summary.Signatures; a bundle whose signatures fail is still
// a valid bundle.
func VerifyWith(ctx context.Context, r io.Reader, opt VerifyOptions) (*Summary, error) {
	rd, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	var sv *SigVerifier
	if rd.Header().Authors {
		sv = NewSigVerifier(ctx, rd.Header(), opt)
	}
	n := 0
	for {
		l, err := rd.Next()
		if err == io.EOF {
			s := &Summary{Header: rd.Header(), Digest: rd.Digest(), Lines: n}
			if sv != nil {
				s.Signatures = sv.Report()
			}
			return s, nil
		}
		if err != nil {
			return nil, err
		}
		n++
		if sv != nil {
			sv.Line(l)
		}
	}
}

// SourceKeyChecker checks grant-line keys against the source deployment c
// reads: the revision's position in the source namespace's log, whose
// namespace document in force there must list the key; or, for an operator
// key, the deployment's JWK Set, whose entry must have been in force at the
// revision's created time (§C.3.1, §C.4). The namespace is the one the
// revision was written in (the line's written, else its ns), so a branch's
// read-through revision is placed in its base's log. It returns
// KeyUnchecked where the source can't tell: the revision isn't in that
// namespace's log, was written at another deployment, or the source can't
// be read.
func SourceKeyChecker(c *client.Client) KeyChecker {
	chk, _ := SourceKeys(c)
	return chk
}

// SourceKeys is SourceKeyChecker with the matching KeyFinder, for grant
// lines that leave `key` out (§G.4.1): the finder lists the keys named kid
// that the source's namespace document at the revision's position, or its
// operator key history at the revision's created time, has.
func SourceKeys(c *client.Client) (KeyChecker, KeyFinder) {
	sk := &sourceKeys{c: c, logs: map[string]*nsPositions{}, docs: map[string][]KeyEntry{}}
	return sk.check, sk.find
}

type nsPositions struct {
	err     error
	pos     map[string]string // revision id → the namespace log entry that wrote it
	configs []string          // the entries that changed the namespace document, genesis first
	index   map[string]int    // entry id → its place in the log, oldest first
	grants  map[string]string // grant id → the first entry that recorded it
}

type sourceKeys struct {
	c  *client.Client
	mu sync.Mutex

	logs map[string]*nsPositions
	docs map[string][]KeyEntry // "ns/entry" → the keys of the namespace document there

	jwks    []client.OperatorKey
	jwksErr error
	jwksOK  bool
}

func (sk *sourceKeys) positions(ctx context.Context, ns string) *nsPositions {
	if p, ok := sk.logs[ns]; ok {
		return p
	}
	p := &nsPositions{pos: map[string]string{}, index: map[string]int{}, grants: map[string]string{}}
	sk.logs[ns] = p
	h, err := sk.c.NSHead(ctx, ns)
	if err != nil {
		p.err = err
		return p
	}
	log, err := sk.c.NSLog(ctx, ns, h.ID, "")
	if err != nil {
		p.err = err
		return p
	}
	for i, e := range log {
		p.index[e.ID] = i
		if e.Grant != nil && e.Grant.ID != "" {
			if _, seen := p.grants[e.Grant.ID]; !seen {
				p.grants[e.Grant.ID] = e.ID
			}
		}
		switch e.Kind {
		case "config":
			p.configs = append(p.configs, e.ID)
		case "head", "tombstone":
			if e.Target != "" {
				p.pos[e.Target] = e.ID
			}
		case "batch":
			for _, s := range e.Entries {
				if s.Kind == "config" {
					p.configs = append(p.configs, e.ID)
				}
				if (s.Kind == "head" || s.Kind == "tombstone") && s.Target != "" {
					p.pos[s.Target] = e.ID
				}
			}
		}
	}
	return p
}

// keysAt are the keys of ns's document at the log entry id.
func (sk *sourceKeys) keysAt(ctx context.Context, ns, entry string) ([]KeyEntry, error) {
	k := ns + "/" + entry
	if ks, ok := sk.docs[k]; ok {
		return ks, nil
	}
	doc, err := sk.c.NSDoc(ctx, ns, entry)
	if err != nil {
		return nil, err
	}
	var out []KeyEntry
	arr, _ := doc.Value["keys"].([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		kid, _ := m["kid"].(string)
		pub, _ := m["pub"].(string)
		alg, _ := m["alg"].(string)
		out = append(out, KeyEntry{Kid: kid, Alg: alg, Pub: pub})
	}
	sk.docs[k] = out
	return out, nil
}

// find implements KeyFinder.
func (sk *sourceKeys) find(ctx context.Context, ns, kid string, rev *Line) []KeyEntry {
	sk.mu.Lock()
	defer sk.mu.Unlock()
	if !rev.Written.IsZero() && rev.Written.Origin != "" {
		return nil // another deployment than the source
	}
	var out []KeyEntry
	if p := sk.positions(ctx, ns); p.err == nil {
		if entry, ok := p.pos[rev.ID]; ok {
			if keys, err := sk.keysAt(ctx, ns, entry); err == nil {
				for _, k := range keys {
					if k.Kid == kid {
						out = append(out, k)
					}
				}
			}
		}
	}
	return append(out, sk.operatorKeysAt(ctx, kid, rev.Created)...)
}

// operatorKeysAt lists the operator keys named kid that were in force at
// created (§C.4); none if the history can't be read or created isn't a time.
func (sk *sourceKeys) operatorKeysAt(ctx context.Context, kid, created string) []KeyEntry {
	if !sk.jwksOK {
		sk.jwks, sk.jwksErr = sk.c.OperatorKeys(ctx)
		sk.jwksOK = true
	}
	at, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return nil
	}
	var out []KeyEntry
	for _, k := range sk.jwks {
		if k.Kid != kid {
			continue
		}
		if from, err := time.Parse(time.RFC3339, k.From); err == nil && at.Before(from) {
			continue
		}
		if k.Until != "" {
			if until, err := time.Parse(time.RFC3339, k.Until); err == nil && !at.Before(until) {
				continue
			}
		}
		out = append(out, KeyEntry{Kid: k.Kid, Alg: sig.Alg, Pub: base64.RawURLEncoding.EncodeToString(k.Pub)})
	}
	return out
}

func (sk *sourceKeys) check(ctx context.Context, ns string, key KeyEntry, rev *Line) (KeyVerdict, string) {
	sk.mu.Lock()
	defer sk.mu.Unlock()
	if !rev.Written.IsZero() && rev.Written.Origin != "" {
		return KeyUnchecked, "the revision was written at " + rev.Written.Origin + ", not at the source deployment"
	}
	p := sk.positions(ctx, ns)
	if p.err != nil {
		return KeyUnchecked, "the source's namespace log can't be read: " + p.err.Error()
	}
	if entry, ok := p.pos[rev.ID]; ok {
		keys, err := sk.keysAt(ctx, ns, entry)
		if err != nil {
			return KeyUnchecked, "the namespace document at the revision's position can't be read: " + err.Error()
		}
		for _, k := range keys {
			if k.Kid == key.Kid && k.Pub == key.Pub {
				return KeyInForce, ""
			}
		}
	}
	// An operator key: in force at the revision's created time.
	if !sk.jwksOK {
		sk.jwks, sk.jwksErr = sk.c.OperatorKeys(ctx)
		sk.jwksOK = true
	}
	if sk.jwksErr == nil {
		created, cerr := time.Parse(time.RFC3339, rev.Created)
		pub, _ := base64.RawURLEncoding.DecodeString(key.Pub)
		for _, k := range sk.jwks {
			if k.Kid != key.Kid || string(k.Pub) != string(pub) {
				continue
			}
			if cerr != nil {
				return KeyUnchecked, "the revision has no created time to place the operator key in"
			}
			from, ferr := time.Parse(time.RFC3339, k.From)
			if ferr == nil && created.Before(from) {
				continue
			}
			if k.Until != "" {
				if until, uerr := time.Parse(time.RFC3339, k.Until); uerr == nil && !created.Before(until) {
					continue
				}
			}
			return KeyInForce, ""
		}
	}
	if _, ok := p.pos[rev.ID]; !ok {
		return KeyUnchecked, "the revision isn't in the source namespace's own log, so its position is unknown"
	}
	if sk.jwksErr != nil {
		return KeyUnchecked, "the key isn't in the namespace document at that position, and the operator key history can't be read: " + sk.jwksErr.Error()
	}
	return KeyNotInForce, fmt.Sprintf("key %q was in force neither in the namespace document at the revision's position nor in the operator key history at %s", key.Kid, rev.Created)
}
