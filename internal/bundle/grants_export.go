package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
)

// Grant lines and `written` in an export (§G.4.1, §C.3.1).
//
// With Authors the exporter writes, before the first line that names a
// grant, one grant line for it: the grant as GET /ns/{ns}/grants/{gid}
// serves it, and the key entry its root block verified against at the
// source. Decisions where the spec leaves room:
//
//   - The line's ns is the namespace whose entry first recorded the grant,
//     in the form of `written`. For an export of a local branch the
//     exporter looks through the branch's bases, deepest first, for the
//     first namespace log with an entry under that grant (a base's only up
//     to the branch's at). Where no log says (an entry from before the
//     source recorded grants), it is the namespace that wrote the first
//     line naming the grant.
//   - The key is, in order: a key of the namespace document in force at the
//     first entry that recorded the grant (at the position of the first
//     line naming it where the log doesn't say), or an operator key in
//     force at the created time of the first line naming it (§C.4). Only a
//     key that verifies the stored authority block counts. An exporter that
//     finds none leaves `key` out.
//   - A grant the exporter can't fetch (the source answers 404, 401, 403 or
//     410, or doesn't have it) gets no grant line, and the lines that name
//     it carry no grant member, only their signature: a bundle tool
//     reports those as unverifiable. A note on the plan says which grants
//     and why. Sealed namespaces seal the answer (pl { ns, grant }), which
//     the exporter opens with the namespace's epoch key; end-to-end ones
//     serve it in the clear.
//   - `written` is set on a line whose revision is in the log of a base,
//     not of the namespace the line names. A line the exporter can't place
//     in any log is left as the exporting namespace's, as the spec has it.

// grantEntry is what a log entry says about its grant: the id, or "".
func grantEntry(e client.LogEntry) string {
	switch g := e.Raw["grant"].(type) {
	case map[string]any:
		id, _ := g["id"].(string)
		return id
	case string:
		return g
	}
	return ""
}

// nsLink is a namespace of a branch's base chain: the branch itself, then
// its base, and so on. at is the base's ns_id under which the previous link
// reads this one (zero for the first).
type nsLink struct {
	ref NSRef
	at  string
}

// grantExporter writes grant lines and works out `written`, as the lines
// that need them come.
type grantExporter struct {
	p      *ExportPlan
	sk     *sourceKeys
	remote map[string]*sourceKeys // by origin: readers of other deployments
	chains map[string][]nsLink
	levels map[string]string
	epochs map[string][]byte // kid → epoch key, for sealed grants
	state  map[string]bool   // gid → carried (true) or given up on (false)
	noted  map[string]bool
	n      int // grant lines written
}

func newGrantExporter(p *ExportPlan) *grantExporter {
	return &grantExporter{p: p, sk: &sourceKeys{c: p.c, logs: map[string]*nsPositions{}, docs: map[string][]KeyEntry{}},
		remote: map[string]*sourceKeys{}, chains: map[string][]nsLink{}, levels: map[string]string{},
		epochs: map[string][]byte{}, state: map[string]bool{}, noted: map[string]bool{}}
}

func (g *grantExporter) note(key, format string, args ...any) {
	if g.noted[key] {
		return
	}
	g.noted[key] = true
	g.p.Notes = append(g.p.Notes, fmt.Sprintf(format, args...))
}

// chain is ns and its bases, as of the export (§7.6, §G.3). A remote base
// is followed through base.chain, its own namespace and the bases it read
// through, none of which this deployment has.
func (g *grantExporter) chain(ctx context.Context, ns string) []nsLink {
	if c, ok := g.chains[ns]; ok {
		return c
	}
	links := []nsLink{{ref: NSRef{NS: ns}}}
	cur, at := ns, g.p.At[ns]
	for depth := 0; depth < 64 && at != ""; depth++ {
		doc, err := g.p.c.NSDoc(ctx, cur, at)
		if err != nil {
			g.note("chain "+cur, "the base chain of %s can't be read (%v), so lines read through from a base aren't attributed to it", cur, err)
			break
		}
		b, ok := doc.Value["base"].(map[string]any)
		if !ok {
			break
		}
		bns, _ := b["ns"].(string)
		bat, _ := b["at"].(string)
		if origin, _ := b["origin"].(string); origin != "" {
			names := []string{bns}
			if arr, ok := b["chain"].([]any); ok && len(arr) > 0 {
				names = names[:0]
				for _, x := range arr {
					if s, ok := x.(string); ok {
						names = append(names, s)
					}
				}
			}
			for _, n := range names {
				links = append(links, nsLink{ref: NSRef{Origin: origin, NS: n}, at: bat})
			}
			break
		}
		links = append(links, nsLink{ref: NSRef{NS: bns}, at: bat})
		cur, at = bns, bat
	}
	g.chains[ns] = links
	return links
}

// remoteKeys reads a deployment this one's branches are based on, without
// credentials: only what is public there is readable.
func (g *grantExporter) remoteKeys(origin string) *sourceKeys {
	if sk, ok := g.remote[origin]; ok {
		return sk
	}
	var sk *sourceKeys
	if rc, err := client.New(origin); err == nil {
		sk = &sourceKeys{c: rc, logs: map[string]*nsPositions{}, docs: map[string][]KeyEntry{}}
	}
	g.remote[origin] = sk
	return sk
}

// writtenIn reports where the revision id of a line of ns was written (§G.4.1
// `written`): the zero NSRef for the namespace itself. known is false if no
// log of the chain has it. A remote base is the namespace that wrote what
// the branch reads through when it is the only remote link (§G.3); where
// it read through from bases of its own, their logs are read at the origin
// without credentials, and a revision they don't show is not known.
func (g *grantExporter) writtenIn(ctx context.Context, ns, id string) (ref NSRef, known bool) {
	links := g.chain(ctx, ns)
	remotes := g.remoteChainLen(links)
	for i, l := range links {
		var p *nsPositions
		if l.ref.Origin == "" {
			p = g.sk.positions(ctx, l.ref.NS)
		} else {
			if remotes == 1 {
				return l.ref, true
			}
			sk := g.remoteKeys(l.ref.Origin)
			if sk == nil {
				return l.ref, false
			}
			p = sk.positions(ctx, l.ref.NS)
		}
		if p.err != nil {
			if l.ref.Origin != "" {
				return l.ref, false
			}
			continue
		}
		if _, ok := p.pos[id]; ok {
			if i == 0 {
				return NSRef{}, true
			}
			return l.ref, true
		}
	}
	return NSRef{}, false
}

// remoteChainLen counts the remote links of a chain.
func (g *grantExporter) remoteChainLen(links []nsLink) int {
	n := 0
	for _, l := range links {
		if l.ref.Origin != "" {
			n++
		}
	}
	return n
}

// firstRecorded finds the namespace of the chain of ns whose log has the
// first entry under grant gid, and that entry. A base counts only up to the
// at its derived namespace reads it at (§C.3.1).
func (g *grantExporter) firstRecorded(ctx context.Context, ns, gid string) (ref NSRef, entry string, ok bool) {
	links := g.chain(ctx, ns)
	for i := len(links) - 1; i >= 0; i-- {
		l := links[i]
		if l.ref.Origin != "" {
			continue
		}
		p := g.sk.positions(ctx, l.ref.NS)
		if p.err != nil {
			continue
		}
		e, has := p.grants[gid]
		if !has {
			continue
		}
		if l.at != "" {
			if at, known := p.index[l.at]; known && p.index[e] > at {
				continue
			}
		}
		return l.ref, e, true
	}
	return NSRef{}, "", false
}

// level is a namespace's encryption level as the source serves it.
func (g *grantExporter) level(ctx context.Context, ns string) string {
	if a, ok := g.p.Access[ns]; ok {
		if a == AccessSealed || a == AccessE2E {
			return a
		}
		return ""
	}
	if lv, ok := g.levels[ns]; ok {
		return lv
	}
	lv, err := g.p.c.EncryptionLevel(ctx, ns)
	if err != nil {
		lv = ""
	}
	g.levels[ns] = lv
	return lv
}

// errUngettable marks a grant the source doesn't give: skip it, don't fail.
type errUngettable struct{ why string }

func (e *errUngettable) Error() string { return e.why }

// fetch reads grant gid from ns of the source, or of another deployment.
func (g *grantExporter) fetch(ctx context.Context, ref NSRef, gid string) (*client.GrantDoc, error) {
	var c *client.Client
	sealed := false
	if ref.Origin != "" {
		sk := g.remoteKeys(ref.Origin)
		if sk == nil {
			return nil, &errUngettable{"the origin of the base can't be reached"}
		}
		c = sk.c
	} else {
		c = g.p.c
		sealed = g.level(ctx, ref.NS) == AccessSealed
	}
	var rec *client.GrantDoc
	var err error
	if sealed {
		rec, err = g.fetchSealed(ctx, ref.NS, gid)
	} else {
		rec, err = c.Grant(ctx, ref.NS, gid)
	}
	if err != nil {
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == 404 || ae.Status == 401 || ae.Status == 403 || ae.Status == 410) {
			return nil, &errUngettable{fmt.Sprintf("the source answers %d %s", ae.Status, ae.Code)}
		}
		var ug *errUngettable
		if errors.As(err, &ug) {
			return nil, err
		}
		return nil, err
	}
	return rec, nil
}

// fetchSealed reads a grant of a sealed namespace: a JWE with pl { ns,
// grant } under the namespace's epoch key (§E.2.2, §C.3.1).
func (g *grantExporter) fetchSealed(ctx context.Context, ns, gid string) (*client.GrantDoc, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(g.p.c.BaseURL(), "/")+"/ns/"+ns+"/grants/"+gid, nil)
	if err != nil {
		return nil, err
	}
	if g.p.opt.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+g.p.opt.Bearer)
	}
	hc := g.p.opt.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case 200:
	case 404, 401, 403, 410:
		return nil, &errUngettable{fmt.Sprintf("the source answers %d", res.StatusCode)}
	default:
		return nil, fmt.Errorf("export: grant %s of %s: %d %s", gid, ns, res.StatusCode, strings.TrimSpace(string(body)))
	}
	ct := res.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	var pt []byte
	if strings.EqualFold(strings.TrimSpace(ct), seal.ContentType) {
		jwe := strings.TrimSpace(string(body))
		h, err := seal.ParseHeader(jwe)
		if err != nil {
			return nil, fmt.Errorf("export: sealed grant %s of %s: %w", gid, ns, err)
		}
		key, err := g.epochKey(ctx, ns, h.Kid)
		if err != nil {
			return nil, err
		}
		pt, err = seal.OpenExpect(jwe, key, h.Kid, seal.PL{"ns": ns, "grant": gid})
		if err != nil {
			return nil, fmt.Errorf("export: sealed grant %s of %s: %w", gid, ns, err)
		}
	} else {
		pt = body
	}
	v, err := jsonv.Parse(pt)
	if err != nil {
		return nil, fmt.Errorf("export: grant %s of %s: %w", gid, ns, err)
	}
	m, _ := v.(map[string]any)
	rec := &client.GrantDoc{}
	rec.ID, _ = m["id"].(string)
	rec.Root, _ = m["root"].(map[string]any)
	arr, _ := m["stored"].([]any)
	for _, x := range arr {
		s, _ := x.(string)
		rec.Stored = append(rec.Stored, s)
	}
	return rec, nil
}

// epochKey is the epoch key of kid "{ns}#{e}", fetched with the exporter's
// read grant and unwrapped with its identity if the grant's enc wraps it.
func (g *grantExporter) epochKey(ctx context.Context, ns, kid string) ([]byte, error) {
	if k, ok := g.epochs[kid]; ok {
		return k, nil
	}
	kns, epoch, err := seal.ParseKid(kid)
	if err != nil || kns != ns {
		return nil, fmt.Errorf("export: sealed grant of %s is sealed under %q", ns, kid)
	}
	got, err := g.p.c.FetchKeys(ctx, ns, []int{epoch}, nil)
	if err != nil {
		return nil, fmt.Errorf("export: keys of %s for its grants: %w", ns, err)
	}
	for _, e := range got {
		if e.Kid != kid || e.Resource != "" {
			continue
		}
		key := e.Key
		if key == nil {
			if g.p.opt.Identity == nil {
				return nil, fmt.Errorf("export: the keys of %s are wrapped to the grant's enc, and the exporter has no identity to unwrap them: %w", ns, client.ErrNoKeys)
			}
			if key, err = seal.UnwrapKey(g.p.opt.Identity, e.Wrapped); err != nil {
				return nil, fmt.Errorf("export: unwrapping %s: %w", kid, err)
			}
		}
		g.epochs[kid] = key
		return key, nil
	}
	return nil, fmt.Errorf("export: the server gave no epoch key %s: %w", kid, client.ErrNoKeys)
}

// ensure writes the grant line of gid before the line of rev, the first
// that names it, unless it was written or given up on. rev is the entry of
// the history line of ns; written is where that revision was written. It
// reports whether the line may name the grant.
func (g *grantExporter) ensure(ctx context.Context, bw *Writer, ns, gid string, rev client.LogEntry, written NSRef) (bool, error) {
	if ok, seen := g.state[gid]; seen {
		return ok, nil
	}
	g.state[gid] = false
	own := written
	if own.IsZero() {
		own = NSRef{NS: ns}
	}
	// The namespace whose entry first recorded it, in the log of the
	// exporting namespace or its bases.
	lineRef, entry, found := g.firstRecorded(ctx, ns, gid)
	if !found {
		lineRef = own
	}
	var rec *client.GrantDoc
	var why string
	tried := map[NSRef]bool{}
	for _, src := range []NSRef{lineRef, own, {NS: ns}} {
		if tried[src] {
			continue
		}
		tried[src] = true
		r, err := g.fetch(ctx, src, gid)
		if err == nil {
			rec = r
			break
		}
		var ug *errUngettable
		if !errors.As(err, &ug) {
			return false, fmt.Errorf("export: grant %s of %s: %w", gid, src.NS, err)
		}
		why = ug.why
	}
	if rec == nil {
		g.note("grant "+gid, "grant %s isn't carried: %s", gid, why)
		return false, nil
	}
	gr, err := parseStoredGrant(rec.Stored)
	if err != nil {
		g.note("grant "+gid, "grant %s isn't carried: the source's stored grant is malformed: %v", gid, err)
		return false, nil
	}
	if id := gr.ID().String(); id != rec.ID || id != gid {
		g.note("grant "+gid, "grant %s isn't carried: the source's grant record doesn't match its own id (%s)", gid, id)
		return false, nil
	}
	key := g.findKey(ctx, lineRef, found, entry, rec, rev, ns)
	if !key.valid {
		g.note("key "+gid, "grant %s is carried without a key: no key named %q in the namespace document at the first entry that recorded it (or in its bases' then, in a branch), or in the operator key history at %s, verifies its root block (%d candidates)", gid, gr.Blocks[0].Kid, rev.Created, key.tried)
	}
	line := Line{NS: lineRef.NS, GrantLine: &GrantLine{ID: rec.ID, Root: rec.Root, Stored: rec.Stored, Origin: lineRef.Origin}}
	if key.valid {
		line.GrantLine.Key = key.entry
	}
	if err := bw.Line(line); err != nil {
		return false, err
	}
	g.n++
	g.state[gid] = true
	return true, nil
}

type foundKey struct {
	entry KeyEntry
	valid bool
	tried int
}

// findKey finds the key entry rec's root block verifies against at the
// source (see the decisions above).
func (g *grantExporter) findKey(ctx context.Context, lineRef NSRef, found bool, entry string, rec *client.GrantDoc, rev client.LogEntry, ns string) foundKey {
	gr, err := parseStoredGrant(rec.Stored)
	if err != nil {
		return foundKey{}
	}
	kid := gr.Blocks[0].Kid
	var out foundKey
	try := func(k KeyEntry) bool {
		out.tried++
		if k.Kid != kid {
			return false
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return false
		}
		return verifyRootSignature(gr, lineRef.NS, ed25519.PublicKey(pub)) == nil
	}
	norm := func(k KeyEntry) foundKey { k.Alg = sig.Alg; return foundKey{entry: k, valid: true} }

	sk := g.sk
	if lineRef.Origin != "" {
		sk = g.remoteKeys(lineRef.Origin)
	}
	if sk != nil {
		// 1. The namespace document in force at the first entry that
		// recorded the grant; where the log doesn't say, at the position
		// of the line naming it.
		sk.mu.Lock()
		if p := sk.positions(ctx, lineRef.NS); p.err == nil {
			at := entry
			if !found {
				at = p.pos[rev.ID]
			}
			if at != "" {
				if keys, err := sk.keysInForce(ctx, lineRef.NS, at, rev.Created); err == nil {
					for _, k := range keys {
						if try(k) {
							sk.mu.Unlock()
							return norm(k)
						}
					}
				}
			}
		}
		// 2. An operator key in force at the created of the first line
		// naming the grant (§C.4).
		for _, k := range sk.operatorKeysAt(ctx, kid, rev.Created) {
			if try(k) {
				sk.mu.Unlock()
				return norm(k)
			}
		}
		sk.mu.Unlock()
	}
	return out
}

// FindRootKey picks, from candidate keys, the one that verifies the
// authority block of the stored grant (§C.3.1), for exporters that write
// grant lines from a store they hold, such as pruning archives (§8.6). ns
// is the grant line's namespace.
func FindRootKey(stored []string, ns string, candidates []KeyEntry) (KeyEntry, bool) {
	gr, err := parseStoredGrant(stored)
	if err != nil {
		return KeyEntry{}, false
	}
	kid := gr.Blocks[0].Kid
	for _, k := range candidates {
		if k.Kid != kid {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if verifyRootSignature(gr, ns, ed25519.PublicKey(pub)) == nil {
			k.Alg = sig.Alg
			return k, true
		}
	}
	return KeyEntry{}, false
}
