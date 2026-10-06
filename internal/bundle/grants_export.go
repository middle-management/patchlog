package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/sig"
)

// Grant lines in an export (§G.4.1, §C.3.1).
//
// With Authors the exporter writes, before the first line that names a
// grant, one grant line for it: the grant as GET /ns/{ns}/grants/{gid}
// serves it, and the key entry its root block verified against at the
// source. Decisions where the spec leaves room:
//
//   - The key is found among, in order: the keys of the namespace document
//     in force at the position of the first revision that names the grant;
//     the operator key history (the JWK Set at GET /'s jwks_uri) at that
//     revision's created time; and every key of every version of the
//     namespace document. The first candidate whose key verifies the
//     authority block wins, so the line never attests a key that doesn't
//     match the stored grant. Its alg is written as "Ed25519".
//   - A grant the exporter can't carry (the source doesn't have it, its key
//     can't be determined, or the namespace is sealed or end-to-end, whose
//     grants endpoint answers 404 not_offered) gets no grant line, and the
//     lines that were written under it carry no grant member, only their
//     signature: a bundle tool reports those signatures as unverifiable. A
//     note on the plan says which grants and why. In sealed and e2e
//     namespaces the exporter doesn't try: the endpoint isn't offered
//     there (§C.3.1), and the grants are not otherwise readable through the
//     API. The spec's "their bundles carry the grants" can't be met by an
//     exporter that holds only the public API, so those signatures are
//     carried but stay unverifiable until the source offers the grants.

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

// grantExporter writes grant lines as the lines that need them come.
type grantExporter struct {
	p     *ExportPlan
	sk    *sourceKeys
	state map[string]bool // "ns\x00gid" → carried (true) or given up on (false)
	noted map[string]bool
	n     int // grant lines written
}

func newGrantExporter(p *ExportPlan) *grantExporter {
	return &grantExporter{p: p, sk: &sourceKeys{c: p.c, logs: map[string]*nsPositions{}, docs: map[string][]KeyEntry{}},
		state: map[string]bool{}, noted: map[string]bool{}}
}

func (g *grantExporter) note(key, format string, args ...any) {
	if g.noted[key] {
		return
	}
	g.noted[key] = true
	g.p.Notes = append(g.p.Notes, fmt.Sprintf(format, args...))
}

// ensure writes the grant line of gid in ns before rev, the first line that
// names it, unless it was written or given up on. It reports whether rev
// may name the grant.
func (g *grantExporter) ensure(ctx context.Context, bw *Writer, ns, gid string, rev client.LogEntry) (bool, error) {
	k := ns + "\x00" + gid
	if ok, seen := g.state[k]; seen {
		return ok, nil
	}
	g.state[k] = false
	if a := g.p.Access[ns]; a == AccessSealed || a == AccessE2E {
		g.note("sealed "+ns, "grants of %s (%s) aren't carried: a sealed or end-to-end namespace doesn't offer GET /ns/%s/grants/{gid} (§C.3.1), so its signatures can't be verified from this bundle", ns, a, ns)
		return false, nil
	}
	rec, err := g.p.c.GetGrant(ctx, ns, gid)
	if err != nil {
		if ae, ok := client.AsAPIError(err); ok && (ae.Status == 404 || ae.Status == 401 || ae.Status == 403) {
			g.note("grant "+k, "grant %s of %s isn't carried: the source answers %d %s for it", gid, ns, ae.Status, ae.Code)
			return false, nil
		}
		return false, fmt.Errorf("export: grant %s of %s: %w", gid, ns, err)
	}
	key, err := g.findKey(ctx, ns, rec, rev)
	if err != nil {
		g.note("grant "+k, "grant %s of %s isn't carried: %v", gid, ns, err)
		return false, nil
	}
	if err := bw.Line(Line{NS: ns, GrantLine: &GrantLine{ID: rec.ID, Root: rec.Root, Stored: rec.Stored, Key: key}}); err != nil {
		return false, err
	}
	g.n++
	g.state[k] = true
	return true, nil
}

// findKey finds the key entry rec's root block verifies against at the
// source (see the decisions above), checking the grant on the way.
func (g *grantExporter) findKey(ctx context.Context, ns string, rec *client.GrantRecord, rev client.LogEntry) (KeyEntry, error) {
	gr, err := parseStoredGrant(rec.Stored)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("the source's stored grant is malformed: %v", err)
	}
	if id := gr.ID().String(); id != rec.ID {
		return KeyEntry{}, fmt.Errorf("the source's grant record doesn't match its own id (%s)", id)
	}
	kid := gr.Blocks[0].Kid
	try := func(k KeyEntry) bool {
		pub, err := base64.RawURLEncoding.DecodeString(k.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize || k.Kid != kid {
			return false
		}
		return verifyRootSignature(gr, ns, ed25519.PublicKey(pub)) == nil
	}
	norm := func(k KeyEntry) KeyEntry { k.Alg = sig.Alg; return k }

	sk := g.sk
	// 1. The namespace document at the revision's position.
	var tried int
	if p := sk.positions(ctx, ns); p.err == nil {
		if entry, ok := p.pos[rev.ID]; ok {
			if keys, err := sk.keysAt(ctx, ns, entry); err == nil {
				for _, k := range keys {
					tried++
					if try(k) {
						return norm(k), nil
					}
				}
			}
		}
	}
	// 2. The operator key history at the revision's created time.
	if !sk.jwksOK {
		sk.jwks, sk.jwksErr = g.p.c.OperatorKeys(ctx)
		sk.jwksOK = true
	}
	created, cerr := time.Parse(time.RFC3339, rev.Created)
	for _, ok := range sk.jwks {
		if ok.Kid != kid {
			continue
		}
		if cerr == nil {
			if from, err := time.Parse(time.RFC3339, ok.From); err == nil && created.Before(from) {
				continue
			}
			if ok.Until != "" {
				if until, err := time.Parse(time.RFC3339, ok.Until); err == nil && !created.Before(until) {
					continue
				}
			}
		}
		k := KeyEntry{Kid: ok.Kid, Alg: sig.Alg, Pub: base64.RawURLEncoding.EncodeToString(ok.Pub)}
		tried++
		if try(k) {
			return k, nil
		}
	}
	// 3. Fallback: any version of the namespace document. The key then
	// verified at the source at some position, not necessarily this one.
	if p := sk.positions(ctx, ns); p.err == nil {
		for _, entry := range p.configs {
			keys, err := sk.keysAt(ctx, ns, entry)
			if err != nil {
				continue
			}
			for _, k := range keys {
				tried++
				if try(k) {
					return norm(k), nil
				}
			}
		}
	}
	return KeyEntry{}, fmt.Errorf("no key named %q in the namespace document (any version) or the operator key history verifies its root block (%d candidates)", kid, tried)
}
