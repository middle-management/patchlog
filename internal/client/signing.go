package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
)

// Author signatures (§C.3, §C.3.1). A client with a signer (WithSigner)
// signs every revision and tombstone it writes: the Signature header of
// Create, Append, Restore and Delete, and each batch step's "signature"
// (§7.5). The signing input binds the deployment's origin (GET /), the
// namespace, the resource, the parent the write applies on and the
// canonical patch set as sent (the sealed one at E3), or "tombstone" for a
// delete. The server verifies a signature whose kid the grant's root block
// lists in "signers", so the grant should list k.Entry().

// WithSigner signs every resource write and batch step with k (§C.3.1). An
// explicit WithSignature, or a step's own Signature, takes precedence.
func WithSigner(k sig.Key) Option {
	return func(c *Client) { kk := k; c.signer = &kk }
}

// SignWrite is the signature of k over a write of ns/name on parent (text
// id, "" for a genesis) with patches, or of a tombstone when del is set
// (§C.3, §C.3.1), in the Signature header form.
func SignWrite(k sig.Key, origin, ns, name, parent string, patches any, del bool) (string, error) {
	var p *ids.ID
	if parent != "" {
		id, err := ids.Parse(parent)
		if err != nil {
			return "", fmt.Errorf("client: parent: %w", err)
		}
		p = &id
	}
	if del {
		if p == nil {
			return "", fmt.Errorf("client: a tombstone needs a parent")
		}
		return k.SignTombstone(origin, ns, name, *p), nil
	}
	v, err := Value(patches)
	if err != nil {
		return "", err
	}
	return k.SignPatches(origin, ns, name, p, jsonv.Canonical(v)), nil
}

// signHeader sets the Signature header of a single write when the client
// has a signer and none was given.
func (c *Client) signHeader(ctx context.Context, rq *request, ns, name, parent string, patches any, del bool) error {
	if c.signer == nil {
		return nil
	}
	if _, has := rq.header["Signature"]; has {
		return nil
	}
	origin, err := c.Origin(ctx)
	if err != nil {
		return err
	}
	s, err := SignWrite(*c.signer, origin, ns, name, parent, patches, del)
	if err != nil {
		return err
	}
	rq.header["Signature"] = s
	return nil
}

// signBatch returns the batch's items with every step signed that has no
// signature of its own, each on the id the step before it produces (§3.3,
// §3.4, §7.5).
func (c *Client) signBatch(ctx context.Context, ns string, items []BatchItem) ([]BatchItem, error) {
	if c.signer == nil || len(items) == 0 {
		return items, nil
	}
	origin, err := c.Origin(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BatchItem, len(items))
	for i, it := range items {
		steps := append([]Step(nil), it.Steps...)
		var parent *ids.ID
		if it.IfMatch != "" {
			p, err := ids.Parse(it.IfMatch)
			if err != nil {
				return nil, fmt.Errorf("client: batch item %s: ifMatch: %w", it.Resource, err)
			}
			parent = &p
		}
		for j, s := range steps {
			var id ids.ID
			var body []byte
			if s.Delete {
				if parent == nil {
					return nil, fmt.Errorf("client: batch item %s: a delete step needs a parent", it.Resource)
				}
				id = ids.Tombstone(*parent)
			} else {
				v, err := Value(s.Patches)
				if err != nil {
					return nil, fmt.Errorf("client: batch item %s: %w", it.Resource, err)
				}
				body = jsonv.Canonical(v)
				id = ids.Revision(parent, body)
			}
			if s.Signature == "" {
				steps[j].Signature = c.signer.Sign(sig.Digest(origin, ns, it.Resource, parent, body))
			}
			parent = &id
		}
		it.Steps = steps
		out[i] = it
	}
	return out, nil
}

// GrantDoc is a stored grant as GET /ns/{ns}/grants/{gid} serves it
// (§C.3.1): its id, root block and the non-bearer form's SignedBlocks,
// authority first, in base64url without padding.
type GrantDoc struct {
	ID     string
	Root   map[string]any
	Stored []string
}

// Blocks decodes Stored.
func (g *GrantDoc) Blocks() ([][]byte, error) {
	out := make([][]byte, len(g.Stored))
	for i, s := range g.Stored {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("client: stored[%d]: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}

// Grant fetches a grant recorded in ns (§C.3.1). It needs unrestricted
// read on the namespace. A sealed namespace serves it sealed, pl
// { ns, grant: gid } (§E.2.2), which needs the client's keys (ErrNoKeys
// without them); an end-to-end one serves it in the clear. A purged
// namespace answers 410.
func (c *Client) Grant(ctx context.Context, ns, gid string) (*GrantDoc, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if err := checkID("grant", gid); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/grants/"+gid, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	m := r.obj()
	if isJOSE(r) {
		pt, err := c.open(ctx, ns, "", strings.TrimSpace(string(r.body)), fixedPL(seal.GrantPL(ns, gid)))
		if err != nil {
			return nil, fmt.Errorf("client: grant %s of %s: %w", gid, ns, err)
		}
		v, err := jsonv.Parse(pt)
		if err != nil {
			return nil, fmt.Errorf("client: grant %s of %s: %w", gid, ns, err)
		}
		m, _ = v.(map[string]any)
	}
	g := &GrantDoc{ID: str(m, "id")}
	if g.ID != gid {
		return nil, fmt.Errorf("client: %s: grant %q answered for %q", r.path, g.ID, gid)
	}
	g.Root, _ = m["root"].(map[string]any)
	arr, _ := m["stored"].([]any)
	for _, x := range arr {
		s, _ := x.(string)
		g.Stored = append(g.Stored, s)
	}
	return g, nil
}
