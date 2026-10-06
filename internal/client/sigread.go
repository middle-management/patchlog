package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// This file holds the reads that author-signature verification needs
// (§C.3.1, §C.4): a recorded grant in its stored form, and the operator
// key history. Tools use them to build and check bundles.

// GrantRecord is the answer of GET /ns/{ns}/grants/{gid} (§C.3.1): the
// grant's root block and its non-bearer form, a JSON array of the token's
// protobuf SignedBlocks in base64url without padding, authority first.
type GrantRecord struct {
	ID     string
	Root   map[string]any
	Stored []string
}

// GetGrant reads a grant recorded by an entry of ns (or of its bases, in a
// local branch). It needs unrestricted read on ns. A sealed or end-to-end
// namespace doesn't offer it: an *APIError with code "not_offered".
func (c *Client) GetGrant(ctx context.Context, ns, gid string) (*GrantRecord, error) {
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
	rec := &GrantRecord{ID: str(m, "id")}
	rec.Root, _ = m["root"].(map[string]any)
	for _, x := range strList(m["stored"]) {
		rec.Stored = append(rec.Stored, x)
	}
	if rec.ID == "" || rec.Root == nil || len(rec.Stored) == 0 {
		return nil, fmt.Errorf("client: %s: not a grant record", r.path)
	}
	return rec, nil
}

// OperatorKey is a key of the deployment's operator key history (§C.4).
type OperatorKey struct {
	Kid string
	Pub []byte // Ed25519, 32 bytes
	// From and Until are the RFC 3339 period the key was in force; Until
	// is "" while it still is.
	From, Until string
}

// OperatorKeys reads the JWK Set at the jwks_uri that GET / gives, by
// default /.well-known/patchlog-keys (§C.4). Entries that aren't OKP
// Ed25519 keys with a kid are left out.
func (c *Client) OperatorKeys(ctx context.Context) ([]OperatorKey, error) {
	r, err := c.do(ctx, "GET", "/", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	uri := str(r.obj(), "jwks_uri")
	var body []byte
	switch {
	case uri == "":
		uri = "/.well-known/patchlog-keys"
		fallthrough
	case strings.HasPrefix(uri, "/"):
		jr, err := c.do(ctx, "GET", uri, nil, nil)
		if err != nil {
			return nil, err
		}
		if jr.status != 200 {
			return nil, jr.apiError()
		}
		body = jr.body
	case strings.HasPrefix(uri, c.base+"/"):
		jr, err := c.do(ctx, "GET", strings.TrimPrefix(uri, c.base), nil, nil)
		if err != nil {
			return nil, err
		}
		if jr.status != 200 {
			return nil, jr.apiError()
		}
		body = jr.body
	default:
		// Another host: public, so no credentials go along.
		req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
		if err != nil {
			return nil, err
		}
		res, err := c.hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("client: GET %s: %d", uri, res.StatusCode)
		}
		if body, err = io.ReadAll(res.Body); err != nil {
			return nil, err
		}
	}
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("client: the JWK Set is not JSON: %w", err)
	}
	set, _ := v.(map[string]any)
	arr, _ := set["keys"].([]any)
	var out []OperatorKey
	for _, x := range arr {
		k, _ := x.(map[string]any)
		if str(k, "kty") != "OKP" || str(k, "crv") != "Ed25519" || str(k, "kid") == "" {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(str(k, "x"))
		if err != nil || len(pub) != 32 {
			continue
		}
		ok := OperatorKey{Kid: str(k, "kid"), Pub: pub}
		if pl, _ := k["patchlog"].(map[string]any); pl != nil {
			ok.From, ok.Until = str(pl, "from"), str(pl, "until")
		}
		out = append(out, ok)
	}
	return out, nil
}
