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

// OperatorKeys reads the operator key history (§C.4) that
// author-signature verification needs; Grant (signing.go) reads a
// recorded grant.

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
	root := r.obj()
	uri := str(root, "jwks_uri")
	// Under the deployment's own origin, the key set is this server's:
	// fetch it through the client's base, which may differ from the origin
	// (a proxy, a test server).
	if o := str(root, "origin"); o != "" && strings.HasPrefix(uri, o+"/") {
		uri = strings.TrimPrefix(uri, o)
	}
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
