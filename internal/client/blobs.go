package client

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
)

// BlobID computes a blob's id (§3.7) from its media type (lowercased,
// without parameters), nonce ("" for none) and bytes.
func BlobID(typ, nonce string, data []byte) string {
	return ids.Blob(blobType(typ), nonce, data).String()
}

func blobType(ct string) string {
	if mt, _, err := mime.ParseMediaType(ct); err == nil {
		return strings.ToLower(mt)
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// BlobRef is a blob reference to put in a document (§7.8):
// { "$blob", "type", "size", "nonce"? }.
func BlobRef(bid, typ string, size int, nonce string) map[string]any {
	m := map[string]any{"$blob": bid, "type": blobType(typ), "size": size}
	if nonce != "" {
		m["nonce"] = nonce
	}
	return m
}

// UploadBlob uploads data as a blob of resource ns/name (§7.8) and returns
// its id. The blob stays pending, visible to nobody and usable only by
// this uploader, until a write references it. nonce is "" or 26 base32
// characters (Blob-Nonce, e.g. seal.NewNonce()).
func (c *Client) UploadBlob(ctx context.Context, ns, name, typ, nonce string, data []byte) (string, error) {
	if err := checkRes(ns, name); err != nil {
		return "", err
	}
	bid := BlobID(typ, nonce, data)
	rq := &request{body: data, ct: typ}
	if rq.body == nil {
		rq.body = []byte{}
	}
	if nonce != "" {
		rq.header = map[string]string{"Blob-Nonce": nonce}
	}
	r, err := c.do(ctx, "PUT", "/r/"+ns+"/"+name+"/blob/"+bid, nil, rq)
	if err != nil {
		return "", err
	}
	if r.status != 201 {
		return "", r.apiError()
	}
	return bid, nil
}

// CopyBlob copies blob bid of fromNS/fromName into ns/name within the
// deployment (§7.8 Copying), pending for this client. sourceGrant, if set,
// is sent as Source-Authorization to read the source; otherwise the
// client's own grant is used.
func (c *Client) CopyBlob(ctx context.Context, ns, name, bid, fromNS, fromName, sourceGrant string) error {
	if err := checkRes(ns, name); err != nil {
		return err
	}
	if err := checkRes(fromNS, fromName); err != nil {
		return err
	}
	if err := checkID("blob", bid); err != nil {
		return err
	}
	h := map[string]string{"Blob-From": "/r/" + fromNS + "/" + fromName + "/blob/" + bid}
	if sourceGrant != "" {
		h["Source-Authorization"] = "Bearer " + sourceGrant
	}
	r, err := c.do(ctx, "PUT", "/r/"+ns+"/"+name+"/blob/"+bid, nil, &request{header: h})
	if err != nil {
		return err
	}
	if r.status != 201 {
		return r.apiError()
	}
	return nil
}

// Blob is a blob as served.
type Blob struct {
	Type string
	Data []byte
}

// GetBlob reads blob bid of ns/name (§7.8 Reading) and checks the bytes
// against the id, with the nonce of the reference ("" for none). A pending
// or unknown blob is a 404 *APIError, a pruned or purged one a 410.
func (c *Client) GetBlob(ctx context.Context, ns, name, bid, nonce string) (*Blob, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("blob", bid); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/r/"+ns+"/"+name+"/blob/"+bid, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	b := &Blob{Type: r.header.Get("Content-Type"), Data: r.body}
	if got := BlobID(b.Type, nonce, b.Data); got != bid {
		return nil, fmt.Errorf("client: blob %s/%s/%s doesn't match its id (got %s)", ns, name, bid, got)
	}
	return b, nil
}

// GetBlobRange reads bytes [from, to] (inclusive) of a blob (§7.8: 206).
// The bytes can't be checked against the id.
func (c *Client) GetBlobRange(ctx context.Context, ns, name, bid string, from, to int64) ([]byte, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("blob", bid); err != nil {
		return nil, err
	}
	rng := "bytes=" + strconv.FormatInt(from, 10) + "-" + strconv.FormatInt(to, 10)
	r, err := c.do(ctx, "GET", "/r/"+ns+"/"+name+"/blob/"+bid, nil, &request{header: map[string]string{"Range": rng}})
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusPartialContent && r.status != 200 {
		return nil, r.apiError()
	}
	return r.body, nil
}
