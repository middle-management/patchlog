package client

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
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
	var gs []string
	if sourceGrant != "" {
		gs = []string{sourceGrant}
	}
	return c.CopyBlobWith(ctx, ns, name, bid, fromNS, fromName, gs...)
}

// CopyBlobWith is CopyBlob with any number of Source-Authorization grants,
// sent as repeated headers: any that verifies for fromNS reads the source
// (§7.8). Without any (and none set with WithSourceAuthorization), the
// client's own grant is used.
func (c *Client) CopyBlobWith(ctx context.Context, ns, name, bid, fromNS, fromName string, sourceGrants ...string) error {
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
	r, err := c.do(ctx, "PUT", "/r/"+ns+"/"+name+"/blob/"+bid, nil, &request{header: h, sourceAuth: sourceGrants})
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
	if r.status == 302 {
		return nil, fmt.Errorf("client: blob %s/%s/%s is sealed for delivery (§E.2.2): read it with GetBlobRef", ns, name, bid)
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

// RawBlobOf is the blob id of a raw document (§7.8), one whose root is a
// blob reference with no other members than those validation leaves out
// ($schema, a fresh $nonce, a well-formed $successor, §6.2 step 5): a file
// stored as a blob. "" for any other document.
func RawBlobOf(doc any) string {
	m, ok := doc.(map[string]any)
	if !ok {
		return ""
	}
	bid, _ := m["$blob"].(string)
	if checkID("blob", bid) != nil {
		return ""
	}
	if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
		return ""
	}
	_, typed := m["type"].(string)
	_, sized := m["size"].(float64)
	if !typed || !sized {
		return ""
	}
	for k, v := range m {
		switch k {
		case "$blob", "type", "size":
		case "nonce":
			if _, ok := v.(string); !ok {
				return ""
			}
		default:
			if !schema.LeftOut(k, v) {
				return ""
			}
		}
	}
	return bid
}

// Raw asks for the blob a raw document stands for (§7.1): …/raw at the head
// (id "") or …/rev/{id}/raw, whose 302 names it, for reading with GetBlob.
// A document that isn't raw is a 404 *APIError (not_found), as is any
// document of a sealed or e2e namespace (not_offered); a tombstoned head
// or id, a purge or a prune is a 410, as at the document's own URL.
func (c *Client) Raw(ctx context.Context, ns, name, id string) (string, error) {
	if err := checkRes(ns, name); err != nil {
		return "", err
	}
	path := "/r/" + ns + "/" + name
	if id != "" {
		if err := checkID("revision", id); err != nil {
			return "", err
		}
		path += "/rev/" + id
	}
	r, err := c.do(ctx, "GET", path+"/raw", nil, nil)
	if err != nil {
		return "", err
	}
	if r.status != 302 {
		return "", r.apiError()
	}
	bid, ok := strings.CutPrefix(r.header.Get("Location"), "/r/"+ns+"/"+name+"/blob/")
	if !ok || checkID("blob", bid) != nil {
		return "", fmt.Errorf("client: %s/raw redirects to %q", path, r.header.Get("Location"))
	}
	return bid, nil
}
