package client

// Blobs of encrypted namespaces (§7.8, §E.2.2, §E.3.1).
//
//   - Sealed namespaces (E2) never serve a blob's plaintext: GET
//     /r/{ns}/{name}/blob/{bid} answers 302 to …/blob/{bid}/e/{e}, the blob
//     in the binary sealed form (seal.SealBlob) under the resource's K_r of
//     epoch e. GetBlobRef follows the redirect, opens the blob with the
//     client's Keys (WithKeys) and checks it against the reference; a
//     reader holding only older epochs asks for one with GetBlobRefEpoch.
//     Writers give the blobs they create a nonce (§C.7): UploadBlob with
//     seal.NewNonce().
//   - End-to-end namespaces (E3): a client encrypts each blob under a fresh
//     key of its own (EncryptBlob, E2E.UploadBlob), and the key travels in
//     the reference, inside the sealed document: { "$blob", "type":
//     SealedBlobType, "size", "sealed": { "key", "type", "size" } }. Sealed
//     writes declare the blobs their document references in plaintext
//     (BlobIDs, §E.3.1); E2E does that itself. GetBlobRef (or E2E.GetBlob)
//     decrypts with the reference's key.

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// SealedBlobType is the media type of sealed blobs (§E.2.2), the only type
// e2e namespaces accept (§E.3.1).
const SealedBlobType = seal.BlobContentType

// BlobIDs lists the distinct blob ids a document references (§7.8: objects
// whose $blob member is a string, at any depth; schema documents have
// none), sorted: the declared list of a sealed write (§E.3.1).
func BlobIDs(doc any) []string {
	if m, ok := doc.(map[string]any); ok {
		if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
			return nil
		}
	}
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			if s, ok := x["$blob"].(string); ok {
				seen[s] = true
				return
			}
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// sameBlobs reports whether two blob lists name the same set of ids.
func sameBlobs(a, b []string) bool {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	other := map[string]bool{}
	for _, s := range b {
		if !set[s] {
			return false
		}
		other[s] = true
	}
	return len(set) == len(other)
}

// EncryptBlob encrypts data, of media type typ, for an e2e namespace
// (§E.3.1): under a fresh random key, in the sealed-blob form with the
// header {"enc": "A256GCM"}, padded with zero bytes to its bucket if pad
// is set (the namespace's encryption.pad). It returns the bytes to upload
// with Content-Type SealedBlobType, and the reference to put in the
// document, which carries the key.
func EncryptBlob(typ string, data []byte, pad bool) (sealed []byte, ref map[string]any, err error) {
	key := seal.NewKey()
	sealed, err = seal.SealBlob(key, "", nil, data, pad)
	if err != nil {
		return nil, nil, err
	}
	ref = map[string]any{"$blob": BlobID(SealedBlobType, "", sealed), "type": SealedBlobType, "size": len(sealed),
		"sealed": map[string]any{"key": base64.RawURLEncoding.EncodeToString(key), "type": blobType(typ), "size": len(data)}}
	return sealed, ref, nil
}

// blobRef is a parsed blob reference.
type blobRef struct {
	bid, typ, nonce string
	size            int64
	sealed          *sealedRef // E3
}

type sealedRef struct {
	key  []byte
	typ  string
	size int64
}

func parseBlobRef(ref any) (*blobRef, error) {
	v, err := ToValue(ref)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	r := &blobRef{bid: str(m, "$blob"), typ: str(m, "type"), nonce: str(m, "nonce")}
	size, ok := m["size"].(float64)
	if checkID("blob", r.bid) != nil || r.typ == "" || !ok || size < 0 || size != math.Trunc(size) {
		return nil, fmt.Errorf("client: malformed blob reference")
	}
	r.size = int64(size)
	if s, has := m["sealed"]; has {
		sm, _ := s.(map[string]any)
		key, err := base64.RawURLEncoding.DecodeString(str(sm, "key"))
		ssize, ok := sm["size"].(float64)
		if err != nil || len(key) != seal.KeySize || str(sm, "type") == "" || !ok || ssize < 0 || ssize != math.Trunc(ssize) {
			return nil, fmt.Errorf("client: malformed sealed blob reference (§E.3.1)")
		}
		r.sealed = &sealedRef{key: key, typ: str(sm, "type"), size: int64(ssize)}
	}
	return r, nil
}

// DecryptBlob opens an e2e blob (§E.3.1): sealed are its bytes as served,
// checked against the reference's id and size, and decrypted with the key
// the reference carries. It returns the plaintext with its own type.
func DecryptBlob(ref any, sealed []byte) (*Blob, error) {
	r, err := parseBlobRef(ref)
	if err != nil {
		return nil, err
	}
	return r.decrypt(sealed)
}

func (r *blobRef) decrypt(sealed []byte) (*Blob, error) {
	if r.sealed == nil {
		return nil, fmt.Errorf("client: blob %s: the reference carries no key (§E.3.1)", r.bid)
	}
	if BlobID(r.typ, r.nonce, sealed) != r.bid || int64(len(sealed)) != r.size {
		return nil, fmt.Errorf("client: blob %s doesn't match its id or size", r.bid)
	}
	h, data, err := seal.OpenBlob(sealed, r.sealed.key)
	if err != nil {
		return nil, fmt.Errorf("client: blob %s: %w", r.bid, err)
	}
	if h.Kid != "" {
		return nil, fmt.Errorf("client: blob %s: an e2e blob's header has no kid: %w", r.bid, seal.ErrMismatch)
	}
	if int64(len(data)) != r.sealed.size {
		return nil, fmt.Errorf("client: blob %s: %d bytes, the reference says %d", r.bid, len(data), r.sealed.size)
	}
	return &Blob{Type: r.sealed.typ, Data: data}, nil
}

// GetBlobRef reads the blob a reference names, of ns/name, and checks it
// against the reference (§7.8). In a sealed namespace it follows the 302
// to the latest epoch and opens the blob with the client's keys (§E.2.2);
// a reference with "sealed" (E3) is decrypted with its key (§E.3.1). The
// Blob has the plaintext and its own type.
func (c *Client) GetBlobRef(ctx context.Context, ns, name string, ref any) (*Blob, error) {
	return c.getBlobRef(ctx, ns, name, ref, 0)
}

// GetBlobRefEpoch is GetBlobRef for the blob of a sealed namespace sealed
// under epoch e, for a reader that holds older epochs only (§E.2.2). An
// epoch the blob isn't served under is a 404, or 410 once pruned.
func (c *Client) GetBlobRefEpoch(ctx context.Context, ns, name string, ref any, e int) (*Blob, error) {
	if e < 1 {
		return nil, fmt.Errorf("client: epochs start at 1")
	}
	return c.getBlobRef(ctx, ns, name, ref, e)
}

func (c *Client) getBlobRef(ctx context.Context, ns, name string, ref any, epoch int) (*Blob, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	r, err := parseBlobRef(ref)
	if err != nil {
		return nil, err
	}
	base := "/r/" + ns + "/" + name + "/blob/" + r.bid
	path := base
	if epoch > 0 {
		path += "/e/" + strconv.Itoa(epoch)
	}
	resp, err := c.do(ctx, "GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.status == 302 && epoch == 0 {
		loc := resp.header.Get("Location")
		if !strings.HasPrefix(loc, base+"/e/") {
			return nil, fmt.Errorf("client: %s redirects to %q", path, loc)
		}
		if resp, err = c.do(ctx, "GET", loc, nil, nil); err != nil {
			return nil, err
		}
	}
	if resp.status != 200 {
		return nil, resp.apiError()
	}
	body := resp.body
	if blobType(resp.header.Get("Content-Type")) == SealedBlobType {
		if h, err := seal.ParseBlobHeader(body); err == nil && h.Kid != "" {
			// Sealed for delivery (E2).
			if body, err = c.openBlob(ctx, ns, name, r.bid, body); err != nil {
				return nil, err
			}
		}
	}
	if r.sealed != nil {
		return r.decrypt(body)
	}
	if BlobID(r.typ, r.nonce, body) != r.bid || int64(len(body)) != r.size {
		return nil, fmt.Errorf("client: blob %s/%s/%s doesn't match its reference", ns, name, r.bid)
	}
	return &Blob{Type: r.typ, Data: body}, nil
}

// openBlob opens a blob of ns/name sealed for delivery (§E.2.2): its kid
// names ns and its pl the resource and blob; the key is the resource's
// K_r of that epoch (or derived from K_e).
func (c *Client) openBlob(ctx context.Context, ns, name, bid string, sealed []byte) ([]byte, error) {
	if c.keys == nil {
		return nil, ErrNoKeys
	}
	h, err := seal.ParseBlobHeader(sealed)
	if err != nil {
		return nil, fmt.Errorf("client: sealed blob: %w", err)
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, fmt.Errorf("client: sealed blob: %w", err)
	}
	if kns != ns {
		return nil, fmt.Errorf("client: blob of %s is sealed under %s: %w", ns, h.Kid, seal.ErrMismatch)
	}
	key, err := c.keys.key(ctx, c, h.Kid, name)
	if err != nil {
		return nil, err
	}
	oh, data, err := seal.OpenBlob(sealed, key)
	if err != nil {
		return nil, fmt.Errorf("client: sealed blob: %w", err)
	}
	if err := oh.Expect(h.Kid, seal.BlobPL(ns, name, bid)); err != nil {
		return nil, fmt.Errorf("client: sealed blob %s: %w", bid, err)
	}
	return data, nil
}

// UploadBlob encrypts data, of media type typ, under a fresh key (padded if
// the namespace pads), uploads it to ns/name and returns the reference to
// put in the document (§E.3.1). The blob stays pending until a sealed write
// whose declared list names it.
func (x *E2E) UploadBlob(ctx context.Context, ns, name, typ string, data []byte) (map[string]any, error) {
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return nil, err
	}
	sealed, ref, err := EncryptBlob(typ, data, cfg.Pad)
	if err != nil {
		return nil, err
	}
	if _, err := x.c.UploadBlob(ctx, ns, name, SealedBlobType, "", sealed); err != nil {
		return nil, err
	}
	return ref, nil
}

// GetBlob reads and decrypts the e2e blob ref names (§E.3.1).
func (x *E2E) GetBlob(ctx context.Context, ns, name string, ref any) (*Blob, error) {
	return x.c.GetBlobRef(ctx, ns, name, ref)
}
