package core

import (
	"context"
	"crypto/sha256"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// Blobs of remote branches (§G.3, §7.8).
//
// A remote branch reads through shadows that mirror the base's chains up
// front (remote_branch.go), and its base's blobs are mirrored with them:
// every blob a mirrored document references is fetched from the base's
// immutable /r/{ns}/{name}/blob/{bid}, verified against its id (§3.7) with
// the reference that names it, and attached to the shadow's resource at
// the revisions that reference it, as a write would (blob_refs and
// blobs). Branch availability and reads (historyBlob) then work as for a
// local branch, and the branch keeps the blobs whatever the base prunes or
// loses access to later ("mirror up front to be independent").

// remoteBlob is a blob fetched from the base and verified.
type remoteBlob struct {
	typ, nonce string
	data       []byte
}

// fetchBlobs fetches and verifies every blob that a document of ch
// references, from resource name of base namespace ns, whose view (as
// the base serves it, read-through included) has every document of ch.
// They are kept in ch.blobs, which prefixes share.
func fetchBlobs(ctx context.Context, c *client.Client, ns, name string, ch *remoteChain, mapErr func(string, error) *Error) *Error {
	if ch.opaque {
		// TODO(blobs-e2e): e2e documents are ciphertext; the blobs of an
		// e2e base are those its sealed ops declare (§E.3.1), mirrored
		// verbatim once core exposes the declared lists.
		return nil
	}
	refs := map[ids.ID]blobRef{}
	var order []ids.ID
	err := ch.fold(func(_ int, e client.LogEntry, doc any) error {
		if e.Kind != "rev" {
			return nil
		}
		for _, r := range blobRefsOf(doc) {
			if _, ok := refs[r.bid]; !ok {
				refs[r.bid] = r
				order = append(order, r.bid)
			}
		}
		return nil
	})
	if err != nil {
		return unverified("/r/%s/%s: %v", ns, name, err)
	}
	if ch.blobs == nil {
		ch.blobs = map[ids.ID]*remoteBlob{}
	}
	for _, bid := range order {
		if ch.blobs[bid] != nil {
			continue
		}
		r := refs[bid]
		what := "/r/" + ns + "/" + name + "/blob/" + bid.String()
		// TODO(blobs-sealed): a sealed (E2) base answers 302 to the blob's
		// sealed form (§E.2.2); fetching it needs the client to open
		// sealed blobs with the endpoint's keys, as it does sealed rows.
		b, err := c.GetBlob(ctx, ns, name, bid.String(), r.nonce)
		if err != nil {
			if _, api := client.AsAPIError(err); !api {
				// GetBlob's own check: bytes that don't hash to the id.
				return unverified("%s: %v", what, err)
			}
			return mapErr(what, err)
		}
		typ, _ := parseBlobType(b.Type)
		if typ != r.typ || int64(len(b.Data)) != r.size {
			return unverified("%s doesn't match the reference's type or size", what)
		}
		ch.blobs[bid] = &remoteBlob{typ: typ, nonce: r.nonce, data: b.Data}
	}
	return nil
}

// attachMirrored records the blobs that doc, the document of mirrored
// revision seq of res, references, and attaches them (attachStep), storing
// the bytes fetched from the base. A reference whose blob wasn't fetched
// (a mirrored schema has none) is neither recorded nor attached.
func (t *tx) attachMirrored(res int64, ch *remoteChain, doc any, seq int64) {
	step := &stepState{blobs: map[ids.ID]*blobRow{}}
	owner := t.bytesOwner(res)
	for _, r := range blobRefsOf(doc) {
		b := ch.blobs[r.bid]
		if b == nil || step.blobs[r.bid] != nil {
			continue
		}
		h := sha256.Sum256(b.data)
		t.putBytes(owner, h[:], b.data)
		step.blobs[r.bid] = &blobRow{res: res, bid: r.bid, typ: b.typ, nonce: b.nonce, size: int64(len(b.data)), hash: h[:], owner: owner}
	}
	t.attachStep(res, step, seq)
}
