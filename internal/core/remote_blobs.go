package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
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
//
// Encrypted bases (§G.5.2):
//
//   - E2. A sealed base never serves a blob's plaintext: its /blob/{bid}
//     answers 302 to the blob sealed under an epoch (§E.2.2). The client
//     follows it and opens the blob with the keys it opens the base's
//     sealed revisions with (the endpoint's grant gets K_e, or K_r for a
//     per-resource grant, from the base's POST /ns/{ns}/keys), then checks
//     it against the reference. The shadows hold the plaintext, as they
//     hold the documents', and the branch seals it under its own epoch
//     keys when it serves it.
//   - E3. The documents are ciphertext, so the blobs are those the sealed
//     ops declare in plaintext (§E.3.1): each revision's list, or for a
//     restore with [] the last live document's. The bytes are the writer's
//     ciphertext, mirrored verbatim, of SealedBlobType and without a nonce,
//     and verified against the id; their keys travel in the sealed
//     references, which only readers open. Each revision's list is
//     recorded in blob_refs and attached, as a sealed write does.

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
	if ch.blobs == nil {
		ch.blobs = map[ids.ID]*remoteBlob{}
	}
	if ch.opaque {
		return fetchDeclared(ctx, c, ns, name, ch, mapErr)
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
	for _, bid := range order {
		if ch.blobs[bid] != nil {
			continue
		}
		r := refs[bid]
		what := "/r/" + ns + "/" + name + "/blob/" + bid.String()
		// GetBlobRef follows a sealed base's 302 and opens the blob with
		// the endpoint's keys (§E.2.2); a plaintext base serves it as is.
		// Either way the bytes are checked against the reference.
		b, err := c.GetBlobRef(ctx, ns, name, client.BlobRef(bid.String(), r.typ, int(r.size), r.nonce))
		if err != nil {
			return blobFetchErr(what, err, mapErr)
		}
		typ, _ := parseBlobType(b.Type)
		if typ != r.typ || int64(len(b.Data)) != r.size {
			return unverified("%s doesn't match the reference's type or size", what)
		}
		ch.blobs[bid] = &remoteBlob{typ: typ, nonce: r.nonce, data: b.Data}
	}
	return nil
}

// fetchDeclared fetches and verifies the blobs an e2e chain's sealed ops
// declare (§E.3.1): the writer's ciphertext, of SealedBlobType and without
// a nonce, as the base serves it.
func fetchDeclared(ctx context.Context, c *client.Client, ns, name string, ch *remoteChain, mapErr func(string, error) *Error) *Error {
	lists, err := ch.declaredLists()
	if err != nil {
		return unverified("/r/%s/%s: %v", ns, name, err)
	}
	for _, list := range lists {
		for _, bid := range list {
			if ch.blobs[bid] != nil {
				continue
			}
			what := "/r/" + ns + "/" + name + "/blob/" + bid.String()
			b, err := c.GetBlob(ctx, ns, name, bid.String(), "")
			if err != nil {
				return blobFetchErr(what, err, mapErr)
			}
			if typ, _ := parseBlobType(b.Type); typ != SealedBlobType {
				return unverified("%s is of type %q; an e2e blob is a sealed blob (§E.3.1)", what, b.Type)
			}
			ch.blobs[bid] = &remoteBlob{typ: SealedBlobType, data: b.Data}
		}
	}
	return nil
}

// blobFetchErr maps a failed blob fetch: an answer from the base, or keys
// this deployment can't get, as mapErr does; anything else (bytes that
// don't match the reference, a sealing that doesn't open) is unverified.
func blobFetchErr(what string, err error, mapErr func(string, error) *Error) *Error {
	if _, api := client.AsAPIError(err); api || errors.Is(err, client.ErrNoKeys) {
		return mapErr(what, err)
	}
	return unverified("%s: %v", what, err)
}

// declaredLists lists, for each entry of an e2e chain, the blobs its
// resulting document references as the server knows them (§E.3.1): a
// revision's declared list, for a restore with [] the last live
// document's, and nil for a tombstone.
func (c *remoteChain) declaredLists() ([][]ids.ID, error) {
	out := make([][]ids.ID, len(c.entries))
	var last []ids.ID
	for i, e := range c.entries {
		if e.Kind != "rev" {
			continue
		}
		if !e.HasPatches {
			return nil, fmt.Errorf("revision %s has no patch set", e.ID)
		}
		if string(jsonv.Canonical(e.Patches)) != "[]" {
			_, list, ok := seal.SealedOp(e.Patches)
			if !ok {
				return nil, fmt.Errorf("revision %s is not one sealed op (§E.3.1)", e.ID)
			}
			ds, derr := parseDeclared(list)
			if derr != nil {
				return nil, fmt.Errorf("revision %s: malformed declared blob list (§E.3.1)", e.ID)
			}
			last = ds
		}
		out[i] = last
	}
	return out, nil
}

// attachMirrored records the blobs that doc, the document of mirrored
// revision seq of res, references, and attaches them (attachFetched).
func (t *tx) attachMirrored(res int64, ch *remoteChain, doc any, seq int64) {
	refs := blobRefsOf(doc)
	bids := make([]ids.ID, len(refs))
	for i, r := range refs {
		bids[i] = r.bid
	}
	t.attachFetched(res, ch, bids, seq)
}

// attachFetched records bids as the blobs the document of mirrored
// revision seq of res references, and attaches them (attachStep), storing
// the bytes fetched from the base; at E3 bids is the revision's declared
// list (declaredLists). A blob that wasn't fetched (a mirrored schema has
// none) is neither recorded nor attached.
func (t *tx) attachFetched(res int64, ch *remoteChain, bids []ids.ID, seq int64) {
	step := &stepState{blobs: map[ids.ID]*blobRow{}}
	owner := t.bytesOwner(res)
	for _, bid := range bids {
		b := ch.blobs[bid]
		if b == nil || step.blobs[bid] != nil {
			continue
		}
		h := sha256.Sum256(b.data)
		t.putBytes(owner, h[:], b.data)
		step.blobs[bid] = &blobRow{res: res, bid: bid, typ: b.typ, nonce: b.nonce, size: int64(len(b.data)), hash: h[:], owner: owner}
	}
	t.attachStep(res, step, seq)
}
