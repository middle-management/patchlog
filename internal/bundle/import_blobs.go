package bundle

import (
	"context"
	"fmt"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// Blobs first (§G.4.4): what an import uploads or copies before each
// batch (blobs.go has the overview).

// blobNeed is a blob a batch's item may bring into its target resource.
type blobNeed struct {
	it  *item
	bid string
}

// batchBlobs lists the blobs a batch's steps may bring in, per item.
func (im *importer) batchBlobs(b *batch) []blobNeed {
	var out []blobNeed
	seen := map[string]bool{}
	for _, p := range b.parts {
		for i := p.from; i < p.to && i < len(p.it.blobs); i++ {
			for _, bid := range p.it.blobs[i] {
				k := p.it.ns + "/" + p.it.name + "/" + bid
				if !seen[k] {
					seen[k] = true
					out = append(out, blobNeed{it: p.it, bid: bid})
				}
			}
		}
	}
	return out
}

// sendBlobs makes the blobs a batch references pending for the importer
// in each item's target resource, before the batch is dry-run or submitted
// (§G.4.4): copied with Blob-From within one deployment, else uploaded
// from the bundle. Blobs sent less than half the namespace's blobGrace ago
// are not sent again. A blob the bundle doesn't carry is left to the
// target, which has it unless the batch fails with code "blob"; for a
// snapshot document's target it is copied from its upstream resource.
func (im *importer) sendBlobs(ctx context.Context, b *batch, l limits) error {
	if im.sent == nil {
		im.sent = map[string]time.Time{}
	}
	for _, nd := range im.batchBlobs(b) {
		it := nd.it
		k := it.ns + "/" + it.name + "/" + nd.bid
		if t, ok := im.sent[k]; ok && time.Since(t) < l.blobGrace/2 {
			continue
		}
		line := it.d.blobs[nd.bid]
		switch {
		case line != nil && im.local && im.copyBlob(ctx, it.ns, it.name, nd.bid, it.d.ns, it.d.name):
			b.rep.Copied++
		case line != nil:
			if im.h.AccessOf(it.d.ns) == AccessE2E && normType(line.Type) != SealedBlobType {
				// An e2e target takes only the writers' ciphertext (§E.3.1),
				// which the line carries verbatim; it would answer 415.
				return fmt.Errorf("import: blob %s of e2e namespace %s is of type %q, not %s: an e2e target accepts only sealed blobs (§E.3.1)",
					nd.bid, it.d.ns, line.Type, SealedBlobType)
			}
			err := im.retry(ctx, func() error {
				bid, err := im.c.UploadBlob(ctx, it.ns, it.name, line.Type, line.Nonce, line.Data)
				if err == nil && bid != nd.bid {
					err = fmt.Errorf("uploaded as %s", bid)
				}
				return err
			})
			if err != nil {
				if ae, ok := client.AsAPIError(err); ok && ae.Status == 413 {
					return fmt.Errorf("import: uploading blob %s to %s/%s: %w; a large import needs an allowance that raises the importer's blobPending (§6.6, §G.4.4)", nd.bid, it.ns, it.name, err)
				}
				return fmt.Errorf("import: uploading blob %s to %s/%s: %w", nd.bid, it.ns, it.name, err)
			}
			b.rep.Uploaded++
		case !it.upstream && it.d.info.History == Snapshot && im.up[it.d.key] != nil:
			// A blob of the upstream chain, from an earlier import.
			u := im.up[it.d.key]
			if !im.copyBlob(ctx, it.ns, it.name, nd.bid, u.ns, u.name) {
				continue
			}
			b.rep.Copied++
		default:
			continue
		}
		im.sent[k] = time.Now()
	}
	return nil
}

// copyBlob copies a blob within the deployment (§7.8 Copying) and reports
// whether the server did. A source it can't serve or read, or of a higher
// rank than the target, answers 404, and the caller falls back.
func (im *importer) copyBlob(ctx context.Context, ns, name, bid, fromNS, fromName string) bool {
	return im.retry(ctx, func() error { return im.c.CopyBlob(ctx, ns, name, bid, fromNS, fromName, "") }) == nil
}

// retry runs fn, again after 429, 5xx and transport errors, as call does.
func (im *importer) retry(ctx context.Context, fn func() error) error {
	backoff := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || !client.Retryable(err) || attempt >= im.opt.MaxRetries || ctx.Err() != nil {
			return err
		}
		wait := backoff
		if ae, ok := client.AsAPIError(err); ok && ae.RetryAfter > 0 {
			wait = ae.RetryAfter
		}
		backoff *= 2
		if err := im.opt.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}
