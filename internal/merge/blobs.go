package merge

import (
	"context"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
)

// Blobs (§F.3, §7.8). A batch's local source makes the branch's blobs
// available only to a merger with unrestricted read on the branch, by its
// own grant or one in Source-Authorization (§7.5); any other merger copies
// each blob its items reference into the target resource first (Blob-From),
// and uploads the bytes where the ranks refuse the copy (§2.1: a 404).
// Copies and uploads are pending blobs of the batch's own principal, so
// they go with the batch client; they are idempotent, and a plan makes
// each only once.

// readsBranch reports whether the batch's principal, or a grant in
// SourceAuthorizations, has unrestricted read on the branch: GET
// /ns/{branch}/branches needs exactly that (§7.4).
func (p *Plan) readsBranch(ctx context.Context) (bool, error) {
	if p.unrestricted != nil {
		return *p.unrestricted, nil
	}
	bc := p.batchClient()
	clients := []*client.Client{bc}
	for _, g := range p.opt.SourceAuthorizations {
		clients = append(clients, bc.With(client.WithBearer(g)))
	}
	ok := false
	for _, c := range clients {
		_, err := c.Branches(ctx, p.Branch)
		if err == nil {
			ok = true
			break
		}
		if _, api := client.AsAPIError(err); !api {
			return false, err
		}
	}
	p.unrestricted = &ok
	return ok, nil
}

// copyBlobs makes the blobs the items reference available in the target
// where the batch's source doesn't (see above).
func (p *Plan) copyBlobs(ctx context.Context) error {
	items := p.Items()
	if len(items) == 0 {
		return nil
	}
	ok, err := p.readsBranch(ctx)
	if err != nil || ok {
		return err
	}
	if p.copied == nil {
		p.copied = map[string]bool{}
	}
	bc := p.batchClient()
	for _, r := range items {
		refs, err := p.newBlobRefs(ctx, r)
		if err != nil {
			return fmt.Errorf("merge: blobs of %s: %w", r.Name, err)
		}
		for _, bid := range sortedKeys(refs) {
			key := r.Name + "/" + bid
			if p.copied[key] {
				continue
			}
			err := bc.CopyBlobWith(ctx, p.Target, r.Name, bid, p.Branch, r.Name, p.opt.SourceAuthorizations...)
			if client.IsNotFound(err) {
				// The ranks refuse the copy, or the source doesn't serve it
				// to this caller: upload the bytes (§F.3, §2.1).
				err = p.uploadBlob(ctx, r.Name, refs[bid])
			}
			if err != nil {
				return fmt.Errorf("merge: making blob %s of %s/%s available in %s: %w", bid, p.Branch, r.Name, p.Target, err)
			}
			p.copied[key] = true
		}
	}
	return nil
}

// uploadBlob reads a blob from the branch and uploads it to the target
// resource with its id: the reference's type and nonce, and at E3 the
// ciphertext as stored (§E.3.1: blobs keep their ids).
func (p *Plan) uploadBlob(ctx context.Context, name string, ref map[string]any) error {
	stored := make(map[string]any, len(ref))
	for k, v := range ref {
		if k != "sealed" {
			stored[k] = v
		}
	}
	b, err := p.c.GetBlobRef(ctx, p.Branch, name, stored)
	if err != nil {
		return err
	}
	typ, _ := ref["type"].(string)
	nonce, _ := ref["nonce"].(string)
	_, err = p.batchClient().UploadBlob(ctx, p.Target, name, typ, nonce, b.Data)
	return err
}

// newBlobRefs returns the blob references of the documents r's steps
// produce in the target that its document at B doesn't have, by id.
func (p *Plan) newBlobRefs(ctx context.Context, r *Resource) (map[string]map[string]any, error) {
	var doc any
	var err error
	switch {
	case r.IfNoneMatch:
	case r.BaseState == client.Live.String():
		doc, err = p.doc(ctx, p.Target, r.Name, r.Base)
	case r.BaseState == client.Tombstoned.String() && r.baseLast != "":
		doc, err = p.doc(ctx, p.Target, r.Name, r.baseLast)
	}
	if err != nil {
		return nil, err
	}
	have := blobRefs(doc)
	out := map[string]map[string]any{}
	doc = jsonv.Clone(doc)
	for _, s := range r.Steps {
		if s.Delete {
			continue
		}
		v, err := client.ToValue(s.Patches)
		if err != nil {
			return nil, err
		}
		ops, err := patch.Parse(v)
		if err != nil {
			return nil, err
		}
		// A create applies to null (§6.2 step 3).
		if doc, _, err = patch.Apply(doc, true, ops, patch.Options{InPlace: true}); err != nil {
			return nil, err
		}
		for bid, ref := range blobRefs(doc) {
			if _, ok := have[bid]; !ok {
				out[bid] = ref
			}
		}
	}
	return out, nil
}

// blobRefs lists the blob references in a document by id (§7.8: objects
// whose $blob member is a string, at any depth; schema documents have
// none).
func blobRefs(doc any) map[string]map[string]any {
	out := map[string]map[string]any{}
	if m, ok := doc.(map[string]any); ok {
		if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
			return out
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			if s, ok := x["$blob"].(string); ok {
				out[s] = x
				return
			}
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	return out
}

// undeclarableBlob names a blob reference in doc that a sealed op can't
// declare (§E.3.1): one whose type isn't the sealed type, or that has a
// nonce, such as one from before a raise to e2e (Addendum E, Levels). ""
// if there is none.
func undeclarableBlob(doc any) string {
	refs := blobRefs(doc)
	for _, bid := range sortedKeys(refs) {
		ref := refs[bid]
		typ, _ := ref["type"].(string)
		nonce, _ := ref["nonce"].(string)
		switch {
		case typ != client.SealedBlobType:
			return fmt.Sprintf("blob %s of type %q", bid, typ)
		case nonce != "":
			return fmt.Sprintf("blob %s with a nonce", bid)
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
