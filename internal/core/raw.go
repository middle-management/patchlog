package core

import (
	"context"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// Raw is the answer for GET /r/{ns}/{name}/raw and …/rev/{id}/raw (§7.1,
// §7.8). Every answer but a live raw document's is that of the document URL
// it stands for: Head for /raw (ResourceHead), Rev for /rev/{id}/raw
// (ResourceRev). For a live document, Blob is the blob its root references
// (302 to …/blob/{Blob}), or "" if it isn't raw (404 not_found).
type Raw struct {
	Head *Head // /raw: the head pointer's answer; for a live head, its id
	Rev  *Rev  // the document's answer, when it was read
	Blob string
	// Public is the namespace's visibility, for the cache class.
	Public bool
}

// ResourceRaw serves a raw document's URL (§7.1): id "" for …/raw, at the
// head, or a revision id. The order is the read check (the ordinary one:
// a schemaReads referrer opens only revision paths, §6.1), a purged
// namespace's 410 (§8.5), a purged resource's 410, the document URL's
// (§8.3), then 404 not_offered in a namespace serving it that is sealed or
// e2e, the keyring included (the blob is sealed, or the root can't be
// seen), and then the answers of the document URL.
func (e *Engine) ResourceRaw(ctx context.Context, ns, name, id string, cred Credentials) (*Raw, error) {
	out := &Raw{}
	err := e.gateRead(ctx, func(t *gate) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		if n.purged {
			return t.purgedRead(n)
		}
		out.Public = t.cachePublic(n)
		if t.nsLevel(n) >= levelSealed && t.resolve(n, name, nil).state != Purged {
			return rawNotOffered(out.Public)
		}
		// A purged resource, of any level, answers as its document URL
		// below: 410, before not_offered (§8.3).
		return nil
	})
	if err != nil {
		return nil, err
	}
	if id == "" {
		h, err := e.ResourceHead(ctx, ns, name, cred)
		if err != nil || h.State != Live {
			out.Head = h
			return out, err
		}
		out.Head, id = h, h.Head
	}
	rev, err := e.ResourceRev(ctx, ns, name, id, cred)
	if err != nil {
		return nil, err
	}
	out.Rev = rev
	if rev.Status != 200 {
		return out, nil
	}
	if rev.JWE != "" || rev.Snapshot || rev.Doc == nil {
		// Raised to sealed since the check above.
		return nil, rawNotOffered(out.Public)
	}
	if doc, err := jsonv.Parse(rev.Doc); err == nil {
		out.Blob = RawBlob(doc)
	}
	return out, nil
}

// rawNotOffered is …/raw in a sealed or e2e namespace (§7.1). Public is
// for the server's cache class: as the document URL's, since a level is
// never lowered.
func rawNotOffered(public bool) *Error {
	e := apiErr(404, "not_offered", "message", "raw documents aren't served in sealed or end-to-end namespaces (§7.1)")
	e.Public = &public
	return e
}

// RawBlob is the blob id of a raw document (§7.8): one whose root is a blob
// reference, { "$blob", "type", "size", "nonce"? }, with no other members
// than the top-level ones validation leaves out ($schema, a fresh $nonce,
// a well-formed $successor, §6.2 step 5). "" for any other document, a
// schema document included, whose $schema is a dialect and which holds no
// references.
func RawBlob(doc any) string {
	m, ok := doc.(map[string]any)
	if !ok {
		return ""
	}
	bid, ok := m["$blob"].(string)
	if !ok {
		return ""
	}
	if _, err := ids.Parse(bid); err != nil {
		return ""
	}
	if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
		return ""
	}
	if _, ok := m["type"].(string); !ok {
		return ""
	}
	if _, ok := m["size"].(float64); !ok {
		return ""
	}
	for k, v := range m {
		switch {
		case k == "$blob", k == "type", k == "size":
		case k == "nonce":
			if _, ok := v.(string); !ok {
				return ""
			}
		case schema.LeftOut(k, v):
		default:
			return ""
		}
	}
	return bid
}
