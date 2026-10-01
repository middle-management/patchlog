package bundle

import (
	"mime"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schema"
)

// Blobs in bundles (§G.4.1, §G.4.4, §7.8).
//
//   - Export: every blob that an exported revision of a full document, or a
//     snapshot, references gets a blob line, once per resource, right before
//     the first line whose document references it. Incremental bundles
//     leave out the blobs the history up to requires already references
//     (the target has them). The bytes are read from the source's
//     /r/{ns}/{name}/blob/{bid}, which serves a branch's read-through blobs
//     too, and checked against the id with the reference's type and nonce.
//     A sealed (E2) source never serves a blob's plaintext: its /blob/{bid}
//     answers 302 to the blob sealed under an epoch (§E.2.2), which the
//     client follows and opens with its keys, checking the plaintext
//     against the reference (client.GetBlobRef). The blob line carries the
//     plaintext, like every line of a sealed namespace (§G.5: E2), and a
//     sealed bundle seals it like any other line (§G.5.1.1). An e2e source
//     serves the writer's ciphertext, which the line carries verbatim.
//   - References are found by walking the documents (§7.8), schema
//     documents excepted. At E3 the documents are ciphertext and the
//     sealed op declares the blobs in plaintext (§E.3.1): a revision's
//     blobs are its op's list (a restore with [] keeps the previous one, so
//     it brings nothing new), each of type SealedBlobType and without a
//     nonce.
//   - Import: the Reader recomputes every blob id; a blob line that comes
//     after a line referencing it is rejected. Before a batch is dry-run or
//     submitted, the blobs its steps reference are uploaded to each item's
//     target resource, as the importer, so they are pending for the
//     principal that submits the batch. Within one deployment they are
//     copied with Blob-From from the source resource instead, and a copy
//     the server refuses falls back to uploading the bundle's bytes. A
//     snapshot document's blobs go to its upstream resource and its target;
//     a blob of the upstream chain that the bundle doesn't carry (an
//     earlier import's) is copied into the target from the upstream
//     resource. Uploads older than half the namespace's blobGrace are
//     repeated before the submit, since pending blobs expire (§G.4.4). A
//     dry-run import uploads nothing, so its blob failures are reported as
//     deferred.
//   - Which blobs a step references is over-approximated from the values
//     its patch ops write (references in them, and ids written at …/$blob,
//     as diffs do): a reference a step keeps from the document it applies
//     to is attached in the target already. The import's order check uses
//     the same rule, and so does the export when it places blob lines.

// SealedBlobType is the media type of an e2e namespace's blobs (§E.3.1).
const SealedBlobType = "application/vnd.patchlog.sealed-blob"

// blobRef is a blob reference in a document (§7.8). size is the
// reference's, which a sealed source's blobs are checked against (§E.2.2);
// a declared e2e blob has none (0).
type blobRef struct {
	bid, typ, nonce string
	size            int
}

// docBlobs lists the blob references of a document, in document order,
// each blob once. Schema documents have none (§7.8).
func docBlobs(doc any) []blobRef {
	if m, ok := doc.(map[string]any); ok {
		if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
			return nil
		}
	}
	var out []blobRef
	seen := map[string]bool{}
	walkBlobs(doc, func(r blobRef) {
		if !seen[r.bid] {
			seen[r.bid] = true
			out = append(out, r)
		}
	})
	return out
}

// walkBlobs calls fn for every well-formed-looking blob reference in v.
func walkBlobs(v any, fn func(blobRef)) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			walkBlobs(e, fn)
		}
	case map[string]any:
		if s, ok := x["$blob"].(string); ok {
			if validID(s) {
				r := blobRef{bid: s}
				r.typ, _ = x["type"].(string)
				r.typ = normType(r.typ)
				r.nonce, _ = x["nonce"].(string)
				if f, ok := x["size"].(float64); ok {
					r.size = int(f)
				}
				fn(r)
			}
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkBlobs(x[k], fn)
		}
	}
}

// normType is a media type as §3.7 hashes it: lowercased, without
// parameters.
func normType(s string) string {
	if mt, _, err := mime.ParseMediaType(s); err == nil {
		return strings.ToLower(mt)
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// sealedBlobs returns the blobs an e2e patch set declares (§E.3.1): the
// list of its sealed op. ok is false for a patch set without one (a
// restore with [] keeps the previous list).
func sealedBlobs(patches any) (bids []string, ok bool) {
	ops, _ := patches.([]any)
	for _, o := range ops {
		m, _ := o.(map[string]any)
		if m["op"] != "sealed" {
			continue
		}
		ok = true
		list, _ := m["blobs"].([]any)
		for _, b := range list {
			if s, isStr := b.(string); isStr && validID(s) {
				bids = append(bids, s)
			}
		}
	}
	return bids, ok
}

// revisionBlobs lists the blobs a revision references: those of its
// document, or at E3 those its patch set declares.
func revisionBlobs(e2e bool, patches, doc any) []blobRef {
	if !e2e {
		return docBlobs(doc)
	}
	bids, _ := sealedBlobs(patches)
	out := make([]blobRef, len(bids))
	for i, b := range bids {
		out[i] = blobRef{bid: b, typ: SealedBlobType}
	}
	return out
}

// stepBlobs over-approximates the blobs a step references that it may
// bring into the document: references in the values its ops write, ids
// written at …/$blob, and at E3 the blobs its sealed op declares.
func stepBlobs(s client.Step) []string {
	if s.Delete || s.Patches == nil {
		return nil
	}
	v, err := client.ToValue(s.Patches)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(b string) {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	if bids, ok := sealedBlobs(v); ok {
		for _, b := range bids {
			add(b)
		}
		return out
	}
	ops, _ := v.([]any)
	for _, o := range ops {
		m, _ := o.(map[string]any)
		if m["op"] == "test" {
			continue
		}
		val, has := m["value"]
		if !has {
			continue
		}
		walkBlobs(val, func(r blobRef) { add(r.bid) })
		// A diff may replace only a reference's id (…/$blob).
		if p, _ := m["path"].(string); strings.HasSuffix(p, "/$blob") {
			if s, ok := val.(string); ok && validID(s) {
				add(s)
			}
		}
	}
	return out
}
