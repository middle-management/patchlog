package dav

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
)

// Moves that copy (§H.5): a file moved onto an existing file, or across
// namespaces, is a copy and then a delete of the source.

// moveOnto moves live file src onto existing file dst (§H.5 "Move onto
// an existing file"): a save of src's content into dst, whose base is
// taken as a PUT's (§H.4), so dst keeps its history, then a delete of src
// as a DELETE deletes it. This is how "write a temporary file, rename it
// over" saves land. One document shown in both places isn't moved onto
// itself, and one whose source the grant can't delete (allows) is refused
// before anything is written. What only rules decide (§C.2) isn't known
// before the core is asked: such a refusal of the delete still leaves the
// copy.
func (st *reqState) moveOnto(ctx context.Context, src, dst target) error {
	st.onto = dst.path
	if src.docNS == dst.docNS && src.docName == dst.docName {
		return fail(http.StatusForbidden, "%s and %s are one document, %s/%s, shown in two places; delete the one you don't want", src.path, dst.path, src.docNS, src.docName)
	}
	if err := st.allows(ctx, src, src.docNS, "delete"); err != nil {
		return err
	}
	hd, b, err := st.copyOfFile(ctx, src)
	if err != nil {
		return err
	}
	if st.srcMatch != "" && hd.rev != st.srcMatch {
		return st.sourceMoved(src.path)
	}
	rev, _, err := st.commitRev(ctx, dst, b)
	if err != nil {
		return st.undoOwnDelete(ctx, dst, upstream(err))
	}
	if rev == "" {
		return notMoved(src, dst)
	}
	return st.deleteSource(ctx, src, dst, hd.rev, "")
}

// moveAcross moves live file src to dst, a new name in another namespace
// (§H.5 "Across namespaces"): a copy, a new resource with src's content (a raw file's blob copied with Blob-From
// where its rank allows, §7.8), then a delete of src; where its item is
// deleted, its last revision first takes $successor naming the copy
// (§8.1), unless its root isn't an object. One whose source the grant
// can't delete (allows) is refused before anything is written.
func (st *reqState) moveAcross(ctx context.Context, src, dst target) error {
	if err := st.allows(ctx, src, src.docNS, "delete"); err != nil {
		return err
	}
	hd, b, err := st.copyOfFile(ctx, src)
	if err != nil {
		return err
	}
	if st.srcMatch != "" && hd.rev != st.srcMatch {
		return st.sourceMoved(src.path)
	}
	// Its last revision takes $successor first, an append, where its root
	// is an object (deleteItem).
	e, err := st.entry(ctx, &hd)
	if err != nil {
		return err
	}
	if _, obj := e.value.(map[string]any); obj {
		if err := st.allows(ctx, src, src.docNS, "append"); err != nil {
			return err
		}
	}
	st.wroteTo = ""
	st.moving = true
	rev, _, err := st.commitRev(ctx, dst, b)
	st.moving = false
	if err != nil {
		return err
	}
	if rev == "" {
		return notMoved(src, dst)
	}
	succ := ""
	if ns, name, ok := strings.Cut(st.wroteTo, "/"); ok {
		succ = "/r/" + ns + "/" + name
		if ns == hd.ns {
			succ = name
		}
	}
	return st.deleteSource(ctx, src, dst, hd.rev, succ)
}

// copyOfFile reads live file src whole, for a copy: its content as its
// reader gets it (fileBytes), with its type and, for a raw file, its blob
// (copySrc), so the copy keeps the blob's id and copies it (§7.8).
func (st *reqState) copyOfFile(ctx context.Context, src target) (headDoc, []byte, error) {
	hd, live, err := st.docAt(ctx, src)
	switch {
	case err != nil:
		return hd, nil, err
	case !live:
		return hd, nil, errNotExist
	}
	b, err := st.fileBytes(ctx, &hd)
	if err != nil {
		return hd, nil, err
	}
	st.ctype, st.copySrc = hd.m.Type, nil
	if r := hd.m.raw; r != nil {
		st.copySrc = &blobSrc{ns: hd.ns, name: hd.name, ref: *r}
	}
	return hd, b, nil
}

// deleteSource deletes file src after its content, revision rev, went to
// dst (a MOVE): a flat namespace's resource; successor, if given, is where it went (§8.1).
// Only rev is deleted: an edit someone made to src meanwhile, which dst
// doesn't hold, leaves src as it is now, a 409.
func (st *reqState) deleteSource(ctx context.Context, src, dst target, rev, successor string) error {
	_, err := st.deleteItem(ctx, src.docNS, src.docName, rev, successor)
	if de, ok := upstream(err).(*davError); ok && de.status == http.StatusPreconditionFailed {
		return fail(http.StatusConflict, "%s was changed by someone else while it was moved: %s holds the version moved, and %s stays as it is now; reload both", src.path, dst.path, src.path)
	}
	if err == nil {
		st.s.forgetPath(st.p, src.path)
	}
	return err
}

// notMoved refuses a MOVE whose copy wrote nothing to the core (an empty
// placeholder), whose source isn't deleted for it.
func notMoved(src, dst target) error {
	return fail(http.StatusConflict, "%s wasn't written to the core, so %s isn't deleted", dst.path, src.path)
}

// allows refuses a MOVE of src whose delete takes verb in ns where the
// grant's verbs there (GET /ns/{ns}/principal can, §7.4) don't include
// it; where they aren't known (that read failed, an older core), the
// core's refusal of the delete is the answer.
func (st *reqState) allows(ctx context.Context, src target, ns, verb string) error {
	if can := st.s.nsInfo(ctx, st.tk, ns).can; can != nil && !can[verb] {
		return fail(http.StatusForbidden, "%s isn't moved: the grant doesn't allow %s in %s, which deleting it takes (§C.2), so it would stay where it is beside the copy; nothing was written", src.path, verb, ns)
	}
	return nil
}

// deleteItem tombstones ns/name (§8.1), if its head is ifMatch when that
// is given, and returns the tombstone; with successor, its last revision
// first sets $successor to it, in the same batch (§7.5), unless its root
// isn't an object, which can't carry one (§H.5).
func (st *reqState) deleteItem(ctx context.Context, ns, name, ifMatch, successor string) (string, error) {
	if successor == "" {
		return st.deleteDoc(ctx, ns, name, ifMatch)
	}
	in := st.s.nsInfo(ctx, st.tk, ns)
	var tomb string
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		if ifMatch != "" && h.ID != ifMatch {
			return false, fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", ns, name, ifMatch)
		}
		cur, err := st.s.doc(ctx, st.tk, ns, name, h.ID)
		if err != nil {
			return false, err
		}
		if _, obj := cur.value.(map[string]any); !obj {
			res, err := st.tk.c.Delete(ctx, ns, name, h.ID)
			if client.IsStale(err) {
				return true, nil
			}
			if err == nil {
				tomb = res.ID
				st.s.markOwn(st.p, ns, name, tomb)
			}
			return false, err
		}
		ps := withNonce(in, cur.value, []any{map[string]any{"op": "add", "path": "/$successor", "value": successor}})
		res, err := st.tk.c.Batch(ctx, ns, client.BatchRequest{Items: []client.BatchItem{{Resource: name, IfMatch: h.ID,
			Steps: []client.Step{client.PatchStep(ps), client.DeleteStep()}}}}, false)
		err = batchErr(err)
		if client.IsStale(err) {
			return true, nil
		}
		if err == nil && len(res.Items) == 1 && len(res.Items[0].IDs) == 2 {
			tomb = res.Items[0].IDs[1]
			st.s.markOwn(st.p, ns, name, tomb)
		}
		st.committed = st.committed || err == nil
		return false, err
	})
	if errors.Is(err, errNotExist) {
		return "", errNotExist
	}
	return tomb, err
}

// writes reports whether the request writes to the core where its paths
// lead (a COPY's source is read for the copy, which a stale name would
// misdirect too).
func (st *reqState) writes() bool {
	switch st.method {
	case "PUT", "DELETE", "MOVE", "COPY", "MKCOL":
		return true
	}
	return false
}
