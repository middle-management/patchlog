package dav

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// parseBody parses a written JSON file as I-JSON (§3.1), a UTF-8 byte
// order mark aside: anything else is 400 and nothing is written (§H.1).
func parseBody(body []byte) (any, error) {
	body = trimBOM(body)
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "not a JSON document (I-JSON, §3.1), as a JSON file's content must be (§H.1): %v; nothing was written", err)
	}
	return v, nil
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// dropNonce is doc without its top-level $nonce, which a create where
// nonces apply replaces with a fresh one (§C.7).
func dropNonce(doc any) any {
	m, ok := doc.(map[string]any)
	if _, has := m["$nonce"]; !ok || !has {
		return doc
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != "$nonce" {
			out[k] = v
		}
	}
	return out
}

// withNonce adds a fresh $nonce at the end of patches where ns needs one
// (§C.7), to doc, the document they result in, if its root is an object
// that can carry one (nil: unknown, taken as one).
func withNonce(in nsInfo, doc any, patches []any) []any {
	if _, obj := doc.(map[string]any); !in.nonce || doc != nil && !obj {
		return patches
	}
	return append(patches, map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
}

// rootRefused refuses JSON file v of namespace ns where nonces are
// required (§C.7): its root must be an object, which carries $nonce
// (§H.1).
func rootRefused(in nsInfo, ns string, v any) error {
	if _, obj := v.(map[string]any); obj || !in.nonceRequired {
		return nil
	}
	return fail(http.StatusUnprocessableEntity, "namespace %s requires a fresh $nonce in every write (§C.7), which a JSON file carries at its root, so its root must be an object, not %s (§H.1); nothing was written", ns, jsonKind(v))
}

// jsonKind names a JSON value's kind, for messages.
func jsonKind(v any) string {
	switch v.(type) {
	case []any:
		return "an array"
	case string:
		return "a string"
	case float64:
		return "a number"
	case bool:
		return "a boolean"
	case nil:
		return "null"
	}
	return "an object"
}

// saveOpts say how a save treats what is there: pre, the document is the
// PUT's file, whose preconditions hold for it; fresh, it only creates (a
// tree's new item: a name that exists or existed is a 409, never edited
// or restored); fname, the file's name, which types a raw file
// (fileType).
type saveOpts struct {
	pre, fresh bool
	fname      string
}

// taken is a fresh save's refusal of ns/name, which exists or existed.
func taken(ns, name string) error {
	return fail(http.StatusConflict, "%s/%s, the name drawn for a new file, exists or existed already; try again", ns, name)
}

// commitDoc writes v, uploaded as body, as JSON file ns/name (§H.1). It
// returns the revision holding it, and whether that revision's rendering
// is exactly v (else the upload was merged with others' edits, and the
// revision is no validator of it). A new name is created (If-None-Match:
// *); a tombstoned one restored (one name keeps one chain, §8.2); a live
// one edited: the edit from its base (base) to v, rebased on the head and
// appended with If-Match (§11.3, §H.4).
func (st *reqState) commitDoc(ctx context.Context, ns, name string, v any, body []byte, o saveOpts) (string, bool, error) {
	in := st.s.nsInfo(ctx, st.tk, ns)
	if in.sealed {
		return "", false, notOffered(ns)
	}
	if err := rootRefused(in, ns, v); err != nil {
		return "", false, err
	}
	var rev string
	var exact bool
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.tk.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		switch {
		case o.fresh && h.State != client.NotFound:
			return false, taken(ns, name)
		case h.State == client.Purged:
			return false, purgedErr(ns, name)
		case h.State == client.Live:
			if o.pre && st.noneMatch {
				return false, fail(http.StatusPreconditionFailed, "%s/%s exists (If-None-Match: *)", ns, name)
			}
			r, x, retry, err := st.edit(ctx, in, ns, name, h.ID, v, body)
			rev, exact = r, x
			return retry, err
		}
		if o.pre && st.matchAny && !st.placeholder {
			return false, fail(http.StatusPreconditionFailed, "%s/%s doesn't exist (If-Match: *)", ns, name)
		}
		if o.pre && st.ifMatch != "" && h.State == client.NotFound {
			return false, noRevision(ns, name, st.ifMatch)
		}
		var res *client.WriteResult
		var parent, out any = map[string]any{}, nil
		var ps []any
		var atBase bool
		if h.State == client.NotFound {
			doc := v
			if in.nonce {
				doc = dropNonce(v)
			}
			ps = withNonce(in, doc, client.GenesisPatches(doc))
			res, err = st.tk.c.Create(ctx, ns, name, ps)
			err = tooLarge(err, true)
		} else if parent, ps, out, atBase, err = st.restorePatches(ctx, in, ns, name, h, v); err == nil {
			// Over opsPerSet or patchSetSize, a restore from the version
			// the client had is written whole, as an edit is (§H.4).
			over := setOver(in, ps)
			if over != nil && !atBase {
				return false, over
			}
			whole := over != nil
			if whole {
				ps = wholeDoc(in, parent, out)
			}
			res, err = st.tk.c.Restore(ctx, ns, name, h.ID, ps)
			if atBase && !whole && setTooLarge(err) {
				ps = wholeDoc(in, parent, out)
				res, err = st.tk.c.Restore(ctx, ns, name, h.ID, ps)
			}
			err = tooLarge(err, atBase)
			if err == nil {
				st.s.markOwn(st.p, ns, name, res.ID)
			}
		} else {
			return false, err
		}
		if client.IsStale(err) || client.IsGone(err) && !client.IsPurged(err) {
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile; reload it", ns, name)
		}
		if err != nil {
			return false, err
		}
		rev, exact = res.ID, st.wrote(ns, name, parent, ps, writesOf(parent, ps), res, v, body, rendersAs(v))
		return false, nil
	})
	return rev, exact, err
}

// noRevision is a save's 412 for an If-Match naming no revision of
// ns/name, which never existed (§H.4 "Answers").
func noRevision(ns, name, rev string) error {
	return fail(http.StatusPreconditionFailed, "%s/%s has no revision %s (If-Match): it doesn't exist; reload it", ns, name, rev)
}

// restorePatches is the patch set writing v over tombstoned ns/name, and
// the last live document it applies to (§8.2), as tombBase says: a write
// moments after the principal's own DELETE (an editor's, or a client's
// that creates only) restores the file with the edit from its base
// rebased on the last live document, as a save over a live one is, so
// others' edits are kept (without a base, the last live document is the
// base, and the file as written wins); any other write is a new file, the
// root replaced, which drops a $successor (§8.1), as does one over a raw
// file's last document (another file now) or a pruned one (§8.6). It
// returns the rebased document too, and whether its base is the last
// live document, from which it may be written whole (§H.4).
func (st *reqState) restorePatches(ctx context.Context, in nsInfo, ns, name string, h *client.Head, v any) (parent any, ps []any, out any, atBase bool, err error) {
	last, err := st.tombBase(ctx, ns, name, h)
	switch {
	case err != nil:
		return nil, nil, nil, false, err
	case last == nil, last.raw != nil:
		doc := v
		if in.nonce {
			doc = dropNonce(v)
		}
		return map[string]any{}, withNonce(in, doc, []any{map[string]any{"op": "replace", "path": "", "value": doc}}), doc, true, nil
	}
	out, atBase, err = st.rebased(ctx, ns, name, v, h.Last, last.value)
	if err != nil {
		return nil, nil, nil, false, err
	}
	return last.value, withNonce(in, out, merge.Diff(files.Bare(last.value), out)), out, atBase, nil
}

// tombBase says how a write over tombstoned ns/name, head h, goes (§H.6
// "Delete, then write", §H.4): restored rebased on the last live
// document, which it returns, when the principal's own DELETE wrote h
// within ownDeleteUndo; a 409 when the principal has a base from before
// someone else's delete (§11.3), whose reload (a GET finding the file
// gone) lets the write make a new file; a 409 naming where it went for
// a file moved away, whose last revision has $successor (§8.1), which no
// save makes anew, before or after that reload (movedAway, §H.2 "Flat
// view", §H.4 "The reload"), though a MOVE of a live file there does, a
// rename back included (moving); else nil: a new file, but not by a
// token refused a save of it that hasn't read it since (refusedSave).
func (st *reqState) tombBase(ctx context.Context, ns, name string, h *client.Head) (*docEntry, error) {
	last, err := st.tombLast(ctx, ns, name, h)
	if err == nil && last == nil {
		// A new file, written over the tombstone: not by a token refused
		// a save of it and that hasn't read it since.
		err = st.refusedSave(ns, name)
	}
	return last, err
}

// tombLast is tombBase but for refusedSave.
func (st *reqState) tombLast(ctx context.Context, ns, name string, h *client.Head) (*docEntry, error) {
	own := st.p.deletedOwn(ns, name, h.ID, st.s.opt.Now())
	if !own && !st.s.ownEntry(st.p, ns, name, h.ID) && st.hasBase(ns, name) {
		st.refuse(ns, name)
		return nil, fail(http.StatusConflict, "%s/%s was deleted by someone else since you opened it (§11.3, §H.4): your save isn't written over the delete; reload it (it reads as gone), and save it again to make it anew", ns, name)
	}
	var last *docEntry
	if h.Last != "" {
		var err error
		last, err = st.s.doc(ctx, st.tk, ns, name, h.Last)
		switch {
		case pruned(err):
			last = nil
		case err != nil:
			return nil, err
		case last.sealed:
			// Successors aren't trusted where the gateway can't read them
			// (sealed, F-H11): a new file.
			return nil, nil
		}
	}
	if !st.moving {
		if err := movedAway(ns, name, h, last); err != nil {
			return nil, err
		}
	}
	if !own || last == nil {
		return nil, nil
	}
	return last, nil
}

// movedAway refuses a new file over tombstoned ns/name, head h, last live
// document last (nil where unknown), whose last revision has $successor
// (§8.1): it moved, and no save makes it anew (§H.2 "Flat view", §H.4
// "The reload", §H.6): a 409 naming where it went, as a path the user can
// open: its file in the same namespace's directory (a raw file by its
// name, a JSON file as {name}.json, §H.2), else /r/{ns}/{name}. A MOVE
// of a live file to the name isn't a save, and makes it anew (a rename
// back would otherwise be refused, naming its own source).
func movedAway(ns, name string, h *client.Head, last *docEntry) error {
	succ := h.Successor
	if succ == "" && last != nil {
		succ = client.SuccessorOf(last.value)
	}
	ns2, name2, ok := client.ResolveSuccessor(ns, succ)
	if !ok {
		return nil
	}
	to := "/r/" + ns2 + "/" + name2
	if ns2 == ns {
		to = "/" + ns + "/" + name2
		if last == nil || last.raw == nil {
			to += ".json"
		}
	}
	return fail(http.StatusConflict, "%s/%s was moved to %s (§8.1): a save doesn't make it anew at its old name (§H.2, §H.4); open it there, or save under another name", ns, name, to)
}

// hasBase reports whether a save of ns/name names or has a base (§H.4):
// an If-Match (or If header) tag, or the principal's records of it, kept
// or lost.
func (st *reqState) hasBase(ns, name string) bool {
	if st.ifMatch != "" {
		return true
	}
	d := st.s.recordsOf(st.p, ns, name)
	return len(d.rs) > 0 || d.lost
}

// edit appends the principal's edit of ns/name on head: the edit from its
// base to v, rebased on the head (rebased). Changes others made since the
// base are kept; where they overlap the edit's and v doesn't already
// agree with the head, the save is 409 and nothing is written, never an
// overwrite. A patch set over opsPerSet or patchSetSize (§6.6) is sent as
// a root replace instead, which may be as large as documentSize, if the
// base is the head (§H.4): it then writes nothing of others' over; a
// merged one is 413, unsent where the gateway knows the limit (setOver).
// retry: the head moved (412), read it again.
func (st *reqState) edit(ctx context.Context, in nsInfo, ns, name, head string, v any, body []byte) (string, bool, bool, error) {
	cur, err := st.s.doc(ctx, st.tk, ns, name, head)
	switch {
	case err != nil:
		return "", false, false, err
	case cur.sealed:
		return "", false, false, notOffered(ns)
	case cur.raw != nil:
		return "", false, false, fail(http.StatusConflict, "%s/%s is a raw file, shown as %s: a JSON file can't take its name (§H.2)", ns, name, name)
	}
	out, atHead, err := st.rebased(ctx, ns, name, v, head, cur.value)
	if err != nil {
		return "", false, false, err
	}
	ps := merge.Diff(files.Bare(cur.value), out)
	if len(ps) == 0 {
		// It already reads so: nothing is written, so it is no write of
		// the principal's (an undo would take it for one), but the
		// principal has the head now, as written if exactly so.
		exact := rendersAs(v)(cur.value)
		if exact {
			st.s.remember(st.p, ns, name, record{rev: head, raw: keepRaw(body, cur.rendered)}, false)
		}
		return head, exact, false, nil
	}
	paths := writesOf(files.Bare(cur.value), ps)
	ps = withNonce(in, out, ps)
	over := setOver(in, ps)
	if over != nil && !atHead {
		return "", false, false, over
	}
	whole := over != nil
	if whole {
		ps = wholeDoc(in, cur.value, out)
	}
	res, err := st.tk.c.Append(ctx, ns, name, head, ps)
	if atHead && !whole && setTooLarge(err) {
		ps = wholeDoc(in, cur.value, out)
		res, err = st.tk.c.Append(ctx, ns, name, head, ps)
	}
	err = tooLarge(err, atHead)
	switch {
	case client.IsStale(err):
		return "", false, true, nil
	case client.IsGone(err) && !client.IsPurged(err):
		return "", false, false, fail(http.StatusConflict, "%s/%s was deleted meanwhile", ns, name)
	case isPatchFailure(err):
		st.refuse(ns, name)
		return "", false, false, fail(http.StatusConflict, "your edit no longer applies to %s/%s, which someone else changed: %s; reload it and edit again", ns, name, apiText(errAPI(err)))
	case err != nil:
		return "", false, false, err
	}
	return res.ID, st.wrote(ns, name, cur.value, ps, paths, res, v, body, rendersAs(v)), false, nil
}

// setOver is the 413 of a patch set over the opsPerSet or patchSetSize
// the namespace sets (§6.6), measured as the core measures them (§3.1),
// for a save merged with others' edits, which isn't written whole (§H.4)
// and isn't sent; nil if it is within them. One from the head is written
// whole instead. The deployment's limits, which this server doesn't
// know, the core's refusal tells (setTooLarge).
func setOver(in nsInfo, ps []any) error {
	if in.opsPerSet > 0 && len(ps) > in.opsPerSet {
		return overLimit("opsPerSet", int64(len(ps)), int64(in.opsPerSet), "(§6.6): too many operations%s", mergedNote)
	}
	if n := len(jsonv.Canonical(ps)); in.patchSetSize > 0 && n > in.patchSetSize {
		return overLimit("patchSetSize", int64(n), int64(in.patchSetSize), "(§6.6): patch set too large%s", mergedNote)
	}
	return nil
}

// setTooLarge reports the core's refusal of a patch set over patchSetSize
// (413) or opsPerSet (422), code limit (§6.6): by the limit it names, or,
// from cores that name none, by its message.
func setTooLarge(err error) bool {
	ae, ok := client.AsAPIError(err)
	if !ok || ae.Code != "limit" {
		return false
	}
	if l, _ := ae.Body["limit"].(string); l != "" {
		return l == "patchSetSize" || l == "opsPerSet"
	}
	m, _ := ae.Body["message"].(string)
	return ae.Status == http.StatusRequestEntityTooLarge && m == "patch set too large" ||
		ae.Status == http.StatusUnprocessableEntity && m == "too many operations"
}

// wholeDoc is the root replace writing out, a JSON file's document as
// rendered (files.Bare), over cur (§H.4, §11.3 "Overwriting on purpose"): it
// carries cur's $successor, which the rendering leaves out, and a fresh
// $nonce where one is needed (§C.7).
func wholeDoc(in nsInfo, cur, out any) []any {
	doc := out
	if m, ok := out.(map[string]any); ok {
		if s := client.SuccessorOf(cur); s != "" {
			c := make(map[string]any, len(m)+1)
			for k, x := range m {
				c[k] = x
			}
			c["$successor"] = s
			doc = c
		}
	}
	return withNonce(in, doc, []any{map[string]any{"op": "replace", "path": "", "value": doc}})
}

func conflict(ns, name string, clash []string) error {
	return fail(http.StatusConflict, "%s/%s was changed by someone else since you opened it, where you changed it too: %s; reload it and edit again",
		ns, name, strings.Join(clash, ", "))
}

func errAPI(err error) *client.APIError {
	ae, _ := client.AsAPIError(err)
	return ae
}

// pruned reports a revision the core no longer serves: 404, or 410
// (pruned, §8.6, or the resource's chain gone).
func pruned(err error) bool {
	ae, ok := client.AsAPIError(err)
	return ok && (ae.Status == http.StatusNotFound || ae.Status == http.StatusGone)
}

// candidate is a version a save may have been edited from: its document,
// the revision holding it or written as it, when it was recorded, and,
// for a write of the principal's, what it changed.
type candidate struct {
	doc   any
	rev   string
	seq   uint64
	wrote bool
	paths []pointer.Pointer
}

// candidates returns the versions a save of ns/name may have been edited
// from, oldest first, and whether records of it were lost (records.go)
// (§H.4 "The base"). That is the revision the PUT's If-Match (or If
// header) names, and the writes of the principal's it holds merged (whose
// tag a client may learn from a listing, or a HEAD after the PUT); else
// the principal's records. If-Match: * names none: the head is the base.
// An If-Match no revision of the document answers to is a 412, and one
// the core no longer has (pruned, §8.6) a 409 asking for a reload; a
// record whose revision is gone so counts as lost. A revision that can't
// be read otherwise (a 429, a 5xx) fails the save: the head is never the
// base instead.
func (st *reqState) candidates(ctx context.Context, ns, name string) ([]candidate, bool, error) {
	if st.matchAny {
		return nil, false, nil
	}
	d := st.s.recordsOf(st.p, ns, name)
	var cs []candidate
	var goneErr error
	// add adds r's version; gone: its revision isn't served any more
	// (goneErr says how).
	add := func(r record) (bool, error) {
		c := candidate{rev: r.rev, seq: r.seq, wrote: r.wrote, paths: r.paths}
		var err error
		switch {
		case r.doc != nil:
			c.doc, err = jsonv.Parse(r.doc)
		case r.raw != nil:
			c.doc, err = jsonv.Parse(trimBOM(r.raw))
		default:
			e, err := st.s.doc(ctx, st.tk, ns, name, r.rev)
			switch {
			case pruned(err):
				goneErr = err
				return true, nil
			case err != nil:
				return false, err
			case e.sealed:
				return true, nil
			}
			c.doc = e.value
		}
		if err != nil {
			// What this server parsed before: not expected to fail.
			return true, nil
		}
		cs = append(cs, c)
		return false, nil
	}
	if st.ifMatch == "" {
		lost := d.lost
		for _, r := range d.rs {
			gone, err := add(r)
			if err != nil {
				return nil, false, err
			}
			lost = lost || gone
		}
		return cs, lost, nil
	}
	// What the client says it had, as recent as the principal's newest
	// record of it.
	named := record{rev: st.ifMatch}
	for _, r := range d.rs {
		if r.rev == st.ifMatch && !r.wrote {
			named.seq = r.seq
		}
	}
	gone, err := add(named)
	if err != nil {
		return nil, false, err
	}
	if gone {
		if ae, ok := client.AsAPIError(goneErr); ok && ae.Status == http.StatusGone {
			st.refuse(ns, name)
			return nil, false, fail(http.StatusConflict, "%s/%s: revision %s, the version you edited (If-Match), is no longer kept (pruned, §8.6), so your changes can't be told from others'; reload it and edit again", ns, name, st.ifMatch)
		}
	}
	for _, r := range d.rs {
		if r.wrote && r.rev == st.ifMatch {
			if _, err := add(r); err != nil {
				return nil, false, err
			}
		}
	}
	if len(cs) == 0 {
		return nil, false, fail(http.StatusPreconditionFailed, "%s/%s has no revision %s (If-Match) to rebase the save on; reload it and edit again", ns, name, st.ifMatch)
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].seq < cs[j].seq })
	return cs, false, nil
}

// rebased returns v, a save of JSON file ns/name, rebased on head,
// revision headRev (§11.3, §H.4), and whether its base is the head, the
// same content (or none is known, and the head is the base: the file as
// written wins). Documents are compared and written as rendered (files.Bare),
// so a $successor stays; v, head and the result are so.
//
// The base is the candidate (candidates) closest to v, the one its edit
// changes the fewest paths of: an editor's buffer is the version it
// opened or last saved plus the user's edit, while another program's GET
// (a preview, a second window) moves on without it. A v equal to an older
// version is a save of it unchanged, or, when the principal wrote since
// and v reverts just what that write changed, an undo of it: then that
// write is the base. Of equally close candidates, the newest whose
// rebase neither clashes nor is unsafe is taken.
//
// What isn't guessed: the result may change a path of head only where
// every candidate agrees with head (unsafe), so whichever one the client
// really had, no edit someone else made since is undone or overwritten
// unseen; an edit from a base before a delete or restore by someone else
// (spans) isn't merged over it; and where another candidate, taken as the
// base, would give another result as safely (ambiguous), as an undo of
// the principal's own save combined with a new edit and a second
// program's edit from the version before that save do, the save isn't
// applied as either. A save that can't be rebased so is a 409, which asks
// for a reload (refuse); so is one whose records were lost, and one that
// writes by a token refused a save of it that hasn't read it since
// (refusedSave).
func (st *reqState) rebased(ctx context.Context, ns, name string, v any, headRev string, head any) (any, bool, error) {
	out, atHead, err := st.rebasedOn(ctx, ns, name, v, headRev, head)
	if err == nil && !jsonv.Equal(out, files.Bare(head)) {
		// A save that writes: not by a token refused a save of it and
		// that hasn't read it since.
		if err = st.refusedSave(ns, name); err != nil {
			return nil, false, err
		}
	}
	return out, atHead, err
}

// rebasedOn is rebased but for refusedSave.
func (st *reqState) rebasedOn(ctx context.Context, ns, name string, v any, headRev string, head any) (any, bool, error) {
	cs, lost, err := st.candidates(ctx, ns, name)
	if err != nil {
		return nil, false, err
	}
	for i := range cs {
		cs[i].doc = files.Bare(cs[i].doc)
	}
	mine, head := files.Bare(v), files.Bare(head)
	if lost {
		if jsonv.Equal(mine, head) {
			return head, true, nil
		}
		st.refuse(ns, name)
		return nil, false, lostBase(ns, name)
	}
	if len(cs) == 0 {
		out, _ := rebase(head, mine, head, nil)
		return out, true, nil
	}
	dist := make([]int, len(cs))
	least := -1
	for i, c := range cs {
		if dist[i] = len(writesOf(c.doc, merge.Diff(c.doc, mine))); least < 0 || dist[i] < least {
			least = dist[i]
		}
	}
	var tied []int // newest first
	for i := len(cs) - 1; i >= 0; i-- {
		if dist[i] == least {
			tied = append(tied, i)
		}
	}
	if least == 0 {
		for i := len(cs) - 1; i >= 0 && cs[i].seq > cs[tied[0]].seq; i-- {
			if undoes(cs[i], mine) {
				tied = []int{i}
				break
			}
		}
	}
	all := make([]int, len(cs))
	for i := range all {
		all[i] = i
	}
	sp, err := st.spans(ctx, ns, name, headRev, cs, all)
	if err != nil {
		return nil, false, err
	}
	var why []string
	foreign := false
	for _, i := range tied {
		s := sp[cs[i].rev]
		if s.foreign && least > 0 {
			if why == nil {
				foreign = true
				why = []string{}
			}
			continue
		}
		out, clash := rebase(cs[i].doc, mine, head, s.writes)
		if len(clash) == 0 {
			if clash = unsafe(out, head, cs); len(clash) == 0 {
				if amb := ambiguous(cs, dist, sp, i, mine, head, out); amb != nil {
					st.refuse(ns, name)
					return nil, false, fail(http.StatusConflict, "%s/%s: your save reads as an edit of more than one version you were served or wrote, which give different results at %s (an undo of a save of yours combined with a new edit, and another program's edit from the version before that save, look alike; §H.4); reload it and save again", ns, name, strings.Join(amb, ", "))
				}
				return out, jsonv.Equal(cs[i].doc, head), nil
			}
		}
		if why == nil {
			why = clash
		}
	}
	st.refuse(ns, name)
	if foreign {
		return nil, false, fail(http.StatusConflict, "%s/%s was deleted or restored by someone else since you opened it (§11.3): your changes aren't merged over that; reload it and edit again", ns, name)
	}
	return nil, false, conflict(ns, name, why)
}

// ambiguous returns where another candidate than cs[i], taken as the
// base as safely (rebase, unsafe), gives another result than out, or nil:
// then the save can't be told for an edit of one version rather than the
// other (§H.4 "if the closest records disagree … a conflict", here of
// any two). A candidate the save equals (dist 0) is its save unchanged,
// which the undo of a later write of the principal's, if chosen, is
// meant over, and one from before someone else's delete or restore is
// never a base.
func ambiguous(cs []candidate, dist []int, sp map[string]span, i int, mine, head, out any) []string {
	for j, c := range cs {
		if j == i || dist[j] == 0 || sp[c.rev].foreign || jsonv.Equal(c.doc, cs[i].doc) {
			continue
		}
		o, clash := rebase(c.doc, mine, head, sp[c.rev].writes)
		if len(clash) > 0 || len(unsafe(o, head, cs)) > 0 || jsonv.Equal(o, out) {
			continue
		}
		var at []string
		for _, p := range writesOf(out, merge.Diff(out, o)) {
			s := p.String()
			if s == "" {
				s = "(the whole document)"
			}
			at = append(at, s)
		}
		return at
	}
	return nil
}

// lostBase is a save's refusal where the versions it may have been made
// from are no longer known (records.go, §8.6).
func lostBase(ns, name string) error {
	return fail(http.StatusConflict, "%s/%s: the version you edited is no longer to be had (this server's records of it were dropped, or the core pruned it, §8.6), so your changes can't be told from others'; reload it and edit again", ns, name)
}

// span is what the log says happened between a candidate base and the
// head (§11.3): the writes of its entries (logWrites) but the principal's
// own, and whether someone else deleted or restored the document in
// between, a tombstone or a restore the principal didn't write, whose
// writes are empty but which a save from before isn't merged over.
type span struct {
	writes  []pointer.Pointer
	foreign bool
}

// spans returns the spans from the revisions of candidates which (of cs)
// to headRev, by revision, read from the log (§7.1), once from the oldest
// where one range holds the others (one chain per name, §8.2). A
// candidate at the head has none. A range the core no longer has (pruned,
// §8.6) is a 409 asking for a reload.
func (st *reqState) spans(ctx context.Context, ns, name, headRev string, cs []candidate, which []int) (map[string]span, error) {
	out := map[string]span{}
	need := map[string]bool{}
	var revs []string
	for _, i := range which {
		if r := cs[i].rev; r != "" && r != headRev && !need[r] {
			need[r] = true
			revs = append(revs, r)
		}
	}
	// Recorded earlier, likely older: read first, so later ones are in
	// its range.
	sort.SliceStable(revs, func(i, j int) bool { return seqOf(cs, revs[i]) < seqOf(cs, revs[j]) })
	gone := func() error {
		st.refuse(ns, name)
		return fail(http.StatusConflict, "%s/%s: its history since the version you edited is no longer kept (pruned, §8.6), so your changes can't be told from others'; reload it and edit again", ns, name)
	}
	for _, from := range revs {
		if _, ok := out[from]; ok {
			continue
		}
		es, err := st.tk.c.Log(ctx, ns, name, headRev, from)
		if pruned(err) {
			return nil, gone()
		}
		if err != nil {
			return nil, err
		}
		base, err := st.s.doc(ctx, st.tk, ns, name, from)
		switch {
		case pruned(err):
			return nil, gone()
		case err != nil:
			return nil, err
		}
		ws := logWrites(base.value, es)
		// Each candidate's span is that of the entries after its
		// revision: from the last entry back.
		var acc span
		for i := len(es) - 1; i >= -1; i-- {
			if i < 0 {
				out[from] = acc
				break
			}
			if need[es[i].ID] {
				out[es[i].ID] = span{writes: append([]pointer.Pointer(nil), acc.writes...), foreign: acc.foreign}
			}
			if st.s.ownEntry(st.p, ns, name, es[i].ID) || wroteRev(cs, es[i].ID) {
				// The principal's own: what it changed is in the head
				// (rebase's diff), and its own to change again (unsafe).
				continue
			}
			acc.writes = append(acc.writes, ws[i]...)
			if es[i].Kind == "tombstone" || i > 0 && es[i-1].Kind == "tombstone" {
				acc.foreign = true
			}
		}
	}
	return out, nil
}

// seqOf is when the first candidate of revision rev was recorded.
func seqOf(cs []candidate, rev string) uint64 {
	for _, c := range cs {
		if c.rev == rev {
			return c.seq
		}
	}
	return 0
}

// wroteRev reports whether rev is a write of the principal's among cs.
func wroteRev(cs []candidate, rev string) bool {
	for _, c := range cs {
		if c.wrote && c.rev == rev {
			return true
		}
	}
	return false
}

// logWrites returns the writes of each log entry of es (§6.4.1), applied
// in order to doc, the document before the first: each cut at the
// outermost array it goes through, before or after the entry (§H.4), and
// without the members no file shows ($nonce, $successor, §H.1). A
// tombstone writes nothing, and the restore after it applies to the last
// live document (§8.2). An entry whose patch set is absent or doesn't
// apply here writes the whole document, as do all after it.
func logWrites(doc any, es []client.LogEntry) [][]pointer.Pointer {
	out := make([][]pointer.Pointer, len(es))
	cur, known := doc, true
	for i, e := range es {
		if e.Kind == "tombstone" {
			continue
		}
		var ws []pointer.Pointer
		var nd any
		ops, err := patch.Parse(e.Patches)
		if err == nil && known && e.HasPatches {
			nd, ws, err = patch.Apply(cur, true, ops, patch.Options{ResourceEnvelope: true})
		}
		if err != nil || !known || !e.HasPatches {
			out[i], known = []pointer.Pointer{{}}, false
			continue
		}
		for _, w := range ws {
			if len(w) == 1 && (w[0] == "$nonce" || w[0] == "$successor") {
				continue
			}
			out[i] = append(out[i], cutAtArray(w, cur, nd))
		}
		cur = nd
	}
	return out
}

// cutAtArray is p cut at the outermost array it goes through in a or b.
func cutAtArray(p pointer.Pointer, a, b any) pointer.Pointer {
	for i := range p {
		for _, d := range []any{a, b} {
			if v, ok := pointer.Get(d, p[:i]); ok {
				if _, arr := v.([]any); arr {
					return append(pointer.Pointer{}, p[:i]...)
				}
			}
		}
	}
	return p
}

// undoes reports whether mine reverts write w of the principal's: what
// differs from it is only what w changed. Documents are as rebased's view
// shows them.
func undoes(w candidate, mine any) bool {
	if !w.wrote || len(w.paths) == 0 {
		return false
	}
	for _, o := range writesOf(w.doc, merge.Diff(w.doc, mine)) {
		in := false
		for _, p := range w.paths {
			if o.HasPrefix(p) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	return true
}

// unsafe returns the paths where out changes head and a candidate holds
// another value than head, which someone else wrote since: had the client
// that candidate, the save would undo that write unseen, or overwrite it
// with a change of its own without a conflict. A value the principal
// wrote since (a later write of its own there, which head still holds) is
// its own to change again.
func unsafe(out, head any, cs []candidate) []string {
	var bad []string
	for _, q := range writesOf(head, merge.Diff(head, out)) {
		for _, c := range cs {
			if !agree(c.doc, head, q) && !ownSince(c, q, head, cs) {
				p := q.String()
				if p == "" {
					p = "(the whole document)"
				}
				bad = append(bad, p)
				break
			}
		}
	}
	return bad
}

// ownSince reports whether the principal wrote q after c, and head still
// holds what it wrote.
func ownSince(c candidate, q pointer.Pointer, head any, cs []candidate) bool {
	for _, w := range cs {
		if !w.wrote || w.seq <= c.seq || !agree(w.doc, head, q) {
			continue
		}
		for _, p := range w.paths {
			if p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}

// rebase applies the edit from base to mine onto head (§11.3): the result
// is head with mine's value at each path the edit writes, as writes count
// (§6.4.1) but whole arrays for anything in one (§F.3's array rule, from
// the outermost array: elements have no identity, so an index one side
// names is another element after the other's insert or delete). Where
// those writes overlap others' since base, mine must agree with head
// there, a change both made, or a version reloaded since; otherwise the
// clashing paths are returned and nothing is. Others' writes are what
// differs between base and head, and logged, the writes of the log
// entries between them (spans), which also hold a value someone changed
// and changed back. Documents are as rebased's view shows them.
func rebase(base, mine, head any, logged []pointer.Pointer) (any, []string) {
	ours := writesOf(base, merge.Diff(base, mine))
	if len(ours) == 0 {
		return head, nil
	}
	theirs := append(writesOf(base, merge.Diff(base, head)), logged...)
	clash := map[string]bool{}
	for _, o := range ours {
		for _, t := range theirs {
			if o.Overlaps(t) && !agree(mine, head, o) {
				clash[o.String()], clash[t.String()] = true, true
			}
		}
	}
	out := jsonv.Clone(head)
	for _, o := range ours {
		var ok bool
		if out, ok = graft(out, mine, o); !ok {
			clash[o.String()] = true
		}
	}
	if len(clash) > 0 {
		paths := make([]string, 0, len(clash))
		for p := range clash {
			if p == "" {
				p = "(the whole document)"
			}
			paths = append(paths, p)
		}
		sort.Strings(paths)
		return nil, paths
	}
	return out, nil
}

// writesOf returns the paths patch set ops (add, replace and remove, as
// merge.Diff makes them) writes in base, each cut at the outermost array
// it goes through.
func writesOf(base any, ops []any) []pointer.Pointer {
	seen := map[string]bool{}
	var out []pointer.Pointer
	for _, op := range ops {
		m, _ := op.(map[string]any)
		s, _ := m["path"].(string)
		p, err := pointer.Parse(s)
		if err != nil {
			continue
		}
		for i := range p {
			v, ok := pointer.Get(base, p[:i])
			if !ok {
				break
			}
			if _, arr := v.([]any); arr {
				p = p[:i]
				break
			}
		}
		if k := "/" + p.String(); !seen[k] {
			seen[k] = true
			out = append(out, append(pointer.Pointer{}, p...))
		}
	}
	// Outer paths first: a write under one already grafted is in it.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out
}

// agree reports whether a and b hold the same at p, or both nothing.
func agree(a, b any, p pointer.Pointer) bool {
	x, okA := pointer.Get(a, p)
	y, okB := pointer.Get(b, p)
	return okA == okB && (!okA || jsonv.Equal(x, y))
}

// graft sets doc's value at p, an object path, to src's (removing it
// where src has none); false when doc has no object to hold it.
func graft(doc, src any, p pointer.Pointer) (any, bool) {
	v, has := pointer.Get(src, p)
	if len(p) == 0 {
		return jsonv.Clone(v), has
	}
	cur := doc
	for _, tok := range p[:len(p)-1] {
		m, ok := cur.(map[string]any)
		if !ok {
			return doc, false
		}
		if cur, ok = m[tok]; !ok {
			return doc, !has
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return doc, false
	}
	if has {
		m[p[len(p)-1]] = jsonv.Clone(v)
	} else {
		delete(m, p[len(p)-1])
	}
	return doc, true
}

// wrote records a write of v, uploaded as body, as revision res.ID, which
// changed paths, and reports whether that revision holds exactly what was
// uploaded: whether same says so of its document. The revision's
// document, the patches applied to parent as the core applies them, is
// cached with its creation time from the log entry. A create or restore
// replaces the whole document, so its parent is any object.
func (st *reqState) wrote(ns, name string, parent any, ps []any, paths []pointer.Pointer, res *client.WriteResult, v any, body []byte, same func(doc any) bool) bool {
	var doc any
	if ops, err := patch.Parse(ps); err == nil {
		doc, _, err = patch.Apply(parent, true, ops, patch.Options{})
		if err != nil {
			doc = nil
		}
	}
	st.committed = true
	st.s.markOwn(st.p, ns, name, res.ID)
	exact := doc != nil && same(doc)
	r := record{rev: res.ID, wrote: true, paths: paths}
	var e *docEntry
	if doc != nil {
		var created time.Time
		if res.Entry != nil {
			created, _ = time.Parse(time.RFC3339Nano, res.Entry.Created)
		}
		e = newEntry(doc, created)
		st.s.keep(docKey(ns, name, res.ID), e)
	}
	if exact {
		r.raw = keepRaw(body, e.rendered)
	} else {
		r.doc = jsonv.Canonical(v)
	}
	st.s.remember(st.p, ns, name, r, false)
	return exact
}

// rendersAs reports, of a document, whether its rendering is v, a JSON
// file as uploaded (§H.1 "Identity"): what the uploader holds is that
// revision's, whatever its formatting, and whatever $nonce it got.
func rendersAs(v any) func(doc any) bool {
	return func(doc any) bool { return jsonv.Equal(files.Bare(doc), v) }
}

// retrying runs a write attempt again while it asks to (the head moved:
// 412, §11 submit), up to Retries times, and waits out a 429 whose
// Retry-After is at most MaxRetryWait, twice at most; a longer one, or a
// third, is 503 with Retry-After (§6.6).
func (st *reqState) retrying(ctx context.Context, attempt func() (retry bool, err error)) error {
	waits := 0
	for moved := 0; ; {
		retry, err := attempt()
		if client.IsRateLimited(err) {
			ae := errAPI(err)
			if waits >= 2 || ae.RetryAfter > st.s.opt.MaxRetryWait {
				return busy(ae)
			}
			waits++
			t := time.NewTimer(ae.RetryAfter)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
			continue
		}
		if err != nil {
			return upstream(err)
		}
		if !retry {
			return nil
		}
		if moved++; moved > st.s.opt.Retries {
			return fail(http.StatusConflict, "the document kept changing; try again")
		}
	}
}

// tooLarge is the core's refusal of a write for a limit (§6.6: 413, or
// 422 code limit) as 413 (§H.4 "Answers"), with the limit and the sizes
// the core gave (limitRefusal). A save merged with others' edits (not
// atHead) isn't written whole, which only a save from the head may be
// (§H.4), so it says to reload. Other errors pass.
func tooLarge(err error, atHead bool) error {
	ae, ok := client.AsAPIError(err)
	if !ok {
		return err
	}
	more := ""
	if !atHead {
		more = mergedNote
	}
	if e := limitRefusal(ae, more); e != nil {
		return e
	}
	return err
}

// mergedNote ends a 413 of a save merged with others' edits.
const mergedNote = "; your save was merged with others' edits made since your version, so it isn't written whole (§H.4): reload it and save again"

// undelete restores ns/name, tombstoned by the principal's own DELETE as
// tomb, as it was (an empty patch set on the last live document, §8.2,
// with If-Match on tomb), after the write meant to restore it failed with
// err, which it returns, saying so.
func (st *reqState) undelete(ctx context.Context, in nsInfo, ns, name, tomb string, err error) error {
	res, rerr := st.tk.c.Restore(ctx, ns, name, tomb, withNonce(in, nil, []any{}))
	if rerr != nil {
		st.s.opt.Logf("dav: %s/%s: restoring it as it was after a refused save: %v", ns, name, rerr)
		return err
	}
	st.s.markOwn(st.p, ns, name, res.ID)
	st.p.forgetDelete(ns, name)
	st.undeleted = true
	de, ok := upstream(err).(*davError)
	if !ok {
		return err
	}
	out := *de
	if note := " (the original, deleted before this write, is restored as it was)"; !strings.HasSuffix(out.msg, note) {
		out.msg += note
	}
	return &out
}

// undoOwnDelete is the failure err of a write to the document at t, a
// save that deleted the original before writing the new version (DELETE,
// then a PUT, a COPY or a MOVE onto the name): whatever refused the
// write (a conflict, a body that isn't JSON, one too large, a frozen
// namespace, a precondition), the principal's own DELETE moments before
// is undone, and the document restored as it was, as a failed PUT leaves
// it (§H.6). In a tree, that is the file the principal's DELETE of the
// path removed: its placement, then its item if it went too. Only the
// principal's own tombstone, still the head and written within
// ownDeleteUndo, is restored (with If-Match on it).
func (st *reqState) undoOwnDelete(ctx context.Context, t target, err error) error {
	if err == nil || !t.isDoc() {
		return err
	}
	type res struct{ ns, name string }
	var todo []res
	if t.docNS != "" {
		todo = append(todo, res{t.docNS, t.docName})
	}
	if t.rawName != "" {
		todo = append(todo, res{t.docNS, t.rawName})
	}
	if d, ok := st.p.treeDeleted(t.path, st.s.opt.Now()); ok && t.kind == kNewNode && d.cat == t.ns {
		todo = append(todo, res{d.cat, d.node})
		if d.itemTomb != "" {
			todo = append(todo, res{d.itemNS, d.itemName})
		}
	}
	for _, r := range todo {
		if !st.p.deletedOwn(r.ns, r.name, "", st.s.opt.Now()) {
			continue
		}
		h, herr := st.tk.c.Head(ctx, r.ns, r.name)
		if herr != nil || h.State != client.Tombstoned || !st.p.deletedOwn(r.ns, r.name, h.ID, st.s.opt.Now()) {
			continue
		}
		err = st.undelete(ctx, st.s.nsInfo(ctx, st.tk, r.ns), r.ns, r.name, h.ID, err)
		st.changed()
	}
	return err
}

// deleteDoc tombstones ns/name (§8.1), if its head is ifMatch when that
// is given (412 otherwise), and returns the tombstone. The principal's
// records of it stay: a save that deletes the original before writing
// the new version restores it from them (restorePatches), or as it was if
// that write is refused.
func (st *reqState) deleteDoc(ctx context.Context, ns, name, ifMatch string) (string, error) {
	if st.s.nsInfo(ctx, st.tk, ns).sealed {
		return "", notOffered(ns)
	}
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
		res, err := st.tk.c.Delete(ctx, ns, name, h.ID)
		if client.IsStale(err) {
			return true, nil
		}
		if err == nil {
			tomb = res.ID
			st.s.markOwn(st.p, ns, name, res.ID)
			st.p.noteDelete(ns, name, res.ID, st.s.opt.Now())
		}
		return false, err
	})
	if errors.Is(err, errNotExist) {
		return "", errNotExist
	}
	return tomb, err
}

// purgedErr is a save's answer for purged ns/name (§8.3), or a name of a
// purged namespace (§8.5): 410 (§H.4 "Answers").
func purgedErr(ns, name string) error {
	return fail(http.StatusGone, "%s/%s was purged (§8.3, §8.5); its name can't be used again", ns, name)
}
