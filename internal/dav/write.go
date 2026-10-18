package dav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// parseBody parses a written file as I-JSON (§3.1), a UTF-8 byte order
// mark aside: anything else is 400 and nothing is written.
func parseBody(body []byte) (any, error) {
	body = trimBOM(body)
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "not a JSON document (I-JSON, §3.1): %v", err)
	}
	return v, nil
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// dropNonce is doc without its top-level $nonce: a fresh one is the
// writer's to add (§C.7), so it is never part of a user's edit.
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
// (§C.7).
func withNonce(in nsInfo, patches []any) []any {
	if !in.nonce {
		return patches
	}
	return append(patches, map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
}

// commitDoc writes v, uploaded as body, as the document of ns/name. It
// returns the revision holding it, and whether that revision's document
// is exactly v (else the upload was merged or given a $nonce, and the
// revision is no validator of it). A new name is created (If-None-Match:
// *); a tombstoned one restored (one name keeps one chain, §8.2); a live
// one edited: the edit from its base (base) to v, rebased on the head and
// appended with If-Match (§11 submit). pre: the document is the PUT's
// file, whose preconditions hold for it.
func (st *reqState) commitDoc(ctx context.Context, ns, name string, v any, body []byte, pre bool) (string, bool, error) {
	in := st.s.nsInfo(ctx, st.p, ns)
	if in.sealed {
		return "", false, fail(http.StatusNotImplemented, "%s is sealed or end-to-end (Addendum E); it isn't written over WebDAV", ns)
	}
	var rev string
	var exact bool
	st.made = ""
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		switch h.State {
		case client.Purged:
			return false, fail(http.StatusForbidden, "%s/%s was purged; its name can't be used again (§8.3)", ns, name)
		case client.Live:
			if pre && st.noneMatch {
				return false, fail(http.StatusPreconditionFailed, "%s/%s exists (If-None-Match: *)", ns, name)
			}
			r, x, retry, err := st.edit(ctx, in, ns, name, h.ID, v, body)
			rev, exact = r, x
			return retry, err
		}
		if pre && st.matchAny && !st.placeholder {
			return false, fail(http.StatusPreconditionFailed, "%s/%s doesn't exist (If-Match: *)", ns, name)
		}
		var res *client.WriteResult
		var parent any = map[string]any{}
		var ps []any
		if h.State == client.NotFound {
			doc := v
			if in.nonce {
				doc = dropNonce(v)
			}
			ps = withNonce(in, client.GenesisPatches(doc))
			res, err = st.p.c.Create(ctx, ns, name, ps)
			err = tooLarge(err, in, parent, ps, true)
		} else if parent, ps, err = st.restorePatches(ctx, in, ns, name, h, v); err == nil {
			res, err = st.p.c.Restore(ctx, ns, name, h.ID, ps)
			err = tooLarge(err, in, parent, ps, false)
		}
		if client.IsStale(err) || client.IsGone(err) {
			return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile; reload it", ns, name)
		}
		if err != nil {
			return false, err
		}
		rev, exact = res.ID, st.wrote(ns, name, parent, ps, writesOf(parent, ps), res, v, body)
		st.made = rev
		return false, nil
	})
	return rev, exact, err
}

// restorePatches is the patch set restoring tombstoned ns/name with v,
// applied to the last live document (§8.2), and that document. With a
// base the principal had, the edit from it is rebased on the last live
// document, as a save over a live one is: a save that deletes the
// original before writing (an editor's, or a client's that creates only)
// keeps others' edits. Without one, the last live document is the base,
// so the file as written wins, as over a live one: either way the patch
// set is the diff from the last live document, not a whole new one. With
// the last document pruned (§8.6), the root is replaced.
func (st *reqState) restorePatches(ctx context.Context, in nsInfo, ns, name string, h *client.Head, v any) (any, []any, error) {
	whole := func() (any, []any, error) {
		doc := v
		if in.nonce {
			doc = dropNonce(v)
		}
		return map[string]any{}, withNonce(in, []any{map[string]any{"op": "replace", "path": "", "value": doc}}), nil
	}
	if h.Last == "" {
		return whole()
	}
	last, err := st.s.doc(ctx, st.p, ns, name, h.Last)
	switch {
	case pruned(err):
		return whole()
	case err != nil:
		return nil, nil, err
	case last.sealed:
		return whole()
	}
	out, _, err := st.rebased(ctx, ns, name, v, last.value)
	if err != nil {
		return nil, nil, err
	}
	return last.value, withNonce(in, merge.Diff(dropNonce(last.value), out)), nil
}

// edit appends the principal's edit of ns/name on head: the edit from its
// base to v, rebased on the head (rebased). Changes others made since the
// base are kept; where they overlap the edit's and v doesn't already
// agree with the head, the save is 409 and nothing is written, never an
// overwrite. retry: the head moved (412), read it again.
func (st *reqState) edit(ctx context.Context, in nsInfo, ns, name, head string, v any, body []byte) (string, bool, bool, error) {
	cur, err := st.s.doc(ctx, st.p, ns, name, head)
	if err != nil {
		return "", false, false, err
	}
	if cur.sealed {
		return "", false, false, fail(http.StatusNotImplemented, "%s/%s is sealed (Addendum E); it isn't written over WebDAV", ns, name)
	}
	out, _, err := st.rebased(ctx, ns, name, v, cur.value)
	if err != nil {
		return "", false, false, err
	}
	ps := merge.Diff(dropNonce(cur.value), out)
	if len(ps) == 0 {
		// It already reads so: nothing is written, so it is no write of
		// the principal's (an undo would take it for one), but the
		// principal has the head now, as written if exactly so.
		exact := jsonv.Equal(cur.value, v)
		if exact {
			st.s.remember(st.p, ns, name, record{rev: head, raw: keepRaw(body, cur.rendered)}, false)
		}
		return head, exact, false, nil
	}
	paths := writesOf(dropNonce(cur.value), ps)
	ps = withNonce(in, ps)
	res, err := st.p.c.Append(ctx, ns, name, head, ps)
	err = tooLarge(err, in, cur.value, ps, false)
	switch {
	case client.IsStale(err):
		return "", false, true, nil
	case client.IsGone(err):
		return "", false, false, fail(http.StatusConflict, "%s/%s was deleted meanwhile", ns, name)
	case isPatchFailure(err):
		st.s.refuse(st.p, ns, name)
		return "", false, false, fail(http.StatusConflict, "your edit no longer applies to %s/%s, which someone else changed: %s; reload it and edit again", ns, name, apiText(errAPI(err)))
	case err != nil:
		return "", false, false, err
	}
	return res.ID, st.wrote(ns, name, cur.value, ps, paths, res, v, body), false, nil
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

// candidate is a version a save may have been edited from.
type candidate struct {
	doc   any
	seq   uint64
	wrote bool
	paths []pointer.Pointer
}

// candidates returns the versions a save of ns/name may have been edited
// from, oldest first, and whether records of it were lost (records.go).
// That is the revision the PUT's If-Match (or If header) names, and the
// writes of the principal's it holds merged (whose tag a client may learn
// from a listing, or a HEAD after the PUT); else the principal's records.
// A revision pruned since (§8.6) is no candidate; one that can't be read
// otherwise (a 429, a 5xx) fails the save, and an If-Match no readable
// revision answers to is a 412.
func (st *reqState) candidates(ctx context.Context, ns, name string) ([]candidate, bool, error) {
	d := st.s.recordsOf(st.p, ns, name)
	var cs []candidate
	add := func(r record) (bool, error) {
		c := candidate{seq: r.seq, wrote: r.wrote, paths: r.paths}
		var err error
		switch {
		case r.doc != nil:
			c.doc, err = jsonv.Parse(r.doc)
		case r.raw != nil:
			c.doc, err = jsonv.Parse(trimBOM(r.raw))
		default:
			e, err := st.s.doc(ctx, st.p, ns, name, r.rev)
			switch {
			case pruned(err):
				return false, nil
			case err != nil:
				return false, err
			case e.sealed:
				return false, nil
			}
			c.doc = e.value
		}
		if err != nil {
			// What this server parsed before: not expected to fail.
			return false, nil
		}
		cs = append(cs, c)
		return true, nil
	}
	if st.ifMatch == "" {
		for _, r := range d.rs {
			if _, err := add(r); err != nil {
				return nil, false, err
			}
		}
		return cs, d.lost, nil
	}
	// What the client says it had, as recent as the principal's newest
	// record of it.
	named := record{rev: st.ifMatch}
	for _, r := range d.rs {
		if r.rev == st.ifMatch && !r.wrote {
			named.seq = r.seq
		}
	}
	ok, err := add(named)
	if err != nil {
		return nil, false, err
	}
	for _, r := range d.rs {
		if r.wrote && r.rev == st.ifMatch {
			got, err := add(r)
			if err != nil {
				return nil, false, err
			}
			ok = ok || got
		}
	}
	if !ok {
		return nil, false, fail(http.StatusPreconditionFailed, "%s/%s has no revision %s (If-Match) to rebase the save on; reload it and edit again", ns, name, st.ifMatch)
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].seq < cs[j].seq })
	return cs, false, nil
}

// rebased returns v, a save of ns/name, rebased on head (§11 submit), and
// whether a base of the principal's was known (else the head is the
// base, and the file as written wins).
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
// unseen. A save that can't be rebased so is a 409, which asks for a
// reload (refuse); so is one whose records were lost.
func (st *reqState) rebased(ctx context.Context, ns, name string, v, head any) (any, bool, error) {
	cs, lost, err := st.candidates(ctx, ns, name)
	if err != nil {
		return nil, false, err
	}
	mine := dropNonce(v)
	if lost {
		if jsonv.Equal(mine, dropNonce(head)) {
			return dropNonce(head), true, nil
		}
		st.s.refuse(st.p, ns, name)
		return nil, false, fail(http.StatusConflict, "%s/%s: this server no longer has the version you edited, so it can't tell your changes from others'; reload it and edit again", ns, name)
	}
	if len(cs) == 0 {
		out, _ := rebase(head, v, head)
		return out, false, nil
	}
	dist := make([]int, len(cs))
	least := -1
	for i, c := range cs {
		b := dropNonce(c.doc)
		if dist[i] = len(writesOf(b, merge.Diff(b, mine))); least < 0 || dist[i] < least {
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
	var why []string
	for _, i := range tied {
		out, clash := rebase(cs[i].doc, v, head)
		if len(clash) == 0 {
			if clash = unsafe(out, head, cs); len(clash) == 0 {
				return out, true, nil
			}
		}
		if why == nil {
			why = clash
		}
	}
	st.s.refuse(st.p, ns, name)
	return nil, true, conflict(ns, name, why)
}

// undoes reports whether mine reverts write w of the principal's: what
// differs from it is only what w changed.
func undoes(w candidate, mine any) bool {
	if !w.wrote || len(w.paths) == 0 {
		return false
	}
	b := dropNonce(w.doc)
	for _, o := range writesOf(b, merge.Diff(b, mine)) {
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
	head, out = dropNonce(head), dropNonce(out)
	var bad []string
	for _, q := range writesOf(head, merge.Diff(head, out)) {
		for _, c := range cs {
			if !agree(dropNonce(c.doc), head, q) && !ownSince(c, q, head, cs) {
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
		if !w.wrote || w.seq <= c.seq || !agree(dropNonce(w.doc), head, q) {
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

// rebase applies the edit from base to mine onto head (§11 submit): the
// result is head with mine's value at each path the edit writes, as
// writes count (§6.4.1) but whole arrays for anything in one (§F.3's
// array rule, from the outermost array: elements have no identity, so an
// index one side names is another element after the other's insert or
// delete). Where those writes overlap others' since base (head's), mine
// must agree with head there, a change both made, or a version reloaded
// since; otherwise the clashing paths are returned and nothing is.
func rebase(base, mine, head any) (any, []string) {
	base, mine, head = dropNonce(base), dropNonce(mine), dropNonce(head)
	ours := writesOf(base, merge.Diff(base, mine))
	if len(ours) == 0 {
		return head, nil
	}
	theirs := writesOf(base, merge.Diff(base, head))
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
// changed paths, and reports whether that revision's document is exactly
// v. The revision's document, the patches applied to parent as the core
// applies them, is cached with its creation time from the log entry. A
// create or restore replaces the whole document, so its parent is any
// object.
func (st *reqState) wrote(ns, name string, parent any, ps []any, paths []pointer.Pointer, res *client.WriteResult, v any, body []byte) bool {
	var doc any
	if ops, err := patch.Parse(ps); err == nil {
		doc, _, err = patch.Apply(parent, true, ops, patch.Options{})
		if err != nil {
			doc = nil
		}
	}
	st.committed = true
	exact := doc != nil && jsonv.Equal(doc, v)
	r := record{rev: res.ID, wrote: true, paths: paths}
	var e *docEntry
	if doc != nil {
		e = &docEntry{value: doc, rendered: render(doc)}
		if res.Entry != nil {
			e.created, _ = time.Parse(time.RFC3339Nano, res.Entry.Created)
		}
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

// tooLarge is the core's 413 for a write of patch set ps on parent (§6.6)
// with what the core doesn't say: the sizes it measured, and the limits
// the namespace sets, else that the deployment's apply. A create's patch
// set counts against documentSize, not patchSetSize. Other errors pass.
func tooLarge(err error, in nsInfo, parent any, ps []any, create bool) error {
	ae, ok := client.AsAPIError(err)
	if !ok || ae.Status != http.StatusRequestEntityTooLarge {
		return err
	}
	var b strings.Builder
	b.WriteString(apiText(ae))
	fmt.Fprintf(&b, ": the patch set is %d bytes", len(jsonv.Canonical(ps)))
	if ops, perr := patch.Parse(ps); perr == nil {
		if doc, _, aerr := patch.Apply(parent, true, ops, patch.Options{}); aerr == nil {
			fmt.Fprintf(&b, " and the document %d bytes", len(jsonv.Canonical(doc)))
		}
	}
	b.WriteString(", as canonical JSON (§3.1); ")
	if create {
		b.WriteString("a create's patch set counts against documentSize; ")
	}
	var set []string
	if in.patchSetSize > 0 {
		set = append(set, fmt.Sprintf("patchSetSize %d", in.patchSetSize))
	}
	if in.docSize > 0 {
		set = append(set, fmt.Sprintf("documentSize %d", in.docSize))
	}
	if len(set) > 0 {
		b.WriteString("the namespace sets " + strings.Join(set, " and ") + " (§6.6)")
	} else {
		b.WriteString("the namespace sets no size limits, so the deployment's apply (§6.6; by default patchSetSize 262144 and documentSize 1048576)")
	}
	return fail(http.StatusRequestEntityTooLarge, "%s", b.String())
}

// undelete restores ns/name, tombstoned by the principal's own DELETE as
// tomb, as it was (an empty patch set on the last live document, §8.2,
// with If-Match on tomb), after the write meant to restore it failed with
// err, which it returns, saying so.
func (st *reqState) undelete(ctx context.Context, in nsInfo, ns, name, tomb string, err error) error {
	if _, rerr := st.p.c.Restore(ctx, ns, name, tomb, withNonce(in, []any{})); rerr != nil {
		st.s.opt.Logf("dav: %s/%s: restoring it as it was after a refused save: %v", ns, name, rerr)
		return err
	}
	st.p.forgetDelete(ns, name)
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
// it. So is a placement's node the principal's DELETE removed (unplaced)
// before the write to its path. Only the principal's own tombstone, still
// the head, is restored (with If-Match on it).
func (st *reqState) undoOwnDelete(ctx context.Context, t target, err error) error {
	if err == nil || !t.isDoc() {
		return err
	}
	type res struct{ ns, name string }
	todo := []res{{t.docNS, t.docName}}
	if t.kind == kNewPlacement {
		todo = append(todo, res{t.ns, t.node})
	}
	for _, r := range todo {
		if !st.p.deletedOwn(r.ns, r.name, "") {
			continue
		}
		h, herr := st.p.c.Head(ctx, r.ns, r.name)
		if herr != nil || h.State != client.Tombstoned || !st.p.deletedOwn(r.ns, r.name, h.ID) {
			continue
		}
		err = st.undelete(ctx, st.s.nsInfo(ctx, st.p, r.ns), r.ns, r.name, h.ID, err)
		st.changed()
	}
	return err
}

// deleteDoc tombstones ns/name (§8.1), if its head is ifMatch when that
// is given (412 otherwise). The principal's records of it stay: a save
// that deletes the original before writing the new version restores it
// from them (restorePatches), or as it was if that write is refused.
func (st *reqState) deleteDoc(ctx context.Context, ns, name, ifMatch string) error {
	if st.s.nsInfo(ctx, st.p, ns).sealed {
		return fail(http.StatusNotImplemented, "%s is sealed or end-to-end (Addendum E); it isn't written over WebDAV", ns)
	}
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if h.State != client.Live {
			return false, errNotExist
		}
		if ifMatch != "" && h.ID != ifMatch {
			return false, fail(http.StatusPreconditionFailed, "%s/%s changed since %s (If-Match); reload it", ns, name, ifMatch)
		}
		res, err := st.p.c.Delete(ctx, ns, name, h.ID)
		if client.IsStale(err) {
			return true, nil
		}
		if err == nil {
			st.p.noteDelete(ns, name, res.ID, st.s.opt.Now())
		}
		return false, err
	})
	if errors.Is(err, errNotExist) {
		return errNotExist
	}
	return err
}
