package dav

import (
	"context"
	"errors"
	"net/http"
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

// commitDoc writes v as the document of ns/name and returns its head
// revision afterwards. A new name is created (If-None-Match: *), a
// tombstoned one restored with the whole document (one name keeps one
// chain, §8.2), and a live one edited: the diff from what the principal
// was last served (or wrote) to v, appended on the head (§11 submit).
func (st *reqState) commitDoc(ctx context.Context, ns, name string, v any) (string, error) {
	in := st.s.nsInfo(ctx, st.p, ns)
	if in.sealed {
		return "", fail(http.StatusNotImplemented, "%s is sealed or end-to-end (Addendum E); it isn't written over WebDAV", ns)
	}
	var rev string
	err := st.retrying(ctx, func() (bool, error) {
		h, err := st.p.c.Head(ctx, ns, name)
		if err != nil {
			return false, err
		}
		switch h.State {
		case client.Purged:
			return false, fail(http.StatusForbidden, "%s/%s was purged; its name can't be used again (§8.3)", ns, name)
		case client.NotFound, client.Tombstoned:
			doc := v
			if in.nonce {
				doc = dropNonce(v)
			}
			var res *client.WriteResult
			if h.State == client.NotFound {
				ps := withNonce(in, client.GenesisPatches(doc))
				res, err = st.p.c.Create(ctx, ns, name, ps)
				if err == nil {
					st.wrote(ns, name, map[string]any{}, ps, res, v)
				}
			} else {
				ps := withNonce(in, []any{map[string]any{"op": "replace", "path": "", "value": doc}})
				res, err = st.p.c.Restore(ctx, ns, name, h.ID, ps)
				if err == nil {
					st.wrote(ns, name, map[string]any{}, ps, res, v)
				}
			}
			if client.IsStale(err) || client.IsGone(err) {
				return false, fail(http.StatusConflict, "%s/%s was created or restored by someone else meanwhile; reload it", ns, name)
			}
			if err != nil {
				return false, err
			}
			rev = res.ID
			return false, nil
		}
		r, retry, err := st.edit(ctx, in, ns, name, h.ID, v)
		rev = r
		return retry, err
	})
	return rev, err
}

// edit appends the principal's edit of ns/name on head: the diff from its
// base to v. Changes others made since the base are kept; where they
// overlap the edit's, compared as merges compare writes (§F.3: a write
// inside an array counts for the whole array), the save is 409 and nothing
// is written, never an overwrite. retry: the head moved (412), read it
// again.
func (st *reqState) edit(ctx context.Context, in nsInfo, ns, name, head string, v any) (string, bool, error) {
	cur, err := st.s.doc(ctx, st.p, ns, name, head)
	if err != nil {
		return "", false, err
	}
	if cur.sealed {
		return "", false, fail(http.StatusNotImplemented, "%s/%s is sealed (Addendum E); it isn't written over WebDAV", ns, name)
	}
	base := cur.value
	if sv := st.p.servedOf(ns, name); sv != nil && sv.rev != "" {
		switch {
		case sv.doc != nil:
			base = sv.doc
		case sv.rev != head:
			if e, err := st.s.doc(ctx, st.p, ns, name, sv.rev); err == nil && !e.sealed {
				base = e.value
			}
			// A base that can't be read any more (pruned, §8.6) leaves the
			// head as base.
		}
	}
	base, theirs, mine := dropNonce(base), dropNonce(cur.value), dropNonce(v)
	ours := merge.Diff(base, mine)
	if len(ours) == 0 || jsonv.Equal(mine, theirs) {
		// Nothing changed, or it already reads so.
		return head, false, nil
	}
	if !jsonv.Equal(base, theirs) {
		if clash := overlaps(base, ours, merge.Diff(base, theirs)); len(clash) > 0 {
			return "", false, fail(http.StatusConflict, "%s/%s was changed by someone else since you opened it, where you changed it too: %s; reload it and edit again",
				ns, name, strings.Join(clash, ", "))
		}
	}
	ps := withNonce(in, ours)
	res, err := st.p.c.Append(ctx, ns, name, head, ps)
	switch {
	case client.IsStale(err):
		return "", true, nil
	case client.IsGone(err):
		return "", false, fail(http.StatusConflict, "%s/%s was deleted meanwhile", ns, name)
	case isPatchFailure(err):
		return "", false, fail(http.StatusConflict, "your edit no longer applies to %s/%s, which someone else changed: %s; reload it and edit again", ns, name, apiText(errAPI(err)))
	case err != nil:
		return "", false, err
	}
	st.wrote(ns, name, cur.value, ps, res, v)
	return res.ID, false, nil
}

func errAPI(err error) *client.APIError {
	ae, _ := client.AsAPIError(err)
	return ae
}

// overlaps returns the paths where ours and theirs, both diffs from base,
// overlap: their writes (§6.4.1) under the array rule of §F.3.
func overlaps(base any, ours, theirs []any) []string {
	a, errA := merge.Writes(base, true, []client.Step{client.PatchStep(ours)})
	b, errB := merge.Writes(base, true, []client.Step{client.PatchStep(theirs)})
	if errA != nil || errB != nil {
		return []string{"(the whole document)"}
	}
	return merge.Overlaps(pointers(a), pointers(b))
}

func pointers(ss []string) []pointer.Pointer {
	out := make([]pointer.Pointer, 0, len(ss))
	for _, s := range ss {
		if p, err := pointer.Parse(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// wrote records a write: the principal's next save of ns/name is diffed
// from v, what it wrote, and the revision's document, the patches applied
// to parent as the core applies them, is cached with its creation time
// from the log entry. A create or restore replaces the whole document, so
// its parent is any object.
func (st *reqState) wrote(ns, name string, parent any, ps []any, res *client.WriteResult, v any) {
	canon := jsonv.Canonical(v)
	st.p.setServed(ns, name, &served{rev: res.ID, doc: v}, 2*len(canon))
	ops, err := patch.Parse(ps)
	if err != nil {
		return
	}
	doc, _, err := patch.Apply(parent, true, ops, patch.Options{})
	if err != nil {
		return
	}
	e := &docEntry{value: doc, rendered: render(doc)}
	if res.Entry != nil {
		e.created, _ = time.Parse(time.RFC3339Nano, res.Entry.Created)
	}
	st.s.keep(docKey(ns, name, res.ID), e)
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

// deleteDoc tombstones ns/name (§8.1); the principal's base for it goes.
func (st *reqState) deleteDoc(ctx context.Context, ns, name string) error {
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
		_, err = st.p.c.Delete(ctx, ns, name, h.ID)
		if client.IsStale(err) {
			return true, nil
		}
		return false, err
	})
	if err == nil {
		st.p.forget(ns, name)
	}
	if errors.Is(err, errNotExist) {
		return errNotExist
	}
	return err
}
