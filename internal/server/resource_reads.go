package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// Resource reads (§7.1).

func (s *Server) resourceHead(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	h, err := s.e.ResourceHead(r.Context(), ns, name, creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err, resTags(ns, name)...) {
			return
		}
		writeErr(w, err)
		return
	}
	if h.State == core.Live {
		s.cache(w, r, ccHead, h.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(h.Head))
		w.Header().Set("Location", "/r/"+ns+"/"+name+"/rev/"+h.Head)
		w.WriteHeader(302)
		return
	}
	s.headGone(w, r, ns, name, h)
}

// headGone answers a head pointer that isn't live (§7.1): never existed
// (short), purged (long), or tombstoned, with successor where the engine
// read one (§8.1: a moved resource, outside sealed and e2e namespaces);
// each with the resource's tags (§9).
func (s *Server) headGone(w http.ResponseWriter, r *http.Request, ns, name string, h *core.Head) {
	switch h.State {
	case core.NotFound:
		s.cache(w, r, ccShort, h.Public, resTags(ns, name)...)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case core.Purged:
		s.cache(w, r, ccLong, h.Public, resTags(ns, name)...)
		writeJSON(w, 410, map[string]any{"code": "gone"})
	case core.Tombstoned:
		s.cache(w, r, ccHead, h.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(h.Head))
		body := map[string]any{"code": "gone", "tombstone": h.Head, "last": h.Last}
		if h.Successor != "" {
			body["successor"] = h.Successor
		}
		writeJSON(w, 410, body)
	}
}

// resourceRaw is GET /r/{ns}/{name}/raw and …/rev/{id}/raw (§7.1, §7.8):
// for a raw document, a 302 to the blob its root references, so a file
// stored as a blob has a URL of its own; a document that isn't raw is 404
// not_found. Both are cached as the document URL they stand for, a head
// pointer or immutable, with its tags, as is a sealed or e2e namespace's
// 404 not_offered (a level is never lowered). Every other answer is the
// document URL's: an unknown id or head, a purge, a prune, a tombstone id
// and a tombstoned head (with successor, §8.1). The Location is the
// serving namespace's, so a branch reads its base's blob through.
func (s *Server) resourceRaw(w http.ResponseWriter, r *http.Request) {
	ns, name, id := r.PathValue("ns"), r.PathValue("name"), r.PathValue("id")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	class := ccHead
	if id != "" {
		class = ccImmutable
	}
	raw, err := s.e.ResourceRaw(r.Context(), ns, name, id, creds(r))
	if err != nil {
		var ae *core.Error
		if errors.As(err, &ae) && ae.Status == 404 && ae.Body["code"] == "not_offered" && ae.Public != nil {
			s.cache(w, r, class, *ae.Public, resTags(ns, name)...)
			writeJSON(w, 404, ae.Body)
			return
		}
		if s.writeErrShort(w, r, err, resTags(ns, name)...) {
			return
		}
		writeErr(w, err)
		return
	}
	if raw.Rev == nil {
		s.headGone(w, r, ns, name, raw.Head)
		return
	}
	if raw.Rev.Status != 200 {
		// The head moved on, or the document went, since it was read.
		rid := id
		if rid == "" {
			rid = raw.Head.Head
		}
		s.revGone(w, r, ns, name, rid, raw.Rev)
		return
	}
	s.cache(w, r, class, raw.Rev.Public, resTags(ns, name)...)
	if id == "" {
		w.Header().Set("ETag", quote(raw.Head.Head))
	} else {
		w.Header().Set("ETag", quote(id))
		w.Header().Set("X-Revision", id)
	}
	if raw.Blob == "" {
		writeJSON(w, 404, map[string]any{"code": "not_found", "message": "not a raw document (§7.8)"})
		return
	}
	w.Header().Set("Location", "/r/"+ns+"/"+name+"/blob/"+raw.Blob)
	w.WriteHeader(302)
}

func (s *Server) resourceRev(w http.ResponseWriter, r *http.Request) {
	ns, name, id := r.PathValue("ns"), r.PathValue("name"), r.PathValue("id")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	rev, err := s.e.ResourceRev(r.Context(), ns, name, id, creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err, resTags(ns, name)...) {
			return
		}
		writeErr(w, err)
		return
	}
	switch {
	case rev.Fold:
		// An e2e revision (§E.3): the server has no document, so the
		// client folds the log from the latest snapshot at or before it.
		// The target only changes when a prune adds a newer snapshot,
		// and the old target stays correct (§8.6), so it caches long.
		loc := "/r/" + ns + "/" + name + "/rev/" + id + "/log"
		if rev.FoldSince != "" {
			loc += "?since=" + rev.FoldSince
		}
		s.cache(w, r, ccLong, rev.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(id))
		w.Header().Set("X-Revision", id)
		w.Header().Set("X-E2E", "fold")
		w.Header().Set("Location", loc)
		w.WriteHeader(302)
	case rev.Snapshot:
		// An e2e prune's sealed snapshot, served as /rev/{H} and never as
		// a log entry (§7.1 Paging, §8.6): 200 as the revision's sealed
		// document, or for a tombstone horizon the tombstone's 410 with
		// the snapshot (the last live document) in its body. Either is
		// immutable: the snapshot stays stored until a later prune or a
		// purge makes the revision 410 for good.
		s.cache(w, r, ccImmutable, rev.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(id))
		w.Header().Set("X-Revision", id)
		w.Header().Set("X-E2E", "snapshot")
		if s.notModified(r, quote(id), rev) {
			w.WriteHeader(304)
			return
		}
		if rev.Status == 410 {
			writeJSON(w, 410, map[string]any{"code": "gone", "snapshot": rev.JWE})
			return
		}
		s.revMeta(w, rev)
		w.Header().Set("Content-Type", seal.ContentType)
		w.WriteHeader(200)
		if r.Method != http.MethodHead {
			w.Write([]byte(rev.JWE))
		}
	case rev.Status == 200:
		if rev.Referrer {
			referrerCache(w)
		} else {
			s.cache(w, r, ccImmutable, rev.Public, resTags(ns, name)...)
		}
		// A sealed document's tag names its epoch (§E.2.2); an e2e
		// snapshot's (above) and a head pointer's don't.
		tag := quote(id)
		if rev.JWE != "" {
			tag = sealedTag(id, rev.JWE)
		}
		w.Header().Set("ETag", tag)
		w.Header().Set("X-Revision", id)
		if rev.SchemaRules != "" {
			// The rules marker of a schema revision (§6.1), immutable as
			// the revision is: a client or a remote mirror compiles it as
			// this server does.
			w.Header().Set(schema.RulesHeader, rev.SchemaRules)
		}
		if s.notModified(r, tag, rev) {
			w.WriteHeader(304)
			return
		}
		body, ct := rev.Doc, "application/json"
		if rev.JWE != "" {
			body, ct = []byte(rev.JWE), seal.ContentType
		}
		s.revMeta(w, rev)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(200)
		if r.Method != http.MethodHead {
			w.Write(body)
		}
	default:
		s.revGone(w, r, ns, name, id, rev)
	}
}

// revGone answers a revision URL without a document (§7.1): an unknown
// id (short), a pruned revision, a tombstone id (immutable) or a purge
// (long), each with the resource's tags (§9).
func (s *Server) revGone(w http.ResponseWriter, r *http.Request, ns, name, id string, rev *core.Rev) {
	switch {
	case rev.Status == 404:
		s.cache(w, r, ccShort, rev.Public, resTags(ns, name)...)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case rev.Code == "pruned":
		s.cache(w, r, ccPruned, rev.Public, resTags(ns, name)...)
		writeJSON(w, 410, prunedBody(rev.Horizon, rev.Archive))
	case rev.Code == "tombstone":
		// A tombstone id is immutable (§7.1).
		s.cache(w, r, ccImmutable, rev.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(id))
		writeJSON(w, 410, map[string]any{"code": "gone"})
	default:
		// A purge is "long".
		s.cache(w, r, ccLong, rev.Public, resTags(ns, name)...)
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}

// revMeta sets a revision's 200 headers outside sealed and e2e namespaces
// (§7.1), where the engine sets Created and Digest: Last-Modified
// (lastModified), and Repr-Digest (RFC 9530), the sha-256 of the canonical
// document served, which no content coding changes (none is applied).
// Sealed and e2e reads carry neither (§E.2.2), the e2e keyring included.
func (s *Server) revMeta(w http.ResponseWriter, rev *core.Rev) {
	if lm, ok := s.lastModified(rev); ok {
		w.Header().Set("Last-Modified", lm.Format(http.TimeFormat))
	}
	if rev.JWE == "" && len(rev.Digest) > 0 {
		w.Header().Set("Repr-Digest", core.ReprDigest(rev.Digest))
	}
}

// lastModified is a revision's Last-Modified: its created time to the
// second, which never changes, but never later than now (RFC 9110
// §8.8.2.1). Created times come from the writing instance's clock, or a
// remote base's entries (§G.3), unchecked.
func (s *Server) lastModified(rev *core.Rev) (time.Time, bool) {
	if rev.Created.IsZero() {
		return time.Time{}, false
	}
	lm, now := rev.Created.UTC().Truncate(time.Second), s.e.Now().UTC().Truncate(time.Second)
	if lm.After(now) {
		lm = now
	}
	return lm, true
}

// notModified tells whether a revision's answer is a 304: If-None-Match
// names its tag (an immutable ETag, "{id}.{e}" when sealed), or, without
// If-None-Match, a 200's Last-Modified is no later than If-Modified-Since
// (§7.1, RFC 9110 §13.1.3, §13.2.2). Either is exact: a revision never
// changes. Where no Last-Modified is sent (sealed and e2e namespaces)
// If-Modified-Since is ignored, so 304s can't be probed for the created
// time the level hides.
func (s *Server) notModified(r *http.Request, tag string, rev *core.Rev) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return inmMatches(inm, tag)
	}
	ims := r.Header.Values("If-Modified-Since")
	if rev.Status != 200 || len(ims) != 1 {
		return false
	}
	since, err := http.ParseTime(ims[0])
	lm, ok := s.lastModified(rev)
	return err == nil && ok && !lm.After(since)
}

func (s *Server) resourceRevLog(w http.ResponseWriter, r *http.Request) {
	ns, name, id := r.PathValue("ns"), r.PathValue("name"), r.PathValue("id")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	lg, err := s.e.ResourceLog(r.Context(), ns, name, id, r.URL.Query().Get("since"), s.e.Limits().LogPageSize, creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err, resTags(ns, name)...) {
			return
		}
		writeErr(w, err)
		return
	}
	s.writeLog(w, r, lg, ns, resTags(ns, name))
}
