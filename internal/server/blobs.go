package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// Blobs (§7.8).

func (s *Server) blobPut(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name, bid := r.PathValue("ns"), r.PathValue("name"), r.PathValue("bid")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	up := blobUpload(r)
	if up.From != "" {
		// A copy has an empty body (400 if not, in its place in the order,
		// before any body is read): a declared length says so; only a
		// body of unknown length is peeked at.
		switch {
		case r.ContentLength > 0:
			up.HasBody = true
		case r.ContentLength < 0:
			var one [1]byte
			n, _ := io.ReadFull(r.Body, one[:])
			up.HasBody = n > 0
		}
	}
	req := core.Request{NS: ns, Cred: creds(r), SourceCreds: sourceCreds(r)}
	if err := s.uploadBlob(r.Context(), req, name, bid, up); err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("ETag", quote(bid))
	w.Header().Set("Location", "/r/"+ns+"/"+name+"/blob/"+bid)
	w.WriteHeader(201)
}

// blobUpload is what an upload or copy's headers say (§7.8), for the
// core's checks in their order: Blob-Nonce as sent, repeated values joined
// as a list would be, which is no nonce (check 4); whether a precondition,
// which an upload doesn't take, was sent (428 at check 4); and two, or a
// malformed one, as a request-shape error in its headers (400 at check 4).
func blobUpload(r *http.Request) core.BlobUpload {
	up := core.BlobUpload{Type: r.Header.Get("Content-Type"), From: r.Header.Get("Blob-From"), Body: r.Body, Length: r.ContentLength}
	if vs := r.Header.Values("Blob-Nonce"); len(vs) > 0 {
		up.NonceSent, up.Nonce = true, strings.Join(vs, ",")
	}
	if p, err := preconditions(r); err != nil {
		up.ShapeErr = errMessage(err)
	} else {
		up.Precondition = p.sent()
	}
	return up
}

// blobRoutes are the routes that read blobs, whose every answer carries
// blobHeaders.
var blobRoutes = map[string]bool{
	"GET /r/{ns}/{name}/blob/{bid}":       true,
	"GET /r/{ns}/{name}/blob/{bid}/e/{e}": true,
}

// blobHeaders sets what every blob response carries, errors and the
// sealed 302 included (§7.8 Reading): writers choose a blob's type and its
// URL is on the API's origin, so browsers must neither sniff another type
// nor run script from one. sandbox alone, not the services' default-src
// 'none', so images and text still display inline. Chromium's PDF viewer
// is an extension, which shows a sandboxed PDF as a blank page.
func blobHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
}

func (s *Server) blobGet(w http.ResponseWriter, r *http.Request) {
	blobHeaders(w)
	ns, name, bid := r.PathValue("ns"), r.PathValue("name"), r.PathValue("bid")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	b, err := s.e.OpenBlob(r.Context(), ns, name, bid, creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err) {
			return
		}
		writeErr(w, err)
		return
	}
	defer b.Close()
	if b.Status == 302 {
		// A sealed namespace: to the latest epoch the blob is served under,
		// cached as a head pointer (§E.2.2).
		s.cache(w, r, ccHead, b.Public, resTags(ns, name)...)
		w.Header().Set("Location", "/r/"+ns+"/"+name+"/blob/"+bid+"/e/"+strconv.Itoa(b.Epoch))
		w.WriteHeader(302)
		return
	}
	s.serveBlob(w, r, ns, name, quote(bid), b)
}

// blobEpochGet serves a blob of a sealed namespace sealed under an epoch
// (§E.2.2).
func (s *Server) blobEpochGet(w http.ResponseWriter, r *http.Request) {
	blobHeaders(w)
	ns, name, bid, ep := r.PathValue("ns"), r.PathValue("name"), r.PathValue("bid"), r.PathValue("e")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	b, err := s.e.OpenSealedBlob(r.Context(), ns, name, bid, ep, creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err) {
			return
		}
		writeErr(w, err)
		return
	}
	defer b.Close()
	s.serveBlob(w, r, ns, name, quote(bid+"."+ep), b)
}

// serveBlob writes a blob answer (§7.8 Reading) with ETag etag for a 200.
func (s *Server) serveBlob(w http.ResponseWriter, r *http.Request, ns, name, etag string, b *core.Blob) {
	switch {
	case b.Status == 200:
		// Immutable, with the resource's tags (§9); ranges are 206.
		s.cache(w, r, ccImmutable, b.Public, resTags(ns, name)...)
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", b.Type)
		http.ServeContent(w, r, "", time.Time{}, b.Content)
	case b.NoStore:
		// An epoch a sealed namespace doesn't serve the blob under, yet
		// (§E.2.2).
		noStore(w)
		writeJSON(w, b.Status, map[string]any{"code": "not_found"})
	case b.Status == 404:
		s.cache(w, r, ccShort, b.Public)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case b.Code == "pruned":
		s.cache(w, r, ccPruned, b.Public, resTags(ns, name)...)
		writeJSON(w, 410, prunedBody(b.Horizon, b.Archive))
	case b.Status == 410:
		s.cache(w, r, ccLong, b.Public)
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}
