package server

import (
	"net/http"
	"strings"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// Namespace reads (§7.4, §C.3.1, §E.2.3).

// nsGrant is GET /ns/{ns}/grants/{gid} (§C.3.1): a grant recorded by an
// entry of the namespace or of its local bases, in its non-bearer form.
// Immutable; a JWE in sealed namespaces (§E.2.2), and private rather than
// publicly cached in end-to-end ones (§9).
func (s *Server) nsGrant(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	g, err := s.e.Grant(r.Context(), ns, r.PathValue("gid"), creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err) {
			return
		}
		writeErr(w, err)
		return
	}
	if g.Private {
		// Not the immutable class: no shared cache, edge included, keeps
		// a copy (§C.3.1, §9).
		w.Header().Set("Cache-Control", "private, max-age=300")
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Surrogate-Control", "no-store")
	} else {
		s.cache(w, r, ccImmutable, g.Public, "ns:"+ns)
	}
	if g.JWE != "" {
		w.Header().Set("Content-Type", seal.ContentType)
		w.WriteHeader(200)
		if r.Method != http.MethodHead {
			w.Write([]byte(g.JWE))
		}
		return
	}
	writeJSON(w, 200, g)
}

func (s *Server) nsHead(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	info, err := s.e.NamespaceHead(r.Context(), ns, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	s.cache(w, r, ccHead, info.Public, "ns:"+ns)
	w.Header().Set("ETag", quote(info.Head))
	w.Header().Set("X-Config-Revision", info.Config)
	w.Header().Set("Location", "/ns/"+ns+"/rev/"+info.Head)
	w.WriteHeader(302)
}

func (s *Server) nsRev(w http.ResponseWriter, r *http.Request) {
	ns, id := r.PathValue("ns"), r.PathValue("id")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	info, err := s.e.NamespaceRev(r.Context(), ns, id, creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err) {
			return
		}
		writeErr(w, err)
		return
	}
	s.cache(w, r, ccImmutable, info.Public, "ns:"+ns)
	w.Header().Set("ETag", quote(id))
	w.Header().Set("X-Config-Revision", info.Config)
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, quote(id)) {
		w.WriteHeader(304)
		return
	}
	body, ct := info.Doc, "application/json"
	if info.JWE != "" {
		body, ct = []byte(info.JWE), seal.ContentType
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func (s *Server) nsRevLog(w http.ResponseWriter, r *http.Request) {
	ns, id := r.PathValue("ns"), r.PathValue("id")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	lg, err := s.e.NamespaceLog(r.Context(), ns, id, r.URL.Query().Get("since"), s.e.Limits().LogPageSize, creds(r))
	if err != nil {
		// A purged sealed namespace's 410 is long, as any purge (§8.5, §9).
		if s.writeErrShort(w, r, err) {
			return
		}
		writeErr(w, err)
		return
	}
	s.writeLog(w, r, lg, ns, []string{"ns:" + ns})
}

// nsGestures is GET /ns/{ns}/gestures/{gesture} (§7.4, optional): the
// revisions and tombstones written with the gesture or undoing it, oldest
// first, paged as in §7.1 with X-Log-Next naming the cursor of the next
// page, "{resource}/{id}", which the next request gives as ?after=
// (core/gestures.go). The list grows: no-store.
func (s *Server) nsGestures(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	page, err := s.e.Gestures(r.Context(), ns, r.PathValue("gesture"), r.URL.Query().Get("after"), creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if page.Next != "" {
		w.Header().Set("X-Log-Next", page.Next)
	}
	entries := make([]any, len(page.Entries))
	for i, e := range page.Entries {
		entries[i] = e
	}
	writeJSON(w, 200, entries)
}

// nsPrincipal is GET /ns/{ns}/principal (§7.4): what the grant in
// Authorization is here, and what a writer needs from the namespace
// document, with X-Config-Revision. Every answer, errors and the 410 of a
// purged namespace included, is no-store: the origin answers it with the
// grant, which no edge cookie covers (§C.5).
func (s *Server) nsPrincipal(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	ans, err := s.e.Principal(r.Context(), ns, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Config-Revision", ans.Config)
	writeJSON(w, 200, ans.Body)
}

func (s *Server) nsHeads(w http.ResponseWriter, r *http.Request) {
	ns, id := r.PathValue("ns"), r.PathValue("id")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	page, err := s.e.NamespaceHeads(r.Context(), ns, id, r.URL.Query().Get("after"), creds(r))
	if err != nil {
		if s.writeErrShort(w, r, err) {
			return
		}
		writeErr(w, err)
		return
	}
	// heads:{ns} too, which a resource purge purges: an entry's size and
	// digest (§7.4) are its document's, which a purge removes, unlike the
	// names and ids the page also lists. §8.3 accepts that a digest
	// already served survives a purge; this tag, the reference's own,
	// clears the copies its edge holds.
	s.cache(w, r, ccImmutable, page.Public, "ns:"+ns, "heads:"+ns)
	out := map[string]any{"items": page.Items}
	if page.Next != "" {
		out["next"] = page.Next
	}
	writeJSON(w, 200, out)
}

func (s *Server) nsBranches(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	list, public, err := s.e.Branches(r.Context(), ns, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	s.cache(w, r, ccHead, public, "ns:"+ns)
	writeJSON(w, 200, list)
}

// nsKeys answers POST /ns/{ns}/keys (§E.2.3): { "epochs"?: [e…],
// "resources"?: [name…] } → { "keys": [ { kid, resource?, key | suite,
// wrapped } ], "epoch", "level", "pad" }, never cached. A namespace that
// isn't sealed is 404 not_offered.
func (s *Server) nsKeys(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	var kr core.KeysRequest
	if r.ContentLength != 0 {
		// A body is JSON (§7.2); without one, the request asks for the
		// default keys (§E.2.3).
		if err := requireType(r, jsonType); err != nil {
			writeErr(w, err)
			return
		}
		body, err := readJSON(r, 1<<20, noLimit)
		if err != nil {
			writeErr(w, err)
			return
		}
		m, ok := body.(map[string]any)
		if !ok {
			writeErr(w, badInput(`body must be { "epochs"?, "resources"? }`))
			return
		}
		for k, v := range m {
			arr, ok := v.([]any)
			if !ok {
				writeErr(w, badInput(k+" must be an array"))
				return
			}
			switch k {
			case "epochs":
				kr.Epochs = []int{}
				for _, x := range arr {
					f, ok := x.(float64)
					if !ok || f < 0 || f != float64(int(f)) {
						writeErr(w, badInput("epochs must be non-negative integers"))
						return
					}
					kr.Epochs = append(kr.Epochs, int(f))
				}
			case "resources":
				for _, x := range arr {
					n, ok := x.(string)
					if !ok {
						writeErr(w, badInput("resources must be resource names"))
						return
					}
					kr.Resources = append(kr.Resources, n)
				}
			default:
				writeErr(w, badInput("unknown member "+k))
				return
			}
		}
	}
	ans, err := s.e.Keys(r.Context(), ns, creds(r), kr)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]any, len(ans.Keys))
	for i, k := range ans.Keys {
		out[i] = k
	}
	writeJSON(w, 200, map[string]any{"keys": out, "epoch": ans.Epoch, "level": ans.Level, "pad": ans.Pad})
}
