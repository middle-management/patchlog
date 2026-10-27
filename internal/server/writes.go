package server

import (
	"net/http"

	"github.com/middle-management/patchlog/internal/core"
)

// Writes (§7.2, §7.4, §7.5, §7.6, §8.3, §8.5, §8.6).

func (s *Server) resourcePatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, true); err != nil {
		writeErr(w, err)
		return
	}
	if err := requireType(r, jsonPatchType); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	g, u, err := gestures(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	sg, err := signature(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	bound, lim := s.patchBody()
	body, err := readJSON(r, bound, lim)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.writeResource(r.Context(), core.Request{NS: ns, Cred: creds(r), Signature: sg, SourceCreds: sourceCreds(r)},
		core.Item{Resource: name, IfMatch: p.ifMatch, IfNoneMatch: p.ifNoneMatch, Steps: []core.Step{{Patches: body, Gesture: g, Undoes: u}}})
	if err != nil {
		writeErr(w, err)
		return
	}
	id := res.Items[0].IDs[len(res.Items[0].IDs)-1]
	w.Header().Set("Location", "/r/"+ns+"/"+name+"/rev/"+id)
	w.Header().Set("ETag", quote(id))
	setGestures(w, res.Entry)
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	writeJSON(w, res.Status, res.Entry)
}

func (s *Server) resourceDelete(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, true); err != nil {
		writeErr(w, err)
		return
	}
	// If-None-Match: * is a precondition DELETE doesn't take: the core's
	// 428, after authorisation (§7.5, §12.1), not a request-shape error.
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	g, u, err := gestures(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	sg, err := signature(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.writeResource(r.Context(), core.Request{NS: ns, Cred: creds(r), Signature: sg},
		core.Item{Resource: name, IfMatch: p.ifMatch, IfNoneMatch: p.ifNoneMatch, Steps: []core.Step{{Delete: true, Gesture: g, Undoes: u}}})
	if err != nil {
		writeErr(w, err)
		return
	}
	id := res.Items[0].IDs[0]
	w.Header().Set("ETag", quote(id))
	setGestures(w, res.Entry)
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	writeJSON(w, 200, map[string]any{"tombstone": id})
}

func (s *Server) resourcePurge(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, false); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	force := r.URL.Query().Get("force") == "1"
	nsID, err := s.purge(r.Context(), core.Request{NS: ns, Cred: creds(r), SourceCreds: sourceCreds(r)}, name, p.ifMatch, force)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Namespace-Revision", nsID)
	w.WriteHeader(204)
}

func (s *Server) resourcePrune(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, false); err != nil {
		writeErr(w, err)
		return
	}
	pr, err := pruneRequest(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.prune(r.Context(), core.Request{NS: ns, Cred: creds(r)}, name, pr)
	if err != nil {
		writeErr(w, err)
		return
	}
	// An entry only where the prune moved the horizon or changed the keep
	// set (§7.2, §8.6).
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	// The answer is { horizon }, the effective horizon, and nothing else
	// (§8.6): the archive is linked from the pruned revisions' 410 (§7.1).
	writeJSON(w, 200, map[string]any{"horizon": res.Horizon})
}

// pruneRequest reads a prune's request (§8.6): its preconditions, which a
// prune doesn't take, so one sent is the core's 428 at step 2.5 while two,
// or a malformed one, are request-shape 400s; then a JSON body { horizon,
// keep?, snapshot? }. horizon and every keep entry are ids in text form,
// or 400 (§7); a well-formed id the resource lacks is the core's 422.
// keep: [] is told from no keep (KeepSent).
func pruneRequest(r *http.Request) (core.PruneRequest, error) {
	var pr core.PruneRequest
	p, err := preconditions(r)
	if err != nil {
		return pr, err
	}
	pr.Precondition = p.sent()
	if err := requireType(r, jsonType); err != nil {
		return pr, err
	}
	body, err := readJSON(r, 1<<20, noLimit)
	if err != nil {
		return pr, err
	}
	m, ok := body.(map[string]any)
	pr.Horizon, _ = m["horizon"].(string)
	if !ok || pr.Horizon == "" {
		return pr, badInput("body must be { horizon, keep?, snapshot? }")
	}
	if !validID(pr.Horizon) {
		return pr, badInput("horizon must be an id in text form (§7, §8.6)")
	}
	var k any
	if k, pr.KeepSent = m["keep"]; pr.KeepSent {
		arr, ok := k.([]any)
		if !ok {
			return pr, badInput("keep must be an array of ids")
		}
		pr.Keep = []string{}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok || !validID(s) {
				return pr, badInput("keep must be an array of ids in text form (§7, §8.6)")
			}
			pr.Keep = append(pr.Keep, s)
		}
	}
	// A sealed snapshot needs no declared list (§8.6, §E.3.1): the server
	// keeps the list of the snapshot's revision.
	if x, has := m["snapshot"]; has {
		if pr.Snapshot, ok = x.(string); !ok || pr.Snapshot == "" {
			return pr, badInput("snapshot must be a JWE (compact serialization)")
		}
	}
	return pr, nil
}

func (s *Server) nsPatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, false); err != nil {
		writeErr(w, err)
		return
	}
	if err := requireType(r, jsonPatchType); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	bound, lim := s.patchBody()
	body, err := readJSON(r, bound, lim)
	if err != nil {
		writeErr(w, err)
		return
	}
	// A config write is a single write (§7.4), so it MAY carry gestures,
	// which are stored with the config entry, outside its id (§7.2).
	gesture, undoes, gerr := gestures(r)
	if gerr != nil {
		writeErr(w, gerr)
		return
	}
	// No server-side 428: the core answers it after authorisation (§6.2).
	res, err := s.writeConfig(r.Context(), core.Request{NS: ns, Cred: creds(r), SourceCreds: sourceCreds(r)},
		core.ConfigChange{IfMatch: p.ifMatch, IfNoneMatch: p.ifNoneMatch, Patches: body, Gesture: gesture, Undoes: undoes})
	if err != nil {
		writeErr(w, err)
		return
	}
	setGestures(w, res.Entry)
	w.Header().Set("X-Config-Revision", res.ConfigID)
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
		w.Header().Set("Location", "/ns/"+ns+"/rev/"+res.NSID)
	}
	out := map[string]any{"config": res.ConfigID}
	if res.NSID != "" {
		out["ns_id"] = res.NSID
	}
	writeJSON(w, res.Status, out)
}

func (s *Server) nsCreateBranch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, false); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := requireType(r, jsonType); err != nil {
		writeErr(w, err)
		return
	}
	bound, lim := s.patchBody()
	body, err := readJSON(r, bound, lim)
	if err != nil {
		writeErr(w, err)
		return
	}
	m, ok := body.(map[string]any)
	if !ok {
		writeErr(w, badInput("body must be { name, at?, patches? }"))
		return
	}
	if _, remote := m["remote"]; remote {
		s.registerRemote(w, r, ns, p, m)
		return
	}
	for k := range m {
		if k != "name" && k != "at" && k != "patches" {
			writeErr(w, badInput("unknown member "+k))
			return
		}
	}
	name, _ := m["name"].(string)
	// A malformed name is the request's own shape: 400 before
	// authentication and an unknown base's 404, as a malformed at (§3.6,
	// §6.2).
	if !core.ValidNSName(name) {
		writeErr(w, badInput("invalid branch name"))
		return
	}
	// at, if given, is an ns_id in text form, or 400 (§7); one that isn't
	// in the base's chain is the core's 422 (§7.6).
	var at string
	if v, has := m["at"]; has {
		if at, ok = v.(string); !ok || !validID(at) {
			writeErr(w, badInput("at must be an ns_id in text form (§7, §7.6)"))
			return
		}
	}
	res, err := s.createBranch(r.Context(), core.Request{NS: ns, Cred: creds(r)},
		core.BranchRequest{Name: name, At: at, Patches: m["patches"], IfNoneMatch: p.ifNoneMatch})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Location", "/ns/"+name)
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	out := map[string]any{"name": name, "config": res.ConfigID}
	if res.NSID != "" {
		out["ns_id"] = res.NSID
	}
	writeJSON(w, res.Status, out)
}

// registerRemote registers or renews a remote branch (§G.3):
// { "remote": { "origin", "ns" }, "at" } with If-None-Match: * or If-Match.
func (s *Server) registerRemote(w http.ResponseWriter, r *http.Request, ns string, p precond, m map[string]any) {
	rm, ok := m["remote"].(map[string]any)
	origin, _ := rm["origin"].(string)
	name, _ := rm["ns"].(string)
	at, _ := m["at"].(string)
	if !ok || len(rm) != 2 || origin == "" || name == "" || at == "" || len(m) != 2 {
		writeErr(w, badInput("body must be { remote: { origin, ns }, at }"))
		return
	}
	// at is the base's ns_id in text form, or 400 (§7); one that isn't in
	// its chain is the core's 422 (§G.3).
	if !validID(at) {
		writeErr(w, badInput("at must be an ns_id in text form (§7, §G.3)"))
		return
	}
	// The precondition is checked in the core, after authorisation (§G.3).
	res, err := s.registerRemoteBranch(r.Context(), core.Request{NS: ns, Cred: creds(r)},
		core.RemoteRegistration{Origin: origin, NS: name, At: at, IfNoneMatch: p.ifNoneMatch, IfMatch: p.ifMatch})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Namespace-Revision", res.NSID)
	w.Header().Set("ETag", quote(res.NSID))
	writeJSON(w, res.Status, res.Value())
}

func (s *Server) nsBatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	// Each step carries its own signature (§7.5); the header covers
	// single writes and is 400 on a batch (§C.3.1), a request-shape error
	// that comes before the gate (§6.2).
	if _, has := r.Header["Signature"]; has {
		writeErr(w, badInput("a batch carries signatures in its step objects, not in a Signature header (§C.3.1)"))
		return
	}
	if err := s.writeHeaders(r, false); err != nil {
		writeErr(w, err)
		return
	}
	if err := requireType(r, jsonType); err != nil {
		writeErr(w, err)
		return
	}
	// The batch's Gesture and Undoes headers are its defaults (§7.5).
	g, u, err := gestures(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Batch limits depend on the principal (§6.6): authenticate first, then
	// stop reading a body larger than that principal's batchSize (§7.5).
	req := core.Request{NS: ns, Cred: creds(r), SourceCreds: sourceCreds(r)}
	bound, size, err := s.e.BatchBodyLimit(r.Context(), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	body, err := readJSON(r, bound, bodyLimit{"batchSize", size})
	if err != nil {
		writeErr(w, err)
		return
	}
	items, cc, source, err := parseBatch(body, gestureDefaults{g, u})
	if err != nil {
		writeErr(w, err)
		return
	}
	dry := r.URL.Query().Get("dry-run") == "1"
	res, err := s.batch(r.Context(), req, items, cc, source, dry)
	if err != nil {
		writeErr(w, err)
		return
	}
	report := make([]any, len(res.Items))
	for i, it := range res.Items {
		report[i] = it.Value()
	}
	out := map[string]any{"items": report}
	if dry {
		// { items, config? }: the report for every item and for the
		// config change; a dry run writes no entry, so no ns_id and no
		// revision headers (§7.2, §7.5).
		if res.ConfigReport != nil {
			out["config"] = res.ConfigReport
		}
		writeJSON(w, res.Status, out)
		return
	}
	// A submit, or its retry: the batch entry, and with a config change
	// its id, as the body's config and X-Config-Revision (§7.5).
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
		out["ns_id"] = res.NSID
	}
	if res.ConfigID != "" {
		w.Header().Set("X-Config-Revision", res.ConfigID)
		out["config"] = res.ConfigID
	}
	writeJSON(w, res.Status, out)
}

func (s *Server) nsPurge(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.writeHeaders(r, false); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	nsID, err := s.purgeNamespace(r.Context(), core.Request{NS: ns, Cred: creds(r), SourceCreds: sourceCreds(r)}, p.ifMatch, r.URL.Query().Get("force") == "1")
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Namespace-Revision", nsID)
	w.WriteHeader(204)
}
