package index

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/rules"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// References across namespaces (§A.4 "Across namespaces"):
//
//	GET /_refs?to=<reference>             302 → /_refs/at/{at}/g/{gs}?to=…      (head pointer)
//	GET /_refs/at/{at}/g/{gs}?to=…        200 { at, namespaces, hits, next? }  (immutable,
//	                                      tagged idx:{ns} per namespace in at and
//	                                      r:{ns}/{name} per hit)
//	                                      302 → the current at if this one is neither
//	                                      current nor kept
//
// to takes any form ?ref= does. The answer covers every namespace the
// index serves (roots, and with Branches the branches it reached) that it
// has reached and the reader may read, except purged ones and those it
// skips (a sealed or e2e namespace whose keys it can't obtain, §E.3.2).
// Each hit is a ?ref= hit with its ns; hits come in byte order of
// namespace, then resource name. A page holds at most limit hits (default
// and maximum as for other queries), strictly after after, {ns}/{name}
// compared as the pair split at its first "/"; next is the after of the
// following page. ?min={ns}:{ns_id}, repeatable, waits as elsewhere
// (§A.5); a min for a namespace the answer doesn't cover is 400. On an at
// URL, an at whose answer is kept and includes every min is answered
// there.
//
// gs is computed as for subject sets (§B.11.5), over markers of what the
// answer depends on: for every private namespace the reader reads,
// reads:{ns}, or for a grant that reads only some of its resources (whose
// hits are filtered per resource) reads:{ns}:scope:{digest}, digest
// covering the rules its reads there are judged by and the /principal
// values they refer to (readsScope); a namespace where those rules refer
// to /now counts as unreadable. A reader with no marker gets the public
// answer, whose gs is that of the empty set. at is the combined checkpoint
// (§B.5), text(trunc160(sha256(canonical({ ns: ns_id, … })))), over the
// namespaces the answer covers; namespaces lists them. So writes in
// namespaces the reader can't see never move it. If the namespace document
// of one the grant names can't be read, the answer is 502; one the grant
// doesn't name is then left out, as a private one.
//
// Hits from sealed and e2e namespaces carry ns, resource, id and url in the
// clear and the rest as "sealed": a JWE under the resource's K_r, pl { ns,
// name, view }, view being the at URL (§E.2.6 per-entry sealing). An answer
// with sealed hits is also stored (derived.Cache) while its at is current,
// so it is sealed once.
//
// Every answer computed, including the one a redirect names, is kept for
// kept.For and answered 200 at its at however far the namespaces move
// meanwhile (the combined at moves with any of them), as long as the reader
// may still see every namespace it covers. A purge drops kept answers that
// carry a tag it purges (Index.refsPurged, from Apply).

// Keeping answers (Index.refs): at most refsKeepBytes, all in one scope,
// since a purge of any namespace may drop any answer.
const (
	refsKeepBytes = 16 << 20
	refsScope     = "_refs"
)

// refsQuery is a parsed GET /_refs query.
type refsQuery struct {
	ref                *RefFilter
	mins               []MinRef
	limit              int
	afterNS, afterName string // after, split at its first "/"
}

func parseRefsQuery(v url.Values) (*refsQuery, error) {
	pv := url.Values{}
	for k, vals := range v {
		switch k {
		case "to", "after":
		case "min", "limit":
			pv[k] = vals
		default:
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}
	if len(v["to"]) != 1 {
		return nil, errors.New("to is required, once")
	}
	if len(v["after"]) > 1 {
		return nil, errors.New("after given more than once")
	}
	ref, err := ParseRefFilter(v.Get("to"))
	if err != nil {
		return nil, fmt.Errorf("to: %v", err)
	}
	q, err := ParseQuery(pv)
	if err != nil {
		return nil, err
	}
	for _, m := range q.Mins {
		if m.NS == "" {
			return nil, errors.New("min must be {ns}:{ns_id}")
		}
	}
	rq := &refsQuery{ref: ref, mins: q.Mins, limit: q.Limit}
	if s := v.Get("after"); s != "" {
		var ok bool
		if rq.afterNS, rq.afterName, ok = strings.Cut(s, "/"); !ok {
			return nil, errors.New("after must be {ns}/{name}")
		}
	}
	return rq, nil
}

// refsReader is who asks: the namespaces its subject set may see and how.
type refsReader struct {
	gs     string
	public bool                         // reads no private namespace: the answer is public
	nss    []string                     // the namespaces asked, sorted
	allow  map[string]func(string) bool // namespaces it reads only in part
}

// refsNamespaces lists the namespaces the index serves (known), sorted.
func (ix *Index) refsNamespaces() []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var nss []string
	for ns := range ix.roots {
		nss = append(nss, ns)
	}
	if ix.opt.Branches {
		for ns := range ix.cur {
			if !ix.roots[ns] {
				nss = append(nss, ns)
			}
		}
	}
	sort.Strings(nss)
	return nss
}

// refsReader runs the read check of every namespace the answer may cover
// (refsAccess): a namespace the reader may not read is left out, and if
// that leaves none, the answer is a refusal that names none of them (one
// the reader can't see is like one the service doesn't follow): 401 if any
// refusal is, else 403.
func (ix *Index) refsReader(ctx context.Context, r *http.Request) (*refsReader, error) {
	rd := &refsReader{public: true, allow: map[string]func(string) bool{}}
	var (
		markers []string
		refused int
	)
	refuse := func(status int) {
		if refused != 401 {
			refused = status
		}
	}
	g, _ := ix.checker.Decode(bearer(r)) // nil: no usable grant
	for _, ns := range ix.refsNamespaces() {
		if cur, purged, _ := ix.state(ns); cur == "" || purged || ix.keys.Skipped(ns) != "" {
			continue
		}
		a, err := ix.refsAccess(ctx, ns, r, g)
		var ae *grant.AuthError
		if errors.As(err, &ae) {
			refuse(ae.Status)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !a.public {
			marker := "reads:" + ns
			if !a.all {
				digest, ok := readsScope(a.v)
				if !ok {
					refuse(403)
					continue
				}
				marker += ":scope:" + digest
				rd.allow[ns] = func(name string) bool { return ix.checker.AllowsRead(a.v, name) }
			}
			rd.public, markers = false, append(markers, marker)
		}
		rd.nss = append(rd.nss, ns)
	}
	switch {
	case len(rd.nss) > 0 || refused == 0:
	case refused == 401:
		return nil, &grant.AuthError{Status: 401, Msg: "missing or unverifiable grant"}
	default:
		return nil, &grant.AuthError{Status: 403, Msg: "the grant reads no namespace the service follows"}
	}
	rd.gs = grantcheck.SubjectSetID(markers)
	return rd, nil
}

// refsAccess is access to ns with the bearer decoded once (g; nil if there
// is none or it doesn't decode): a private namespace is refused without
// verifying a grant that doesn't name it, which §C.2 refuses first anyway.
// The namespace document decides; if it can't be read, that is an error
// for one the grant names, and one it doesn't is refused as if private.
func (ix *Index) refsAccess(ctx context.Context, ns string, r *http.Request, g *grant.Grant) (*access, error) {
	named := g != nil && g.NamesNS(ns)
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil && named {
		return nil, err
	}
	switch {
	case err == nil && cfg.Read == "public":
		return &access{public: true, all: true}, nil
	case g == nil:
		return nil, &grant.AuthError{Status: 401, Msg: "no usable grant"}
	case !named:
		return nil, &grant.AuthError{Status: 403, Msg: "the grant does not apply to the namespace"}
	}
	return ix.access(ctx, ns, r)
}

// readsScope digests what the reads of a grant that reads a namespace only
// in part depend on (§A.4): the rules they are judged by there (its key's
// scope, its blocks' and those of its roles that grant read, §C.5) and the
// /principal values those refer to, so readers with the same rules and
// values share answers. It reports false if a rule refers to /now (or the
// whole envelope): the namespace then counts as unreadable, since an answer
// at a given at can't change.
func readsScope(v *grant.Verified) (string, bool) {
	lists := [][]any{v.KeyRules, v.BlockRules}
	roles := map[string]any{}
	_, readers := v.Allows("read")
	for _, role := range readers {
		roles[role] = v.RoleRules(role)
		lists = append(lists, v.RoleRules(role))
	}
	env := map[string]any{"principal": v.Principal.Envelope()}
	principal := map[string]any{}
	for _, l := range lists {
		for _, rv := range l {
			r, err := rules.Compile(rv)
			if err != nil {
				return "", false // it refuses every read anyway
			}
			for _, p := range r.RefPaths() {
				switch {
				case len(p) == 0 || p[0] == "now":
					return "", false
				case p[0] == "principal":
					if x, ok := pointer.Get(env, p); ok {
						principal[p.String()] = x
					}
				}
			}
		}
	}
	x := map[string]any{
		"readScope": v.Key.ReadScopeResource, "keyRules": v.KeyRules, "blockRules": v.BlockRules,
		"roles": roles, "principal": principal,
	}
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(x)))
	return ids.FromBytes(sum[:ids.Size]).String(), true
}

// combinedAt is the combined checkpoint of §B.5 over cps (ns → ns_id).
func combinedAt(cps map[string]string) string {
	m := make(map[string]any, len(cps))
	for ns, id := range cps {
		m[ns] = id
	}
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(m)))
	return ids.FromBytes(sum[:ids.Size]).String()
}

// serveRefs answers /_refs and /_refs/at/{at}/g/{gs} (segs, from "_refs").
func (ix *Index) serveRefs(w http.ResponseWriter, r *http.Request, segs []string) {
	var at, gs string
	switch {
	case len(segs) == 1:
		telemetry.SetRoute(r, "/_refs")
	case len(segs) == 5 && segs[1] == "at" && segs[3] == "g":
		at, gs = segs[2], segs[4]
		telemetry.SetRoute(r, "/_refs/at/{at}/g/{gs}")
		if _, err := ids.Parse(at); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_input", "malformed at")
			return
		}
		if _, err := ids.Parse(gs); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", "malformed subject set")
			return
		}
	default:
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	ctx := r.Context()
	vals := r.URL.Query()
	rq, err := parseRefsQuery(vals)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_input", err.Error())
		return
	}
	rd, err := ix.refsReader(ctx, r)
	if err != nil {
		var ae *grant.AuthError
		if errors.As(err, &ae) {
			code := "forbidden"
			if ae.Status == 401 {
				code = "unauthenticated"
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			w.Header().Set("Cache-Control", "no-store")
			writeErr(w, ae.Status, code, ae.Msg)
			return
		}
		ix.opt.Logf("index: access check for /_refs: %v", err)
		writeErr(w, http.StatusBadGateway, "upstream", "cannot read a namespace configuration")
		return
	}
	// Behind a verifying edge, private reads must come through it (§9).
	if !ix.opt.Edge.Allow(r, rd.public) {
		w.Header().Set("Cache-Control", "no-store")
		writeErr(w, http.StatusForbidden, edge.Code, edge.Message)
		return
	}
	setPtr := func() {
		// The pointer names the reader's subject set: shared caches key
		// it by Authorization, and keep none of a private one.
		w.Header().Add("Vary", "Authorization")
		if rd.public {
			w.Header().Set("Cache-Control", ccHeadPointer)
			if len(rd.nss) > 0 {
				w.Header().Set("Cache-Tag", "ns:"+strings.Join(rd.nss, ",ns:"))
			}
		} else {
			w.Header().Set("Cache-Control", ccPrivatePtr)
			w.Header().Set("CDN-Cache-Control", "no-store")
			w.Header().Set("Surrogate-Control", "no-store")
		}
	}
	if at != "" && gs != rd.gs {
		setPtr()
		redirect(w, "/_refs/at/"+at+"/g/"+rd.gs+encodeQuery(vals))
		return
	}
	for _, m := range rq.mins {
		if !slices.Contains(rd.nss, m.NS) {
			w.Header().Set("Cache-Control", "no-store")
			writeErr(w, http.StatusBadRequest, "bad_input", "min names a namespace the service does not follow or the reader can't read")
			return
		}
	}
	// target is the canonical URL of the answer at an at: what redirects
	// name, what answers are kept under, and the view a sealed hit is
	// bound to (§E.2.6), so an answer with one is served there alone.
	target := func(at string) string { return "/_refs/at/" + at + "/g/" + rd.gs + encodeQuery(vals, "min") }
	if at != "" {
		// An at that already includes every min answers (§A.4).
		if st, bound, ok := ix.refsStored(ctx, rd, target(at)); ok && ix.refsIncludes(ctx, st, rq.mins) {
			if bound && r.URL.RequestURI() != target(at) {
				setPtr()
				redirect(w, target(at))
				return
			}
			ix.writeRefs(w, rd, at, st)
			return
		}
	}
	if !ix.waitMins(ctx, rq.mins) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "behind", "the index has not reached min yet")
		return
	}
	st, cur, bound, err := ix.refsAnswer(ctx, rd, rq, target)
	if err != nil {
		if errors.Is(err, errRefsKeys) {
			w.Header().Set("Retry-After", "5")
			writeErr(w, http.StatusServiceUnavailable, "keys", err.Error())
			return
		}
		ix.opt.Logf("index: query %s: %v", r.URL, err)
		writeErr(w, http.StatusInternalServerError, "internal", "query failed")
		return
	}
	if at != cur || bound && r.URL.RequestURI() != target(at) {
		setPtr()
		redirect(w, target(cur))
		return
	}
	ix.writeRefs(w, rd, cur, st)
}

// refsIncludes reports whether an answer's at includes every min: its
// checkpoint of min's namespace is min or, as the core's log says, after
// it (since=min is accepted only if min is in the chain up to it, §7.1).
func (ix *Index) refsIncludes(ctx context.Context, st derived.Stored, mins []MinRef) bool {
	if len(mins) == 0 {
		return true
	}
	var body struct {
		Namespaces map[string]string `json:"namespaces"`
	}
	if err := json.Unmarshal(st.Body, &body); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, m := range mins {
		id, ok := body.Namespaces[m.NS]
		if !ok {
			return false
		}
		if id == m.ID {
			continue
		}
		if _, _, err := ix.c.NSLogPage(ctx, m.NS, id, m.ID); err != nil {
			return false
		}
	}
	return true
}

var errRefsKeys = errors.New("the index cannot obtain the key that seals results of a namespace asked")

// refsStored returns the answer kept or stored at url, and whether it is
// bound to url (it has sealed hits), while rd may still see every
// namespace it covers (its idx: tags). A namespace that turned private, or
// that the index left, moves no gs: public ones add no marker.
func (ix *Index) refsStored(ctx context.Context, rd *refsReader, url string) (derived.Stored, bool, bool) {
	st, bound, ok := ix.refs.Get(url)
	if !ok {
		if st, ok = ix.sealed.Get(ctx, url); !ok {
			return st, false, false
		}
		bound = true
	}
	for _, t := range strings.Split(st.Tags, ",") {
		if ns, ok := strings.CutPrefix(t, "idx:"); ok && !slices.Contains(rd.nss, ns) {
			return derived.Stored{}, false, false
		}
	}
	return st, bound, true
}

// refsAnswer computes the answer at the current combined checkpoint, keeps
// it, and returns it with that checkpoint and whether it is bound to its
// URL. An answer read before a purge of what it shows, which is then not
// kept, is computed again.
func (ix *Index) refsAnswer(ctx context.Context, rd *refsReader, rq *refsQuery, target func(string) string) (derived.Stored, string, bool, error) {
	for try := 0; ; try++ {
		gen := ix.refs.Generation(refsScope)
		st, at, bound, err := ix.refsCompute(ctx, rd, rq, target)
		if err != nil {
			return st, at, bound, err
		}
		if st, ok := ix.refs.Put(target(at), refsScope, gen, bound, st); ok || try == 2 {
			return st, at, bound, nil
		}
	}
}

func (ix *Index) refsCompute(ctx context.Context, rd *refsReader, rq *refsQuery, target func(string) string) (derived.Stored, string, bool, error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return derived.Stored{}, "", false, err
	}
	defer tx.Rollback()
	cps, err := ix.refsCheckpoints(ctx, tx, rd.nss)
	if err != nil {
		return derived.Stored{}, "", false, err
	}
	at := combinedAt(cps)
	view := target(at)
	if st, bound, ok := ix.refsStored(ctx, rd, view); ok {
		return st, at, bound, nil
	}
	nss := make([]string, 0, len(cps))
	for ns := range cps {
		nss = append(nss, ns)
	}
	sort.Strings(nss)

	// The page: each namespace's referrers in resource order (refs_t,
	// as ?ref= reads them) from after on, the reader's per-resource filter
	// applied.
	var hits []Hit
	var hitNS []string
	more := false
	for _, ns := range nss {
		if ns < rq.afterNS {
			continue
		}
		q := &Query{Ref: rq.ref}
		if ns == rq.afterNS {
			q.AfterName = rq.afterName
		}
		stmt, args := ix.candidateSQL(ns, q, q.filters(), 0)
		rows, err := tx.QueryContext(ctx, stmt, args...)
		if err != nil {
			return derived.Stored{}, "", false, err
		}
		allow := rd.allow[ns]
		for rows.Next() {
			var h Hit
			if err := rows.Scan(&h.docid, &h.Resource, &h.ID, &h.Schema, &h.Score); err != nil {
				rows.Close()
				return derived.Stored{}, "", false, err
			}
			if allow != nil && !allow(h.Resource) {
				continue
			}
			if len(hits) == rq.limit {
				more = true
				break
			}
			hits, hitNS = append(hits, h), append(hitNS, ns)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return derived.Stored{}, "", false, err
		}
		if more {
			break
		}
	}
	// Each namespace's hits are contiguous: attach what a ?ref= hit
	// carries.
	var withHits []string
	for i := 0; i < len(hits); {
		ns, j := hitNS[i], i
		for j < len(hits) && hitNS[j] == ns {
			j++
		}
		if err := ix.attachFacets(ctx, tx, ns, hits[i:j]); err != nil {
			return derived.Stored{}, "", false, err
		}
		if err := ix.attachSorts(ctx, tx, ns, hits[i:j]); err != nil {
			return derived.Stored{}, "", false, err
		}
		if err := ix.attachRefs(ctx, tx, ns, rq.ref, hits[i:j]); err != nil {
			return derived.Stored{}, "", false, err
		}
		withHits, i = append(withHits, ns), j
	}
	tx.Rollback()
	// The keys that seal hits of sealed and e2e namespaces.
	keys := map[string]derived.Key{}
	for _, ns := range withHits {
		info, key, err := ix.keys.Current(ctx, ns)
		if err != nil {
			ix.opt.Logf("index: keys of %s: %v", ns, err)
			return derived.Stored{}, "", false, errRefsKeys
		}
		if info.Protected() {
			keys[ns] = key
		}
	}

	tags := make([]string, 0, len(nss)+len(hits))
	for _, ns := range nss {
		tags = append(tags, "idx:"+ns)
	}
	out := make([]any, 0, len(hits))
	for i, h := range hits {
		ns := hitNS[i]
		m := map[string]any{"score": h.Score}
		if h.Schema != "" {
			m["schema"] = h.Schema
		}
		if len(h.Refs) > 0 {
			m["refs"] = h.Refs
		}
		for p, vs := range h.Facets {
			m[p] = vs
		}
		for p, vs := range h.Sorts {
			m[p] = vs
		}
		if h.Self {
			m["self"] = true
		}
		if key, ok := keys[ns]; ok {
			// Per-entry sealing (§E.2.6): what the document gave, under
			// its resource's key.
			jwe, err := derived.SealItem(key, derived.View{NS: ns, Target: view}, h.Resource, m)
			if err != nil {
				return derived.Stored{}, "", false, fmt.Errorf("sealing a hit: %w", err)
			}
			m = map[string]any{"sealed": jwe}
		}
		m["ns"], m["resource"], m["id"] = ns, h.Resource, h.ID
		m["url"] = ix.origin + "/r/" + ns + "/" + h.Resource + "/rev/" + h.ID
		out = append(out, m)
		tags = append(tags, "r:"+ns+"/"+h.Resource)
	}
	body := map[string]any{"at": at, "namespaces": cps, "hits": out}
	if more {
		// The after of the following page.
		body["next"] = hitNS[len(hits)-1] + "/" + hits[len(hits)-1].Resource
	}
	b, err := derived.Marshal(body)
	if err != nil {
		return derived.Stored{}, "", false, err
	}
	st := derived.Stored{Body: b, JSON: true, Tags: strings.Join(tags, ",")}
	if len(keys) > 0 {
		// Sealed once (§E.2.6): stored while at is current, as sealed
		// results of one namespace are.
		scope := "/_refs/g/" + rd.gs
		if st, err = ix.sealed.Put(ctx, view, scope, at, st); err != nil {
			ix.opt.Logf("index: storing a sealed result: %v", err)
		}
		if now, err := ix.refsCheckpoints(ctx, ix.db, rd.nss); err == nil {
			if err := ix.sealed.Retire(ctx, ix.db, scope, combinedAt(now)); err != nil {
				ix.opt.Logf("index: retiring sealed results of %s: %v", scope, err)
			}
		}
	}
	return st, at, len(keys) > 0, nil
}

// queryer runs queries (a *sql.DB or *sql.Tx).
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// refsCheckpoints reads the committed checkpoints of nss (those reached).
func (ix *Index) refsCheckpoints(ctx context.Context, q queryer, nss []string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT ns, ns_id FROM checkpoints WHERE origin = ?`, ix.origin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cps := map[string]string{}
	for rows.Next() {
		var ns, id string
		if err := rows.Scan(&ns, &id); err != nil {
			return nil, err
		}
		if slices.Contains(nss, ns) {
			cps[ns] = id
		}
	}
	return cps, rows.Err()
}

func (ix *Index) writeRefs(w http.ResponseWriter, rd *refsReader, at string, st derived.Stored) {
	if rd.public {
		w.Header().Set("Cache-Control", ccImmutable)
	} else {
		w.Header().Set("Cache-Control", ccPrivateImm)
		ix.opt.Edge.Private(w.Header(), cdnImmutable)
	}
	if st.Tags != "" {
		w.Header().Set("Cache-Tag", st.Tags)
	}
	w.Header().Set("X-Namespace-Revision", at)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(st.Body)
}

// refsPurged drops the answers a purge of tags in ns removes, once its
// apply has committed: kept ones, and stored sealed ones put since the
// apply's own purge of them (answers carry no counts tag, and results
// with counts computed since are current).
func (ix *Index) refsPurged(ctx context.Context, ns string, tags []string) {
	if len(tags) == 0 {
		return
	}
	ix.refs.Purge(refsScope, tags)
	tags = slices.DeleteFunc(slices.Clone(tags), func(t string) bool { return t == countsTag(ns) })
	if err := ix.sealed.Purge(ctx, ix.db, tags); err != nil {
		ix.opt.Logf("index: purging sealed results of /_refs: %v", err)
	}
}
