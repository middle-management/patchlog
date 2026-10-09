package index

import (
	"container/list"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
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
// to takes any form ?ref= does. The query asks every namespace the index
// serves (roots, and with Branches the branches it reached) that the reader
// may read, except purged ones and those it skips (an e2e namespace whose
// keys it doesn't hold, §E.3.2). Each hit is a ?ref= hit with its ns; hits
// come in namespace, then resource order, paged with limit and after as
// other queries are. ?min={ns}:{ns_id}, repeatable, waits as elsewhere
// (§A.5); a min for a namespace the answer doesn't cover is 400.
//
// gs keys the reader's subject set as for private namespaces (§B.11.5):
// its groups, and for every private namespace it reads, a marker of how:
// reads:{ns}, or for a grant that reads only some of its resources (whose
// hits are filtered per resource) reads:{ns}:scope:{digest}, and then the
// subject too. A reader that reads no private namespace gets the public
// answer, whose gs is that of the empty subject set. at is the
// combined checkpoint (§B.5), text(trunc160(sha256(canonical({ ns: ns_id,
// … })))), over the namespaces the answer covers that the index has
// reached; namespaces lists them. So writes in namespaces the reader can't
// see never move it.
//
// Hits from sealed and e2e namespaces carry ns, resource, id and url in the
// clear and the rest as "sealed": a JWE under the resource's K_r, pl { ns,
// name, view }, view being the at URL (§E.2.6 per-entry sealing). An answer
// with sealed hits is also stored (derived.Cache) while its at is current,
// so it is sealed once.
//
// Every answer computed, including the one a redirect names, is kept for
// refsKeepFor and answered 200 at its at however far the namespaces move
// meanwhile (the combined at moves with any of them), as long as the reader
// may still see every namespace it covers. A purge drops kept answers that
// carry a tag it purges (Index.refsPurged, from Apply).

// Keeping answers (refsKept).
const (
	refsKeepFor   = time.Minute
	refsKeepBytes = 16 << 20
)

// refsQuery is a parsed GET /_refs query.
type refsQuery struct {
	ref          *RefFilter
	mins         []MinRef
	limit, after int
}

func parseRefsQuery(v url.Values) (*refsQuery, error) {
	pv := url.Values{}
	for k, vals := range v {
		switch k {
		case "to":
		case "min", "limit", "after":
			pv[k] = vals
		default:
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}
	if len(v["to"]) != 1 {
		return nil, errors.New("to is required, once")
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
	return &refsQuery{ref: ref, mins: q.Mins, limit: q.Limit, after: q.After}, nil
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

// refsReader runs the read check of every namespace served (refsAccess):
// a namespace the reader may not read is left out, and if that leaves
// none, the answer is a refusal that names none of them (one the reader
// can't see is like one the service doesn't follow): 401 if any refusal
// is, else 403.
func (ix *Index) refsReader(ctx context.Context, r *http.Request) (*refsReader, error) {
	rd := &refsReader{public: true, allow: map[string]func(string) bool{}}
	var (
		v          *grant.Verified
		markers    []string
		restricted bool
		refused    int
	)
	g, _ := ix.checker.Decode(bearer(r)) // nil: no usable grant
	for _, ns := range ix.refsNamespaces() {
		if _, purged, _ := ix.state(ns); purged || ix.keys.Skipped(ns) != "" {
			continue
		}
		a, err := ix.refsAccess(ctx, ns, r, g)
		var ae *grant.AuthError
		if errors.As(err, &ae) {
			if refused != 401 {
				refused = ae.Status
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		rd.nss = append(rd.nss, ns)
		if a.public {
			continue
		}
		rd.public, v = false, a.v
		if a.all {
			markers = append(markers, "reads:"+ns)
		} else {
			restricted = true
			markers = append(markers, "reads:"+ns+":scope:"+scopeDigest(a.v))
			rd.allow[ns] = func(name string) bool { return ix.checker.AllowsRead(a.v, name) }
		}
	}
	switch {
	case len(rd.nss) > 0 || refused == 0:
	case refused == 401:
		return nil, &grant.AuthError{Status: 401, Msg: "missing or unverifiable grant"}
	default:
		return nil, &grant.AuthError{Status: 403, Msg: "the grant reads no namespace the service follows"}
	}
	var subjects []string
	if v != nil {
		subjects = append(grantcheck.SubjectSet(v, restricted), markers...)
	}
	rd.gs = grantcheck.SubjectSetID(subjects)
	return rd, nil
}

// refsAccess is access to ns with the bearer decoded once (g; nil if there
// is none or it doesn't decode): a private namespace is refused without
// verifying a grant that doesn't name it, which §C.2 refuses first anyway.
func (ix *Index) refsAccess(ctx context.Context, ns string, r *http.Request, g *grant.Grant) (*access, error) {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return nil, err
	}
	switch {
	case cfg.Read == "public":
		return &access{public: true, all: true}, nil
	case g == nil:
		return nil, &grant.AuthError{Status: 401, Msg: "no usable grant"}
	case !g.NamesNS(ns):
		return nil, &grant.AuthError{Status: 403, Msg: "the grant does not apply to the namespace"}
	}
	return ix.access(ctx, ns, r)
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
	if !ix.waitMins(ctx, rq.mins) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "behind", "the index has not reached min yet")
		return
	}
	target := func(at string) string { return "/_refs/at/" + at + "/g/" + rd.gs + encodeQuery(vals, "min") }
	// Only the canonical form of an at URL is answered: a sealed hit is
	// bound to it (§E.2.6), and with ?min= only the current at is.
	canonical := at != "" && len(rq.mins) == 0 && r.URL.RequestURI() == target(at)
	if canonical {
		if st, ok := ix.refsStored(ctx, rd, target(at)); ok {
			ix.writeRefs(w, rd, at, st)
			return
		}
	}
	st, cur, err := ix.refsAnswer(ctx, rd, rq, vals, target)
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
	if !canonical || at != cur {
		setPtr()
		redirect(w, target(cur))
		return
	}
	ix.writeRefs(w, rd, cur, st)
}

var errRefsKeys = errors.New("the index cannot obtain the key that seals results of a namespace asked")

// refsStored returns the answer kept or stored at url while rd may still
// see every namespace it covers (its idx: tags). A namespace that turned
// private, or that the index left, moves no gs: public ones add no marker.
func (ix *Index) refsStored(ctx context.Context, rd *refsReader, url string) (derived.Stored, bool) {
	st, ok := ix.refs.get(url, ix.opt.Now())
	if !ok {
		if st, ok = ix.sealed.Get(ctx, url); !ok {
			return st, false
		}
	}
	for _, t := range strings.Split(st.Tags, ",") {
		if ns, ok := strings.CutPrefix(t, "idx:"); ok && !slices.Contains(rd.nss, ns) {
			return derived.Stored{}, false
		}
	}
	return st, true
}

// refsAnswer computes the answer at the current combined checkpoint, keeps
// it, and returns it with that checkpoint. An answer read before a purge
// that is applied before it is kept is computed again (refsKept.put).
func (ix *Index) refsAnswer(ctx context.Context, rd *refsReader, rq *refsQuery, vals url.Values, target func(string) string) (derived.Stored, string, error) {
	for try := 0; ; try++ {
		gens := ix.refs.generations(rd.nss)
		st, at, err := ix.refsCompute(ctx, rd, rq, vals, target)
		if err != nil || ix.refs.put(target(at), rd.nss, gens, ix.opt.Now(), &st) || try == 2 {
			return st, at, err
		}
	}
}

func (ix *Index) refsCompute(ctx context.Context, rd *refsReader, rq *refsQuery, vals url.Values, target func(string) string) (derived.Stored, string, error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return derived.Stored{}, "", err
	}
	defer tx.Rollback()
	cps, err := ix.refsCheckpoints(ctx, tx, rd.nss)
	if err != nil {
		return derived.Stored{}, "", err
	}
	at := combinedAt(cps)
	view := target(at)
	if st, ok := ix.refsStored(ctx, rd, view); ok {
		return st, at, nil
	}
	nss := make([]string, 0, len(cps))
	for ns := range cps {
		nss = append(nss, ns)
	}
	sort.Strings(nss)

	// The page: each namespace's referrers in resource order (refs_t,
	// as ?ref= reads them), the reader's per-resource filter applied.
	q := &Query{Ref: rq.ref}
	fs := q.filters()
	var hits []Hit
	var hitNS []string
	n, more := 0, false
	for _, ns := range nss {
		stmt, args := ix.candidateSQL(ns, q, fs, 0)
		rows, err := tx.QueryContext(ctx, stmt, args...)
		if err != nil {
			return derived.Stored{}, "", err
		}
		allow := rd.allow[ns]
		for rows.Next() {
			var h Hit
			if err := rows.Scan(&h.docid, &h.Resource, &h.ID, &h.Schema, &h.Score); err != nil {
				rows.Close()
				return derived.Stored{}, "", err
			}
			if allow != nil && !allow(h.Resource) {
				continue
			}
			n++
			if n > rq.after {
				if len(hits) == rq.limit {
					more = true
					break
				}
				hits, hitNS = append(hits, h), append(hitNS, ns)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return derived.Stored{}, "", err
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
			return derived.Stored{}, "", err
		}
		if err := ix.attachSorts(ctx, tx, ns, hits[i:j]); err != nil {
			return derived.Stored{}, "", err
		}
		if err := ix.attachRefs(ctx, tx, ns, rq.ref, hits[i:j]); err != nil {
			return derived.Stored{}, "", err
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
			return derived.Stored{}, "", errRefsKeys
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
				return derived.Stored{}, "", fmt.Errorf("sealing a hit: %w", err)
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
		nv := url.Values{}
		for k, v := range vals {
			nv[k] = v
		}
		nv.Set("after", strconv.Itoa(rq.after+len(hits)))
		body["next"] = "/_refs/at/" + at + "/g/" + rd.gs + encodeQuery(nv, "min")
	}
	b, err := derived.Marshal(body)
	if err != nil {
		return derived.Stored{}, "", err
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
	return st, at, nil
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
	ix.refs.purge(ns, tags)
	tags = slices.DeleteFunc(slices.Clone(tags), func(t string) bool { return t == countsTag(ns) })
	if err := ix.sealed.Purge(ctx, ix.db, tags); err != nil {
		ix.opt.Logf("index: purging sealed results of /_refs: %v", err)
	}
}

// refsKept keeps answers in memory, under their at URLs, for refsKeepFor
// and at most refsKeepBytes, oldest out first. The zero value is ready.
type refsKept struct {
	mu     sync.Mutex
	m      map[string]*list.Element // URL → *refsEntry
	order  list.List                // oldest first
	size   int
	purges map[string]uint64 // ns → purges applied so far
}

type refsEntry struct {
	url  string
	tags []string
	exp  time.Time
	st   derived.Stored
}

func (e *refsEntry) bytes() int { return len(e.url) + len(e.st.Body) + len(e.st.Tags) }

// generations are the purges applied so far to each of nss.
func (k *refsKept) generations(nss []string) []uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	gens := make([]uint64, len(nss))
	for i, ns := range nss {
		gens[i] = k.purges[ns]
	}
	return gens
}

func (k *refsKept) get(url string, now time.Time) (derived.Stored, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expire(now)
	if el, ok := k.m[url]; ok {
		return el.Value.(*refsEntry).st, true
	}
	return derived.Stored{}, false
}

// put keeps *st as url's answer unless one is kept already (then *st
// becomes that one: the first writer wins) or one of nss had a purge since
// gens; it reports whether *st is kept.
func (k *refsKept) put(url string, nss []string, gens []uint64, now time.Time, st *derived.Stored) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.expire(now)
	if el, ok := k.m[url]; ok {
		*st = el.Value.(*refsEntry).st
		return true
	}
	for i, ns := range nss {
		if k.purges[ns] != gens[i] {
			return false
		}
	}
	if k.m == nil {
		k.m = map[string]*list.Element{}
	}
	e := &refsEntry{url: url, tags: strings.Split(st.Tags, ","), exp: now.Add(refsKeepFor), st: *st}
	k.m[url] = k.order.PushBack(e)
	k.size += e.bytes()
	for k.size > refsKeepBytes {
		k.remove(k.order.Front())
	}
	return true
}

// purge drops the answers carrying any of tags, and makes answers read
// before it unkeepable.
func (k *refsKept) purge(ns string, tags []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.purges == nil {
		k.purges = map[string]uint64{}
	}
	k.purges[ns]++
	set := map[string]bool{}
	for _, t := range tags {
		set[t] = true
	}
	for el := k.order.Front(); el != nil; {
		next := el.Next()
		if slices.ContainsFunc(el.Value.(*refsEntry).tags, func(t string) bool { return set[t] }) {
			k.remove(el)
		}
		el = next
	}
}

func (k *refsKept) expire(now time.Time) {
	for el := k.order.Front(); el != nil && !now.Before(el.Value.(*refsEntry).exp); el = k.order.Front() {
		k.remove(el)
	}
}

func (k *refsKept) remove(el *list.Element) {
	e := k.order.Remove(el).(*refsEntry)
	delete(k.m, e.url)
	k.size -= e.bytes()
}
