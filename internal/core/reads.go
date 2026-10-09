package core

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"sync"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// headItem is one resource as a namespace sees it.
type headItem struct {
	name  string
	state State
	row   *revRow
}

// nfNS is an unknown id of an existing namespace: 404 not_found, which §9
// answers with the short class rather than no-store. Public is the
// namespace's visibility, for the server's cache class.
func nfNS(public bool) *Error {
	e := notFound()
	e.Public = &public
	return e
}

// listHeads lists every resource of n as of asOf (nil = now), including
// read-through ones, sorted by name in ascending byte order (§7.4), by Go's
// string order and never by the database's collation, which on Postgres may
// order punctuation otherwise.
func (t *tx) listHeads(n *nsRow, asOf *int64) []headItem {
	var out []headItem
	for after := ""; ; {
		page, next := t.pageHeads(n, asOf, after, 1000)
		out = append(out, page...)
		if next == "" {
			return out
		}
		after = next
	}
}

// namesAfter returns up to k distinct names of n's resources, including
// those of its bases (read-through), greater than after in ascending byte
// order. Each level answers its own k smallest from the (ns, name) index,
// and the union's k smallest are the answer. Postgres compares and orders
// under the "C" collation, which is byte order, as SQLite's BINARY is.
func (t *tx) namesAfter(n *nsRow, after string, k int) []string {
	q := `SELECT name FROM resources WHERE ns = ? AND name > ? ORDER BY name LIMIT ?`
	if t.e.pg {
		q = `SELECT name FROM resources WHERE ns = ? AND name COLLATE "C" > ? ORDER BY name COLLATE "C" LIMIT ?`
	}
	names := map[string]bool{}
	for m := n; ; m = t.nsByID(m.base.Int64) {
		rows, err := t.Query(q, m.id, after, k)
		t.must(err)
		for rows.Next() {
			var s string
			t.must(rows.Scan(&s))
			names[s] = true
		}
		rows.Close()
		if !m.isBranch() {
			break
		}
	}
	sorted := sortedKeys(names)
	if len(sorted) > k {
		sorted = sorted[:k]
	}
	return sorted
}

// pageHeads lists at most limit resources of n as of asOf (nil = now)
// with names after after, in ascending byte order, and the name to resume
// after when more follow (§7.4). It resolves only the names the page
// needs, so a page costs its own size, not the namespace's: names are
// fetched in chunks, skipping those with no head at asOf, until the page
// is full and one more resource is known to exist.
func (t *tx) pageHeads(n *nsRow, asOf *int64, after string, limit int) (out []headItem, next string) {
	chunk := limit + 1
	for {
		names := t.namesAfter(n, after, chunk)
		t.prefetchHeads(n, names, asOf)
		for _, name := range names {
			v := t.resolve(n, name, asOf)
			if v.state == NotFound {
				continue
			}
			if len(out) == limit {
				return out, out[len(out)-1].name
			}
			out = append(out, headItem{name: name, state: v.state, row: v.head})
		}
		if len(names) < chunk {
			return out, ""
		}
		after = names[len(names)-1]
	}
}

// Head is the answer for GET /r/{ns}/{name}.
type Head struct {
	State   State
	Head    string // head revision or tombstone id
	Last    string // tombstoned: last live revision
	Public  bool
	Horizon string
}

// ResourceHead resolves the head pointer.
func (e *Engine) ResourceHead(ctx context.Context, ns, name string, cred Credentials) (*Head, error) {
	if h, ok := e.rc.head(ns, name); ok {
		return &h, nil
	}
	g := e.rc.load(ns)
	var h *Head
	public, cached := false, false
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		// May read: the answer is the same for every reader (readcache.go).
		if c, ok := e.rc.headFor(g, ns, name); ok {
			h, cached = &c, true
			return nil
		}
		h = &Head{Public: t.cachePublic(n)}
		public = t.config(n.configSeq).Read == "public"
		if n.purged {
			h.State = Purged
			return nil
		}
		v := t.resolve(n, name, nil)
		h.State = v.state
		if v.head != nil && v.state != Purged {
			h.Head = v.head.id.String()
			if v.state == Tombstoned {
				h.Last = t.lastLive(v.head).id.String()
			}
		}
		return nil
	})
	if err == nil && !cached {
		// Credentials don't matter to a public read; other reads serve it
		// only after their check (readcache.go).
		e.rc.putHead(g, ns, name, *h, public)
	}
	return h, err
}

// Rev is the answer for GET /r/{ns}/{name}/rev/{id}.
type Rev struct {
	Status int // 200, 404, 410
	Doc    []byte
	// JWE is the sealed document of a sealed namespace (Addendum E.2),
	// served instead of Doc.
	JWE     string
	Code    string // "pruned", "tombstone" or "" for 410s
	Horizon string
	Archive string // URL of the archive holding a pruned revision, if any (§8.6)
	Public  bool
	// Fold is set (Status 302) for a revision of an e2e resource (§E.3):
	// the server has no document, and the client folds the log from
	// FoldSince (the latest snapshot at or before the revision, "" for
	// genesis) up to the revision.
	Fold      bool
	FoldSince string
	// Snapshot is set for a revision of an e2e resource that has a stored
	// prune snapshot (§7.1 Paging, §8.6): JWE is that sealed snapshot,
	// served as the revision (Status 200), or with the 410 of a tombstone
	// horizon (Code "tombstone"), whose snapshot is the last live document.
	Snapshot bool
	// Referrer is set for a schema revision served under schemaReads to a
	// reader of a referrer (§6.1). The grant is in Authorization and no
	// edge cookie covers the path, so an edge forwards the read undecided:
	// it is served private, and no shared cache stores it.
	Referrer bool
}

// ResourceRev serves the document at a revision.
func (e *Engine) ResourceRev(ctx context.Context, ns, name, id string, cred Credentials) (*Rev, error) {
	if doc := e.rc.rev(ns, name, id); doc != nil {
		return &Rev{Status: 200, Doc: doc, Public: true}, nil
	}
	g := e.rc.load(ns)
	public, cached := false, false
	var out *Rev
	var job *sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		rid, perr := ids.Parse(id)
		referrer := false
		if _, err := t.reader(n, cred, name); err != nil {
			// A schema revision n opens with schemaReads, to a reader of
			// a document that pins it (§6.1, §7); nothing else of n.
			if perr != nil || !t.schemaReadsRev(n, name, rid, cred) {
				return err
			}
			referrer = true
		}
		out = &Rev{Public: t.cachePublic(n), Referrer: referrer}
		public = t.config(n.configSeq).Read == "public"
		if perr != nil {
			out.Status = 404
			return nil
		}
		// May read: a plain document is the same for every reader
		// (readcache.go). Sealed and e2e ones are never cached.
		if !t.isSealedNS(n) && !t.e2eContent(n, name) {
			if doc := e.rc.revFor(g, ns, name, id); doc != nil {
				out.Status, out.Doc, cached = 200, doc, true
				return nil
			}
		}
		v := t.resolve(n, name, nil)
		if n.purged || v.state == Purged {
			out.Status = 410
			return nil
		}
		if v.head == nil {
			out.Status = 404
			return nil
		}
		row := t.findInAncestry(v.head, rid)
		if row == nil {
			out.Status = 404
			return nil
		}
		e2e := t.e2eContent(n, name)
		if e2e {
			// A prune's sealed snapshot is served as /rev/{H}, never as a
			// log entry (§7.1 Paging, §8.6). It stays stored after an
			// archive restore clears the horizon, so the answer doesn't
			// change once given.
			if jwe := t.e2eSnapshot(row); jwe != "" {
				out.Snapshot, out.JWE = true, jwe
				if row.kind == kindTombstone {
					out.Status, out.Code = 410, "tombstone"
				} else {
					out.Status = 200
				}
				return nil
			}
		}
		if row.kind == kindTombstone {
			out.Status, out.Code = 410, "tombstone"
			return nil
		}
		if e2e {
			if !row.patches.Valid {
				var state int
				t.must(t.QueryRow(`SELECT state FROM resources WHERE res = ?`, row.res).Scan(&state))
				if state == statePurged {
					out.Status = 410
					return nil
				}
				out.Status, out.Code = 410, "pruned"
				out.Horizon, out.Archive = t.horizonID(row.res), t.archiveURL(row.res, row.seq)
				return nil
			}
			out.Status, out.Fold, out.FoldSince = 302, true, t.e2eFoldSince(row)
			return nil
		}
		b, err := t.docBytesAt(row)
		if err != nil {
			var pe *prunedError
			if errors.As(err, &pe) {
				out.Status, out.Code = 410, "pruned"
				out.Horizon, out.Archive = t.horizonID(pe.res), t.archiveURL(pe.res, row.seq)
				return nil
			}
			out.Status = 410
			return nil
		}
		out.Status, out.Doc = 200, b
		if t.isSealedNS(n) {
			nsRowID = n.id
			job = t.resJob(n, name, row, sealDoc, func() []byte { return b })
		}
		return nil
	})
	if err == nil && job != nil {
		if err = e.finishSeal(ctx, nsRowID, []*sealJob{job}); err == nil {
			out.Doc, out.JWE = nil, job.jwe
		}
	} else if err == nil && !cached && out.Status == 200 && !out.Snapshot {
		// A plain document (sealed ones have a job, e2e ones no document):
		// immutable, and the same for every reader.
		e.rc.putRev(g, ns, name, id, out.Doc, public)
	}
	return out, err
}

// Log is a range of log entries.
type Log struct {
	Status  int
	Entries []map[string]any
	// Sealed namespaces (Addendum E.2) serve JWEs instead of Entries:
	// resource logs one per entry (EntryJWEs); namespace logs one for the
	// whole range (Range), and for event streams one per entry covering
	// (prev, id] (EntryJWEs). Entries stay set, for the metadata a
	// response carries in the clear (ids, event types), and must not be
	// served.
	Sealed    bool
	EntryJWEs []string
	Range     string
	Last      string // id of the last entry returned (or since)
	More      bool   // the range goes on past Last: a page (§7.1), Last the next since (X-Log-Next)
	Horizon   string
	Archive   string // with Horizon: the archive holding the newest pruned entry, if any
	Public    bool
}

// ResourceLog serves /r/{ns}/{name}/rev/{id}/log?since= (§7.1). With id
// empty it serves from the current head (for long-poll and SSE). Either
// way it answers at most limit entries after since (0: all), oldest first,
// and sets More when the range goes on (§7.1 Paging, §7.7).
func (e *Engine) ResourceLog(ctx context.Context, ns, name, id, since string, limit int, cred Credentials) (*Log, error) {
	var out *Log
	var jobs []*sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		out = &Log{Public: t.cachePublic(n)}
		v := t.resolve(n, name, nil)
		if n.purged || v.state == Purged {
			out.Status = 410
			return nil
		}
		if v.head == nil {
			out.Status = 404
			return nil
		}
		to := v.head
		if id != "" {
			rid, err := ids.Parse(id)
			if err != nil {
				out.Status = 404
				return nil
			}
			to = t.findInAncestry(v.head, rid)
			if to == nil {
				out.Status = 404
				return nil
			}
		}
		var sinceID *ids.ID
		if since != "" {
			sid, err := ids.Parse(since)
			if err != nil {
				out.Status = 404
				return nil
			}
			sinceID = &sid
		}
		entries, more, err := t.logBetween(to, sinceID, limit)
		if err != nil {
			var pe *prunedError
			switch {
			case errors.As(err, &pe):
				out.Status = 410
				out.Horizon, out.Archive = t.prunedInfo(pe)
			case errors.Is(err, errNotAncestor):
				out.Status = 404
			default:
				out.Status = 410
			}
			return nil
		}
		out.Status, out.More = 200, more
		// An e2e range whose since is a pruning horizon holds only the
		// entries after it: the horizon's sealed snapshot is served as
		// /rev/{H} (ResourceRev), never as a log entry (§7.1 Paging).
		out.Last = since
		sealed := t.isSealedNS(n)
		for _, e := range entries {
			v := e.value()
			out.Entries = append(out.Entries, v)
			out.Last = e.ID
			if sealed {
				jobs = append(jobs, t.resJob(n, name, e.row, sealEntry, func() []byte { return jsonv.Canonical(v) }))
			}
		}
		if sealed {
			out.Sealed, nsRowID = true, n.id
		}
		return nil
	})
	if err == nil && out != nil && out.Sealed {
		if err = e.finishSeal(ctx, nsRowID, jobs); err == nil {
			out.EntryJWEs = make([]string, len(jobs))
			for i, j := range jobs {
				out.EntryJWEs[i] = j.jwe
			}
		}
	}
	return out, err
}

// NSInfo is the answer for GET /ns/{ns}.
type NSInfo struct {
	Head   string
	Config string
	Public bool
	Purged bool
	Doc    []byte
	JWE    string // sealed namespaces (Addendum E.2): the sealed document
}

// NamespaceHead returns the namespace head and config ids.
func (e *Engine) NamespaceHead(ctx context.Context, ns string, cred Credentials) (*NSInfo, error) {
	var out *NSInfo
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		out = &NSInfo{
			Head:   t.nsLogID(n.headSeq.Int64).String(),
			Config: t.configID(n.configSeq).String(),
			Public: t.cachePublic(n),
			Purged: n.purged,
		}
		return nil
	})
	return out, err
}

// NamespaceRev returns the namespace document in force at an ns_id.
func (e *Engine) NamespaceRev(ctx context.Context, ns, nsID string, cred Credentials) (*NSInfo, error) {
	var out *NSInfo
	var job *sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		id, perr := ids.Parse(nsID)
		if perr != nil {
			return nfNS(t.cachePublic(n))
		}
		seq, ok := t.nsLogSeq(n.id, id)
		if !ok {
			return nfNS(t.cachePublic(n))
		}
		var cseq int64
		var doc string
		t.must(t.QueryRow(`SELECT l.config_seq, c.doc FROM ns_log l JOIN ns_config c ON c.seq = l.config_seq WHERE l.seq = ?`, seq).Scan(&cseq, &doc))
		out = &NSInfo{Head: nsID, Config: t.configID(cseq).String(), Doc: []byte(doc),
			Public: t.cachePublic(n)}
		if t.isSealedNS(n) {
			nsRowID = n.id
			job = t.configJob(n, seq, nsID, []byte(doc))
		}
		return nil
	})
	if err == nil && job != nil {
		if err = e.finishSeal(ctx, nsRowID, []*sealJob{job}); err == nil {
			out.Doc, out.JWE = nil, job.jwe
		}
	}
	return out, err
}

// NamespaceLog serves /ns/{ns}/rev/{ns_id}/log?since= (§7.4). With nsID
// empty it serves from the current head (for long-poll). Either way it
// answers at most limit entries after since (0: all), oldest first, and
// sets More when the range goes on (§7.1 Paging, §7.7). In a sealed
// namespace the answer is one JWE for the page actually served, pl.range
// [since, Last] (§E.2.2).
func (e *Engine) NamespaceLog(ctx context.Context, ns, nsID, since string, limit int, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, nsID, since, limit, cred, false)
}

// NamespaceEvents is NamespaceLog from the current head for event streams,
// at most limit entries (0: all) with More set when there are more: in a
// sealed namespace each entry is sealed on its own, as the range (prev, id]
// (EntryJWEs).
func (e *Engine) NamespaceEvents(ctx context.Context, ns, since string, limit int, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, "", since, limit, cred, true)
}

func (e *Engine) namespaceLog(ctx context.Context, ns, nsID, since string, limit int, cred Credentials, perEntry bool) (*Log, error) {
	var out *Log
	var jobs []*sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		out = &Log{Public: t.cachePublic(n)}
		toSeq := n.headSeq.Int64
		if nsID != "" {
			id, err := ids.Parse(nsID)
			s, ok := t.nsLogSeq(n.id, id)
			if err != nil || !ok {
				out.Status = 404
				return nil
			}
			toSeq = s
		}
		var fromSeq int64 = 0
		if since != "" {
			id, err := ids.Parse(since)
			s, ok := t.nsLogSeq(n.id, id)
			if err != nil || !ok || s > toSeq {
				out.Status = 404
				return nil
			}
			fromSeq = s
		}
		q := `SELECT seq, id, prev_seq, body, author, created, grant_id, no_auth, gestures FROM ns_log WHERE ns = ? AND seq > ? AND seq <= ? ORDER BY seq`
		args := []any{n.id, fromSeq, toSeq}
		if limit > 0 {
			q += ` LIMIT ?`
			args = append(args, limit)
		}
		rows, err := t.Query(q, args...)
		t.must(err)
		type raw struct {
			seq     int64
			id      []byte
			prev    *int64
			body    string
			author  int64
			created int64
			grantID []byte
			noAuth  sql.NullInt64
			meta    sql.NullString
		}
		var rs []raw
		for rows.Next() {
			var r raw
			t.must(rows.Scan(&r.seq, &r.id, &r.prev, &r.body, &r.author, &r.created, &r.grantID, &r.noAuth, &r.meta))
			rs = append(rs, r)
		}
		rows.Close()
		out.Status = 200
		out.Last = since
		// An entry's prev is the row before it in the page, but for the
		// first entry's: a query for each made a page N+1.
		pageIDs := make(map[int64]string, len(rs))
		for _, r := range rs {
			m := jsonv.MustParse([]byte(r.body)).(map[string]any)
			m["id"] = ids.FromBytes(r.id).String()
			pageIDs[r.seq] = m["id"].(string)
			if r.prev != nil {
				prev, ok := pageIDs[*r.prev]
				if !ok {
					prev = t.nsLogID(*r.prev).String()
				}
				m["prev"] = prev
			}
			m["author"] = t.authorName(r.author)
			m["created"] = formatTime(r.created)
			switch {
			case r.grantID != nil:
				// Not part of the hashed entry, like author and created
				// (§7.4, grantref.go).
				if g := t.grantRef(r.grantID); g != nil {
					m["grant"] = g
				}
			case r.noAuth.Valid && r.noAuth.Int64 != 0:
				// Written while authentication was disabled (§1): null,
				// unlike the server's own entries, which have none.
				m["grant"] = nil
			}
			if r.meta.Valid {
				// gesture and undoes of a single write, gestures of a
				// batch: not part of the hashed entry either (§7.4). In a
				// sealed namespace they are sealed with it (§E.4).
				for k, v := range jsonv.MustParse([]byte(r.meta.String)).(map[string]any) {
					m[k] = v
				}
			}
			out.Entries = append(out.Entries, m)
			out.Last = m["id"].(string)
		}
		// A namespace's chain runs in seq order, so a page that stops
		// short of toSeq is a prefix of the range.
		out.More = len(rs) > 0 && rs[len(rs)-1].seq < toSeq
		if t.isSealedNS(n) {
			out.Sealed, nsRowID = true, n.id
			if perEntry {
				for i, r := range rs {
					m := out.Entries[i]
					prev, _ := m["prev"].(string)
					jobs = append(jobs, t.rangeJob(n, prev, r.seq, m["id"].(string), func() []byte { return jsonv.Canonical([]any{m}) }))
				}
			} else if len(rs) > 0 || nsID != "" {
				// A range, even an empty one, is sealed as a whole, with
				// the bounds of the page actually served: [since, last]
				// (§7.1, §E.2.2). The same page of a range up to a later
				// id, or of a live read, is the same bytes. A live read
				// with nothing new has no range (204).
				entries := make([]any, len(out.Entries))
				for i, m := range out.Entries {
					entries[i] = m
				}
				to, toID := toSeq, nsID
				if len(rs) > 0 {
					to, toID = rs[len(rs)-1].seq, out.Last
				}
				jobs = append(jobs, t.rangeJob(n, since, to, toID, func() []byte { return jsonv.Canonical(entries) }))
			}
		}
		return nil
	})
	if err == nil && out != nil && out.Sealed {
		if err = e.finishSeal(ctx, nsRowID, jobs); err == nil {
			if perEntry {
				out.EntryJWEs = make([]string, len(jobs))
				for i, j := range jobs {
					out.EntryJWEs[i] = j.jwe
				}
			} else if len(jobs) == 1 {
				out.Range = jobs[0].jwe
			}
		}
	}
	return out, err
}

// HeadsPage is a page of GET /ns/{ns}/rev/{ns_id}/heads.
type HeadsPage struct {
	Items  []map[string]any `json:"items"`
	Next   string           `json:"next,omitempty"`
	Public bool             `json:"-"`
}

// NamespaceHeads lists every resource as of a namespace revision, including
// those a branch reads through, in ascending byte order of name after after
// (a byte-order bound, not necessarily a name), a page of at most the log
// page size (§7.4).
func (e *Engine) NamespaceHeads(ctx context.Context, ns, nsID, after string, cred Credentials) (*HeadsPage, error) {
	var out *HeadsPage
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		id, perr := ids.Parse(nsID)
		seq, ok := t.nsLogSeq(n.id, id)
		if perr != nil || !ok {
			return nfNS(t.cachePublic(n))
		}
		out = &HeadsPage{Items: []map[string]any{}, Public: t.cachePublic(n)}
		page, next := t.pageHeads(n, &seq, after, e.opt.Maximums.LogPageSize)
		out.Next = next
		for _, h := range page {
			kind := "head"
			switch h.state {
			case Tombstoned:
				kind = "tombstone"
			case Purged:
				kind = "purge"
			}
			item := map[string]any{"resource": h.name, "kind": kind}
			if h.row != nil {
				item["target"] = h.row.id.String()
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	return out, err
}

// Branches lists a namespace's direct branches (§7.4).
func (e *Engine) Branches(ctx context.Context, ns string, cred Credentials) ([]map[string]any, bool, error) {
	var out []map[string]any
	var public bool
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		public = t.cachePublic(n)
		out = []map[string]any{}
		for _, b := range t.branchesOf(n) {
			cfg := t.config(b.configSeq)
			m := map[string]any{"name": b.name, "at": t.nsLogID(b.baseAt.Int64).String(), "frozen": cfg.Frozen, "purged": b.purged}
			if cfg.Successor != "" {
				m["successor"] = cfg.Successor
			}
			if d, ok := cfg.Doc["drafts"]; ok && cfg.DraftsFor != nil {
				m["drafts"] = d // §7.4: clients apply drafts.for (§6.1)
			}
			out = append(out, m)
		}
		// Remote branches whose registration hasn't expired (§G.3).
		out = append(out, t.liveRegistrations(n)...)
		return nil
	})
	return out, public, err
}

// Wait returns a channel closed on the next change to a namespace's log.
func (e *Engine) Wait(ns string) <-chan struct{} { return e.hub.wait(ns) }

// hub wakes waiters when a namespace log changes.
type hub struct {
	mu sync.Mutex
	m  map[string]chan struct{}
}

func newHub() *hub { return &hub{m: map[string]chan struct{}{}} }

func (h *hub) wait(ns string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.m[ns]
	if !ok {
		c = make(chan struct{})
		h.m[ns] = c
	}
	return c
}

func (h *hub) publish(ns string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.m[ns]; ok {
		close(c)
		delete(h.m, ns)
	}
}

var _ = sort.Strings
