package core

import (
	"context"
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

// listHeads lists every resource of n as of asOf (nil = now), including
// read-through ones, sorted by name.
func (t *tx) listHeads(n *nsRow, asOf *int64) []headItem {
	names := map[string]bool{}
	t.collectNames(n, names)
	sorted := sortedKeys(names)
	var out []headItem
	for _, name := range sorted {
		v := t.resolve(n, name, asOf)
		if v.state == NotFound {
			continue
		}
		out = append(out, headItem{name: name, state: v.state, row: v.head})
	}
	return out
}

func (t *tx) collectNames(n *nsRow, names map[string]bool) {
	rows, err := t.Query(`SELECT name FROM resources WHERE ns = ?`, n.id)
	t.must(err)
	for rows.Next() {
		var s string
		t.must(rows.Scan(&s))
		names[s] = true
	}
	rows.Close()
	if n.isBranch() {
		t.collectNames(t.nsByID(n.base.Int64), names)
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
	public := false
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
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
	if err == nil && public {
		// Credentials don't matter to a public read (readcache.go).
		e.rc.putHead(g, ns, name, *h)
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
}

// ResourceRev serves the document at a revision.
func (e *Engine) ResourceRev(ctx context.Context, ns, name, id string, cred Credentials) (*Rev, error) {
	if doc := e.rc.rev(ns, name, id); doc != nil {
		return &Rev{Status: 200, Doc: doc, Public: true}, nil
	}
	g := e.rc.load(ns)
	public := false
	var out *Rev
	var job *sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		out = &Rev{Public: t.cachePublic(n)}
		public = t.config(n.configSeq).Read == "public"
		rid, perr := ids.Parse(id)
		if perr != nil {
			out.Status = 404
			return nil
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
		if row.kind == kindTombstone {
			out.Status, out.Code = 410, "tombstone"
			return nil
		}
		if t.e2eContent(n, name) {
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
	} else if err == nil && public && out.Status == 200 {
		// A plain document of a public namespace (sealed ones have a job,
		// e2e ones no document): immutable, and the same for every reader.
		e.rc.putRev(g, ns, name, id, out.Doc)
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
	Horizon   string
	Archive   string // with Horizon: the archive holding the newest pruned entry, if any
	Public    bool
}

// ResourceLog serves /r/{ns}/{name}/rev/{id}/log?since= (§7.1). With id
// empty it serves from the current head, up to limit entries after since
// (for long-poll and SSE).
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
		entries, err := t.logBetween(to, sinceID)
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
		if limit > 0 && len(entries) > limit {
			entries = entries[:limit]
		}
		out.Status = 200
		out.Last = since
		if sinceID != nil && id != "" && t.e2eContent(n, name) {
			// An e2e range starting at a snapshot (a pruning horizon)
			// begins with it (§8.6): the client folds from there.
			if srow := t.findInAncestry(to, *sinceID); srow != nil {
				if jwe := t.e2eSnapshot(srow); jwe != "" {
					out.Entries = append(out.Entries, map[string]any{"id": since, "kind": "snapshot", "snapshot": jwe})
				}
			}
		}
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
			return notFound()
		}
		seq, ok := t.nsLogSeq(n.id, id)
		if !ok {
			return notFound()
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
// empty it serves from the current head, up to limit entries after since.
func (e *Engine) NamespaceLog(ctx context.Context, ns, nsID, since string, limit int, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, nsID, since, limit, cred, false)
}

// NamespaceEvents is NamespaceLog from the current head for event streams:
// in a sealed namespace each entry is sealed on its own, as the range
// (prev, id] (EntryJWEs).
func (e *Engine) NamespaceEvents(ctx context.Context, ns, since string, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, "", since, 0, cred, true)
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
		q := `SELECT seq, id, prev_seq, body, author, created, grant_id FROM ns_log WHERE ns = ? AND seq > ? AND seq <= ? ORDER BY seq`
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
		}
		var rs []raw
		for rows.Next() {
			var r raw
			t.must(rows.Scan(&r.seq, &r.id, &r.prev, &r.body, &r.author, &r.created, &r.grantID))
			rs = append(rs, r)
		}
		rows.Close()
		out.Status = 200
		out.Last = since
		for _, r := range rs {
			m := jsonv.MustParse([]byte(r.body)).(map[string]any)
			m["id"] = ids.FromBytes(r.id).String()
			if r.prev != nil {
				m["prev"] = t.nsLogID(*r.prev).String()
			}
			m["author"] = t.authorName(r.author)
			m["created"] = formatTime(r.created)
			if r.grantID != nil {
				// Not part of the hashed entry, like author and created
				// (§7.4, grantref.go).
				if g := t.grantRef(r.grantID); g != nil {
					m["grant"] = g
				}
			}
			out.Entries = append(out.Entries, m)
			out.Last = m["id"].(string)
		}
		if t.isSealedNS(n) {
			out.Sealed, nsRowID = true, n.id
			if perEntry {
				for i, r := range rs {
					m := out.Entries[i]
					prev, _ := m["prev"].(string)
					jobs = append(jobs, t.rangeJob(n, prev, r.seq, m["id"].(string), func() []byte { return jsonv.Canonical([]any{m}) }))
				}
			} else if len(rs) > 0 || nsID != "" {
				// A range, even an empty one, is sealed as a whole. A
				// live read with nothing new has no range (204).
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

// NamespaceHeads lists every resource as of a namespace revision.
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
			return notFound()
		}
		out = &HeadsPage{Items: []map[string]any{}, Public: t.cachePublic(n)}
		limit := e.opt.Maximums.LogPageSize
		for _, h := range t.listHeads(n, &seq) {
			if h.name <= after {
				continue
			}
			if len(out.Items) == limit {
				out.Next = out.Items[len(out.Items)-1]["resource"].(string)
				break
			}
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
