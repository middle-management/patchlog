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
	var h *Head
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		h = &Head{Public: t.config(n.configSeq).Read == "public"}
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
	return h, err
}

// Rev is the answer for GET /r/{ns}/{name}/rev/{id}.
type Rev struct {
	Status  int // 200, 404, 410
	Doc     []byte
	Code    string // "pruned", "tombstone" or "" for 410s
	Horizon string
	Public  bool
}

// ResourceRev serves the document at a revision.
func (e *Engine) ResourceRev(ctx context.Context, ns, name, id string, cred Credentials) (*Rev, error) {
	var out *Rev
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		out = &Rev{Public: t.config(n.configSeq).Read == "public"}
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
		b, err := t.docBytesAt(row)
		if err != nil {
			var pe *prunedError
			if errors.As(err, &pe) {
				out.Status, out.Code, out.Horizon = 410, "pruned", t.horizonID(pe.res)
				return nil
			}
			out.Status = 410
			return nil
		}
		out.Status, out.Doc = 200, b
		return nil
	})
	return out, err
}

// Log is a range of log entries.
type Log struct {
	Status  int
	Entries []map[string]any
	Last    string // id of the last entry returned (or since)
	Horizon string
	Public  bool
}

// ResourceLog serves /r/{ns}/{name}/rev/{id}/log?since= (§7.1). With id
// empty it serves from the current head, up to limit entries after since
// (for long-poll and SSE).
func (e *Engine) ResourceLog(ctx context.Context, ns, name, id, since string, limit int, cred Credentials) (*Log, error) {
	var out *Log
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		if _, err := t.reader(n, cred, name); err != nil {
			return err
		}
		out = &Log{Public: t.config(n.configSeq).Read == "public"}
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
				out.Status, out.Horizon = 410, t.horizonID(pe.res)
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
		for _, e := range entries {
			out.Entries = append(out.Entries, e.value())
			out.Last = e.ID
		}
		return nil
	})
	return out, err
}

// NSInfo is the answer for GET /ns/{ns}.
type NSInfo struct {
	Head   string
	Config string
	Public bool
	Purged bool
	Doc    []byte
}

// NamespaceHead returns the namespace head and config ids.
func (e *Engine) NamespaceHead(ctx context.Context, ns string, cred Credentials) (*NSInfo, error) {
	var out *NSInfo
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		out = &NSInfo{
			Head:   t.nsLogID(n.headSeq.Int64).String(),
			Config: t.configID(n.configSeq).String(),
			Public: t.config(n.configSeq).Read == "public",
			Purged: n.purged,
		}
		return nil
	})
	return out, err
}

// NamespaceRev returns the namespace document in force at an ns_id.
func (e *Engine) NamespaceRev(ctx context.Context, ns, nsID string, cred Credentials) (*NSInfo, error) {
	var out *NSInfo
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
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
			Public: t.config(n.configSeq).Read == "public"}
		return nil
	})
	return out, err
}

// NamespaceLog serves /ns/{ns}/rev/{ns_id}/log?since= (§7.4). With nsID
// empty it serves from the current head, up to limit entries after since.
func (e *Engine) NamespaceLog(ctx context.Context, ns, nsID, since string, limit int, cred Credentials) (*Log, error) {
	var out *Log
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		out = &Log{Public: t.config(n.configSeq).Read == "public"}
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
		q := `SELECT seq, id, prev_seq, body, author, created FROM ns_log WHERE ns = ? AND seq > ? AND seq <= ? ORDER BY seq`
		args := []any{n.id, fromSeq, toSeq}
		if limit > 0 {
			q += ` LIMIT ?`
			args = append(args, limit)
		}
		rows, err := t.Query(q, args...)
		t.must(err)
		type raw struct {
			id      []byte
			prev    *int64
			body    string
			author  int64
			created int64
		}
		var rs []raw
		for rows.Next() {
			var r raw
			var seq int64
			t.must(rows.Scan(&seq, &r.id, &r.prev, &r.body, &r.author, &r.created))
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
			out.Entries = append(out.Entries, m)
			out.Last = m["id"].(string)
		}
		return nil
	})
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
			return notFound()
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		id, perr := ids.Parse(nsID)
		seq, ok := t.nsLogSeq(n.id, id)
		if perr != nil || !ok {
			return notFound()
		}
		out = &HeadsPage{Items: []map[string]any{}, Public: t.config(n.configSeq).Read == "public"}
		limit := e.opt.Limits.LogPageSize
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
			return notFound()
		}
		if _, err := t.reader(n, cred, ""); err != nil {
			return err
		}
		public = t.config(n.configSeq).Read == "public"
		out = []map[string]any{}
		for _, b := range t.branchesOf(n) {
			cfg := t.config(b.configSeq)
			m := map[string]any{"name": b.name, "at": t.nsLogID(b.baseAt.Int64).String(), "frozen": cfg.Frozen, "purged": b.purged}
			if cfg.Successor != "" {
				m["successor"] = cfg.Successor
			}
			out = append(out, m)
		}
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
