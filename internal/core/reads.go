package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
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

// purgedNS is the 410 of a purged namespace n (§8.5): of every /r/{ns}/…
// URL, /ns/{ns}/grants/…, /ns/{ns}/gestures/…, /ns/{ns}/keys and /heads at
// any revision, as soon as the full read check for the URL passes, the
// grant's rules included, and before any other answer (not_offered and
// the 404 of an unknown id included); and of every write to it. Code
// "purged", with head, the ns_id of its purge-ns entry, the log's last.
// /ns/{ns} and its log stay readable, except in a sealed namespace
// (sealedPurged).
func (t *tx) purgedNS(n *nsRow) *Error {
	return apiErr(410, "purged", "head", t.nsLogID(n.headSeq.Int64).String())
}

// purgedRead is purgedNS for a cacheable read, which §9 answers with the
// long class, as any purge; Public is as for nfNS.
func (t *tx) purgedRead(n *nsRow) *Error {
	e := t.purgedNS(n)
	public := t.cachePublic(n)
	e.Public = &public
	return e
}

// sealedPurged reports a purged namespace whose namespace documents and
// log ranges are sealed (§E.2.2): the purge destroyed the epoch keys that
// seal them, so they, events and long-polls included, answer purgedRead
// rather than in the clear, which would show authors and timing to anyone
// the keys kept out (§8.5). /ns/{ns} still redirects, to a revision that
// is 410, and the 410's head tells a consumer of the purge.
func (t *tx) sealedPurged(n *nsRow) bool { return n.purged && t.isSealedNS(n) }

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
// order: namesIn without a prefix.
func (t *tx) namesAfter(n *nsRow, after string, k int) []string { return t.namesIn(n, after, "", k) }

// namesIn returns up to k distinct names of n's resources, including those
// of its bases (read-through), greater than after and, if prefix isn't "",
// starting with it (§7.4 ?prefix=), in ascending byte order. Each level
// answers its own k smallest from the (ns, name) index, bounded below by
// the larger of after and prefix and above by prefixEnd, and the union's k
// smallest are the answer. Postgres compares and orders under the "C"
// collation, which is byte order, as SQLite's BINARY is.
func (t *tx) namesIn(n *nsRow, after, prefix string, k int) []string {
	col := "name"
	if t.e.pg {
		col = `name COLLATE "C"`
	}
	q, args := `SELECT name FROM resources WHERE ns = ? AND `+col+` > ?`, []any{after}
	if prefix != "" {
		if prefix > after {
			// An after below the prefix starts at it (§7.4).
			q, args = `SELECT name FROM resources WHERE ns = ? AND `+col+` >= ?`, []any{prefix}
		}
		q += ` AND ` + col + ` < ?`
		args = append(args, prefixEnd(prefix))
	}
	q += ` ORDER BY ` + col + ` LIMIT ?`
	names := map[string]bool{}
	for m := n; ; m = t.nsByID(m.base.Int64) {
		rows, err := t.Query(q, append(append([]any{m.id}, args...), k)...)
		t.must(err)
		for rows.Next() {
			var s string
			t.must(rows.Scan(&s))
			if strings.HasPrefix(s, prefix) {
				names[s] = true
			}
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

// prefixEnd is the least string above every string starting with prefix,
// a resource name (§3.6): its last byte incremented, which stays ASCII.
func prefixEnd(prefix string) string {
	b := []byte(prefix)
	b[len(b)-1]++
	return string(b)
}

// pageHeads lists at most limit resources of n as of asOf (nil = now)
// with names after after, in ascending byte order, and the name to resume
// after when more follow (§7.4): pageHeadsIn without a prefix.
func (t *tx) pageHeads(n *nsRow, asOf *int64, after string, limit int) (out []headItem, next string) {
	return t.pageHeadsIn(n, asOf, after, "", limit)
}

// pageHeadsIn is pageHeads of the names starting with prefix ("" for all,
// §7.4 ?prefix=). It resolves only the names the page needs, so a page
// costs its own size, not the namespace's: names are fetched in chunks,
// skipping those with no head at asOf, until the page is full and one more
// resource is known to exist, so next stays absent on the last page.
func (t *tx) pageHeadsIn(n *nsRow, asOf *int64, after, prefix string, limit int) (out []headItem, next string) {
	chunk := limit + 1
	for {
		names := t.namesIn(n, after, prefix, chunk)
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
	// Successor is, for a tombstoned head, the well-formed top-level
	// $successor of the document at Last, as written (§8.1, §6.5): a bare
	// name, which the client resolves against this namespace, or
	// /r/{ns}/{name}. Set only where the namespace serving the 410 is
	// neither sealed nor e2e; elsewhere a client reads it from Last.
	Successor string
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
		if n.purged {
			return t.purgedRead(n)
		}
		h = &Head{Public: t.cachePublic(n)}
		public = t.config(n.configSeq).Read == "public"
		v := t.resolve(n, name, nil)
		h.State = v.state
		if v.head != nil && v.state != Purged {
			h.Head = v.head.id.String()
			if v.state == Tombstoned {
				last := t.lastLive(v.head)
				h.Last = last.id.String()
				if t.nsLevel(n) < levelSealed {
					h.Successor = t.successorAt(last)
				}
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

// successorAt is the top-level $successor of the document at row, a
// tombstone's last live revision, if it has the form of §8.1 (§6.5); ""
// if it has none, another form, or the document can't be read. The row
// may be a base's (read-through) or a remote base's mirror: its document
// is read here either way. Whoever wrote the document wrote it (§8.1).
func (t *tx) successorAt(row *revRow) string {
	if row == nil || row.kind != kindRev {
		return ""
	}
	b, err := t.docBytesAt(row)
	if err != nil || !bytes.Contains(b, []byte(`"$successor"`)) {
		return ""
	}
	doc, err := jsonv.Parse(b)
	if err != nil {
		return ""
	}
	m, _ := doc.(map[string]any)
	if s := m["$successor"]; schema.Successor(s) {
		return s.(string)
	}
	return ""
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
	// Snapshot is set for a revision of an e2e resource that a prune's
	// stored snapshot stands for (§7.1, §8.6): JWE is that sealed snapshot,
	// served as the revision (Status 200), at the horizon or, at a
	// tombstone horizon, at the tombstone's parent (§E.3.1). Any other
	// revision of an e2e resource that would be 200 is Status 404 with
	// Code "not_offered": the server never folds (§7.1), and the reader
	// folds the log from Last, else Horizon, else genesis.
	Snapshot bool
	// Last is, with a not_offered 404, the parent of the resource's
	// horizon where that horizon is a tombstone, and with a tombstone's
	// 410 (Code "tombstone") that tombstone's parent (§7.1).
	Last string
	// Referrer is set for a schema revision served under schemaReads to a
	// reader of a referrer (§6.1). The grant is in Authorization and no
	// edge cookie covers the path, so an edge forwards the read undecided:
	// it is served private, and no shared cache stores it.
	Referrer bool
	// Created is the revision's created time and Digest the sha-256 of
	// Doc, the bytes served: a 200's Last-Modified and Repr-Digest (RFC
	// 9530, §7.1). Both are set only where the namespace serving the read
	// is neither sealed nor e2e, the e2e keyring included: sealed logs
	// hide created (§E.2.2), and an exact digest defeats padding, so a
	// JWE, a sealed snapshot or a keyring there carries neither.
	Created time.Time
	Digest  []byte
	// SchemaRules is, for a 200 whose Doc is a schema document served in
	// the clear (the namespace serving the read is neither sealed nor
	// e2e, or the revision is from before a raise to e2e from none or
	// at-rest), the rules marker its revision row was stored with
	// (schema.Rules.String, schemaload.go), sent as schema.RulesHeader so
	// clients and remote mirrors compile it as this server does (§6.1).
	// "" otherwise.
	SchemaRules string
}

// ResourceRev serves the document at a revision.
func (e *Engine) ResourceRev(ctx context.Context, ns, name, id string, cred Credentials) (*Rev, error) {
	if c := e.rc.rev(ns, name, id); c != nil {
		return c.answer(true), nil
	}
	g := e.rc.load(ns)
	public, cached, plain := false, false, false
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
			if perr != nil || !t.schemaReadsRev(n, name, rid, cred, g) {
				return err
			}
			referrer = true
		}
		if n.purged {
			return t.purgedRead(n)
		}
		out = &Rev{Public: t.cachePublic(n), Referrer: referrer}
		public = t.config(n.configSeq).Read == "public"
		// Last-Modified and Repr-Digest, judged by the namespace serving
		// the read (§7.1): a sealed branch of a plain base sends neither.
		plain = t.nsLevel(n) < levelSealed
		if perr != nil {
			out.Status = 404
			return nil
		}
		// May read: a plain document is the same for every reader
		// (readcache.go). Sealed and e2e content is never cached.
		if !t.isSealedNS(n) && !t.e2eContent(n, name) {
			if c := e.rc.revFor(g, ns, name, id); c != nil {
				out, cached = c.answer(out.Public), true
				out.Referrer = referrer
				return nil
			}
		}
		v := t.resolve(n, name, nil)
		if v.state == Purged {
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
		if plain {
			out.Created = time.UnixMilli(row.created)
		}
		if t.e2eContent(n, name) {
			// §7.1 End-to-end namespaces: the server never folds.
			t.e3Rev(n, row, out)
			return nil
		}
		if row.kind == kindTombstone {
			t.tombstoneRev(row, out)
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
		if plain {
			// In the clear: a key holder compiles it as the server
			// resolves it (CIS-24).
			out.SchemaRules = t.schemaRulesHeader(row, b)
		}
		if plain && row.size.Valid && row.size.Int64 == int64(len(b)) && len(row.digest) == sha256.Size {
			// The digest the write stored of these bytes (headMeta).
			out.Digest = row.digest
		}
		if t.isSealedNS(n) {
			nsRowID = n.id
			job = t.resJob(n, name, row, sealDoc, func() []byte { return b })
		}
		return nil
	})
	if err == nil && job != nil {
		if err = e.finishSeal(ctx, nsRowID, []*sealJob{job}); err == nil {
			out.Doc, out.JWE, out.Digest = nil, job.jwe, nil
		}
	} else if err == nil && !cached && out.Status == 200 && !out.Snapshot {
		// A plain document (sealed ones have a job, e2e content no
		// document, and an e2e keyring is kept without its created time
		// and digest): immutable, and the same for every reader. Hashed
		// here unless the write stored its digest.
		d := revDoc{doc: out.Doc, meta: plain, rules: out.SchemaRules}
		if plain {
			d.created = out.Created.UnixMilli()
			if out.Digest != nil {
				copy(d.digest[:], out.Digest)
			} else {
				d.digest = sha256.Sum256(out.Doc)
			}
			out.Digest = d.digest[:]
		}
		e.rc.putRev(g, ns, name, id, d, public)
	}
	return out, err
}

// tombstoneRev answers GET /r/{ns}/{name}/rev/{id} for row, a tombstone,
// after the read check (§7.1): 410 with last, its parent, at every level
// and below a horizon too, where a prune keeps the row and its parent's
// id. A row without a parent, which no write stores, answers without
// last, never a guessed id.
func (t *tx) tombstoneRev(row *revRow, out *Rev) {
	out.Status, out.Code = 410, "tombstone"
	if row.parentSeq.Valid {
		out.Last = t.revID(row.parentSeq.Int64).String()
	}
}

// e3Rev answers GET /r/{ns}/{name}/rev/{id} for row, a revision of an
// e2e resource other than the keyring as n sees it (§7.1 End-to-end
// namespaces), after the read check: a tombstone is 410 with last, its
// parent (tombstoneRev); a prune's stored
// snapshot that stands for row is 200 application/jose, at the horizon
// or, at a tombstone horizon, at its parent (§E.3.1), a base's included
// in a branch (§7.6); a revision below the horizon is 410 pruned; any
// other is 404 not_offered with the horizon as n sees it and, where that
// horizon is a tombstone, last, its parent. The server never folds. A
// stored snapshot whose header binds another revision, as those stored at
// a tombstone horizon before v0.81 did, or carries a pre-v0.63 pl kind or
// zip, is never served: its revision answers 410 pruned (stored.md item
// 4).
func (t *tx) e3Rev(n *nsRow, row *revRow, out *Rev) {
	if row.kind == kindTombstone {
		t.tombstoneRev(row, out)
		return
	}
	pruned := func() {
		var state int
		t.must(t.QueryRow(`SELECT state FROM resources WHERE res = ?`, row.res).Scan(&state))
		if state == statePurged {
			out.Status = 410
			return
		}
		out.Status, out.Code = 410, "pruned"
		out.Horizon, out.Archive = t.horizonID(row.res), t.archiveURL(row.res, row.seq)
	}
	if jwe, ok, found := t.e3SnapshotFor(row); found {
		if !ok {
			pruned()
			return
		}
		out.Status, out.Snapshot, out.JWE = 200, true, jwe
		return
	}
	if !row.patches.Valid {
		pruned()
		return
	}
	out.Status, out.Code = 404, "not_offered"
	if h := t.e3Horizon(row); h != nil {
		out.Horizon = h.id.String()
		if h.kind == kindTombstone && h.parentSeq.Valid {
			out.Last = t.revID(h.parentSeq.Int64).String()
		}
	}
}

// e3SnapshotFor returns the stored prune snapshot that stands for
// revision row (§8.6, §E.3.1): the one stored at row, or at a tombstone
// of row's resource row whose parent row is, the newest; a base's, read
// through, in a branch (§7.6). found reports whether there is one; ok
// whether it may be served, its header binding row as the namespace
// whose resource stored it names it (snapshotHeaderServable).
func (t *tx) e3SnapshotFor(row *revRow) (jwe string, ok, found bool) {
	var seq, res int64
	want := row.id.String()
	err := t.QueryRow(`SELECT s.seq, s.res, s.jwe FROM e2e_snapshots s WHERE s.seq = ?`, row.seq).Scan(&seq, &res, &jwe)
	if errors.Is(err, sql.ErrNoRows) {
		// A tombstone and the parent it can be pruned at are of one
		// resource row: a branch's first own entry, whose parent is a
		// base's, has nothing below it to prune (pruneToE2E).
		err = t.QueryRow(`SELECT s.seq, s.res, s.jwe FROM e2e_snapshots s JOIN revisions h ON h.seq = s.seq
			WHERE s.res = ? AND h.kind = ? AND h.parent_seq = ? ORDER BY s.seq DESC LIMIT 1`, row.res, kindTombstone, row.seq).Scan(&seq, &res, &jwe)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false
	}
	t.must(err)
	var ns int64
	var name string
	t.must(t.QueryRow(`SELECT ns, name FROM resources WHERE res = ?`, res).Scan(&ns, &name))
	return jwe, snapshotHeaderServable(jwe, t.kidName(t.nsByID(ns)), name, want), true
}

// e3Horizon returns the horizon of row's resource as the namespace
// reading row sees it (§7.1): the newest horizon in row's ancestry, a
// base's for content read through, nil if none.
func (t *tx) e3Horizon(row *revRow) *revRow {
	for _, sg := range t.ancestry(row) {
		var h sql.NullInt64
		t.must(t.QueryRow(`SELECT horizon_seq FROM resources WHERE res = ?`, sg.res).Scan(&h))
		if h.Valid && h.Int64 <= sg.max {
			return t.rev(h.Int64)
		}
	}
	return nil
}

// Log is a range of log entries.
type Log struct {
	Status  int
	Entries []map[string]any
	// Sealed namespaces (Addendum E.2) serve JWEs instead of Entries:
	// resource logs one per entry (EntryJWEs); namespace logs one for the
	// whole range (Range), and for event streams one per entry, with the
	// event's own pl (EntryJWEs). Entries stay set, for the metadata a
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
	// Purged is set on a namespace log of a purged namespace, which ends
	// with its purge-ns entry: a namespace stream ends after it (§7.3,
	// §8.5).
	Purged bool
	// Until is when the credential that admitted the read expires, zero
	// if none bounds it (admission.go): an event stream ends there at the
	// latest (§7.3).
	Until time.Time
}

// ResourceLog serves /r/{ns}/{name}/rev/{id}/log?since= (§7.1). With id
// empty it serves from the current head (for long-poll and SSE), and with
// since empty too, for a resource with no entries, an empty range rather
// than 404 (§7.3, §7.7). Either way it answers at most limit entries after
// since (0: all), oldest first, and sets More when the range goes on (§7.1
// Paging, §7.7). A page (limit > 0) also holds no more patch set bytes than
// logPageBytes, at E2 bytes of the entries' JWEs, though always one entry;
// namespace logs carry no patch sets.
func (e *Engine) ResourceLog(ctx context.Context, ns, name, id, since string, limit int, cred Credentials) (*Log, error) {
	var out *Log
	var jobs []*sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		a, aerr := t.reader(n, cred, name)
		if aerr != nil {
			return aerr
		}
		if n.purged {
			return t.purgedRead(n)
		}
		out = &Log{Public: t.cachePublic(n), Until: t.admittedUntil(n, cred, a)}
		v := t.resolve(n, name, nil)
		if v.state == Purged {
			out.Status = 410
			return nil
		}
		if v.head == nil {
			// A resource with no entries: from its head and genesis (a
			// live read with an empty since), an empty range, which an
			// event stream or long-poll waits on, once the read check
			// above has passed (§7.3, §7.7). Any other range of it is
			// unknown.
			out.Status = 404
			if id == "" && since == "" {
				out.Status = 200
			}
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
		maxBytes := 0
		if limit > 0 {
			maxBytes = e.opt.Maximums.LogPageBytes
		}
		// At E2 each entry is served as its own JWE, stored or sealed now,
		// and a page is bounded by their lengths (logBetween).
		sealed := t.isSealedNS(n)
		var served func(LogEntry) int
		if sealed {
			served = func(le LogEntry) int {
				j := t.resJob(n, name, le.row, sealEntry, func() []byte { return jsonv.Canonical(le.value()) })
				l, err := j.servedLen()
				t.must(err)
				jobs = append(jobs, j)
				return l
			}
		}
		entries, more, err := t.logBetween(to, sinceID, limit, maxBytes, served)
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
		for _, e := range entries {
			out.Entries = append(out.Entries, e.value())
			out.Last = e.ID
		}
		if sealed {
			jobs = jobs[:len(entries)]
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

// NamespaceHead returns the namespace head and config ids. A partial
// reader of a namespace §B.11.9 covers gets them too, the head pointer of
// §7.4, though the revision it names stays 403 to it (§B.11.9 Answers).
func (e *Engine) NamespaceHead(ctx context.Context, ns string, cred Credentials) (*NSInfo, error) {
	return e.namespaceHead(ctx, ns, cred, false)
}

// NamespaceLogHead is NamespaceHead for GET /ns/{ns}/log without live,
// redirected to the range /ns/{ns}/rev/{head}/log: a partial reader of a
// namespace §B.11.9 covers gets a *FilteredRedirect to the filtered range
// at the current at instead (§B.11.9 URLs).
func (e *Engine) NamespaceLogHead(ctx context.Context, ns string, cred Credentials) (*NSInfo, error) {
	return e.namespaceHead(ctx, ns, cred, true)
}

func (e *Engine) namespaceHead(ctx context.Context, ns string, cred Credentials, redirect bool) (*NSInfo, error) {
	var out *NSInfo
	err := e.filteredRead(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if redirect {
			if _, err := t.nsReaderOrRedirect(n, cred); err != nil {
				return err
			}
		} else if _, _, _, err := t.nsAccess(n, cred); err != nil {
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

// NamespaceRev returns the namespace document in force at an ns_id; in a
// purged sealed namespace it is 410 purged at any (§8.5).
func (e *Engine) NamespaceRev(ctx context.Context, ns, nsID string, cred Credentials) (*NSInfo, error) {
	var out *NSInfo
	var job *sealJob
	var nsRowID int64
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.nsReader(n, cred); err != nil {
			return err
		}
		// At any revision, before the 404 of an unknown one (§8.5).
		if t.sealedPurged(n) {
			return t.purgedRead(n)
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
// [since, Last] (§E.2.2), and once it is purged, 410 purged (§8.5).
func (e *Engine) NamespaceLog(ctx context.Context, ns, nsID, since string, limit int, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, nsID, since, limit, cred, false, "", nil)
}

// NamespaceEvents is NamespaceLog from the current head for event streams,
// at most limit entries (0: all) with More set when there are more: in a
// sealed namespace each entry is sealed on its own, with the event's pl,
// {ns, event: id} (EntryJWEs, §E.2.2).
func (e *Engine) NamespaceEvents(ctx context.Context, ns, since string, limit int, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, "", since, limit, cred, true, "", nil)
}

// ResourceEvents is NamespaceEvents for the event stream of resource name
// (§7.3), which follows the namespace log for the resource's purges and
// prunes: only the entries that purge or prune it are answered, as their
// events' data, without id and prev, and in a sealed namespace each sealed
// under the resource's K_r (eventseal.go); they need read on it alone, as
// the resource's own URLs do (§C.5). Last and More still cover the whole
// page. With since "" it answers no entries and Last the namespace head,
// where the stream starts following.
func (e *Engine) ResourceEvents(ctx context.Context, ns, name, since string, limit int, cred Credentials) (*Log, error) {
	return e.namespaceLog(ctx, ns, "", since, limit, cred, true, name, nil)
}

func (e *Engine) namespaceLog(ctx context.Context, ns, nsID, since string, limit int, cred Credentials, perEntry bool, resource string, live *liveRead) (*Log, error) {
	var out *Log
	var jobs []*sealJob
	var nsRowID int64
	err := e.filteredRead(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		var a *actor
		var aerr *Error
		switch {
		case live != nil && live.shared:
			// The waiters' passes stand for their read checks (live.go).
			if n == nil {
				return errNotShared
			}
		case n == nil:
			return t.absentNS(ns, cred)
		case resource != "":
			if a, aerr = t.reader(n, cred, resource); aerr != nil {
				return aerr
			}
		default:
			// A partial reader is redirected to the filtered form: a range
			// at the current at, events and long-poll without one (§B.11.9
			// URLs).
			var err error
			if a, err = t.nsReaderOrRedirect(n, cred); err != nil {
				var fr *FilteredRedirect
				if errors.As(err, &fr) && (perEntry || live != nil) {
					fr.At, fr.CP = "", nil
				}
				return err
			}
			if live != nil {
				live.decided(t, n, cred, a)
			}
		}
		// Every range, page and event, before the 404 of an id or since
		// not in the chain (§8.5).
		if t.sealedPurged(n) {
			return t.purgedRead(n)
		}
		out = &Log{Public: t.cachePublic(n), Purged: n.purged}
		if live == nil || !live.shared {
			out.Until = t.admittedUntil(n, cred, a)
		}
		toSeq := n.headSeq.Int64
		if resource != "" && since == "" {
			out.Status, out.Last = 200, t.nsLogID(toSeq).String()
			return nil
		}
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
		// Events and long-poll from a purged namespace's purge-ns entry,
		// its last, are 410 purged, so a follower can tell the end from a
		// restart; an immutable range from it stays an empty page (§8.5).
		if n.purged && resource == "" && (perEntry || live != nil) && since != "" && fromSeq == n.headSeq.Int64 {
			return t.purgedRead(n)
		}
		q := `SELECT ` + nsLogCols + ` FROM ns_log WHERE ns = ? AND seq > ? AND seq <= ? ORDER BY seq`
		args := []any{n.id, fromSeq, toSeq}
		if limit > 0 {
			q += ` LIMIT ?`
			args = append(args, limit)
		}
		rows, err := t.Query(q, args...)
		t.must(err)
		// A page holds at most limit entries, and at most limit resource
		// entries, a batch entry counting as its items (it carries them):
		// it ends before an entry that would take it past, though it
		// always holds one. Without that, a page of 1,000 batch entries of
		// 1,000 items each held a million.
		var rs []nsLogRow
		units := 0
		for rows.Next() {
			r := t.scanNSLogRow(rows)
			u := 1
			if es, ok := r.m["entries"].([]any); ok && len(es) > 1 {
				u = len(es)
			}
			if limit > 0 && len(rs) > 0 && units+u > limit {
				break
			}
			units += u
			rs = append(rs, r)
		}
		rows.Close()
		out.Status = 200
		out.Last = since
		// An entry's prev is the row before it in the page, but for the
		// first entry's: a query for each made a page N+1.
		pageIDs := make(map[int64]string, len(rs))
		for i := range rs {
			r := &rs[i]
			prev := ""
			if r.prev != nil {
				var ok bool
				if prev, ok = pageIDs[*r.prev]; !ok {
					prev = t.nsLogID(*r.prev).String()
				}
			}
			m := t.decorateNSEntry(r, prev)
			pageIDs[r.seq] = m["id"].(string)
			out.Entries = append(out.Entries, m)
			out.Last = m["id"].(string)
		}
		// A namespace's chain runs in seq order, so a page that stops
		// short of toSeq is a prefix of the range.
		out.More = len(rs) > 0 && rs[len(rs)-1].seq < toSeq
		if resource != "" {
			// A resource stream's purge and prune events (eventseal.go).
			out.Entries = resourceEvents(out.Entries, resource)
			if t.isSealedNS(n) {
				out.Sealed, nsRowID = true, n.id
				jobs = t.resourceEventJobs(n, resource, out.Entries)
			}
			return nil
		}
		if t.isSealedNS(n) {
			out.Sealed, nsRowID = true, n.id
			if perEntry {
				// A namespace event is its one entry, sealed under K_n of
				// the current epoch with pl {ns, event: id} (§E.2.2), and
				// never stored (eventJob).
				for _, m := range out.Entries {
					jobs = append(jobs, t.eventJob(n, m["id"].(string), jsonv.Canonical(m)))
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
			if perEntry || resource != "" {
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

// ReprDigest is the RFC 9530 form of a sha-256 digest, sha-256=:<base64>:,
// as /heads entries and the Repr-Digest header give it.
func ReprDigest(sum []byte) string {
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum) + ":"
}

// HeadsPage is a page of GET /ns/{ns}/rev/{ns_id}/heads, served as
// { "heads": Items, "next"? } (§7.4).
type HeadsPage struct {
	Items  []map[string]any `json:"heads"`
	Next   string           `json:"next,omitempty"`
	Public bool             `json:"-"`
}

// NamespaceHeads lists every resource as of a namespace revision, including
// those a branch reads through, in ascending byte order of name after after
// (a byte-order bound, not necessarily a name), a page of at most the log
// page size (§7.4): NamespaceHeadsPrefix without a prefix.
func (e *Engine) NamespaceHeads(ctx context.Context, ns, nsID, after string, cred Credentials) (*HeadsPage, error) {
	return e.NamespaceHeadsPrefix(ctx, ns, nsID, after, "", cred)
}

// NamespaceHeadsPrefix is NamespaceHeads of the names starting with prefix
// ("" for all), a resource name the caller checked (§7.4 ?prefix=, §12.4);
// next stays absent on the last page. A partial reader of a namespace
// §B.11.9 covers, by the grant in Authorization, gets a *FilteredRedirect
// to the filtered form at the current at instead, which is recorded first
// (§B.11.9 URLs).
func (e *Engine) NamespaceHeadsPrefix(ctx context.Context, ns, nsID, after, prefix string, cred Credentials) (*HeadsPage, error) {
	var out *HeadsPage
	err := e.filteredRead(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		if _, err := t.nsReaderOrRedirect(n, cred); err != nil {
			return err
		}
		// At any revision, once its resources are gone (§8.5).
		if n.purged {
			return t.purgedRead(n)
		}
		id, perr := ids.Parse(nsID)
		seq, ok := t.nsLogSeq(n.id, id)
		if perr != nil || !ok {
			return nfNS(t.cachePublic(n))
		}
		out = &HeadsPage{Public: t.cachePublic(n)}
		page, next := t.pageHeadsIn(n, &seq, after, prefix, e.opt.Maximums.LogPageSize)
		out.Items, out.Next = t.headRows(n, page), next
		return nil
	})
	return out, err
}

// headRows are page's rows of /heads (§7.4), filtered or not (§B.11.9).
func (t *tx) headRows(n *nsRow, page []headItem) []map[string]any {
	out := []map[string]any{}
	// created, size and digest show what sealed and e2e namespaces hide:
	// created times, which their logs seal, lengths, which their padding
	// exists for, and a hash of content (§7.4, §E.2.2). Judged by the
	// namespace serving the page when it is listed, so pages at ns_ids
	// from before a raise to sealed list none either. Nor do size and
	// digest show at rest, where none are stored (§E.1 Stored digests;
	// migration 008_clear_at_rest_digests, encryptNamespace).
	level := t.nsLevel(n)
	plain := level < levelSealed
	// Nor for a resource §1 answers 502 for, read through a remote branch
	// whose source was raised to a level this server lacks, or one held
	// back while the branch's raise fails (remoteHeld): its source
	// hides them now (§1, §7.4).
	rb, _, _, lost := t.lostRemote(n)
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
		// created, the target's created time as log entries give it, but
		// not a purged one's, which a remote branch's mirror doesn't know;
		// and a live head's document's size and digest, as GET
		// …/rev/{target} serves it uncoded, where the write stored them
		// (headMeta). A pruned head keeps them, as it keeps its target.
		if plain && h.row != nil && h.state != Purged && !(lost && t.upstreamCovers(rb, h.name, &view{state: h.state})) {
			item["created"] = formatTime(h.row.created)
			if h.state == Live && level < levelAtRest && h.row.size.Valid && len(h.row.digest) == sha256.Size {
				item["size"] = float64(h.row.size.Int64)
				item["digest"] = ReprDigest(h.row.digest)
			}
		}
		out = append(out, item)
	}
	return out
}

// Branches lists a namespace's direct branches (§7.4): once the namespace
// is purged, 410 purged, after the unrestricted-read check (§8.5). public
// is the namespace's cache visibility (BranchList).
func (e *Engine) Branches(ctx context.Context, ns string, cred Credentials) ([]map[string]any, bool, error) {
	bl, err := e.BranchList(ctx, ns, cred)
	if err != nil {
		return nil, false, err
	}
	return bl.List, bl.Public, nil
}

// Branches is the answer of GET /ns/{ns}/branches (§7.4): Public its cache
// visibility. Private is never set since v0.78: a partial reader's
// /branches is 403 (§B.11.9 Answers); it stays for callers of v0.77.
type Branches struct {
	List    []map[string]any
	Public  bool
	Private bool
}

// BranchList is Branches with the answer's caching. A partial reader of a
// namespace §B.11.9 covers is refused, 403 as for any reader without an
// unrestricted read, before a purged namespace's 410: filtered reads
// cover no branch (§B.11.9 Answers; v0.78).
func (e *Engine) BranchList(ctx context.Context, ns string, cred Credentials) (*Branches, error) {
	var out *Branches
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		_, kind, _, err := t.nsAccess(n, cred)
		if err != nil {
			return err
		}
		if kind == accessPartial {
			return forbidden("a partial reader's grant doesn't read the branches of " + ns + ": filtered reads cover no branch (§B.11.9)")
		}
		if n.purged {
			return t.purgedRead(n)
		}
		out = &Branches{List: []map[string]any{}, Public: t.cachePublic(n)}
		for _, b := range t.branchesOf(n) {
			cfg := t.config(b.configSeq)
			m := map[string]any{"name": b.name, "at": t.nsLogID(b.baseAt.Int64).String(), "frozen": cfg.Frozen, "purged": b.purged}
			if cfg.Successor != "" {
				m["successor"] = cfg.Successor
			}
			if d, ok := cfg.Doc["drafts"]; ok && cfg.DraftsFor != nil {
				m["drafts"] = d // §7.4: clients apply drafts.for (§6.1)
			}
			out.List = append(out.List, m)
		}
		// Remote branches whose registration hasn't expired (§G.3).
		out.List = append(out.List, t.liveRegistrations(n)...)
		return nil
	})
	return out, err
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
