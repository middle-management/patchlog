package core

import (
	"context"
	"sync"

	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Reads are judged per revision (§C.2 item 5): a read envelope's doc is
// the document of the revision the read concerns (§6.4.1), the head for a
// resource's URLs that name none, that revision for /rev/{id}, each
// entry's for a log, the deleted document for a tombstone, and null where
// the read concerns no stored document (none, purged, or pruned and not
// kept), in an end-to-end namespace (sealed ones judge the plaintext the
// origin holds, v0.89), and for purge entries. A
// rule that refers to /doc fails as a whole against a null doc.
//
// A judge is one reader's check: its grant's rules, or those a view's
// record keeps for a cookie (§7.9), as a grantcheck.ReadFilter, and the
// digest of what they judge by (grantcheck.ScopeDigest), which keys every
// answer it gives. Where no rule refers to /doc the answer depends on the
// resource's name alone, and is memoised by name. Otherwise it depends on
// the revision: an id determines its document everywhere (§3.3), so an
// answer is kept by (digest, name, id) in read_judged, which a read
// transaction can't write to: the answers it gives are kept in memory at
// once and written to the table after it ends (flushJudged), and are read
// back from it even once pruning drops the document (§7.9 Cost, §8.6). A
// purged resource is judged without its document (null), whatever the
// table holds.
type judge struct {
	key    string
	filter *grantcheck.ReadFilter
	doc    bool // a rule refers to /doc

	mu    sync.Mutex
	names map[string]bool

	once   sync.Once
	nondoc *grantcheck.ReadFilter
}

// byNameOnly reports whether the rules of j that don't refer to /doc,
// alls flattened (grantcheck.ReadFilter.WithoutDoc), allow reading name:
// what holds for every revision j may read, and all a purge entry is
// judged by (§7.9 Log entries).
func (j *judge) byNameOnly(name string) bool {
	j.once.Do(func() {
		j.nondoc = j.filter.WithoutDoc()
		j.nondoc.Steps = j.filter.Steps
	})
	return j.nondoc.Allows(name)
}

// newJudge is the judge of filter, whose digest is key.
func (t *tx) newJudge(key string, filter *grantcheck.ReadFilter) *judge {
	// Each revision judged has its own budget of validationSteps for the
	// rules' schema tests (§6.6 Validation work).
	filter.Steps = t.e.opt.MaxValidationSteps
	return &judge{key: key, filter: filter, doc: filter.RefersToDoc(), names: map[string]bool{}}
}

// grantJudge is the judge of a's grant's reads: its key scope, blocks and
// the roles that count for read (§C.2 item 5, readFilterOf). nil where a
// rule of its blocks or key scope refers to /now, or it carries roles and
// none counts for read: such a grant reads nothing.
func (t *tx) grantJudge(a *actor) *judge {
	if a == nil || a.verified == nil {
		return nil
	}
	if a.judge != nil {
		return a.judge
	}
	in := readScopeInput(a.verified)
	digest, ok := grantcheck.ScopeDigest(in)
	if !ok || a.verified.HasRoles() && len(in.Roles) == 0 {
		return nil
	}
	a.judge = t.newJudge(digest, readFilterOf(a.verified))
	return a.judge
}

// byName reports whether name is readable by j where the read concerns
// no stored document: j's answer for any revision of name when no rule
// refers to /doc.
func (j *judge) byName(name string) bool {
	j.mu.Lock()
	v, ok := j.names[name]
	j.mu.Unlock()
	if ok {
		return v
	}
	if testFilteredJudge != nil {
		testFilteredJudge(j.key, name)
	}
	v = j.filter.Allows(name)
	j.mu.Lock()
	j.names[name] = v
	j.mu.Unlock()
	return v
}

// testFilteredJudge, if set, is called with the judge's key and the
// resource's name each time a judge evaluates its rules for a name or a
// revision that neither memory nor read_judged answered (tests: §7.9
// Cost).
var testFilteredJudge func(key, name string)

// judgedKey keys an answer in the engine's memory and in read_judged.
type judgedKey struct {
	judge, name string
	id          ids.ID
}

// visibleRow reports whether j may read row, a revision or tombstone of
// resource name in n (nil for none: the read concerns no document), with
// that revision's read envelope (§6.4.1, §C.2 item 5).
func (t *tx) visibleRow(j *judge, n *nsRow, name string, row *revRow) bool {
	if !j.doc {
		return j.byName(name)
	}
	if row == nil || t.nsLevel(n) >= levelE2E || t.resPurged(row.res) {
		return j.filter.AllowsDoc(name, nil, false)
	}
	k := judgedKey{j.key, name, row.id}
	if v, ok := t.e.judgedGet(k); ok {
		return v
	}
	var stored int64
	err := t.QueryRow(`SELECT visible FROM read_judged WHERE judge = ? AND name = ? AND id = ?`, j.key, name, row.id[:]).Scan(&stored)
	if err == nil {
		t.e.judgedPut(k, stored != 0)
		return stored != 0
	}
	if testFilteredJudge != nil {
		testFilteredJudge(j.key, name)
	}
	b, derr := t.docBytesAt(row)
	if derr != nil {
		// Pruned and not kept, never judged: null (§6.4.1). Not kept, as
		// an archive may bring the document back.
		return j.filter.AllowsDoc(name, nil, false)
	}
	v := j.filter.AllowsDoc(name, jsonv.MustParse(b), true)
	t.e.judgedPut(k, v)
	t.judged = append(t.judged, judgedRow{k, v})
	return v
}

// resPurged reports whether resource row res is purged.
func (t *tx) resPurged(res int64) bool {
	var state int
	t.must(t.QueryRow(`SELECT state FROM resources WHERE res = ?`, res).Scan(&state))
	return state == statePurged
}

// judgedRow is an answer to write to read_judged (flushJudged).
type judgedRow struct {
	k judgedKey
	v bool
}

const judgedMemMax = 1 << 16

func (e *Engine) judgedGet(k judgedKey) (bool, bool) {
	e.judgedMu.Lock()
	defer e.judgedMu.Unlock()
	return e.judgedMem.Get(k)
}

func (e *Engine) judgedPut(k judgedKey, v bool) {
	e.judgedMu.Lock()
	defer e.judgedMu.Unlock()
	if e.judgedMem.MaxEntries == 0 {
		e.judgedMem.MaxEntries = judgedMemMax
	}
	e.judgedMem.Put(k, v, 1)
}

// flushJudged writes the answers a read transaction gave to read_judged,
// once it has ended. A failure loses only the saving: the answer is
// judged again, while the document is stored.
func (e *Engine) flushJudged(ctx context.Context, rows []judgedRow) {
	if len(rows) == 0 {
		return
	}
	ctx = context.WithoutCancel(ctx)
	_ = e.update(ctx, func(t *tx) error {
		for _, r := range rows {
			if _, err := t.Exec(`INSERT INTO read_judged (judge, name, id, visible) VALUES (?, ?, ?, ?) ON CONFLICT (judge, name, id) DO NOTHING`,
				r.k.judge, r.k.name, r.k.id[:], boolInt(r.v)); err != nil {
				return err
			}
		}
		return nil
	})
}

// rowJudge is the judge a's reads of n's revisions are checked by (§C.2
// item 5), and all true where every revision its admission allows is
// readable: no actor, as with authentication disabled, in a public
// namespace but at a view's URL, an edge cookie for /r/ (issued only without rules on /doc,
// §C.5.2), or an unrestricted reader's cookie at a view's URL. A nil
// judge without all reads nothing.
func (t *tx) rowJudge(n *nsRow, a *actor) (j *judge, all bool) {
	if a == nil || t.e.opt.AuthDisabled {
		return nil, true
	}
	if a.view != "" {
		// Admitted at a view's URL, which judges by the view in a
		// public namespace too (§7.9 Where, v0.90).
		return a.judge, a.judge == nil
	}
	if t.config(n.configSeq).Read == "public" {
		return nil, true
	}
	if a.verified == nil {
		return nil, true
	}
	return t.grantJudge(a), false
}

// mayReadRow is the per-revision read check of a reader admitted at a
// resource's URL (reader), for row, a revision or tombstone of name, nil
// where the read concerns none (§C.2 item 5). A grant whose rules don't
// refer to /doc was decided by its admission.
func (t *tx) mayReadRow(a *actor, n *nsRow, name string, row *revRow) bool {
	j, all := t.rowJudge(n, a)
	switch {
	case all:
		return true
	case j == nil:
		return false
	case !j.doc && a.view == "":
		return true
	}
	return t.visibleRow(j, n, name, row)
}

// readsByDoc reports whether a's reads of n are judged per revision
// beyond its admission: its rules refer to /doc, so that a read serving
// several revisions is judged per entry, or it reads at a view's URL,
// whose admission judged no name (reader).
func (t *tx) readsByDoc(n *nsRow, a *actor) bool {
	j, all := t.rowJudge(n, a)
	return !all && (j == nil || j.doc || a.view != "")
}

// mayReadBlob is the read check of blob bid of name in n under a (§7.8,
// §6.4.1): judged with each stored document of the resource's history
// that references it, passing where one passes, or with the head where
// none references it.
func (t *tx) mayReadBlob(a *actor, n *nsRow, name string, bid ids.ID) bool {
	j, all := t.rowJudge(n, a)
	switch {
	case all:
		return true
	case j == nil:
		return false
	case !j.doc:
		return a.view == "" || j.byName(name)
	}
	v := t.resolve(n, name, nil)
	if v.head == nil {
		return t.visibleRow(j, n, name, nil)
	}
	found := false
	for _, seg := range t.ancestry(v.head) {
		rows, err := t.Query(`SELECT r.seq FROM revisions r JOIN blob_refs b ON b.res = r.res AND b.bid = ?
			WHERE r.res = ? AND r.kind = ? AND r.seq <= ? AND r.seq >= b.from_seq AND (b.to_seq IS NULL OR r.seq < b.to_seq)
			ORDER BY r.seq DESC`, bid[:], seg.res, kindRev, seg.max)
		t.must(err)
		var seqs []int64
		for rows.Next() {
			var s int64
			t.must(rows.Scan(&s))
			seqs = append(seqs, s)
		}
		t.must(rows.Err())
		rows.Close()
		for _, s := range seqs {
			found = true
			if t.visibleRow(j, n, name, t.rev(s)) {
				return true
			}
		}
	}
	return !found && t.visibleRow(j, n, name, v.head)
}

// visibleBlobEpochs lists, for a whose reads of sealed n are judged per
// revision (readsByDoc), the epochs n serves blob bid of name under
// through a revision a may read: those whose epoch is fixed (§E.2.2) and
// whose document references it. A blob of an epoch only hidden revisions
// reference is a read-rule failure (§7.9 Content: "a blob a visible
// revision references (sealed: one of epoch e …)", v0.89). all is true
// where a's admission decides alone (rowJudge).
func (t *tx) visibleBlobEpochs(a *actor, n *nsRow, name string, bid ids.ID) (eps map[int]bool, all bool) {
	j, every := t.rowJudge(n, a)
	if every || j != nil && !j.doc && (a.view == "" || j.byName(name)) {
		return nil, true
	}
	eps = map[int]bool{}
	if j == nil {
		return eps, false
	}
	v := t.resolve(n, name, nil)
	if v.head == nil {
		return eps, false
	}
	for _, seg := range t.ancestry(v.head) {
		rows, err := t.Query(`SELECT r.seq FROM revisions r JOIN blob_refs b ON b.res = r.res AND b.bid = ?
			WHERE r.res = ? AND r.kind = ? AND r.seq <= ? AND r.seq >= b.from_seq AND (b.to_seq IS NULL OR r.seq < b.to_seq)
			ORDER BY r.seq DESC`, bid[:], seg.res, kindRev, seg.max)
		t.must(err)
		var seqs []int64
		for rows.Next() {
			var s int64
			t.must(rows.Scan(&s))
			seqs = append(seqs, s)
		}
		t.must(rows.Err())
		rows.Close()
		for _, s := range seqs {
			row := t.rev(s)
			if !t.visibleRow(j, n, name, row) {
				continue
			}
			if e, fixed := t.revEpochFixed(n, row); fixed {
				eps[e] = true
			}
		}
	}
	return eps, false
}

// ViewPrivate reports whether cred, a view's content URL's (ViewCredentials),
// reads unfiltered under an unrestricted reader's /ns/{ns} cookie: no
// cache may keep its answers for the view's readers.
func (c Credentials) ViewPrivate() bool { return c.viewed != nil && c.viewed.j == nil }

// ViewCredentials admits a request at a view's content URL (§7.9
// Content), /ns/{ns}/view/{view}/r/{name}/…, at the current checkpoint as
// filteredAdmit admits it, and returns the credentials under which the
// resource read paths answer it as its own form, judging each revision by
// the view: a revision it may not read is answered as a read-rule failure
// there (404).
func (e *Engine) ViewCredentials(ctx context.Context, ns, view string, cred Credentials) (Credentials, error) {
	var out Credentials
	err := e.read(ctx, func(t *tx) error {
		n, fs, err := t.filteredOpen(ns, cred)
		if err != nil {
			return err
		}
		fv, aerr := t.filteredAdmit(n, fs, view, t.filteredCurrent(fs), cred)
		if aerr != nil {
			return aerr
		}
		vb := &viewedBy{ns: ns, view: view, reader: fv.a}
		if !fv.unrestricted {
			vb.j = fv.j
		}
		out = Credentials{viewed: vb}
		return nil
	})
	return out, err
}

// fview is one view's reading of a covered namespace at one checkpoint
// (§7.9): its view id and subjects, and the judge of its readers' rules.
// Every filtered read path judges revisions with it (visible). It is safe
// for concurrent use, long-poll waiters of a view sharing one
// (sharedView), but each call reads through the transaction it is given.
type fview struct {
	fs       *fscope
	cp       *fcp
	view     string
	subjects []string
	j        *judge
	// a is the reader: its grant's actor, or one standing for a cookie,
	// named and bucketed by the prefix as edgeReader's are.
	a *actor
	// unrestricted: an unrestricted reader's /ns/{ns} cookie, which
	// reads at the view's URLs as at its own (filteredAdmit).
	unrestricted bool
}

// View is the view's id (§7.9 view).
func (fv *fview) View() string { return fv.view }

// CP is the checkpoint the view judges at.
func (fv *fview) CP() *fcp { return fv.cp }

// newFview builds a view's reading at cp, judged by j.
func (t *tx) newFview(fs *fscope, cp *fcp, view string, subjects []string, j *judge, a *actor) *fview {
	return &fview{fs: fs, cp: cp, view: view, subjects: subjects, j: j, a: a}
}

// visible reports whether row, a revision or tombstone of name (nil for
// none), is visible to the view (§7.9 Visible).
func (fv *fview) visible(t *tx, name string, row *revRow) bool {
	if fv.unrestricted {
		return true
	}
	return t.visibleRow(fv.j, fv.fs.n, name, row)
}

// purgeShown reports whether a purge of name is shown to the view: the
// rules that don't refer to /doc, alls flattened, allow reading it (§7.9
// Log entries).
func (fv *fview) purgeShown(name string) bool {
	if fv.unrestricted {
		return true
	}
	return fv.j.byNameOnly(name)
}

// candidates calls fn, in ascending byte order, with every name the
// namespace has or had after after (and under prefix, if not ""), until
// fn returns false. They are a superset: callers still judge each.
func (fv *fview) candidates(t *tx, after, prefix string, fn func(name string) bool) {
	for from := after; ; {
		names := t.namesIn(fv.fs.n, from, prefix, 256)
		for _, name := range names {
			if !fn(name) {
				return
			}
		}
		if len(names) < 256 {
			return
		}
		from = names[len(names)-1]
	}
}
