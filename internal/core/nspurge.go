package core

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Purge purges a resource (§8.3). It returns the purge entry's ns_id.
func (e *Engine) Purge(ctx context.Context, req Request, name, ifMatch string, force bool) (string, error) {
	var out string
	err := e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(req.NS)
		if n == nil {
			return t.absentNSOp(req.NS, req.Cred, force)
		}
		cfg := t.config(n.configSeq)
		a, operator, aerr := t.purger(n, cfg, req, force)
		if aerr != nil {
			return aerr
		}
		// The write's rules draw on one validation meter (§6.6, writeMeter).
		defer t.metered(func() bool { return t.canRead(n, cfg, a, name) })()
		ran := t.authorize(a, "purge", name)
		if ran != nil && !ran.ranOut {
			return ran
		}
		// ?force=1 under a grant that can't force is 403 at step 1,
		// whether or not the purge needs it (§6.1).
		if force {
			if err := t.mayForce(n, a, operator); err != nil {
				return err
			}
		}
		if ran != nil {
			// Its rules ran out of validationSteps and no check of step 1
			// failed outright: 422, drawing nothing, a purge being exempt
			// (§6.6).
			return ran
		}
		// 410 after authorisation, like every write (§6.2).
		if n.purged {
			return t.purgedNS(n)
		}
		// A purged resource is 410 at step 2.1, before the precondition
		// (§6.2, §8.3).
		v := t.resolve(n, name, nil)
		if v.state == Purged {
			return gone()
		}
		if ifMatch == "" {
			return apiErr(428, "precondition_required")
		}
		if v.state == NotFound {
			return notFound()
		}
		if ifMatch != v.head.id.String() {
			return apiErr(412, "stale", "head", v.head.id.String())
		}
		// What the purge does, in n and in every branch it propagates to
		// (§8.3), each one it reaches locked exclusively before it is read
		// (purgePlan). The copies it removes are those of n and of every
		// branch below it, as when it visited them all: the ones it has
		// nothing to do in hold no copy.
		plan := t.purgePlan(n, name)
		gone := func(ns *nsRow, res string) bool { return res == name && plan.covers(t, ns) }
		forced := false
		if broken := t.brokenReferences(refChange{exclude: gone, removed: gone, name: name}); len(broken) > 0 {
			if !force {
				return t.inUse(broken, "the purge would remove the last available copy of a referenced schema revision (§6.1)")
			}
			// The grant may force: mayForce passed at step 1.
			forced = true
		}
		env := t.basicEnvelope("purge", name, a)
		env["writes"], env["doc"], env["patches"] = []any{}, nil, []any{}
		if err := t.purgeRules(cfg, a, env, operator && forced); err != nil {
			return err
		}
		out = t.purgeApply(plan, t.actorID(a), forced).String()
		return nil
	})
	return out, err
}

// purgeRules is step 6 of a purge or namespace purge (§6.2, §6.4.3): grant,
// key and role rules (403), then namespace rules (422). overridden, a
// purge forced past an in_use refusal under a deployment operator grant,
// isn't judged by namespace rules ("Operator overrides"); its grant's own
// rules still judge it. A purge forced with a * key of a branch, one the
// operator forced that needed no forcing, and any purge while
// authentication is disabled are judged in full.
func (t *tx) purgeRules(cfg *Config, a *actor, env map[string]any, overridden bool) *Error {
	if overridden {
		return t.checkGrantRules(a, env, nil)
	}
	return t.checkRules(cfg, a, env, false)
}

// purger authenticates a purge (§8.3, §8.5). A forced one (§6.1) may come
// with a grant chained to a deployment operator key instead of one of the
// namespace's: then operator is true, and, where the purge is forced past
// an in_use refusal, the namespace's rules don't judge it (purgeRules).
func (t *tx) purger(n *nsRow, cfg *Config, req Request, force bool) (a *actor, operator bool, err *Error) {
	t.reqCreds = req.anyCreds()
	a, err = t.authenticate(n.name, n, cfg, req.Cred, nil)
	if err == nil || !force || len(t.operatorKeys()) == 0 {
		return a, false, err
	}
	if oa, oerr := t.authenticate(n.name, nil, nil, req.Cred, t.operatorKeys()); oerr == nil {
		return oa, true, nil
	}
	return nil, false, err
}

// mayForce decides whether a purge may send ?force=1 (§6.1): with a grant
// chained to a deployment operator key, or, for a purge of a branch or of
// a resource in one, to a * key of that branch, inherited or its own. A *
// key of a namespace that isn't a branch doesn't force. With
// authentication disabled everyone is the operator. Under any other grant
// ?force=1 is 403 at step 1 of §6.2, whether or not the purge needs it.
func (t *tx) mayForce(n *nsRow, a *actor, operator bool) *Error {
	if operator || t.e.opt.AuthDisabled || (n.isBranch() && a.star) {
		return nil
	}
	return forbidden("?force=1 needs a grant chained to a deployment operator key, or, in a branch, to a * key of the branch (§6.1)")
}

// purgeResource purges name in n and propagates to every branch (§8.3). It
// returns the id of n's purge entry. forced marks every entry it writes,
// propagated ones included, as overriding an in_use refusal (§3.5, §6.1).
// Propagated entries are the server's own: they keep the purger as author
// but record no grant (§7.4).
func (t *tx) purgeResource(n *nsRow, name string, author int64, forced bool) ids.ID {
	return t.purgeApply(t.purgePlan(n, name), author, forced)
}

// A purge's reach.
//
// A purge of a name propagates to every branch below its namespace, at any
// depth, frozen ones included, and does something in the ones that hold a
// resource row for the name or see an entry for it through their bases
// (§8.3); a branch that neither holds nor sees it is skipped, though its
// own branches aren't. A base may have thousands of branches made before
// the document existed, so the purge doesn't walk them: it finds the ones
// it has something to do in by name, locks those, and decides what to do
// in each before it writes anything.
//
//   - A statement per level of branches below the purged namespace finds
//     the candidates (purgePlan): asked for the branches of the level
//     above, by its ids, it tells of each whether it holds a resources row
//     for the name (by the table's key, so none is missed, whatever its
//     depth and whatever lies between), has sealed copies or blob
//     sealings stored under it, and when its own row's first entry was.
//     From that the purge keeps the holders and the ones that may read
//     the name through: those created at or after the first entry of the
//     name in their base, or below a base that may itself read it
//     through. That last set is wider than what resolve would answer,
//     never narrower, since it only picks who is looked at.
//   - The candidates are locked exclusively, and the bases their names
//     resolve through shared, in one statement (lockAll); then their rows
//     are read, as of the locks, and resolve decides for each what it
//     sees, as it did when every branch was visited. A candidate found
//     purged, or seeing nothing, gets no entry.
//   - Only then does the purge write: the content of the own copies in a
//     statement per table, an entry per namespace that saw the name, in
//     the order they were always appended in (branches first, siblings by
//     name). On Postgres the logs' heads are read in one statement, the
//     rows of the branches that read the name through inserted in one,
//     and the branches' entries appended in one (appendPurges): the
//     purge's statements don't grow with its branches. The namespaces'
//     exclusive locks stand for their log locks (lockLog).
//
// Why a branch that neither holds nor sees the name may stay unlocked on
// Postgres (D.8). The purge holds its own namespace's lock exclusively from
// before the statement that finds the candidates until it commits, and
// every write that could give such a branch something to purge needs that
// lock shared first:
//
//   - A write that creates the name in the branch found it absent there,
//     which resolve answers only after walking the branch's bases to the
//     root, each locked shared (base): it passes through the purged
//     namespace. It ran before the purge took its lock, and the candidates
//     include its row, or it runs after the purge commits, as it would
//     have behind the branch's own lock.
//   - A write to a name the branch reads through from a base below the
//     purged namespace stops at that base, without the purged namespace's
//     lock. But then the branch sees the name, at the time the candidates
//     are found too (what a branch sees through its bases changes only by
//     a purge, which leaves a row in it), so it is a candidate: the purge
//     waits for the write at the branch's lock and reads the branch's row
//     after it.
//   - A branch is created under the exclusive lock of its base, with the
//     bases above locked shared up to the root (createBranch): so none
//     appears below the purged namespace while the purge runs.
//   - A pending blob's upload may insert a row without entries for the
//     name in a skipped branch (ensureResource). The branch still sees
//     nothing, and a purge that visited it left that row alone too.
//   - Sealed copies and blob sealings are stored for a namespace that
//     serves the name, so one that holds or sees it: a candidate, whose
//     stored rows are deleted under its lock whether or not the statement
//     that found the candidates saw any.
//   - A namespace purge, a freeze or another config write of a skipped
//     branch changes nothing the purge reads: it reads no row of it.
//
// Under PATCHLOG_TEST_VALIDATE_BOTH the walk over every branch still runs,
// read-only, before the purge's first write and after its last
// (purgeCheck), and panics if it would act anywhere the purge didn't plan
// to, or differently, or if anything is left for it afterwards.

// purgePlan is what a purge of name does (§8.3), decided before its first
// write.
type purgePlan struct {
	// root is the namespace purged in, as of its lock.
	root *nsRow
	name string
	// reached are the namespaces the purge has to look at, each locked
	// exclusively: root and the candidates among its branches that aren't
	// purged.
	reached map[int64]bool
	// steps are the reached namespaces in the order the purge visits them:
	// branches first, siblings by name.
	steps []purgeStep
}

// purgeStep is a reached namespace and what it sees of the name.
type purgeStep struct {
	n *nsRow
	v *view
}

// acts reports whether the purge purges the name in the step's namespace
// and appends an entry to its log: it sees an entry for it (§8.3).
func (s purgeStep) acts() bool { return s.v.state != NotFound && s.v.state != Purged }

// covers reports whether the purge removes ns's copy of the name, if it
// has one: ns is the purged namespace or a branch below it, not purged.
// The branches the purge doesn't reach are covered too, as when it visited
// every one.
func (p *purgePlan) covers(t *tx, ns *nsRow) bool {
	if p.reached[ns.id] {
		return true
	}
	// A namespace that isn't purged has no purged base: a namespace is
	// purged only once its branches are (PurgeNamespace, purgeRaisedE2E),
	// and none is made in a purged one.
	if ns.purged || p.root.purged {
		return false
	}
	for l := t.link(ns.id); l.isBranch(); l = t.link(l.base.Int64) {
		if l.base.Int64 == p.root.id {
			return true
		}
	}
	return false
}

// purgePlan locks n and the branches a purge of name in n has something to
// do in, exclusively, and decides what it does in each (see above).
func (t *tx) purgePlan(n *nsRow, name string) *purgePlan {
	if t.locking() {
		// Every namespace a purge reaches is locked exclusively, and read
		// as of its lock (D.8 purge propagation).
		n = t.nsByIDLocked(n.id, lockExclusive)
	}
	p := &purgePlan{root: n, name: name, reached: map[int64]bool{}}
	// A namespace purged since its base listed it is skipped (§8.5).
	if n.purged {
		return p
	}
	// The candidates, level by level below n, one statement per level. lo
	// is the namespace log position from which a branch made of a
	// namespace may see the name: 0 if the namespace may read it through
	// its own base, else the first entry of its own row, else never.
	//
	// The statement names the level above by its ids, and asks of each
	// branch by scalar subqueries, which Postgres answers by the indexes
	// on (ns, name), once per branch. Written as one recursive statement
	// joining namespaces to the level above, the search was at the
	// planner's mercy: where the statistics say one base holds most
	// namespaces it ran the join as a nested loop over all of namespaces
	// for every namespace found (3.5 s with 10,000 branches of one base),
	// and it answered EXISTS from a hash of a sequential scan of resources
	// and of sealed by name.
	const never = math.MaxInt64
	type cand struct {
		id   int64
		base sql.NullInt64
	}
	cands := []cand{{n.id, n.base}}
	isCand := map[int64]bool{n.id: true}
	restore := t.planByIndex()
	const firstEntry = `(SELECT MIN(h.ns_seq) FROM resources r JOIN head_history h ON h.res = r.res WHERE r.ns = c.ns AND r.name = ?)`
	rootLo := sql.NullInt64{}
	if n.isBranch() {
		// Whether n may read the name through its base, which every
		// branch of n then may too, whenever it was made.
		base, at := t.base(n), n.baseAt.Int64
		t.seedResources(base, name)
		if t.resolve(base, name, &at).state != NotFound {
			rootLo.Valid = true
		}
	}
	if !rootLo.Valid {
		t.must(t.QueryRow(`SELECT `+firstEntry+` FROM namespaces c WHERE c.ns = ?`, name, n.id).Scan(&rootLo))
	}
	lo := map[int64]int64{n.id: never}
	if rootLo.Valid {
		lo[n.id] = rootLo.Int64
	}
	for level := []int64{n.id}; len(level) > 0; {
		rows, err := t.Query(`SELECT c.ns, c.base, c.base_at, `+firstEntry+`,
				(SELECT 1 FROM resources r WHERE r.ns = c.ns AND r.name = ? LIMIT 1),
				(SELECT 1 FROM sealed x WHERE x.ns = c.ns AND x.name = ? LIMIT 1),
				(SELECT 1 FROM blob_epochs x WHERE x.ns = c.ns AND x.name = ? LIMIT 1)
			FROM namespaces c WHERE c.purged = 0 AND `+t.e.inArray("c.base", "bigint"),
			name, name, name, name, t.e.arrayArg(level))
		t.must(err)
		var next []int64
		for rows.Next() {
			var c cand
			var at, first, row, sealed, epochs sql.NullInt64
			t.must(rows.Scan(&c.id, &c.base, &at, &first, &row, &sealed, &epochs))
			next = append(next, c.id)
			// Made at or after the position its base's branches may see
			// the name from (at 0 without one, as resolve reads it): it
			// may read the name through, and so may its own branches.
			sees := at.Int64 >= lo[c.base.Int64]
			switch {
			case sees:
				lo[c.id] = 0
			case first.Valid:
				lo[c.id] = first.Int64
			default:
				lo[c.id] = never
			}
			if sees || row.Valid || sealed.Valid || epochs.Valid {
				cands = append(cands, c)
				isCand[c.id] = true
			}
		}
		t.must(rows.Err())
		rows.Close()
		level = next
	}
	restore()
	// The bases the candidates' names resolve through that aren't
	// candidates themselves: skipped branches between a candidate and n,
	// and n's own bases.
	var tops, unknown []int64
	for _, c := range cands {
		if c.id == n.id && !n.isBranch() || isCand[c.base.Int64] && c.id != n.id {
			continue
		}
		tops = append(tops, c.base.Int64)
		if _, ok := t.links[c.base.Int64]; !ok {
			unknown = append(unknown, c.base.Int64)
		}
	}
	if len(unknown) > 0 {
		t.readChains(unknown)
	}
	// Their locks, in one statement: the candidates' exclusive, those
	// bases' shared, up to the root or the first remote shadow, as resolve
	// takes them (keepChain).
	want := map[int32]lockMode{}
	var all []int64
	seen := map[int64]bool{}
	for _, c := range cands {
		want[lockKey(c.id)] = lockExclusive
		all = append(all, c.id)
		seen[c.id] = true
	}
	for _, id := range tops {
		for !seen[id] {
			seen[id] = true
			all = append(all, id)
			want[lockKey(id)] = max(want[lockKey(id)], lockShared)
			l := t.link(id)
			if !l.isBranch() || l.isShadow() {
				break
			}
			id = l.base.Int64
		}
	}
	t.lockAll(want)
	// Their rows, as of the locks, in the order branches are listed in
	// (branchesOf), and kept for resolve (chain.go).
	arg := t.e.arrayArg(all)
	row, rank := map[int64]*nsRow{}, map[int64]int{}
	rows, err := t.Query(`SELECT `+nsCols+` FROM namespaces WHERE `+t.e.inArray("ns", "bigint")+` ORDER BY name`, arg)
	t.must(err)
	for rows.Next() {
		x, err := scanNS(rows)
		t.must(err)
		t.keepLocked(x)
		row[x.id], rank[x.id] = x, len(rank)
	}
	t.must(rows.Err())
	rows.Close()
	row[n.id] = n
	// What resolve reads of each, in a statement per table instead of
	// several per namespace: the name's rows, absent ones too;
	found := map[int64]*resRow{}
	rows, err = t.Query(`SELECT `+resCols+` FROM resources WHERE name = ? AND `+t.e.inArray("ns", "bigint"), name, arg)
	t.must(err)
	for rows.Next() {
		r, err := scanRes(rows)
		t.must(err)
		found[r.ns] = r
	}
	t.must(rows.Err())
	rows.Close()
	for _, id := range all {
		t.memoRes(resKey{id, name}, found[id])
	}
	// their heads as of the positions their branches were made at;
	var heads []int64
	var hres, hat []int64
	asked := map[headAtKey]bool{}
	for _, id := range all {
		x := row[id]
		if x == nil {
			continue
		}
		if r := found[id]; r != nil && r.headSeq.Valid {
			heads = append(heads, r.headSeq.Int64)
		}
		if r := found[x.base.Int64]; r != nil && x.isBranch() && !asked[headAtKey{r.id, x.baseAt.Int64}] {
			asked[headAtKey{r.id, x.baseAt.Int64}] = true
			hres, hat = append(hres, r.id), append(hat, x.baseAt.Int64)
		}
	}
	if len(hres) > 0 {
		q := `SELECT v.res, v.at, (SELECT h.target_seq FROM head_history h WHERE h.res = v.res AND h.ns_seq <= v.at ORDER BY h.ns_seq DESC LIMIT 1)
			FROM unnest(?::bigint[], ?::bigint[]) AS v(res, at)`
		args := []any{hres, hat}
		if !t.e.pg {
			q = `WITH v(res, at) AS (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))
				SELECT v.res, v.at, (SELECT h.target_seq FROM head_history h WHERE h.res = v.res AND h.ns_seq <= v.at ORDER BY h.ns_seq DESC LIMIT 1) FROM v`
			pairs := make([][2]int64, len(hres))
			for i := range hres {
				pairs[i] = [2]int64{hres[i], hat[i]}
			}
			args = []any{t.e.arrayArg(pairs)}
		}
		rows, err = t.Query(q, args...)
		t.must(err)
		if t.memo.headAt == nil {
			t.memo.headAt = map[headAtKey]int64{}
		}
		for rows.Next() {
			var k headAtKey
			var seq sql.NullInt64
			t.must(rows.Scan(&k.res, &k.asOf, &seq))
			t.memo.headAt[k] = seq.Int64
			if seq.Valid {
				heads = append(heads, seq.Int64)
			}
		}
		t.must(rows.Err())
		rows.Close()
	}
	// and the head entries, without their patch sets, which resolve
	// doesn't read and thousands of which needn't be held at once. Rows
	// short of them must not outlive the plan: the memo is dropped below.
	var seqs []int64
	wanted := map[int64]bool{}
	for _, seq := range heads {
		if _, ok := t.memo.rev[seq]; !ok && !wanted[seq] {
			wanted[seq] = true
			seqs = append(seqs, seq)
		}
	}
	if len(seqs) > 0 {
		rows, err = t.Query(`SELECT `+strings.Replace(revCols, " patches,", " CAST(NULL AS text),", 1)+` FROM revisions WHERE `+t.e.inArray("seq", "bigint"), t.e.arrayArg(seqs))
		t.must(err)
		if t.memo.rev == nil {
			t.memo.rev = map[int64]revRow{}
		}
		for rows.Next() {
			r, err := scanRev(rows)
			t.must(err)
			t.memo.rev[r.seq] = *r
			t.knowRevID(r.seq, r.id)
		}
		t.must(rows.Err())
		rows.Close()
	}
	// What each candidate sees. A branch purged since it was found is
	// skipped (§8.5).
	views := map[int64]*view{}
	for _, c := range cands {
		if x := row[c.id]; x != nil && !x.purged {
			p.reached[x.id] = true
			views[x.id] = t.resolve(x, name, nil)
		}
	}
	t.forget()
	// The order: branches first, since a branch reading the resource
	// through recorded its entry before its base's, and siblings by name.
	kids := map[int64][]int64{}
	for _, id := range all {
		if x := row[id]; x != nil && x.isBranch() && id != n.id {
			kids[x.base.Int64] = append(kids[x.base.Int64], id)
		}
	}
	var visit func(id int64)
	visit = func(id int64) {
		ks := kids[id]
		sort.Slice(ks, func(i, j int) bool { return rank[ks[i]] < rank[ks[j]] })
		for _, k := range ks {
			visit(k)
		}
		if p.reached[id] {
			p.steps = append(p.steps, purgeStep{row[id], views[id]})
		}
	}
	visit(n.id)
	if validateBoth {
		t.purgeCheck(p, false)
	}
	return p
}

// planByIndex makes Postgres plan the statements that follow, until the
// function it returns is called, by index scans and nested loops, and
// without compiling them: for the statements that find a purge's
// candidates, whose work must stay in proportion to the branches below the
// purged namespace whatever the tables' sizes and statistics are. Left to
// its costs, the planner reads a small table sequentially for each
// namespace asked about, however large that table has grown since it was
// planned, and past jit_above_cost it compiles a statement's expressions
// first, which took 0.3 to 1.1 s for a statement that then ran in 10 to
// 40 ms. The settings are the transaction's own (SET LOCAL), and are put
// back for the statements after it, whose plans are not this function's
// business.
func (t *tx) planByIndex() (restore func()) {
	if !t.e.pg {
		return func() {}
	}
	// The CTE is read before the row that changes the settings is made.
	const q = `WITH old AS MATERIALIZED (SELECT current_setting('jit') AS a, current_setting('enable_seqscan') AS b,
			current_setting('enable_hashjoin') AS c, current_setting('enable_mergejoin') AS d)
		SELECT old.a, old.b, old.c, old.d, set_config('jit', 'off', true), set_config('enable_seqscan', 'off', true),
			set_config('enable_hashjoin', 'off', true), set_config('enable_mergejoin', 'off', true) FROM old`
	t.counted(q)
	old, set := make([]string, 4), make([]string, 4)
	t.must(t.Tx.QueryRow(q).Scan(&old[0], &old[1], &old[2], &old[3], &set[0], &set[1], &set[2], &set[3]))
	return func() {
		const q = `SELECT set_config('jit', $1, true), set_config('enable_seqscan', $2, true),
			set_config('enable_hashjoin', $3, true), set_config('enable_mergejoin', $4, true)`
		t.counted(q)
		t.must(t.Tx.QueryRow(q, old[0], old[1], old[2], old[3]).Scan(&set[0], &set[1], &set[2], &set[3]))
	}
}

// purgeApply carries out a planned purge (purgeResource). It returns the id
// of the purged namespace's entry.
func (t *tx) purgeApply(p *purgePlan, author int64, forced bool) ids.ID {
	if len(p.steps) == 0 {
		return ids.ID{}
	}
	// Every log the purge appends to, in ascending key order, after
	// every other lock (D.8).
	var logs, own []int64
	for _, s := range p.steps {
		if s.acts() {
			logs = append(logs, s.n.id)
			if s.v.own != nil {
				own = append(own, s.v.own.id)
			}
		}
	}
	t.lockLogs(logs...)
	inserted := map[int64]int64{}
	if t.locking() && len(logs) > 1 {
		// Postgres, where each statement is a round trip: the heads of the
		// logs, as of their locks, in one statement, for appendNS to chain
		// its entries on (logHeadOf); and the rows of the branches that
		// read the name through in one, in the order they were always
		// inserted in.
		rows, err := t.Query(`SELECT ns, head_seq, head_id FROM namespaces WHERE ns = ANY(?::bigint[])`, logs)
		t.must(err)
		if t.logHeads == nil {
			t.logHeads = map[int64]logHead{}
		}
		for rows.Next() {
			var ns int64
			var seq sql.NullInt64
			var id []byte
			t.must(rows.Scan(&ns, &seq, &id))
			// Without a head_id (rows from before the column), logHeadOf
			// looks the head up.
			if seq.Valid && id != nil {
				t.logHeads[ns] = logHead{seq.Int64, ids.FromBytes(id)}
			}
		}
		t.must(rows.Err())
		rows.Close()
		var nss, heads []int64
		for _, s := range p.steps {
			if s.acts() && s.v.own == nil {
				nss, heads = append(nss, s.n.id), append(heads, s.v.head.seq)
			}
		}
		if len(nss) > 0 {
			rows, err := t.Query(`INSERT INTO resources (ns, name, head_seq, state)
				SELECT v.ns, ?, v.head, ? FROM unnest(?::bigint[], ?::bigint[]) WITH ORDINALITY AS v(ns, head, ord) ORDER BY v.ord
				RETURNING ns, res`, p.name, statePurged, nss, heads)
			t.must(err)
			t.wrote()
			for rows.Next() {
				var ns, res int64
				t.must(rows.Scan(&ns, &res))
				inserted[ns] = res
			}
			t.must(rows.Err())
			rows.Close()
			if len(inserted) != len(nss) {
				panic(fmt.Errorf("inserted %d purged rows, want %d", len(inserted), len(nss)))
			}
		}
	}
	if len(own) > 0 {
		// The own copies' content, a statement per table for all of them.
		in, arg := t.e.inArray("res", "bigint"), t.e.arrayArg(own)
		t.deleteArchives(in, arg)
		// Destroying the data keys makes whatever survives of the rows
		// and archives unreadable (§8.3, §E.1).
		t.deleteDEKs(in, arg)
		// The documents' sizes and digests go with them (headMeta).
		_, err := t.Exec(`UPDATE revisions SET patches = NULL, size = NULL, digest = NULL WHERE `+in, arg)
		t.must(err)
		_, err = t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE `+in, statePurged, arg)
		t.must(err)
		// Purge ends every attachment, and pending entries go too (§7.8,
		// §8.3).
		t.purgeBlobs(in, arg)
		// A row the purge inserts for a name read through has none of
		// these: resources rows are never deleted, so its res is new.
		for _, table := range []string{"heads", "snapshots", "e2e_snapshots"} {
			_, err = t.Exec(`DELETE FROM `+table+` WHERE `+in, arg)
			t.must(err)
		}
	}
	entryOf := func(v *view) map[string]any {
		entry := map[string]any{"resource": p.name, "kind": "purge", "target": v.head.id.String()}
		if forced {
			entry["forced"] = true
		}
		return entry
	}
	// On Postgres the propagated entries, which are the server's own and
	// come before the purged namespace's, go in one statement
	// (appendPurges) where the logs' heads are known.
	var batch []purgeAppend
	for _, s := range p.steps {
		if _, known := t.logHeads[s.n.id]; !s.acts() || s.n.id == p.root.id {
			continue
		} else if !known || !t.locking() {
			batch = nil
			break
		}
		a := purgeAppend{n: s.n, res: inserted[s.n.id], target: s.v.head.seq, body: jsonv.Canonical(entryOf(s.v))}
		if s.v.own != nil {
			a.res = s.v.own.id
		}
		batch = append(batch, a)
	}
	appended := map[int64]bool{}
	if len(batch) > 1 {
		t.appendPurges(batch, author)
		for _, a := range batch {
			appended[a.n.id] = true
			t.tags = append(t.tags, "r:"+a.n.name+"/"+p.name, "heads:"+a.n.name)
		}
		t.flushDocs = true
	}
	var out ids.ID
	for _, s := range p.steps {
		if !s.acts() || appended[s.n.id] {
			continue
		}
		n, v := s.n, s.v
		purge := func() {
			var res int64
			switch {
			case v.own != nil:
				res = v.own.id
			case inserted[n.id] != 0:
				res = inserted[n.id]
			default:
				res = t.mustInsert(`INSERT INTO resources (ns, name, head_seq, state) VALUES (?,?,?,?) RETURNING res`, n.id, p.name, v.head.seq, statePurged)
			}
			target := v.head.seq
			_, id := t.appendNS(n, entryOf(v), &res, &target, n.configSeq, author)
			if n.id == p.root.id {
				out = id
			}
			// And the /heads pages, which list a head's document's size and
			// digest (NamespaceHeads): every branch the purge reaches purges
			// its own.
			t.tags = append(t.tags, "r:"+n.name+"/"+p.name, "heads:"+n.name)
			t.flushDocs = true
		}
		if n.id == p.root.id {
			purge()
		} else {
			t.asServer(purge)
		}
	}
	// Sealed copies of its content go too (§E.2.2), in every namespace
	// reached, whatever it saw.
	reached := make([]int64, 0, len(p.steps))
	for _, s := range p.steps {
		reached = append(reached, s.n.id)
	}
	in, arg := `name = ? AND `+t.e.inArray("ns", "bigint"), t.e.arrayArg(reached)
	t.deleteSealed(in, p.name, arg)
	t.deleteBlobEpochs(in, p.name, arg)
	// A remote branch's mirrored copy is its own: it goes too, in every
	// shadow of its base's chain (§G.3). Only the purged namespace can be
	// one: a branch below it has a local base.
	for _, sh := range t.remoteShadows(p.root) {
		t.purgeShadow(sh, p.name)
	}
	if validateBoth {
		t.purgeCheck(p, true)
	}
	return out
}

// purgeAppend is a propagated purge entry to append to n's log: the row
// it purges, the head it targets and its canonical body.
type purgeAppend struct {
	n           *nsRow
	res, target int64
	body        []byte
}

// appendPurges appends a purge's propagated entries, one to the log of
// each of several namespaces, in one statement (Postgres): what appendNS
// does for each as the server's own entry, without a grant. Each
// namespace is locked exclusively and its log's head known (logHeads), so
// each entry is chained on its own log's head; their seqs are drawn
// together and given out in the entries' order, as appendNSMany's.
//
// One statement per entry made a purge's cost per branch grow with its
// branches on Postgres: a backend that holds thousands of advisory locks,
// as a purge does, one per namespace it reaches, takes longer to finish
// every statement, since releasing a statement's own locks then walks the
// table of all the locks the backend holds.
func (t *tx) appendPurges(as []purgeAppend, author int64) {
	k := len(as)
	nss, res, targets, prevs, cfgs := make([]int64, k), make([]int64, k), make([]int64, k), make([]int64, k), make([]int64, k)
	idBytes, bodies := make([][]byte, k), make([]string, k)
	entryIDs := make([]ids.ID, k)
	for i, a := range as {
		t.lockNS(a.n.id, lockExclusive)
		t.reserveEntries(a.n, a.n.configSeq, 1)
		prev, prevSeq := t.logHeadOf(a.n)
		entryIDs[i] = ids.Hash(prev, a.body)
		nss[i], res[i], targets[i], prevs[i], cfgs[i] = a.n.id, a.res, a.target, prevSeq.(int64), a.n.configSeq
		idBytes[i], bodies[i] = entryIDs[i][:], string(a.body)
	}
	t.wrote()
	rows, err := t.Query(`WITH v AS (SELECT * FROM unnest(?::bigint[], ?::bytea[], ?::bigint[], ?::bigint[], ?::bigint[], ?::text[], ?::bigint[])
				WITH ORDINALITY AS v(ns, id, prev_seq, res, target_seq, body, config_seq, ord)),
			r AS MATERIALIZED (SELECT nextval(pg_get_serial_sequence('ns_log', 'seq')) AS seq FROM generate_series(1, ?::int)),
			s AS (SELECT seq, row_number() OVER (ORDER BY seq) AS ord FROM r),
			c AS MATERIALIZED (SELECT v.*, s.seq FROM v JOIN s USING (ord)),
			l AS (INSERT INTO ns_log (seq, ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created)
				SELECT seq, ns, id, prev_seq, ?, res, target_seq, body, config_seq, ?, ? FROM c ORDER BY ord RETURNING seq),
			u AS (UPDATE namespaces n SET head_seq = c.seq, head_id = c.id, config_seq = c.config_seq FROM c WHERE n.ns = c.ns)
			SELECT ord, seq FROM c ORDER BY ord`,
		nss, idBytes, prevs, res, targets, bodies, cfgs, k, nsKindCode("purge"), author, t.now.UnixMilli())
	t.must(err)
	seqs := make([]int64, 0, k)
	for rows.Next() {
		var ord, seq int64
		t.must(rows.Scan(&ord, &seq))
		seqs = append(seqs, seq)
	}
	t.must(rows.Err())
	rows.Close()
	if len(seqs) != k {
		panic(fmt.Errorf("appended %d purge entries, want %d", len(seqs), k))
	}
	for i, a := range as {
		a.n.headSeq = sql.NullInt64{Int64: seqs[i], Valid: true}
		t.logHeads[a.n.id] = logHead{seqs[i], entryIDs[i]}
		t.lastNS = seqs[i]
		t.notify[a.n.name] = true
	}
}

// purgeCheck is the PATCHLOG_TEST_VALIDATE_BOTH oracle of a purge: the walk
// over the purged namespace and every branch below it that isn't purged,
// which a purge was before it found the branches it reaches by name
// (purgePlan). Before the purge's first write it panics unless every
// namespace in which the walk would purge the name, append an entry or
// delete stored sealings is one the plan reaches, and the plan sees there
// what the walk sees; done, after its last write, unless the walk finds
// nothing left to do anywhere, the remote shadows included.
func (t *tx) purgeCheck(p *purgePlan, done bool) {
	steps := map[int64]purgeStep{}
	for _, s := range p.steps {
		steps[s.n.id] = s
	}
	t.asOracle(func() {
		stored := func(ns int64) bool {
			var has bool
			t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM sealed WHERE ns = ? AND name = ?) OR EXISTS (SELECT 1 FROM blob_epochs WHERE ns = ? AND name = ?)`,
				ns, p.name, ns, p.name).Scan(&has))
			return has
		}
		var walk func(x *nsRow)
		walk = func(x *nsRow) {
			for _, b := range t.branchesOf(x) {
				if !b.purged {
					walk(b)
				}
			}
			v := t.resolve(x, p.name, nil)
			acts, has := v.state != NotFound && v.state != Purged, stored(x.id)
			s, planned := steps[x.id]
			switch {
			case done && (acts || has):
				panic(fmt.Sprintf("purge of %s in %s: %s still has it afterwards (state %v, stored sealings %v)", p.name, p.root.name, x.name, v.state, has))
			case done:
			case !p.covers(t, x):
				panic(fmt.Sprintf("purge of %s in %s: %s isn't covered", p.name, p.root.name, x.name))
			case (acts || has) && !p.reached[x.id]:
				panic(fmt.Sprintf("purge of %s in %s: %s isn't reached (state %v, stored sealings %v)", p.name, p.root.name, x.name, v.state, has))
			case planned && acts != s.acts():
				panic(fmt.Sprintf("purge of %s in %s: %s is %v, the plan has %v", p.name, p.root.name, x.name, v.state, s.v.state))
			case acts && (s.v.head.seq != v.head.seq || s.v.head.id != v.head.id || (s.v.own == nil) != (v.own == nil) || v.own != nil && s.v.own.id != v.own.id):
				panic(fmt.Sprintf("purge of %s in %s: the plan sees another head or row in %s", p.name, p.root.name, x.name))
			}
		}
		root := t.nsByID(p.root.id)
		if root.purged {
			return
		}
		walk(root)
		if !done {
			return
		}
		for _, sh := range t.remoteShadows(root) {
			if r := t.resource(sh.id, p.name); r != nil && r.state != statePurged || stored(sh.id) {
				panic(fmt.Sprintf("purge of %s in %s: its remote shadow %s still has it afterwards", p.name, p.root.name, sh.name))
			}
		}
	})
}

// PurgeNamespace purges a frozen namespace (§8.5). It returns the purge-ns
// entry's ns_id.
//
// With force it purges even if that removes the last copy of a referenced
// schema revision (§6.1, §8.5): with a grant chained to a deployment
// operator key, or, for a branch, to a * key of the branch. The purge-ns
// entry then says forced: true (§3.5). Dependents can't be forced.
func (e *Engine) PurgeNamespace(ctx context.Context, req Request, ifMatch string, force bool) (string, error) {
	var out string
	err := e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(req.NS)
		if n == nil {
			return t.absentNSOp(req.NS, req.Cred, force)
		}
		cfg := t.config(n.configSeq)
		a, operator, aerr := t.purger(n, cfg, req, force)
		if aerr != nil {
			return aerr
		}
		// The write's rules draw on one validation meter (§6.6, writeMeter).
		defer t.metered(nil)()
		ran := t.authorize(a, "purge-ns", "")
		if ran != nil && !ran.ranOut {
			return ran
		}
		// ?force=1 under a grant that can't force is 403 at step 1 (§6.1).
		if force {
			if err := t.mayForce(n, a, operator); err != nil {
				return err
			}
		}
		if ran != nil {
			// Out of validationSteps with no check of step 1 failing
			// outright: 422, drawing nothing, as a purge is exempt (§6.6).
			return ran
		}
		// In §6.2's order (§8.5): 410 after authorisation, like every
		// write (step 2.1); not frozen (step 2.4); then the precondition
		// (step 2.5).
		if n.purged {
			return t.purgedNS(n)
		}
		if !cfg.Frozen {
			return apiErr(409, "not_frozen")
		}
		if ifMatch == "" {
			return apiErr(428, "precondition_required")
		}
		head := t.nsLogID(n.headSeq.Int64)
		if ifMatch != head.String() {
			return apiErr(412, "stale", "head", head.String())
		}
		var deps []string
		for _, b := range t.branchesOf(n) {
			if !b.purged {
				deps = append(deps, b.name)
			}
		}
		if len(deps) > 0 {
			return apiErr(409, "in_use", "dependents", anyStrings(deps))
		}
		gone := func(ns *nsRow, _ string) bool { return ns.id == n.id }
		forced := false
		if broken := t.brokenReferences(refChange{exclude: gone, removed: gone}); len(broken) > 0 {
			if !force {
				return t.inUse(broken, "the namespace holds the last available copy of a schema revision referenced from another namespace (§6.1)")
			}
			// The grant may force: mayForce passed at step 1.
			forced = true
		}
		env := t.basicEnvelope("purge-ns", "", a)
		env["writes"], env["doc"], env["patches"] = []any{}, nil, []any{}
		if err := t.purgeRules(cfg, a, env, operator && forced); err != nil {
			return err
		}
		out = t.purgeNSNow(n, forced, t.actorID(a))
		return nil
	})
	return out, err
}

// purgeNSNow purges namespace n, its checks passed (PurgeNamespace), or
// at Open (purgeRaisedE2E), as author: its content, sealed bytes and epoch
// keys go, with its remote shadows', and a purge-ns entry is appended. It
// returns the entry's ns_id.
func (t *tx) purgeNSNow(n *nsRow, forced bool, author int64) string {
	t.deleteArchives(`res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
	t.deleteDEKs(`ns = ?`, n.id)
	// Sealed bytes and epoch keys go too (§E.2, §8.5).
	t.deleteSealed(`ns = ?`, n.id)
	t.deleteBlobEpochs(`ns = ?`, n.id)
	t.deleteEpochKeys(n.id)
	_, err := t.Exec(`UPDATE revisions SET patches = NULL, size = NULL, digest = NULL WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
	t.must(err)
	_, err = t.Exec(`DELETE FROM heads WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
	t.must(err)
	_, err = t.Exec(`DELETE FROM snapshots WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
	t.must(err)
	_, err = t.Exec(`DELETE FROM e2e_snapshots WHERE res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
	t.must(err)
	t.purgeBlobs(`res IN (SELECT res FROM resources WHERE ns = ?)`, n.id)
	_, err = t.Exec(`UPDATE resources SET state = ?, keep = NULL WHERE ns = ?`, statePurged, n.id)
	t.must(err)
	t.metaChanged = true
	_, err = t.Exec(`UPDATE namespaces SET purged = 1 WHERE ns = ?`, n.id)
	t.must(err)
	// A remote branch's mirrored copy of its base goes too; nothing
	// reaches the base (§G.3).
	for _, sh := range t.remoteShadows(n) {
		t.purgeShadowNS(sh)
	}
	entry := map[string]any{"kind": "purge-ns"}
	if forced {
		entry["forced"] = true
	}
	_, nsID := t.appendNS(n, entry, nil, nil, n.configSeq, author)
	t.tags = append(t.tags, "ns:"+n.name)
	t.flushDocs = true
	return nsID.String()
}
