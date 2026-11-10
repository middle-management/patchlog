package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/lifecycle"
)

// Namespaces visibility reads that the index doesn't serve (§A.4 Private
// namespaces: "Where §B.11.9 covers {ns}, the service follows the
// namespaces visibility reads, as §B.5 does"): the catalogs a covered
// namespace trusts, their catalog.trust members and a covered branch's
// bases, wherever the index doesn't follow them as namespaces of its own
// (known). The index calls them members.
//
// Each member has a light follower (follow.Follower with memberHandler)
// that indexes nothing: it applies only checkpoints, purges and config
// entries (§A.1). A purge, of a resource or of the namespace, or a config
// entry on which §9 purges ns:{m} (one making m private or raising it to
// sealed or e2e, narrowed), purges idx:{m}, which every answer at a
// combined checkpoint that lists m carries (coverTags), from the service's
// own cache and drops kept results, by the same path as a purge in a
// namespace the index serves (purgeTx, purgeStored, purgeKept). The
// checkpoint is committed with that purge's second purge in
// member_checkpoints, and the read mode and level last applied in
// member_conf (migration 008), so a restart on the same store resumes
// where the follower stopped and purges made meanwhile still reach the
// cache (§B.5 Behind: "a restart on the same store doesn't wait again").
// A new follower starts at the member's head, purging idx:{m} once: what
// was cached before had no follower behind it.
//
// memberAt takes a member at its follower's committed checkpoint, never at
// a head no follower has applied, so every purge after the position an
// answer was computed at drops it (kept.Store.Generation, taken as the
// view reads the member's position, before its state, sees the purges
// that race its read: fcp.gens). It waits, up to MinWait, for the
// follower to reach the head the grant checker read, so answers are no
// staler than the checker's; until the follower holds its first checkpoint, a member's
// state can't be read, and a partial reader of a namespace covered through
// it is answered 503 behind (errMemberBehind). A follower starts when
// coverage first reads its member (memberAt, baseFollowed). The reconciler
// (Run, reconcile) stops it once no namespace the index serves reads it
// for its coverage, purging idx:{m} once more, as nothing purges it after,
// and forgets its checkpoint (forgetMember): a follower started again
// later is a new catch-up, which starts at the head as any new one, never
// from a checkpoint nothing followed since (§B.5 Behind), and a stopped
// follower still ending commits and publishes nothing more (current). The
// reconciler judges that again whenever a namespace document coverage
// reads may have changed: a config or purge-ns entry applied, or a
// member's first checkpoint.

// errMemberBehind is a member whose follower holds no checkpoint yet
// (memberCP): 503 behind, with Retry-After (writeUpstreamErr). It is never
// errNotReached, a namespace the index itself hasn't reached, whose
// coverage can't be told yet and which grantAccess reads by rules alone
// where its current document says it can't be covered: a namespace the
// index has reached, and covers at its checkpoint, is never read by rules
// alone for want of a member's checkpoint (§A.4, §B.11.9).
var errMemberBehind = errors.New("a namespace visibility reads is not followed yet")

// members are the index's members and their followers.
type members struct {
	mu sync.Mutex
	m  map[string]*member
	// needs are, per namespace the index serves, the members its coverage
	// read when the reconciler last computed it.
	needs map[string]map[string]bool
	// run is Run's context, which followers run under; nil before Run.
	run  context.Context
	wg   sync.WaitGroup
	kick chan struct{} // the reconciler is due
}

// member is one member's state.
type member struct {
	cur     string          // the committed checkpoint, "" before the first
	purged  bool            // its purge-ns applied
	applied map[string]bool // ns_ids its follower reached lately (appliedMax), cur among them
	order   []string        // applied, oldest first
	changed chan struct{}   // closed and replaced whenever cur or purged changes
	stop    context.CancelFunc
	done    chan struct{} // closed once the running follower has ended
}

// appliedMax bounds the ns_ids a member keeps as applied: enough for every
// entry of a busy namespace within the grant checker's TTL, beyond which
// memberAt only waits longer.
const appliedMax = 4096

func (ms *members) init() {
	ms.m, ms.needs, ms.kick = map[string]*member{}, map[string]map[string]bool{}, make(chan struct{}, 1)
}

// get is m's state, created if new; ms.mu is held.
func (ms *members) get(m string) *member {
	mb := ms.m[m]
	if mb == nil {
		mb = &member{applied: map[string]bool{}, changed: make(chan struct{})}
		ms.m[m] = mb
	}
	return mb
}

// reset forgets m's checkpoint, as before its first, and wakes memberAt's
// waiters (forgetMember); ix.mem.mu is held.
func (mb *member) reset() {
	mb.cur, mb.applied, mb.order = "", map[string]bool{}, nil
	close(mb.changed)
	mb.changed = make(chan struct{})
}

// current reports whether done is that of m's running follower: one
// stopped since commits and publishes nothing more (forgetMember);
// ix.mem.mu is held.
func (ms *members) current(m string, done chan struct{}) bool {
	mb := ms.m[m]
	return mb != nil && mb.stop != nil && mb.done == done
}

// reach records that m's follower reached ids, the last its checkpoint
// cur ("" leaves cur as it is), and wakes memberAt's waiters; ms.mu is
// held.
func (mb *member) reach(cur string, purged bool, ids ...string) {
	for _, id := range append(ids, cur) {
		if id == "" || mb.applied[id] {
			continue
		}
		mb.applied[id] = true
		mb.order = append(mb.order, id)
		if len(mb.order) > appliedMax {
			delete(mb.applied, mb.order[0])
			mb.order = mb.order[1:]
		}
	}
	if cur != "" {
		mb.cur = cur
	}
	mb.purged = mb.purged || purged
	close(mb.changed)
	mb.changed = make(chan struct{})
}

// kickMembers makes the reconciler run soon (Run).
func (ix *Index) kickMembers() {
	select {
	case ix.mem.kick <- struct{}{}:
	default:
	}
}

// loadMembers reads the members' committed checkpoints.
func (ix *Index) loadMembers(ctx context.Context) error {
	rows, err := ix.db.QueryContext(ctx, `SELECT ns, ns_id FROM member_checkpoints WHERE origin = ?`, ix.origin)
	if err != nil {
		return err
	}
	defer rows.Close()
	ix.mem.mu.Lock()
	defer ix.mem.mu.Unlock()
	for rows.Next() {
		var ns, id string
		if err := rows.Scan(&ns, &id); err != nil {
			return err
		}
		ix.mem.get(ns).reach(id, false)
	}
	return rows.Err()
}

// Members are the namespaces the index follows without serving them, those
// visibility reads for a namespace §B.11.9 covers (§A.4), each with the
// checkpoint its follower committed ("" before the first).
func (ix *Index) Members() map[string]string {
	ix.mem.mu.Lock()
	defer ix.mem.mu.Unlock()
	out := map[string]string{}
	for m, mb := range ix.mem.m {
		if mb.stop != nil {
			out[m] = mb.cur
		}
	}
	return out
}

// needsKey carries a needSet, which collects the members a computation of
// coverage reads (reconcile).
type needsKey struct{}

type needSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func noteNeed(ctx context.Context, m string) {
	if s, _ := ctx.Value(needsKey{}).(*needSet); s != nil {
		s.mu.Lock()
		s.m[m] = true
		s.mu.Unlock()
	}
}

// memberCP is the committed checkpoint of m, a member read at its head
// (memberAt), once its follower has reached head, the head the grant
// checker read ("" for any checkpoint), waiting up to MinWait for it; at
// the end of the wait, the checkpoint it holds. ok is false, and purged
// true, once m's purge-ns is applied. Before the first checkpoint it is
// errMemberBehind. The follower is started if it isn't running.
func (ix *Index) memberCP(ctx context.Context, m, head string) (id string, ok, purged bool, err error) {
	noteNeed(ctx, m)
	ix.wantMember(m)
	ix.mu.Lock()
	wait := ix.opt.MinWait
	ix.mu.Unlock()
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	for {
		ix.mem.mu.Lock()
		mb := ix.mem.get(m)
		cur, purged, changed := mb.cur, mb.purged, mb.changed
		reached := cur != "" && (head == "" || cur == head || mb.applied[head])
		ix.mem.mu.Unlock()
		switch {
		case purged:
			return "", false, true, nil
		case reached:
			ix.noteGens(ctx)
			return cur, true, false, nil
		}
		select {
		case <-changed:
			continue
		case <-ctx.Done():
			return "", false, false, ctx.Err()
		case <-timer.C:
		case <-lifecycle.Stopping(ctx):
			// Shutting down: answer now, as if the wait had run out.
		}
		if cur == "" {
			return "", false, false, fmt.Errorf("%w: %s (§A.4)", errMemberBehind, m)
		}
		ix.noteGens(ctx)
		return cur, true, false, nil
	}
}

// baseFollowed waits, as memberCP does, until a covered branch's base ns,
// which visibility reads as of the branch's baseAt, has a follower with a
// checkpoint, where the index doesn't serve it: the answer is tagged
// idx:{ns} (coverTags), which only a follower of ns purges (§A.4, §A.1).
func (ix *Index) baseFollowed(ctx context.Context, ns string) error {
	if !client.ValidNSName(ns) || ix.known(ns) {
		return nil
	}
	_, _, _, err := ix.memberCP(ctx, ns, "")
	return err
}

// wantMember starts m's follower if it isn't running, once Run runs.
func (ix *Index) wantMember(m string) {
	ix.mem.mu.Lock()
	started := ix.startMember(m)
	ix.mem.mu.Unlock()
	if started {
		ix.kickMembers()
	}
}

// startMember starts m's follower under Run's context unless it is
// running, Run doesn't run or m is purged, and reports whether it did; a
// follower stopped before ends first. ix.mem.mu is held.
func (ix *Index) startMember(m string) bool {
	mb := ix.mem.get(m)
	if mb.stop != nil || mb.purged || ix.mem.run == nil {
		return false
	}
	ctx, cancel := context.WithCancel(ix.mem.run)
	prev, done := mb.done, make(chan struct{})
	mb.stop, mb.done = cancel, done
	ix.mem.wg.Add(1)
	go func() {
		defer ix.mem.wg.Done()
		defer close(done)
		defer cancel()
		if prev != nil {
			select {
			case <-prev:
			case <-ctx.Done():
				return
			}
		}
		ix.followMember(ctx, m, done)
		ix.mem.mu.Lock()
		if mb.done == done {
			mb.stop = nil
		}
		ix.mem.mu.Unlock()
	}()
	return true
}

// followMember follows m until ctx is done or m is purged. A follower that
// stops on an error is restarted after a pause, as Index.follow does.
func (ix *Index) followMember(ctx context.Context, m string, done chan struct{}) {
	pause := time.Second
	for {
		err := ix.runMember(ctx, m, done)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, follow.ErrPurged) {
			ix.opt.Logf("index: %s, which visibility reads, was purged", m)
			ix.kickMembers()
			return
		}
		ix.opt.Logf("index: following %s, which visibility reads, stopped: %v; restarting in %s", m, err, pause)
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if pause < 30*time.Second {
			pause *= 2
		}
	}
}

// memberCPs are the members' checkpoints (member_checkpoints). Never a
// follow.Resumer: a member's follower always starts from a checkpoint
// (bootstrapMember), never from a snapshot.
type memberCPs struct{ s follow.SQLCheckpoints }

func (c memberCPs) Load(ctx context.Context, origin, ns string) (string, error) {
	return c.s.Load(ctx, origin, ns)
}

func (ix *Index) memberCheckpoints() follow.SQLCheckpoints {
	return follow.SQLCheckpoints{DB: ix.db, Table: "member_checkpoints"}
}

// runMember runs one follower of m, the one done ends, from the head
// where it has no checkpoint yet (bootstrapMember).
func (ix *Index) runMember(ctx context.Context, m string, done chan struct{}) error {
	ix.mem.mu.Lock()
	cur := ix.mem.get(m).cur
	ix.mem.mu.Unlock()
	if cur == "" {
		if err := ix.bootstrapMember(ctx, m, done); err != nil {
			return err
		}
	} else {
		ix.trustAt(ctx, m, cur)
	}
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) { ix.opt.Logf("index: %s, which visibility reads: %v", n, err) }),
	}
	opts = append(opts, ix.opt.FollowOptions...)
	return follow.New(ix.c, m, memberCPs{ix.memberCheckpoints()}, memberHandler{ix, done}, opts...).Run(ctx)
}

// trustAt records m's catalog.trust as of its checkpoint cur where none is
// recorded yet: a namespace the index follows, or a member, resumed from a
// checkpoint committed before catalog_trust was (migration 009). Best effort: one it can't read, a
// purged m's 410 among them, is left without one, and counts as no
// catalog once m is purged (fsTrust); later config entries record it.
func (ix *Index) trustAt(ctx context.Context, m, cur string) {
	if _, ok, err := ix.lastTrust(ctx, m); err != nil || ok {
		return
	}
	doc, err := ix.docAt(ctx, m, cur)
	if err != nil {
		ix.opt.Logf("index: the catalog.trust of %s at %s: %v", m, cur, err)
		return
	}
	c, _ := doc["catalog"].(map[string]any)
	trust, err := json.Marshal(c["trust"])
	if err != nil {
		return
	}
	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	// One recorded meanwhile, by an apply, is newer.
	if _, err := ix.db.ExecContext(ctx, `INSERT INTO catalog_trust (ns, trust) VALUES (?, ?) ON CONFLICT (ns) DO NOTHING`, m, string(trust)); err != nil {
		ix.opt.Logf("index: recording the catalog.trust of %s: %v", m, err)
	}
}

// errMemberStopped is a member's follower that was stopped (current).
var errMemberStopped = errors.New("the follower was stopped")

// bootstrapMember gives m its first checkpoint, its head, with the read
// mode and level of its document there, and purges idx:{m} (above).
func (ix *Index) bootstrapMember(ctx context.Context, m string, done chan struct{}) error {
	if ix.testMemberBootstrap != nil {
		ix.testMemberBootstrap(ctx, m)
	}
	h, err := ix.c.NSHead(ctx, m)
	if client.IsPurged(err) {
		ix.mem.mu.Lock()
		if ix.mem.current(m, done) {
			ix.mem.get(m).reach("", true)
		}
		ix.mem.mu.Unlock()
		return follow.ErrPurged
	}
	if err != nil {
		return lacksRead(m, fmt.Errorf("the head of %s: %w", m, err))
	}
	doc, err := ix.docAt(ctx, m, h.ID)
	if err != nil {
		return err
	}
	tags := []string{"idx:" + m}
	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	read, _ := doc["read"].(string)
	if _, err := tx.ExecContext(ctx, `INSERT INTO member_conf (ns, public, level) VALUES (?, ?, ?) ON CONFLICT (ns) DO UPDATE SET public = excluded.public, level = excluded.level`,
		m, read == "public", derived.InfoOf(doc).Level); err != nil {
		return err
	}
	if err := recordTrust(ctx, tx, m, doc); err != nil {
		return err
	}
	if err := ix.purgeTx(ctx, tx, tags); err != nil {
		return err
	}
	if err := ix.memberCheckpoints().Save(ctx, tx, ix.origin, m, h.ID); err != nil {
		return err
	}
	if err := ix.commitMember(tx, m, done); err != nil {
		return err
	}
	ix.purgeStored(ctx, m, tags, false)
	ix.purgeKept(m, tags)
	ix.mem.mu.Lock()
	if ix.mem.current(m, done) {
		ix.mem.get(m).reach(h.ID, false)
	}
	ix.mem.mu.Unlock()
	ix.checker.Observe(m, h.ID)
	ix.kickMembers()
	return nil
}

// commitMember commits tx, which saves m's checkpoint, unless the
// follower done ends was stopped (current): its checkpoint is forgotten
// (forgetMember). ix.wmu is held, which forgetMember takes too.
func (ix *Index) commitMember(tx *sql.Tx, m string, done chan struct{}) error {
	ix.mem.mu.Lock()
	ok := ix.mem.current(m, done)
	ix.mem.mu.Unlock()
	if !ok {
		return errMemberStopped
	}
	return tx.Commit()
}

// memberHandler applies a member's batches (above), for the follower done
// ends.
type memberHandler struct {
	ix   *Index
	done chan struct{}
}

// Apply implements follow.Handler: of b it applies only the checkpoint,
// purges and config entries (§A.1), in one transaction.
func (h memberHandler) Apply(ctx context.Context, b *follow.Batch) error {
	ix := h.ix
	if b.Partial() {
		return nil // never delivered (memberCPs); its last page completes it
	}
	co := b.Coalesce()
	purged := co.PurgedNS || slices.ContainsFunc(co.Changes, func(c follow.Change) bool { return c.Purged })
	config := slices.ContainsFunc(b.Units, func(u follow.Unit) bool { return u.Config != nil })
	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	narrowed, err := ix.narrowed(ctx, tx, "member_conf", b.NS, configDocs(b))
	if err != nil {
		return err
	}
	var tags []string
	if purged || narrowed {
		tags = []string{"idx:" + b.NS}
	}
	if err := ix.purgeTx(ctx, tx, tags); err != nil {
		return err
	}
	if err := ix.memberCheckpoints().Save(ctx, tx, b.Origin, b.NS, b.NewCheckpoint); err != nil {
		return err
	}
	if err := ix.commitMember(tx, b.NS, h.done); err != nil {
		return err
	}
	// As Apply: purged before the checkpoint is out.
	ix.purgeStored(ctx, b.NS, tags, co.PurgedNS)
	ix.purgeKept(b.NS, tags)
	ids := make([]string, 0, len(b.Units))
	for _, u := range b.Units {
		ids = append(ids, u.Entry.ID)
	}
	ix.mem.mu.Lock()
	if ix.mem.current(b.NS, h.done) {
		ix.mem.get(b.NS).reach(b.NewCheckpoint, co.PurgedNS, ids...)
	}
	ix.mem.mu.Unlock()
	// The checker reads the member's head again, toward which memberAt
	// waits.
	ix.checker.Observe(b.NS, b.NewCheckpoint)
	if config || co.PurgedNS {
		ix.kickMembers()
	}
	return nil
}

// runMembers runs the reconciler until ctx is done, then waits for every
// member's follower to end (Run).
func (ix *Index) runMembers(ctx context.Context) {
	ix.mem.mu.Lock()
	ix.mem.run = ctx
	ix.mem.mu.Unlock()
	// The first reconciliation starts the followers of the members the
	// committed checkpoints read.
	ix.kickMembers()
	for {
		select {
		case <-ctx.Done():
			// No follower starts once run is nil (startMember), so none
			// is added while this waits.
			ix.mem.mu.Lock()
			ix.mem.run = nil
			ix.mem.mu.Unlock()
			ix.mem.wg.Wait()
			return
		case <-ix.mem.kick:
			ix.reconcile(ctx)
		}
	}
}

// reconcile computes, for every namespace the index serves, at its
// committed checkpoint, the members its coverage and combined checkpoint
// read (a computation that fails keeps those read before, as well as
// those read now), starts their followers and stops every other.
func (ix *Index) reconcile(ctx context.Context) {
	ix.mem.mu.Lock()
	old := ix.mem.needs
	ix.mem.mu.Unlock()
	needs := map[string]map[string]bool{}
	for _, ns := range ix.refsNamespaces() {
		z, purged, err := ix.committed(ctx, ns)
		if err != nil || purged || z == "" {
			if err != nil && old[ns] != nil {
				needs[ns] = old[ns]
			}
			continue
		}
		s := &needSet{m: map[string]bool{}}
		if _, err := ix.checkpoint(context.WithValue(ctx, needsKey{}, s), ns, z); err != nil {
			if ctx.Err() != nil {
				return
			}
			for m := range old[ns] {
				s.m[m] = true
			}
		}
		needs[ns] = s.m
	}
	want := map[string]bool{}
	for _, s := range needs {
		for m := range s {
			if !ix.known(m) {
				want[m] = true
			}
		}
	}
	var stopped []string
	ix.mem.mu.Lock()
	ix.mem.needs = needs
	for m, mb := range ix.mem.m {
		if want[m] || mb.stop == nil && mb.cur == "" {
			continue
		}
		// Running, or holding a checkpoint (loadMembers) nothing follows
		// on from.
		if mb.stop != nil {
			mb.stop()
			mb.stop = nil
		}
		mb.reset()
		stopped = append(stopped, m)
	}
	for m := range want {
		ix.startMember(m)
	}
	ix.mem.mu.Unlock()
	sort.Strings(stopped)
	for _, m := range stopped {
		ix.opt.Logf("index: %s is no longer read by the coverage of a namespace the index serves; not following it", m)
		if err := ix.forgetMember(ctx, m); err != nil {
			ix.opt.Logf("index: purging idx:%s: %v", m, err)
		}
	}
}

// forgetMember purges idx:{m}, by the path a purge in m takes, once m's
// follower stopped: nothing purges it after. Its checkpoint, read mode
// and, unless m is purged, catalog.trust are forgotten with it, in the same transaction (reconcile forgot the
// checkpoint in memory already), unless a follower started again since,
// which bootstraps them afresh: a follower started later starts at the
// head, and a restart doesn't resume from them (§B.5 Behind).
func (ix *Index) forgetMember(ctx context.Context, m string) error {
	tags := []string{"idx:" + m}
	// Purged, as the follower applied or the grant checker reads it.
	ix.mem.mu.Lock()
	purged := ix.mem.get(m).purged
	ix.mem.mu.Unlock()
	if !purged {
		_, err := ix.checker.Config(ctx, m)
		purged = client.IsPurged(err)
	}
	ix.wmu.Lock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		ix.wmu.Unlock()
		return err
	}
	err = ix.purgeTx(ctx, tx, tags)
	ix.mem.mu.Lock()
	again := ix.mem.get(m).stop != nil
	ix.mem.mu.Unlock()
	if err == nil && !again {
		_, err = tx.ExecContext(ctx, `DELETE FROM member_checkpoints WHERE origin = ? AND ns = ?`, ix.origin, m)
	}
	if err == nil && !again {
		_, err = tx.ExecContext(ctx, `DELETE FROM member_conf WHERE ns = ?`, m)
	}
	if err == nil && !again && !purged {
		// Of a live m, forgotten too: what it trusts may change unseen
		// from now on. A purged m's stays, its last (fsTrust).
		_, err = tx.ExecContext(ctx, `DELETE FROM catalog_trust WHERE ns = ?`, m)
	}
	if err == nil {
		err = tx.Commit()
	}
	tx.Rollback()
	ix.wmu.Unlock()
	if err != nil {
		return err
	}
	ix.purgeStored(ctx, m, tags, false)
	ix.purgeKept(m, tags)
	return nil
}

// fsForget drops what fstate keeps of ns read at an ns_id, once a purge in
// ns has committed: the names live there, its catalog graphs and node
// documents, and its tombstoned nodes' last live documents, which a purge
// changes or removes. Namespace documents stay, which no resource purge
// changes, and so do checkpoints computed before (fs.cps), which only
// tell a reader's gs at an older at. It counts the purge (fsGeneration),
// so that what a request read of ns before the purge committed, and
// stores after this, isn't kept (fsPutSince).
func (ix *Index) fsForget(ns string) {
	st := &ix.fs
	pre := ns + "\x00"
	st.mu.Lock()
	defer st.mu.Unlock()
	st.gen++
	st.purged = append(st.purged, ns)
	if len(st.purged) > fsMaxPurges {
		st.purged = slices.Delete(st.purged, 0, len(st.purged)-fsMaxPurges)
	}
	for _, k := range st.live.Keys() {
		if strings.HasPrefix(k, pre) {
			st.live.Remove(k)
		}
	}
	for _, k := range st.deleted.Keys() {
		if strings.HasPrefix(k, pre) {
			st.deleted.Remove(k)
		}
	}
	for _, k := range st.cats.Keys() {
		// catalogAt's key: ns \0 id, then member \0 id for each member.
		parts := strings.Split(k, "\x00")
		for i := 0; i < len(parts); i += 2 {
			if parts[i] == ns {
				st.cats.Remove(k)
				break
			}
		}
	}
	delete(st.nodes, ns)
}
