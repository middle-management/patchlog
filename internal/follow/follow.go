// Package follow implements the namespace consumer loop of §10: catch up
// from a checkpoint, follow new entries by long-poll (default) or SSE,
// deliver them in units (one entry, or one batch entry as a whole), and let
// the handler advance its checkpoint in the same transaction as its derived
// data (§A.1).
//
// A consumer implements Handler. The follower calls Handler.Apply with a
// Batch of complete units and the checkpoint that processing them reaches;
// it moves on only after Apply returns nil. A failing Apply is retried with
// backoff, with the same Batch, so Apply must be idempotent (§10: "Processing
// must be idempotent"). Apply calls are serialised across all namespaces a
// follower follows, so handlers need no locking of their own.
//
// Checkpoints are (origin, ns, ns_id) (§G.2). The follower reads them through
// Checkpoint.Load when it starts following a namespace; the handler writes
// them, e.g. with SQLCheckpoints.Save inside its transaction or
// MemoryCheckpoints.Save.
package follow

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// Checkpoint loads the last fully processed ns_id of a namespace, "" if
// none (§10).
type Checkpoint interface {
	Load(ctx context.Context, origin, ns string) (nsID string, err error)
}

// Handler processes delivered entries.
type Handler interface {
	// Apply processes b and durably records b.NewCheckpoint for (b.Origin,
	// b.NS), ideally in one transaction with the derived data. It must be
	// idempotent: after a crash, or an error return, the same entries are
	// delivered again.
	Apply(ctx context.Context, b *Batch) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, b *Batch) error

// Apply calls f.
func (f HandlerFunc) Apply(ctx context.Context, b *Batch) error { return f(ctx, b) }

// Batch is what one Apply call processes: complete units of one namespace,
// in log order, and the checkpoint they reach.
type Batch struct {
	Origin string
	NS     string
	Units  []Unit
	// From is the checkpoint before these units ("" = none).
	From string
	// NewCheckpoint is the ns_id to record once the units are processed.
	NewCheckpoint string
	// Snapshot marks a batch built from a /heads listing (snapshot
	// bootstrap or a new branch), or in place of one for a namespace
	// purged by then: its units are synthetic, and the
	// consumer should treat it as the complete state as of NewCheckpoint
	// (dropping anything it holds for the namespace not listed, if it
	// holds anything).
	//
	// A listing longer than a page (§7.1 Paging) comes as several Snapshot
	// batches, one per page, all at the same NewCheckpoint: the first has
	// After "" and the last More "". Only the first replaces what the
	// consumer holds (Replaces); each later one adds to it. Until the
	// last, the snapshot isn't complete: NewCheckpoint is where it will
	// be, not one reached, so a consumer records it as progress (Partial;
	// SQLCheckpoints.SaveBatch does) rather than as its checkpoint, and
	// doesn't serve the namespace as of it yet. A follower that restarts
	// meanwhile resumes after the last page recorded, when its Checkpoint
	// is a Resumer, and from the first page otherwise.
	Snapshot bool
	// After is the /heads cursor this page of a snapshot starts after,
	// "" for the first page (and for every batch that isn't a snapshot).
	After string
	// More is the cursor of the page after this one, "" for the last page
	// of a snapshot (and for every batch that isn't one).
	More string
}

// Partial reports whether b is a page of a snapshot that further pages
// complete: b.NewCheckpoint isn't reached yet.
func (b *Batch) Partial() bool { return b.More != "" }

// Replaces reports whether b replaces what the consumer holds for the
// namespace: a snapshot, or its first page.
func (b *Batch) Replaces() bool { return b.Snapshot && b.After == "" }

// Unit is one unit of processing (§10): a single namespace entry, or a
// batch entry whose sub-entries must be applied together.
type Unit struct {
	// Entry is the namespace entry. For a batch, Entry.Entries holds its
	// config entry (first, if any) and resource entries. For synthetic
	// units from a /heads snapshot, Entry has Resource, Kind ("head",
	// "tombstone" or "purge"), Target and the row's Created, if any, and
	// no ID; a namespace purged by
	// then has no listing, and gives one unit with only Kind "purge-ns"
	// and ID, its head, which is its purge-ns entry. So does a sealed
	// namespace once it is purged, whose log is 410 too (§8.5), in place
	// of the entries it no longer serves.
	Entry client.NSEntry
	// Synthetic marks a unit made from a /heads listing (or in place of
	// one).
	Synthetic bool
	// Config is the namespace document in force after this unit, set when
	// the unit changes the configuration (a config entry, or a batch with
	// one). Where that document is sealed under an epoch whose key the
	// follower's client can't have, it is the newest document the client
	// can open instead, the one at the namespace's head (Config.ID names
	// it; attachConfig).
	Config *client.NSDoc
}

// Changes flattens the unit to its resource-level entries (a batch's
// sub-entries, or the entry itself for head/tombstone/purge/prune).
func (u Unit) Changes() []client.NSEntry {
	if u.Entry.Kind == "batch" {
		var out []client.NSEntry
		for _, e := range u.Entry.Entries {
			if e.IsResource() {
				out = append(out, e)
			}
		}
		return out
	}
	if u.Entry.IsResource() {
		return []client.NSEntry{u.Entry}
	}
	return nil
}

// State is a namespace's lifecycle state, reported via WithOnState. A
// purge reports Purged with Frozen, as only a frozen namespace is purged
// (§8.5); Successor comes from config changes only.
type State struct {
	NS        string
	Frozen    bool
	Successor string
	Purged    bool
}

// Follower follows a namespace (and optionally its branches).
type Follower struct {
	c    *client.Client
	ns   string
	cp   Checkpoint
	h    Handler
	opt  options
	aMu  sync.Mutex // serialises Apply
	mu   sync.Mutex
	seen map[string]bool // namespaces being followed
	wg   sync.WaitGroup
}

type options struct {
	sse        bool
	branches   bool
	snapshot   bool
	isBranch   bool
	maxUnits   int
	minBackoff time.Duration
	maxBackoff time.Duration
	onError    func(ns string, err error)
	onState    func(State)
	onCatchUp  func(ns, head string, done bool)
}

// Option configures a Follower.
type Option func(*options)

// WithSSE follows by server-sent events instead of long-poll.
func WithSSE() Option { return func(o *options) { o.sse = true } }

// WithBranches follows branches as they are discovered from branch entries
// (and, at start, from GET /ns/{ns}/branches), recursively. A new branch is
// bootstrapped from its /heads listing at its first ns_id, then followed
// through its own log. Branches the client may not read are skipped.
func WithBranches() Option { return func(o *options) { o.branches = true } }

// WithSnapshot makes a consumer with an empty checkpoint start from the
// /heads listing at the current head instead of replaying from "" (§10).
// A purged namespace has none (410 purged): the consumer gets its purge-ns
// entry instead, and Run ends with ErrPurged.
func WithSnapshot() Option { return func(o *options) { o.snapshot = true } }

// AsBranch makes a consumer that follows a branch directly (not through
// its base, WithBranches) start, with an empty checkpoint, from the
// branch's first entry together with its /heads listing there, which
// includes what it reads through, then follow its own log (§10 Branches:
// contents). A release preview follows branches this way (§B.5).
func AsBranch() Option { return func(o *options) { o.isBranch = true } }

// WithMaxUnits sets how many units one Apply may receive. The default 1
// delivers each unit separately; 0 delivers every unit of a fetched page
// together, for handlers that coalesce (see Coalesce).
func WithMaxUnits(n int) Option { return func(o *options) { o.maxUnits = n } }

// WithBackoff sets the retry backoff range (default 200ms to 30s). A 429's
// Retry-After is always honoured.
func WithBackoff(min, max time.Duration) Option {
	return func(o *options) { o.minBackoff, o.maxBackoff = min, max }
}

// WithOnError receives errors that are retried or that end the following of
// a branch (e.g. not readable).
func WithOnError(f func(ns string, err error)) Option { return func(o *options) { o.onError = f } }

// WithOnState receives lifecycle changes: frozen/successor from config
// changes, and purged from purge-ns entries, or from the 410 purged that
// stands in for them (§8.5).
func WithOnState(f func(State)) Option { return func(o *options) { o.onState = f } }

// WithOnCatchUp receives the catch-up's progress (§10 Catch up): done
// false once the head to catch up to has been read (the core serves the
// namespace), done true once the checkpoint has reached that head, every
// page of the range before it delivered. A consumer that replays a long
// log a page at a time has a checkpoint after the first page, long before
// it reflects the namespace as of its start.
func WithOnCatchUp(f func(ns, head string, done bool)) Option {
	return func(o *options) { o.onCatchUp = f }
}

// New returns a follower of namespace ns.
func New(c *client.Client, ns string, cp Checkpoint, h Handler, opts ...Option) *Follower {
	o := options{maxUnits: 1, minBackoff: 200 * time.Millisecond, maxBackoff: 30 * time.Second}
	for _, f := range opts {
		f(&o)
	}
	return &Follower{c: c, ns: ns, cp: cp, h: h, opt: o, seen: map[string]bool{}}
}

// ErrPurged is returned by Run when the followed namespace was purged
// (after its purge-ns unit was applied, from the log or in place of a
// /heads listing or of a sealed namespace's log, or at once when the
// checkpoint is that unit already).
var ErrPurged = errors.New("follow: namespace purged")

// Run follows until ctx is done (returning ctx.Err()), the namespace is
// purged (ErrPurged), or a permanent error occurs for the root namespace
// (e.g. its checkpoint is not in its chain, or access is denied). Branch
// followers end on their own permanent errors, reported via WithOnError.
func (f *Follower) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	origin, err := f.retryValue(ctx, f.ns, func() (any, error) { return f.c.Origin(ctx) })
	if err != nil {
		return err
	}
	ns := &nsFollower{f: f, origin: origin.(string), ns: f.ns}
	f.mu.Lock()
	f.seen[f.ns] = true
	f.mu.Unlock()
	err = ns.run(ctx)
	cancel()
	f.wg.Wait()
	return err
}

// nsFollower follows one namespace.
type nsFollower struct {
	f      *Follower
	origin string
	ns     string
	cur    string // the checkpoint reached
	// branch bootstrap: the base's branch entry (nil for the root or a
	// branch found through /branches).
	branch *client.NSEntry
	// purging is set while deliverPurged reads the log up to the purge-ns
	// entry: a 410 meanwhile ends it there.
	purging bool
}

func (n *nsFollower) run(ctx context.Context) error {
	f := n.f
	cp, err := f.retryValue(ctx, n.ns, func() (any, error) { return f.cp.Load(ctx, n.origin, n.ns) })
	if err != nil {
		return err
	}
	n.cur = cp.(string)
	if f.opt.branches {
		if err := n.discoverBranches(ctx); err != nil {
			return err
		}
	}
	if n.cur == "" {
		isBranch := n.branch != nil
		if !isBranch && (n.ns != f.ns || f.opt.isBranch) {
			isBranch = true
		}
		resumed, err := n.resumeSnapshot(ctx, isBranch || f.opt.snapshot)
		if err != nil {
			return err
		}
		if resumed {
			// Delivered the rest of a snapshot a restart interrupted.
		} else if isBranch {
			if err := n.bootstrapBranch(ctx); err != nil {
				return err
			}
		} else if f.opt.snapshot {
			if err := n.bootstrapSnapshot(ctx); err != nil {
				return err
			}
		}
	}
	if err := n.catchUp(ctx); err != nil {
		return err
	}
	if f.opt.sse {
		return n.followSSE(ctx)
	}
	return n.followLongPoll(ctx)
}

// discoverBranches starts followers for the namespace's current branches.
func (n *nsFollower) discoverBranches(ctx context.Context) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.Branches(ctx, n.ns) })
	if client.IsPurged(err) {
		// A purged namespace's /branches is 410 (§7.4, §8.5); it had no
		// live branches left to purge it (§2.1), and its log still ends
		// in the purge-ns entry its follower delivers.
		return nil
	}
	if err != nil {
		return err
	}
	for _, b := range v.([]client.Branch) {
		if b.Name == "" || b.Purged {
			continue
		}
		n.startBranch(ctx, b.Name, nil)
	}
	return nil
}

func (n *nsFollower) startBranch(ctx context.Context, name string, entry *client.NSEntry) {
	f := n.f
	f.mu.Lock()
	if f.seen[name] {
		f.mu.Unlock()
		return
	}
	f.seen[name] = true
	f.mu.Unlock()
	bf := &nsFollower{f: f, origin: n.origin, ns: name, branch: entry}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		err := bf.run(ctx)
		if err != nil && !errors.Is(err, ErrPurged) && ctx.Err() == nil {
			f.report(name, fmt.Errorf("follow: stopped following branch %s: %w", name, err))
		}
	}()
}

// bootstrapSnapshot delivers the /heads listing at the current head.
func (n *nsFollower) bootstrapSnapshot(ctx context.Context) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSHead(ctx, n.ns) })
	if err != nil {
		return err
	}
	head := v.(*client.NSHead)
	return n.deliverHeads(ctx, head.ID, "", nil)
}

// resumeSnapshot delivers the rest of a snapshot bootstrap that a restart
// interrupted after some of its pages (Batch.Partial), if the Checkpoint
// recorded one (Resumer) and a bootstrap is still due. A listing the
// origin no longer serves at that position (a 4xx other than a purge) is
// left, and the bootstrap starts again from its first page.
func (n *nsFollower) resumeSnapshot(ctx context.Context, due bool) (bool, error) {
	rs, ok := n.f.cp.(Resumer)
	if !ok || !due {
		return false, nil
	}
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) {
		at, after, err := rs.LoadBootstrap(ctx, n.origin, n.ns)
		return [2]string{at, after}, err
	})
	if err != nil {
		return false, err
	}
	p := v.([2]string)
	if p[0] == "" || p[1] == "" {
		return false, nil
	}
	err = n.deliverHeads(ctx, p[0], p[1], nil)
	if ae, ok := client.AsAPIError(err); ok && n.cur == "" && ae.Status >= 400 && ae.Status < 500 && !client.IsPurged(err) {
		n.f.report(n.ns, fmt.Errorf("follow: resuming the snapshot at %s: %w; starting it again", p[0], err))
		return false, nil
	}
	return err == nil, err
}

// bootstrapBranch delivers a new branch's first entry (its config genesis)
// together with its /heads listing at that entry (§10 Branches: contents).
func (n *nsFollower) bootstrapBranch(ctx context.Context) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) {
		h, err := n.f.c.NSHead(ctx, n.ns)
		if err != nil {
			return nil, err
		}
		first := ""
		if n.branch != nil && n.branch.Target != "" {
			if first, err = client.FirstBranchEntry(n.branch.Target); err != nil {
				return nil, err
			}
		}
		// The first page holds the first entry (§7.1 Paging).
		entries, _, err := n.f.c.NSLogPage(ctx, n.ns, h.ID, "")
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 || (first != "" && entries[0].ID != first) || entries[0].Kind != "config" {
			return nil, fmt.Errorf("follow: branch %s does not start with its config genesis", n.ns)
		}
		return entries[0], nil
	})
	if client.IsPurged(err) {
		// A sealed branch's log, once it is purged (§8.5).
		return n.deliverPurged(ctx, err)
	}
	if err != nil {
		return err
	}
	genesis := v.(client.NSEntry)
	return n.deliverHeads(ctx, genesis.ID, "", &genesis)
}

// deliverHeads delivers the /heads listing at at, from the page after
// after ("" for the first), each page as a Snapshot batch of its own once
// the one before it is applied (Batch.Partial), so a listing of any length
// costs a page of memory and a page per Apply. genesis, a new branch's
// config genesis, goes first, in the first page's batch.
func (n *nsFollower) deliverHeads(ctx context.Context, at, after string, genesis *client.NSEntry) error {
	type page struct {
		items []client.HeadItem
		next  string
	}
	for {
		v, err := n.f.retryValue(ctx, n.ns, func() (any, error) {
			items, next, err := n.f.c.HeadsPage(ctx, n.ns, at, after)
			return page{items, next}, err
		})
		if client.IsPurged(err) {
			return n.deliverPurged(ctx, err)
		}
		if err != nil {
			return err
		}
		p := v.(page)
		var units []Unit
		if genesis != nil {
			u := Unit{Entry: *genesis}
			if err := n.attachConfig(ctx, &u); client.IsPurged(err) {
				return n.deliverPurged(ctx, err)
			} else if err != nil {
				return err
			}
			units = append(units, u)
			genesis = nil
		}
		for _, it := range p.items {
			e := client.NSEntry{Resource: it.Resource, Kind: it.Kind, Target: it.Target, Created: it.Created}
			units = append(units, Unit{Entry: e, Synthetic: true})
		}
		if p.next == after && after != "" {
			return fmt.Errorf("follow: %s: /heads at %s doesn't move past %q", n.ns, at, after)
		}
		b := &Batch{Origin: n.origin, NS: n.ns, Units: units, From: n.cur, NewCheckpoint: at, Snapshot: true, After: after, More: p.next}
		if err := n.apply(ctx, b); err != nil {
			return err
		}
		if p.next == "" {
			return nil
		}
		after = p.next
	}
}

// deliverPurged stands in for what a purged namespace no longer serves: its
// /heads listing, 410 purged at any revision, and, in a sealed namespace,
// its log, long-polls, events and documents too (§8.5). The namespace's
// log ends with its purge-ns entry, which is how a consumer learns of it
// otherwise (§10), and nothing is written after it, so the head is that
// entry. The 410 names it as head; from a core that doesn't, it is read
// from /ns/{ns}.
//
// A 410 can come after a checkpoint short of that head: the purge came
// after the head the follower last read (purgedAtHead's check of a
// checkpoint at the head races it), or after the entries being delivered
// were read. The entries in between, the freeze every purge follows (§8.5,
// not_frozen) among them, are delivered from the log first, as catch-up
// would, so their units are applied and the states they change reported,
// the purge-ns entry last (deliver). Only where the log is 410 too (a
// sealed namespace), or in place of a bootstrap's listing, is the purge-ns
// unit synthetic (purgedAt).
func (n *nsFollower) deliverPurged(ctx context.Context, gone error) error {
	head, err := n.purgeHead(ctx, gone)
	if err != nil {
		return err
	}
	if head != n.cur && n.cur != "" && !n.purging {
		n.purging = true
		err := n.pageTo(ctx, head)
		n.purging = false
		if err != nil && !client.IsPurged(err) {
			// ErrPurged once the purge-ns entry is delivered.
			return err
		}
		// The log is 410 too, from where the checkpoint got to, or it
		// reached the head without a purge-ns entry to report.
	}
	return n.purgedAt(ctx, head)
}

// logPurged is deliverPurged for a 410 of the log range itself, which
// leaves nothing to read up to the purge-ns entry (§8.5).
func (n *nsFollower) logPurged(ctx context.Context, gone error) error {
	head, err := n.purgeHead(ctx, gone)
	if err != nil {
		return err
	}
	return n.purgedAt(ctx, head)
}

// purgeHead is the head of a purged namespace, its purge-ns entry: the one
// gone, its 410, names, else /ns/{ns}'s.
func (n *nsFollower) purgeHead(ctx context.Context, gone error) (string, error) {
	if ae, ok := client.AsAPIError(gone); ok && ae.Head() != "" {
		return ae.Head(), nil
	}
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSHead(ctx, n.ns) })
	if err != nil {
		return "", err
	}
	return v.(*client.NSHead).ID, nil
}

// purgedAt delivers a synthetic purge-ns unit at head, the purge-ns entry,
// unless the checkpoint is there already, reports the state, and ends with
// ErrPurged. The batch is a Snapshot only in place of a bootstrap's
// listing: after a checkpoint it follows what was delivered, as the
// purge-ns entry would, so a consumer marks what it holds as purged rather
// than dropping it.
func (n *nsFollower) purgedAt(ctx context.Context, head string) error {
	if head != n.cur {
		u := Unit{Entry: client.NSEntry{ID: head, Kind: "purge-ns"}, Synthetic: true}
		if err := n.apply(ctx, &Batch{Origin: n.origin, NS: n.ns, Units: []Unit{u}, From: n.cur, NewCheckpoint: head, Snapshot: n.cur == ""}); err != nil {
			return err
		}
	}
	n.f.state(purgedState(n.ns))
	return ErrPurged
}

// purgedState is the state a purge reports: frozen too, as only a frozen
// namespace is purged (§8.5, 409 not_frozen), whether or not the freeze's
// config entry could be delivered (a sealed namespace's log is 410 once
// purged).
func purgedState(ns string) State { return State{NS: ns, Frozen: true, Purged: true} }

// catchUp replays the immutable range from the checkpoint to the head,
// page by page (§7.1, §10 Catch up): each page is delivered, and the
// checkpoint advanced, before the next is fetched.
func (n *nsFollower) catchUp(ctx context.Context) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSHead(ctx, n.ns) })
	if err != nil {
		return err
	}
	head := v.(*client.NSHead)
	n.f.catchUp(n.ns, head.ID, false)
	if n.cur != "" && n.cur == head.ID {
		if err := n.purgedAtHead(ctx, head.ID); err != nil {
			return err
		}
	}
	if err := n.pageTo(ctx, head.ID); client.IsPurged(err) {
		// A sealed namespace's log, once it is purged: the 410's
		// head stands in for its purge-ns entry (§8.5, §10).
		return n.logPurged(ctx, err)
	} else if err != nil {
		return err
	}
	n.f.catchUp(n.ns, head.ID, true)
	return nil
}

// pageTo delivers the log from the checkpoint to head, a page at a time,
// each delivered, and the checkpoint advanced, before the next is fetched.
// A 410 of the range is returned as it is.
func (n *nsFollower) pageTo(ctx context.Context, head string) error {
	for n.cur != head {
		type page struct {
			entries []client.NSEntry
			next    string
		}
		v, err := n.f.retryValue(ctx, n.ns, func() (any, error) {
			es, next, err := n.f.c.NSLogPage(ctx, n.ns, head, n.cur)
			return page{es, next}, err
		})
		if err != nil {
			return err
		}
		p := v.(page)
		if err := n.deliver(ctx, p.entries); err != nil {
			return err
		}
		// deliver moved the checkpoint to the page's last entry: the next
		// page's since (X-Log-Next), or the head.
		if want := cmp.Or(p.next, head); n.cur != want {
			return fmt.Errorf("follow: %s: caught up to %s, not %s", n.ns, n.cur, want)
		}
	}
	return nil
}

// lastName sorts after every resource name (§3.6): a /heads page after it
// is empty.
var lastName = strings.Repeat("z", 128)

// purgedAtHead checks, for a checkpoint at the head, whether the namespace
// is purged: whether the checkpoint is the purge-ns entry where an earlier
// run stopped (ErrPurged). Nothing follows that entry, so a stream from it
// ends at once and a long-poll from it times out, at every reconnect
// (§7.3, §7.7). /heads is 410 purged at any revision of a purged namespace
// (§8.5), and a page of it after the last possible name is empty
// otherwise, which costs a live namespace's follower one small request
// when it starts. Once purged, it ends with ErrPurged (deliverPurged
// delivers nothing at the head). A purge since head was read, after a
// freeze, is 410 here too, naming a later head: deliverPurged then
// delivers the log up to it first. Any other error is left to following.
func (n *nsFollower) purgedAtHead(ctx context.Context, head string) error {
	_, err := n.f.retryValue(ctx, n.ns, func() (any, error) {
		_, _, err := n.f.c.HeadsPage(ctx, n.ns, head, lastName)
		return nil, err
	})
	switch {
	case client.IsPurged(err):
		return n.deliverPurged(ctx, err)
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		n.f.report(n.ns, fmt.Errorf("follow: checking for a purge at %s: %w", head, err))
	}
	return nil
}

func (n *nsFollower) followLongPoll(ctx context.Context) error {
	cursor := ""
	backoff := n.f.newBackoff()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := n.f.c.LongPoll(ctx, n.ns, n.cur, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if client.IsPurged(err) {
				// Purged since: a sealed namespace's long-poll is 410
				// rather than its purge-ns entry (§8.5).
				return n.deliverPurged(ctx, err)
			}
			if cursor != "" && client.IsBadInput(err) {
				// A cursor too far behind the server's (a long pause, a
				// clock change) is 400: poll again without it (§7.7).
				// Without a cursor, a 400 is the follower's to report.
				cursor = ""
				continue
			}
			if !client.Retryable(err) {
				return err
			}
			n.f.report(n.ns, err)
			if err := backoff.wait(ctx, err); err != nil {
				return err
			}
			continue
		}
		backoff.reset()
		cursor = res.Cursor
		if res.Timeout {
			continue
		}
		if err := n.deliver(ctx, res.Entries); err != nil {
			return err
		}
	}
}

func (n *nsFollower) followSSE(ctx context.Context) error {
	backoff := n.f.newBackoff()
	for {
		err := n.f.c.NSEvents(ctx, n.ns, n.cur, func(e client.NSEntry) error {
			backoff.reset()
			return n.deliver(ctx, []client.NSEntry{e})
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrPurged) {
			return ErrPurged
		}
		if client.IsPurged(err) {
			// A sealed namespace's events are 410 once it is purged,
			// and its stream ends without the purge-ns entry (§8.5).
			return n.deliverPurged(ctx, err)
		}
		if err != nil {
			var ae *client.APIError
			if errors.As(err, &ae) && !client.Retryable(err) {
				return err
			}
			n.f.report(n.ns, err)
		}
		// The stream ended or failed: reconnect from the checkpoint.
		if err := backoff.wait(ctx, err); err != nil {
			return err
		}
	}
}

// deliver splits entries into units and applies them in groups.
func (n *nsFollower) deliver(ctx context.Context, entries []client.NSEntry) error {
	max := n.f.opt.maxUnits
	var group []Unit
	flush := func() error {
		if len(group) == 0 {
			return nil
		}
		last := group[len(group)-1].Entry.ID
		b := &Batch{Origin: n.origin, NS: n.ns, Units: group, From: n.cur, NewCheckpoint: last}
		group = nil
		return n.apply(ctx, b)
	}
	purged := false
	for _, e := range entries {
		if e.Prev != n.cur && len(group) == 0 || len(group) > 0 && e.Prev != group[len(group)-1].Entry.ID {
			return fmt.Errorf("follow: %s: entry %s does not follow %s (prev %s)", n.ns, e.ID, n.cur, e.Prev)
		}
		u := Unit{Entry: e}
		if err := n.attachConfig(ctx, &u); client.IsPurged(err) {
			// A sealed namespace purged since the entries were read: its
			// documents are 410 too. What came before is delivered, and
			// the purge stands in for the rest (§8.5).
			if err := flush(); err != nil {
				return err
			}
			return n.deliverPurged(ctx, err)
		} else if err != nil {
			return err
		}
		group = append(group, u)
		if e.Kind == "purge-ns" {
			purged = true
		}
		if max > 0 && len(group) >= max {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if purged {
		n.f.state(purgedState(n.ns))
		return ErrPurged
	}
	return nil
}

// attachConfig fetches the namespace document after a config change.
//
// A document sealed under an epoch whose key the client can't have, as it
// is configured (LacksKey: the genesis document of a namespace rotated
// since, read by a service whose grant gets only the current epoch, say,
// §E.2.3), would stop the follower there for good. The newest document it
// can open, the one in force at the namespace's head, stands in for it
// (Unit.Config), so the follower carries on and what it can't open is
// served by name only (§E.2.6). Only when that can't be opened either is
// the failure returned.
func (n *nsFollower) attachConfig(ctx context.Context, u *Unit) error {
	has := u.Entry.Kind == "config"
	if u.Entry.Kind == "batch" && len(u.Entry.Entries) > 0 && u.Entry.Entries[0].Kind == "config" {
		has = true
	}
	if !has || u.Entry.ID == "" {
		return nil
	}
	doc, lacking, err := n.nsDoc(ctx, u.Entry.ID)
	if err != nil {
		return err
	}
	if lacking != nil {
		v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSHead(ctx, n.ns) })
		if err != nil {
			return err
		}
		head := v.(*client.NSHead).ID
		if doc, _, err = n.nsDoc(ctx, head); err != nil {
			return err
		}
		if doc == nil {
			return lacking
		}
		n.f.report(n.ns, fmt.Errorf("follow: the namespace document at %s stands in for the one at %s: %w", head, u.Entry.ID, lacking))
	}
	u.Config = doc
	return nil
}

// nsDoc fetches the namespace document at id, retrying what may mend.
// lacking, with a nil doc, is a failure that won't: the document is
// sealed under an epoch whose key the client can't have (LacksKey).
func (n *nsFollower) nsDoc(ctx context.Context, id string) (doc *client.NSDoc, lacking, err error) {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) {
		d, err := n.f.c.NSDoc(ctx, n.ns, id)
		if LacksKey(ctx, err) {
			lacking = err
			return (*client.NSDoc)(nil), nil
		}
		return d, err
	})
	if err != nil {
		return nil, nil, err
	}
	if lacking != nil {
		return nil, lacking, nil
	}
	return v.(*client.NSDoc), nil, nil
}

// LacksKey reports whether err, from opening sealed content, leaves the
// client lacking the key for good, as its grant and keys are configured
// (§A.4, §E.2.6): no key for the epoch (ErrNoKeys), none it can unwrap
// (seal.ErrDecrypt) or will take (ErrUntrustedKey, §E.3.2), or /keys
// answered a 4xx other than 429. Any other failure, the document's own
// GET's among them, is not; nor is any once ctx is done.
func LacksKey(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if ae, ok := client.AsAPIError(err); ok {
		return strings.HasSuffix(ae.Path, "/keys") && ae.Status >= 400 && ae.Status < 500 && ae.Status != 429
	}
	return errors.Is(err, client.ErrNoKeys) || errors.Is(err, seal.ErrDecrypt) || errors.Is(err, client.ErrUntrustedKey)
}

// apply calls the handler until it succeeds, then advances and reacts to
// branch and config entries.
func (n *nsFollower) apply(ctx context.Context, b *Batch) error {
	f := n.f
	backoff := f.newBackoff()
	for {
		f.aMu.Lock()
		err := f.h.Apply(ctx, b)
		f.aMu.Unlock()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.report(n.ns, fmt.Errorf("follow: handler: %w", err))
		if err := backoff.wait(ctx, err); err != nil {
			return err
		}
	}
	if !b.Partial() {
		n.cur = b.NewCheckpoint
	}
	observeApplied(b)
	for _, u := range b.Units {
		if u.Config != nil {
			st := State{NS: n.ns}
			st.Frozen, _ = u.Config.Value["frozen"].(bool)
			st.Successor, _ = u.Config.Value["successor"].(string)
			f.state(st)
		}
		if f.opt.branches && u.Entry.Kind == "branch" && u.Entry.Remote == nil && u.Entry.Name != "" {
			e := u.Entry
			n.startBranch(ctx, e.Name, &e)
		}
	}
	return nil
}

func (f *Follower) report(ns string, err error) {
	if f.opt.onError != nil {
		f.opt.onError(ns, err)
	}
}

func (f *Follower) catchUp(ns, head string, done bool) {
	if f.opt.onCatchUp != nil {
		f.opt.onCatchUp(ns, head, done)
	}
}

func (f *Follower) state(s State) {
	if f.opt.onState != nil {
		f.opt.onState(s)
	}
}

// retryValue calls fn until it succeeds or fails permanently.
func (f *Follower) retryValue(ctx context.Context, ns string, fn func() (any, error)) (any, error) {
	b := f.newBackoff()
	for {
		v, err := fn()
		if err == nil {
			return v, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !client.Retryable(err) {
			return nil, err
		}
		f.report(ns, err)
		if err := b.wait(ctx, err); err != nil {
			return nil, err
		}
	}
}

// backoff is exponential with full jitter; Retry-After overrides it.
type backoff struct {
	min, max, cur time.Duration
}

func (f *Follower) newBackoff() *backoff {
	return &backoff{min: f.opt.minBackoff, max: f.opt.maxBackoff, cur: f.opt.minBackoff}
}

func (b *backoff) reset() { b.cur = b.min }

func (b *backoff) wait(ctx context.Context, cause error) error {
	d := b.cur/2 + time.Duration(rand.Int64N(int64(b.cur/2)+1))
	if ae, ok := client.AsAPIError(cause); ok && ae.RetryAfter > 0 {
		d = ae.RetryAfter
	}
	b.cur *= 2
	if b.cur > b.max {
		b.cur = b.max
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
