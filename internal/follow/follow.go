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
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
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
	// bootstrap or a new branch): its units are synthetic, and the
	// consumer should treat it as the complete state as of NewCheckpoint
	// (dropping anything it holds for the namespace not listed, if it
	// holds anything).
	Snapshot bool
}

// Unit is one unit of processing (§10): a single namespace entry, or a
// batch entry whose sub-entries must be applied together.
type Unit struct {
	// Entry is the namespace entry. For a batch, Entry.Entries holds its
	// config entry (first, if any) and resource entries. For synthetic
	// units from a /heads snapshot, Entry has Resource, Kind ("head",
	// "tombstone" or "purge") and Target, and no ID; a namespace purged by
	// then has no listing, and gives one unit with only Kind "purge-ns"
	// and ID, its head, which is its purge-ns entry.
	Entry client.NSEntry
	// Synthetic marks a unit made from a /heads listing (or in place of
	// one).
	Synthetic bool
	// Config is the namespace document in force after this unit, set when
	// the unit changes the configuration (a config entry, or a batch with
	// one).
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

// State is a namespace's lifecycle state, reported via WithOnState.
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
// changes, and purged from purge-ns entries.
func WithOnState(f func(State)) Option { return func(o *options) { o.onState = f } }

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
// /heads listing).
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
		if isBranch {
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
	return n.deliverHeads(ctx, head.ID, nil)
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
	if err != nil {
		return err
	}
	genesis := v.(client.NSEntry)
	return n.deliverHeads(ctx, genesis.ID, &genesis)
}

func (n *nsFollower) deliverHeads(ctx context.Context, at string, genesis *client.NSEntry) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.Heads(ctx, n.ns, at) })
	if isPurged(err) {
		return n.deliverPurged(ctx)
	}
	if err != nil {
		return err
	}
	var units []Unit
	if genesis != nil {
		u := Unit{Entry: *genesis}
		if err := n.attachConfig(ctx, &u); err != nil {
			return err
		}
		units = append(units, u)
	}
	for _, it := range v.([]client.HeadItem) {
		e := client.NSEntry{Resource: it.Resource, Kind: it.Kind, Target: it.Target}
		units = append(units, Unit{Entry: e, Synthetic: true})
	}
	return n.apply(ctx, &Batch{Origin: n.origin, NS: n.ns, Units: units, From: n.cur, NewCheckpoint: at, Snapshot: true})
}

// deliverPurged stands in for the /heads listing of a purged namespace,
// which is 410 purged at any revision (§8.5): the namespace's log ends with
// its purge-ns entry, which is how a consumer learns of it otherwise (§10),
// and nothing is written after it, so the head is that entry. It is
// delivered as a synthetic purge-ns unit at the head, and Run ends with
// ErrPurged.
func (n *nsFollower) deliverPurged(ctx context.Context) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSHead(ctx, n.ns) })
	if err != nil {
		return err
	}
	head := v.(*client.NSHead).ID
	u := Unit{Entry: client.NSEntry{ID: head, Kind: "purge-ns"}, Synthetic: true}
	if err := n.apply(ctx, &Batch{Origin: n.origin, NS: n.ns, Units: []Unit{u}, From: n.cur, NewCheckpoint: head, Snapshot: true}); err != nil {
		return err
	}
	n.f.state(State{NS: n.ns, Purged: true})
	return ErrPurged
}

// isPurged reports the 410 of a purged namespace's URLs (§8.5).
func isPurged(err error) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == 410 && ae.Code == "purged"
}

// catchUp replays the immutable range from the checkpoint to the head,
// page by page (§7.1, §10 Catch up): each page is delivered, and the
// checkpoint advanced, before the next is fetched.
func (n *nsFollower) catchUp(ctx context.Context) error {
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSHead(ctx, n.ns) })
	if err != nil {
		return err
	}
	head := v.(*client.NSHead)
	for n.cur != head.ID {
		type page struct {
			entries []client.NSEntry
			next    string
		}
		v, err = n.f.retryValue(ctx, n.ns, func() (any, error) {
			es, next, err := n.f.c.NSLogPage(ctx, n.ns, head.ID, n.cur)
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
		if want := cmp.Or(p.next, head.ID); n.cur != want {
			return fmt.Errorf("follow: %s: caught up to %s, not %s", n.ns, n.cur, want)
		}
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
		if errors.Is(err, errStop) {
			return ErrPurged
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

var errStop = errors.New("follow: stop")

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
		if err := n.attachConfig(ctx, &u); err != nil {
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
		n.f.state(State{NS: n.ns, Purged: true})
		if n.f.opt.sse {
			return errStop
		}
		return ErrPurged
	}
	return nil
}

// attachConfig fetches the namespace document after a config change.
func (n *nsFollower) attachConfig(ctx context.Context, u *Unit) error {
	has := u.Entry.Kind == "config"
	if u.Entry.Kind == "batch" && len(u.Entry.Entries) > 0 && u.Entry.Entries[0].Kind == "config" {
		has = true
	}
	if !has || u.Entry.ID == "" {
		return nil
	}
	id := u.Entry.ID
	v, err := n.f.retryValue(ctx, n.ns, func() (any, error) { return n.f.c.NSDoc(ctx, n.ns, id) })
	if err != nil {
		return err
	}
	u.Config = v.(*client.NSDoc)
	return nil
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
	n.cur = b.NewCheckpoint
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
