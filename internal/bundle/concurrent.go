package bundle

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

// Concurrent batches (§G.4.4 Order). A backfill under an allowance submits
// up to ImportOptions.Concurrency batches at once, in dependency order
// all the same: a namespace's batches start once every batch of the
// namespaces it depends on has committed, and within a namespace a batch
// waits for any batch in flight that it goes on with (a chain cut between
// them) or whose documents it pins (orderItems). Paced batches, without
// an allowance, go one at a time: the pacing is what bounds them.
//
// Concurrent batches aren't paced after each submit (pace): each request
// waits at the namespace's gate before it is sent, until the allowance's
// bucket has refilled what the requests before it drew, and a chain cut
// between batches waits on its resource's bucket too, which the
// allowance doesn't replace (§6.6).
//
// The importer's state is guarded by one lock, im.mu, held while a batch
// is planned, checked and reported, and released only around requests
// and waits (io), so batches overlap only on the wire and in the server.

// defaultConcurrency is how many batches an import under an allowance
// submits at once by default.
const defaultConcurrency = 4

type flight struct {
	n    *node
	b    *batch
	done bool
}

type runner struct {
	im      *importer
	cond    *sync.Cond
	flights []*flight
	err     error // the first error of a batch, which stops the rest
}

// newRunner starts running batches; the caller holds im.mu from then on
// until stop.
func (im *importer) newRunner() *runner {
	im.mu.Lock()
	im.concurrent = true
	im.run = &runner{im: im, cond: sync.NewCond(&im.mu)}
	return im.run
}

// stop waits for the batches in flight and releases im.mu. It returns the
// first error of a batch.
func (r *runner) stop() error {
	for r.inFlight(func(*flight) bool { return true }) {
		r.cond.Wait()
	}
	r.im.concurrent, r.im.run = false, nil
	r.im.mu.Unlock()
	return r.err
}

func (r *runner) inFlight(match func(*flight) bool) bool {
	live := r.flights[:0]
	found := false
	for _, f := range r.flights {
		if !f.done {
			live = append(live, f)
			found = found || match(f)
		}
	}
	r.flights = live
	return found
}

// waitFor waits until no batch in flight matches; it returns a batch's
// error instead, once there is one.
func (r *runner) waitFor(match func(*flight) bool) error {
	for r.err == nil && r.inFlight(match) {
		r.cond.Wait()
	}
	return r.err
}

// slot waits until fewer than max batches are in flight; it returns a
// batch's error instead, once there is one.
func (r *runner) slot(max int) error {
	for r.err == nil {
		count := 0
		r.inFlight(func(*flight) bool { count++; return false })
		if count < max {
			break
		}
		r.cond.Wait()
	}
	return r.err
}

// start runs a batch's job in its own goroutine, under im.mu, once fewer
// than max batches are in flight.
func (r *runner) start(n *node, b *batch, max int, job func() error) error {
	if err := r.slot(max); err != nil {
		return err
	}
	f := &flight{n: n, b: b}
	r.flights = append(r.flights, f)
	go func() {
		r.im.mu.Lock()
		defer r.im.mu.Unlock()
		if r.err == nil {
			// Not once another batch has failed: the import stops there.
			if err := job(); err != nil && r.err == nil {
				r.err = err
			}
		}
		f.done = true
		r.cond.Broadcast()
	}()
	return nil
}

// io runs f, a request to the target or a wait, without im.mu while
// batches run concurrently.
func (im *importer) io(f func()) {
	if im.concurrent {
		im.mu.Unlock()
		defer im.mu.Lock()
	}
	f()
}

// keysOf are the source documents of a batch's items.
func keysOf(b *batch) map[string]bool {
	if b.keys == nil {
		b.keys = map[string]bool{}
		for _, p := range b.parts {
			b.keys[p.it.d.key] = true
		}
	}
	return b.keys
}

// after reports whether batch b, of the same namespace as a batch in
// flight, must wait for it: it goes on with a chain that one cut, or pins
// one of its documents (orderItems). A snapshot document's target pins
// none of its namespace's snapshot documents: those references point
// upstream once rewritten, or at revisions this import doesn't bring.
func (im *importer) after(b, inFlight *batch) bool {
	if p := b.parts[0]; p.from > 0 && inFlight.parts[len(inFlight.parts)-1].it == p.it {
		return true
	}
	keys := keysOf(inFlight)
	for _, p := range b.parts {
		target := !p.it.upstream && p.it.d.info.History == Snapshot
		for k := range p.it.d.pinKeys {
			if !keys[k] || k == p.it.d.key {
				continue
			}
			if t := im.docs[k]; target && t != nil && t.info.History == Snapshot {
				continue
			}
			return true
		}
	}
	return false
}

// gate paces the requests of a namespace's concurrent batches by the
// allowance's bucket (§6.6): its rate and burst. The server admits a
// request while the bucket holds a token, and takes its tokens off when it
// handles it, which for a large batch is well after it was sent; requests
// sent at once can be handled in any order. So the gate takes the bucket
// to hold what the requests answered so far left, each drawn when it was
// answered (the server drew no later, so the bucket holds at least that),
// starting from a single token when the gate was made, as pace takes it
// to hold none to spare; and those in flight to be drawn at any moment.
// A request is sent once the bucket holds a token more than all those in
// flight draw: however they land around it, it is admitted. A namespace
// has only as many batches in flight as the burst holds the draws of
// (gateFor), so the bucket always fills to that. A chain cut between
// batches draws on its resource's own bucket too, at ratePerResource,
// which is paced as pace does, holding none to spare.
type gate struct {
	rate, burst, resource float64
	// level is what the requests answered so far left in the bucket, and
	// draws those in flight; cut are the resources of chains the node's
	// batches cut, whose own buckets the gate keeps, and doneRes what
	// answered requests drew from them.
	level   bucketLevel
	cut     map[string]bool
	doneRes map[string]*bucketDebt
	draws   []*gateDraw
}

// bucketLevel is a token bucket's level, tokens at last.
type bucketLevel struct {
	tokens float64
	last   time.Time
}

// at is the level at t, refilled at rate up to burst since last.
func (b bucketLevel) at(t time.Time, rate, burst float64) float64 {
	if !t.After(b.last) {
		return b.tokens
	}
	return min(burst, b.tokens+t.Sub(b.last).Seconds()*rate)
}

// wait is how long from now until the bucket holds a token more than the
// requests in flight draw.
func (g *gate) wait(now time.Time) time.Duration {
	need := 1.0
	for _, d := range g.draws {
		need += float64(d.tokens)
	}
	// More than the burst can't be: gateFor has fewer batches in flight.
	need = min(need, g.burst)
	have := g.level.at(now, g.rate, g.burst)
	if have >= need {
		return 0
	}
	return time.Duration((need - have) / g.rate * float64(time.Second))
}

type gateDraw struct {
	at        time.Time // when it was admitted
	tokens    int
	resources []string // those of g.cut it drew a token from
}

// bucketDebt is what a bucket that holds none to spare at the first draw
// owes after draws up to last (owedOf).
type bucketDebt struct {
	owed float64
	last time.Time
}

// add draws tokens at at, at most refilled at rate since the last draw.
func (b *bucketDebt) add(at time.Time, tokens int, rate float64) {
	if !b.last.IsZero() {
		b.owed = max(0, b.owed-at.Sub(b.last).Seconds()*rate)
	}
	b.owed += float64(tokens)
	if at.After(b.last) {
		b.last = at
	}
}

// wait is how long from now the bucket takes to refill what it owes.
func (b bucketDebt) wait(now time.Time, rate float64) time.Duration {
	return time.Duration(b.owed/rate*float64(time.Second)) - now.Sub(b.last)
}

// owed is how long from now a cut chain's resource's bucket, which
// refills at rate, takes to refill what the gate's requests drew from it:
// those answered when they were, those in flight no earlier than now.
func (g *gate) owed(now time.Time, rate float64, resource string) time.Duration {
	b := bucketDebt{}
	if d := g.doneRes[resource]; d != nil {
		b = *d
	}
	var flight []*gateDraw
	for _, d := range g.draws {
		if slices.Contains(d.resources, resource) {
			flight = append(flight, d)
		}
	}
	slices.SortStableFunc(flight, func(a, b *gateDraw) int { return a.at.Compare(b.at) })
	for _, d := range flight {
		b.add(later(d.at, now), 1, rate)
	}
	return b.wait(now, rate)
}

// answered folds a request's draw into what the gate's buckets hold, at
// the time it was answered: the server drew no later.
func (g *gate) answered(d *gateDraw, at time.Time) {
	g.draws = slices.DeleteFunc(g.draws, func(x *gateDraw) bool { return x == d })
	g.level.tokens = g.level.at(at, g.rate, g.burst) - float64(d.tokens)
	if at.After(g.level.last) {
		g.level.last = at
	}
	for _, r := range d.resources {
		if g.doneRes[r] == nil {
			g.doneRes[r] = &bucketDebt{}
		}
		g.doneRes[r].add(at, 1, g.resource)
	}
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// errStopped stops a concurrent batch before its next request once
// another has failed: the import stops at the first failure.
var errStopped = errors.New("import: stopped after another batch failed")

// admit waits until a request into ns drawing tokens, and a token from
// the buckets of those of resources whose chains a batch cuts, may be
// sent; at once if ns has no gate. done records that the request was
// answered (under im.mu). Once a batch has failed it returns errStopped.
func (im *importer) admit(ctx context.Context, ns string, tokens int, resources ...string) (done func(), err error) {
	g := im.gates[ns]
	if g == nil {
		return func() {}, nil
	}
	var cut []string
	for _, r := range resources {
		if g.cut[r] {
			cut = append(cut, r)
		}
	}
	now := im.opt.Now()
	wait := g.wait(now)
	for _, r := range cut {
		wait = max(wait, g.owed(now, g.resource, r))
	}
	d := &gateDraw{at: now.Add(max(0, wait)), tokens: tokens, resources: cut}
	g.draws = append(g.draws, d)
	err = im.sleepUntil(ctx, d.at)
	if err == nil && im.run != nil && im.run.err != nil {
		err = errStopped
	}
	if err != nil {
		g.draws = slices.DeleteFunc(g.draws, func(x *gateDraw) bool { return x == d })
		return nil, err
	}
	return func() { g.answered(d, im.opt.Now()) }, nil
}

// gateFor is the gate of a node's concurrent batches, and how many may be
// in flight: Concurrency, or fewer, as many as the allowance's burst holds
// the draws of, all at once, of the batch that draws the most (its blob
// uploads, dry run and submit). If the allowance ends, no more than its
// rate draws in half the margin before its until (allowanceMargin): a
// batch started before then is sent before it, however long it waits at
// the gate. Nil, and one, without an allowance, or where the allowance
// holds no more than one batch's draws so.
func (im *importer) gateFor(n *node, l limits) (*gate, int) {
	if im.opt.Mode != Backfill || l.allowance == 0 || im.opt.Concurrency < 2 {
		return nil, 1
	}
	g := &gate{rate: l.allowance, burst: l.burst, resource: l.resource, cut: map[string]bool{}, doneRes: map[string]*bucketDebt{},
		level: bucketLevel{tokens: 1, last: im.opt.Now()}}
	most := 1
	for _, b := range n.batches {
		t := len(b.parts) + len(im.batchBlobs(b))
		if b.rep.DryRun != "ok" && b.updates() {
			t += len(b.parts)
		}
		most = max(most, t)
		for _, r := range cutChains(b) {
			g.cut[r] = true
		}
	}
	k := min(im.opt.Concurrency, int(l.burst)/most)
	if !l.until.IsZero() {
		k = min(k, int(allowanceMargin.Seconds()/2*l.allowance)/most)
	}
	if k < 2 {
		return nil, 1
	}
	return g, k
}

// cutChains are the resources of a batch's chains cut between it and the
// batch before or after it.
func cutChains(b *batch) []string {
	var out []string
	if p := b.parts[0]; p.from > 0 {
		out = append(out, p.it.name)
	}
	if p := b.parts[len(b.parts)-1]; p.to < len(p.it.steps) && (len(out) == 0 || out[0] != p.it.name) {
		out = append(out, p.it.name)
	}
	return out
}

// sleepUntil waits until at by the import's clock, as a paced wait.
func (im *importer) sleepUntil(ctx context.Context, at time.Time) error {
	now := im.opt.Now()
	d := at.Sub(now)
	if d <= 0 {
		return nil
	}
	var err error
	var woke time.Time
	im.paced.begin(now)
	im.io(func() { err = im.opt.Sleep(ctx, d); woke = im.opt.Now() })
	im.paced.end(woke, &im.rep.Timings.Paced)
	return err
}

// span adds up the time covered by one or more of overlapping intervals,
// such as concurrent batches' requests or waits, into a timing once none
// is open: wall time, as the timings report it, not the sum of each.
type span struct {
	open        int
	since, last time.Time
}

func (s *span) begin(now time.Time) {
	if s.open == 0 {
		s.since, s.last = now, now
	}
	s.open++
}

func (s *span) end(at time.Time, into *float64) {
	if at.After(s.last) {
		s.last = at
	}
	if s.open--; s.open == 0 {
		*into += s.last.Sub(s.since).Seconds()
	}
}
