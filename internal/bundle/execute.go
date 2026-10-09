package bundle

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/merge"
)

// limits are the batch and rate limits of a target namespace (§6.6), or
// the importer's allowance's there.
type limits struct {
	items, size       int
	nsRate, principal float64
	resource          float64 // ratePerResource, which an allowance doesn't replace
	blobGrace         time.Duration
	// allowance is the rate of the importer's allowance's bucket, which
	// replaces the principal and namespace buckets (§6.6), and burst its
	// burst; 0 without one.
	allowance, burst float64
	// With an allowance, own are the namespace's own limits, which apply
	// once it ends at until (zero: it doesn't end).
	own   *limits
	until time.Time
}

// allowanceMargin is how long before its until an importer stops going by
// an allowance (§6.6): a batch begun before then reaches the server before
// it, whatever the batch takes and the clocks differ by, within reason.
const allowanceMargin = time.Minute

func defaultLimits() limits {
	return limits{items: 1000, size: 16 << 20, nsRate: 500, principal: 50, resource: 10, blobGrace: 24 * time.Hour}
}

var sizeRE = regexp.MustCompile(`^(\d+)\s*(B|KiB|MiB|GiB)?$`)

func parseSize(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), x > 0
	case string:
		m := sizeRE.FindStringSubmatch(strings.TrimSpace(x))
		if m == nil {
			return 0, false
		}
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "KiB":
			n <<= 10
		case "MiB":
			n <<= 20
		case "GiB":
			n <<= 30
		}
		return n, n > 0
	}
	return 0, false
}

// limitsOf reads a namespace document's limits, replaced by those that al,
// the importer's allowance there, sets.
func limitsOf(doc, al map[string]any) limits {
	l := defaultLimits()
	m, _ := doc["limits"].(map[string]any)
	if n, ok := m["itemsPerBatch"].(float64); ok && n > 0 {
		l.items = int(n)
	}
	if n, ok := parseSize(m["batchSize"]); ok {
		l.size = n
	}
	if r, ok := m["ratePerNamespace"].(map[string]any); ok {
		if x, ok := r["rate"].(float64); ok && x > 0 {
			l.nsRate = x
		}
	}
	if r, ok := m["ratePerPrincipal"].(map[string]any); ok {
		if x, ok := r["rate"].(float64); ok && x > 0 {
			l.principal = x
		}
	}
	if r, ok := m["ratePerResource"].(map[string]any); ok {
		if x, ok := r["rate"].(float64); ok && x > 0 {
			l.resource = x
		}
	}
	if s, ok := m["blobGrace"].(string); ok {
		if d, err := grant.ParseDuration(s); err == nil && d > 0 {
			l.blobGrace = d
		}
	}
	if al == nil {
		return l
	}
	own := l
	l.own = &own
	if s, ok := al["until"].(string); ok {
		l.until, _ = time.Parse(time.RFC3339, s)
	}
	if n, ok := al["itemsPerBatch"].(float64); ok && n > 0 {
		l.items = int(n)
	}
	if n, ok := parseSize(al["batchSize"]); ok {
		l.size = n
	}
	if b, ok := al["bucket"].(map[string]any); ok {
		if x, ok := b["rate"].(float64); ok && x > 0 {
			l.allowance = x
		}
		l.burst, _ = b["burst"].(float64)
	}
	return l
}

// allowanceOf returns the allowance of the principal sub and kid in a
// namespace document, as the server picks it (§6.6): the first with that
// sub and kid, or with that sub when kid is "" (authentication disabled),
// and none from allowanceMargin before its until.
func allowanceOf(doc map[string]any, sub, kid string, now time.Time) map[string]any {
	if sub == "" {
		return nil
	}
	as, _ := doc["allowances"].([]any)
	for _, x := range as {
		a, _ := x.(map[string]any)
		if a["sub"] != sub || (kid != "" && a["kid"] != kid) {
			continue
		}
		if s, ok := a["until"].(string); ok {
			if u, err := time.Parse(time.RFC3339, s); err == nil && !now.Add(allowanceMargin).Before(u) {
				return nil
			}
		}
		return a
	}
	return nil
}

// ended reports whether the allowance that l goes by ends by now, as
// allowanceOf judges it.
func (l limits) ended(now time.Time) bool {
	return l.own != nil && !l.until.IsZero() && !now.Add(allowanceMargin).Before(l.until)
}

// rate is the pace of a backfill into a namespace, in items per second,
// and the bucket it paces by (§6.6, §G.4.4): an allowance's at its full
// rate, since that bucket is the importer's own and holds up no other
// writer; else Pace of the lower of the principal and namespace rates.
func (l limits) rate(pace float64) (float64, string) {
	switch {
	case l.allowance > 0:
		return l.allowance, "allowance"
	case l.principal <= l.nsRate:
		return l.principal * pace, "ratePerPrincipal"
	}
	return l.nsRate * pace, "ratePerNamespace"
}

func (im *importer) namespaceDoc(ctx context.Context, ns string) (map[string]any, bool, error) {
	h, err := im.c.NSHead(ctx, ns)
	if client.IsNotFound(err) || client.IsGone(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d, err := im.c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return nil, false, noKeysHint(ns, err)
	}
	return d.Value, true, nil
}

// split sizes a node's items into batches: one batch in Atomic mode;
// in Backfill mode as many as the namespace's itemsPerBatch and batchSize
// require (splitParts).
func (im *importer) split(n *node, l limits) {
	if im.opt.Mode == Atomic {
		b := &batch{n: n}
		for _, it := range n.items {
			b.parts = append(b.parts, part{it: it, from: 0, to: len(it.steps)})
			for _, sz := range it.stepSizes() {
				b.size += sz
			}
		}
		n.batches = []*batch{b}
		return
	}
	parts := make([]part, len(n.items))
	for i, it := range n.items {
		parts[i] = part{it: it, from: 0, to: len(it.steps)}
	}
	n.batches = splitParts(n, parts, l)
}

// resplit splits a node's batches from i on again by l, when the importer's
// allowance ends part-way through its batches and the namespace's own
// limits apply to the rest (§6.6). A chain cut between two of them is
// whole again first. Their reports replace the old ones.
func (im *importer) resplit(n *node, i int, l limits) {
	var rest []part
	for _, b := range n.batches[i:] {
		for _, p := range b.parts {
			if k := len(rest) - 1; k >= 0 && rest[k].it == p.it && rest[k].to == p.from {
				rest[k].to = p.to
			} else {
				rest = append(rest, p)
			}
		}
	}
	at, old := slices.Index(im.rep.Batches, n.batches[i].rep), len(n.batches)-i
	n.batches = append(n.batches[:i:i], splitParts(n, rest, l)...)
	var reps []*BatchReport
	for j, b := range n.batches {
		if j < i {
			b.rep.Parts = len(n.batches)
			continue
		}
		b.rep = im.batchReport(b, j+1, len(n.batches))
		b.rep.Rate, b.rep.PacedBy = l.rate(im.opt.Pace)
		reps = append(reps, b.rep)
	}
	im.rep.Batches = slices.Replace(im.rep.Batches, at, at+old, reps...)
}

// splitParts sizes parts of a node's items into batches by l's itemsPerBatch
// and batchSize, cutting a long chain into consecutive parts if needed.
func splitParts(n *node, parts []part, l limits) []*batch {
	var out []*batch
	cur := &batch{n: n}
	flush := func() {
		if len(cur.parts) > 0 {
			out = append(out, cur)
		}
		cur = &batch{n: n}
	}
	for _, p := range parts {
		it, start := p.it, p.from
		for start < p.to {
			if len(cur.parts) >= l.items {
				flush()
			}
			end, sz := start, 0
			for end < p.to {
				s := it.stepSizes()[end]
				if cur.size+sz+s > l.size && (end > start || len(cur.parts) > 0) {
					break
				}
				sz += s
				end++
			}
			if end == start {
				flush()
				continue
			}
			cur.parts = append(cur.parts, part{it: it, from: start, to: end})
			cur.size += sz
			start = end
		}
	}
	flush()
	return out
}

// request builds a batch request with its source (§G.4.4).
func (im *importer) request(b *batch) (client.BatchRequest, []string) {
	var req client.BatchRequest
	ids := map[string]any{}
	var expected []string
	for _, p := range b.parts {
		it := p.it
		bi := client.BatchItem{Resource: it.name, Steps: it.steps[p.from:p.to]}
		switch {
		case p.from > 0:
			bi.IfMatch = it.expected[p.from-1]
		case it.ifNone:
			bi.IfNoneMatch = true
		default:
			bi.IfMatch = it.ifMatch
		}
		if im.opt.Signer != nil {
			// The importer's own signature on each step; any signature of
			// the bundle's revisions stays in the bundle (§C.3.1).
			steps, err := merge.SignSteps(*im.opt.Signer, im.origin, b.n.ns, it.name, bi.IfMatch, bi.Steps)
			if err != nil {
				im.signErr = err
			} else {
				bi.Steps = steps
			}
		}
		req.Items = append(req.Items, bi)
		if it.sameIDs {
			ids[it.name] = it.expected[p.to-1]
		} else {
			ids[it.name] = it.srcID
		}
		expected = append(expected, it.expected[p.to-1])
	}
	src := map[string]any{"ns": b.n.srcNS, "at": im.h.At[b.n.srcNS], "bundle": im.digest, "ids": ids}
	if !im.local {
		src["origin"] = im.h.Origin
	}
	req.Source = src
	return req, expected
}

func (im *importer) batchReport(b *batch, part, parts int) *BatchReport {
	req, _ := im.request(b)
	r := &BatchReport{NS: b.n.ns, Upstream: b.n.upstream, Part: part, Parts: parts, Size: b.size, Source: req.Source}
	for _, p := range b.parts {
		r.Resources = append(r.Resources, p.it.name)
		r.Steps += p.to - p.from
	}
	return r
}

// call runs a batch or dry run, retrying after 429, 5xx and transport
// errors. Retrying a submit is safe (§7.5 idempotent retry).
func (im *importer) call(ctx context.Context, ns string, req client.BatchRequest, dry bool, cut ...string) (*client.BatchResult, error) {
	backoff := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		done, err := im.admit(ctx, ns, len(req.Items), cut...)
		if err != nil {
			return nil, err
		}
		at := im.opt.Now()
		var res *client.BatchResult
		var end time.Time
		im.batching.begin(at)
		im.io(func() { res, err = im.c.Batch(ctx, ns, req, dry); end = im.opt.Now() })
		done()
		im.batching.end(end, &im.rep.Timings.Batches)
		im.rep.Timings.Requests++
		if dry {
			im.rep.Timings.DryRuns++
		}
		if im.gates[ns] == nil && (err == nil || blobsOnly(err)) {
			resources := make([]string, len(req.Items))
			for i, it := range req.Items {
				resources[i] = it.Resource
			}
			im.drew(ns, at, len(req.Items), resources...)
		}
		if err == nil || !client.Retryable(err) || attempt >= im.opt.MaxRetries || ctx.Err() != nil {
			return res, err
		}
		if err := im.wait(ctx, err, backoff); err != nil {
			return nil, err
		}
		backoff *= 2
	}
}

// wait waits before retrying a request that failed with err: a 429's
// retryAfter, else backoff.
func (im *importer) wait(ctx context.Context, err error, backoff time.Duration) error {
	if ae, ok := client.AsAPIError(err); ok && ae.RetryAfter > 0 {
		backoff = ae.RetryAfter
	}
	if client.IsRateLimited(err) {
		im.rep.Timings.RateLimited += backoff.Seconds()
	}
	var err2 error
	im.io(func() { err2 = im.opt.Sleep(ctx, backoff) })
	return err2
}

// timed adds the time since t0 to a timing.
func (im *importer) timed(s *float64, t0 time.Time) {
	*s += im.opt.Now().Sub(t0).Seconds()
}

// blobsOnly reports a batch refused only for blobs that aren't available
// to it (code "blob", §7.8): at step 4 of §6.2, after the request drew its
// tokens (§6.6).
func blobsOnly(err error) bool {
	ae, ok := client.AsAPIError(err)
	if !ok || ae.Code != "batch" {
		return false
	}
	items := ae.Items()
	for _, it := range items {
		if it["code"] != "blob" {
			return false
		}
	}
	return len(items) > 0
}

// deferrable codes: dry-run failures that are expected while an earlier
// namespace's batch (e.g. the schemas) hasn't committed.
var deferrable = map[string]bool{"schema_unavailable": true}

// dryRun dry-runs a batch. deferOK allows failures that only mean an
// earlier batch hasn't committed yet.
func (im *importer) dryRun(ctx context.Context, b *batch, deferOK bool) error {
	req, expected := im.request(b)
	if im.signErr != nil {
		return fmt.Errorf("import: %w", im.signErr)
	}
	res, err := im.call(ctx, b.n.ns, req, true, cutChains(b)...)
	if err != nil {
		b.rep.DryRun = "failed"
		b.rep.Error = err.Error()
		if ae, ok := client.AsAPIError(err); ok && ae.Status == 413 && im.opt.Mode == Atomic {
			return &TooLargeError{NS: b.n.ns, Items: len(req.Items), Size: b.size, Err: err}
		}
		return fmt.Errorf("import: dry run of the batch into %s: %w", b.n.ns, err)
	}
	var failures []string
	allDeferrable, onlyBlobs, allBlob := true, true, true
	for i, it := range res.Items {
		st, _ := it.Raw["status"].(float64)
		if st != 200 {
			code, _ := it.Raw["code"].(string)
			msg, _ := it.Raw["message"].(string)
			failures = append(failures, fmt.Sprintf("%s: %v %s %s", it.Resource, st, code, msg))
			if !deferrable[code] {
				allDeferrable = false
			}
			if code != "blob" {
				allBlob = false
			}
			// A dry-run import uploads no blobs (§G.4.4): their absence is
			// expected for blobs it would upload.
			if code != "blob" || !im.opt.DryRun || len(im.batchBlobs(b)) == 0 {
				onlyBlobs = false
			}
			continue
		}
		if i < len(expected) && (len(it.IDs) == 0 || it.IDs[len(it.IDs)-1] != expected[i]) {
			failures = append(failures, fmt.Sprintf("%s: would produce %v, expected %s", it.Resource, it.IDs, expected[i]))
			allDeferrable, onlyBlobs, allBlob = false, false, false
		}
	}
	b.rep.Failures = failures
	if len(failures) == 0 {
		b.rep.DryRun = "ok"
		return nil
	}
	if allBlob && b.rep.ViaSource > 0 && !im.opt.DryRun {
		return errViaSource
	}
	if deferOK && allDeferrable {
		b.rep.DryRun = "deferred"
		return nil
	}
	if onlyBlobs {
		b.rep.DryRun = "deferred"
		b.rep.Failures = append(b.rep.Failures, "a dry run uploads no blobs; the import uploads them before the batch")
		return nil
	}
	b.rep.DryRun = "failed"
	return fmt.Errorf("import: dry run of the batch into %s fails: %s", b.n.ns, strings.Join(failures, "; "))
}

func (im *importer) defaultNSDoc(ctx context.Context, n *node) any {
	upstreamOf := ""
	if n.upstream {
		upstreamOf = im.mapNS(n.srcNS)
	}
	if im.opt.NamespaceDoc != nil {
		return im.opt.NamespaceDoc(n.ns, upstreamOf)
	}
	if upstreamOf != "" {
		// An upstream namespace is exactly as readable as the namespace it
		// serves (§G.5); checkAccess seals it too if its source is sealed.
		if doc, ok, err := im.namespaceDoc(ctx, upstreamOf); err == nil && ok {
			if r, ok := doc["read"].(string); ok {
				return map[string]any{"read": r}
			}
		}
		return map[string]any{"read": "grant"}
	}
	return map[string]any{}
}

func (im *importer) execute(ctx context.Context) error {
	// A bearer that doesn't decode has no allowance; the server answers
	// for it.
	sub, kid, err := im.c.Principal(ctx)
	if err != nil {
		sub = ""
	}
	lims := map[*node]limits{}
	for _, n := range im.order {
		doc, ok, err := im.namespaceDoc(ctx, n.ns)
		if err != nil {
			return err
		}
		n.missing = !ok
		if !ok {
			// One the import creates goes by the limits and allowances of
			// the document it is created with.
			v, _ := client.ToValue(im.nsDoc(ctx, n))
			doc, _ = v.(map[string]any)
			im.rep.Create = append(im.rep.Create, n.ns)
		}
		l := limitsOf(doc, allowanceOf(doc, sub, kid, im.opt.Now()))
		lims[n] = l
		im.split(n, l)
		for i, b := range n.batches {
			b.rep = im.batchReport(b, i+1, len(n.batches))
			if im.opt.Mode == Backfill {
				b.rep.Rate, b.rep.PacedBy = l.rate(im.opt.Pace)
			}
			im.rep.Batches = append(im.rep.Batches, b.rep)
		}
	}
	unresolved := im.rep.Unresolved()
	if len(unresolved) > 0 && !im.opt.DryRun {
		return ErrConflicts
	}
	if len(im.rep.Create) > 0 && !im.opt.CreateNamespaces {
		msg := fmt.Sprintf("import: namespaces %s don't exist in the target", strings.Join(im.rep.Create, ", "))
		if !im.opt.DryRun {
			return fmt.Errorf("%s; create them (or allow the importer to)", msg)
		}
		im.rep.Notes = append(im.rep.Notes, msg)
	}

	// Dry-run the first batch of every namespace before anything is
	// written: one that would fail stops the import with nothing written.
	// A namespace that depends on earlier batches may fail only because
	// they haven't committed; its submit tells. Later batches aren't
	// dry-run, since a dry run draws the tokens a submit does (§6.6): a
	// batch is atomic, so one the server refuses writes nothing (§7.5),
	// but the ids it gives a batch's revisions are checked against the
	// bundle's only once it has written them. A namespace the import
	// creates has its first item dry-run once it exists (probe), and a
	// batch that moves heads the target had is dry-run before its submit
	// (updates).
	im.timed(&im.rep.Timings.Planning, im.start)
	pending := map[string]bool{}
	for _, n := range im.order {
		b := n.batches[0]
		if n.missing {
			b.rep.DryRun = "deferred"
			b.rep.Failures = []string{"the namespace doesn't exist yet"}
		} else {
			deferOK := false
			for dep := range n.deps {
				deferOK = deferOK || pending[dep]
			}
			if !im.opt.DryRun {
				// Blobs first (§G.4.4): uploads change no head, so they
				// come before the dry run, which checks them too. A
				// backfill paces its dry runs as its batches (§G.4.4).
				if err := im.prepare(ctx, b, lims[n], deferOK); err != nil {
					return err
				}
				if im.opt.Mode == Backfill {
					if err := im.pace(ctx, n.ns, lims[n], ""); err != nil {
						return err
					}
				}
			} else if err := im.dryRun(ctx, b, deferOK); err != nil {
				// A dry-run-only import uploads none (§G.4.4).
				return err
			}
		}
		pending[n.ns] = true
	}
	if im.opt.DryRun {
		// The batches that would move heads the target had are dry-run
		// too, so a promotion can be checked end to end (§G.4.4 Partial
		// failure), but for one that goes on with a chain an earlier batch
		// cut, which needs that batch written. Failures that mean only
		// that earlier batches haven't committed are deferred.
		for _, n := range im.order {
			for _, b := range n.batches[1:] {
				if !b.updates() || b.parts[0].from > 0 {
					continue
				}
				if err := im.dryRun(ctx, b, true); err != nil {
					return err
				}
				if im.opt.Mode == Backfill {
					if err := im.pace(ctx, n.ns, lims[n], ""); err != nil {
						return err
					}
				}
			}
		}
		return nil // the report lists conflicts and dry-run results
	}

	run := im.newRunner()
	if err := im.submitAll(ctx, run, lims); err != nil {
		run.stop()
		return err
	}
	return run.stop()
}

// submitAll submits every node's batches in order, as many at once as the
// node allows (concurrent.go), each dry-run first if it updates.
func (im *importer) submitAll(ctx context.Context, run *runner, lims map[*node]limits) error {
	for _, n := range im.order {
		// Its dependencies' batches have committed (§G.4.4 Order); a
		// namespace whose batches go one at a time waits for all.
		if err := run.waitFor(func(f *flight) bool { return n.deps[f.n.ns] }); err != nil {
			return err
		}
		if im.opt.Mode != Backfill || lims[n].allowance == 0 || im.opt.Concurrency < 2 {
			if err := run.slot(1); err != nil {
				return err
			}
		}
		if n.missing {
			var cr *client.ConfigResult
			var err error
			doc := im.nsDoc(ctx, n)
			im.io(func() { cr, err = im.c.CreateNamespace(ctx, n.ns, doc) })
			if err != nil && !client.IsStale(err) {
				return fmt.Errorf("import: creating namespace %s: %w", n.ns, err)
			}
			if err == nil && im.bump[n.ns] > 0 {
				if err := im.bumpEpochs(ctx, n.ns, cr.Config); err != nil {
					return err
				}
			}
			n.missing = false
			if err := im.probe(ctx, n, lims[n]); err != nil {
				return err
			}
		}
		g, conc := im.gateFor(n, lims[n])
		if g != nil {
			im.gates[n.ns] = g
		} else if err := run.slot(1); err != nil {
			return err
		}
		for i := 0; i < len(n.batches); i++ {
			b := n.batches[i]
			max := 1
			if im.gates[n.ns] != nil {
				max = conc
			}
			if err := run.waitFor(func(f *flight) bool { return f.n == n && im.after(b, f.b) }); err != nil {
				return err
			}
			if err := run.slot(max); err != nil {
				return err
			}
			if l := lims[n]; im.opt.Mode == Backfill && l.ended(im.opt.Now()) {
				// The rest fit the namespace's own limits, and are paced
				// as they say. They fit the allowance's too, which the
				// server goes by until its until.
				if err := run.waitFor(func(f *flight) bool { return f.n == n }); err != nil {
					return err
				}
				if g := im.gates[n.ns]; g != nil {
					// The concurrent batches were paced as they went; the
					// rest pace after each batch, from what they draw.
					delete(im.gates, n.ns)
					delete(im.draws, n.ns)
				}
				own := *l.own
				own.items, own.size = min(own.items, l.items), min(own.size, l.size)
				lims[n] = own
				im.resplit(n, i, own)
				rate, by := lims[n].rate(im.opt.Pace)
				im.rep.Notes = append(im.rep.Notes, fmt.Sprintf("the importer's allowance in %s ends at %s (§6.6): batches %d to %d fit the namespace's own limits, paced at %g items/s (%s)",
					n.ns, l.until.Format(time.RFC3339), i+1, len(n.batches), rate, by))
				b, max = n.batches[i], 1
			}
			l, i := lims[n], i
			if err := run.start(n, b, max, func() error { return im.submitBatch(ctx, n, i, l) }); err != nil {
				return err
			}
		}
	}
	return nil
}

// submitBatch submits a node's batch i, dry-run first if it updates, and
// checks the ids it produced. A concurrent batch's requests wait at its
// namespace's gate (admit); any other batch paces after each (pace).
func (im *importer) submitBatch(ctx context.Context, n *node, i int, l limits) error {
	b := n.batches[i]
	gated := im.gates[n.ns] != nil
	if b.rep.DryRun != "ok" && b.updates() {
		if err := im.prepare(ctx, b, l, false); err != nil {
			return err
		}
		if !gated && im.opt.Mode == Backfill {
			// The submit draws again on the bucket of a chain the
			// batch goes on with.
			cut := ""
			if p := b.parts[0]; p.from > 0 {
				cut = p.it.name
			}
			if err := im.pace(ctx, n.ns, l, cut); err != nil {
				return err
			}
		}
	}
	res, expected, err := im.submit(ctx, b, l)
	if err != nil {
		b.rep.Error = err.Error()
		var failures []string
		if ae, ok := client.AsAPIError(err); ok {
			switch {
			case ae.Status == 413 && im.opt.Mode == Atomic:
				return &TooLargeError{NS: n.ns, Items: len(b.parts), Size: b.size, Err: err}
			case ae.Status == 412:
				return fmt.Errorf("import: the target moved while importing into %s (%w); import again: classification by ancestry picks up what is left", n.ns, err)
			}
			// The failing items, as a dry run lists them.
			for _, it := range ae.Items() {
				name := ""
				if k, ok := it["index"].(float64); ok && int(k) < len(b.parts) {
					name = b.parts[int(k)].it.name
				}
				code, _ := it["code"].(string)
				msg, _ := it["message"].(string)
				failures = append(failures, fmt.Sprintf("%s: %v %s %s", name, it["status"], code, msg))
			}
		}
		if len(failures) > 0 {
			b.rep.Failures = append(b.rep.Failures, failures...)
			return fmt.Errorf("import: batch %d/%d into %s fails: %s (%w)", i+1, len(n.batches), n.ns, strings.Join(failures, "; "), err)
		}
		return fmt.Errorf("import: batch %d/%d into %s: %w", i+1, len(n.batches), n.ns, err)
	}
	b.rep.Status, b.rep.NSID = res.Status, res.NSID
	for j, it := range res.Items {
		if j < len(expected) && (len(it.IDs) == 0 || it.IDs[len(it.IDs)-1] != expected[j]) {
			return fmt.Errorf("import: %s/%s produced %v, expected %s", n.ns, it.Resource, it.IDs, expected[j])
		}
	}
	if im.opt.Progress != nil {
		im.opt.Progress(b.rep)
	}
	if im.opt.Mode == Backfill {
		// A chain cut between this batch and the next draws on its
		// resource's bucket again.
		cut := ""
		if p := b.parts[len(b.parts)-1]; p.to < len(p.it.steps) {
			cut = p.it.name
		}
		if gated {
			return nil
		}
		if err := im.pace(ctx, n.ns, l, cut); err != nil {
			return err
		}
	}
	return nil
}

// probe dry-runs the first item of a namespace's first batch once the
// import has created the namespace: a token, paced as a dry run is, that
// checks before anything is written there that the server gives the
// bundle's revisions their ids. A server that derives them otherwise
// takes the submit all the same: source.ids only records them (§3.5).
func (im *importer) probe(ctx context.Context, n *node, l limits) error {
	b := n.batches[0]
	p := &batch{n: n, parts: b.parts[:1], rep: b.rep}
	for _, sz := range p.parts[0].it.stepSizes()[p.parts[0].from:p.parts[0].to] {
		p.size += sz
	}
	if err := im.prepare(ctx, p, l, false); err != nil {
		return err
	}
	if im.opt.Mode == Backfill {
		return im.pace(ctx, n.ns, l, "")
	}
	return nil
}

// updates reports whether a batch writes to a resource the target had: a
// fast-forward, a resolved conflict or a restore. Its new heads take
// effect at once, and a failure part-way through the import leaves them
// changed (§G.4.4 Partial failure), so such a batch is dry-run before its
// submit, its blobs sent first; creates rely on their own failure report
// (§7.5). So does a snapshot's next diff upstream: live references don't
// see upstream heads, only pinned revisions (§G.4.4), and the next import
// picks up one whose target batch didn't follow.
func (b *batch) updates() bool {
	for _, p := range b.parts {
		if !p.it.ifNone && !p.it.upstream {
			return true
		}
	}
	return false
}

// submit submits a batch, its blobs sent first (§G.4.4), again if they
// may have expired since its dry run. A batch that fails only for blobs it
// left to its local source, which doesn't make them available
// (sourceHas), is submitted again with them sent, as prepare does after a
// dry run: it wrote nothing (§7.5).
func (im *importer) submit(ctx context.Context, b *batch, l limits) (*client.BatchResult, []string, error) {
	if err := im.sendBlobs(ctx, b, l); err != nil {
		return nil, nil, err
	}
	req, expected := im.request(b)
	if im.signErr != nil {
		return nil, nil, fmt.Errorf("import: %w", im.signErr)
	}
	res, err := im.call(ctx, b.n.ns, req, false, cutChains(b)...)
	if err != nil && b.rep.ViaSource > 0 && blobsOnly(err) {
		if err := im.sendAll(ctx, b, l); err != nil {
			return nil, nil, err
		}
		res, err = im.call(ctx, b.n.ns, req, false, cutChains(b)...)
	}
	return res, expected, err
}

// pace waits after a backfill's batch request into ns until the buckets it
// draws on have refilled what the import drew there since it last paced
// (drew): every batch request, dry runs included (§6.6, §7.5), and a token
// for every blob upload or copy (§7.8). It counts on no burst: a bucket is
// taken to hold none to spare at the first draw, and refills between
// draws. The bucket it paces by
// (limits.rate) refills at Pace of the lower of the namespace's and the
// principal's rates, or at an allowance's full rate, which holds up no
// other writer (§G.4.4). cut, if not "", is a resource the next batch
// writes again, whose own bucket an allowance doesn't replace: the
// import's draws on it are repaid at ratePerResource too. A 429 the pacing
// doesn't avoid is retried after its retryAfter (call).
func (im *importer) pace(ctx context.Context, ns string, l limits, cut string) error {
	rate, _ := l.rate(im.opt.Pace)
	wait := im.owed(ns, rate, "")
	if cut != "" {
		wait = max(wait, im.owed(ns, l.resource, cut))
	}
	delete(im.draws, ns)
	if wait <= 0 {
		return nil
	}
	return im.sleepUntil(ctx, im.opt.Now().Add(wait))
}

// owed is how long from now a bucket that refills at rate takes to refill
// the import's draws on it in ns since it last paced: on resource's own
// bucket if resource isn't "".
func (im *importer) owed(ns string, rate float64, resource string) time.Duration {
	return owedOf(im.draws[ns], im.opt.Now(), rate, resource)
}

// owedOf is how long from now a bucket that refills at rate, holding none
// to spare at the first of draws, takes to refill them: resource's own
// bucket if resource isn't "", which each draw naming it drew a token from.
func owedOf(draws []draw, now time.Time, rate float64, resource string) time.Duration {
	var owed float64
	var last time.Time
	for _, d := range draws {
		tokens := d.tokens
		if resource != "" {
			if !slices.Contains(d.resources, resource) {
				continue
			}
			tokens = 1
		}
		owed = max(0, owed-d.at.Sub(last).Seconds()*rate) + float64(tokens)
		last = d.at
	}
	return time.Duration(owed/rate*float64(time.Second)) - now.Sub(last)
}

// draw is what an import drew from a target namespace's rate buckets, and
// when (pace): tokens from the principal and namespace buckets, or the
// allowance's, and one from each resource's own.
type draw struct {
	at        time.Time
	tokens    int
	resources []string
}

// drew records tokens drawn from ns's buckets by a request sent at at.
func (im *importer) drew(ns string, at time.Time, tokens int, resources ...string) {
	if im.draws == nil {
		im.draws = map[string][]draw{}
	}
	im.draws[ns] = append(im.draws[ns], draw{at, tokens, resources})
}
