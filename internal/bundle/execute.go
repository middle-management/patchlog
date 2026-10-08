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
	blobGrace         time.Duration
	// allowance is the rate of the importer's allowance's bucket, which
	// replaces the principal and namespace buckets (§6.6); 0 without one.
	allowance float64
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
	return limits{items: 1000, size: 16 << 20, nsRate: 500, principal: 50, blobGrace: 24 * time.Hour}
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
			for _, s := range it.steps {
				b.size += stepSize(s)
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
				s := stepSize(it.steps[end])
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
func (im *importer) call(ctx context.Context, ns string, req client.BatchRequest, dry bool) (*client.BatchResult, error) {
	backoff := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		at := im.opt.Now()
		res, err := im.c.Batch(ctx, ns, req, dry)
		if err == nil {
			im.drew(ns, at, len(req.Items))
		}
		if err == nil || !client.Retryable(err) || attempt >= im.opt.MaxRetries || ctx.Err() != nil {
			return res, err
		}
		wait := backoff
		if ae, ok := client.AsAPIError(err); ok && ae.RetryAfter > 0 {
			wait = ae.RetryAfter
		}
		backoff *= 2
		if err := im.opt.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
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
	res, err := im.call(ctx, b.n.ns, req, true)
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
		b.rep.DryRun, b.dryOK = "ok", true
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
		l := defaultLimits()
		if ok {
			l = limitsOf(doc, allowanceOf(doc, sub, kid, im.opt.Now()))
		} else {
			im.rep.Create = append(im.rep.Create, n.ns)
		}
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
	// written. A namespace that depends on earlier batches may fail only
	// because they haven't committed; it is dry-run again before its
	// submit.
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
				// come before the dry run, which checks them too.
				if err := im.prepare(ctx, b, lims[n], deferOK); err != nil {
					return err
				}
			} else if err := im.dryRun(ctx, b, deferOK); err != nil {
				// A dry-run-only import uploads none (§G.4.4).
				return err
			}
		}
		pending[n.ns] = true
	}
	if im.opt.DryRun {
		return nil // the report lists conflicts and dry-run results
	}

	for _, n := range im.order {
		if n.missing {
			cr, err := im.c.CreateNamespace(ctx, n.ns, im.nsDoc(ctx, n))
			if err != nil && !client.IsStale(err) {
				return fmt.Errorf("import: creating namespace %s: %w", n.ns, err)
			}
			if err == nil && im.bump[n.ns] > 0 {
				if err := im.bumpEpochs(ctx, n.ns, cr.Config); err != nil {
					return err
				}
			}
			n.missing = false
		}
		for i := 0; i < len(n.batches); i++ {
			if l := lims[n]; im.opt.Mode == Backfill && l.ended(im.opt.Now()) {
				// The rest fit the namespace's own limits, and are paced
				// as they say. They fit the allowance's too, which the
				// server goes by until its until.
				own := *l.own
				own.items, own.size = min(own.items, l.items), min(own.size, l.size)
				lims[n] = own
				im.resplit(n, i, own)
				rate, by := lims[n].rate(im.opt.Pace)
				im.rep.Notes = append(im.rep.Notes, fmt.Sprintf("the importer's allowance in %s ends at %s (§6.6): batches %d to %d fit the namespace's own limits, paced at %g items/s (%s)",
					n.ns, l.until.Format(time.RFC3339), i+1, len(n.batches), rate, by))
			}
			b, start := n.batches[i], im.opt.Now()
			// Blobs first (§G.4.4), again if they may have expired since.
			if !b.dryOK {
				if err := im.prepare(ctx, b, lims[n], false); err != nil {
					return err
				}
			} else if err := im.sendBlobs(ctx, b, lims[n]); err != nil {
				return err
			}
			req, expected := im.request(b)
			if im.signErr != nil {
				return fmt.Errorf("import: %w", im.signErr)
			}
			res, err := im.call(ctx, n.ns, req, false)
			if err != nil {
				b.rep.Error = err.Error()
				if ae, ok := client.AsAPIError(err); ok {
					switch {
					case ae.Status == 413 && im.opt.Mode == Atomic:
						return &TooLargeError{NS: n.ns, Items: len(req.Items), Size: b.size, Err: err}
					case ae.Status == 412:
						return fmt.Errorf("import: the target moved while importing into %s (%w); import again: classification by ancestry picks up what is left", n.ns, err)
					}
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
				if err := im.pace(ctx, n.ns, lims[n], len(req.Items), start); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// pace waits after a backfill's batch into ns, begun at start, until the
// bucket it paces by (limits.rate) has refilled what the batch drew, less
// the time the batch took. Without an allowance that is its items, at Pace
// of the rate. An allowance's bucket is paced at its full rate, so there it
// counts every draw since the last batch (drew), as the bucket does: a dry
// run draws as a submit does (§6.6, §7.5), a blob upload or copy a token
// (§7.8), and the bucket refills between them, up to full. A 429 the
// pacing doesn't avoid is retried after its Retry-After (call).
func (im *importer) pace(ctx context.Context, ns string, l limits, items int, start time.Time) error {
	rate, _ := l.rate(im.opt.Pace)
	wait := time.Duration(float64(items)/rate*float64(time.Second)) - im.opt.Now().Sub(start)
	if l.allowance > 0 {
		var owed float64
		var last time.Time
		for _, d := range im.draws[ns] {
			owed = max(0, owed-d.at.Sub(last).Seconds()*rate) + float64(d.tokens)
			last = d.at
		}
		wait = time.Duration(owed/rate*float64(time.Second)) - im.opt.Now().Sub(last)
	}
	delete(im.draws, ns)
	if wait <= 0 {
		return nil
	}
	return im.opt.Sleep(ctx, wait)
}

// draw is what an import drew from a target namespace's rate buckets, and
// when (pace).
type draw struct {
	at     time.Time
	tokens int
}

// drew records tokens drawn from ns's buckets by a request sent at at.
func (im *importer) drew(ns string, at time.Time, tokens int) {
	if im.draws == nil {
		im.draws = map[string][]draw{}
	}
	im.draws[ns] = append(im.draws[ns], draw{at, tokens})
}
