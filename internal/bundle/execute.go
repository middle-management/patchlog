package bundle

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
)

// limits are the batch and rate limits of a target namespace (§6.6).
type limits struct {
	items, size       int
	nsRate, principal float64
	blobGrace         time.Duration
}

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

func limitsOf(doc map[string]any) limits {
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
	return l
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
// require, cutting a long chain into consecutive parts if needed.
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
	cur := &batch{n: n}
	flush := func() {
		if len(cur.parts) > 0 {
			n.batches = append(n.batches, cur)
		}
		cur = &batch{n: n}
	}
	for _, it := range n.items {
		start := 0
		for start < len(it.steps) {
			if len(cur.parts) >= l.items {
				flush()
			}
			end, sz := start, 0
			for end < len(it.steps) {
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
		res, err := im.c.Batch(ctx, ns, req, dry)
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
	lims := map[*node]limits{}
	for _, n := range im.order {
		doc, ok, err := im.namespaceDoc(ctx, n.ns)
		if err != nil {
			return err
		}
		n.missing = !ok
		l := defaultLimits()
		if ok {
			l = limitsOf(doc)
		} else {
			im.rep.Create = append(im.rep.Create, n.ns)
		}
		lims[n] = l
		im.split(n, l)
		for i, b := range n.batches {
			b.rep = im.batchReport(b, i+1, len(n.batches))
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
		for i, b := range n.batches {
			// Blobs first (§G.4.4), again if they may have expired since.
			if !b.dryOK {
				if err := im.prepare(ctx, b, lims[n], false); err != nil {
					return err
				}
			} else if err := im.sendBlobs(ctx, b, lims[n]); err != nil {
				return err
			}
			req, expected := im.request(b)
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
				rate := math.Min(lims[n].nsRate, lims[n].principal) * im.opt.Pace
				wait := time.Duration(float64(len(req.Items)) / rate * float64(time.Second))
				if err := im.opt.Sleep(ctx, wait); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
