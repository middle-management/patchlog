package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// busyNamespaces is the namespaces phase: the write capacity of a
// deployment's database across namespaces (docs/CAPACITY.md, "Several
// namespaces on one database"), as doors' ec2-sources.sh measures it on
// Postgres, without its consumers. For each count of --busy-namespaces,
// that many new namespaces of --busy-docs documents each (about 80 bytes
// of JSON), each document written --busy-rate times a second by a writer
// of its own, closed loop: a write waits for the one before it, then for
// its time (one principal, the loader; each write a single-operation JSON
// Patch with If-Match, an append), for --busy-seconds. A namespace's
// writes go to its home instance (-url, a hash of its name). It reports
// the writes acknowledged a second in all, their latency, and the errors.
//
// The namespaces allow the writers' rates (ratePerResource at twice
// --busy-rate, ratePerPrincipal and ratePerNamespace unbounded): the core
// needs --max-rate-per-resource, --max-rate-per-principal and
// --max-rate-per-namespace raised to them (1e9,1e9 for all three).
func (r *runner) busyNamespaces() {
	var counts []int
	for _, f := range strings.Split(r.c.busyNS, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 {
			fail(fmt.Errorf("--busy-namespaces: %q", f))
		}
		counts = append(counts, n)
	}
	unbounded := map[string]any{"rate": 1e9, "burst": 1e9}
	limits := map[string]any{
		"ratePerResource":  map[string]any{"rate": 2 * r.c.busyRate, "burst": 2 * r.c.busyRate},
		"ratePerPrincipal": unbounded,
		"ratePerNamespace": unbounded,
	}
	stamp := time.Now().Unix()
	patch := func(v int) []any { return []any{map[string]any{"op": "replace", "path": "/n", "value": v}} }
	for _, n := range counts {
		// New namespaces each step, with their documents.
		nss := make([]string, n)
		heads := make([][]string, n)
		var wg sync.WaitGroup
		for i := range nss {
			nss[i] = fmt.Sprintf("cap-busy-%d-%d-%02d", stamp, n, i)
			r.createNS(nss[i], limits)
			heads[i] = make([]string, r.c.busyDocs)
			for d := range heads[i] {
				wg.Add(1)
				go func(i, d int) {
					defer wg.Done()
					w, err := retry(func() (*client.WriteResult, error) {
						return r.w(nss[i]).CreateDoc(r.ctx, nss[i], docName(d), map[string]any{"title": fmt.Sprintf("document %d", d), "n": 0})
					})
					if err != nil {
						fail(err)
					}
					heads[i][d] = w.ID
				}(i, d)
			}
		}
		wg.Wait()
		r.logf("namespaces %d: %d documents each, writing for %ds", n, r.c.busyDocs, r.c.busySecs)
		time.Sleep(2 * time.Second)
		every := time.Duration(float64(time.Second) / r.c.busyRate)
		var mu sync.Mutex
		var lat []time.Duration
		var ok, stale, limited, failed atomic.Int64
		cpu0 := r.cpu()
		t0 := time.Now()
		deadline := t0.Add(time.Duration(r.c.busySecs) * time.Second)
		for i := range nss {
			for d := range heads[i] {
				wg.Add(1)
				go func(ns, name, head string) {
					defer wg.Done()
					c := r.w(ns)
					var mine []time.Duration
					// Each writer starts at a random point of its period.
					next := time.Now().Add(time.Duration(float64(every) * float64(d%97) / 97))
					for v := 1; ; v++ {
						if wait := time.Until(next); wait > 0 {
							time.Sleep(wait)
						}
						if !time.Now().Before(deadline) {
							break
						}
						next = next.Add(every)
						t := time.Now()
						w, err := c.Append(r.ctx, ns, name, head, patch(v))
						if err == nil {
							head = w.ID
							mine = append(mine, time.Since(t))
							ok.Add(1)
							continue
						}
						ae, isAPI := client.AsAPIError(err)
						switch {
						case isAPI && ae.Status == 412:
							stale.Add(1)
							if h, err := c.Head(r.ctx, ns, name); err == nil {
								head = h.ID
							}
						case isAPI && ae.Status == 429:
							limited.Add(1)
						default:
							if failed.Add(1) == 1 {
								r.logf("error: %v", err)
							}
						}
					}
					mu.Lock()
					lat = append(lat, mine...)
					mu.Unlock()
				}(nss[i], docName(d), heads[i][d])
			}
		}
		wg.Wait()
		wall := time.Since(t0)
		res := map[string]any{"namespaces": n, "documents": n * r.c.busyDocs, "asked_per_second": float64(n*r.c.busyDocs) * r.c.busyRate,
			"stale_412": stale.Load(), "limited_429": limited.Load(), "errors": failed.Load()}
		if len(lat) > 0 {
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			for k, v := range summary(lat, wall) {
				res[k] = v
			}
		}
		if cpu := r.cpu(); cpu > 0 {
			res["origin_cpu_seconds"] = cpu - cpu0
		}
		r.record(fmt.Sprintf("namespaces_%d", n), res)
	}
}
