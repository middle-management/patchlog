package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// The branches phase measures what §6.6 says branchesPerNamespace and
// branchDepth bound: one base with -branch-count live branches (and
// -branch-frozen frozen ones, -branch-children branches under each), or a
// chain of -branch-depth branches of branches. It is meant for a new,
// empty database per run, since a purge's cost depends on every namespace
// of the deployment. The core needs --max-branches-per-namespace and
// --max-branch-depth raised to what is asked for.

// purgeStub counts the tags the core sends to -purge-listen, its
// --purge-url.
type purgeStub struct{ reqs, tags atomic.Int64 }

func (p *purgeStub) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	p.reqs.Add(1)
	for _, vs := range q.Header {
		for _, v := range vs {
			if strings.Contains(v, "heads:") || strings.Contains(v, "r:") || strings.Contains(v, "ns:") {
				p.tags.Add(int64(len(strings.Fields(v))))
			}
		}
	}
	w.WriteHeader(200)
}

// bw is a client for the phase's namespaces: in the grants profile its
// grant names nss and carries every verb.
func (r *runner) bw(nss ...string) *client.Client {
	if r.op == nil {
		return r.pubs[r.urls[0]]
	}
	names := make([]any, len(nss))
	for i, n := range nss {
		names[i] = n
	}
	return r.newClient(r.urls[0], r.mint(r.key, map[string]any{"kid": keyKid, "sub": loaderSub, "ns": names,
		"can": []any{"read", "create", "append", "restore", "delete", "purge", "config", "branch", "purge-ns", "export", "prune"}}))
}

// branchBase creates a namespace whose key may do everything and which
// may have limit live branches; it returns its config id.
func (r *runner) branchBase(ns string, limit int) string {
	c := r.pubs[r.urls[0]]
	if r.op != nil {
		c = r.newClient(r.urls[0], r.mint(r.op, map[string]any{"kid": "operator", "sub": "op:capacity", "ns": []any{ns}, "can": []any{"config"}}))
	}
	doc := r.nsDoc()
	if r.op != nil {
		doc["keys"] = []any{map[string]any{"kid": keyKid, "alg": "ed25519", "pub": r.keyPub, "can": []any{"*"}}}
	}
	doc["limits"] = map[string]any{"branchesPerNamespace": limit}
	return must(c.CreateNamespace(r.ctx, ns, doc)).Config
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// timesOf runs fn n times, one after another.
func timesOf(n int, fn func(i int) error) map[string]any {
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t := time.Now()
		if err := fn(i); err != nil {
			fail(err)
		}
		lat = append(lat, time.Since(t))
	}
	s := summary(lat, 0)
	delete(s, "p95_ms")
	delete(s, "p99_ms")
	return s
}

// during runs fn while a writer creates documents name-i in ns one write
// after another, and returns fn's result with the slowest and median of
// those writes.
// Each write creates a document, so no per-resource rate applies.
func (r *runner) during(c *client.Client, ns, name string, fn func() map[string]any) map[string]any {
	stop := make(chan struct{})
	var lat []time.Duration
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			t := time.Now()
			_, err := c.CreateDoc(r.ctx, ns, fmt.Sprintf("%s-%d", name, i), map[string]any{"n": i})
			if err != nil {
				r.logf("write during: %v", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			lat = append(lat, time.Since(t))
			// Few enough that the documents they add don't change what a
			// purge scans.
			time.Sleep(50 * time.Millisecond)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	out := fn()
	close(stop)
	wg.Wait()
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		out["other_write_p50_ms"], out["other_write_max_ms"], out["other_writes"] = ms(lat[len(lat)/2]), ms(lat[len(lat)-1]), len(lat)
	}
	return out
}

func body(i int) map[string]any {
	return map[string]any{"n": i, "text": strings.Repeat("x", 480)}
}

// purges purges names of ns one after another and reports the times and
// the purge tags the core sent for each.
func (r *runner) purges(c *client.Client, ns string, names []string, stub *purgeStub) map[string]any {
	if len(names) == 0 {
		return map[string]any{"n": 0}
	}
	heads := make([]string, len(names))
	for i, n := range names {
		heads[i] = must(c.Head(r.ctx, ns, n)).ID
	}
	t0 := stub.tags.Load()
	out := timesOf(len(names), func(i int) error {
		_, err := c.Purge(r.ctx, ns, names[i], heads[i], false)
		return err
	})
	if stub.reqs.Load() > 0 || r.c.purgeListen != "" {
		time.Sleep(1500 * time.Millisecond)
		out["purge_tags_each"] = float64(stub.tags.Load()-t0) / float64(len(names))
	}
	return out
}

func (r *runner) branches() {
	stub := &purgeStub{}
	if r.c.purgeListen != "" {
		l := must(net.Listen("tcp", r.c.purgeListen))
		go http.Serve(l, stub)
	}
	tag := fmt.Sprintf("cb%d", time.Now().Unix()%10000000)
	if r.c.branchDepth >= 0 {
		r.branchChain(tag, stub)
		return
	}
	r.branchWidth(tag, stub)
}

func (r *runner) branchWidth(tag string, stub *purgeStub) {
	n, frozen, children, docs := r.c.branchCount, r.c.branchFrozen, r.c.branchChildren, r.c.branchDocs
	base, other := tag+"-base", tag+"-other"
	r.record("branch_count", n)
	r.record("branch_frozen", frozen)
	r.record("branch_children", children)
	r.record("branch_docs", docs)
	cfg := r.branchBase(base, n+10)
	r.branchBase(other, 100)
	cb, co := r.bw(base), r.bw(other)
	var wg sync.WaitGroup
	par := func(k int, fn func(i int)) {
		var next atomic.Int64
		for w := 0; w < r.c.workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(next.Add(1)) - 1
					if i >= k {
						return
					}
					fn(i)
				}
			}()
		}
		wg.Wait()
	}
	par(docs, func(i int) {
		must(retry(func() (*client.WriteResult, error) { return cb.CreateDoc(r.ctx, base, fmt.Sprintf("d-%d", i), body(i)) }))
	})
	names := func(p string) []string {
		out := make([]string, r.c.purgeRuns)
		for i := range out {
			out[i] = fmt.Sprintf("%s-%d", p, i)
		}
		return out
	}
	for _, p := range []string{"through", "own"} {
		for _, name := range names(p) {
			must(cb.CreateDoc(r.ctx, base, name, body(0)))
		}
	}
	for _, name := range append(names("o-before"), names("o-after")...) {
		must(co.CreateDoc(r.ctx, other, name, body(0)))
	}
	sw := must(cb.CreateDoc(r.ctx, base, "schema", structuredSchema()))
	schemaRef := fmt.Sprintf("/r/%s/schema/rev/%s", base, sw.ID)
	// Typed documents of the base, which every branch reads through: each
	// branch then references the schema too.
	for i := 0; i < 20; i++ {
		must(cb.CreateDoc(r.ctx, base, fmt.Sprintf("typed-%d", i), structuredDoc(2048, schemaRef)))
	}

	// With no branch anywhere: the purge of a document of another
	// namespace, and of one of the base.
	r.record("purge_other_before", r.purges(co, other, names("o-before"), stub))

	// Frozen branches first, each frozen as it is made, then the live ones.
	bname := func(i int) string { return fmt.Sprintf("%s-b%d", tag, i) }
	var create []time.Duration
	t0 := time.Now()
	for i := 0; i < frozen+n; i++ {
		t := time.Now()
		br, err := cb.CreateBranch(r.ctx, base, client.BranchRequest{Name: bname(i)})
		if err != nil {
			fail(fmt.Errorf("branch %d: %w", i, err))
		}
		create = append(create, time.Since(t))
		if i < frozen {
			must(r.bw(bname(i)).PatchConfig(r.ctx, bname(i), br.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		}
		if (i+1)%1000 == 0 {
			r.logf("%d branches", i+1)
		}
	}
	r.record("branch_seed_seconds", time.Since(t0).Seconds())
	tail := create
	if len(tail) > 50 {
		tail = tail[len(tail)-50:]
	}
	if len(tail) > 0 {
		r.record("branch_create_last", summary(tail, 0))
	}
	live := func(i int) string { return bname(frozen + i) }
	// Every live branch holds a revision of its own of the "own" documents.
	if n > 0 {
		par(n, func(i int) {
			c := r.bw(live(i))
			for _, name := range names("own") {
				h := must(retry(func() (*client.Head, error) { return c.Head(r.ctx, live(i), name) }))
				must(retry(func() (*client.WriteResult, error) {
					return c.Append(r.ctx, live(i), name, h.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 1}})
				}))
			}
		})
	}
	if children > 0 {
		t0 := time.Now()
		par(n, func(i int) {
			c := r.bw(live(i))
			for k := 0; k < children; k++ {
				must(retry(func() (*client.BranchResult, error) {
					return c.CreateBranch(r.ctx, live(i), client.BranchRequest{Name: fmt.Sprintf("%s-c%d", live(i), k)})
				}))
			}
		})
		r.record("branch_children_seed_seconds", time.Since(t0).Seconds())
	}
	// Documents the branches don't see: created after them (§8.4's at).
	for _, name := range names("unseen") {
		must(cb.CreateDoc(r.ctx, base, name, body(0)))
	}
	r.settle()

	// The whole listing, every page of it (§7.4: logPageSize rows a
	// page, so one request per thousand branches at the default), then
	// its first page alone.
	r.record("branch_list", timesOf(10, func(int) error {
		bs, err := cb.Branches(r.ctx, base)
		if err == nil && len(bs) != frozen+n {
			err = fmt.Errorf("listed %d branches", len(bs))
		}
		return err
	}))
	r.record("branch_list_first_page", timesOf(10, func(int) error {
		bs, next, err := cb.BranchesPage(r.ctx, base, "")
		if err == nil && next == "" && len(bs) != frozen+n {
			err = fmt.Errorf("listed %d branches on the only page", len(bs))
		}
		return err
	}))
	// One more branch, with the base at its count.
	r.record("branch_create_one", timesOf(5, func(i int) error {
		_, err := cb.CreateBranch(r.ctx, base, client.BranchRequest{Name: fmt.Sprintf("%s-x%d", tag, i)})
		return err
	}))
	// Namespace-document writes of the base: a key added, a revocation.
	r.record("base_config_add_key", timesOf(5, func(i int) error {
		res, err := cb.PatchConfig(r.ctx, base, cfg, []any{map[string]any{"op": "add", "path": "/keys/-",
			"value": map[string]any{"kid": fmt.Sprintf("k%d", i), "alg": "ed25519", "pub": r.keyPub, "can": []any{"read"}}}})
		if err == nil {
			cfg = res.Config
		}
		return err
	}))
	if r.op != nil {
		r.record("base_config_revoke", timesOf(5, func(i int) error {
			raw := make([]byte, 32)
			rand.Read(raw)
			h := sha256.Sum256(raw)
			id := "1" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:20]))
			path, val := "/revoked/-", any(id)
			if i == 0 {
				path, val = "/revoked", []any{id}
			}
			res, err := cb.PatchConfig(r.ctx, base, cfg, []any{map[string]any{"op": "add", "path": path, "value": val}})
			if err == nil {
				cfg = res.Config
			}
			return err
		}))
	}
	if n > 0 {
		b0 := live(0)
		c0 := r.bw(b0, base)
		r.record("branch_read_through", r.measure(1, func() error { _, err := c0.Head(r.ctx, b0, "d-0"); return err }))
		var k atomic.Int64
		r.record("branch_create_doc", r.measure(1, func() error {
			_, err := c0.CreateDoc(r.ctx, b0, fmt.Sprintf("w-%d", k.Add(1)), body(0))
			return err
		}))
		r.record("branch_create_typed", r.measure(1, func() error {
			_, err := c0.CreateDoc(r.ctx, b0, fmt.Sprintf("t-%d", k.Add(1)), structuredDoc(2048, schemaRef))
			return err
		}))
		// A draft: a schema revision written in the branch, named under
		// the base's path (§6.1).
		dw := must(c0.CreateDoc(r.ctx, b0, "draft", structuredSchema()))
		draftRef := fmt.Sprintf("/r/%s/draft/rev/%s", base, dw.ID)
		r.record("branch_create_draft_typed", r.measure(1, func() error {
			_, err := c0.CreateDoc(r.ctx, b0, fmt.Sprintf("dt-%d", k.Add(1)), structuredDoc(2048, draftRef))
			return err
		}))
	}
	r.record("base_create_doc", r.measure(1, func() error {
		_, err := cb.CreateDoc(r.ctx, base, fmt.Sprintf("w-%d", time.Now().UnixNano()), body(0))
		return err
	}))
	r.settle()

	// Purges, while another namespace takes writes.
	r.record("purge_other_after", r.purges(co, other, names("o-after"), stub))
	for _, kind := range []string{"unseen", "through", "own"} {
		kind := kind
		r.record("purge_base_"+kind, r.during(co, other, "busy-"+kind, func() map[string]any {
			return r.purges(cb, base, names(kind), stub)
		}))
	}
	// The purge that still runs the full check: of the schema the typed
	// documents reference, refused (409 in_use).
	if n > 0 && r.c.purgeRuns > 0 {
		head := must(cb.Head(r.ctx, base, "schema")).ID
		r.record("purge_schema_refused", timesOf(3, func(int) error {
			_, err := cb.Purge(r.ctx, base, "schema", head, false)
			if err == nil {
				return fmt.Errorf("the referenced schema was purged")
			}
			if !strings.Contains(err.Error(), "in_use") {
				return err
			}
			return nil
		}))
	}
}

func (r *runner) branchChain(tag string, stub *purgeStub) {
	d := r.c.branchDepth
	root := tag + "-root"
	r.record("branch_depth", d)
	r.branchBase(root, 100)
	cr := r.bw(root)
	for i := 0; i < r.c.branchDocs; i++ {
		must(cr.CreateDoc(r.ctx, root, fmt.Sprintf("d-%d", i), body(i)))
	}
	pn := make([]string, r.c.purgeRuns)
	for i := range pn {
		pn[i] = fmt.Sprintf("through-%d", i)
		must(cr.CreateDoc(r.ctx, root, pn[i], body(0)))
	}
	sw := must(cr.CreateDoc(r.ctx, root, "schema", structuredSchema()))
	schemaRef := fmt.Sprintf("/r/%s/schema/rev/%s", root, sw.ID)
	// The plain namespace's figures, for depth 0.
	leaf, parent := root, root
	var create []time.Duration
	for i := 1; i <= d; i++ {
		name := fmt.Sprintf("%s-l%d", tag, i)
		t := time.Now()
		must(r.bw(leaf).CreateBranch(r.ctx, leaf, client.BranchRequest{Name: name}))
		create = append(create, time.Since(t))
		parent, leaf = leaf, name
	}
	if len(create) > 0 {
		r.record("chain_create_deepest_ms", ms(create[len(create)-1]))
	}
	c := r.bw(leaf, root)
	must(c.CreateDoc(r.ctx, leaf, "own", body(0)))
	r.settle()
	for _, conc := range []int{1, 16} {
		sfx := fmt.Sprintf("_c%d", conc)
		r.record("chain_read_own"+sfx, r.measure(conc, func() error { _, err := c.Head(r.ctx, leaf, "own"); return err }))
		r.record("chain_read_root"+sfx, r.measure(conc, func() error { _, err := c.Head(r.ctx, leaf, "d-0"); return err }))
		r.record("chain_read_miss"+sfx, r.measure(conc, func() error {
			h, err := c.Head(r.ctx, leaf, "no-such-document")
			if err != nil && client.IsNotFound(err) || err == nil && h.State != client.Live {
				return nil
			}
			return err
		}))
		if r.op != nil {
			// A grant the core hasn't seen: its verification walks the
			// chain's keys and revocations.
			fresh := make(chan *client.Client, r.c.samples)
			for i := 0; i < r.c.samples; i++ {
				fresh <- r.newClient(r.urls[0], r.mint(r.key, map[string]any{"kid": keyKid, "sub": fmt.Sprintf("user:f%d-%d", conc, i), "ns": []any{leaf}, "can": []any{"read"}}))
			}
			r.record("chain_read_root_new_grant"+sfx, r.measure(conc, func() error { _, err := (<-fresh).Head(r.ctx, leaf, "d-0"); return err }))
		}
		var k atomic.Int64
		r.record("chain_create_doc"+sfx, r.measure(conc, func() error {
			_, err := c.CreateDoc(r.ctx, leaf, fmt.Sprintf("w%d-%d", conc, k.Add(1)), body(0))
			return err
		}))
		r.record("chain_create_typed"+sfx, r.measure(conc, func() error {
			_, err := c.CreateDoc(r.ctx, leaf, fmt.Sprintf("t%d-%d", conc, k.Add(1)), structuredDoc(2048, schemaRef))
			return err
		}))
		if d > 0 {
			name := fmt.Sprintf("draft%d", conc)
			dw := must(c.CreateDoc(r.ctx, leaf, name, structuredSchema()))
			draftRef := fmt.Sprintf("/r/%s/%s/rev/%s", root, name, dw.ID)
			r.record("chain_create_draft_typed"+sfx, r.measure(conc, func() error {
				_, err := c.CreateDoc(r.ctx, leaf, fmt.Sprintf("dt%d-%d", conc, k.Add(1)), structuredDoc(2048, draftRef))
				return err
			}))
		}
	}
	// Appends in the leaf to documents read through from the root, one
	// each (the per-resource rate allows no more on one document).
	if k := min(r.c.samples, r.c.branchDocs-2); k > 0 && d > 0 {
		heads := make([]string, k)
		for i := range heads {
			heads[i] = must(c.Head(r.ctx, leaf, fmt.Sprintf("d-%d", i+2))).ID
		}
		r.record("chain_append_through_c1", timesOf(k, func(i int) error {
			_, err := c.Append(r.ctx, leaf, fmt.Sprintf("d-%d", i+2), heads[i], []any{map[string]any{"op": "replace", "path": "/n", "value": -1}})
			return err
		}))
	}
	if d > 0 {
		r.record("chain_create_sibling", timesOf(5, func(i int) error {
			_, err := r.bw(parent).CreateBranch(r.ctx, parent, client.BranchRequest{Name: fmt.Sprintf("%s-s%d", tag, i)})
			return err
		}))
	}
	r.settle()
	r.record("chain_purge_root", r.purges(cr, root, pn, stub))
}
