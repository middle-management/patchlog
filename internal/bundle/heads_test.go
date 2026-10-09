package bundle_test

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// headsTransport counts an importer's head lookups (GET /r/{ns}/{name})
// and listing pages (GET /ns/{ns}/rev/{id}/heads), and with block answers
// the pages 503, which leaves the import to its lookups; with purged, every
// page after the first 410, as a namespace purged while it is listed does
// (§8.5). With race set, it runs race once, before the first batch (dry:
// dry run) is sent.
type headsTransport struct {
	block, purged  bool
	lookups, pages atomic.Int64
	dry            bool
	race           func()
	once           sync.Once
}

func (h *headsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/heads"):
		n := h.pages.Add(1)
		if h.block {
			return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
		}
		if h.purged && n > 1 {
			return &http.Response{StatusCode: 410, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"code":"purged"}`)), Request: r}, nil
		}
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/r/") && strings.Count(r.URL.Path, "/") == 3:
		h.lookups.Add(1)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") && h.race != nil && (r.URL.Query().Get("dry-run") == "1") == h.dry:
		h.once.Do(h.race)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// reportJSON is an import's report without its timings, to compare
// imports by.
func reportJSON(rep *bundle.Report) []byte {
	rep.Timings = bundle.Timings{}
	return must(json.MarshalIndent(rep, "", " "))
}

// importer is a client of d whose requests go through h.
func (d *deployment) importer(h *headsTransport, opts ...client.Option) *client.Client {
	return must(client.New(d.url, append([]client.Option{client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)),
		client.WithHTTPClient(&http.Client{Transport: h})}, opts...)...))
}

// pageSize sets a deployment's log page size, with fast rate limits.
func pageSize(n int) func(*core.Options) {
	return func(o *core.Options) {
		fastLimits(o)
		o.Maximums = o.Limits
		o.Maximums.LogPageSize = n
	}
}

// headsScenario imports a first bundle of namespace m into a target, then
// changes both sides so that a second bundle meets every classification:
// 30 new documents (c00…c29) and, already imported, ff (moved on in the
// source), pr (unchanged), bh (moved on in the target), cf (both),
// ts (deleted in the target), pg (purged in the target) and, for
// snapshots, pu (its upstream resource purged in the target). With
// branch, the second bundle goes into mb, a branch of the target's m, which
// reads every earlier document through. It returns the second bundle and
// the target, with the import options that map it.
func headsScenario(t *testing.T, mode string, sealed, branch bool) ([]byte, *deployment, bundle.ImportOptions) {
	newD := func(t *testing.T, origin string) *deployment { return newDeployment(t, origin) }
	doc := map[string]any{"read": "public"}
	if sealed {
		newD, doc = newEncDeployment, map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}}
	}
	src, dst := newD(t, stagingOrigin), newD(t, cmsOrigin)
	src.ns("m", doc)
	ps := func(p ...map[string]any) []any {
		if sealed {
			return nonce(p...)
		}
		return ops(p...)
	}
	create := func(name string) {
		must(src.c.Create(ctx, "m", name, append(client.GenesisPatches(map[string]any{"v": name}), ps()...)))
	}
	change := func(d *deployment, ns, name string) {
		must(d.c.Append(ctx, ns, name, d.head(ns, name).ID, ps(op("replace", "/v", d.origin))))
	}
	names := []string{"ff", "pr", "bh", "cf", "ts", "pg"}
	if mode == bundle.Snapshot {
		names = append(names, "pu")
	}
	for _, n := range names {
		create(n)
	}
	export := func() []byte {
		b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"m"}, Mode: mode, Plaintext: sealed})
		return b
	}
	importB(t, dst, export(), bundle.ImportOptions{})

	for i := 0; i < 30; i++ {
		create(fmt.Sprintf("c%02d", i))
	}
	change(src, "m", "ff")
	change(src, "m", "cf")
	for i := 0; i < 3; i++ {
		change(dst, "m", "bh") // three ahead: its ancestry spans pages of 2
	}
	change(dst, "m", "cf")
	must(dst.c.Delete(ctx, "m", "ts", dst.head("m", "ts").ID))
	must(dst.c.Purge(ctx, "m", "pg", dst.head("m", "pg").ID, false))
	if mode == bundle.Snapshot {
		must(dst.c.Purge(ctx, "m-upstream", "pu", dst.head("m-upstream", "pu").ID, false))
	}
	opt := bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true}
	if branch {
		must(dst.c.CreateBranch(ctx, "m", client.BranchRequest{Name: "mb"}))
		opt.NSMap = map[string]string{"m": "mb"}
	}
	return export(), dst, opt
}

// The heads listing classifies every document exactly as looking each one
// up does, and plans the same batches with the same ids (§G.4.4):
// created, fast-forwarded, present, behind, conflicting, tombstoned and
// purged documents, upstream resources of snapshot documents, a branch's
// read-through documents, and a sealed namespace's.
func TestHeadsListing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		mode           string
		sealed, branch bool
	}{
		{"history", bundle.Full, false, false},
		{"snapshot", bundle.Snapshot, false, false},
		{"branch", bundle.Full, false, true},
		{"sealed", bundle.Full, true, false},
		{"sealed snapshot", bundle.Snapshot, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testHeadsListing(t, tc.mode, tc.sealed, tc.branch)
		})
	}
}

func testHeadsListing(t *testing.T, mode string, sealed, branch bool) {
	b, dst, opt := headsScenario(t, mode, sealed, branch)
	run := func(h *headsTransport) (*bundle.Report, []byte) {
		rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), opt)
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		if sealed && mode == bundle.Snapshot {
			// The import's own patch sets carry fresh nonces in a sealed
			// target (§E.2.5), so the ids it plans differ on every run.
			for _, d := range rep.Docs {
				d.Expected, d.Upstream.Head = nil, ""
			}
			for _, br := range rep.Batches {
				delete(br.Source, "ids")
			}
		}
		return rep, reportJSON(rep)
	}
	looked, listed := &headsTransport{block: true}, &headsTransport{}
	_, want := run(looked)
	rep, got := run(listed)
	if string(got) != string(want) {
		t.Fatalf("listed:\n%s\nlooked up:\n%s", got, want)
	}
	if listed.pages.Load() == 0 || listed.lookups.Load() >= looked.lookups.Load() {
		t.Fatalf("listed with %d pages and %d lookups, against %d lookups", listed.pages.Load(), listed.lookups.Load(), looked.lookups.Load())
	}

	classes := map[string]string{"c00": "create", "c29": "create", "ff": "fast-forward", "pr": "present", "bh": "behind",
		"cf": "conflict", "ts": "behind", "pg": "purged"}
	if mode == bundle.Snapshot {
		// The target's own changes since the last import are kept.
		classes["bh"], classes["ts"], classes["pu"] = "present", "present", "purged"
	}
	for name, class := range classes {
		if d := rep.Doc("m/" + name); d == nil || d.Class != class {
			t.Fatalf("%s: %+v, want %s", name, d, class)
		}
	}
}

// A listing whose pages run out part-way through the namespace: the names
// up to where it stopped are read from it, the rest looked up one by one,
// and every document is classified as lookups alone classify it. The
// target interleaves names of its own with the bundle's, which meets every
// classification; with branch, into a branch with writes of its own and
// base writes after the branch point that don't show through.
func TestHeadsPartialListing(t *testing.T) {
	t.Parallel()
	for _, branch := range []bool{false, true} {
		t.Run(fmt.Sprint("branch=", branch), func(t *testing.T) {
			t.Parallel()
			src, dst := newDeployment(t, stagingOrigin, pageSize(3)), newDeployment(t, cmsOrigin, pageSize(3))
			src.ns("m", nil)
			for i := 0; i < 42; i++ {
				src.create("m", fmt.Sprintf("d%03d", i), map[string]any{"v": i})
			}
			export := func() []byte { b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"m"}}); return b }
			importB(t, dst, export(), bundle.ImportOptions{})
			for i := 0; i < 42; i++ {
				dst.create("m", fmt.Sprintf("d%03d%s", i, []string{"a", "-x", ".x", "_x", "0"}[i%5]), map[string]any{"x": i})
				name := fmt.Sprintf("d%03d", i)
				switch i % 7 {
				case 0:
					src.append("m", name, op("replace", "/v", "src"))
				case 1:
					dst.append("m", name, op("replace", "/v", "dst"))
				case 2:
					src.append("m", name, op("replace", "/v", "src"))
					dst.append("m", name, op("replace", "/v", "dst"))
				case 3:
					must(dst.c.Delete(ctx, "m", name, dst.head("m", name).ID))
				case 4:
					must(dst.c.Purge(ctx, "m", name, dst.head("m", name).ID, false))
				case 5:
					must(dst.c.Delete(ctx, "m", name, dst.head("m", name).ID))
					src.append("m", name, op("replace", "/v", "src"))
				}
			}
			for i := 0; i < 20; i++ {
				src.create("m", fmt.Sprintf("n%03d", i), map[string]any{"v": i})
				src.create("m", fmt.Sprintf("d%03d%s", i, []string{"-a", ".a", "_a", "z", "-"}[i%5]), map[string]any{"v": i})
			}
			b := export()
			opt := bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true}
			if branch {
				must(dst.c.CreateBranch(ctx, "m", client.BranchRequest{Name: "mb"}))
				opt.NSMap = map[string]string{"m": "mb"}
				dst.append("mb", "d006", op("replace", "/v", "branch"))
				dst.append("mb", "d000", op("replace", "/v", "branch"))
				must(dst.c.Delete(ctx, "mb", "d013", dst.head("mb", "d013").ID))
				dst.create("mb", "n003", map[string]any{"v": "branch"})
				dst.create("mb", "n019", map[string]any{"v": "branch"})
				dst.append("m", "d020", op("replace", "/v", "after"))
				dst.create("m", "n010", map[string]any{"v": "after"})
			}
			run := func(h *headsTransport) []byte {
				rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), opt)
				if err != nil {
					t.Fatalf("import: %v", err)
				}
				return reportJSON(rep)
			}
			looked, listed := &headsTransport{block: true}, &headsTransport{}
			if want, got := run(looked), run(listed); string(got) != string(want) {
				t.Fatalf("listed:\n%s\nlooked up:\n%s", got, want)
			}
			if listed.pages.Load() == 0 || listed.lookups.Load() == 0 || listed.lookups.Load() >= looked.lookups.Load() {
				t.Fatalf("not a partial listing: %d pages and %d lookups, against %d lookups", listed.pages.Load(), listed.lookups.Load(), looked.lookups.Load())
			}
		})
	}
}

// A listing that answers 410 is of a namespace purged since its document
// was read (§8.5): it is dropped, and every name looked up one by one, as
// for a frozen namespace, which then answers 410 for each. Here the second
// page answers 410 and the target isn't purged, so the lookups classify as
// they do without a listing.
func TestHeadsListingPurged(t *testing.T) {
	t.Parallel()
	src, dst := newDeployment(t, stagingOrigin, pageSize(3)), newDeployment(t, cmsOrigin, pageSize(3))
	src.ns("m", nil)
	for i := 0; i < 30; i++ {
		src.create("m", fmt.Sprintf("d%02d", i), map[string]any{"v": i})
	}
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"m"}})
	importB(t, dst, b, bundle.ImportOptions{})
	src.append("m", "d00", op("replace", "/v", "src"))
	b, _ = exportFrom(t, src, bundle.ExportOptions{Select: []string{"m"}})
	run := func(h *headsTransport) []byte {
		rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true})
		noErr(t, err)
		if d := rep.Doc("m/d00"); d.Class != "fast-forward" {
			t.Fatalf("d00: %+v", d)
		}
		return reportJSON(rep)
	}
	looked, purged := &headsTransport{block: true}, &headsTransport{purged: true}
	if want, got := run(looked), run(purged); string(got) != string(want) {
		t.Fatalf("listed:\n%s\nlooked up:\n%s", got, want)
	}
	if purged.pages.Load() != 2 || purged.lookups.Load() != looked.lookups.Load() {
		t.Fatalf("%d pages and %d lookups, want 2 and %d", purged.pages.Load(), purged.lookups.Load(), looked.lookups.Load())
	}
}

// A small import into a large namespace lists little of it: from just
// below the first name it looks up, and only while pages replace enough
// lookups. 40 new documents into a namespace of 1,000, 20 heads a page.
func TestHeadsListingLarge(t *testing.T) {
	t.Parallel()
	dst := newDeployment(t, cmsOrigin, pageSize(20))
	dst.ns("m", nil)
	var items []client.BatchItem
	for i := 0; i < 1000; i++ {
		items = append(items, client.BatchItem{Resource: fmt.Sprintf("a%04d", i), IfNoneMatch: true,
			Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"i": i}))}})
	}
	must(dst.c.Batch(ctx, "m", client.BatchRequest{Items: items}, false))
	for _, tc := range []struct {
		name           string
		doc            func(i int) string
		pages, lookups int64
	}{
		// Past every name there: an empty page lists the rest.
		{"after", func(i int) string { return fmt.Sprintf("z%02d", i) }, 1, 0},
		// One by every 25th name there: the first page replaces a lookup,
		// too few to go on.
		{"sparse", func(i int) string { return fmt.Sprintf("a%04d.n", 25*i) }, 1, 39},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := newDeployment(t, stagingOrigin, fastLimits)
			src.ns("m", nil)
			for i := 0; i < 40; i++ {
				src.create("m", tc.doc(i), map[string]any{"i": i})
			}
			b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"m"}})
			run := func(h *headsTransport) []byte {
				rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true})
				noErr(t, err)
				return reportJSON(rep)
			}
			looked, listed := &headsTransport{block: true}, &headsTransport{}
			if want, got := run(looked), run(listed); string(got) != string(want) {
				t.Fatalf("listed:\n%s\nlooked up:\n%s", got, want)
			}
			if listed.pages.Load() != tc.pages || listed.lookups.Load() != tc.lookups {
				t.Fatalf("%d pages and %d lookups, want %d and %d", listed.pages.Load(), listed.lookups.Load(), tc.pages, tc.lookups)
			}
		})
	}
}

// With authentication disabled, a target namespace that answers 404 doesn't
// exist, and none of its resources do: a fresh import into it and its
// upstream namespace looks nothing up.
func TestHeadsListingAbsent(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("m", nil)
	for i := 0; i < 12; i++ {
		src.create("m", fmt.Sprintf("c%02d", i), map[string]any{"v": i})
	}
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"m"}, Mode: bundle.Snapshot})
	dst := newDeployment(t, cmsOrigin)
	h := &headsTransport{}
	rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	noErr(t, err)
	if h.lookups.Load() != 0 || h.pages.Load() != 0 {
		t.Fatalf("%d lookups, %d pages", h.lookups.Load(), h.pages.Load())
	}
	for _, d := range rep.Docs {
		if d.Class != "create" || d.Upstream.Class != "create" || dst.head("m", d.Doc[2:]).State != client.Live {
			t.Fatalf("%+v", d)
		}
	}
}

// An e2e target (§E.3) lists its heads in the clear as any other: the
// listing classifies its documents as lookups do.
func TestHeadsListingE2E(t *testing.T) {
	t.Parallel()
	src := newEncDeployment(t, stagingOrigin)
	src.ns("e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
	k := seal.NewKey()
	kr, err := seal.BuildKeyring("e", 1, k, []*ecdh.PublicKey{identity(t).PublicKey()})
	noErr(t, err)
	src.create("e", "keyring", kr.Value())
	write := func(d *deployment, name string, patches []any) string {
		parent := ""
		if h := d.head("e", name); h.State == client.Live {
			parent = h.ID
		}
		return e2eWrite(t, d, k, "e#1", "e", name, parent, patches)
	}
	for i := 0; i < 12; i++ {
		write(src, fmt.Sprintf("d%02d", i), client.GenesisPatches(map[string]any{"v": i}))
	}
	export := func() []byte {
		b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"e"}})
		return b
	}
	dst := newEncDeployment(t, cmsOrigin)
	importB(t, dst, export(), bundle.ImportOptions{})
	write(src, "d00", ops(op("add", "/w", 1.0)))
	write(dst, "d01", ops(op("add", "/w", 2.0)))
	write(src, "d02", ops(op("add", "/w", 1.0)))
	write(dst, "d02", ops(op("add", "/w", 2.0)))
	write(src, "n00", client.GenesisPatches(map[string]any{"v": 0}))
	b := export()

	run := func(h *headsTransport) []byte {
		rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true})
		noErr(t, err)
		for name, class := range map[string]string{"d00": "fast-forward", "d01": "behind", "d02": "conflict", "d03": "present", "n00": "create"} {
			if d := rep.Doc("e/" + name); d.Class != class {
				t.Fatalf("%s: %+v, want %s", name, d, class)
			}
		}
		return reportJSON(rep)
	}
	looked, listed := &headsTransport{block: true}, &headsTransport{}
	if want, got := run(looked), run(listed); string(got) != string(want) {
		t.Fatalf("listed:\n%s\nlooked up:\n%s", got, want)
	}
	if listed.pages.Load() == 0 || listed.lookups.Load() >= looked.lookups.Load() {
		t.Fatalf("listed with %d pages and %d lookups, against %d lookups", listed.pages.Load(), listed.lookups.Load(), looked.lookups.Load())
	}
}

// A write that lands in the target after its heads were listed fails the
// batch it races, which names the head it was classified against: 412 for
// the items it wrote in the dry run, or for the batch, the target moved,
// when it lands between the dry run and the submit. Nothing of the batch
// is written.
func TestHeadsListingRace(t *testing.T) {
	t.Parallel()
	for _, dry := range []bool{true, false} {
		t.Run(fmt.Sprintf("dry=%v", dry), func(t *testing.T) {
			t.Parallel()
			b, dst, opt := headsScenario(t, bundle.Full, false, false)
			opt.DryRun = false
			opt.Resolutions = map[string]bundle.Resolution{"m/cf": bundle.ResolveSkip}
			h := &headsTransport{dry: dry, race: func() {
				bob := dst.c.With(client.WithAuthor("bob"))
				must(bob.CreateDoc(ctx, "m", "c00", map[string]any{"v": "bob"}))
				must(bob.Append(ctx, "m", "ff", dst.head("m", "ff").ID, ops(op("replace", "/v", "bob"))))
			}}
			rep, err := bundle.Import(ctx, dst.importer(h), bundle.BytesOpener(b), opt)
			var ae *client.APIError
			switch {
			case dry && (err == nil || !strings.Contains(err.Error(), "c00: 412 stale") || !strings.Contains(err.Error(), "ff: 412 stale")):
				t.Fatalf("write racing the dry run: %v", err)
			case !dry && (!errors.As(err, &ae) || ae.Status != 412 || !strings.Contains(err.Error(), "the target moved")):
				t.Fatalf("write racing the submit: %v", err)
			}
			if h.pages.Load() == 0 || rep.Doc("m/c00").Class != "create" {
				t.Fatalf("not listed: %d pages, %+v", h.pages.Load(), rep.Doc("m/c00"))
			}
			if dst.head("m", "c01").State != client.NotFound {
				t.Fatal("the batch was written")
			}
		})
	}
}
