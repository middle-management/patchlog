package bundle_test

// Purges follow imports (§G.1, FED-26, VEC-87): a deployment that imported
// from a trusted origin applies that origin's later purges of the names it
// imported, as the server, in the namespace, its upstream namespace and its
// branches.

import (
	"bytes"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/schema"
)

// tagPurger records the cache tags purged.
type tagPurger struct {
	mu   sync.Mutex
	tags []string
}

func (p *tagPurger) PurgeTags(tags []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tags = append(p.tags, tags...)
}

func (p *tagPurger) has(tag string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.tags, tag)
}

// importer is the principal the test deployments import as (their
// client's author, authentication being disabled), which a follower names
// as each trusted origin's importer (§G.1, v0.88).
const importer = "alice"

// follower is an importing deployment that trusts the origins given, or
// none, with importer as their importer, and follows only when asked
// (Interval -1).
func follower(t *testing.T, purger core.Purger, trusted ...*deployment) *deployment {
	return newDeployment(t, cmsOrigin, func(o *core.Options) {
		o.Purger = purger
		o.FollowPurges.Interval = -1
		o.FollowPurges.Origins = map[string]core.PurgeOrigin{}
		for _, d := range trusted {
			o.FollowPurges.Origins[d.origin] = core.PurgeOrigin{BaseURL: d.url, Importers: []string{importer}}
		}
	})
}

func exportBundle(t *testing.T, d *deployment, opt bundle.ExportOptions) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, _, err := bundle.Export(ctx, d.c, &buf, opt); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (d *deployment) purge(ns, name string) {
	d.t.Helper()
	must(d.c.Purge(ctx, ns, name, d.head(ns, name).ID, false))
}

func (d *deployment) purgeNS(ns string) {
	d.t.Helper()
	must(d.c.PatchConfig(ctx, ns, must(d.c.NSHead(ctx, ns)).Config, []any{op("add", "/frozen", true)}))
	must(d.c.PurgeNamespace(ctx, ns, must(d.c.NSHead(ctx, ns)).ID))
}

func (d *deployment) follow() {
	d.t.Helper()
	noErr(d.t, d.e.FollowPurges(ctx))
}

// status is the status a read of ns/name answers: 200 live, 410 purged,
// 404; 0 tombstoned.
func (d *deployment) status(ns, name string) int {
	d.t.Helper()
	switch h := d.head(ns, name); h.State {
	case client.Live:
		return 200
	case client.NotFound:
		return 404
	case client.Purged:
		return 410
	default:
		return 0
	}
}

// purgeEntries are ns's purge entries of name.
func (d *deployment) purgeEntries(ns, name string) []client.NSEntry {
	d.t.Helper()
	var out []client.NSEntry
	for _, en := range mustRead(d.c.NSLog(ctx, ns, must(d.c.NSHead(ctx, ns)).ID, "")) {
		if en.Kind == "purge" && en.Resource == name {
			out = append(out, en)
		}
	}
	return out
}

// followedEntry checks that ns has exactly one purge entry of name, the
// server's own: the follow author, no grant (not even null) and no via.
func (d *deployment) followedEntry(ns, name string) {
	d.t.Helper()
	es := d.purgeEntries(ns, name)
	if len(es) != 1 {
		d.t.Fatalf("%s/%s: %d purge entries, want 1", ns, name, len(es))
	}
	en := es[0]
	if en.Author != core.FollowAuthor || en.Grant != nil || en.GrantNull || en.Via != nil {
		d.t.Fatalf("%s/%s: purge entry author %q grant %v null %v via %v, want the server's own", ns, name, en.Author, en.Grant, en.GrantNull, en.Via)
	}
}

func TestPurgesFollowImports(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"title": "Derby"})
	src.create("matches", "cup", map[string]any{"title": "Cup"})
	src.create("matches", "final", map[string]any{"title": "Final"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches"}})
	// Created at the origin after the export: never imported.
	src.create("matches", "later", map[string]any{"title": "Later"})

	tags := &tagPurger{}
	dst := follower(t, tags, src)
	importB(t, dst, b, bundle.ImportOptions{})
	// A local branch reads the imported names through.
	must(dst.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-b"}))
	// The importer's own documents, one under a name the origin has but
	// that was never imported.
	dst.create("matches", "local", map[string]any{"title": "Local"})
	dst.create("matches", "later", map[string]any{"title": "Mine"})

	// Nothing to follow yet.
	dst.follow()
	if dst.status("matches", "derby") != 200 {
		t.Fatal("derby gone before any purge")
	}

	// A purge at the origin of a name imported.
	src.purge("matches", "derby")
	// And of one that was never imported.
	src.purge("matches", "later")
	dst.follow()
	if st := dst.status("matches", "derby"); st != 410 {
		t.Fatalf("derby after the origin's purge: %d, want 410", st)
	}
	if st := dst.status("matches-b", "derby"); st != 410 {
		t.Fatalf("derby in the branch: %d, want 410", st)
	}
	dst.followedEntry("matches", "derby")
	if len(dst.purgeEntries("matches-b", "derby")) != 1 {
		t.Fatal("no propagated purge entry in the branch")
	}
	for _, tag := range []string{"r:matches/derby", "heads:matches", "r:matches-b/derby", "heads:matches-b"} {
		if !tags.has(tag) {
			t.Errorf("cache tag %s not purged; purged %v", tag, tags.tags)
		}
	}
	if st := dst.status("matches", "later"); st != 200 {
		t.Fatalf("a name never imported: %d, want 200", st)
	}
	// Following again changes nothing.
	dst.follow()
	dst.followedEntry("matches", "derby")

	// purge-ns at the origin: every name imported, and only those; the
	// namespace itself stays.
	src.purgeNS("matches")
	dst.follow()
	for _, name := range []string{"cup", "final"} {
		if st := dst.status("matches", name); st != 410 {
			t.Fatalf("%s after the origin's purge-ns: %d, want 410", name, st)
		}
		dst.followedEntry("matches", name)
	}
	for _, name := range []string{"local", "later"} {
		if st := dst.status("matches", name); st != 200 {
			t.Fatalf("%s after the origin's purge-ns: %d, want 200", name, st)
		}
	}
	dst.create("matches", "after", map[string]any{"title": "After"})
	if len(dst.purgeEntries("matches", "derby")) != 1 {
		t.Fatal("derby purged twice")
	}
}

// VEC-87: a source whose origin isn't trusted purges nothing.
func TestPurgesFollowUntrustedOrigin(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"title": "Derby"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches"}})
	other := newDeployment(t, "https://other.example")
	dst := follower(t, &tagPurger{}, other) // trusts another origin only
	importB(t, dst, b, bundle.ImportOptions{})
	src.purge("matches", "derby")
	dst.follow()
	if st := dst.status("matches", "derby"); st != 200 {
		t.Fatalf("derby after an untrusted origin's purge: %d, want 200", st)
	}
	if len(dst.purgeEntries("matches", "derby")) != 0 {
		t.Fatal("a purge entry for an untrusted origin's purge")
	}
}

// Snapshot imports go through the upstream namespace (§G.4.4), whose
// chains the purge reaches too.
func TestPurgesFollowUpstream(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "cup", map[string]any{"title": "Cup"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches"}, Mode: bundle.Snapshot})
	dst := follower(t, &tagPurger{}, src)
	importB(t, dst, b, bundle.ImportOptions{})
	if st := dst.status("matches-upstream", "cup"); st != 200 {
		t.Fatalf("upstream cup: %d", st)
	}
	src.purge("matches", "cup")
	dst.follow()
	for _, ns := range []string{"matches", "matches-upstream"} {
		if st := dst.status(ns, "cup"); st != 410 {
			t.Fatalf("%s/cup after the origin's purge: %d, want 410", ns, st)
		}
		dst.followedEntry(ns, "cup")
	}
}

// An import that brings a name after the follow passed the origin's purge
// of it (an older bundle imported late) still gets the purge.
func TestPurgesFollowLateImport(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"title": "Derby"})
	src.create("matches", "cup", map[string]any{"title": "Cup"})
	old := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches/cup"}})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches/derby"}})
	dst := follower(t, &tagPurger{}, src)
	importB(t, dst, b, bundle.ImportOptions{})
	src.purge("matches", "cup")
	dst.follow() // past the purge of cup, not imported yet
	importB(t, dst, old, bundle.ImportOptions{})
	dst.follow()
	if st := dst.status("matches", "cup"); st != 410 {
		t.Fatalf("cup imported late: %d, want 410", st)
	}
	dst.followedEntry("matches", "cup")
	if st := dst.status("matches", "derby"); st != 200 {
		t.Fatalf("derby: %d, want 200", st)
	}
}

// A followed purge §6.1 refuses as in_use waits for an operator; later
// purges don't wait for it.
func TestPurgesFollowInUseWaits(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("schemas", nil)
	s := src.create("schemas", "s", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	src.create("schemas", "t", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"schemas"}})
	dst := follower(t, &tagPurger{}, src)
	importB(t, dst, b, bundle.ImportOptions{})
	// A local document pins the imported schema s from another namespace.
	dst.ns("pages", nil)
	dst.create("pages", "p", map[string]any{"$schema": rev("schemas", "s", s)})

	src.purge("schemas", "s")
	dst.follow()
	if st := dst.status("schemas", "s"); st != 200 {
		t.Fatalf("schemas/s refused as in_use: %d, want 200", st)
	}
	w := must(dst.e.FollowedPurgesWaiting(ctx))
	if len(w) != 1 || w[0].NS != "schemas" || w[0].Name != "s" || w[0].Origin != stagingOrigin || w[0].Refusal["code"] != "in_use" {
		t.Fatalf("waiting: %+v", w)
	}
	// A later purge doesn't wait for it.
	src.purge("schemas", "t")
	dst.follow()
	if st := dst.status("schemas", "t"); st != 410 {
		t.Fatalf("schemas/t: %d, want 410", st)
	}
	if st := dst.status("schemas", "s"); st != 200 {
		t.Fatalf("schemas/s still referenced: %d, want 200", st)
	}
	// The operator removes the reference: the waiting purge goes through.
	dst.purge("pages", "p")
	dst.follow()
	if st := dst.status("schemas", "s"); st != 410 {
		t.Fatalf("schemas/s once unreferenced: %d, want 410", st)
	}
	dst.followedEntry("schemas", "s")
	if w := must(dst.e.FollowedPurgesWaiting(ctx)); len(w) != 0 {
		t.Fatalf("still waiting: %+v", w)
	}
}

// A source asserting the trusted origin with an at the origin doesn't know
// doesn't hold up a later genuine import's follow.
func TestPurgesFollowUnknownAt(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.ns("other", nil)
	unknown := src.create("other", "x", map[string]any{"a": 1}) // an id, not in matches' chain
	src.create("matches", "derby", map[string]any{"title": "Derby"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches"}})
	dst := follower(t, &tagPurger{}, src)
	dst.ns("matches", nil)
	must(dst.c.Batch(ctx, "matches", client.BatchRequest{
		Items:  []client.BatchItem{{Resource: "asserted", IfNoneMatch: true, Steps: []client.Step{{Patches: ops(op("add", "", map[string]any{"title": "A"}))}}}},
		Source: map[string]any{"origin": stagingOrigin, "ns": "matches", "at": unknown, "bundle": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}, false))
	if err := dst.e.FollowPurges(ctx); err == nil {
		t.Fatal("following from an unknown at: no error")
	}
	importB(t, dst, b, bundle.ImportOptions{})
	src.purge("matches", "derby")
	_ = dst.e.FollowPurges(ctx) // the unknown cursor is reported once more, and replaced
	if st := dst.status("matches", "derby"); st != 410 {
		t.Fatalf("derby: %d, want 410", st)
	}
	dst.followedEntry("matches", "derby")
	dst.follow() // and the follow is clean again
}

// The leader's loop follows every interval.
func TestPurgesFollowLoop(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"title": "Derby"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches"}})
	dst := newDeployment(t, cmsOrigin, func(o *core.Options) {
		o.FollowPurges.Interval = 20 * time.Millisecond
		o.FollowPurges.Origins = map[string]core.PurgeOrigin{src.origin: {BaseURL: src.url, Importers: []string{importer}}}
	})
	importB(t, dst, b, bundle.ImportOptions{})
	src.purge("matches", "derby")
	deadline := time.Now().Add(20 * time.Second)
	for dst.status("matches", "derby") != 410 {
		if time.Now().After(deadline) {
			t.Fatal("the loop didn't follow the purge")
		}
		time.Sleep(20 * time.Millisecond)
	}
	dst.followedEntry("matches", "derby")
}

// v0.88 §G.1 ("Its operator may trust that origin and name the principals
// that import from it … only import batches by such a principal count"):
// a deployment that trusts the origin but names another principal as its
// importer follows none of the purges of what alice imported.
func TestPurgesFollowOnlyNamedImporters(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"title": "Derby"})
	b := exportBundle(t, src, bundle.ExportOptions{Select: []string{"matches"}})
	dst := newDeployment(t, cmsOrigin, func(o *core.Options) {
		o.FollowPurges.Interval = -1
		o.FollowPurges.Origins = map[string]core.PurgeOrigin{src.origin: {BaseURL: src.url, Importers: []string{"bob"}}}
	})
	importB(t, dst, b, bundle.ImportOptions{})
	src.purge("matches", "derby")
	dst.follow()
	if st := dst.status("matches", "derby"); st != 200 {
		t.Fatalf("derby, imported by alice where bob is the importer: %d, want 200", st)
	}
	if es := dst.purgeEntries("matches", "derby"); len(es) != 0 {
		t.Fatalf("purge entries %+v", es)
	}
}
