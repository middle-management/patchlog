package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/schema"
)

// v86Paths records the URL path of every request a client sends.
type v86Paths struct {
	mu    sync.Mutex
	paths []string
}

func (p *v86Paths) client(d *deployment) *client.Client {
	return d.c.With(client.WithTransport(func(next http.RoundTripper) http.RoundTripper {
		return v86RoundTrip(func(r *http.Request) (*http.Response, error) {
			p.mu.Lock()
			p.paths = append(p.paths, r.URL.Path)
			p.mu.Unlock()
			return next.RoundTrip(r)
		})
	}))
}

// under lists the recorded paths that start with prefix.
func (p *v86Paths) under(prefix string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, s := range p.paths {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

type v86RoundTrip func(*http.Request) (*http.Response, error)

func (f v86RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// v86First is a namespace's first ns_id.
func v86First(t *testing.T, d *deployment, ns string) string {
	t.Helper()
	page, _, err := d.c.NSLogPage(ctx, ns, must(d.c.NSHead(ctx, ns)).ID, "")
	noErr(t, err)
	if len(page) == 0 {
		t.Fatalf("namespace %s has no log", ns)
	}
	return page[0].ID
}

func v86Heads(t *testing.T, d *deployment, ns, at string) map[string]client.HeadItem {
	t.Helper()
	m := map[string]client.HeadItem{}
	for _, it := range must(d.c.Heads(ctx, ns, at)) {
		m[it.Resource] = it
	}
	return m
}

// §G.4.1 Full-history lines (v0.86; FED-3): "Chains exported from a branch
// include the base's entries back to genesis, or name in requires the
// foreign parent: the resource's head as the branch's /heads lists it at
// the branch's first ns_id (§10)." The branch's own /heads there is the
// base's as of the branch's at, a tombstone of the base's a row with its
// target; the exporter reads it, and nothing of the base, whose later
// writes don't move the foreign parent.
func TestV086ForeignParentFromBranchHeads(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"score": "0-0"})
	parent := src.append("matches", "derby", op("replace", "/score", "1-0"))
	cup := src.create("matches", "cup", map[string]any{"title": "Cup"})
	src.create("matches", "gone", map[string]any{"title": "Gone"})
	tomb := must(src.c.Delete(ctx, "matches", "gone", src.head("matches", "gone").ID)).ID
	at := must(src.c.NSHead(ctx, "matches")).ID
	must(src.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}))
	// The base moves on; the branch continues derby and the deleted one.
	src.append("matches", "derby", op("replace", "/score", "9-9"))
	src.append("matches", "cup", op("replace", "/title", "Cup, later"))
	head := src.append("r7", "derby", op("replace", "/score", "2-0"))
	restored := must(src.c.Restore(ctx, "r7", "gone", tomb, ops(op("replace", "/title", "Back")))).ID
	src.create("r7", "final", map[string]any{"title": "Final"})

	// What the clause reads: the branch's own /heads at its first ns_id,
	// the same rows as the base's at the branch's at.
	own, base := v86Heads(t, src, "r7", v86First(t, src, "r7")), v86Heads(t, src, "matches", at)
	if len(own) != len(base) || len(own) != 3 {
		t.Fatalf("the branch's /heads at its first ns_id: %v, the base's at %s: %v", own, at, base)
	}
	for name, b := range base {
		if o := own[name]; o.Kind != b.Kind || o.Target != b.Target {
			t.Fatalf("%s: the branch lists %+v at its first ns_id, the base %+v at the branch's at", name, o, b)
		}
	}
	if g := own["gone"]; g.Kind != "tombstone" || g.Target != tomb {
		t.Fatalf("the base's tombstone in the branch's /heads: %+v, want a tombstone row with target %s", g, tomb)
	}

	var seen v86Paths
	var buf bytes.Buffer
	_, sum, err := bundle.Export(ctx, seen.client(src), &buf, bundle.ExportOptions{Select: []string{"r7"}, ForeignParents: true})
	noErr(t, err)
	h := sum.Header
	if h.Requires["r7/derby"] != parent || h.Docs["r7/derby"].Head != head {
		t.Fatalf("derby: requires %q, want the foreign parent %s; head %v", h.Requires["r7/derby"], parent, h.Docs["r7/derby"])
	}
	if h.Requires["r7/gone"] != tomb || h.Docs["r7/gone"].Head != restored {
		t.Fatalf("gone, restored in the branch: requires %q, want the base's tombstone %s", h.Requires["r7/gone"], tomb)
	}
	if h.Requires["r7/final"] != "" || !slices.Equal(h.External, []string{"r7/cup/rev/" + cup}) {
		t.Fatalf("the branch's own document requires %q; external %v, want cup as the branch reads it", h.Requires["r7/final"], h.External)
	}
	if got := seen.under("/ns/matches"); len(got) != 0 {
		t.Fatalf("the export read the base: %v", got)
	}
	if got := seen.under("/r/matches/"); len(got) != 0 {
		t.Fatalf("the export read the base's resources: %v", got)
	}
	must(bundle.Verify(bytes.NewReader(buf.Bytes())))
}

// The foreign parents are read at the branch's first ns_id only where
// that entry is the branch's config genesis (§G.3, §10 Branches), before
// any write of its own. A log that starts otherwise would make a
// resource's own first write its foreign parent, which then isn't
// exported: the export fails instead, and writes nothing.
func TestV086ForeignParentNeedsConfigGenesis(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"score": "0-0"})
	must(src.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}))
	src.append("r7", "derby", op("replace", "/score", "2-0"))
	src.create("r7", "final", map[string]any{"title": "Final"})
	// The branch's log as a server would give it without its genesis.
	cut := 0
	c := src.c.With(client.WithTransport(func(next http.RoundTripper) http.RoundTripper {
		return v86RoundTrip(func(r *http.Request) (*http.Response, error) {
			res, err := next.RoundTrip(r)
			if err != nil || res.StatusCode != 200 || !strings.HasPrefix(r.URL.Path, "/ns/r7/rev/") || !strings.HasSuffix(r.URL.Path, "/log") || r.URL.Query().Get("since") != "" {
				return res, err
			}
			b, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				return nil, err
			}
			var entries []json.RawMessage
			if err := json.Unmarshal(b, &entries); err != nil || len(entries) < 2 {
				t.Errorf("the branch's log page: %v, %d entries", err, len(entries))
				res.Body = io.NopCloser(bytes.NewReader(b))
				return res, nil
			}
			cut++
			b, _ = json.Marshal(entries[1:])
			res.Body, res.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
			res.Header.Set("Content-Length", strconv.Itoa(len(b)))
			return res, nil
		})
	}))
	var out bytes.Buffer
	_, _, err := bundle.Export(ctx, c, &out, bundle.ExportOptions{Select: []string{"r7"}, ForeignParents: true})
	if cut == 0 {
		t.Fatal("the export didn't read the branch's log")
	}
	if err == nil || !strings.Contains(err.Error(), "does not start with its config genesis") {
		t.Fatalf("export of a branch whose log doesn't start with its config genesis: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("the refused export wrote %d bytes", out.Len())
	}
}

// The same for a branch of a branch: the foreign parent is the head as
// the inner branch's /heads lists it at its first ns_id, the outer
// branch's own revision where it had one, the base's where it read
// through.
func TestV086ForeignParentBranchOfBranch(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"score": "0-0"})
	cup := src.create("matches", "cup", map[string]any{"title": "Cup"})
	old := src.create("matches", "old", map[string]any{"n": 1})
	must(src.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}))
	outer := src.append("r7", "derby", op("replace", "/score", "1-0"))
	must(src.c.CreateBranch(ctx, "r7", client.BranchRequest{Name: "r7-fix"}))
	src.append("r7", "derby", op("replace", "/score", "5-5"))
	head := src.append("r7-fix", "derby", op("replace", "/score", "2-0"))
	oldHead := src.append("r7-fix", "old", op("replace", "/n", 2))

	_, sum := exportFrom(t, src, bundle.ExportOptions{Select: []string{"r7-fix"}, ForeignParents: true})
	h := sum.Header
	if h.Requires["r7-fix/derby"] != outer || h.Docs["r7-fix/derby"].Head != head {
		t.Fatalf("derby: requires %q, want the outer branch's %s", h.Requires["r7-fix/derby"], outer)
	}
	if h.Requires["r7-fix/old"] != old || h.Docs["r7-fix/old"].Head != oldHead {
		t.Fatalf("old: requires %q, want the base's %s, read through the outer branch", h.Requires["r7-fix/old"], old)
	}
	if !slices.Equal(h.External, []string{"r7-fix/cup/rev/" + cup}) {
		t.Fatalf("external %v", h.External)
	}
}

// A branch whose base is in another deployment (§G.3) exports the same
// way (v0.86: "remote-base exports"): its foreign parents are in its own
// /heads at its first ns_id, where the shadow of the base was mirrored
// before the branch's creation committed. Before, the exporter read
// /heads of whatever local namespace carried the base's name.
func TestV086ForeignParentRemoteBase(t *testing.T) {
	t.Parallel()
	up := newDeployment(t, stagingOrigin)
	up.ns("matches", nil)
	up.create("matches", "derby", map[string]any{"score": "0-0"})
	parent := up.append("matches", "derby", op("replace", "/score", "1-0"))
	cup := up.create("matches", "cup", map[string]any{"title": "Cup"})
	at := must(up.c.NSHead(ctx, "matches")).ID
	up.append("matches", "derby", op("replace", "/score", "9-9"))

	src := newDeployment(t, cmsOrigin, func(o *core.Options) {
		o.Remote = core.RemoteOptions{FollowInterval: -1, Resolve: func(origin string) (core.RemoteEndpoint, error) {
			if origin != stagingOrigin {
				return core.RemoteEndpoint{}, errors.New("unknown origin " + origin)
			}
			return core.RemoteEndpoint{BaseURL: up.url}, nil
		}}
	})
	src.ns("rel", map[string]any{"read": "public", "base": map[string]any{"origin": stagingOrigin, "ns": "matches", "at": at, "chain": []any{"matches"}}})
	if got := src.head("rel", "derby").ID; got != parent {
		t.Fatalf("the remote branch reads derby at %s, want the base's %s as of its at", got, parent)
	}
	head := src.append("rel", "derby", op("replace", "/score", "2-0"))
	src.create("rel", "final", map[string]any{"title": "Final"})

	b, sum := exportFrom(t, src, bundle.ExportOptions{Select: []string{"rel"}, ForeignParents: true})
	h := sum.Header
	if h.Requires["rel/derby"] != parent || h.Docs["rel/derby"].Head != head {
		t.Fatalf("derby: requires %q, want the foreign parent %s; docs %v", h.Requires["rel/derby"], parent, h.Docs)
	}
	if _, ok := h.Docs["rel/final"]; !ok || h.Requires["rel/final"] != "" || !slices.Equal(h.External, []string{"rel/cup/rev/" + cup}) {
		t.Fatalf("docs %v, requires %v, external %v", h.Docs, h.Requires, h.External)
	}
	// It goes into the base's own deployment, mapped onto a branch of the
	// base there.
	must(up.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "rel", At: at}))
	importB(t, up, b, bundle.ImportOptions{})
	sameHeads(t, src, "rel", up, "rel", "derby", "cup", "final")
}

// The same for an e2e branch of a remote base, which exported only the
// documents that were its own from genesis: a document continued in the
// branch names its foreign parent in requires, one it reads through is
// external, and no line sealed for the base is written (§G.5.1).
func TestV086E2EBranchOfRemoteBase(t *testing.T) {
	t.Parallel()
	up := newEncDeployment(t, stagingOrigin)
	id := identity(t)
	x := up.c.E2E(id)
	up.ns("m", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
	must(x.InitKeyring(ctx, "m"))
	first := must(x.CreateDocSealed(ctx, "m", "derby", map[string]any{"title": "Derby", "score": "0-0"})).ID
	parent := must(x.AppendSealed(ctx, "m", "derby", first, ops(op("replace", "/score", "1-0")))).ID
	cup := must(x.CreateDocSealed(ctx, "m", "cup", map[string]any{"title": "Cup"})).ID
	at := must(up.c.NSHead(ctx, "m")).ID
	must(x.AppendSealed(ctx, "m", "derby", parent, ops(op("replace", "/score", "9-9"))))

	src := newEncDeployment(t, cmsOrigin, func(o *core.Options) {
		o.Remote = core.RemoteOptions{FollowInterval: -1, Resolve: func(origin string) (core.RemoteEndpoint, error) {
			return core.RemoteEndpoint{BaseURL: up.url}, nil
		}}
	})
	src.ns("m-r7", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"},
		"base": map[string]any{"origin": stagingOrigin, "ns": "m", "at": at, "chain": []any{"m"}}})
	// The branch's writer holds the base's key too (§E.3.2), fetched from
	// the base's keyring in its own deployment.
	sx := src.c.E2E(id)
	sx.AddKey("m#1", must(x.Key(ctx, "m#1")))
	must(sx.InitKeyring(ctx, "m-r7"))
	head := must(sx.AppendSealed(ctx, "m-r7", "derby", parent, ops(op("replace", "/score", "2-0")))).ID
	own := must(sx.CreateDocSealed(ctx, "m-r7", "final", map[string]any{"title": "Final"})).ID

	var buf bytes.Buffer
	plan, sum, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"m-r7"}})
	noErr(t, err)
	h := sum.Header
	if h.Access["m-r7"] != bundle.AccessE2E {
		t.Fatalf("access %v", h.Access)
	}
	if h.Requires["m-r7/derby"] != parent || h.Docs["m-r7/derby"].Head != head {
		t.Fatalf("derby: requires %q, want the foreign parent %s; docs %v", h.Requires["m-r7/derby"], parent, h.Docs)
	}
	if h.Docs["m-r7/final"].Head != own || h.Requires["m-r7/final"] != "" {
		t.Fatalf("the branch's own document: %v, requires %v", h.Docs, h.Requires)
	}
	if _, bundled := h.Docs["m-r7/cup"]; bundled || len(plan.External) != 1 || plan.External[0] != "m-r7/cup/rev/"+cup {
		t.Fatalf("cup, read through: docs %v, external %v", h.Docs, plan.External)
	}
	for k, nss := range v82SealedFor(t, buf.Bytes()) {
		for _, ns := range nss {
			if ns != "m-r7" {
				t.Fatalf("%s carries a line sealed for %q, read through from the base", k, ns)
			}
		}
	}
	if bytes.Contains(buf.Bytes(), []byte(first)) {
		t.Fatalf("the bundle names %s, a line of the base", first)
	}
	must(bundle.Verify(bytes.NewReader(buf.Bytes())))

	// A requires before the foreign parent is refused as for a local base.
	_, _, err = bundle.Export(ctx, src.c, &bytes.Buffer{}, bundle.ExportOptions{Select: []string{"m-r7/derby"}, Requires: map[string]string{"m-r7/derby": first}})
	if err == nil || !strings.Contains(err.Error(), "foreign parent "+parent) {
		t.Fatalf("export with requires before the foreign parent: %v", err)
	}
}

// v86Archive gives a deployment an archive destination, which a prune
// needs (§8.6), and a clock that later runs ahead by what the returned
// function adds: a prune leaves the revisions of the last minutes.
func v86Archive(t *testing.T) (func(*core.Options), func(time.Duration)) {
	t.Helper()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	noErr(t, err)
	var ahead atomic.Int64
	return func(o *core.Options) {
		o.Archiver = arch
		o.Now = func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
	}, func(d time.Duration) { ahead.Add(int64(d)) }
}

// v86Pins is a source whose p-refs/y1 and p-refs/y3 pin revisions 1 and 3
// of p-data/x, of four, by a schema's pinned x-ref; data is the bundle of
// p-schemas and p-data, and pin1, pin3 those of y1 and y3 with p-data and
// p-schemas external.
type v86Pins struct {
	x                [4]string
	data, pin1, pin3 []byte
}

func newV86Pins(t *testing.T, e2e bool) (*v86Pins, *client.E2E, *ecdh.PrivateKey) {
	t.Helper()
	var d *deployment
	var x *client.E2E
	var id *ecdh.PrivateKey
	p := &v86Pins{}
	if e2e {
		d = newEncDeployment(t, stagingOrigin)
		id = identity(t)
		x = d.c.E2E(id)
		d.ns("p-data", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}})
		must(x.InitKeyring(ctx, "p-data"))
		p.x[0] = must(x.CreateDocSealed(ctx, "p-data", "x", map[string]any{"n": 1})).ID
		for i := 1; i < 4; i++ {
			p.x[i] = must(x.AppendSealed(ctx, "p-data", "x", p.x[i-1], ops(op("replace", "/n", i+1)))).ID
		}
	} else {
		d = newDeployment(t, stagingOrigin)
		d.ns("p-data", nil)
		p.x[0] = d.create("p-data", "x", map[string]any{"n": 1})
		for i := 1; i < 4; i++ {
			p.x[i] = d.append("p-data", "x", op("replace", "/n", i+1))
		}
	}
	d.ns("p-schemas", nil)
	d.ns("p-refs", nil)
	item := d.create("p-schemas", "item", map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": map[string]any{
		"pin": map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}}}})
	d.create("p-refs", "y1", map[string]any{"$schema": rev("p-schemas", "item", item), "pin": rev("p-data", "x", p.x[0])})
	d.create("p-refs", "y3", map[string]any{"$schema": rev("p-schemas", "item", item), "pin": rev("p-data", "x", p.x[2])})
	p.data, _ = exportFrom(t, d, bundle.ExportOptions{Select: []string{"p-schemas", "p-data"}})
	var sum *bundle.Summary
	p.pin1, sum = exportFrom(t, d, bundle.ExportOptions{Select: []string{"p-refs/y1"}, External: []string{"p-data", "p-schemas"}})
	if want := "p-data/x/rev/" + p.x[0]; !slices.Contains(sum.Header.External, want) {
		t.Fatalf("y1's externals %v lack the pin %s", sum.Header.External, want)
	}
	p.pin3, sum = exportFrom(t, d, bundle.ExportOptions{Select: []string{"p-refs/y3"}, External: []string{"p-data", "p-schemas"}})
	if want := "p-data/x/rev/" + p.x[2]; !slices.Contains(sum.Header.External, want) {
		t.Fatalf("y3's externals %v lack the pin %s", sum.Header.External, want)
	}
	return p, x, id
}

// v86Refused imports b into d and wants it refused by the check, naming
// the pinned revision id as not in the target; nothing is written.
func v86Refused(t *testing.T, d *deployment, b []byte, id string) {
	t.Helper()
	rep, err := bundle.Import(ctx, d.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	var ce *bundle.CheckError
	want := "external p-data/x/rev/" + id + ": revision " + id + " is not in the target"
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), want) {
		t.Fatalf("import with the pin %s pruned: %v (report %+v), want the check's %q", id, err, rep, want)
	}
	if h, err := d.c.Head(ctx, "p-refs", "y1"); err == nil && h.State == client.Live {
		t.Fatalf("the refused import wrote p-refs/y1: %+v", h)
	}
}

// TOOLS §G.4.2 (v0.86; FED-15): an external is in the target "by id for
// pinned references, in the resource's chain and neither purged nor
// pruned without a kept document (§8.6)". A pin below the target's
// horizon is not in the target, so the bundle is refused; with the
// revision in the prune's keep set its document is kept, and it is; the
// horizon itself is always there.
func TestV086PrunedPinNotInTarget(t *testing.T) {
	t.Parallel()
	p, _, _ := newV86Pins(t, false)

	t.Run("pruned", func(t *testing.T) {
		t.Parallel()
		opt, advance := v86Archive(t)
		dst := newDeployment(t, cmsOrigin, opt)
		importB(t, dst, p.data, bundle.ImportOptions{})
		advance(time.Hour)
		// Before the prune the pin is there.
		if _, err := dst.c.Doc(ctx, "p-data", "x", p.x[0]); err != nil {
			t.Fatal(err)
		}
		must(dst.c.Prune(ctx, "p-data", "x", client.PruneRequest{Horizon: p.x[2]}))
		if _, err := dst.c.Doc(ctx, "p-data", "x", p.x[0]); !client.IsPruned(err) {
			t.Fatalf("the pinned revision below the horizon: %v, want 410 pruned", err)
		}
		v86Refused(t, dst, p.pin1, p.x[0])
		// The horizon's document stays: a pin to it is in the target.
		importB(t, dst, p.pin3, bundle.ImportOptions{})
		if got := dst.doc("p-refs", "y3")["pin"]; got != rev("p-data", "x", p.x[2]) {
			t.Fatalf("y3 %v", got)
		}
	})
	t.Run("kept", func(t *testing.T) {
		t.Parallel()
		opt, advance := v86Archive(t)
		dst := newDeployment(t, cmsOrigin, opt)
		importB(t, dst, p.data, bundle.ImportOptions{})
		advance(time.Hour)
		must(dst.c.Prune(ctx, "p-data", "x", client.PruneRequest{Horizon: p.x[2], Keep: []string{p.x[0]}}))
		if _, err := dst.c.Doc(ctx, "p-data", "x", p.x[1]); !client.IsPruned(err) {
			t.Fatalf("the revision between the kept one and the horizon: %v, want 410 pruned", err)
		}
		importB(t, dst, p.pin1, bundle.ImportOptions{})
		if got := dst.doc("p-refs", "y1")["pin"]; got != rev("p-data", "x", p.x[0]) {
			t.Fatalf("y1 %v", got)
		}
	})
}

// The same in an end-to-end target, which serves no document by revision
// (§E.3.1): a pin in the readable log is looked for in the chain, one
// below the horizon is refused, and the horizon's, whose sealed snapshot
// the prune stored, is in the target.
func TestV086PrunedPinNotInE2ETarget(t *testing.T) {
	t.Parallel()
	p, _, id := newV86Pins(t, true)

	t.Run("readable", func(t *testing.T) {
		t.Parallel()
		opt, advance := v86Archive(t)
		dst := newEncDeployment(t, cmsOrigin, opt)
		importB(t, dst, p.data, bundle.ImportOptions{})
		advance(time.Hour)
		importB(t, dst, p.pin1, bundle.ImportOptions{})
	})
	t.Run("pruned", func(t *testing.T) {
		t.Parallel()
		opt, advance := v86Archive(t)
		dst := newEncDeployment(t, cmsOrigin, opt)
		importB(t, dst, p.data, bundle.ImportOptions{})
		advance(time.Hour)
		if res, err := dst.c.E2E(id).PruneE2E(ctx, "p-data", "x", p.x[2]); err != nil || res.Horizon != p.x[2] {
			t.Fatalf("PruneE2E: %+v %v", res, err)
		}
		v86Refused(t, dst, p.pin1, p.x[0])
		importB(t, dst, p.pin3, bundle.ImportOptions{})
		if got := dst.doc("p-refs", "y3")["pin"]; got != rev("p-data", "x", p.x[2]) {
			t.Fatalf("y3 %v", got)
		}
	})
}
